// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 3 workload export glue: captured `KCTX` rows plus helper
//! resolutions through the common typed report.
//!
//! - [`join_ctx_rows`] joins each captured context key against its
//!   native identity (`kh` → parsed `KAgg` row). First-seen `KWHO`
//!   labels never enter: identity comes only from the typed helper
//!   response, and rows without a resolution stay explicitly
//!   unresolved in their own context rows.
//! - [`assemble_live`] builds the [`WorkloadReport`] with the frozen
//!   assembly entry point. Consistency is ALWAYS unproven (Stage 1
//!   disposition: the fence F1/F3 soundness proof is pending, so
//!   snapshots export `gap_unreconciled`, never an exact unknown).
//! - [`scope_for_filter`] computes the exact partition behind a
//!   `--filter-cgroup-id` view over row-scoped projected observations
//!   (native tuple from the aggregate dictionary, quantities and
//!   event context from each row, system tallies omitted).
//! - [`workload_exit_code`] maps a rendered report to 0/3: complete
//!   evidence is 0, named gaps are 3.
//!
//! [`WorkloadReport`]: kryprobe_report::workload::WorkloadReport

use crate::live::LiveOutcome;
use kryprobe_core::evidence::NativeObservation;
use kryprobe_core::ids::ObservationId;
use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, ContextIdentity, CountOperand, ExecutionKind,
    MAX_SNAPSHOT_ASSOCIATIONS, MetadataUnavailable, Relationship, ScopePartition,
    SnapshotConsistency, SnapshotInterval, SnapshotKey, SnapshotRequest, SnapshotResponse,
    WorkloadIdentity, encode_request,
};
use kryprobe_privilege::kcrypto_backend::{CtxSnapshot, MissTerminal};
use kryprobe_privilege::workload_launch::{PinnedHelper, serve_pinned_snapshot};
use kryprobe_report::sanitize_cell;
use kryprobe_report::workload::{
    AssemblyInput, CoverageLevel, GroupBy, MetadataAvailability, NativeIdentity, ReportCoverage,
    ReportRowInput, WorkloadBuildError, WorkloadReport, WorkloadSelector as ReportSelector,
    assemble,
};
use std::collections::HashMap;

/// One parsed native row: the `kh` join key, the full native identity
/// (never hash-only), and the observed execution kind. Built in the
/// live driver from the terminal `KAGG` walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNative {
    /// Row hash joining `KCTX` rows to this native identity.
    pub kh: u64,
    /// Full native operation identity.
    pub native: NativeIdentity,
    /// Observed execution kind decoded from the native context code.
    pub kind: ExecutionKind,
}

/// One joined capture row: captured context + folded calls + native
/// identity. Resolutions attach later (report assembly), never here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedRow {
    /// The captured kernel/session context.
    pub context: ContextIdentity,
    /// Folded call count for this context.
    pub calls: u64,
    /// Full native operation identity.
    pub native: NativeIdentity,
}

/// Terminal capture essentials stashed by the live driver (parsed
/// `KAGG` natives, system ledger, capture interval).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalWorkload {
    /// Parsed native rows from the terminal `KAGG` walk.
    pub natives: Vec<ParsedNative>,
    /// Terminal `KTOT` system-ledger calls.
    pub system_total: u64,
    /// Whether the system ledger saturated.
    pub system_saturated: bool,
    /// Capture interval start (monotonic boot-time ns, inclusive).
    pub interval_start_ns: u64,
    /// Capture interval end (monotonic boot-time ns, inclusive).
    pub interval_end_ns: u64,
}

/// Joined workload capture: per-context rows plus the ledger operands
/// and capture interval behind one typed report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadCapture {
    /// Joined per-context rows (accounting-key order at assembly).
    pub rows: Vec<JoinedRow>,
    /// Terminal `KTOT` system-ledger calls.
    pub system_total: u64,
    /// Whether the system ledger saturated.
    pub system_saturated: bool,
    /// Exact `KCTX_DROPS` refused-insert count.
    pub refused_inserts: u64,
    /// Capture interval start (monotonic boot-time ns, inclusive).
    pub interval_start_ns: u64,
    /// Capture interval end (monotonic boot-time ns, inclusive).
    pub interval_end_ns: u64,
}

/// Typed workload-assembly failure. Every variant is an internal
/// inconsistency (exit 1 at integration): caller input was validated
/// earlier (usage errors exit 2 at the argument layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadError {
    /// Two different native identities share one `kh` (the join cannot
    /// establish identity — ambiguity never resolves by position).
    AmbiguousNative(u64),
    /// A captured context row has no native identity (`kh` joins no
    /// terminal `KAGG` row — the snapshot is inconsistent).
    NativeUnknown(u64),
    /// A report row has no aggregate observation (`kh` joins no live
    /// observation — the outcome is inconsistent).
    ObservationMissing(u64),
    /// The session id could not be minted (no randomness source).
    SessionMintFailed,
    /// The typed report assembly refused.
    Build(WorkloadBuildError),
    /// Scoped partition computation failed.
    Scope(String),
}

impl std::fmt::Display for WorkloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmbiguousNative(kh) => {
                write!(f, "two native identities share row hash {kh}")
            }
            Self::NativeUnknown(kh) => {
                write!(f, "captured context row {kh} has no native identity")
            }
            Self::ObservationMissing(kh) => {
                write!(f, "report row {kh} has no aggregate observation")
            }
            Self::SessionMintFailed => write!(f, "cannot mint a workload session id"),
            Self::Build(err) => write!(f, "workload report refused: {err}"),
            Self::Scope(detail) => write!(f, "scoped partition failed: {detail}"),
        }
    }
}

impl std::error::Error for WorkloadError {}

/// Decode the observed execution kind from a native context code
/// (`KCTX_*`: proc 0, kthread 1, reserved softirq 2, unknown codes —
/// including `KCTX_UNKNOWN` 3 — map to [`ExecutionKind::Unknown`]).
#[must_use]
pub fn execution_kind_for_ctx(ctx: u8) -> ExecutionKind {
    use kryprobe_abi::kcrypto_agg::{KCTX_KTHREAD, KCTX_PROC, KCTX_SOFTIRQ};
    if ctx == KCTX_PROC {
        ExecutionKind::Proc
    } else if ctx == KCTX_KTHREAD {
        ExecutionKind::Kthread
    } else if ctx == KCTX_SOFTIRQ {
        ExecutionKind::Softirq
    } else {
        ExecutionKind::Unknown
    }
}

/// Join captured context rows against parsed natives: each `KCTX` key
/// meets exactly one native identity by `kh`. A `kh` with zero or two
/// different natives refuses ([`WorkloadError::NativeUnknown`] /
/// [`WorkloadError::AmbiguousNative`]) — `kh` alone is an index, never
/// identity, so joins retain ambiguity instead of guessing.
pub fn join_ctx_rows(
    ctx: &[CtxSnapshot],
    natives: &[ParsedNative],
) -> Result<Vec<JoinedRow>, WorkloadError> {
    let mut by_kh: HashMap<u64, &ParsedNative> = HashMap::with_capacity(natives.len());
    for native in natives {
        match by_kh.get(&native.kh) {
            None => {
                by_kh.insert(native.kh, native);
            }
            Some(first) if *first == native => {}
            Some(_) => return Err(WorkloadError::AmbiguousNative(native.kh)),
        }
    }
    let mut rows = Vec::with_capacity(ctx.len());
    for row in ctx {
        let key = &row.key;
        let Some(native) = by_kh.get(&key.kh) else {
            return Err(WorkloadError::NativeUnknown(key.kh));
        };
        rows.push(JoinedRow {
            context: ContextIdentity::new(
                key.kh,
                key.cgroup,
                key.tgid,
                key.uid,
                key.start_ns,
                native.kind,
            ),
            calls: row.val.calls,
            native: native.native.clone(),
        });
    }
    Ok(rows)
}

/// Join the terminal capture into report-ready rows: `KCTX` rows meet
/// terminal natives, and the ledger operands + interval ride along.
pub fn join_capture(
    terminal: &TerminalWorkload,
    ctx: &[CtxSnapshot],
    refused_inserts: u64,
) -> Result<WorkloadCapture, WorkloadError> {
    Ok(WorkloadCapture {
        rows: join_ctx_rows(ctx, &terminal.natives)?,
        system_total: terminal.system_total,
        system_saturated: terminal.system_saturated,
        refused_inserts,
        interval_start_ns: terminal.interval_start_ns,
        interval_end_ns: terminal.interval_end_ns,
    })
}

/// One helper-request identity: the (cgroup, tgid, lifetime) triple
/// the resolver corroborates. Rows sharing a triple share one key.
pub type KeyTriple = (u64, u32, u64);

/// Build helper request keys from joined rows: deduplicated triples
/// in deterministic (sorted) order, capped at
/// [`MAX_SNAPSHOT_ASSOCIATIONS`]. The flag reports truncation:
/// capped-out rows stay unresolved and metadata coverage reads
/// partial — keys are never silently dropped.
pub fn request_keys(
    rows: &[JoinedRow],
    kernel_scope: &str,
    session_id: &str,
) -> (SnapshotKeyBatch, bool) {
    let mut triples: Vec<KeyTriple> = rows
        .iter()
        .map(|row| (row.context.cgroup, row.context.tgid, row.context.start_ns))
        .collect();
    triples.sort_unstable();
    triples.dedup();
    let truncated = triples.len() > MAX_SNAPSHOT_ASSOCIATIONS;
    triples.truncate(MAX_SNAPSHOT_ASSOCIATIONS);
    let keys = triples
        .into_iter()
        .map(|(cgroup, tgid, start_ns)| SnapshotKey {
            kernel_scope: kernel_scope.to_string(),
            cgroup,
            tgid,
            start_ns,
        })
        .collect();
    (
        SnapshotKeyBatch {
            session_id: session_id.to_string(),
            keys,
        },
        truncated,
    )
}

/// Split keys into request batches that each fit the frozen 4 KiB
/// encoder budget (finding C3): greedy pack using `encode_request`
/// itself as the measure, so the split tracks the contract exactly
/// (byte budget, not just the 256-association count). Batches keep
/// the input order; every emitted batch encodes within budget. A
/// lone key always fits (bounded key + envelope ≪ budget); if one
/// ever did not, it ships alone and the serve refuses it typed —
/// the split never invents a refusal of its own.
fn split_request_batches(
    session_id: &str,
    keys: Vec<SnapshotKey>,
    interval: SnapshotInterval,
) -> Vec<SnapshotRequest> {
    let mut batches = Vec::new();
    let mut current: Vec<SnapshotKey> = Vec::new();
    for key in keys {
        current.push(key);
        let probe = SnapshotRequest {
            session_id: session_id.to_string(),
            keys: current.clone(),
            capture_interval: Some(interval),
        };
        if encode_request(&probe).is_err() {
            let overflow = current.pop().expect("probed non-empty");
            if current.is_empty() {
                batches.push(SnapshotRequest {
                    session_id: session_id.to_string(),
                    keys: vec![overflow],
                    capture_interval: Some(interval),
                });
            } else {
                batches.push(SnapshotRequest {
                    session_id: session_id.to_string(),
                    keys: std::mem::take(&mut current),
                    capture_interval: Some(interval),
                });
                current.push(overflow);
            }
        }
    }
    if !current.is_empty() {
        batches.push(SnapshotRequest {
            session_id: session_id.to_string(),
            keys: current,
            capture_interval: Some(interval),
        });
    }
    batches
}

/// Helper request keys plus their session binding (the caller adds the
/// counted capture interval when established).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotKeyBatch {
    /// Session id shared with the report (binds request ↔ response).
    pub session_id: String,
    /// Deduplicated, bounded request keys.
    pub keys: Vec<SnapshotKey>,
}

/// Mint a workload session id: 16 random bytes as 32 lowercase hex
/// chars. Failure (no randomness source) is an internal error — the
/// report cannot exist without its session binding.
pub fn mint_session_id() -> Result<String, WorkloadError> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| WorkloadError::SessionMintFailed)?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write;
        write!(id, "{byte:02x}").expect("hex push");
    }
    Ok(id)
}

/// Index a bound helper response by request triple: association
/// identity + evidence per answered key. Per-key errors and missing
/// keys are simply absent — those rows resolve unresolved.
pub fn resolutions_from_response(
    response: &SnapshotResponse,
) -> HashMap<KeyTriple, (WorkloadIdentity, AttributionEvidence)> {
    response
        .associations
        .iter()
        .map(|assoc| {
            (
                (assoc.key.cgroup, assoc.key.tgid, assoc.key.start_ns),
                (assoc.identity.clone(), assoc.evidence.clone()),
            )
        })
        .collect()
}

/// The bare unresolved row: no identity, unresolved hook-context
/// evidence — matching the frozen raw-id fixture shape (stays
/// implicit on the wire, renders explicit `unknown`).
fn unresolved_row() -> (WorkloadIdentity, AttributionEvidence) {
    (
        WorkloadIdentity::none(),
        AttributionEvidence::unresolved(Relationship::HookContext),
    )
}

/// Whether an attribution status establishes workload identity for
/// coverage purposes: verified/asserted count as attributed;
/// unresolved/ambiguous/unsupported do not — and neither does stale
/// (finding C2): a stale binding keeps its identity on the row but
/// never qualifies as complete attribution, so the report reads
/// PARTIAL and the row stays counted-unresolved per ADR-0012.
fn status_is_attributed(status: AttributionStatus) -> bool {
    matches!(
        status,
        AttributionStatus::Verified | AttributionStatus::Asserted
    )
}

/// Fold joined rows plus resolutions into typed assembly input rows.
/// Rows without a resolution stay explicitly unresolved in their own
/// context rows — never promoted, never merged, never host rows.
pub fn input_rows(
    rows: &[JoinedRow],
    resolutions: &HashMap<KeyTriple, (WorkloadIdentity, AttributionEvidence)>,
) -> Vec<ReportRowInput> {
    rows.iter()
        .map(|row| {
            let triple = (row.context.cgroup, row.context.tgid, row.context.start_ns);
            let (identity, evidence) = resolutions
                .get(&triple)
                .cloned()
                .unwrap_or_else(unresolved_row);
            ReportRowInput {
                context: row.context,
                calls: row.calls,
                native: row.native.clone(),
                identity,
                evidence,
            }
        })
        .collect()
}

/// Metadata coverage for one session: unavailable availability
/// reads unavailable; answered clean (no per-key errors across any
/// chunk, no key truncation) is complete; answered with per-key
/// errors, key truncation, or no answer at all is partial.
#[must_use]
pub fn metadata_coverage(
    availability: &MetadataAvailability,
    answered: bool,
    response_errors: bool,
    keys_truncated: bool,
) -> CoverageLevel {
    match availability {
        MetadataAvailability::Unavailable(_) => CoverageLevel::Unavailable,
        MetadataAvailability::Available => {
            if answered && !response_errors && !keys_truncated {
                CoverageLevel::Complete
            } else {
                CoverageLevel::Partial
            }
        }
    }
}

/// Attribution coverage over assembly input rows: complete when every
/// row carries an attributed status, partial otherwise (vacuously
/// complete for empty reports — nothing to attribute).
#[must_use]
pub fn attribution_coverage(rows: &[ReportRowInput]) -> CoverageLevel {
    if rows
        .iter()
        .all(|row| status_is_attributed(row.evidence.status))
    {
        CoverageLevel::Complete
    } else {
        CoverageLevel::Partial
    }
}

/// Live assembly input: joined capture, helper outcome, and the
/// view the report carries (selector + partition + grouping).
#[derive(Debug, Clone)]
pub struct LiveAssembly {
    /// Session id shared with the helper request (binds the report).
    pub session_id: String,
    /// Execution-kernel scope tag (`osrelease/boot_id`).
    pub kernel_scope: String,
    /// Capture profile name (`api-returns` — workload views refuse
    /// any other profile at the argument layer).
    pub profile: String,
    /// Joined capture rows + ledger operands + interval.
    pub capture: WorkloadCapture,
    /// Typed assembly input rows (joined rows + resolutions folded).
    pub rows: Vec<ReportRowInput>,
    /// Applied workload selector (a view, never confinement).
    pub selector: ReportSelector,
    /// Selector partition over the observed population.
    pub partition: ScopePartition,
    /// Declared row grouping (a rendering axis, never a recount).
    pub group_by: GroupBy,
    /// Metadata availability + coverage (one helper outcome).
    pub metadata: MetadataAvailability,
    /// Independent coverage.
    pub coverage: ReportCoverage,
}

/// Assemble one live typed report through the frozen entry point.
/// Consistency is ALWAYS [`SnapshotConsistency::Unproven`] (Stage 1
/// disposition: no fence soundness proof, so the ledger exports
/// `gap_unreconciled` with unknown 0 — never an exact unknown).
pub fn assemble_live(input: LiveAssembly) -> Result<WorkloadReport, WorkloadError> {
    assemble(AssemblyInput {
        session_id: input.session_id,
        kernel_identity: input.kernel_scope,
        interval_start_ns: input.capture.interval_start_ns,
        interval_end_ns: input.capture.interval_end_ns,
        consistency: SnapshotConsistency::Unproven,
        profile: input.profile,
        system_total: CountOperand {
            value: input.capture.system_total,
            saturated: input.capture.system_saturated,
            population: "global".to_string(),
        },
        per_context_saturated: false,
        refused_inserts: input.capture.refused_inserts,
        rows: input.rows,
        partition: input.partition,
        selector: input.selector,
        group_by: input.group_by,
        metadata: input.metadata,
        coverage: input.coverage,
    })
    .map_err(WorkloadError::Build)
}

/// Compute the exact partition behind a `--filter-cgroup-id` view:
/// each report row decides exactly once (match/non-match/unknown)
/// over per-row observations projected from the live aggregate rows
/// (native tuple from the aggregate dictionary, quantities and event
/// context from the row — `KCTX` carries no comm, so comm-constrained
/// rules stay honestly unevaluable downstream).
pub fn scope_for_filter(
    rows: &[ReportRowInput],
    agg_obs: &[NativeObservation],
    cgroup_id: u64,
) -> Result<ScopePartition, WorkloadError> {
    use kryprobe_policy::workload::{ScopedRow, WorkloadSelector, scope_rows};
    let selector =
        WorkloadSelector::cgroup(cgroup_id).map_err(|err| WorkloadError::Scope(err.to_string()))?;
    let observations = observations_for_rows(rows, agg_obs)?;
    let scoped: Vec<ScopedRow<'_>> = rows
        .iter()
        .zip(observations.iter())
        .map(|(row, observation)| ScopedRow {
            calls: row.calls,
            context: row.context,
            identity: row.identity.clone(),
            evidence: row.evidence.clone(),
            observation,
        })
        .collect();
    scope_rows(&selector, &scoped)
        .map(|outcome| outcome.partition)
        .map_err(|err| WorkloadError::Scope(err.to_string()))
}

/// Scoped-evidence marker key (SEM04): this payload describes one
/// report row's population, never the system aggregate.
pub const SCOPED_SCOPE_KEY: &str = "evidence_scope";
/// Scoped-evidence marker value: row-scoped evidence.
pub const SCOPED_SCOPE_ROW: &str = "row";
/// Captured event context block of one scoped row.
pub const SCOPED_EVENT_KEY: &str = "event";
/// Separately labeled back-reference to the system template
/// observation one scoped row was projected from.
pub const SCOPED_AGGREGATE_KEY: &str = "aggregate_obs";

/// Project one scoped observation per report row (matched by the
/// `key_hash` payload both paths derive from the same `kh`). The
/// native tuple (row discriminator, hash, family/op/result,
/// algorithm/driver/context) and the capture labels come from the
/// aggregate template dictionary; quantities (`counts.calls`) and
/// the event context (cgroup/tgid/start/uid) come from the row.
/// System-only tallies (`bytes`, latency, window, `ok`/`errors`/
/// `queued`) and the system window timestamps are omitted, never
/// restamped under the row's uid — and the template survives only as
/// the separately labeled [`SCOPED_AGGREGATE_KEY`] back-reference.
/// Fresh positional session-scoped ids number the projection in row
/// order.
pub fn observations_for_rows(
    rows: &[ReportRowInput],
    agg_obs: &[NativeObservation],
) -> Result<Vec<NativeObservation>, WorkloadError> {
    use kryprobe_core::evidence::payload_keys as K;
    let mut by_kh: HashMap<u64, &NativeObservation> = HashMap::with_capacity(agg_obs.len());
    for obs in agg_obs {
        if let Some(kh) = obs.backend_payload.get("key_hash").and_then(|v| v.as_u64()) {
            by_kh.entry(kh).or_insert(obs);
        }
    }
    let mut out = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let Some(template) = by_kh.get(&row.context.kh) else {
            return Err(WorkloadError::ObservationMissing(row.context.kh));
        };
        let mut obs = (*template).clone();
        obs.id = ObservationId::new(index as u64 + 1);
        let dictionary = &template.backend_payload;
        let mut scoped = serde_json::Map::new();
        // Native tuple, status annotation, and capture labels: the
        // template dictionary's allowed facts (copied only when the
        // template carries them — never invented).
        for key in [
            K::ROW,
            K::KEY_HASH,
            K::FAMILY,
            K::OP,
            K::RESULT,
            K::ALGORITHM,
            K::DRIVER,
            K::CONTEXT,
            K::STATUS_CANONICAL,
            K::CAPTURE_PROFILE,
            K::COUNT_UNIT,
            K::COMPLETION_COVERAGE,
            K::EXECUTION,
            K::RESULT_NOTE,
        ] {
            if let Some(value) = dictionary.get(key) {
                scoped.insert(key.to_owned(), value.clone());
            }
        }
        // Quantities and event context: the row's own facts. Every
        // other template key (system tallies, latency, window, flat
        // legacy quantities) stays out.
        scoped.insert(
            K::COUNTS.to_owned(),
            serde_json::json!({"calls": row.calls}),
        );
        scoped.insert(K::UID.to_owned(), serde_json::json!(row.context.uid));
        scoped.insert(
            SCOPED_SCOPE_KEY.to_owned(),
            serde_json::json!(SCOPED_SCOPE_ROW),
        );
        scoped.insert(
            SCOPED_EVENT_KEY.to_owned(),
            serde_json::json!({
                "cgroup": row.context.cgroup,
                "tgid": row.context.tgid,
                "start_ns": row.context.start_ns,
                "uid": row.context.uid,
            }),
        );
        scoped.insert(
            SCOPED_AGGREGATE_KEY.to_owned(),
            serde_json::json!(template.id.to_string()),
        );
        obs.backend_payload = serde_json::Value::Object(scoped);
        // The system window timestamps are not row facts.
        obs.started_ns = None;
        obs.ended_ns = None;
        out.push(obs);
    }
    Ok(out)
}

/// One command's post-capture workload view: grouping, optional
/// cgroup filter, optional metadata file, and the capture profile
/// name the report declares.
#[derive(Debug, Clone)]
pub struct WorkloadFinishOpts {
    /// Declared row grouping (a rendering axis, never a recount).
    pub group_by: GroupBy,
    /// Exact cgroup-id view (`None` reports the whole population).
    pub filter_cgroup_id: Option<u64>,
    /// Optional metadata file feeding the helper serve.
    pub metadata_file: Option<std::path::PathBuf>,
    /// Capture profile name (`api-returns`).
    pub profile: String,
}

/// Finished workload evidence: the typed report plus the exact
/// assembly input rows behind it (scoped checks evaluate the same
/// rows the report renders — one population, two views).
#[derive(Debug, Clone)]
pub struct WorkloadFinish {
    /// The assembled typed report.
    pub report: WorkloadReport,
    /// The assembly input rows (for scoped evaluation).
    pub rows: Vec<ReportRowInput>,
}

/// Serve metadata and assemble one typed report (post-capture only):
/// the helper serve is bounded and separate from BPF drain/stop (the
/// drain stopped inside the session before this runs). Missing
/// capture, an unmintable session, or an inconsistent join refuses
/// [`WorkloadError`] (exit 1 at integration); helper failure is data
/// (raw-ID rows + typed unavailability), never an error here.
pub fn finish_workload_report(
    outcome: &LiveOutcome,
    opts: &WorkloadFinishOpts,
) -> Result<WorkloadFinish, WorkloadError> {
    let Some(capture) = outcome.workload_capture.as_ref() else {
        return Err(WorkloadError::Scope("workload capture missing".to_string()));
    };
    // The preflight pins helper + principal + kernel scope (or names
    // why metadata is unavailable); a missing preflight fails closed
    // to an unavailable helper (raw-ID rows, never a guess). The
    // kernel scope tag is required either way: the report cannot
    // exist without its execution-kernel binding.
    let preflight = outcome.workload_preflight.as_ref();
    let launchable = preflight.is_some_and(|p| p.launchable());
    let kernel_scope = preflight
        .and_then(|p| p.kernel_scope.clone())
        .unwrap_or_default();
    if kernel_scope.is_empty() {
        return Err(WorkloadError::Scope("kernel scope unreadable".to_string()));
    }
    let session_id = mint_session_id()?;
    let (batch, keys_truncated) = request_keys(&capture.rows, &kernel_scope, &session_id);
    let mut availability = match preflight {
        Some(p) => p
            .unavailable
            .map(MetadataAvailability::Unavailable)
            .unwrap_or(MetadataAvailability::Available),
        None => MetadataAvailability::Unavailable(MetadataUnavailable::HelperRefused),
    };
    let mut resolutions: HashMap<KeyTriple, (WorkloadIdentity, AttributionEvidence)> =
        HashMap::new();
    let mut answered = false;
    let mut response_errors = false;
    if launchable {
        let preflight = preflight.expect("launchable preflight");
        let helper = preflight.helper.as_ref().expect("launchable helper");
        let identity = preflight
            .helper_identity
            .as_ref()
            .expect("launchable identity");
        // The serve re-verifies the preflight pin and fd-execs the
        // same image (C1 A1): a post-preflight replacement refuses.
        let pinned = PinnedHelper {
            path: helper.clone(),
            identity: *identity,
        };
        let principal = preflight.principal.as_ref().expect("launchable principal");
        // Byte-budget batches (finding C3): every chunk encodes
        // within budget, binds to its own request inside the serve,
        // and merges here (keys disjoint across chunks, total bounded
        // by the input keys). Any chunk failure degrades the whole
        // serve, exactly as the old single request did.
        let interval = SnapshotInterval {
            start_ns: capture.interval_start_ns,
            end_ns: capture.interval_end_ns,
        };
        let batches = split_request_batches(&batch.session_id, batch.keys, interval);
        let mut merged: HashMap<KeyTriple, (WorkloadIdentity, AttributionEvidence)> =
            HashMap::new();
        // Zero captured keys split into zero requests: preserve the
        // frozen empty-request refusal (C2 C5) — an empty key set is
        // what `SnapshotRequest::validate` refuses with `ParseFailed`
        // (snapshot.rs), so the finish degrades exactly as if that
        // single empty request had been encoded: typed refusal, no
        // answer, never `Available`.
        let mut failed: Option<MetadataUnavailable> = None;
        if batches.is_empty() {
            failed = Some(MetadataUnavailable::ParseFailed);
        }
        for request in &batches {
            match serve_pinned_snapshot(&pinned, principal, opts.metadata_file.as_deref(), request)
            {
                Ok(served) => {
                    response_errors |= !served.errors.is_empty();
                    merged.extend(resolutions_from_response(&served));
                }
                Err(kind) => {
                    failed = Some(kind);
                    break;
                }
            }
        }
        match failed {
            None => {
                // All-or-nothing: partial chunk answers never reach
                // the rows (a failed serve folds raw-ID rows, as
                // before — enrichment degrades, never half-applies).
                resolutions = merged;
                answered = true;
                availability = MetadataAvailability::Available;
            }
            Some(kind) => {
                availability = MetadataAvailability::Unavailable(kind);
            }
        }
    }
    finish_with_response(
        capture,
        opts,
        batch.session_id,
        &kernel_scope,
        &resolutions,
        &availability,
        answered,
        response_errors,
        keys_truncated,
        outcome,
    )
}

/// Fold one helper outcome (merged chunk resolutions or typed
/// unavailability) into the typed report: resolutions attach to
/// rows, coverage reads the outcome, the selector partitions the
/// observed population.
#[allow(clippy::too_many_arguments)]
fn finish_with_response(
    capture: &WorkloadCapture,
    opts: &WorkloadFinishOpts,
    session_id: String,
    kernel_scope: &str,
    resolutions: &HashMap<KeyTriple, (WorkloadIdentity, AttributionEvidence)>,
    availability: &MetadataAvailability,
    answered: bool,
    response_errors: bool,
    keys_truncated: bool,
    outcome: &LiveOutcome,
) -> Result<WorkloadFinish, WorkloadError> {
    let rows = input_rows(&capture.rows, resolutions);
    // Capture coverage is partial by construction while the ledger
    // is unproven (Stage 1 disposition: the exact unknown is
    // unavailable, so the capture account is incomplete); correlation
    // is complete for the declared M1 boundary (one observation
    // boundary — nothing to correlate across).
    let coverage = kryprobe_report::workload::ReportCoverage {
        capture: CoverageLevel::Partial,
        attribution: attribution_coverage(&rows),
        metadata: metadata_coverage(availability, answered, response_errors, keys_truncated),
        correlation: CoverageLevel::Complete,
    };
    let (selector, partition) = match opts.filter_cgroup_id {
        None => {
            let sum: u64 = rows.iter().map(|row| row.calls).sum();
            (
                ReportSelector::None,
                ScopePartition::from_counts(sum, 0, 0).map_err(WorkloadError::Scope)?,
            )
        }
        Some(id) => (
            ReportSelector::CgroupId(id),
            scope_for_filter(&rows, &outcome.observations, id)?,
        ),
    };
    let report = assemble_live(LiveAssembly {
        session_id,
        kernel_scope: kernel_scope.to_string(),
        profile: opts.profile.clone(),
        capture: capture.clone(),
        rows: rows.clone(),
        selector,
        partition,
        group_by: opts.group_by,
        metadata: *availability,
        coverage,
    })?;
    Ok(WorkloadFinish { report, rows })
}

/// Pre-capture metadata gate: the file must exist, be a regular
/// file, and fit the metadata byte budget. Stats only — content is
/// NEVER read here (the helper reads and validates it; the
/// privileged CLI never parses metadata bytes). Failure is a usage
/// error (exit 2), reported before capture starts.
pub fn precheck_metadata_file(
    tool: &str,
    path: &std::path::Path,
    stderr: &mut dyn std::io::Write,
) -> Result<(), i32> {
    use kryprobe_core::workload::MAX_METADATA_BYTES;
    let meta = std::fs::symlink_metadata(path);
    let usable = meta.as_ref().is_ok_and(|m| m.file_type().is_file())
        && meta
            .as_ref()
            .is_ok_and(|m| m.len() <= MAX_METADATA_BYTES as u64);
    if usable {
        Ok(())
    } else {
        let _ = writeln!(
            stderr,
            "{tool}: cannot use workload metadata '{}' (missing, not a regular file, or over the size budget)",
            path.display()
        );
        Err(2)
    }
}

/// Exit intent for one rendered workload report: 0 when the evidence
/// is complete, 3 when the window was cut short or the report names
/// gaps (unreconciled ledger gap or any non-complete coverage
/// dimension). Reports never violate (no policy evaluated here).
#[must_use]
pub fn workload_exit_code(report: &WorkloadReport, interrupted: bool) -> i32 {
    if interrupted
        || report.ledger.gap_unreconciled
        || report.coverage.capture != CoverageLevel::Complete
        || report.coverage.attribution != CoverageLevel::Complete
        || report.coverage.metadata != CoverageLevel::Complete
        || report.coverage.correlation != CoverageLevel::Complete
    {
        3
    } else {
        0
    }
}

/// Terminal miss section for the human workload report (finding
/// C4): per-program guard skips with the stable (section,
/// program-ID) join keys, per-operation run qualification, and
/// unavailable reasons verbatim. Sorted by (section, program ID)
/// for determinism. Global telemetry only — never distributed
/// across context rows (rows render from the frozen report, which
/// this section does not touch).
pub fn render_miss_section(misses: Option<&MissTerminal>) -> String {
    let Some(misses) = misses else {
        return "misses: unavailable (not collected)\n".to_owned();
    };
    match misses {
        MissTerminal::Available(deltas) => {
            let mut deltas: Vec<_> = deltas.iter().collect();
            deltas.sort_by(|a, b| (&a.section, a.program_id).cmp(&(&b.section, b.program_id)));
            let mut text = format!("misses: {} program(s)\n", deltas.len());
            for delta in deltas {
                let run = delta
                    .run_delta
                    .map_or("unavailable".to_owned(), |run| run.to_string());
                text.push_str(&format!(
                    "  {} id={} baseline={} current={} delta={} run={}\n",
                    sanitize_cell(&delta.section),
                    delta.program_id,
                    delta.miss_baseline,
                    delta.miss_current,
                    delta.miss_delta,
                    run,
                ));
            }
            text
        }
        MissTerminal::Unavailable { reason } => {
            format!("misses: unavailable ({})\n", sanitize_cell(reason))
        }
    }
}

/// Human workload report text: the frozen report rendering plus the
/// terminal miss section (finding C4). The JSON format stays pure
/// (frozen schema — misses ride text + stderr telemetry only).
pub fn render_workload_text(outcome: &LiveOutcome, finished: &WorkloadFinish) -> String {
    let mut text = finished.report.render_text();
    text.push_str(&render_miss_section(outcome.workload_misses.as_ref()));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_watch::fixtures::agg_obs;
    use kryprobe_abi::kcrypto_ctx::{KCtxKey, VCtx};
    use kryprobe_core::workload::{
        ContainerRef, KernelIdentity, MetadataEntry, MetadataSnapshot, Relationship,
        SnapshotInterval, SnapshotRequest, ValidityInterval, validate_session_id,
    };
    use kryprobe_report::workload::{ReportLedger, ReportScope, ReportSession, report_from_bytes};

    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const SCOPE: &str = "test-release/test-boot-id";

    fn native(family: u8, algorithm: &str, driver: Option<&str>) -> NativeIdentity {
        NativeIdentity::new(family, 2, 0, 0, algorithm, driver)
    }

    fn parsed(kh: u64, native: NativeIdentity) -> ParsedNative {
        ParsedNative {
            kh,
            native,
            kind: ExecutionKind::Proc,
        }
    }

    fn ctx_row(kh: u64, cgroup: u64, tgid: u32, calls: u64) -> CtxSnapshot {
        CtxSnapshot {
            key: KCtxKey {
                kh,
                cgroup,
                tgid,
                uid: 1000,
                start_ns: 555,
            },
            val: VCtx {
                calls,
                ..VCtx::default()
            },
        }
    }

    #[test]
    fn join_matches_each_context_to_its_native() {
        let natives = vec![
            parsed(7, native(1, "cbc(aes)", Some("aesni"))),
            parsed(9, native(2, "sha256", None)),
        ];
        let ctx = vec![ctx_row(7, 42, 100, 5), ctx_row(9, 43, 101, 8)];
        let rows = join_ctx_rows(&ctx, &natives).expect("joins");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].calls, 5);
        assert_eq!(rows[0].native.algorithm, "cbc(aes)");
        assert_eq!(rows[0].context.cgroup, 42);
        assert_eq!(rows[1].native.driver, None);
        // Identical re-inserts (same kh, same native) are idempotent.
        let mut doubled = natives.clone();
        doubled.extend(natives.clone());
        assert_eq!(join_ctx_rows(&ctx, &doubled).expect("joins").len(), 2);
    }

    #[test]
    fn join_refuses_missing_and_ambiguous_natives() {
        let natives = vec![parsed(7, native(1, "cbc(aes)", Some("aesni")))];
        assert_eq!(
            join_ctx_rows(&[ctx_row(8, 42, 100, 5)], &natives),
            Err(WorkloadError::NativeUnknown(8))
        );
        let colliding = vec![
            parsed(7, native(1, "cbc(aes)", Some("aesni"))),
            parsed(7, native(1, "ecb(aes)", Some("aesni"))),
        ];
        assert_eq!(
            join_ctx_rows(&[ctx_row(7, 42, 100, 5)], &colliding),
            Err(WorkloadError::AmbiguousNative(7))
        );
    }

    #[test]
    fn execution_kind_decodes_native_context_codes() {
        assert_eq!(execution_kind_for_ctx(0), ExecutionKind::Proc);
        assert_eq!(execution_kind_for_ctx(1), ExecutionKind::Kthread);
        assert_eq!(execution_kind_for_ctx(2), ExecutionKind::Softirq);
        assert_eq!(execution_kind_for_ctx(3), ExecutionKind::Unknown);
        assert_eq!(execution_kind_for_ctx(9), ExecutionKind::Unknown);
    }

    #[test]
    fn request_keys_dedupe_sort_and_cap() {
        let natives = vec![parsed(7, native(1, "a", None))];
        let rows = join_ctx_rows(
            &[
                ctx_row(7, 9, 3, 1),
                ctx_row(7, 9, 3, 2),
                ctx_row(7, 5, 1, 3),
            ],
            &natives,
        )
        .expect("joins");
        let (batch, truncated) = request_keys(&rows, SCOPE, SESSION);
        assert!(!truncated);
        assert_eq!(batch.session_id, SESSION);
        // Sorted ((5,1,555) before (9,3,555)), deduplicated.
        assert_eq!(batch.keys.len(), 2);
        assert_eq!(batch.keys[0].cgroup, 5);
        assert_eq!(batch.keys[1].cgroup, 9);
        // 300 distinct triples cap at the frozen association bound.
        let many: Vec<CtxSnapshot> = (0..300)
            .map(|i| ctx_row(7, 1000 + i, i as u32, 1))
            .collect();
        let rows = join_ctx_rows(&many, &natives).expect("joins");
        let (batch, truncated) = request_keys(&rows, SCOPE, SESSION);
        assert!(truncated);
        assert_eq!(batch.keys.len(), MAX_SNAPSHOT_ASSOCIATIONS);
    }

    #[test]
    fn session_ids_mint_32_hex() {
        let first = mint_session_id().expect("mints");
        let second = mint_session_id().expect("mints");
        for id in [&first, &second] {
            validate_session_id(id).expect("32 lowercase hex");
        }
        assert_ne!(first, second, "mints are unique");
    }

    fn capture_two_rows() -> (WorkloadCapture, Vec<ParsedNative>) {
        let natives = vec![
            parsed(7, native(1, "cbc(aes)", Some("aesni"))),
            parsed(9, native(4, "md5", Some("md5-generic"))),
        ];
        let terminal = TerminalWorkload {
            natives: natives.clone(),
            system_total: 30,
            system_saturated: false,
            interval_start_ns: 100,
            interval_end_ns: 1000,
        };
        let capture = join_capture(
            &terminal,
            &[ctx_row(7, 42, 100, 20), ctx_row(9, 43, 101, 10)],
            0,
        )
        .expect("joins");
        (capture, natives)
    }

    fn assemble_two_rows(capture: &WorkloadCapture, rows: Vec<ReportRowInput>) -> WorkloadReport {
        let sum: u64 = rows.iter().map(|row| row.calls).sum();
        assemble_live(LiveAssembly {
            session_id: SESSION.to_string(),
            kernel_scope: SCOPE.to_string(),
            profile: "api-returns".to_string(),
            capture: capture.clone(),
            rows,
            selector: ReportSelector::None,
            partition: ScopePartition::from_counts(sum, 0, 0).expect("partition"),
            group_by: GroupBy::Cgroup,
            metadata: MetadataAvailability::Unavailable(MetadataUnavailable::NoPrincipal),
            coverage: ReportCoverage {
                capture: CoverageLevel::Partial,
                attribution: CoverageLevel::Partial,
                metadata: CoverageLevel::Unavailable,
                correlation: CoverageLevel::Complete,
            },
        })
        .expect("assembles")
    }

    #[test]
    fn live_report_exports_gap_never_exact_unknown() {
        // Raw-ID capture (no helper): rows stay unresolved, the ledger
        // exports the gap with unknown 0, the exit names partial.
        let (capture, _) = capture_two_rows();
        let rows = input_rows(&capture.rows, &HashMap::new());
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.identity, WorkloadIdentity::none());
            assert_eq!(
                row.evidence,
                AttributionEvidence::unresolved(Relationship::HookContext)
            );
        }
        let report = assemble_two_rows(&capture, rows);
        assert!(report.ledger.gap_unreconciled);
        assert_eq!(report.ledger.unknown, 0);
        assert_eq!(report.ledger.per_context_sum, 30);
        assert_eq!(report.ledger.system_total, 30);
        // Bare unresolved rows stay implicit on the wire (frozen
        // raw-id fixture shape) and render explicit unknown.
        for row in &report.rows {
            assert!(row.workload.is_none());
            assert!(row.evidence.is_none());
        }
        assert_eq!(workload_exit_code(&report, false), 3);
        let text = report.render_text();
        assert!(text.contains("gap unreconciled"), "{text}");
        assert!(text.contains("unavailable (no_principal)"), "{text}");
    }

    fn asserted_response() -> SnapshotResponse {
        // One Asserted association via the frozen pure resolver: the
        // file claims cgroup 42 with a validity covering the counted
        // interval; cgroup 43 has no entry (stays unresolved).
        let request = SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: vec![
                kryprobe_core::workload::SnapshotKey {
                    kernel_scope: SCOPE.to_string(),
                    cgroup: 42,
                    tgid: 100,
                    start_ns: 555,
                },
                kryprobe_core::workload::SnapshotKey {
                    kernel_scope: SCOPE.to_string(),
                    cgroup: 43,
                    tgid: 101,
                    start_ns: 555,
                },
            ],
            capture_interval: Some(SnapshotInterval {
                start_ns: 100,
                end_ns: 1000,
            }),
        };
        let snapshot = MetadataSnapshot {
            collector: "workload-test".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: 100,
                end_ns: 1000,
            },
            kernel_identity: KernelIdentity::Known(SCOPE.to_string()),
            entries: vec![MetadataEntry {
                container: Some(ContainerRef {
                    runtime: "docker://host-a".to_string(),
                    id: "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57"
                        .to_string(),
                    lifetime: None,
                }),
                pod: None,
                cluster: None,
                node: None,
                ancestor_container: None,
                display_name: None,
                cgroup_id: Some(42),
                binding: kryprobe_core::workload::BindingProvenance {
                    method: kryprobe_core::workload::METHOD_METADATA_FILE.to_string(),
                    source: kryprobe_core::workload::WorkloadOrigin::OperatorMetadataFile,
                    status: AttributionStatus::Asserted,
                    validity: Some(ValidityInterval::monotonic(100, 1000)),
                },
            }],
        };
        kryprobe_core::workload::resolve(&request, &snapshot).expect("resolves")
    }

    #[test]
    fn attributed_rows_carry_identity_and_evidence() {
        let (capture, _) = capture_two_rows();
        let response = asserted_response();
        assert!(response.errors.is_empty());
        let resolutions = resolutions_from_response(&response);
        assert_eq!(resolutions.len(), 2);
        let rows = input_rows(&capture.rows, &resolutions);
        // Cgroup 42 asserted; cgroup 43 explicitly unresolved.
        assert!(rows[0].identity.is_resolved());
        assert_eq!(rows[0].evidence.status, AttributionStatus::Asserted);
        assert_eq!(rows[1].identity, WorkloadIdentity::none());
        assert_eq!(rows[1].evidence.status, AttributionStatus::Unresolved);
        assert_eq!(attribution_coverage(&rows), CoverageLevel::Partial);
        let all = vec![rows[0].clone()];
        assert_eq!(attribution_coverage(&all), CoverageLevel::Complete);
        assert_eq!(attribution_coverage(&[]), CoverageLevel::Complete);
        // Metadata coverage follows the helper outcome, never the rows.
        assert!(response.errors.is_empty());
        assert_eq!(
            metadata_coverage(&MetadataAvailability::Available, true, false, false),
            CoverageLevel::Complete
        );
        assert_eq!(
            metadata_coverage(&MetadataAvailability::Available, true, false, true),
            CoverageLevel::Partial
        );
        assert_eq!(
            metadata_coverage(&MetadataAvailability::Available, true, true, false),
            CoverageLevel::Partial
        );
        assert_eq!(
            metadata_coverage(&MetadataAvailability::Available, false, false, false),
            CoverageLevel::Partial
        );
        assert_eq!(
            metadata_coverage(
                &MetadataAvailability::Unavailable(MetadataUnavailable::NoPrincipal),
                false,
                false,
                false
            ),
            CoverageLevel::Unavailable
        );
    }

    #[test]
    fn splitter_packs_by_byte_budget() {
        // 256 max-scope keys: every emitted batch fits the budget,
        // their union covers the input exactly once, in order.
        let keys: Vec<SnapshotKey> = (0..256u64)
            .map(|i| SnapshotKey {
                kernel_scope: "s".repeat(128),
                cgroup: i,
                tgid: i as u32,
                start_ns: i,
            })
            .collect();
        let batches = split_request_batches(
            "0123456789abcdef0123456789abcdef",
            keys,
            SnapshotInterval {
                start_ns: 100,
                end_ns: 1000,
            },
        );
        assert!(batches.len() > 1, "max-scope keys split: {}", batches.len());
        let mut seen = Vec::new();
        for batch in &batches {
            encode_request(batch).expect("batch fits the budget");
            assert_eq!(batch.session_id, "0123456789abcdef0123456789abcdef");
            seen.extend(batch.keys.iter().map(|key| key.cgroup));
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..256u64).collect::<Vec<_>>());
        // A small batch stays whole.
        let small: Vec<SnapshotKey> = (0..3u64)
            .map(|i| SnapshotKey {
                kernel_scope: "test-scope".to_string(),
                cgroup: i,
                tgid: i as u32,
                start_ns: i,
            })
            .collect();
        let single = split_request_batches(
            "0123456789abcdef0123456789abcdef",
            small,
            SnapshotInterval {
                start_ns: 100,
                end_ns: 1000,
            },
        );
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].keys.len(), 3);
    }

    #[test]
    fn filter_partition_is_exact_per_row() {
        let natives = vec![parsed(7, native(1, "a", None))];
        let capture = join_capture(
            &TerminalWorkload {
                natives,
                system_total: 100,
                system_saturated: false,
                interval_start_ns: 100,
                interval_end_ns: 1000,
            },
            &[
                ctx_row(7, 5, 1, 20),
                ctx_row(7, 5, 2, 30),
                ctx_row(7, 7, 3, 10),
                ctx_row(7, 0, 4, 5),
            ],
            0,
        )
        .expect("joins");
        let rows = input_rows(&capture.rows, &HashMap::new());
        let mut obs = agg_obs(1, "sk", "encrypt", "ok", "a", "d", "process", 1, 1, 1, 0, 0);
        obs.backend_payload["key_hash"] = serde_json::json!(7u64);
        let partition = scope_for_filter(&rows, &[obs], 5).expect("scopes");
        assert_eq!(partition.matched(), 50);
        assert_eq!(partition.nonmatched(), 10);
        assert_eq!(partition.unknown_match(), 5);
        assert_eq!(partition.observed(), 65);
        // The unreadable marker is not selectable, even as a view.
        assert!(scope_for_filter(&rows, &[], 0).is_err());
    }

    #[test]
    fn observations_for_rows_projects_scoped_row_evidence() {
        // SEM04 unit pin: a flat legacy template (top-level
        // quantities, the review-probe shape) projects exactly like a
        // nested one — row calls in, system tallies out, marker +
        // event context on, absent template keys never invented.
        let row = ReportRowInput {
            context: ContextIdentity::new(7, 42, 1000, 1234, 555, ExecutionKind::Proc),
            calls: 5,
            native: native(1, "cbc(aes)", Some("aesni")),
            identity: WorkloadIdentity::none(),
            evidence: AttributionEvidence::unresolved(Relationship::HookContext),
        };
        let mut template = agg_obs(
            1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 100, 409600, 100, 0, 2,
        );
        template.backend_payload = serde_json::json!({
            "row": "agg",
            "key_hash": 7,
            "family": "skcipher",
            "op": "encrypt",
            "result": "ok",
            "algorithm": "cbc(aes)",
            "driver": "aesni",
            "context": "process",
            "calls": 100,
            "bytes": 409600,
            "ok": 100,
            "errors": 0,
            "queued": 2,
            "capture_profile": "api-returns",
        });
        let projected =
            observations_for_rows(std::slice::from_ref(&row), &[template]).expect("projects");
        assert_eq!(projected.len(), 1);
        let payload = &projected[0].backend_payload;
        assert_eq!(
            payload["counts"]["calls"],
            serde_json::json!(5),
            "{payload}"
        );
        assert_eq!(
            payload["counts"].as_object().expect("counts block").len(),
            1,
            "counts carries the row's calls only: {payload}"
        );
        for key in ["calls", "bytes", "ok", "errors", "queued", "lat", "window"] {
            assert!(
                payload.get(key).is_none(),
                "system-only `{key}` omitted: {payload}"
            );
        }
        assert_eq!(
            payload["evidence_scope"],
            serde_json::json!("row"),
            "{payload}"
        );
        assert_eq!(
            payload["event"]["cgroup"],
            serde_json::json!(42),
            "{payload}"
        );
        assert_eq!(
            payload["aggregate_obs"],
            serde_json::json!("observation:1"),
            "{payload}"
        );
        assert_eq!(
            payload["algorithm"],
            serde_json::json!("cbc(aes)"),
            "{payload}"
        );
        assert!(
            payload.get("status_canonical").is_none(),
            "absent template keys stay absent: {payload}"
        );
        assert_eq!(projected[0].started_ns, None);
        assert_eq!(projected[0].ended_ns, None);
        // A row without a template still refuses typed.
        assert_eq!(
            observations_for_rows(std::slice::from_ref(&row), &[]),
            Err(WorkloadError::ObservationMissing(7))
        );
    }

    #[test]
    fn scope_without_observation_refuses() {
        let natives = vec![parsed(7, native(1, "a", None))];
        let capture = join_capture(
            &TerminalWorkload {
                natives,
                system_total: 1,
                system_saturated: false,
                interval_start_ns: 100,
                interval_end_ns: 1000,
            },
            &[ctx_row(7, 5, 1, 1)],
            0,
        )
        .expect("joins");
        let rows = input_rows(&capture.rows, &HashMap::new());
        assert_eq!(
            scope_for_filter(&rows, &[], 5),
            Err(WorkloadError::ObservationMissing(7))
        );
    }

    #[test]
    fn exit_intent_names_gaps() {
        let complete = WorkloadReport {
            session: ReportSession {
                session_id: SESSION.to_string(),
                kernel_identity: SCOPE.to_string(),
            },
            interval: kryprobe_report::workload::ReportInterval {
                start_ns: 100,
                end_ns: 1000,
                consistency: SnapshotConsistency::Quiescent,
            },
            profile: "api-returns".to_string(),
            boundary: kryprobe_core::workload::ObservationBoundary::ApiReturn,
            rows: Vec::new(),
            ledger: ReportLedger {
                system_total: 0,
                per_context_sum: 0,
                unknown: 0,
                consistency: SnapshotConsistency::Quiescent,
                gap_unreconciled: false,
                system_saturated: false,
                per_context_saturated: false,
                refused_inserts: 0,
            },
            partition: ScopePartition::from_counts(0, 0, 0).expect("partition"),
            selector: ReportSelector::None,
            scope: ReportScope::Unscoped,
            group_by: GroupBy::None,
            metadata: MetadataAvailability::Available,
            coverage: ReportCoverage {
                capture: CoverageLevel::Complete,
                attribution: CoverageLevel::Complete,
                metadata: CoverageLevel::Complete,
                correlation: CoverageLevel::Complete,
            },
        };
        assert_eq!(workload_exit_code(&complete, false), 0);
        assert_eq!(workload_exit_code(&complete, true), 3);
        let mut gapped = complete.clone();
        gapped.ledger.gap_unreconciled = true;
        assert_eq!(workload_exit_code(&gapped, false), 3);
        let mut partial = complete.clone();
        partial.coverage.metadata = CoverageLevel::Partial;
        assert_eq!(workload_exit_code(&partial, false), 3);
    }

    #[test]
    fn integers_beyond_2pow53_survive_json_exactly() {
        // Spec §5.4 integer convention: u64 magnitudes ride digit
        // strings, so values past the float exact range lose nothing.
        let big: u64 = (1 << 53) + 1;
        assert_eq!(big, 9_007_199_254_740_993);
        let natives = vec![parsed(7, native(1, "a", None))];
        let capture = join_capture(
            &TerminalWorkload {
                natives,
                system_total: big,
                system_saturated: false,
                interval_start_ns: 100,
                interval_end_ns: 1000,
            },
            &[ctx_row(7, 5, 1, big)],
            0,
        )
        .expect("joins");
        let rows = input_rows(&capture.rows, &HashMap::new());
        let report = assemble_two_rows(&capture, rows);
        let bytes = report.to_json_bytes().expect("encodes");
        let text = String::from_utf8(bytes).expect("utf-8");
        assert!(
            text.contains("\"9007199254740993\""),
            "calls ride a digit string: {text}"
        );
        let replay = report_from_bytes(text.as_bytes()).expect("replays");
        assert_eq!(replay.rows[0].calls, big);
        assert_eq!(replay.ledger.system_total, big);
    }
}
