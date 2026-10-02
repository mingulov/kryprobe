// SPDX-License-Identifier: GPL-3.0-or-later
//! Task 2 conformance: batch `BackendDriver::run` vs the live tick-loop
//! sessions (`drive_session`, `drive_lifecycle_session`).
//!
//! Contract: ADR-0007 invariants I1–I5 — same scripted stream in, equal
//! observations + coverage out, modulo id/clock normalization. Both
//! sides decode through the SAME test-backend implementation passed to
//! both drivers (I5); the live side takes `&dyn Backend` directly (no
//! registry lookup on the live path by design — bring-up selection at
//! `live.rs:2160` is outside the compared unit), so the harness wires
//! the shared implementation explicitly and probes decode-equality
//! through both handles.
//!
//! Scoping (written reasons, not silent narrowing):
//! - Who attribution is live-owned (ADR-0007 §3: aggregate-live owns
//!   who attribution via `observation_for_who`, ids minted directly
//!   from the session issuer at `live.rs:1658-1660`, bypassing
//!   `Backend::decode`). The batch driver can only produce decode
//!   outputs, so who rows can never conformance-compare: the harness
//!   scripts ZERO who rows. Excluded by construction, never masked by
//!   normalization. Follow-up: none — structural, blessed by the ADR.
//! - Capability-skip receipts compare vacuously (both sides skip
//!   nothing under the open harness runtime). A non-vacuous skip
//!   comparison is out of scope: `drive_session` performs no gating
//!   (gates live in bring-up, `run_live_session_inner`, outside the
//!   compared drivers per ADR-0007 §3). Follow-up: none — structural.
//! - Coverage (I2) compares live-measured coverage against the
//!   harness-supplied expectation for the scripted stream (the batch
//!   driver has no clock and emits no coverage — coverage there is
//!   input session state). Interval walls normalize away; status +
//!   counters compare exact.
//! - Duplicate-key streams are excluded by scripting: aggregate-live
//!   upserts latest-per-key (`live.rs:1609` — repeats collapse) while
//!   batch appends every decode, so equality on duplicate-key streams
//!   is untestable by design. Fixtures script distinct keys only
//!   (`agg_tick`: two distinct-key agg rows). Follow-up: none —
//!   structural.

use kryprobe_cli::live::{
    LifecycleSessionSensor, LiveConfig, SessionSensor, drive_lifecycle_session, drive_session,
};
use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendDriver, BackendPlan, BackendRegistry, BackendSummary,
    ConfigureContext, DecodeContext, DetectContext, DetectedInstance, DriverReport,
    FinalizeContext, PlanContext, RawEvent, SharedFeedError,
};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{
    BackendId, CallKind, CaptureMode, CoverageStatus, EvidencePhase, OperationClass,
};
use kryprobe_core::error::{BackendError, BudgetReason, InputReason};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCounter, DimensionCoverage, IntegrityRef, IntegritySummary,
    NativeObservation, NativeResult, SharedLosses, ValidityInterval,
};
use kryprobe_core::ids::{IdIssuer, ObservationId, PlanGeneration, SessionId};
use kryprobe_core::kcrypto::{
    LifecycleFamily, OpDirection, ReducerStats, RequestMeta, RequestRecord, Terminal,
};
use kryprobe_core::plan::CapabilityRequirements;
use kryprobe_privilege::kcrypto_backend::KDROP_SITES;
use kryprobe_privilege::kcrypto_lifecycle::async_adapter::AdapterStats;
use kryprobe_privilege::kcrypto_lifecycle::backend::lifecycle_event;
use kryprobe_privilege::kcrypto_lifecycle::decode::DecodeStats;
use kryprobe_privilege::kcrypto_lifecycle::profile::{LifecycleProfile, manifest, max_programs};
use kryprobe_privilege::kcrypto_lifecycle::sensor::{
    DrainOutcome, EnrichmentStatus, LifecycleLedger, QuietOutcome,
};
use kryprobe_privilege::kcrypto_lifecycle::tfm::TfmStats;
use kryprobe_privilege::kcrypto_snapshot::{
    IdentBytes, ParsedRow, RowBytes, SnapshotRows, TotalsBytes, parse_snapshot_row,
    raw_event_stamped,
};

// ── shared harness fixtures ──────────────────────────────────────────

/// Bring-up-walked controller: `drive_session` requires `Attaching` on
/// entry (production reaches it via gate → detect → plan → configure).
fn attached_controller() -> kryprobe_core::session::SessionController {
    use kryprobe_core::session::SessionState as S;
    let mut controller = kryprobe_core::session::SessionController::new();
    for state in [S::Qualified, S::Discovering, S::Attaching] {
        controller.transition(state).expect("bring-up hop legal");
    }
    controller
}

/// Harness runtime: the conformance backends require no host
/// capabilities, so all-false still skips nothing (I4 vacuous leg).
fn open_runtime() -> RuntimeCapabilities {
    RuntimeCapabilities {
        kernel_release: String::from("conformance-harness"),
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf_present: false,
        userns: false,
        yama_scope: 0,
        caps: Vec::new(),
    }
}

/// Open capabilities for the conformance backends (KCrypto id so
/// the batch router claims the kcrypto-wire-id scripted events — the
/// same id the live path stamps via `raw_event_stamped`).
static CONFORMANCE_CAPS: BackendCapabilities = BackendCapabilities {
    backend: BackendId::KCrypto,
    name: "conformance-kcrypto",
    required: CapabilityRequirements {
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf: false,
    },
};

// ── normalization + invariant checks (I1–I5) ─────────────────────────────
// REVIEW CHECKPOINT (self-audit): normalization strips session-issued
// ids (I1) and interval walls (I2) ONLY. Every other field compares
// exact — including `started_ns`/`ended_ns`, which both decodes stamp
// from row payload, never from a driver clock (ADR-0007 I1). No
// normalization touches counts, statuses, payloads, or verdicts, so
// no real divergence (dropped/doubled/mangled rows, misrouting,
// count or status drift) can hide behind it.

/// Strip session-issued ids: batch issues in registration × input
/// order from its own issuer, live in tick/row order — issuance order
/// is driver-owned (ADR-0007 I1).
fn strip_ids(observations: &[NativeObservation]) -> Vec<NativeObservation> {
    observations
        .iter()
        .map(|observation| {
            let mut stripped = observation.clone();
            stripped.id = ObservationId::new(0);
            stripped
        })
        .collect()
}

/// Multiset keys: canonical JSON of each id-stripped observation,
/// sorted (serde struct field order is deterministic, so string sort
/// is a canonical multiset — order-free, duplicates kept).
fn multiset_keys(observations: &[NativeObservation]) -> Vec<String> {
    let mut keys: Vec<String> = strip_ids(observations)
        .iter()
        .map(|observation| serde_json::to_string(observation).expect("observation serializes"))
        .collect();
    keys.sort();
    keys
}

/// I1: same observation multiset modulo ids. The length leg runs
/// first so a collapse/duplication fails loudly as a count mismatch
/// (multiset equality alone would still catch it, but the message
/// would obscure the shape of the divergence).
fn check_observations_i1(batch: &[NativeObservation], live: &[NativeObservation]) {
    assert_eq!(
        batch.len(),
        live.len(),
        "I1: same observation count (a collapse or duplication is divergence, not ordering)"
    );
    assert_eq!(
        multiset_keys(batch),
        multiset_keys(live),
        "I1: observation multisets agree modulo ids"
    );
}

/// All eight dimensions with names (struct order).
fn dims(coverage: &CoverageSummary) -> [(&'static str, &DimensionCoverage); 8] {
    [
        ("target_population", &coverage.target_population),
        ("object_discovery", &coverage.object_discovery),
        ("attachment", &coverage.attachment),
        ("aggregate_counts", &coverage.aggregate_counts),
        ("detailed_events", &coverage.detailed_events),
        ("attribution", &coverage.attribution),
        ("correlation", &coverage.correlation),
        ("completion", &coverage.completion),
    ]
}

/// Normalize every dimension interval to the zero wall: live walls
/// are measured `CLOCK_MONOTONIC`, the batch driver has no clock
/// (ADR-0007 I2). Status + counters + omissions + scope are untouched.
fn normalize_coverage(coverage: &CoverageSummary) -> CoverageSummary {
    let mut normalized = coverage.clone();
    let zero = ValidityInterval {
        start_ns: 0,
        end_ns: None,
    };
    normalized.target_population.interval = zero;
    normalized.object_discovery.interval = zero;
    normalized.attachment.interval = zero;
    normalized.aggregate_counts.interval = zero;
    normalized.detailed_events.interval = zero;
    normalized.attribution.interval = zero;
    normalized.correlation.interval = zero;
    normalized.completion.interval = zero;
    normalized
}

/// I2: live-measured coverage equals the harness expectation for the
/// scripted stream, modulo walls. The raw-wall leg pins what the
/// normalization drops: every wall must be exactly the scripted
/// measurement (first → closing tick), never a foreign clock.
fn check_coverage_i2(live: &CoverageSummary, expected: &CoverageSummary, wall_ns: u64) {
    for (name, dim) in dims(live) {
        assert_eq!(
            dim.interval.start_ns, wall_ns,
            "I2: {name} wall opens at the scripted first tick"
        );
        assert_eq!(
            dim.interval.end_ns,
            Some(wall_ns),
            "I2: {name} wall closes at the scripted closing tick"
        );
    }
    assert_eq!(
        normalize_coverage(live),
        normalize_coverage(expected),
        "I2: coverage agrees (status + counters exact, walls normalized)"
    );
}

/// I3: integrity agrees exact with no normalization. Both sides must
/// feed before comparing — the unfed batch report must refuse with
/// `MissingFeed` instead of totaling (ADR-0007 I3).
fn check_integrity_i3(batch: &mut DriverReport, live_integrity: &IntegritySummary) {
    assert!(
        matches!(
            batch.session_integrity_checked(),
            Err(SharedFeedError::MissingFeed)
        ),
        "I3: unfed batch side refuses instead of comparing"
    );
    batch
        .feed_shared_losses(SharedLosses::new(0, 0))
        .expect("first shared feed lands");
    let batch_integrity = batch
        .session_integrity_checked()
        .expect("fed batch side totals");
    assert_eq!(
        batch_integrity,
        IntegritySummary::default(),
        "I3: lossless script totals zero"
    );
    assert_eq!(
        batch_integrity, *live_integrity,
        "I3: integrity agrees exact, no normalization"
    );
}

/// I4: per-backend facts exact per backend; skip receipts exact (both
/// empty — the vacuous leg, see module docs).
fn check_summaries_i4(batch: &DriverReport, live_summary: &BackendSummary) {
    assert_eq!(
        batch.summaries(),
        std::slice::from_ref(live_summary),
        "I4: per-backend facts exact"
    );
    assert!(
        batch.skipped().is_empty(),
        "I4: open harness runtime skips nothing on the batch side"
    );
}

/// I5: both sides resolve the same decode implementation. Same backend
/// id, plus a behavioral probe — one scripted event decoded through
/// each handle must yield identical id-stripped observations. Runs
/// after the summaries file (the probe decodes bump both instances'
/// counters post-finalize, harmlessly).
fn check_decoder_identity_i5(
    registry_backend: &dyn Backend,
    live_backend: &dyn Backend,
    events: &[RawEvent<'_>],
) {
    assert_eq!(
        registry_backend.id(),
        live_backend.id(),
        "I5: same backend id both sides"
    );
    let event = events.first().expect("script is non-empty");
    let baseline = IntegritySummary::default();
    let decode_through = |backend: &dyn Backend| {
        let issuer = IdIssuer::default();
        let ctx = DecodeContext {
            session: SessionId::new(1),
            generation: PlanGeneration::new(1),
            integrity: &baseline,
            id_issuer: &issuer,
        };
        backend
            .decode(&ctx, *event)
            .expect("probe decode drives green")
    };
    let mut via_registry = decode_through(registry_backend);
    let mut via_live = decode_through(live_backend);
    via_registry.id = ObservationId::new(0);
    via_live.id = ObservationId::new(0);
    assert_eq!(
        via_registry, via_live,
        "I5: same event decodes identically through both handles"
    );
}

fn counter(name: &str, value: u64) -> DimensionCounter {
    DimensionCounter {
        name: name.to_owned(),
        value,
    }
}

// ── aggregate-path fixtures ──────────────────────────────────────────

/// Conformance backend for the aggregate profile: scripted
/// detect/plan/configure (no privilege), deterministic content-
/// sensitive decode over kcrypto snapshot row bytes, counting
/// finalize. Decode mirrors `KCryptoBackend::decode` structurally
/// (strict parse → fail-closed refuse → stamp from row payload →
/// issue id) minus the production observation constructors (which are
/// `pub(crate)` — widening them was permitted but unnecessary, so the
/// harness uses fakes instead).
/// Fixed verdict-neutral labels; content sensitivity rides the
/// backend-payload echo plus the row-stamped clocks — identical bytes
/// decode identically on both drivers, any byte divergence flips the
/// multiset.
struct ConformanceAggBackend {
    decoded: std::sync::atomic::AtomicU64,
}

impl ConformanceAggBackend {
    fn new() -> Self {
        Self {
            decoded: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Backend for ConformanceAggBackend {
    fn id(&self) -> BackendId {
        BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        &CONFORMANCE_CAPS
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        Ok(vec![DetectedInstance {
            backend: BackendId::KCrypto,
            object: None,
            detail: String::from("conformance scripted instance"),
        }])
    }

    fn plan(
        &self,
        _ctx: &PlanContext<'_>,
        _instance: &DetectedInstance,
        _mode: CaptureMode,
    ) -> Result<BackendPlan, BackendError> {
        Ok(BackendPlan {
            backend: BackendId::KCrypto,
            probes: Vec::new(),
            required: CONFORMANCE_CAPS.required,
        })
    }

    fn configure(
        &self,
        _ctx: &mut ConfigureContext<'_>,
        _plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn decode(
        &self,
        ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        // Strict parse first (fail-closed like production: a foreign
        // payload refuses, never decodes partial).
        let parsed = parse_snapshot_row(event.payload)?;
        let id = ctx.id_issuer.issue().map_err(|exhausted| {
            BackendError::Exhausted(BudgetReason::with_detail(
                "observation_ids",
                &exhausted.to_string(),
            ))
        })?;
        let (phase, call_kind, operation_class, started_ns, ended_ns, payload) = match parsed {
            ParsedRow::Agg { kagg, vagg } => (
                EvidencePhase::Returned,
                CallKind::Operation,
                OperationClass::Encrypt,
                Some(vagg.first_ns),
                Some(vagg.last_ns),
                serde_json::json!({
                    "row": "agg",
                    "family": kagg.fam(),
                    "op": kagg.op(),
                    "result": kagg.res(),
                    "context": kagg.ctx(),
                    "algorithm": kagg.alg(),
                    "driver": kagg.drv(),
                    "calls": vagg.calls,
                    "bytes": vagg.bytes,
                    "ok": vagg.ok,
                    "errors": vagg.errors,
                    "queued": vagg.queued,
                    "first_ns": vagg.first_ns,
                    "last_ns": vagg.last_ns,
                }),
            ),
            ParsedRow::Totals { vagg } => (
                EvidencePhase::Returned,
                CallKind::Unknown,
                OperationClass::Unknown,
                Some(vagg.first_ns),
                Some(vagg.last_ns),
                serde_json::json!({
                    "row": "totals",
                    "calls": vagg.calls,
                    "bytes": vagg.bytes,
                    "ok": vagg.ok,
                    "errors": vagg.errors,
                    "queued": vagg.queued,
                    "first_ns": vagg.first_ns,
                    "last_ns": vagg.last_ns,
                }),
            ),
            ParsedRow::Ident { kctl } => (
                EvidencePhase::Discovered,
                CallKind::Unknown,
                OperationClass::Unknown,
                Some(kctl.val2),
                None,
                serde_json::json!({
                    "row": "ident",
                    "kind": kctl.kind,
                    "key_hash": kctl.key_hash,
                    "val0": kctl.val0,
                    "val1": kctl.val1,
                    "val2": kctl.val2,
                    "val3": kctl.val3,
                }),
            ),
        };
        self.decoded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(NativeObservation {
            id,
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase,
            call_kind,
            operation_class,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns,
            ended_ns,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: payload,
        })
    }

    fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        Ok(BackendSummary {
            backend: BackendId::KCrypto,
            observations: self.decoded.load(std::sync::atomic::Ordering::Relaxed),
            integrity: IntegritySummary::default(),
        })
    }
}

/// Scripted aggregate sensor: canned snapshot ticks, ZERO who rows
/// (who bypasses decode — see module docs), zero drop sites. Mirrors
/// the `ScriptedSensor` pattern from `live_session.rs` (separate test
/// crates cannot share the type, so the harness carries its own).
struct ConformanceSensor {
    script: Vec<SnapshotRows>,
}

impl SessionSensor for ConformanceSensor {
    fn snapshot_tick(
        &mut self,
        barrier_id: u64,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<SnapshotRows, kryprobe_cli::live::LiveError> {
        let idx = (barrier_id - 1) as usize;
        if idx + 1 >= self.script.len() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(self.script[idx.min(self.script.len() - 1)].clone())
    }

    fn kallsyms_text(&mut self) -> String {
        String::new()
    }

    fn snapshot_who(
        &mut self,
    ) -> Result<
        (Vec<kryprobe_privilege::kcrypto_backend::WhoSnapshot>, u64),
        kryprobe_cli::live::LiveError,
    > {
        Ok((Vec::new(), 0))
    }

    fn finish(
        &mut self,
    ) -> Result<
        kryprobe_privilege::kcrypto_backend::AggregateTerminalSample,
        kryprobe_cli::live::LiveError,
    > {
        let snapshot = self.script.last().expect("script").clone();
        let started_ns = snapshot.monotonic_ns;
        Ok(
            kryprobe_privilege::kcrypto_backend::AggregateTerminalSample {
                snapshot,
                who: Vec::new(),
                who_drops: 0,
                drops: [0; 8],
                drain: Default::default(),
                started_ns,
            },
        )
    }

    fn cleanup(
        &mut self,
    ) -> Result<Option<kryprobe_privilege::drain::DrainStats>, kryprobe_cli::live::LiveError> {
        Ok(None)
    }
}

fn agg_row(calls: u64, name8: &[u8; 8]) -> RowBytes {
    let out =
        kryprobe_testkit::kcrypto_rows::agg_row_bytes(kryprobe_testkit::kcrypto_rows::AggSpec {
            family: kryprobe_abi::kcrypto_agg::KFAM_SK,
            op: kryprobe_abi::kcrypto_agg::KOP_ENC,
            result: kryprobe_abi::kcrypto_agg::KRES_OK,
            ctx: kryprobe_abi::kcrypto_agg::KCTX_PROC,
            name: name8.as_slice(),
            drv: b"",
            calls,
            bytes: 0,
            ok: 0,
            errors: 0,
            queued: 0,
        });
    RowBytes::new(out).expect("hand agg row")
}

fn totals_row(calls: u64) -> TotalsBytes {
    let out = kryprobe_testkit::kcrypto_rows::totals_row_bytes(calls, 0, 0);
    TotalsBytes::new(out).expect("hand totals row")
}

fn ident_row() -> IdentBytes {
    let out = kryprobe_testkit::kcrypto_rows::ident_row_bytes();
    IdentBytes::new(out).expect("hand ident row")
}

/// One scripted tick: two DISTINCT-key agg rows (no latest-per-key
/// collapse on the live side) + totals reconciled to gap 0 + one
/// ident. Clean transport (no drops/overflow) at wall 100.
fn agg_tick() -> SnapshotRows {
    SnapshotRows {
        rows: vec![agg_row(10, b"cbc(aes)"), agg_row(20, b"gcm(aes)")],
        totals: Some(totals_row(30)),
        idents: vec![ident_row()],
        overflow_identities: 0,
        drops: 0,
        monotonic_ns: 100,
        lagmax_ns: None,
    }
}

/// Batch-side events for one scripted tick: byte-identical to what the
/// live driver constructs internally — `raw_event_stamped` over the
/// same row bytes with the same per-kind stamp (`vagg.last_ns` for
/// agg/totals, `kctl.val2` for idents; `live.rs:1606/1623/1639`).
/// Owned (header, payload) pairs; callers borrow both into `RawEvent`s.
fn agg_batch_events(tick: &SnapshotRows) -> Vec<(kryprobe_abi::RawEventHeader, Vec<u8>)> {
    let mut events = Vec::new();
    for row in &tick.rows {
        let stamp = match parse_snapshot_row(row.as_bytes()).expect("script parses") {
            ParsedRow::Agg { vagg, .. } => vagg.last_ns,
            ParsedRow::Totals { .. } | ParsedRow::Ident { .. } => {
                panic!("agg slot holds a non-agg row")
            }
        };
        let event = raw_event_stamped(row.as_bytes(), stamp);
        events.push((event.header, event.payload.to_vec()));
    }
    if let Some(totals) = &tick.totals {
        let stamp = match parse_snapshot_row(totals.as_bytes()).expect("script parses") {
            ParsedRow::Totals { vagg } => vagg.last_ns,
            _ => panic!("totals slot holds a non-totals row"),
        };
        let event = raw_event_stamped(totals.as_bytes(), stamp);
        events.push((event.header, event.payload.to_vec()));
    }
    for ident in &tick.idents {
        let stamp = match parse_snapshot_row(ident.as_bytes()).expect("script parses") {
            ParsedRow::Ident { kctl } => kctl.val2,
            _ => panic!("ident slot holds a non-ident row"),
        };
        let event = raw_event_stamped(ident.as_bytes(), stamp);
        events.push((event.header, event.payload.to_vec()));
    }
    events
}

/// Harness-supplied I2 expectation for the aggregate script: a fully
/// attached single clean tick with reconciled totals (gap 0, no
/// unexpected drops) decodes `decoded` observations. Hand-derived from
/// `session_coverage` (`live.rs:739`): attach `Complete`; aggregate
/// counts / detailed events / completion `Unknown` with their reason
/// counters (S04/T02 — measured-clean still cannot claim delivery or
/// completion); the four declared-boundary dims `Complete`.
fn expected_agg_coverage(attached: usize, expected: usize, decoded: u64) -> CoverageSummary {
    let zero = ValidityInterval {
        start_ns: 0,
        end_ns: None,
    };
    let complete = CoverageStatus::CompleteForDeclaredBoundary;
    let mut attachment = DimensionCoverage::new(complete, zero);
    attachment
        .counters
        .push(counter("probes_attached", attached as u64));
    attachment
        .counters
        .push(counter("probes_expected", expected as u64));
    let mut aggregate_counts = DimensionCoverage::new(CoverageStatus::Unknown, zero);
    aggregate_counts
        .counters
        .push(counter("uncovered:aggregate_snapshot_not_quiescent", 1));
    aggregate_counts
        .counters
        .push(counter("uncovered:kernel_delivery_unmeasured", 1));
    aggregate_counts.counters.extend([
        counter("snapshot_agg_calls", 30),
        counter("snapshot_totals_calls", 30),
        counter("ktot_gap", 0),
        counter("snapshot_gap_unreconciled", 0),
    ]);
    for site in KDROP_SITES {
        aggregate_counts
            .counters
            .push(counter(&format!("predrop_{site}"), 0));
    }
    let mut detailed_events = DimensionCoverage::new(CoverageStatus::Unknown, zero);
    detailed_events
        .counters
        .push(counter("uncovered:kernel_delivery_unmeasured", 1));
    detailed_events.counters.push(counter("ring_drops", 0));
    detailed_events
        .counters
        .push(counter("overflow_identities", 0));
    detailed_events.counters.extend([
        counter("user_queue_drops", 0),
        counter("terminal_backlog_bytes", 0),
        counter("terminal_busy", 0),
        counter("uncovered:aggregate_snapshot_not_quiescent", 1),
    ]);
    let mut attribution = DimensionCoverage::new(complete, zero);
    attribution.counters.push(counter("who_drops", 0));
    let mut completion = DimensionCoverage::new(CoverageStatus::Unknown, zero);
    completion
        .counters
        .push(counter("observations_decoded", decoded));
    completion
        .counters
        .push(counter("uncovered:completion_unobserved", 1));
    CoverageSummary {
        target_population: DimensionCoverage::new(complete, zero),
        object_discovery: DimensionCoverage::new(complete, zero),
        attachment,
        aggregate_counts,
        detailed_events,
        attribution,
        correlation: DimensionCoverage::new(complete, zero),
        completion,
    }
}

#[test]
fn batch_vs_live_aggregate_agree() {
    // Same scripted stream through both drivers: batch decodes the
    // owned events; live replays the tick through a scripted sensor.
    let tick = agg_tick();
    let owned = agg_batch_events(&tick);
    let events: Vec<RawEvent<'_>> = owned
        .iter()
        .map(|(header, payload)| RawEvent {
            header: *header,
            payload,
        })
        .collect();

    let mut registry = BackendRegistry::new();
    registry
        .register(Box::new(ConformanceAggBackend::new()))
        .expect("fresh registry accepts the conformance backend");
    let mut driver = BackendDriver::harness();
    let mut batch = driver
        .run(&registry, &open_runtime(), &events)
        .expect("batch run over the scripted stream drives green");

    let mut controller = attached_controller();
    let cfg = LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(0),
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = ConformanceSensor { script: vec![tick] };
    let live_backend = ConformanceAggBackend::new();
    let live = drive_session(
        &cfg,
        &live_backend,
        &mut sensor,
        &stop,
        kryprobe_privilege::btf_resolve::KCRYPTO_SYMBOLS.len(),
        SessionId::new(1),
        PlanGeneration::new(1),
        &IdIssuer::default(),
        None,
        &mut controller,
        None,
    )
    .expect("scripted live session drives green");

    // ADR-0007 I1–I5 over the scripted stream.
    check_observations_i1(batch.observations(), &live.observations);
    let points = kryprobe_privilege::btf_resolve::KCRYPTO_SYMBOLS.len();
    check_coverage_i2(
        &live.coverage,
        &expected_agg_coverage(points, points, 4),
        100,
    );
    check_integrity_i3(&mut batch, &live.integrity);
    check_summaries_i4(&batch, &live.summary);
    check_decoder_identity_i5(
        registry
            .get(BackendId::KCrypto)
            .expect("conformance backend registered"),
        &live_backend,
        &events,
    );
}

// ── lifecycle-path fixtures ──────────────────────────────────────────

/// Corrupt-input refusal naming the offending envelope field.
fn corrupt(field: &'static str) -> BackendError {
    BackendError::CorruptInput(InputReason::new(field))
}

/// Conformance backend for the request-lifecycle profile: scripted
/// detect/plan/configure (no privilege), deterministic decode over
/// the lifecycle JSON envelope (`lifecycle_event` bytes), counting
/// finalize with attested cap omissions. Decode mirrors
/// `LifecycleBackend::decode` structurally (strict closed-key envelope
/// walk → terminal/status pairing rules → fail-closed refuse → issue
/// id; production constructors are private, so the harness echoes
/// envelope content with fixed verdict-neutral labels). Timestamps
/// stay `None`/`None` like production (`backend.rs:577-578`).
struct ConformanceLifecycleBackend {
    decoded: std::sync::atomic::AtomicU64,
    output_omissions: std::sync::atomic::AtomicU64,
}

impl ConformanceLifecycleBackend {
    fn new() -> Self {
        Self {
            decoded: std::sync::atomic::AtomicU64::new(0),
            output_omissions: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Backend for ConformanceLifecycleBackend {
    fn id(&self) -> BackendId {
        BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        &CONFORMANCE_CAPS
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        Ok(vec![DetectedInstance {
            backend: BackendId::KCrypto,
            object: None,
            detail: String::from("conformance lifecycle scripted instance"),
        }])
    }

    fn plan(
        &self,
        _ctx: &PlanContext<'_>,
        _instance: &DetectedInstance,
        _mode: CaptureMode,
    ) -> Result<BackendPlan, BackendError> {
        Ok(BackendPlan {
            backend: BackendId::KCrypto,
            probes: Vec::new(),
            required: CONFORMANCE_CAPS.required,
        })
    }

    fn configure(
        &self,
        _ctx: &mut ConfigureContext<'_>,
        _plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn decode(
        &self,
        ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        // Strict closed-key envelope walk (the production shape: the
        // JSON envelope discriminates by construction, so like
        // production this checks payload only).
        let value: serde_json::Value =
            serde_json::from_slice(event.payload).map_err(|_| corrupt("envelope_json"))?;
        let obj = value.as_object().ok_or_else(|| corrupt("envelope_shape"))?;
        for key in obj.keys() {
            match key.as_str() {
                "request_id" | "terminal" | "status" | "duration_ns" | "tfm_id" | "family"
                | "cryptlen" | "assoclen" | "authsize" => {}
                _ => return Err(corrupt("envelope_key")),
            }
        }
        let get = |key: &str| obj.get(key).ok_or_else(|| corrupt("envelope_key"));
        let request_id = get("request_id")?
            .as_u64()
            .ok_or_else(|| corrupt("request_id"))?;
        let terminal_name = get("terminal")?
            .as_str()
            .ok_or_else(|| corrupt("terminal"))?;
        let status = match get("status")? {
            serde_json::Value::Null => None,
            value => Some(
                value
                    .as_i64()
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or_else(|| corrupt("status"))?,
            ),
        };
        // Terminal/status pairing rules (production parity): grounded
        // terminals carry an i32 status, `unknown` carries null.
        let grounded = match (terminal_name, status) {
            ("sync" | "callback", Some(_)) => true,
            ("unknown", None) => false,
            _ => return Err(corrupt("terminal_status")),
        };
        let duration_ns = match get("duration_ns")? {
            serde_json::Value::Null => None,
            serde_json::Value::String(duration) => {
                let canonical = duration == "0"
                    || (!duration.is_empty()
                        && !duration.starts_with('0')
                        && duration.bytes().all(|b| b.is_ascii_digit()));
                if !canonical || duration.parse::<u64>().is_err() {
                    return Err(corrupt("duration_ns"));
                }
                Some(duration.clone())
            }
            _ => return Err(corrupt("duration_ns")),
        };
        // T05 parity: an unobserved terminal carries neither status
        // (ruled out above) nor duration.
        if !grounded && duration_ns.is_some() {
            return Err(corrupt("unknown_duration"));
        }
        let id = ctx.id_issuer.issue().map_err(|exhausted| {
            BackendError::Exhausted(BudgetReason::with_detail(
                "observation_ids",
                &exhausted.to_string(),
            ))
        })?;
        self.decoded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (phase, call_kind, native_result) = if grounded {
            (
                EvidencePhase::Completed,
                CallKind::Operation,
                NativeResult::KCrypto {
                    status: status.expect("grounded carries status"),
                },
            )
        } else {
            (
                EvidencePhase::Entered,
                CallKind::Unknown,
                NativeResult::KCryptoUnknown,
            )
        };
        Ok(NativeObservation {
            id,
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase,
            call_kind,
            // The record carries no op: Unknown, never guessed (the
            // production precedent).
            operation_class: OperationClass::Unknown,
            native_name: None,
            native_code: None,
            native_result,
            started_ns: None,
            ended_ns: None,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "lifecycle",
                "request_id": request_id,
                "terminal": terminal_name,
                "status": get("status")?,
                "duration_ns": duration_ns,
                "tfm_id": get("tfm_id")?,
                "family": get("family")?,
                "cryptlen": get("cryptlen")?,
                "assoclen": get("assoclen")?,
                "authsize": get("authsize")?,
            }),
        })
    }

    fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        Ok(BackendSummary {
            backend: BackendId::KCrypto,
            observations: self.decoded.load(std::sync::atomic::Ordering::Relaxed),
            integrity: IntegritySummary {
                budget_omissions: self
                    .output_omissions
                    .load(std::sync::atomic::Ordering::Relaxed),
                ..IntegritySummary::default()
            },
        })
    }

    fn note_output_omissions(&self, omitted: u64) {
        self.output_omissions
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |current| Some(current.saturating_add(omitted)),
            )
            .ok();
    }
}

/// Scripted lifecycle sensor: canned per-tick completions plus
/// stop-time `finish` records through the `LifecycleSessionSensor`
/// seam. Mirrors the `ScriptedLifecycleSensor` pattern from
/// `live_session.rs` (the `ScriptedOutputSensor` order-tape variant in
/// `kcrypto_output.rs` serves the same seam with teardown taping —
/// both suffice for replaying a scripted stream; separate test crates
/// cannot share either type, so the harness carries its own).
struct ConformanceLifecycleSensor<'a> {
    ticks: Vec<Vec<RequestRecord>>,
    finish_records: Vec<RequestRecord>,
    finish_staged: bool,
    ledger: LifecycleLedger,
    now: u64,
    drains: usize,
    taken: usize,
    quiet_backlog: u64,
    stop: &'a std::sync::atomic::AtomicBool,
}

impl LifecycleSessionSensor for ConformanceLifecycleSensor<'_> {
    fn wait_for_activity(
        &mut self,
        _max_wait: std::time::Duration,
        _pending_writer: bool,
    ) -> Result<(), kryprobe_cli::live::LiveError> {
        Ok(())
    }

    fn drain_tick(
        &mut self,
        _max_records: usize,
    ) -> Result<DrainOutcome, kryprobe_cli::live::LiveError> {
        let call = self.drains;
        self.drains += 1;
        if call + 1 >= self.ticks.len() {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let completed = self.ticks[call.min(self.ticks.len() - 1)].len();
        Ok(DrainOutcome {
            records: completed,
            completed,
            busy: false,
            lagmax_ns: None,
        })
    }

    fn take_completed(&mut self) -> Result<Vec<RequestRecord>, kryprobe_cli::live::LiveError> {
        // Retention drains once: the Nth take surfaces the Nth
        // scripted tick; takes past the script surface nothing — until
        // `finish_stop` stages the reconciled records, which the next
        // take surfaces (the production retain-then-take protocol).
        if self.finish_staged {
            self.finish_staged = false;
            return Ok(self.finish_records.clone());
        }
        let call = self.taken;
        self.taken += 1;
        if call >= self.ticks.len() {
            return Ok(Vec::new());
        }
        Ok(self.ticks[call].clone())
    }

    fn verify_identity(&self) -> Result<(), kryprobe_cli::live::LiveError> {
        Ok(())
    }

    fn fence_admissions(&mut self) -> Result<(), kryprobe_cli::live::LiveError> {
        Ok(())
    }

    fn in_flight(&self) -> Result<u64, kryprobe_cli::live::LiveError> {
        Ok(0)
    }

    fn close_input(&mut self) -> Result<(), kryprobe_cli::live::LiveError> {
        Ok(())
    }

    fn drain_quiet(&mut self) -> Result<QuietOutcome, kryprobe_cli::live::LiveError> {
        Ok(QuietOutcome {
            rounds: 1,
            records: 0,
            quiet: self.quiet_backlog == 0,
            backlog_bytes: self.quiet_backlog,
        })
    }

    fn finish_stop(&mut self, stop_ns: u64) -> Result<(), kryprobe_cli::live::LiveError> {
        assert_eq!(stop_ns, self.now, "finish stamps the closing wall");
        self.finish_staged = true;
        Ok(())
    }

    fn ledger(&self) -> Result<LifecycleLedger, kryprobe_cli::live::LiveError> {
        Ok(self.ledger.clone())
    }

    fn now_ns(&self) -> Result<u64, kryprobe_cli::live::LiveError> {
        Ok(self.now)
    }
}

/// One scripted request record: grounded terminals carry the
/// submit-to-terminal span, `Unknown` carries no duration (T05 — a
/// span without endpoints would be fabricated timing).
fn lifecycle_record(id: u64, terminal: Terminal) -> RequestRecord {
    let duration_ns = if terminal == Terminal::Unknown {
        None
    } else {
        Some(1000 + id)
    };
    RequestRecord {
        id,
        tfm_id: None,
        terminal,
        duration_ns,
        meta: RequestMeta {
            family: LifecycleFamily::Skcipher,
            direction: OpDirection::Encrypt,
            cryptlen: Some(16),
            req_flags: Some(0),
            epoch: Some(0),
            aead: None,
        },
    }
}

/// Loss-clean scripted ledger over three admitted/emitted requests,
/// one truthless (the `finish` record below): six consumed edges, no
/// loss class, verified view.
fn lifecycle_ledger() -> LifecycleLedger {
    LifecycleLedger {
        completed: Vec::new(),
        edge_hits: [
            2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        adapter: AdapterStats::default(),
        decode: DecodeStats {
            admitted: 3,
            ..DecodeStats::default()
        },
        reducer: ReducerStats {
            admitted: 3,
            emitted: 3,
            unfinished: 1,
            ..ReducerStats::default()
        },
        kernel_loss: [0; 5],
        agg_accepted: [
            2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        retained_dropped: 0,
        view_valid: true,
        loss_baseline: [0; 5],
        agg_baseline: [0; 22],
        prog_misses: Vec::new(),
        miss_current: Vec::new(),
        tfm_stats: TfmStats::default(),
        generations: Vec::new(),
        enrichment: EnrichmentStatus::Available {
            entries: 0,
            truncated: false,
        },
    }
}

/// Harness-supplied I2 expectation for the lifecycle script: a
/// fully attached loss-clean session over three completions (one
/// truthless `finish` record, one `Unknown` terminal, no truncation,
/// empty close ring). Hand-derived from `lifecycle_coverage`
/// (`live.rs:869`): attach + correlation `Complete`; aggregate
/// counts / detailed events `Unknown` (S04 twin — loss-clean still
/// cannot claim kernel delivery); completion `Partial` (truthless +
/// unknown terminals); attribution `Unknown` (lifecycle rows carry no
/// context class). Script-data inputs (edge arrays, admitted,
/// unfinished) echo from the scripted ledger; every verdict and
/// derived count is hand-pinned.
fn expected_lifecycle_coverage(
    ledger: &LifecycleLedger,
    attached: usize,
    expected_points: usize,
    decoded: u64,
    unknown_terminals: u64,
) -> CoverageSummary {
    let zero = ValidityInterval {
        start_ns: 0,
        end_ns: None,
    };
    let complete = CoverageStatus::CompleteForDeclaredBoundary;
    let mut attachment = DimensionCoverage::new(complete, zero);
    attachment
        .counters
        .push(counter("probes_attached", attached as u64));
    attachment
        .counters
        .push(counter("probes_expected", expected_points as u64));
    let mut aggregate_counts = DimensionCoverage::new(CoverageStatus::Unknown, zero);
    aggregate_counts
        .counters
        .push(counter("uncovered:kernel_delivery_unmeasured", 1));
    for (hook, hits) in ledger.edge_hits.iter().enumerate() {
        aggregate_counts
            .counters
            .push(counter(&format!("edge_hits_hook{hook}"), *hits));
    }
    aggregate_counts.counters.push(counter("count_loss", 0));
    aggregate_counts
        .counters
        .push(counter("unbound_destroy_inventory", 0));
    aggregate_counts
        .counters
        .push(counter("prog_miss_delta", 0));
    aggregate_counts
        .counters
        .push(counter("submits_admitted", ledger.reducer.admitted));
    let mut detailed_events = DimensionCoverage::new(CoverageStatus::Unknown, zero);
    detailed_events
        .counters
        .push(counter("uncovered:kernel_delivery_unmeasured", 1));
    detailed_events.counters.push(counter("ring_drops", 0));
    detailed_events
        .counters
        .push(counter("retained_dropped", 0));
    detailed_events
        .counters
        .push(counter("close_backlog_bytes", 0));
    let agg_sum: u64 = ledger.agg_accepted.iter().sum();
    let hits_sum: u64 = ledger.edge_hits.iter().sum();
    detailed_events
        .counters
        .push(counter("agg_accepted", agg_sum));
    detailed_events
        .counters
        .push(counter("agg_consumed", hits_sum));
    detailed_events
        .counters
        .push(counter("agg_residual_unexplained", 0));
    let mut completion = DimensionCoverage::new(CoverageStatus::Partial, zero);
    completion.counters.push(counter("identity_verified", 1));
    completion
        .counters
        .push(counter("observations_decoded", decoded));
    completion.counters.push(counter(
        "terminals_grounded",
        decoded.saturating_sub(unknown_terminals),
    ));
    completion
        .counters
        .push(counter("unfinished_truthless", ledger.reducer.unfinished));
    completion
        .counters
        .push(counter("unknown_terminals", unknown_terminals));
    completion
        .counters
        .push(counter("observations_truncated", 0));
    let mut attribution = DimensionCoverage::new(CoverageStatus::Unknown, zero);
    attribution
        .counters
        .push(counter("uncovered:attribution_unobserved", 1));
    let mut correlation = DimensionCoverage::new(complete, zero);
    correlation.counters.push(counter("correlation_events", 0));
    CoverageSummary {
        target_population: DimensionCoverage::new(complete, zero),
        object_discovery: DimensionCoverage::new(complete, zero),
        attachment,
        aggregate_counts,
        detailed_events,
        attribution,
        correlation,
        completion,
    }
}

#[test]
fn batch_vs_live_lifecycle_agree() {
    // Same scripted stream through both drivers: two grounded ticks
    // (sync + callback) plus one truthless `finish` record. The live
    // side keeps every completion (no dedup on this path).
    let ticks = vec![
        vec![lifecycle_record(1, Terminal::Sync(0))],
        vec![lifecycle_record(2, Terminal::Callback(-5))],
    ];
    let finish = vec![lifecycle_record(3, Terminal::Unknown)];
    let scripted: Vec<RequestRecord> = ticks
        .iter()
        .flatten()
        .cloned()
        .chain(finish.clone())
        .collect();

    let owned: Vec<(kryprobe_abi::RawEventHeader, Vec<u8>)> =
        scripted.iter().map(lifecycle_event).collect();
    let events: Vec<RawEvent<'_>> = owned
        .iter()
        .map(|(header, payload)| RawEvent {
            header: *header,
            payload,
        })
        .collect();

    let mut registry = BackendRegistry::new();
    registry
        .register(Box::new(ConformanceLifecycleBackend::new()))
        .expect("fresh registry accepts the conformance backend");
    let mut driver = BackendDriver::harness();
    let mut batch = driver
        .run(&registry, &open_runtime(), &events)
        .expect("batch run over the scripted stream drives green");

    let mut controller = attached_controller();
    let cfg = LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: None,
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: LifecycleProfile::RequestLifecycle,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = ConformanceLifecycleSensor {
        ticks,
        finish_records: finish,
        finish_staged: false,
        ledger: lifecycle_ledger(),
        now: 555,
        drains: 0,
        taken: 0,
        quiet_backlog: 0,
        stop: &stop,
    };
    let live_backend = ConformanceLifecycleBackend::new();
    let attached = max_programs(&manifest(LifecycleProfile::RequestLifecycle));
    let live = drive_lifecycle_session(
        &cfg,
        &live_backend,
        &mut sensor,
        &stop,
        attached,
        SessionId::new(1),
        PlanGeneration::new(1),
        &IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("scripted lifecycle session drives green");

    // ADR-0007 I1–I5 over the scripted stream (Task 1 scoped
    // nothing out: both scripted-sensor seams replay scripted streams,
    // so both paths compare — see the sensor docs above).
    check_observations_i1(batch.observations(), &live.observations);
    check_coverage_i2(
        &live.coverage,
        &expected_lifecycle_coverage(&lifecycle_ledger(), attached, attached, 3, 1),
        555,
    );
    check_integrity_i3(&mut batch, &live.integrity);
    check_summaries_i4(&batch, &live.summary);
    check_decoder_identity_i5(
        registry
            .get(BackendId::KCrypto)
            .expect("conformance backend registered"),
        &live_backend,
        &events,
    );
}
