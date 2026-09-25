// SPDX-License-Identifier: GPL-3.0-or-later
//! Live kcrypto capture session (K3 Task 1): the frozen-trait lifecycle
//! driven per-tick against a session-owned sensor.
//!
//! Flow (D1): shared registry + [`register_kcrypto_profile`] → gate
//! check → `detect` → `plan` (Trace) → K5 token/caps pre-flight →
//! stage bytes + token → `configure` once (loads the single sensor) →
//! tick loop (`snapshot_rows` → raw events in row order → `decode` each
//! with a session [`IdIssuer`], then `snapshot_who` → who rows via
//! [`observation_for_who`](kryprobe_privilege::kcrypto_backend::observation_for_who)
//! with once-per-tick kallsyms) → `finalize` ONCE → [`DriverReport::feed_shared_losses`] ONCE from
//! measured drop counters only.
//!
//! Single sensor (H1(b); was: session twin + backend twin): per-tick
//! snapshots run against the backend's own sensor via a dup'd handle
//! ([`KCryptoBackend::session_sensor`](kryprobe_privilege::kcrypto_backend::KCryptoBackend::session_sensor)
//! — same kernel objects, one attach, one probe stream, one set of
//! maps), and `finalize` assesses that same sensor. Ticks drain the
//! session ring through the shared handle, and the once-only finalize
//! drain drops only duplicates of decoded idents.
//!
//! Snapshots are non-consuming reads (only the KRING drain consumes), so
//! agg/totals/who rows repeat per tick with cumulative counters — the
//! driver accumulates latest-per-row-key (H2: memory is O(keys +
//! idents), never O(ticks × rows)) while idents, disjoint across
//! ticks, are all kept. `summary.observations` counts `decode` calls
//! (fresh decodes every tick for latest counters);
//! `observations.len()` counts latest-per-key + idents.
//!
//! The shared feed carries the session sensor's measured `KIDN_DROPS`
//! read (the K2 `finalize_drops` idiom, including ENOENT→0), disjoint
//! from the backend summary — never double-counted in the rollup. The
//! queue pins 0 inside [`shared_losses_from_snapshot`] (the K1 documented
//! rationale: queue 1024 + concurrent recv at KIDN-gated counts).
//!
//! Coverage is assembled from session measurements only (never zero for
//! unmeasured): attach from counted points, aggregate counts from the
//! twin KTOT gap (totals-missing leaves the dimension `Unknown` with an
//! `uncovered:ktot_baseline_missing` reason counter), detailed events
//! from measured ring drops + accumulated overflow. Completion and the
//! declared-boundary vacuous dimensions (`target_population`,
//! `object_discovery`, `attribution`, `correlation`) are `Complete`
//! within the kcrypto-v0.1 contract, so a healthy session renders kp2 §8
//! COMPLETE; any measured loss flips its dimension to `Partial`.
//!
//! Sessions are process-exclusive (sensors are system-wide; the BPF lane
//! lock serializes). Bounded runs stop at the deadline, unbounded runs
//! stop on closed stdin; SIGINT is caught (4B-M5: a flag recorder, no
//! libc in the CLI) — the tick loop observes it, finalizes, renders
//! the partial window, and exits 3 instead of dying mid-capture.
//!
//! Profile twin (T06 item 4): `request-lifecycle` sessions drive the
//! same machine through [`drive_lifecycle_session`] — per-tick ring
//! drains into the terminal ledger, completed records decoded through
//! the lifecycle envelope plus `decode`, stop-time `finish`
//! reconciliation, `finalize` ONCE, and coverage from the terminal
//! ledger. Registry and live entry points both select through
//! [`register_kcrypto_profile`], so they can never choose different
//! profiles/decoders.

use kryprobe_abi::kcrypto_agg::kh_of;
use kryprobe_core::backend::{
    Backend, BackendRegistry, BackendSummary, ConfigureContext, DecodeContext, DetectContext,
    DriverReport, FinalizeContext, PlanContext, RawEvent,
};
use kryprobe_core::budget::BudgetManager;
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{BackendId, CaptureMode, CoverageStatus};
use kryprobe_core::error::BackendError;
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCounter, DimensionCoverage, IntegritySummary, NativeObservation,
    SharedLosses, ValidityInterval,
};
use kryprobe_core::ids::{IdIssuer, PlanGeneration, SessionId};
use kryprobe_core::kcrypto::RequestRecord;
use kryprobe_core::plan::{CapabilityRequirements, PlanBudget};
use kryprobe_core::session::{SessionController, SessionState};
use kryprobe_privilege::btf_resolve::{ConfiguredKcrypto, KCRYPTO_SYMBOLS};
use kryprobe_privilege::drain::DrainThread;
use kryprobe_privilege::host::{SIGINT_SEEN, monotonic_ns};
use kryprobe_privilege::kallsyms::{SymTable, read_kallsyms};
use kryprobe_privilege::kcrypto_backend::{
    ClosingCounts, KCryptoBackend, KDROP_DESTROY, KDROP_SITES, ProfileBackend, WhoCache,
    WhoSnapshot, observation_for_who, register_kcrypto_profile, snapshot_drops,
    snapshot_who_cached,
};
use kryprobe_privilege::kcrypto_lifecycle::backend::{LifecycleBackend, lifecycle_event};
use kryprobe_privilege::kcrypto_lifecycle::profile::{LifecycleProfile, manifest, max_programs};
use kryprobe_privilege::kcrypto_lifecycle::sensor::{DrainOutcome, LifecycleLedger, QuietOutcome};
use kryprobe_privilege::kcrypto_lifecycle::view::prog_miss_delta_sum;
use kryprobe_privilege::kcrypto_snapshot::{
    ParsedRow, SnapshotRows, parse_snapshot_row, raw_event_stamped, session_drain,
    shared_losses_from_snapshot, snapshot_rows_with_drain,
};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

/// The only source captured live in v0.1.
pub const LIVE_SOURCE: &str = "kernel-crypto";

/// Default tick cadence (brief-exact).
pub const DEFAULT_TICK_MS: u64 = 1000;

/// Stop-flag poll slice: the tick sleep wakes this often so SIGINT /
/// closed-stdin stops a session promptly.
const STOP_POLL_MS: u64 = 50;

/// Per-tick progress hook (4B-M5): `(tick_1_based, rows, drops)`.
/// Production prints a stderr liveness line; tests pass `None`.
/// Stderr progress is human-only/unstable (4B-M4): never script on it.
pub type TickProgress = dyn Fn(u64, u64, u64);

/// JSON-mode audit line for the privileged object load (4B-M4): the
/// staged object path plus its sha256. Pure over inputs for tests;
/// the shape is documented in `docs/json.md`.
fn audit_object_line(path: &str, sha256: &str) -> String {
    serde_json::json!({"audit": "object-load", "path": path, "sha256": sha256}).to_string()
}

/// JSON-mode audit line for the attach outcome (4B-M4): attached vs
/// expected probe points. Pure over inputs for tests.
fn audit_attach_line(attached: usize, expected: usize) -> String {
    serde_json::json!({"audit": "attach", "attached": attached, "expected": expected}).to_string()
}

/// Emits one audit line to stderr in JSON mode, silent otherwise
/// (4B-M4: stderr stays human-only outside JSON mode).
fn emit_audit(json_audit: bool, line: &str) {
    if json_audit {
        eprintln!("{line}");
    }
}

/// Live capture configuration (brief-exact shape + the K5 token path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveConfig {
    /// Capture source; only [`LIVE_SOURCE`] is supported.
    pub source: String,
    /// Window length; `None` runs until SIGINT or closed stdin. SIGINT
    /// is caught (4B-M5): the session finalizes, renders the partial
    /// window, and exits 3. Closed stdin stops gracefully through a
    /// watcher thread sharing the session stop flag.
    pub duration_secs: Option<u64>,
    /// Tick cadence in milliseconds.
    pub tick_ms: u64,
    /// Explicit BPF token path (K5: first in the `--token` >
    /// `KRYPROBE_TOKEN` > default-pin discovery order; `None` consults
    /// env + default only).
    pub token: Option<PathBuf>,
    /// JSON-mode audit trail (4B-M4): one structured stderr line per
    /// privileged operation (object load, attach). Human mode stays
    /// silent (stderr is human-only/unstable there).
    pub json_audit: bool,
    /// Capture profile (T06 F8a): registry + live entry points both
    /// select this (never diverge); default keeps api-returns.
    pub profile: LifecycleProfile,
}

impl Default for LiveConfig {
    /// `kernel-crypto`, unbounded, 1000ms ticks, no explicit token,
    /// no audit trail, `api-returns` profile.
    fn default() -> Self {
        Self {
            source: LIVE_SOURCE.to_owned(),
            duration_secs: None,
            tick_ms: DEFAULT_TICK_MS,
            token: None,
            json_audit: false,
            profile: LifecycleProfile::default(),
        }
    }
}

/// Live capture outcome (brief-exact shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOutcome {
    /// Latest-per-row-key survivors (agg/totals/who upsert, idents
    /// appended disjoint per tick): ids unique-positive but sparse —
    /// evicted ticks leave gaps, never renumbering.
    pub observations: Vec<NativeObservation>,
    /// The backend's once-only end-of-session facts.
    pub summary: BackendSummary,
    /// Session coverage assembled from measurements only.
    pub coverage: CoverageSummary,
    /// Reconciled session integrity (rollup + the once-only shared feed).
    pub integrity: IntegritySummary,
    /// Terminal ARCH §4.1 machine state (1B-H4): `Finalized` on every
    /// `Ok` return — the machine's observable proof it governed this
    /// session end to end.
    pub terminal_state: SessionState,
    /// SIGINT ended the window early (4B-M5): the outcome is final
    /// evidence for a cut-short window — callers render and exit 3.
    pub interrupted: bool,
}

/// Live failure: unusable environment (→ exit 4) or internal defect
/// (→ exit 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveError {
    /// Environmental: gate, detect, object, or denied bring-up. Names the
    /// reason; the caller exits 4.
    Unusable(String),
    /// Defect marker: post-attach read failure, decode failure, or any
    /// unexpected error. The caller exits 1.
    Internal(String),
}

impl std::fmt::Display for LiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unusable(reason) => write!(f, "live session unusable: {reason}"),
            Self::Internal(reason) => write!(f, "live session internal error: {reason}"),
        }
    }
}

impl std::error::Error for LiveError {}

impl LiveError {
    /// kp2 exit for this failure (Task 2 maps through here).
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Unusable(_) => 4,
            Self::Internal(_) => 1,
        }
    }
}

/// Gate check: every required capability must have probed present, else
/// `Unusable` naming each missing gate (1B-H1: the gate vocabulary is
/// core's [`RuntimeCapabilities::missing_gates`] — no CLI copy).
fn gate_check(
    stage: &str,
    required: &CapabilityRequirements,
    runtime: &RuntimeCapabilities,
) -> Result<(), LiveError> {
    let missing = runtime.missing_gates(required);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LiveError::Unusable(format!(
            "{stage} capability gate unsatisfied for kcrypto: missing {}",
            missing.join(", ")
        )))
    }
}

/// Backend errors to live errors (1B-M2): every world condition —
/// refused/unsupported bring-up, budget exhaustion, target
/// instability, fired safety rules, ambiguous identity, corrupt input
/// — stays `Unusable` (exit 4: retry/fix env). Only
/// `BackendError::Internal` is a kryprobe defect (`Internal`, exit 1).
fn backend_err(stage: &str, err: BackendError) -> LiveError {
    match err {
        BackendError::Internal(_) => LiveError::Internal(format!("{stage}: {err}")),
        _ => LiveError::Unusable(format!("{stage}: {err}")),
    }
}

/// 1A-L9: one decode→map tail for the tick row blocks (agg, totals,
/// ident). Each block keeps its own parse, stamp, and key handling —
/// only the shared `decode` + `Internal` wrap folds here.
fn decode_tick_row(
    backend: &dyn Backend,
    decode_ctx: &DecodeContext,
    event: RawEvent<'_>,
    what: &str,
) -> Result<NativeObservation, LiveError> {
    backend
        .decode(decode_ctx, event)
        .map_err(|err| LiveError::Internal(format!("live decode {what}: {err}")))
}

/// KTOT gap from call counts: `KTOT − ΣKAGG` calls (saturating).
/// `None` when totals are absent (no baseline — the caller leaves the
/// dimension uncovered, never claims zero).
fn ktot_gap_from_calls(agg_calls: &[u64], totals_calls: Option<u64>) -> Option<u64> {
    totals_calls.map(|totals| {
        totals.saturating_sub(
            agg_calls
                .iter()
                .fold(0u64, |sum, calls| sum.saturating_add(*calls)),
        )
    })
}

/// Session measurements feeding the coverage assembly (all observed live,
/// never defaulted).
struct SessionMeasurements {
    attached_points: usize,
    expected_points: usize,
    totals_present: bool,
    ktot_gap: Option<u64>,
    ring_drops: u64,
    overflow_identities: u64,
    drops: [u64; 8],
    observations_decoded: u64,
    interval: ValidityInterval,
}

fn counter(name: &str, value: u64) -> DimensionCounter {
    DimensionCounter {
        name: name.to_owned(),
        value,
    }
}

/// Coverage from measurements only: `Complete` iff measured-clean,
/// `Partial` on measured loss, `Unknown` + reason counter when the
/// measurement is absent (never `Complete` on a missing input — the
/// no-silent-zeros rule). The interval stamps the session wall.
///
/// T02 (api-returns): internal reconciliation is measured, but kernel
/// hook-delivery and terminal completion are not — so a reconciled
/// session still reports `aggregate_counts`, `detailed_events`, and
/// `completion` as `Unknown` (S04). Exact-count and absence claims
/// over these sessions are therefore inconclusive, never clean.
fn session_coverage(m: &SessionMeasurements) -> CoverageSummary {
    let dim = |status| DimensionCoverage::new(status, m.interval);
    // Attach: counted at bring-up (always measured).
    let mut attachment = dim(if m.attached_points == m.expected_points {
        CoverageStatus::CompleteForDeclaredBoundary
    } else {
        CoverageStatus::Partial
    });
    attachment
        .counters
        .push(counter("probes_attached", m.attached_points as u64));
    attachment
        .counters
        .push(counter("probes_expected", m.expected_points as u64));
    // Aggregate counts: the twin gap + the pre-KTOT skip sites (absent
    // totals → uncovered, not zero). Every KDROPS site rides as a
    // counter (always present — never silent); unexpected sites flip
    // the dimension (measured loss), destroy stays non-flipping
    // (C7-known). A reconciled twin (gap 0, no unexpected drops) is
    // still `Unknown`: internal reconciliation cannot prove kernel
    // hook-delivery (S04/G9) — delivery is unmeasured, so no
    // exact-count claim follows.
    let mut unexpected_drops = 0u64;
    for (site, count) in m.drops.iter().enumerate() {
        if site < KDROP_DESTROY {
            unexpected_drops = unexpected_drops.saturating_add(*count);
        }
    }
    let mut aggregate_counts = match (m.totals_present, m.ktot_gap) {
        (true, Some(gap)) if gap > 0 || unexpected_drops > 0 => dim(CoverageStatus::Partial),
        (true, Some(_)) => dim(CoverageStatus::Unknown),
        _ => dim(CoverageStatus::Unknown),
    };
    match (m.totals_present, m.ktot_gap) {
        (true, Some(gap)) => {
            aggregate_counts.counters.push(counter("ktot_gap", gap));
            aggregate_counts
                .counters
                .push(counter("uncovered:kernel_delivery_unmeasured", 1));
        }
        _ => aggregate_counts
            .counters
            .push(counter("uncovered:ktot_baseline_missing", 1)),
    }
    for (site, name) in KDROP_SITES.iter().enumerate() {
        aggregate_counts
            .counters
            .push(counter(&format!("predrop_{name}"), m.drops[site]));
    }
    // Detailed events: measured ring drops + accumulated overflow. A
    // clean ring is still `Unknown`: transport health cannot prove the
    // kernel invoked the sensor for every operation (S04) — kernel-side
    // skips are invisible to the ring.
    let mut detailed_events = dim(if m.ring_drops == 0 && m.overflow_identities == 0 {
        CoverageStatus::Unknown
    } else {
        CoverageStatus::Partial
    });
    if m.ring_drops == 0 && m.overflow_identities == 0 {
        detailed_events
            .counters
            .push(counter("uncovered:kernel_delivery_unmeasured", 1));
    }
    detailed_events
        .counters
        .push(counter("ring_drops", m.ring_drops));
    detailed_events
        .counters
        .push(counter("overflow_identities", m.overflow_identities));
    // Completion: the api-returns sensor observes returns, never
    // terminal request completion — always `Unknown`, with the
    // decoded count kept as a magnitude, not a completeness proof.
    let mut completion = dim(CoverageStatus::Unknown);
    completion
        .counters
        .push(counter("observations_decoded", m.observations_decoded));
    completion
        .counters
        .push(counter("uncovered:completion_unobserved", 1));
    // Declared-boundary vacuous dimensions: the kcrypto-v0.1 contract
    // observes the whole machine (no target selection), kernel symbols
    // (detect resolved them — reaching here proves it), ctx-class-only
    // attribution (C10: every row carries a context class), and no
    // cross-backend correlation (single-backend session). Nothing in the
    // declared boundary is omitted, so these are `Complete`.
    CoverageSummary {
        target_population: dim(CoverageStatus::CompleteForDeclaredBoundary),
        object_discovery: dim(CoverageStatus::CompleteForDeclaredBoundary),
        attachment,
        aggregate_counts,
        detailed_events,
        attribution: dim(CoverageStatus::CompleteForDeclaredBoundary),
        correlation: dim(CoverageStatus::CompleteForDeclaredBoundary),
        completion,
    }
}

/// Lifecycle coverage from the terminal ledger (T06 item 4 twin of
/// [`session_coverage`]): same no-silent-zeros rule — `Complete` iff
/// measured-clean, `Partial` on measured loss, `Unknown` + reason
/// counter when the measurement is absent.
///
/// The one dimension that differs structurally is `completion`: the
/// aggregate sensor observes returns, never terminal request
/// completion (always `Unknown`), while the lifecycle sensor pairs
/// submit with terminal truth per request — so a session whose every
/// decoded record grounded (`unfinished == 0` AND zero
/// `Unknown`-terminal records — the ambiguous branch emits `Unknown`
/// without touching `unfinished`, so the driver counts terminals
/// from the records themselves) completes
/// `CompleteForDeclaredBoundary` over the admitted requests. The
/// S04 kernel-delivery caveat (requests with zero delivered edges
/// are invisible) rides `aggregate_counts`/`detailed_events` as
/// `Unknown`, never silently inside `completion`.
/// Driver-measured close stats (beyond the terminal ledger): the
/// driver sees every record and the quiet verdict, so it counts
/// `Unknown` terminals, truncation, and close backlog itself.
struct LifecycleCloseStats {
    /// Records with `Terminal::Unknown` (ambiguous or truthless).
    unknown_terminals: u64,
    /// Decoded records dropped by the observation cap (COUNTED, not
    /// a flag — feeds `observations_truncated` and integrity).
    omitted: u64,
    /// Quiet-verdict close backlog in ring bytes.
    backlog_bytes: u64,
}

fn lifecycle_coverage(
    ledger: &LifecycleLedger,
    attached_points: usize,
    expected_points: usize,
    observations_decoded: u64,
    close: &LifecycleCloseStats,
    interval: ValidityInterval,
) -> CoverageSummary {
    let dim = |status| DimensionCoverage::new(status, interval);
    // Attach: counted at bring-up (always measured).
    let mut attachment = dim(if attached_points == expected_points {
        CoverageStatus::CompleteForDeclaredBoundary
    } else {
        CoverageStatus::Partial
    });
    attachment
        .counters
        .push(counter("probes_attached", attached_points as u64));
    attachment
        .counters
        .push(counter("probes_expected", expected_points as u64));
    // Count-corrupting loss: any kernel loss class (reserve failures
    // drop edges; disabled/badkey/fret mean the sensor skipped work),
    // any per-program recursion-miss session delta (H2: the kernel
    // skipped whole runs — no edge, no LLOSS, only the miss counter
    // sees it), any refused/corrupt/synthesized/stale decode
    // evidence, and any reducer evidence that never became a
    // trustworthy record (orphans, ambiguous, admission failures).
    // Duplicates repeat known state — no information lost, never
    // flipping. A loss-clean ledger is still `Unknown`: internal
    // pairing cannot prove kernel hook-delivery (S04/G9 twin).
    let count_loss = ledger
        .kernel_loss
        .iter()
        .fold(0u64, |sum, loss| sum.saturating_add(*loss));
    let count_loss = count_loss
        .saturating_add(prog_miss_delta_sum(&ledger.prog_misses))
        .saturating_add(ledger.decode.submit_refused)
        .saturating_add(ledger.decode.unknown_invoc_returns)
        .saturating_add(ledger.decode.bad_records)
        .saturating_add(ledger.decode.gaps_synthesized)
        .saturating_add(ledger.decode.stale_returns)
        .saturating_add(ledger.reducer.orphan)
        .saturating_add(ledger.reducer.ambiguous)
        .saturating_add(ledger.reducer.admission_failed);
    let mut aggregate_counts = dim(if count_loss > 0 {
        CoverageStatus::Partial
    } else {
        CoverageStatus::Unknown
    });
    if count_loss == 0 {
        aggregate_counts
            .counters
            .push(counter("uncovered:kernel_delivery_unmeasured", 1));
    }
    for (hook, hits) in ledger.edge_hits.iter().enumerate() {
        aggregate_counts
            .counters
            .push(counter(&format!("edge_hits_hook{hook}"), *hits));
    }
    aggregate_counts
        .counters
        .push(counter("count_loss", count_loss));
    aggregate_counts.counters.push(counter(
        "prog_miss_delta",
        prog_miss_delta_sum(&ledger.prog_misses),
    ));
    aggregate_counts
        .counters
        .push(counter("submits_admitted", ledger.reducer.admitted));
    // Detailed events: measured ring reserve failures + retention
    // drops + close-time ring backlog + unexplained aggregate
    // residual (accepted minus consumed, reserve, and noslot with an
    // empty close ring — the accounting equation broke). A clean
    // transport is still `Unknown` (S04 twin: transport health
    // cannot prove the kernel invoked the sensor for every
    // operation).
    let ring_drops = ledger.kernel_loss[0];
    let agg_sum: u64 = ledger
        .agg_accepted
        .iter()
        .fold(0, |s, a| s.saturating_add(*a));
    let hits_sum: u64 = ledger.edge_hits.iter().fold(0, |s, h| s.saturating_add(*h));
    let residual = agg_sum
        .saturating_sub(hits_sum)
        .saturating_sub(ledger.kernel_loss[0])
        .saturating_sub(ledger.kernel_loss[4]);
    // The residual flips only with an empty close ring (backlog
    // bytes explain accepted-but-unconsumed edges — roughly, a byte
    // count, not a record count, so the equation stays descriptive).
    let transport_clean = ring_drops == 0
        && ledger.retained_dropped == 0
        && close.backlog_bytes == 0
        && residual == 0;
    let mut detailed_events = dim(if transport_clean {
        CoverageStatus::Unknown
    } else {
        CoverageStatus::Partial
    });
    if transport_clean {
        detailed_events
            .counters
            .push(counter("uncovered:kernel_delivery_unmeasured", 1));
    }
    detailed_events
        .counters
        .push(counter("ring_drops", ring_drops));
    detailed_events
        .counters
        .push(counter("retained_dropped", ledger.retained_dropped));
    detailed_events
        .counters
        .push(counter("close_backlog_bytes", close.backlog_bytes));
    detailed_events
        .counters
        .push(counter("agg_accepted", agg_sum));
    detailed_events
        .counters
        .push(counter("agg_consumed", hits_sum));
    detailed_events
        .counters
        .push(counter("agg_residual_unexplained", residual));
    // Completion: every decoded record grounded in observed terminal
    // truth (no unfinished, no `Unknown` terminals, no truncation)
    // completes over the admitted requests — PROVISIONALLY (M2
    // provisional-hold: the commit ALSO requires a loss-clean ledger,
    // a clean transport, and a verified sensor identity, since any
    // miss voids the exact counts the completion claim rests on).
    // Truthless-drained, ambiguous, truncated, lossy, or
    // identity-void records flip `Partial` (their terminals are
    // explicit unknowns — or unattributed evidence — never trusted
    // results). Commit-before-report: nothing downstream reads a
    // completion verdict until this gate commits it.
    let commit_clean = count_loss == 0 && transport_clean && ledger.view_valid;
    let mut completion = dim(
        if ledger.reducer.unfinished == 0
            && close.unknown_terminals == 0
            && close.omitted == 0
            && commit_clean
        {
            CoverageStatus::CompleteForDeclaredBoundary
        } else {
            CoverageStatus::Partial
        },
    );
    completion
        .counters
        .push(counter("identity_verified", u64::from(ledger.view_valid)));
    completion
        .counters
        .push(counter("observations_decoded", observations_decoded));
    completion.counters.push(counter(
        "terminals_grounded",
        observations_decoded.saturating_sub(close.unknown_terminals),
    ));
    completion
        .counters
        .push(counter("unfinished_truthless", ledger.reducer.unfinished));
    completion
        .counters
        .push(counter("unknown_terminals", close.unknown_terminals));
    completion
        .counters
        .push(counter("observations_truncated", close.omitted));
    // Attribution: lifecycle rows carry no context class (the
    // aggregate ctx-class rationale does not transfer) — always
    // `Unknown` with the reason counter.
    let mut attribution = dim(CoverageStatus::Unknown);
    attribution
        .counters
        .push(counter("uncovered:attribution_unobserved", 1));
    // Correlation: transport-loss gaps, stale joins, unjoined
    // returns, refused submits, ambiguous evidence, and reducer
    // orphans are ALL correlation events — any flips `Partial`; a
    // single backend with zero such events completes the declared
    // boundary. (Round-3 minor: omitting `unknown_invoc_returns` /
    // `submit_refused` let a lone tainted return claim Complete.)
    let correlation_events = ledger
        .decode
        .gaps_synthesized
        .saturating_add(ledger.decode.stale_returns)
        .saturating_add(ledger.decode.unknown_invoc_returns)
        .saturating_add(ledger.decode.submit_refused)
        .saturating_add(ledger.reducer.ambiguous)
        .saturating_add(ledger.reducer.orphan);
    let mut correlation = dim(if correlation_events == 0 {
        CoverageStatus::CompleteForDeclaredBoundary
    } else {
        CoverageStatus::Partial
    });
    correlation
        .counters
        .push(counter("correlation_events", correlation_events));
    // Declared-boundary vacuous dimensions (the session_coverage
    // rationale, unchanged: whole-machine, resolved symbols).
    CoverageSummary {
        target_population: dim(CoverageStatus::CompleteForDeclaredBoundary),
        object_discovery: dim(CoverageStatus::CompleteForDeclaredBoundary),
        attachment,
        aggregate_counts,
        detailed_events,
        attribution,
        correlation,
        completion,
    }
}

/// Spawn the closed-stdin watcher: EOF (or a stdin error, read as closed)
/// sets the stop flag. Input bytes are not a stop signal. Generic over
/// the reader so tests feed a cursor; production passes `stdin()`. The
/// handle is detached (never joined — a blocked stdin read has no
/// timeout; process exit reaps it).
///
/// 1A-M2: spawn failure (thread limit, memory pressure) is a genuine
/// OS error, so it returns `LiveError::Internal` — never a panic.
fn spawn_stdin_watcher<R: std::io::Read + Send + 'static>(
    reader: R,
    stop: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, LiveError> {
    std::thread::Builder::new()
        .name("kryprobe-stdin-watch".to_owned())
        .spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 64];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        })
        .map_err(|err| LiveError::Internal(format!("live stdin watcher spawn: {err}")))
}

/// Sleep one tick in stop-poll slices (early-out on the stop flag
/// or a recorded SIGINT).
fn sleep_tick(tick_ms: u64, stop: &AtomicBool) {
    let mut remaining = tick_ms;
    while remaining > 0 && !stop.load(Ordering::Relaxed) && !SIGINT_SEEN.load(Ordering::Relaxed) {
        let slice = remaining.min(STOP_POLL_MS);
        std::thread::sleep(Duration::from_millis(slice));
        remaining = remaining.saturating_sub(slice);
    }
}

/// Session sensor seam (P0-4 / 3A-C-T2): everything the tick driver
/// reads from the live sensor. Production serves [`RealSensor`]
/// (session-owned sensor + session drain); tests serve scripted ticks
/// with no privilege. `snapshot_tick` receives the shared stop flag
/// so a script can end the session after its Nth tick; the
/// production impl ignores it (deadline/stdin still stop the loop).
pub trait SessionSensor {
    /// One snapshot pass (`barrier_id` counts 1, 2, … per session).
    fn snapshot_tick(
        &mut self,
        barrier_id: u64,
        stop: &AtomicBool,
    ) -> Result<SnapshotRows, LiveError>;
    /// Raw kallsyms text for this tick's who rows (read once per
    /// tick, 2B-C2 — the counting seam for H-T3; the driver parses it
    /// once via [`SymTable::parse`] with the text kept alive locally).
    fn kallsyms_text(&mut self) -> String;
    /// Who attribution rows for this tick (drops merge at finalize).
    fn snapshot_who(&mut self) -> Result<(Vec<WhoSnapshot>, u64), LiveError>;
    /// The 8 `KDROPS` pre-KTOT skip sites.
    fn drop_sites(&mut self) -> Result<[u64; 8], LiveError>;
    /// End-of-session teardown (runs once, after the closing tick).
    fn finish(&mut self);
}

/// Production sensor: the session-owned sensor plus its session
/// drain (2B-C1: one spawn for all ticks) plus the cross-tick
/// who-join cache (H4: quiescent rows skip their joins).
#[derive(Debug)]
pub struct RealSensor<'a> {
    sensor: &'a ConfiguredKcrypto,
    drain: Option<DrainThread>,
    who_cache: WhoCache,
}

impl<'a> RealSensor<'a> {
    /// Opens the session drain; drain stats stay discarded (see the
    /// snapshot docs).
    pub fn new(sensor: &'a ConfiguredKcrypto) -> Result<Self, LiveError> {
        let drain = session_drain(sensor)
            .map_err(|err| LiveError::Internal(format!("live session drain: {err}")))?;
        Ok(Self {
            sensor,
            drain: Some(drain),
            who_cache: WhoCache::new(),
        })
    }
}

impl SessionSensor for RealSensor<'_> {
    fn snapshot_tick(
        &mut self,
        barrier_id: u64,
        _stop: &AtomicBool,
    ) -> Result<SnapshotRows, LiveError> {
        let drain = self
            .drain
            .as_ref()
            .ok_or_else(|| LiveError::Internal("live snapshot after finish".to_owned()))?;
        snapshot_rows_with_drain(self.sensor, drain, barrier_id)
            .map_err(|err| LiveError::Internal(format!("live snapshot: {err}")))
    }

    fn kallsyms_text(&mut self) -> String {
        read_kallsyms()
    }

    fn snapshot_who(&mut self) -> Result<(Vec<WhoSnapshot>, u64), LiveError> {
        snapshot_who_cached(self.sensor, &mut self.who_cache)
            .map_err(|err| LiveError::Internal(format!("live snapshot who: {err}")))
    }

    fn drop_sites(&mut self) -> Result<[u64; 8], LiveError> {
        snapshot_drops(self.sensor)
            .map_err(|err| LiveError::Internal(format!("live snapshot drops: {err}")))
    }

    fn finish(&mut self) {
        if let Some(drain) = self.drain.take() {
            let _drain_stats = drain.stop();
        }
    }
}

/// Lifecycle session sensor seam (T06 item 4 twin of [`SessionSensor`]):
/// everything the lifecycle tick driver reads from the live backend.
/// Production serves [`RealLifecycleSensor`] (the shared backend's own
/// sensor, locked in place — no handle duplication); tests serve
/// scripted drains with no privilege. The seam owns the ring-clock
/// domain: [`now_ns`](LifecycleSessionSensor::now_ns) stamps the
/// coverage interval and the stop-time `finish` in `CLOCK_MONOTONIC`.
pub trait LifecycleSessionSensor {
    /// Drain newly produced ring records into the terminal ledger (at
    /// most `max_records` visits).
    fn drain_tick(&mut self, max_records: usize) -> Result<DrainOutcome, LiveError>;
    /// Drain retained completions (each record surfaces once).
    fn take_completed(&mut self) -> Result<Vec<RequestRecord>, LiveError>;
    /// M2 read-after-ingest: re-verify sensor identity while attached
    /// (the ledger re-verifies post-detach; both feed the same sticky
    /// bit, and coverage consults it — a void verdict never aborts
    /// teardown, it flips the report).
    fn verify_identity(&self) -> Result<(), LiveError>;
    /// Detach-then-drain, step 1: drop the attach links (no hook
    /// fires after; the closing drain converges).
    fn close_input(&mut self) -> Result<(), LiveError>;
    /// Detach-then-drain, step 2: bounded quiet loop; the exact
    /// close backlog reaches the ledger (coverage flips on it).
    fn drain_quiet(&mut self) -> Result<QuietOutcome, LiveError>;
    /// Drain pending truthless into retention (stop-the-world): the
    /// final reconciliation at `stop_ns` (ring-clock domain).
    /// Returns nothing — read via [`Self::take_completed`].
    fn finish_stop(&mut self, stop_ns: u64) -> Result<(), LiveError>;
    /// Snapshot the terminal ledger (finalize + coverage read this).
    fn ledger(&self) -> Result<LifecycleLedger, LiveError>;
    /// Ring-clock now (`CLOCK_MONOTONIC` ns): the coverage interval
    /// walls and the `finish` stamp come from here (measured, never a
    /// separate wall clock the ring cannot share).
    fn now_ns(&self) -> Result<u64, LiveError>;
}

/// Production lifecycle sensor: the shared backend, whose mutex is the
/// single sensor owner (ticks lock it in place — the sensor is
/// `!Clone` by design, so no H1(b) handle duplication exists here).
#[derive(Debug)]
pub struct RealLifecycleSensor<'a> {
    backend: &'a LifecycleBackend,
}

impl<'a> RealLifecycleSensor<'a> {
    /// Borrows the shared backend's sensor owner for the session.
    #[must_use]
    pub fn new(backend: &'a LifecycleBackend) -> Self {
        Self { backend }
    }
}

impl LifecycleSessionSensor for RealLifecycleSensor<'_> {
    fn drain_tick(&mut self, max_records: usize) -> Result<DrainOutcome, LiveError> {
        self.backend
            .drain_tick(max_records)
            .map_err(|err| backend_err("live lifecycle drain", err))
    }

    fn take_completed(&mut self) -> Result<Vec<RequestRecord>, LiveError> {
        self.backend
            .take_completed()
            .map_err(|err| backend_err("live lifecycle take", err))
    }

    fn verify_identity(&self) -> Result<(), LiveError> {
        self.backend
            .verify_identity()
            .map_err(|err| backend_err("live lifecycle identity", err))
    }

    fn close_input(&mut self) -> Result<(), LiveError> {
        self.backend
            .close_input()
            .map_err(|err| backend_err("live lifecycle close", err))
    }

    fn drain_quiet(&mut self) -> Result<QuietOutcome, LiveError> {
        self.backend
            .drain_quiet()
            .map_err(|err| backend_err("live lifecycle quiet", err))
    }

    fn finish_stop(&mut self, stop_ns: u64) -> Result<(), LiveError> {
        self.backend
            .finish_stop(stop_ns)
            .map_err(|err| backend_err("live lifecycle finish", err))
    }

    fn ledger(&self) -> Result<LifecycleLedger, LiveError> {
        self.backend
            .lifecycle_ledger()
            .map_err(|err| backend_err("live lifecycle ledger", err))
    }

    fn now_ns(&self) -> Result<u64, LiveError> {
        monotonic_ns().map_err(|err| LiveError::Internal(format!("live lifecycle clock: {err}")))
    }
}

/// Latest-per-key identity (H2): mirrors the render's downstream
/// keys exactly — agg `(family, op, result, algorithm, driver,
/// context)` collapses to the shared `kh_of` identity hash (it covers
/// all six render fields); who matches `(key_hash, tgid)`; totals is
/// a singleton. Idents are disjoint across ticks and bypass the map
/// (every ident is kept).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ObsKey {
    Agg(u64),
    Totals,
    Who(u64, u32),
}

/// Latest-wins insert at first-seen position (H2): repeats overwrite
/// in place (cumulative counters supersede), new keys append in tick
/// order. Memory is O(keys + idents), never O(ticks × rows).
fn upsert_latest(
    index: &mut HashMap<ObsKey, usize>,
    observations: &mut Vec<NativeObservation>,
    key: ObsKey,
    observation: NativeObservation,
) {
    match index.entry(key) {
        Entry::Occupied(slot) => observations[*slot.get()] = observation,
        Entry::Vacant(slot) => {
            slot.insert(observations.len());
            observations.push(observation);
        }
    }
}

/// Governed tick driver over a caller-supplied sensor (P0-4 +
/// 1B-H4): the ARCH §4.1 machine walks `Attaching -> Observing ->
/// Quiescing -> Draining -> Finalized` on the success path; any
/// failure after `Observing` parks it in `FailedPartial` (best-effort
/// — the original error always wins, fail-closed preserved).
///
/// Callers bring the controller to `Attaching` first (production via
/// `run_live_session` bring-up); a refused entry hop is a loud
/// `Internal`, never a silent skip. `concrete` stages the
/// closing-tick counts for the finalize fast path (M5): production
/// passes the shared backend, scripted tests pass `None` (their fake
/// finalizes need no staging).
#[allow(clippy::too_many_arguments)]
pub fn drive_session(
    cfg: &LiveConfig,
    backend: &dyn Backend,
    sensor: &mut dyn SessionSensor,
    stop: &AtomicBool,
    attached_points: usize,
    session: SessionId,
    generation: PlanGeneration,
    issuer: &IdIssuer,
    concrete: Option<&KCryptoBackend>,
    controller: &mut SessionController,
    progress: Option<&TickProgress>,
) -> Result<LiveOutcome, LiveError> {
    hop(controller, SessionState::Observing, "session start")?;
    match drive_session_inner(
        cfg,
        backend,
        sensor,
        stop,
        attached_points,
        session,
        generation,
        issuer,
        concrete,
        controller,
        progress,
    ) {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            let _ = controller.transition(SessionState::FailedPartial);
            Err(err)
        }
    }
}

/// One governed session hop (1B-H4): a refused hop is a loud
/// `Internal` naming the stage — phase reorderings fail here, not
/// silently.
fn hop(controller: &mut SessionController, to: SessionState, stage: &str) -> Result<(), LiveError> {
    controller
        .transition(to)
        .map_err(|err| LiveError::Internal(format!("live session machine refused {stage}: {err}")))
}

/// Tick driver over a caller-supplied sensor (P0-4): the tick loop
/// (snapshot → parse each row once → decode each → who attribution
/// with latest-per-key accumulation), then finalize ONCE and the
/// shared feed ONCE, then coverage from the session measurements.
/// NEVER finalizes per tick (D1/M1).
#[allow(clippy::too_many_arguments)]
fn drive_session_inner(
    cfg: &LiveConfig,
    backend: &dyn Backend,
    sensor: &mut dyn SessionSensor,
    stop: &AtomicBool,
    attached_points: usize,
    session: SessionId,
    generation: PlanGeneration,
    issuer: &IdIssuer,
    concrete: Option<&KCryptoBackend>,
    controller: &mut SessionController,
    progress: Option<&TickProgress>,
) -> Result<LiveOutcome, LiveError> {
    let baseline = IntegritySummary::default();
    // Tick loop: snapshot → raw events in row order → decode each
    // (first error aborts `Internal`). Always at least the opening
    // tick, even for a zero-second window; the tick at/after the
    // deadline is the closing snapshot.
    // Sub-ms ticks are meaningless against snapshot cost; floor at 1ms.
    let tick_ms = cfg.tick_ms.max(1);
    let start_wall = Instant::now();
    let deadline = cfg
        .duration_secs
        .map(|secs| start_wall + Duration::from_secs(secs));
    let mut observations: Vec<NativeObservation> = Vec::new();
    let mut latest: HashMap<ObsKey, usize> = HashMap::new();
    let mut overflow_identities = 0u64;
    let mut first_wall = 0u64;
    let mut first_tick = true;
    let mut barrier_id = 0u64;
    // Closing tick's parsed call counts (H3): each tick overwrites, so
    // the gap recompute after the loop never re-parses the closing
    // snapshot's rows. Deferred init: the loop always ticks at least
    // once, so both are assigned before any `break`.
    let mut closing_agg_calls: Vec<u64>;
    let mut closing_totals_calls: Option<u64>;
    // 4B-M5: latched when the loop observes a recorded SIGINT — the
    // session finalizes normally and the outcome carries `interrupted`.
    let mut interrupted = false;
    let closing: SnapshotRows = loop {
        barrier_id += 1;
        let snap = sensor.snapshot_tick(barrier_id, stop)?;
        // Coverage interval walls come from the snapshots themselves
        // (measured `CLOCK_MONOTONIC`, no separate clock read).
        if first_tick {
            first_wall = snap.monotonic_ns;
            first_tick = false;
        }
        let decode_ctx = DecodeContext {
            session,
            generation,
            integrity: &baseline,
            id_issuer: issuer,
        };
        // Each row parses ONCE (H3): the parsed form yields the dedup
        // key, the header stamp, and the gap call counts. `decode`
        // re-parses internally (frozen-trait residual: `decode` takes
        // row bytes, not rows — the header pre-parse and the gap
        // re-parse are the parses this loop eliminates).
        let mut tick_agg_calls = Vec::with_capacity(snap.rows.len());
        let mut tick_totals_calls = None;
        for row in &snap.rows {
            let parsed = parse_snapshot_row(row.as_bytes())
                .map_err(|err| LiveError::Internal(format!("live parse agg: {err}")))?;
            let ParsedRow::Agg { kagg, vagg } = parsed else {
                return Err(LiveError::Internal(
                    "live parse agg: unexpected row kind".to_owned(),
                ));
            };
            tick_agg_calls.push(vagg.calls);
            let key = ObsKey::Agg(kh_of(
                kagg.fam(),
                kagg.op(),
                kagg.res(),
                kagg.ctx(),
                &kagg.alg(),
                &kagg.drv(),
            ));
            let observation = decode_tick_row(
                backend,
                &decode_ctx,
                raw_event_stamped(row.as_bytes(), vagg.last_ns),
                "agg",
            )?;
            upsert_latest(&mut latest, &mut observations, key, observation);
        }
        if let Some(totals) = &snap.totals {
            let parsed = parse_snapshot_row(totals.as_bytes())
                .map_err(|err| LiveError::Internal(format!("live parse totals: {err}")))?;
            let ParsedRow::Totals { vagg } = parsed else {
                return Err(LiveError::Internal(
                    "live parse totals: unexpected row kind".to_owned(),
                ));
            };
            tick_totals_calls = Some(vagg.calls);
            let observation = decode_tick_row(
                backend,
                &decode_ctx,
                raw_event_stamped(totals.as_bytes(), vagg.last_ns),
                "totals",
            )?;
            upsert_latest(&mut latest, &mut observations, ObsKey::Totals, observation);
        }
        for ident in &snap.idents {
            let parsed = parse_snapshot_row(ident.as_bytes())
                .map_err(|err| LiveError::Internal(format!("live parse ident: {err}")))?;
            let ParsedRow::Ident { kctl } = parsed else {
                return Err(LiveError::Internal(
                    "live parse ident: unexpected row kind".to_owned(),
                ));
            };
            let observation = decode_tick_row(
                backend,
                &decode_ctx,
                raw_event_stamped(ident.as_bytes(), kctl.val2),
                "ident",
            )?;
            // Idents are disjoint across ticks: every one is kept.
            observations.push(observation);
        }
        // K5 attribution: who rows decode from the session sensor's
        // who maps on the same tick. Kallsyms is read AND parsed ONCE
        // per tick (per-row parse+sort re-sorts ~1e5 entries per row,
        // 2B-C2; per-session would go stale across module load/unload)
        // and the table is shared across all rows; ids draw from the
        // session issuer so who rows sequence with the tick's other
        // rows. Per-tick who drops are NOT fed here — `finalize`
        // merges them (Task 4), and the shared feed only speaks
        // ring/queue counters.
        let (whos, _who_drops) = sensor.snapshot_who()?;
        let kallsyms = sensor.kallsyms_text();
        let table = SymTable::parse(&kallsyms);
        for who in &whos {
            let id = issuer
                .issue()
                .map_err(|_| LiveError::Internal("live who id exhausted".to_owned()))?;
            upsert_latest(
                &mut latest,
                &mut observations,
                ObsKey::Who(who.key.kh, who.key.tgid),
                observation_for_who(who, id, &table),
            );
        }
        closing_agg_calls = tick_agg_calls;
        closing_totals_calls = tick_totals_calls;
        overflow_identities = overflow_identities.saturating_add(snap.overflow_identities);
        interrupted |= SIGINT_SEEN.load(Ordering::Relaxed);
        if let Some(report) = progress {
            report(
                barrier_id,
                (snap.rows.len() + snap.idents.len()) as u64,
                u64::from(snap.drops),
            );
        }
        let stopped = stop.load(Ordering::Relaxed)
            || interrupted
            || deadline.is_some_and(|end| Instant::now() >= end);
        if stopped {
            break snap;
        }
        sleep_tick(tick_ms, stop);
    };
    // Observing -> Quiescing: the loop stopped taking new work.
    hop(controller, SessionState::Quiescing, "session quiesce")?;
    // Session drain stops once, after the closing tick: later snapshots
    // (finalize) run their own one-shot drains.
    sensor.finish();
    // Stage closing counts for the finalize fast path (M5): the
    // same parsed counts the coverage gap uses below, so finalize
    // and coverage agree by construction.
    if let Some(concrete) = concrete {
        let agg_calls = closing_agg_calls
            .iter()
            .fold(0u64, |sum, calls| sum.saturating_add(*calls));
        concrete.stage_closing_counts(ClosingCounts {
            generation,
            agg_calls,
            totals_calls: closing_totals_calls,
            drops: closing.drops,
        });
    }
    // Quiescing -> Draining: queued events become evidence now.
    hop(controller, SessionState::Draining, "session drain")?;
    // Finalize ONCE, then the shared feed ONCE.
    // All-`NotRun` baseline is core's (1B-H1): the backend ignores its
    // context — it assesses its own sensor.
    let notrun = CoverageSummary::not_run();
    let summary = backend
        .finalize(&FinalizeContext {
            session,
            coverage: &notrun,
            integrity: &baseline,
        })
        .map_err(|err| backend_err("live finalize", err))?;
    // Feed drops come from the closing snapshot's retained read (M3):
    // no end-of-session re-read of the key (a drop landing between the
    // closing snapshot and the feed is unattributed — a microseconds
    // window, versus a guaranteed extra syscall before).
    let drops = closing.drops;
    let mut report = DriverReport::default();
    // 1B-L4: checked transitions only — no field assignment.
    report.extend_observations(observations);
    report.push_summary(summary);
    report
        .feed_shared_losses(shared_losses_from_snapshot(&closing, drops))
        .map_err(|err| LiveError::Internal(format!("live shared feed: {err}")))?;
    let integrity = report
        .session_integrity_checked()
        .map_err(|err| LiveError::Internal(format!("live session integrity: {err}")))?;
    let gap = ktot_gap_from_calls(&closing_agg_calls, closing_totals_calls);
    let kdrop_sites = sensor.drop_sites()?;
    let coverage = session_coverage(&SessionMeasurements {
        attached_points,
        expected_points: KCRYPTO_SYMBOLS.len(),
        totals_present: closing.totals.is_some(),
        ktot_gap: gap,
        ring_drops: u64::from(drops),
        overflow_identities,
        drops: kdrop_sites,
        observations_decoded: report.observations().len() as u64,
        interval: ValidityInterval {
            start_ns: first_wall,
            end_ns: Some(closing.monotonic_ns),
        },
    });
    hop(controller, SessionState::Finalized, "session finalize")?;
    Ok(LiveOutcome {
        observations: report.take_observations(),
        summary,
        coverage,
        integrity,
        terminal_state: controller.state(),
        interrupted,
    })
}

/// Per-tick ring-drain visit cap: 8192 covers a full ring (≈5461
/// records at 48 B per frame) plus margin, still bounded — a tick
/// never leaves routine backlog for the next one.
const LIFECYCLE_DRAIN_BUDGET: usize = 8192;

/// Session observation cap (design C12: configured bound, counted
/// admission, deterministic stop): past 100K decoded records the
/// session stops early with an explicit truncation counter and
/// `Partial` completion — memory stays ≈tens of MB, never
/// O(flood).
const LIFECYCLE_OBSERVATION_CAP: usize = 100_000;

/// Governed lifecycle tick driver (T06 item 4 twin of [`drive_session`]):
/// the same ARCH §4.1 tail — `Observing -> Quiescing -> Draining ->
/// Finalized` on success, `FailedPartial` on any failure after
/// `Observing` (best-effort; the original error always wins).
#[allow(clippy::too_many_arguments)]
pub fn drive_lifecycle_session(
    cfg: &LiveConfig,
    backend: &dyn Backend,
    sensor: &mut dyn LifecycleSessionSensor,
    stop: &AtomicBool,
    attached_points: usize,
    session: SessionId,
    generation: PlanGeneration,
    issuer: &IdIssuer,
    controller: &mut SessionController,
    progress: Option<&TickProgress>,
) -> Result<LiveOutcome, LiveError> {
    hop(controller, SessionState::Observing, "lifecycle start")?;
    match drive_lifecycle_session_inner(
        cfg,
        backend,
        sensor,
        stop,
        attached_points,
        session,
        generation,
        issuer,
        controller,
        progress,
    ) {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            let _ = controller.transition(SessionState::FailedPartial);
            Err(err)
        }
    }
}

/// Lifecycle tick driver (T06 item 4 twin of [`drive_session_inner`]):
/// per-tick ring drain → completed records → `decode` each (first
/// error aborts `Internal`), then stop-time `finish` reconciliation,
/// then `finalize` ONCE and the shared feed ONCE, then coverage from
/// the terminal ledger. NEVER finalizes per tick (D1/M1).
///
/// Completed records are disjoint across ticks (each surfaces once
/// from retention), so every decoded record is kept — memory is
/// O(completions), the ident precedent, never O(ticks × rows).
#[allow(clippy::too_many_arguments)]
fn drive_lifecycle_session_inner(
    cfg: &LiveConfig,
    backend: &dyn Backend,
    sensor: &mut dyn LifecycleSessionSensor,
    stop: &AtomicBool,
    attached_points: usize,
    session: SessionId,
    generation: PlanGeneration,
    issuer: &IdIssuer,
    controller: &mut SessionController,
    progress: Option<&TickProgress>,
) -> Result<LiveOutcome, LiveError> {
    let baseline = IntegritySummary::default();
    let tick_ms = cfg.tick_ms.max(1);
    let start_wall = Instant::now();
    let deadline = cfg
        .duration_secs
        .map(|secs| start_wall + Duration::from_secs(secs));
    let mut observations: Vec<NativeObservation> = Vec::new();
    let mut first_wall = 0u64;
    let mut first_tick = true;
    let mut barrier_id = 0u64;
    let mut interrupted = false;
    // `Unknown`-terminal records counted from the records
    // themselves: the ambiguous reducer branch emits `Unknown`
    // without touching `unfinished`, so the ledger alone cannot
    // prove grounding — the driver (which sees every record) can.
    // The observation cap truncates deterministically: at capacity
    // the session stops early (flag below) instead of growing
    // unbounded — kept observations stay valid evidence.
    let mut unknown_terminals = 0u64;
    // Shared with the decode closure across loop iterations (the
    // closure mutably borrows the terminal counter; the omission
    // COUNT rides a `Cell` so the loop can read it while the closure
    // is alive). The cap drops are COUNTED (remaining batch length
    // at each break), never a bare flag: the count feeds coverage
    // AND backend integrity (`budget_omissions`).
    let omitted = std::cell::Cell::new(0u64);
    let mut decode_records = |records: Vec<RequestRecord>,
                              observations: &mut Vec<NativeObservation>|
     -> Result<(), LiveError> {
        for (idx, record) in records.iter().enumerate() {
            if observations.len() >= LIFECYCLE_OBSERVATION_CAP {
                let remaining = records.len().saturating_sub(idx) as u64;
                omitted.set(omitted.get().saturating_add(remaining));
                break;
            }
            let decode_ctx = DecodeContext {
                session,
                generation,
                integrity: &baseline,
                id_issuer: issuer,
            };
            let (header, payload) = lifecycle_event(record);
            let observation = decode_tick_row(
                backend,
                &decode_ctx,
                RawEvent {
                    header,
                    payload: &payload,
                },
                "lifecycle",
            )?;
            if record.terminal == kryprobe_core::kcrypto::Terminal::Unknown {
                unknown_terminals += 1;
            }
            observations.push(observation);
        }
        Ok(())
    };
    loop {
        barrier_id += 1;
        let now = sensor.now_ns()?;
        // Coverage interval walls come from the ring clock itself
        // (the snapshot precedent: measured `CLOCK_MONOTONIC`, no
        // separate clock read the ring cannot share).
        if first_tick {
            first_wall = now;
            first_tick = false;
        }
        let drained = sensor.drain_tick(LIFECYCLE_DRAIN_BUDGET)?;
        let completed = sensor.take_completed()?;
        let completed_this_tick = completed.len() as u64;
        decode_records(completed, &mut observations)?;
        interrupted |= SIGINT_SEEN.load(Ordering::Relaxed);
        if let Some(report) = progress {
            // Human-only liveness (4B-M4): completions decoded this
            // tick plus raw records consumed (drops ride the ledger).
            report(barrier_id, completed_this_tick, drained.records as u64);
        }
        let stopped = stop.load(Ordering::Relaxed)
            || interrupted
            || omitted.get() > 0
            || deadline.is_some_and(|end| Instant::now() >= end);
        if stopped {
            break;
        }
        sleep_tick(tick_ms, stop);
    }
    // Observing -> Quiescing: the loop stopped taking new work.
    hop(controller, SessionState::Quiescing, "lifecycle quiesce")?;
    // Stop-time reconciliation, detach-then-drain: links drop first
    // (no hook fires after, so the close converges), then the quiet
    // loop plays every landed edge — its verdict's backlog reaches
    // the ledger and flips coverage, never ignored — then truthless
    // `finish` at the closing wall turns every pending request into
    // a record (grounded or explicit-unknown).
    let end_ns = sensor.now_ns()?;
    // M2 read-after-ingest (full, while attached): a void verdict
    // must NOT abort teardown — the sticky bit carries it into the
    // ledger, where coverage flips Partial and integrity counts it.
    let _ = sensor.verify_identity();
    sensor.close_input()?;
    // The quiet verdict feeds coverage below (backlog bytes flip
    // `detailed_events`) — consumed, never ignored, never asserted
    // (a corrupt ring reports Partial, it does not panic).
    let quiet = sensor.drain_quiet()?;
    let completed = sensor.take_completed()?;
    decode_records(completed, &mut observations)?;
    sensor.finish_stop(end_ns)?;
    let reconciled = sensor.take_completed()?;
    decode_records(reconciled, &mut observations)?;
    // Cap omissions attest BEFORE finalize reads them: the driver
    // dropped decoded records the sensor counted, so the backend
    // surfaces the count via `budget_omissions` (never silent).
    backend.note_output_omissions(omitted.get());
    // Quiescing -> Draining: queued events become evidence now.
    hop(controller, SessionState::Draining, "lifecycle drain")?;
    // Finalize ONCE, then the shared feed ONCE.
    let notrun = CoverageSummary::not_run();
    let summary = backend
        .finalize(&FinalizeContext {
            session,
            coverage: &notrun,
            integrity: &baseline,
        })
        .map_err(|err| backend_err("live lifecycle finalize", err))?;
    let ledger = sensor.ledger()?;
    let mut report = DriverReport::default();
    report.extend_observations(std::mem::take(&mut observations));
    report.push_summary(summary);
    // Empty shared feed (required, but zero): the lifecycle drain
    // lives INSIDE the backend, so its ring reserve failures and
    // retention drops already ride the summary integrity above —
    // feeding the same counters here would double-count through
    // `session_integrity` (which adds the shared feed on top of the
    // per-backend sums). Nothing outside any backend observed loss.
    report
        .feed_shared_losses(SharedLosses::new(0, 0))
        .map_err(|err| LiveError::Internal(format!("live lifecycle shared feed: {err}")))?;
    let integrity = report
        .session_integrity_checked()
        .map_err(|err| LiveError::Internal(format!("live lifecycle session integrity: {err}")))?;
    let close = LifecycleCloseStats {
        unknown_terminals,
        omitted: omitted.get(),
        backlog_bytes: quiet.backlog_bytes,
    };
    let coverage = lifecycle_coverage(
        &ledger,
        attached_points,
        max_programs(&manifest(LifecycleProfile::RequestLifecycle)),
        report.observations().len() as u64,
        &close,
        ValidityInterval {
            start_ns: first_wall,
            end_ns: Some(end_ns),
        },
    );
    hop(controller, SessionState::Finalized, "lifecycle finalize")?;
    Ok(LiveOutcome {
        observations: report.take_observations(),
        summary,
        coverage,
        integrity,
        terminal_state: controller.state(),
        interrupted,
    })
}

/// Live kcrypto capture: shared registry + the concrete backend
/// handle, then the injectable session below. See the module docs for
/// the flow.
///
/// Profile dispatch (T06 item 4): registry and live entry points both
/// select through [`register_kcrypto_profile`] — `api-returns` drives
/// the aggregate session, `request-lifecycle` the lifecycle session —
/// so the two can never choose different profiles/decoders.
pub fn run_live_capture(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
) -> Result<LiveOutcome, LiveError> {
    let mut registry = BackendRegistry::new();
    let profiled = register_kcrypto_profile(&mut registry, cfg.profile)
        .map_err(|err| LiveError::Internal(format!("kcrypto registration: {err}")))?;
    match profiled {
        ProfileBackend::ApiReturns(shared) => {
            run_live_session(cfg, runtime, &registry, Some(shared.backend()))
        }
        ProfileBackend::RequestLifecycle(shared) => {
            run_lifecycle_session(cfg, runtime, &registry, &shared)
        }
    }
}

/// Live capture over a caller-supplied registry (the injection seam:
/// tests pass scripted fakes that stop before any attach — no
/// concrete backend, so a session that reaches the sensor errors
/// typed instead of loading). Dispatches on `cfg.profile` exactly
/// like [`run_live_capture`]: a request-lifecycle config over an
/// injected registry refuses typed (the lifecycle session needs its
/// concrete backend handle, which injection cannot supply) — it must
/// never silently run the aggregate session instead.
pub fn run_live_capture_with_registry(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
    registry: &BackendRegistry,
) -> Result<LiveOutcome, LiveError> {
    match cfg.profile {
        LifecycleProfile::ApiReturns => run_live_session(cfg, runtime, registry, None),
        LifecycleProfile::RequestLifecycle => Err(LiveError::Unusable(
            "request-lifecycle capture needs a concrete backend; registry injection carries none"
                .to_owned(),
        )),
    }
}

/// Lifecycle orchestrator (T06 item 4 twin of [`run_live_session`]):
/// the same bring-up machine (`Created -> Qualified -> Discovering
/// -> Attaching`) over the lifecycle object + concrete backend, then
/// [`drive_lifecycle_session`] for the governed tail. Same parking
/// rule: a started session that fails parks in `FailedPartial`; a
/// refused session never started and stays `Created`.
fn run_lifecycle_session(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
    registry: &BackendRegistry,
    concrete: &LifecycleBackend,
) -> Result<LiveOutcome, LiveError> {
    let mut controller = SessionController::new();
    let outcome = run_lifecycle_session_inner(cfg, runtime, registry, concrete, &mut controller);
    if outcome.is_err() && controller.state() != SessionState::Created {
        let _ = controller.transition(SessionState::FailedPartial);
    }
    outcome
}

fn run_lifecycle_session_inner(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
    registry: &BackendRegistry,
    concrete: &LifecycleBackend,
    controller: &mut SessionController,
) -> Result<LiveOutcome, LiveError> {
    if cfg.source != LIVE_SOURCE {
        return Err(LiveError::Unusable(format!(
            "unsupported live source '{}': only '{}' is captured live",
            cfg.source, LIVE_SOURCE
        )));
    }
    let backend = registry
        .get(BackendId::KCrypto)
        .ok_or_else(|| LiveError::Unusable("kcrypto backend not registered".to_owned()))?;
    gate_check("session", &backend.capabilities().required, runtime)?;
    // Created -> Qualified: capabilities probed present.
    hop(controller, SessionState::Qualified, "session qualify")?;
    // Harness-style session state (fresh ids, open budgets; the
    // driver owns the zero integrity baseline).
    let session = SessionId::new(1);
    let generation = PlanGeneration::new(1);
    // Wide-open session budget is core's (1B-H1): the session gates
    // on privilege/BTF, not on budgets.
    let mut budget = BudgetManager::new(PlanBudget::open());
    let issuer = IdIssuer::default();
    // Qualified -> Discovering: targets and objects resolve now.
    hop(controller, SessionState::Discovering, "session discover")?;
    let instances = backend
        .detect(&DetectContext { session, runtime })
        .map_err(|err| backend_err("kcrypto detect", err))?;
    let Some(instance) = instances.into_iter().next() else {
        return Err(LiveError::Unusable(
            "kcrypto detect found no instances".to_owned(),
        ));
    };
    let plan = backend
        .plan(
            &PlanContext { session, runtime },
            &instance,
            CaptureMode::Trace,
        )
        .map_err(|err| backend_err("kcrypto plan", err))?;
    gate_check("plan", &plan.required, runtime)?;
    // Object bytes resolve once here (H1(b)/M2 twin): staged into the
    // backend below so `configure` loads the single sensor from them
    // instead of locating + reading a second time. The lifecycle
    // object (`kcrypto-lifecycle.bpf.o`), never the aggregate one —
    // the profile selects the object exactly as it selects the
    // decoder.
    let (object_path, object_bytes) = kryprobe_privilege::locate_lifecycle_object_bytes()
        .map_err(|err| LiveError::Unusable(format!("lifecycle object: {err}")))?;
    // 4B-M4: the object load is a privileged operation — in JSON mode
    // it leaves one structured stderr line (path + sha256). The hash
    // runs only when the line will print.
    if cfg.json_audit {
        let digest = kryprobe_privilege::sha256_hex(&object_bytes);
        emit_audit(
            true,
            &audit_object_line(&object_path.display().to_string(), &digest),
        );
    }
    // K5 bring-up authority (the aggregate pre-flight, unchanged): the
    // first usable token in discovery order, refused AFTER the object
    // resolves but BEFORE `configure` loads anything.
    let token = crate::token::usable_token(cfg.token.as_deref());
    if token.is_none() && !crate::runtime_facts::process_has_bpf_caps() {
        return Err(LiveError::Unusable(crate::token::no_mechanism_reason(
            cfg.token.as_deref(),
        )));
    }
    concrete.stage_session_inputs(object_bytes, token);
    // Discovering -> Attaching: the plan is validated and inputs are
    // staged; `configure` loads and attaches the single sensor.
    hop(controller, SessionState::Attaching, "session attach")?;
    backend
        .configure(
            &mut ConfigureContext {
                session,
                generation,
                budget: &mut budget,
            },
            &plan,
        )
        .map_err(|err| backend_err("kcrypto configure", err))?;
    // Single sensor, single owner (the H1(b) twin): the tick loop
    // drains the backend's own sensor in place (no handle
    // duplication — the sensor is `!Clone` by design), and `finalize`
    // assesses that same sensor. Attached points count the live links
    // (links exist only for attached points); expected points derive
    // from the lifecycle manifest (one program per required edge).
    let attached_points = concrete
        .attached_points()
        .map_err(|err| backend_err("lifecycle attach count", err))?;
    let expected_points = max_programs(&manifest(LifecycleProfile::RequestLifecycle));
    // 4B-M4: the attach outcome is the second audit line.
    emit_audit(
        cfg.json_audit,
        &audit_attach_line(attached_points, expected_points),
    );
    // Stop machinery: a session-local flag; the stdin watcher feeds it
    // for unbounded runs, and the SIGINT recorder (4B-M5) ends any run
    // with finalize + partial render + exit 3 instead of dying.
    kryprobe_privilege::host::install_sigint_flag()
        .map_err(|err| LiveError::Internal(format!("live SIGINT handler: {err}")))?;
    let stop = Arc::new(AtomicBool::new(false));
    if cfg.duration_secs.is_none() {
        let _watcher = spawn_stdin_watcher(std::io::stdin(), Arc::clone(&stop))?;
    }
    // No session drain spawn: the lifecycle drain lives inside the
    // backend (`drain_tick` per tick) — one owner, one drain, no
    // thread to stop after the closing tick.
    let mut production = RealLifecycleSensor::new(concrete);
    // 4B-M5 liveness line (stderr, human-only/unstable — never script on it).
    let progress = |tick: u64, rows: u64, drops: u64| {
        eprintln!("kryprobe: progress tick={tick} rows={rows} drops={drops}");
    };
    drive_lifecycle_session(
        cfg,
        backend,
        &mut production,
        &stop,
        attached_points,
        session,
        generation,
        &issuer,
        controller,
        Some(&progress),
    )
}

/// Shared orchestrator: frozen-trait lifecycle through `registry`
/// plus the concrete sensor handle (H1(b)). Production passes `Some`
/// (one sensor for ticks and finalize); the fake-registry test path
/// passes `None` and stops at `configure` before any sensor access.
///
/// 1B-H4: the orchestrator owns the ARCH §4.1 machine for bring-up
/// (`Created -> Qualified -> Discovering -> Attaching`) and hands it
/// to `drive_session` for the governed tail. A started session that
/// fails parks in `FailedPartial`; a refused session (bad source,
/// missing backend, failed gate) never started and stays `Created` —
/// refusal is not partial.
fn run_live_session(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
    registry: &BackendRegistry,
    concrete: Option<&KCryptoBackend>,
) -> Result<LiveOutcome, LiveError> {
    let mut controller = SessionController::new();
    let outcome = run_live_session_inner(cfg, runtime, registry, concrete, &mut controller);
    if outcome.is_err() && controller.state() != SessionState::Created {
        let _ = controller.transition(SessionState::FailedPartial);
    }
    outcome
}

fn run_live_session_inner(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
    registry: &BackendRegistry,
    concrete: Option<&KCryptoBackend>,
    controller: &mut SessionController,
) -> Result<LiveOutcome, LiveError> {
    if cfg.source != LIVE_SOURCE {
        return Err(LiveError::Unusable(format!(
            "unsupported live source '{}': only '{}' is captured live",
            cfg.source, LIVE_SOURCE
        )));
    }
    let backend = registry
        .get(BackendId::KCrypto)
        .ok_or_else(|| LiveError::Unusable("kcrypto backend not registered".to_owned()))?;
    gate_check("session", &backend.capabilities().required, runtime)?;
    // Created -> Qualified: capabilities probed present.
    hop(controller, SessionState::Qualified, "session qualify")?;
    // Harness-style session state (fresh ids, open budgets; the
    // driver owns the zero integrity baseline).
    let session = SessionId::new(1);
    let generation = PlanGeneration::new(1);
    // Wide-open session budget is core's (1B-H1): the session gates
    // on privilege/BTF, not on budgets.
    let mut budget = BudgetManager::new(PlanBudget::open());
    let issuer = IdIssuer::default();
    // Qualified -> Discovering: targets and objects resolve now.
    hop(controller, SessionState::Discovering, "session discover")?;
    let instances = backend
        .detect(&DetectContext { session, runtime })
        .map_err(|err| backend_err("kcrypto detect", err))?;
    let Some(instance) = instances.into_iter().next() else {
        return Err(LiveError::Unusable(
            "kcrypto detect found no instances".to_owned(),
        ));
    };
    let plan = backend
        .plan(
            &PlanContext { session, runtime },
            &instance,
            CaptureMode::Trace,
        )
        .map_err(|err| backend_err("kcrypto plan", err))?;
    gate_check("plan", &plan.required, runtime)?;
    // Object bytes resolve once here (H1(b)/M2): staged into the
    // backend below so `configure` loads the single sensor from them
    // instead of locating + reading a second time.
    let (object_path, object_bytes) = kryprobe_privilege::locate_kcrypto_object_bytes()
        .map_err(|err| LiveError::Unusable(format!("kcrypto object: {err}")))?;
    // 4B-M4: the object load is a privileged operation — in JSON mode
    // it leaves one structured stderr line (path + sha256). The hash
    // runs only when the line will print.
    if cfg.json_audit {
        let digest = kryprobe_privilege::sha256_hex(&object_bytes);
        emit_audit(
            true,
            &audit_object_line(&object_path.display().to_string(), &digest),
        );
    }
    // K5 bring-up authority: the first usable token in discovery order
    // (`--token` > `KRYPROBE_TOKEN` > default pin), staged into the
    // backend so the single sensor loads through it. No usable token
    // and no process caps is the honest exit-4 naming `token mint` —
    // refused AFTER the object resolves (a missing object is its own
    // exit-4 with its own name) but BEFORE `configure` loads anything
    // (a doomed unprivileged run must not start the load either).
    let token = crate::token::usable_token(cfg.token.as_deref());
    if token.is_none() && !crate::runtime_facts::process_has_bpf_caps() {
        return Err(LiveError::Unusable(crate::token::no_mechanism_reason(
            cfg.token.as_deref(),
        )));
    }
    if let Some(concrete) = concrete {
        concrete.stage_session_inputs(object_bytes, token);
    }
    // Discovering -> Attaching: the plan is validated and inputs are
    // staged; `configure` loads and attaches the single sensor.
    hop(controller, SessionState::Attaching, "session attach")?;
    backend
        .configure(
            &mut ConfigureContext {
                session,
                generation,
                budget: &mut budget,
            },
            &plan,
        )
        .map_err(|err| backend_err("kcrypto configure", err))?;
    // Single sensor (H1(b), was: session twin + backend twin): the
    // tick loop snapshots the backend's own sensor via a dup'd handle
    // (same kernel objects — one attach, one probe stream, one set of
    // maps), and `finalize` assesses that same sensor. Attached points
    // count the live links (links exist only for attached points).
    let Some(concrete) = concrete else {
        return Err(LiveError::Internal(
            "live session needs a concrete kcrypto backend".to_owned(),
        ));
    };
    let sensor = concrete
        .session_sensor()
        .map_err(|err| LiveError::Internal(format!("kcrypto session sensor: {err}")))?;
    let attached_points = sensor.links.len();
    // 4B-M4: the attach outcome is the second audit line.
    emit_audit(
        cfg.json_audit,
        &audit_attach_line(attached_points, KCRYPTO_SYMBOLS.len()),
    );
    // Stop machinery: a session-local flag; the stdin watcher feeds it
    // for unbounded runs, and the SIGINT recorder (4B-M5) ends any run
    // with finalize + partial render + exit 3 instead of dying.
    kryprobe_privilege::host::install_sigint_flag()
        .map_err(|err| LiveError::Internal(format!("live SIGINT handler: {err}")))?;
    let stop = Arc::new(AtomicBool::new(false));
    if cfg.duration_secs.is_none() {
        let _watcher = spawn_stdin_watcher(std::io::stdin(), Arc::clone(&stop))?;
    }
    // Session KRING drain (2B-C1): one spawn for all ticks — a per-tick
    // spawn/stop would pay thread + ~2MB mmap + epoll + up to 10ms
    // quantum on every tick. The drain lives in the production sensor;
    // the driver stops it once after the closing tick.
    let mut production = RealSensor::new(&sensor)?;
    // 4B-M5 liveness line (stderr, human-only/unstable — never script on it).
    let progress = |tick: u64, rows: u64, drops: u64| {
        eprintln!("kryprobe: progress tick={tick} rows={rows} drops={drops}");
    };
    drive_session(
        cfg,
        backend,
        &mut production,
        &stop,
        attached_points,
        session,
        generation,
        &issuer,
        Some(concrete),
        controller,
        Some(&progress),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_with(btf: bool) -> RuntimeCapabilities {
        RuntimeCapabilities {
            kernel_release: "test".to_owned(),
            uprobe_multi: true,
            cookies: true,
            ringbuf: true,
            btf_present: btf,
            userns: true,
            yama_scope: 0,
            caps: Vec::new(),
        }
    }

    // (The gate-vocabulary test moved to core with `missing_gates`
    // itself — 1B-H1/1B-L2; `gate_check` below still pins the CLI's
    // error attribution over the shared vocabulary.)

    #[test]
    fn audit_lines_pin_json_shapes() {
        // 4B-M4: one structured stderr line per privileged operation
        // in JSON mode — object load carries path + sha256, attach
        // carries the attached/expected counts.
        let object: serde_json::Value =
            serde_json::from_str(&audit_object_line("/prefix/kcrypto.bpf.o", "aa"))
                .expect("object line parses");
        assert_eq!(
            object,
            serde_json::json!({
                "audit": "object-load",
                "path": "/prefix/kcrypto.bpf.o",
                "sha256": "aa",
            })
        );
        let attach: serde_json::Value =
            serde_json::from_str(&audit_attach_line(9, 9)).expect("attach line parses");
        assert_eq!(
            attach,
            serde_json::json!({"audit": "attach", "attached": 9, "expected": 9})
        );
    }

    #[test]
    fn gate_check_error_names_gates() {
        let need_btf = CapabilityRequirements {
            btf: true,
            ..CapabilityRequirements::default()
        };
        let err = gate_check("session", &need_btf, &runtime_with(false)).expect_err("must fail");
        match err {
            LiveError::Unusable(reason) => assert!(reason.contains("btf"), "{reason}"),
            other => panic!("expected Unusable, got {other:?}"),
        }
        assert!(gate_check("session", &need_btf, &runtime_with(true)).is_ok());
        assert_eq!(LiveError::Unusable("x".to_owned()).exit_code(), 4);
        assert_eq!(LiveError::Internal("x".to_owned()).exit_code(), 1);
    }

    #[test]
    fn backend_error_map_is_environmental_vs_defect() {
        use kryprobe_core::error::{
            AmbiguityReason, BackendError, BudgetReason, DeniedReason, InputReason, InternalError,
            SafetyReason, UnstableReason, UnsupportedReason,
        };
        // World conditions stay `Unusable` (exit 4: retry/fix env),
        // naming stage + reason. Only a kryprobe defect is `Internal`
        // (exit 1). 1B-M2: budget exhaustion, target instability, and
        // corrupt input are environmental/usage — not defects — and
        // neither is a fired safety rule (`Unsafe`, a protection like
        // `Denied`) nor an unclear identity (`Ambiguous`, a data
        // condition).
        for err in [
            BackendError::Unsupported(UnsupportedReason::with_detail("r", "d")),
            BackendError::Denied(DeniedReason::with_detail("r", "d")),
            BackendError::Unstable(UnstableReason::with_detail("r", "d")),
            BackendError::Exhausted(BudgetReason::with_detail("r", "d")),
            BackendError::Unsafe(SafetyReason::with_detail("r", "d")),
            BackendError::Ambiguous(AmbiguityReason::with_detail("r", "d")),
            BackendError::CorruptInput(InputReason::with_detail("r", "d")),
        ] {
            match backend_err("kcrypto configure", err) {
                LiveError::Unusable(reason) => {
                    assert!(reason.contains("kcrypto configure"), "{reason}");
                }
                other => panic!("expected Unusable, got {other:?}"),
            }
        }
        assert!(
            matches!(
                backend_err(
                    "kcrypto plan",
                    BackendError::Internal(InternalError::with_detail("r", "d"))
                ),
                LiveError::Internal(_)
            ),
            "only Internal maps Internal"
        );
    }

    fn measurements() -> SessionMeasurements {
        SessionMeasurements {
            attached_points: 9,
            expected_points: 9,
            totals_present: true,
            ktot_gap: Some(0),
            ring_drops: 0,
            overflow_identities: 0,
            drops: [0; 8],
            observations_decoded: 12,
            interval: ValidityInterval {
                start_ns: 100,
                end_ns: Some(200),
            },
        }
    }

    #[test]
    fn coverage_healthy_session_leaves_delivery_unknown() {
        // T02 (S04): a reconciled twin with a clean ring proves
        // internal health, not kernel delivery or completion — those
        // three dimensions stay `Unknown` with reason counters, so no
        // exact-count or absence claim can go clean.
        let coverage = session_coverage(&measurements());
        assert_eq!(coverage.overall(), CoverageStatus::Unknown);
        assert_eq!(
            coverage.weaker_dimensions(),
            vec!["aggregate_counts", "detailed_events", "completion"]
        );
        assert_eq!(coverage.aggregate_counts.interval.start_ns, 100);
        assert_eq!(coverage.aggregate_counts.interval.end_ns, Some(200));
        for (dim, reason) in [
            (
                &coverage.aggregate_counts,
                "uncovered:kernel_delivery_unmeasured",
            ),
            (
                &coverage.detailed_events,
                "uncovered:kernel_delivery_unmeasured",
            ),
            (&coverage.completion, "uncovered:completion_unobserved"),
        ] {
            assert!(
                dim.counters
                    .iter()
                    .any(|c| c.name == reason && c.value == 1),
                "reason counter {reason} present: {:?}",
                dim.counters
            );
        }
        // Internal reconciliation magnitudes are kept, not dropped.
        assert!(
            coverage
                .aggregate_counts
                .counters
                .iter()
                .any(|c| c.name == "ktot_gap" && c.value == 0),
            "ktot_gap kept: {:?}",
            coverage.aggregate_counts.counters
        );
    }

    #[test]
    fn coverage_measured_loss_flips_its_dimension() {
        // Measured loss still flips its own dimension to `Partial`;
        // overall stays `Unknown` (delivery/completion outrank loss).
        let mut m = measurements();
        m.ktot_gap = Some(7);
        let coverage = session_coverage(&m);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.overall(), CoverageStatus::Unknown);
        assert_eq!(
            coverage.weaker_dimensions(),
            vec!["aggregate_counts", "detailed_events", "completion"]
        );

        let mut m = measurements();
        m.attached_points = 8;
        let coverage = session_coverage(&m);
        assert_eq!(coverage.attachment.status, CoverageStatus::Partial);
        assert_eq!(
            coverage.weaker_dimensions(),
            vec![
                "attachment",
                "aggregate_counts",
                "detailed_events",
                "completion"
            ]
        );

        let mut m = measurements();
        m.ring_drops = 2;
        m.overflow_identities = 1;
        let coverage = session_coverage(&m);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Partial);
        assert_eq!(
            coverage.weaker_dimensions(),
            vec!["aggregate_counts", "detailed_events", "completion"]
        );
    }

    #[test]
    fn coverage_unmeasured_gap_stays_uncovered_not_zero() {
        // Totals absent: no baseline, so no gap claim — `Unknown` with a
        // reason counter, never `Complete`, never a zero gap.
        let mut m = measurements();
        m.totals_present = false;
        m.ktot_gap = None;
        let coverage = session_coverage(&m);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        assert!(
            coverage
                .aggregate_counts
                .counters
                .iter()
                .any(|c| c.name == "uncovered:ktot_baseline_missing" && c.value == 1),
            "reason counter present: {:?}",
            coverage.aggregate_counts.counters
        );
        assert!(
            !coverage
                .aggregate_counts
                .counters
                .iter()
                .any(|c| c.name == "ktot_gap"),
            "no gap claim without a baseline: {:?}",
            coverage.aggregate_counts.counters
        );
        assert_eq!(coverage.overall(), CoverageStatus::Unknown);
        // Surprise shape (totals present, gap missing) fails closed too.
        let mut m = measurements();
        m.ktot_gap = None;
        assert_eq!(
            session_coverage(&m).aggregate_counts.status,
            CoverageStatus::Unknown
        );
    }

    fn lifecycle_ledger_clean() -> LifecycleLedger {
        use kryprobe_core::kcrypto::ReducerStats;
        use kryprobe_privilege::kcrypto_lifecycle::decode::DecodeStats;
        LifecycleLedger {
            completed: Vec::new(),
            edge_hits: [4, 4, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            decode: DecodeStats {
                admitted: 6,
                ..DecodeStats::default()
            },
            reducer: ReducerStats {
                admitted: 6,
                emitted: 6,
                ..ReducerStats::default()
            },
            kernel_loss: [0; 5],
            agg_accepted: [4, 4, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            retained_dropped: 0,
            view_valid: true,
            loss_baseline: [0; 5],
            agg_baseline: [0; 16],
            prog_misses: Vec::new(),
            miss_current: Vec::new(),
            tfm_stats: kryprobe_privilege::kcrypto_lifecycle::tfm::TfmStats::default(),
            generations: Vec::new(),
        }
    }

    fn close_clean() -> LifecycleCloseStats {
        LifecycleCloseStats {
            unknown_terminals: 0,
            omitted: 0,
            backlog_bytes: 0,
        }
    }

    #[test]
    fn lifecycle_coverage_clean_session_completes_completion() {
        // The structural twin difference: the lifecycle sensor pairs
        // submit with terminal truth per request, so a session whose
        // every emitted record grounded completes `completion` — while
        // delivery-sensitive dimensions stay `Unknown` (S04 twin).
        let coverage = lifecycle_coverage(
            &lifecycle_ledger_clean(),
            2,
            2,
            6,
            &close_clean(),
            ValidityInterval {
                start_ns: 100,
                end_ns: Some(200),
            },
        );
        assert_eq!(
            coverage.attachment.status,
            CoverageStatus::CompleteForDeclaredBoundary
        );
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Unknown);
        assert_eq!(
            coverage.completion.status,
            CoverageStatus::CompleteForDeclaredBoundary
        );
        // Lifecycle rows carry no context class: attribution can never
        // complete (the aggregate rationale does not transfer).
        assert_eq!(coverage.attribution.status, CoverageStatus::Unknown);
        // Zero correlation events across one backend: complete.
        assert_eq!(
            coverage.correlation.status,
            CoverageStatus::CompleteForDeclaredBoundary
        );
        assert_eq!(coverage.overall(), CoverageStatus::Unknown);
        assert_eq!(
            coverage.weaker_dimensions(),
            vec!["aggregate_counts", "detailed_events", "attribution"]
        );
        for dim in [&coverage.aggregate_counts, &coverage.detailed_events] {
            assert!(
                dim.counters
                    .iter()
                    .any(|c| c.name == "uncovered:kernel_delivery_unmeasured" && c.value == 1),
                "reason counter present: {:?}",
                dim.counters
            );
        }
        // Per-hook edge hits ride as counters (the VM gate's post-GO
        // evidence), plus grounded-terminal magnitudes.
        assert!(
            coverage
                .aggregate_counts
                .counters
                .iter()
                .any(|c| c.name == "edge_hits_hook0" && c.value == 4),
            "edge hits kept: {:?}",
            coverage.aggregate_counts.counters
        );
        assert!(
            coverage
                .completion
                .counters
                .iter()
                .any(|c| c.name == "terminals_grounded" && c.value == 6),
            "grounded terminals kept: {:?}",
            coverage.completion.counters
        );
    }

    #[test]
    fn lifecycle_coverage_measured_loss_flips_its_dimension() {
        let interval = ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        };
        // Kernel reserve failure: counts AND transport flip — and
        // completion holds provisional (M2: any miss voids the exact
        // counts the completion claim rests on).
        let mut ledger = lifecycle_ledger_clean();
        ledger.kernel_loss[0] = 2;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Partial);
        assert_eq!(
            coverage.completion.status,
            CoverageStatus::Partial,
            "misses void exact completion claims"
        );
        // Refused decode evidence corrupts counts only.
        let mut ledger = lifecycle_ledger_clean();
        ledger.decode.submit_refused = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Unknown);
        // A per-program recursion-miss delta corrupts counts AND voids
        // completion (H2: wholly skipped runs leave no edge and no
        // LLOSS — the miss counter is the only witness).
        let mut ledger = lifecycle_ledger_clean();
        ledger.prog_misses = vec![kryprobe_privilege::kcrypto_lifecycle::view::ProgMissDelta {
            section: "fsession/a".to_owned(),
            baseline: 0,
            current: 1,
        }];
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(
            coverage.completion.status,
            CoverageStatus::Partial,
            "miss deltas void exact completion claims"
        );
        // Truthless-drained records flip completion only.
        let mut ledger = lifecycle_ledger_clean();
        ledger.reducer.unfinished = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.completion.status, CoverageStatus::Partial);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        // Attach shortfall flips attachment only.
        let coverage =
            lifecycle_coverage(&lifecycle_ledger_clean(), 1, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.attachment.status, CoverageStatus::Partial);
        // Duplicates repeat known state: no information lost, no flip.
        let mut ledger = lifecycle_ledger_clean();
        ledger.reducer.duplicate = 9;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        assert_eq!(
            coverage.completion.status,
            CoverageStatus::CompleteForDeclaredBoundary
        );
        // Ambiguous-Unknown terminals (emitted, never unfinished) flip
        // completion: grounded means observed terminal truth.
        let close = LifecycleCloseStats {
            unknown_terminals: 1,
            ..close_clean()
        };
        let coverage = lifecycle_coverage(&lifecycle_ledger_clean(), 2, 2, 6, &close, interval);
        assert_eq!(coverage.completion.status, CoverageStatus::Partial);
        // Truncation flips completion only.
        let close = LifecycleCloseStats {
            omitted: 7,
            ..close_clean()
        };
        let coverage = lifecycle_coverage(&lifecycle_ledger_clean(), 2, 2, 6, &close, interval);
        assert_eq!(coverage.completion.status, CoverageStatus::Partial);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Unknown);
        // Close-time ring backlog flips transport only.
        let close = LifecycleCloseStats {
            backlog_bytes: 128,
            ..close_clean()
        };
        let coverage = lifecycle_coverage(&lifecycle_ledger_clean(), 2, 2, 6, &close, interval);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Partial);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        // Correlation gaps (resubmit transport loss) flip correlation
        // — and completion holds provisional (M2: count loss voids
        // exact completion claims).
        let mut ledger = lifecycle_ledger_clean();
        ledger.decode.gaps_synthesized = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        assert_eq!(
            coverage.completion.status,
            CoverageStatus::Partial,
            "misses void exact completion claims"
        );
        // Unexplained aggregate residual (accepted minus consumed,
        // reserve, and noslot, with an empty close ring) flips
        // transport: the accounting equation broke.
        let mut ledger = lifecycle_ledger_clean();
        ledger.agg_accepted = [5, 4, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Partial);
    }

    #[test]
    fn w8_completion_holds_provisional_without_identity() {
        // M2 provisional-hold: a void sensor identity voids the
        // completion claim (unattributed evidence never grounds a
        // Complete), attested by the `identity_verified` counter; a
        // verified session commits.
        let interval = ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        };
        let mut ledger = lifecycle_ledger_clean();
        ledger.view_valid = false;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.completion.status, CoverageStatus::Partial);
        assert!(
            coverage
                .completion
                .counters
                .iter()
                .any(|c| c.name == "identity_verified" && c.value == 0),
            "void verdict attested: {:?}",
            coverage.completion.counters
        );
        let coverage =
            lifecycle_coverage(&lifecycle_ledger_clean(), 2, 2, 6, &close_clean(), interval);
        assert_eq!(
            coverage.completion.status,
            CoverageStatus::CompleteForDeclaredBoundary
        );
        assert!(
            coverage
                .completion
                .counters
                .iter()
                .any(|c| c.name == "identity_verified" && c.value == 1),
            "verified verdict attested: {:?}",
            coverage.completion.counters
        );
    }

    #[test]
    fn lifecycle_coverage_unjoined_returns_flip_correlation() {
        // Round-3 minor: a lone tainted return (`unknown_invoc_returns`)
        // or refused submit (`submit_refused`) is a failed join, so
        // correlation must read `Partial` — never Complete.
        let interval = ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        };
        let mut ledger = lifecycle_ledger_clean();
        ledger.decode.unknown_invoc_returns = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        assert!(
            coverage
                .correlation
                .counters
                .iter()
                .any(|c| c.name == "correlation_events" && c.value == 1),
            "unjoined return counted: {:?}",
            coverage.correlation.counters
        );
        let mut ledger = lifecycle_ledger_clean();
        ledger.decode.submit_refused = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
    }

    #[test]
    fn upsert_latest_overwrites_in_place_at_first_seen_position() {
        // H2: repeats overwrite (latest counters win) without moving
        // the first-seen slot; new keys append in tick order.
        let issuer = IdIssuer::default();
        let table = SymTable::parse("");
        let who = WhoSnapshot {
            key: Default::default(),
            val: Default::default(),
            stack_ips: Vec::new(),
            first_errno: None,
            params: None,
        };
        let obs = || observation_for_who(&who, issuer.issue().expect("id"), &table);
        let (a1, b1, a2) = (obs(), obs(), obs());
        let mut index = HashMap::new();
        let mut out = Vec::new();
        upsert_latest(&mut index, &mut out, ObsKey::Agg(7), a1);
        upsert_latest(&mut index, &mut out, ObsKey::Totals, b1.clone());
        upsert_latest(&mut index, &mut out, ObsKey::Agg(7), a2.clone());
        assert_eq!(out.len(), 2, "repeat reuses its slot");
        assert_eq!(out[0], a2, "latest wins at the first-seen position");
        assert_eq!(out[1], b1, "unrelated key untouched");
    }

    #[test]
    fn gap_recompute_conserves_and_detects_pressure() {
        // Gap math over the tick loop's parsed call counts (H3: the
        // closing snapshot's rows are never re-parsed for the gap).
        assert_eq!(ktot_gap_from_calls(&[10, 20], Some(30)), Some(0));
        assert_eq!(ktot_gap_from_calls(&[10, 20], Some(40)), Some(10));
        assert_eq!(ktot_gap_from_calls(&[10], None), None);
        // Saturation, never wrap.
        assert_eq!(ktot_gap_from_calls(&[u64::MAX, 1], Some(5)), Some(0));
        assert_eq!(ktot_gap_from_calls(&[], Some(7)), Some(7));
    }

    #[test]
    fn coverage_predrop_counters_ride_aggregate_counts() {
        // Fix wave (G-C1): all 8 KDROPS sites surface as counters on
        // aggregate_counts (always present — a missing counter would be
        // silent), in KDROP_SITES order.
        let mut m = measurements();
        m.drops = [1, 0, 0, 7, 0, 3, 0, 0];
        let counters = session_coverage(&m).aggregate_counts.counters;
        let site_counters: Vec<(&str, u64)> = counters
            .iter()
            .filter(|c| c.name.starts_with("predrop_"))
            .map(|c| (c.name.as_str(), c.value))
            .collect();
        assert_eq!(
            site_counters,
            vec![
                ("predrop_cfg_fail", 1),
                ("predrop_fret_fail", 0),
                ("predrop_arg_null", 0),
                ("predrop_chase_fail", 7),
                ("predrop_name_fail", 0),
                ("predrop_destroy_skip", 3),
                ("predrop_spare_6", 0),
                ("predrop_spare_7", 0),
            ]
        );
    }

    #[test]
    fn coverage_unexpected_predrop_flips_aggregate_counts() {
        // Any unexpected pre-KTOT site (0–4) is measured loss → Partial.
        let mut m = measurements();
        m.drops[3] = 7;
        let coverage = session_coverage(&m);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(
            coverage.weaker_dimensions(),
            vec!["aggregate_counts", "detailed_events", "completion"]
        );
        // Destroy-only skips never flip to Partial (C7-expected,
        // separately keyed) — but the dimension still cannot go
        // `Complete`: delivery is unmeasured (S04).
        let mut m = measurements();
        m.drops[KDROP_DESTROY] = 50;
        let coverage = session_coverage(&m);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        assert_eq!(
            coverage.weaker_dimensions(),
            vec!["aggregate_counts", "detailed_events", "completion"]
        );
    }

    #[test]
    fn stdin_watcher_stops_on_eof_only() {
        use std::io::Cursor;
        let eof_stop = Arc::new(AtomicBool::new(false));
        let handle =
            spawn_stdin_watcher(Cursor::new(Vec::new()), Arc::clone(&eof_stop)).expect("spawns");
        handle.join().expect("watcher joins");
        assert!(eof_stop.load(Ordering::Relaxed), "EOF stops");
        // Input bytes do not stop; EOF after input does.
        let input_stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_stdin_watcher(Cursor::new(b"hello".to_vec()), Arc::clone(&input_stop))
            .expect("spawns");
        handle.join().expect("watcher joins");
        assert!(input_stop.load(Ordering::Relaxed), "EOF-after-input stops");
    }
}
