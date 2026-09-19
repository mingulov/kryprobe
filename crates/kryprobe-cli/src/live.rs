// SPDX-License-Identifier: GPL-3.0-or-later
//! Live kcrypto capture session (K3 Task 1): the frozen-trait lifecycle
//! driven per-tick against a session-owned sensor.
//!
//! Flow (D1): registry + [`register_kcrypto`] → gate check → `detect` →
//! `plan` (Trace) → `configure` once → tick loop (`snapshot_rows` → raw
//! events in row order → `decode` each with a session [`IdIssuer`]) →
//! `finalize` ONCE → [`DriverReport::feed_shared_losses`] ONCE from
//! measured drop counters only.
//!
//! Twin sensors (M1 resolution): per-tick snapshots run against a
//! session-owned sensor loaded here via [`load_kcrypto_configured`], while
//! the backend's `configure` owns its own sensor for the end-of-session
//! `finalize` assessment. The backend's sensor handle is private and this
//! task's file budget forbids new privilege accessors; the K2
//! `driver_e2e` already proves twin attach works. M1 dissolves
//! structurally: ticks drain the session ring, and the once-only finalize
//! drain drops only duplicates of decoded idents. The session sensor loads
//! before `configure` (lane-observed: the second-attached twin records
//! nothing, so the decoded sensor must attach first).
//!
//! Snapshots are non-consuming reads (only the KRING drain consumes), so
//! agg/totals observations repeat per tick with cumulative counters —
//! consumers render the latest per row key — while idents are disjoint
//! across ticks. Nothing is deduped: `summary.observations` always equals
//! `observations.len()` (`finalize == decoded`).
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
//! lock serializes). Stopping is std-only: bounded runs stop at the
//! deadline, unbounded runs stop on closed stdin; SIGINT keeps the
//! default disposition and terminates (documented approach, no handler).

use kryprobe_abi::kcrypto_agg::KIDN_DROPS;
use kryprobe_core::backend::{
    BackendRegistry, BackendSummary, ConfigureContext, DecodeContext, DetectContext, DriverReport,
    FinalizeContext, PlanContext,
};
use kryprobe_core::budget::BudgetManager;
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{BackendId, CaptureMode, CoverageStatus};
use kryprobe_core::error::BackendError;
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCounter, DimensionCoverage, IntegritySummary, NativeObservation,
    ValidityInterval,
};
use kryprobe_core::ids::{IdIssuer, PlanGeneration, SessionId};
use kryprobe_core::plan::{CapabilityRequirements, PlanBudget};
use kryprobe_privilege::btf_resolve::{
    AttachOutcome, ConfiguredError, ConfiguredKcrypto, KCRYPTO_SYMBOLS, load_kcrypto_configured,
};
use kryprobe_privilege::kcrypto_backend::register_kcrypto;
use kryprobe_privilege::kcrypto_snapshot::{
    ParsedRow, SnapshotRows, parse_snapshot_row, raw_event_for_agg, raw_event_for_ident,
    raw_event_for_totals, shared_losses_from_snapshot, snapshot_rows,
};
use kryprobe_privilege::mapops::{MapOpsError, map_lookup_bytes};
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

/// Live capture configuration (brief-exact shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveConfig {
    /// Capture source; only [`LIVE_SOURCE`] is supported.
    pub source: String,
    /// Window length; `None` runs until SIGINT or closed stdin. Stopping
    /// is std-only (the brief's documented approach): no SIGINT handler
    /// is installed, so SIGINT terminates via the default disposition
    /// (sensors drop via RAII); closed stdin stops gracefully through a
    /// watcher thread sharing the session stop flag.
    pub duration_secs: Option<u64>,
    /// Tick cadence in milliseconds.
    pub tick_ms: u64,
}

impl Default for LiveConfig {
    /// `kernel-crypto`, unbounded, 1000ms ticks.
    fn default() -> Self {
        Self {
            source: LIVE_SOURCE.to_owned(),
            duration_secs: None,
            tick_ms: DEFAULT_TICK_MS,
        }
    }
}

/// Live capture outcome (brief-exact shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOutcome {
    /// Decoded observations, tick after tick in row order (agg rows, then
    /// totals, then idents per tick; ids sequence from 1).
    pub observations: Vec<NativeObservation>,
    /// The backend's once-only end-of-session facts.
    pub summary: BackendSummary,
    /// Session coverage assembled from measurements only.
    pub coverage: CoverageSummary,
    /// Reconciled session integrity (rollup + the once-only shared feed).
    pub integrity: IntegritySummary,
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

/// Required capabilities the runtime does not satisfy, in
/// [`CapabilityRequirements`] field order.
fn missing_gates(
    required: &CapabilityRequirements,
    runtime: &RuntimeCapabilities,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if required.uprobe_multi && !runtime.uprobe_multi {
        missing.push("uprobe_multi");
    }
    if required.cookies && !runtime.cookies {
        missing.push("cookies");
    }
    if required.ringbuf && !runtime.ringbuf {
        missing.push("ringbuf");
    }
    if required.btf && !runtime.btf_present {
        missing.push("btf");
    }
    missing
}

/// Gate check: every required capability must have probed present, else
/// `Unusable` naming each missing gate.
fn gate_check(
    stage: &str,
    required: &CapabilityRequirements,
    runtime: &RuntimeCapabilities,
) -> Result<(), LiveError> {
    let missing = missing_gates(required, runtime);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LiveError::Unusable(format!(
            "{stage} capability gate unsatisfied for kcrypto: missing {}",
            missing.join(", ")
        )))
    }
}

/// Backend errors to live errors: environmental (`Unsupported`/`Denied`)
/// stay `Unusable`; everything else is a defect marker (`Internal`).
fn backend_err(stage: &str, err: BackendError) -> LiveError {
    match err {
        BackendError::Unsupported(_) | BackendError::Denied(_) => {
            LiveError::Unusable(format!("{stage}: {err}"))
        }
        _ => LiveError::Internal(format!("{stage}: {err}")),
    }
}

/// Twin bring-up errors to live errors (the D5 map in live terms: only a
/// post-load map-write failure is `Internal`; resolution/load/attach
/// failures are environmental).
fn configured_err(err: ConfiguredError) -> LiveError {
    match err {
        ConfiguredError::Configure(_) => {
            LiveError::Internal(format!("live session sensor configure: {err}"))
        }
        _ => LiveError::Unusable(format!("live session sensor: {err}")),
    }
}

/// Wide-open session budget (the `BackendDriver::harness` ceilings: the
/// live session gates on privilege/BTF, not on budgets).
fn open_budget() -> PlanBudget {
    PlanBudget {
        max_targets: u64::MAX,
        max_objects: u64::MAX,
        max_bytes: u64::MAX,
        max_links: u64::MAX,
        max_state_entries: u64::MAX,
        max_queue: u64::MAX,
        max_duration_ns: u64::MAX,
    }
}

/// All-`NotRun` coverage for the finalize context (the K2 backend ignores
/// its context — it assesses its own sensor; session coverage is
/// assembled here afterwards).
fn notrun_coverage() -> CoverageSummary {
    let dimension = || {
        DimensionCoverage::new(
            CoverageStatus::NotRun,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        )
    };
    CoverageSummary {
        target_population: dimension(),
        object_discovery: dimension(),
        attachment: dimension(),
        aggregate_counts: dimension(),
        detailed_events: dimension(),
        attribution: dimension(),
        correlation: dimension(),
        completion: dimension(),
    }
}

/// Session sensor `KIDN[KIDN_DROPS]` read (the K2 `finalize_drops` idiom:
/// absent key reads healthy-zero; any other map failure is loud).
fn session_drops(sensor: &ConfiguredKcrypto) -> Result<u8, LiveError> {
    match map_lookup_bytes(
        &sensor.loaded.maps.ident,
        &KIDN_DROPS.to_le_bytes(),
        1,
        "live/kidn-drops",
    ) {
        Ok(value) => Ok(value.first().copied().unwrap_or(0)),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => Ok(0),
        Err(err) => Err(LiveError::Internal(format!("live kidn-drops read: {err}"))),
    }
}

/// Twin KTOT gap from the closing snapshot: `KTOT − ΣKAGG` calls
/// (saturating). `None` when totals are absent (no baseline — the caller
/// leaves the dimension uncovered, never claims zero). A reparse failure
/// or a surprise row kind is `Internal` (rows came from our own snapshot;
/// failing to re-read them is a defect — the K2 `integrity_for_snapshot`
/// arms).
fn ktot_gap(snap: &SnapshotRows) -> Result<Option<u64>, LiveError> {
    let reparse =
        |err: BackendError| LiveError::Internal(format!("live gap recompute: row reparse: {err}"));
    let Some(totals) = &snap.totals else {
        return Ok(None);
    };
    let mut agg_calls = 0u64;
    for row in &snap.rows {
        match parse_snapshot_row(&row.0).map_err(reparse)? {
            ParsedRow::Agg { vagg, .. } => {
                agg_calls = agg_calls.saturating_add(vagg.calls);
            }
            _ => {
                return Err(LiveError::Internal(
                    "live gap recompute: unexpected row kind".to_owned(),
                ));
            }
        }
    }
    match parse_snapshot_row(&totals.0).map_err(reparse)? {
        ParsedRow::Totals { vagg } => Ok(Some(vagg.calls.saturating_sub(agg_calls))),
        _ => Err(LiveError::Internal(
            "live gap recompute: unexpected totals kind".to_owned(),
        )),
    }
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
    // Aggregate counts: the twin gap (absent totals → uncovered, not zero).
    let mut aggregate_counts = match (m.totals_present, m.ktot_gap) {
        (true, Some(0)) => dim(CoverageStatus::CompleteForDeclaredBoundary),
        (true, Some(_)) => dim(CoverageStatus::Partial),
        _ => dim(CoverageStatus::Unknown),
    };
    match (m.totals_present, m.ktot_gap) {
        (true, Some(gap)) => aggregate_counts.counters.push(counter("ktot_gap", gap)),
        _ => aggregate_counts
            .counters
            .push(counter("uncovered:ktot_baseline_missing", 1)),
    }
    // Detailed events: measured ring drops + accumulated overflow.
    let mut detailed_events = dim(if m.ring_drops == 0 && m.overflow_identities == 0 {
        CoverageStatus::CompleteForDeclaredBoundary
    } else {
        CoverageStatus::Partial
    });
    detailed_events
        .counters
        .push(counter("ring_drops", m.ring_drops));
    detailed_events
        .counters
        .push(counter("overflow_identities", m.overflow_identities));
    // Completion: finalize ran (reaching here means it did).
    let mut completion = dim(CoverageStatus::CompleteForDeclaredBoundary);
    completion
        .counters
        .push(counter("observations_decoded", m.observations_decoded));
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

/// Spawn the closed-stdin watcher: EOF (or a stdin error, read as closed)
/// sets the stop flag. Input bytes are not a stop signal. Generic over
/// the reader so tests feed a cursor; production passes `stdin()`. The
/// handle is detached (never joined — a blocked stdin read has no
/// timeout; process exit reaps it).
fn spawn_stdin_watcher<R: std::io::Read + Send + 'static>(
    reader: R,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
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
        .expect("live stdin watcher spawns")
}

/// Sleep one tick in stop-poll slices (early-out on the stop flag).
fn sleep_tick(tick_ms: u64, stop: &AtomicBool) {
    let mut remaining = tick_ms;
    while remaining > 0 && !stop.load(Ordering::Relaxed) {
        let slice = remaining.min(STOP_POLL_MS);
        std::thread::sleep(Duration::from_millis(slice));
        remaining = remaining.saturating_sub(slice);
    }
}

/// Live kcrypto capture: registry + `register_kcrypto`, then the
/// injectable session below. See the module docs for the flow.
pub fn run_live_capture(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
) -> Result<LiveOutcome, LiveError> {
    let mut registry = BackendRegistry::new();
    register_kcrypto(&mut registry)
        .map_err(|err| LiveError::Internal(format!("kcrypto registration: {err}")))?;
    run_live_capture_with_registry(cfg, runtime, &registry)
}

/// Live capture over a caller-supplied registry (the injection seam:
/// production passes a registry with the real kcrypto backend; tests
/// pass scripted fakes that stop before any attach).
pub fn run_live_capture_with_registry(
    cfg: &LiveConfig,
    runtime: &RuntimeCapabilities,
    registry: &BackendRegistry,
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
    // Harness-style session state (fresh ids, open budgets, zero baseline).
    let session = SessionId::new(1);
    let generation = PlanGeneration::new(1);
    let mut budget = BudgetManager::new(open_budget());
    let baseline = IntegritySummary::default();
    let issuer = IdIssuer::default();
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
    // Session-owned sensor for per-tick snapshots (twin of the backend's),
    // loaded BEFORE `configure`: lane-observed, the second-attached of two
    // twin sensors records nothing (links exist, maps stay empty — the K2
    // e2e loads its snapshot twin first for the same reason), so the
    // session sensor — the one whose rows decode — must attach first.
    let object_path = kryprobe_privilege::locate_kcrypto_object()
        .map_err(|err| LiveError::Unusable(format!("kcrypto object: {err}")))?;
    let object_bytes = std::fs::read(&object_path).map_err(|err| {
        LiveError::Unusable(format!("kcrypto object {}: {err}", object_path.display()))
    })?;
    let (sensor, points) = load_kcrypto_configured(&object_bytes, None).map_err(configured_err)?;
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
    let attached_points = points
        .iter()
        .filter(|point| point.attach == Some(AttachOutcome::Attached))
        .count();
    // Stop machinery: a session-local flag; the stdin watcher feeds it
    // for unbounded runs (SIGINT keeps the default disposition — see the
    // `duration_secs` docs).
    let stop = Arc::new(AtomicBool::new(false));
    if cfg.duration_secs.is_none() {
        let _watcher = spawn_stdin_watcher(std::io::stdin(), Arc::clone(&stop));
    }
    // Tick loop: snapshot → raw events in row order → decode each (first
    // error aborts `Internal`). Always at least the opening tick, even
    // for a zero-second window; the tick at/after the deadline is the
    // closing snapshot. NEVER finalize per tick (D1/M1).
    // Sub-ms ticks are meaningless against snapshot cost; floor at 1ms.
    let tick_ms = cfg.tick_ms.max(1);
    let start_wall = Instant::now();
    let deadline = cfg
        .duration_secs
        .map(|secs| start_wall + Duration::from_secs(secs));
    let mut observations = Vec::new();
    let mut overflow_identities = 0u64;
    let mut first_wall = 0u64;
    let mut first_tick = true;
    let closing: SnapshotRows = loop {
        let snap = snapshot_rows(&sensor)
            .map_err(|err| LiveError::Internal(format!("live snapshot: {err}")))?;
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
            id_issuer: &issuer,
        };
        for row in &snap.rows {
            let observation = backend
                .decode(&decode_ctx, raw_event_for_agg(row))
                .map_err(|err| LiveError::Internal(format!("live decode agg: {err}")))?;
            observations.push(observation);
        }
        if let Some(totals) = &snap.totals {
            let observation = backend
                .decode(&decode_ctx, raw_event_for_totals(totals))
                .map_err(|err| LiveError::Internal(format!("live decode totals: {err}")))?;
            observations.push(observation);
        }
        for ident in &snap.idents {
            let observation = backend
                .decode(&decode_ctx, raw_event_for_ident(ident))
                .map_err(|err| LiveError::Internal(format!("live decode ident: {err}")))?;
            observations.push(observation);
        }
        overflow_identities = overflow_identities.saturating_add(snap.overflow_identities);
        let stopped =
            stop.load(Ordering::Relaxed) || deadline.is_some_and(|end| Instant::now() >= end);
        if stopped {
            break snap;
        }
        sleep_tick(tick_ms, &stop);
    };
    // Finalize ONCE, then the shared feed ONCE.
    let notrun = notrun_coverage();
    let summary = backend
        .finalize(&FinalizeContext {
            session,
            coverage: &notrun,
            integrity: &baseline,
        })
        .map_err(|err| LiveError::Internal(format!("live finalize: {err}")))?;
    let drops = session_drops(&sensor)?;
    let mut report = DriverReport::default();
    report.observations = observations;
    report.summaries.push(summary);
    report
        .feed_shared_losses(shared_losses_from_snapshot(&closing, drops))
        .map_err(|err| LiveError::Internal(format!("live shared feed: {err}")))?;
    let integrity = report
        .session_integrity_checked()
        .map_err(|err| LiveError::Internal(format!("live session integrity: {err}")))?;
    let gap = ktot_gap(&closing)?;
    let coverage = session_coverage(&SessionMeasurements {
        attached_points,
        expected_points: KCRYPTO_SYMBOLS.len(),
        totals_present: closing.totals.is_some(),
        ktot_gap: gap,
        ring_drops: u64::from(drops),
        overflow_identities,
        observations_decoded: report.observations.len() as u64,
        interval: ValidityInterval {
            start_ns: first_wall,
            end_ns: Some(closing.monotonic_ns),
        },
    });
    let summary = report
        .summaries
        .pop()
        .ok_or_else(|| LiveError::Internal("live session filed no summary".to_owned()))?;
    Ok(LiveOutcome {
        observations: report.observations,
        summary,
        coverage,
        integrity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_privilege::kcrypto_snapshot::{RowBytes, TotalsBytes};

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

    #[test]
    fn missing_gates_names_each_gap_in_field_order() {
        let all = CapabilityRequirements {
            uprobe_multi: true,
            cookies: true,
            ringbuf: true,
            btf: true,
        };
        let none = RuntimeCapabilities {
            kernel_release: "test".to_owned(),
            uprobe_multi: false,
            cookies: false,
            ringbuf: false,
            btf_present: false,
            userns: false,
            yama_scope: 0,
            caps: Vec::new(),
        };
        assert_eq!(
            missing_gates(&all, &none),
            vec!["uprobe_multi", "cookies", "ringbuf", "btf"]
        );
        assert!(missing_gates(&all, &runtime_with(true)).is_empty());
        let need_btf = CapabilityRequirements {
            btf: true,
            ..CapabilityRequirements::default()
        };
        assert_eq!(missing_gates(&need_btf, &runtime_with(false)), vec!["btf"]);
        assert!(missing_gates(&need_btf, &runtime_with(true)).is_empty());
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
        // Environmental stages stay `Unusable`, naming stage + reason.
        for err in [
            BackendError::Unsupported(UnsupportedReason::with_detail("r", "d")),
            BackendError::Denied(DeniedReason::with_detail("r", "d")),
        ] {
            match backend_err("kcrypto configure", err) {
                LiveError::Unusable(reason) => {
                    assert!(reason.contains("kcrypto configure"), "{reason}");
                }
                other => panic!("expected Unusable, got {other:?}"),
            }
        }
        // Every other variant is a defect marker (`Internal`).
        for err in [
            BackendError::Unstable(UnstableReason::with_detail("r", "d")),
            BackendError::Exhausted(BudgetReason::with_detail("r", "d")),
            BackendError::Unsafe(SafetyReason::with_detail("r", "d")),
            BackendError::Ambiguous(AmbiguityReason::with_detail("r", "d")),
            BackendError::CorruptInput(InputReason::with_detail("r", "d")),
            BackendError::Internal(InternalError::with_detail("r", "d")),
        ] {
            assert!(
                matches!(backend_err("kcrypto plan", err), LiveError::Internal(_)),
                "defect variants map Internal"
            );
        }
    }

    #[test]
    fn twin_bringup_map_marks_only_post_load_failure_internal() {
        use kryprobe_privilege::bpfloader::LoaderError;
        use kryprobe_privilege::btf_resolve::BtfError;
        use kryprobe_privilege::mapops::MapOpsError;
        // Resolution/load/attach failures are environmental (`Unusable`).
        for err in [
            ConfiguredError::Resolve(BtfError::MissingFunc {
                name: "f".to_owned(),
            }),
            ConfiguredError::Load(LoaderError::BadObject {
                reason: "x".to_owned(),
            }),
            ConfiguredError::AttachSetup {
                detail: "x".to_owned(),
            },
            ConfiguredError::NoPointAttached { points: vec![] },
        ] {
            assert!(
                matches!(configured_err(err), LiveError::Unusable(_)),
                "bring-up failures map Unusable"
            );
        }
        // Post-load map-write failure is the defect marker (`Internal`).
        let err = ConfiguredError::Configure(MapOpsError::UpdateFailed {
            stage: "kcfg".to_owned(),
            errno: 5,
        });
        assert!(
            matches!(configured_err(err), LiveError::Internal(_)),
            "post-load failure maps Internal"
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
            observations_decoded: 12,
            interval: ValidityInterval {
                start_ns: 100,
                end_ns: Some(200),
            },
        }
    }

    #[test]
    fn coverage_healthy_session_is_complete() {
        let coverage = session_coverage(&measurements());
        assert_eq!(
            coverage.overall(),
            CoverageStatus::CompleteForDeclaredBoundary
        );
        assert!(coverage.weaker_dimensions().is_empty());
        assert_eq!(coverage.aggregate_counts.interval.start_ns, 100);
        assert_eq!(coverage.aggregate_counts.interval.end_ns, Some(200));
    }

    #[test]
    fn coverage_measured_loss_flips_only_its_dimension() {
        let mut m = measurements();
        m.ktot_gap = Some(7);
        let coverage = session_coverage(&m);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.overall(), CoverageStatus::Partial);
        assert_eq!(coverage.weaker_dimensions(), vec!["aggregate_counts"]);

        let mut m = measurements();
        m.attached_points = 8;
        let coverage = session_coverage(&m);
        assert_eq!(coverage.attachment.status, CoverageStatus::Partial);
        assert_eq!(coverage.weaker_dimensions(), vec!["attachment"]);

        let mut m = measurements();
        m.ring_drops = 2;
        m.overflow_identities = 1;
        let coverage = session_coverage(&m);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Partial);
        assert_eq!(coverage.weaker_dimensions(), vec!["detailed_events"]);
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

    /// Hand 382B agg row with `calls` (mirrors the K2 hand-row layout).
    fn hand_agg(calls: u64) -> RowBytes {
        let mut out = Vec::with_capacity(382);
        out.push(0x01);
        out.push(1);
        out.extend_from_slice(&[
            kryprobe_abi::kcrypto_agg::KFAM_SK,
            kryprobe_abi::kcrypto_agg::KOP_ENC,
            kryprobe_abi::kcrypto_agg::KRES_OK,
            kryprobe_abi::kcrypto_agg::KCTX_PROC,
        ]);
        out.extend_from_slice(b"cbc(aes)\0");
        out.extend_from_slice(&[0u8; 260 - 4 - 9]);
        out.extend_from_slice(&calls.to_le_bytes());
        out.extend_from_slice(&[0u8; 120 - 8]);
        assert_eq!(out.len(), 382);
        RowBytes::new(out).expect("hand row")
    }

    /// Hand 122B totals row with `calls`.
    fn hand_totals(calls: u64) -> TotalsBytes {
        let mut out = Vec::with_capacity(122);
        out.push(0x01);
        out.push(2);
        out.extend_from_slice(&calls.to_le_bytes());
        out.extend_from_slice(&[0u8; 120 - 8]);
        assert_eq!(out.len(), 122);
        TotalsBytes::new(out).expect("hand totals")
    }

    fn hand_snapshot(agg_calls: &[u64], tot_calls: Option<u64>) -> SnapshotRows {
        SnapshotRows {
            rows: agg_calls.iter().map(|c| hand_agg(*c)).collect(),
            totals: tot_calls.map(hand_totals),
            idents: Vec::new(),
            overflow_identities: 0,
            monotonic_ns: 7,
        }
    }

    #[test]
    fn gap_recompute_conserves_and_detects_pressure() {
        assert_eq!(
            ktot_gap(&hand_snapshot(&[10, 20], Some(30))).expect("gap"),
            Some(0)
        );
        assert_eq!(
            ktot_gap(&hand_snapshot(&[10, 20], Some(40))).expect("gap"),
            Some(10)
        );
        assert_eq!(ktot_gap(&hand_snapshot(&[10], None)).expect("gap"), None);
    }

    #[test]
    fn stdin_watcher_stops_on_eof_only() {
        use std::io::Cursor;
        let eof_stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_stdin_watcher(Cursor::new(Vec::new()), Arc::clone(&eof_stop));
        handle.join().expect("watcher joins");
        assert!(eof_stop.load(Ordering::Relaxed), "EOF stops");
        // Input bytes do not stop; EOF after input does.
        let input_stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_stdin_watcher(Cursor::new(b"hello".to_vec()), Arc::clone(&input_stop));
        handle.join().expect("watcher joins");
        assert!(input_stop.load(Ordering::Relaxed), "EOF-after-input stops");
    }
}
