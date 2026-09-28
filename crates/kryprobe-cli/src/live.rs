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
use kryprobe_privilege::kcrypto_lifecycle::sensor::{
    DrainOutcome, EnrichmentStatus, LifecycleLedger, QuietOutcome,
};
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

/// Progress hook (4B-M5): `(tick_1_based, rows, activity)`.
/// Aggregate sessions report drops as activity; lifecycle sessions
/// report consumed raw records. Callers label the counter accordingly.
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
    /// Registry-enrichment outcome (T07-R2-09: `Some` on the
    /// lifecycle profile — the ledger's available/unavailable
    /// verdict reaches the user report; `None` where the profile
    /// never snapshots the registry, rendered as not-attempted,
    /// never silent).
    pub enrichment: Option<EnrichmentStatus>,
    /// Lifecycle request totals + per-stage loss (T11/P6: `Some` on
    /// the request-lifecycle profile — feeds the session-envelope
    /// coverage record and receipt; `None` where the profile runs no
    /// lifecycle reducer).
    pub lifecycle_totals: Option<LifecycleTotals>,
}

/// Request-lifecycle terminal totals: the reducer equation plus every
/// per-stage loss counter, copied out of the [`LifecycleLedger`] at
/// session end. Feeds the session-envelope `coverage` record and the
/// terminal receipt — the envelope's global loss evidence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LifecycleTotals {
    /// Reducer admits (submit lifecycles opened — the equation owner:
    /// `admitted == emitted + live`, `unfinished ⊆ emitted`).
    pub admitted: u64,
    /// Reducer emits (records produced via apply/finish).
    pub emitted: u64,
    /// Emitted records drained truthless by finish (subset of emitted).
    pub unfinished: u64,
    /// Reducer orphans/duplicates/ambiguity/admission failures.
    pub orphan: u64,
    /// Reducer duplicate edges.
    pub duplicate: u64,
    /// Reducer ambiguous edges.
    pub ambiguous: u64,
    /// Reducer fresh submits refused (live set full).
    pub admission_failed: u64,
    /// Decode submits refused (table full, id exhaustion, BPF taint).
    pub submit_refused: u64,
    /// Returns for invocations with no outstanding submit.
    pub unknown_invoc_returns: u64,
    /// Records failing twin validation.
    pub bad_records: u64,
    /// Gaps synthesized for same-invocation resubmits.
    pub gaps_synthesized: u64,
    /// Returns refused against an outstanding submit.
    pub stale_returns: u64,
    /// Adapter submits admitted without relation cover.
    pub cover_refused: u64,
    /// Callbacks naming no live or tombstoned token.
    pub callback_orphans: u64,
    /// Callbacks naming an ambiguous key.
    pub ambiguous_keys: u64,
    /// Tombstone FIFO evictions past capacity.
    pub tombstone_evictions: u64,
    /// Callbacks predating their submit.
    pub stale_callbacks: u64,
    /// Kernel `LLOSS` per-class deltas
    /// (reserve/disabled/badkey/fret/noslot).
    pub kernel_loss: [u64; 5],
    /// Completions dropped from retention past the ledger bound.
    pub retained_dropped: u64,
    /// Transform-lifetime loss, one counter per loss field the
    /// coverage path counts (P6-N5: no folding — each rides its own
    /// `tfm.*` stage so the export names the cause). Verdict-neutral
    /// inventory (`unknown_releases`) and truth accounting
    /// (admissions, completions, joined configs) stay out, exactly
    /// as in `count_loss`.
    pub tfm_submit_refused: u64,
    /// Tainted transform edges refused quietly.
    pub tfm_tainted_refused: u64,
    /// Transform entries refused past the pending table bound.
    pub tfm_table_full: u64,
    /// Success completions/admissions refused past the live bound.
    pub tfm_live_full: u64,
    /// Transform records failing twin validation.
    pub tfm_bad_records: u64,
    /// First-seen attempts with a zero transform word.
    pub tfm_unlinked_ops: u64,
    /// Transform returns for no outstanding attempt.
    pub tfm_unknown_returns: u64,
    /// Transform returns predating their entry.
    pub tfm_stale_returns: u64,
    /// Twin-valid returns for a parked entry of the other site.
    pub tfm_mismatched_returns: u64,
    /// Pending transform attempts finalized without return.
    pub tfm_unfinished: u64,
    /// Releases that proved nothing (generation stays live).
    pub tfm_ambiguous_releases: u64,
    /// Generations forced-retired by a new alloc at their base.
    pub tfm_forced_retires: u64,
    /// Destroy returns whose generation no longer holds the base.
    pub tfm_stale_releases: u64,
    /// Unbound destroys colliding with a live occupant.
    pub tfm_colliding_releases: u64,
    /// Joined configs with no attributable generation.
    pub tfm_config_unlinked: u64,
    /// First-seen admissions (creation boundary never observed).
    pub tfm_unobserved_boundary: u64,
    /// Retired transform tombstones evicted past the history bound.
    pub tfm_tombstone_evictions: u64,
    /// Session per-program recursion-miss delta sum (H2: the kernel
    /// skipped whole runs — the miss counter is the only witness).
    pub prog_miss_delta: u64,
    /// Accepted-but-unconsumed aggregate residual (accepted minus
    /// consumed, reserve, and noslot — the accounting equation
    /// broke). UNEXPLAINED unconditionally: backlog bytes can never
    /// exonerate edge counts (byte and edge units do not convert,
    /// and ring framing is unobservable from userspace) — so no
    /// backlog value zeroes this field.
    pub transport_residual: u64,
    /// Close-ring backlog in BYTES at quiet verdict (the measured
    /// close backlog, not an edge count — honestly labeled as bytes
    /// everywhere it rides). Nonzero voids clean exactly like any
    /// counted stage loss: backlog is unmeasured-at-close evidence,
    /// never an exoneration.
    pub close_backlog_bytes: u64,
    /// Driver-side observation-cap omissions (decoded records the
    /// session kept no observation for — counted, never silent).
    pub omitted: u64,
    /// Records whose terminal is `Unknown` (counted from the records
    /// themselves — the ambiguous branch emits `Unknown` without
    /// touching `unfinished`).
    pub unknown_terminals: u64,
}

impl LifecycleTotals {
    /// Copies terminal totals out of the session ledger plus the
    /// driver's own close stats. `kernel_loss` takes session DELTAS
    /// (post minus pre-arm baseline), never absolutes. Every loss
    /// counter the coverage path counts rides along (P6-N5):
    /// program-miss deltas, all transform loss fields, the
    /// transport residual, and the close-backlog byte measurement
    /// (P6r2-N1: its own honestly-labeled stage) — the envelope's
    /// global loss evidence.
    #[must_use]
    pub fn from_ledger(
        ledger: &LifecycleLedger,
        kernel_loss_delta: [u64; 5],
        omitted: u64,
        unknown_terminals: u64,
        backlog_bytes: u64,
    ) -> Self {
        // The transport residual, exactly as the coverage path
        // computes it (accepted minus consumed, reserve, and noslot —
        // the accounting equation broke) — UNEXPLAINED under ANY
        // backlog (P6r2-N1: bytes can never exonerate edge counts).
        // The backlog measurement rides alongside as its own
        // honestly-labeled bytes stage, never folded into the
        // residual and never zeroing it.
        let agg_sum: u64 = ledger
            .agg_accepted
            .iter()
            .fold(0, |sum, accepted| sum.saturating_add(*accepted));
        let hits_sum: u64 = ledger
            .edge_hits
            .iter()
            .fold(0, |sum, hits| sum.saturating_add(*hits));
        let residual = agg_sum
            .saturating_sub(hits_sum)
            .saturating_sub(ledger.kernel_loss[0])
            .saturating_sub(ledger.kernel_loss[4]);
        Self {
            admitted: ledger.reducer.admitted,
            emitted: ledger.reducer.emitted,
            unfinished: ledger.reducer.unfinished,
            orphan: ledger.reducer.orphan,
            duplicate: ledger.reducer.duplicate,
            ambiguous: ledger.reducer.ambiguous,
            admission_failed: ledger.reducer.admission_failed,
            submit_refused: ledger.decode.submit_refused,
            unknown_invoc_returns: ledger.decode.unknown_invoc_returns,
            bad_records: ledger.decode.bad_records,
            gaps_synthesized: ledger.decode.gaps_synthesized,
            stale_returns: ledger.decode.stale_returns,
            cover_refused: ledger.adapter.cover_refused,
            callback_orphans: ledger.adapter.callback_orphans,
            ambiguous_keys: ledger.adapter.ambiguous_keys,
            tombstone_evictions: ledger.adapter.tombstone_evictions,
            stale_callbacks: ledger.adapter.stale_callbacks,
            kernel_loss: kernel_loss_delta,
            retained_dropped: ledger.retained_dropped,
            tfm_submit_refused: ledger.tfm_stats.submit_refused,
            tfm_tainted_refused: ledger.tfm_stats.tainted_refused,
            tfm_table_full: ledger.tfm_stats.table_full,
            tfm_live_full: ledger.tfm_stats.live_full,
            tfm_bad_records: ledger.tfm_stats.bad_records,
            tfm_unlinked_ops: ledger.tfm_stats.unlinked_ops,
            tfm_unknown_returns: ledger.tfm_stats.unknown_returns,
            tfm_stale_returns: ledger.tfm_stats.stale_returns,
            tfm_mismatched_returns: ledger.tfm_stats.mismatched_returns,
            tfm_unfinished: ledger.tfm_stats.unfinished,
            tfm_ambiguous_releases: ledger.tfm_stats.ambiguous_releases,
            tfm_forced_retires: ledger.tfm_stats.forced_retires,
            tfm_stale_releases: ledger.tfm_stats.stale_releases,
            tfm_colliding_releases: ledger.tfm_stats.colliding_releases,
            tfm_config_unlinked: ledger.tfm_stats.config_unlinked,
            tfm_unobserved_boundary: ledger.tfm_stats.unobserved_boundary,
            tfm_tombstone_evictions: ledger.tfm_stats.tombstone_evictions,
            prog_miss_delta: prog_miss_delta_sum(&ledger.prog_misses),
            transport_residual: residual,
            close_backlog_bytes: backlog_bytes,
            omitted,
            unknown_terminals,
        }
    }

    /// Nonzero loss stages in fixed order (stage name + count) for the
    /// envelope loss map. Zero stages are ABSENT (empty map = no
    /// counted stage loss); every counter above that can witness loss
    /// appears here when nonzero — none are folded away silently.
    #[must_use]
    pub fn loss_stages(&self) -> Vec<(&'static str, u64)> {
        [
            ("reducer.orphan", self.orphan),
            ("reducer.duplicate", self.duplicate),
            ("reducer.ambiguous", self.ambiguous),
            ("reducer.admission_failed", self.admission_failed),
            ("decode.submit_refused", self.submit_refused),
            ("decode.unknown_invoc_returns", self.unknown_invoc_returns),
            ("decode.bad_records", self.bad_records),
            ("decode.gaps_synthesized", self.gaps_synthesized),
            ("decode.stale_returns", self.stale_returns),
            ("adapter.cover_refused", self.cover_refused),
            ("adapter.callback_orphans", self.callback_orphans),
            ("adapter.ambiguous_keys", self.ambiguous_keys),
            ("adapter.tombstone_evictions", self.tombstone_evictions),
            ("adapter.stale_callbacks", self.stale_callbacks),
            ("kernel.reserve", self.kernel_loss[0]),
            ("kernel.disabled", self.kernel_loss[1]),
            ("kernel.badkey", self.kernel_loss[2]),
            ("kernel.fret", self.kernel_loss[3]),
            ("kernel.noslot", self.kernel_loss[4]),
            ("kernel.prog_miss_delta", self.prog_miss_delta),
            ("retained_dropped", self.retained_dropped),
            ("tfm.submit_refused", self.tfm_submit_refused),
            ("tfm.tainted_refused", self.tfm_tainted_refused),
            ("tfm.table_full", self.tfm_table_full),
            ("tfm.live_full", self.tfm_live_full),
            ("tfm.bad_records", self.tfm_bad_records),
            ("tfm.unlinked_ops", self.tfm_unlinked_ops),
            ("tfm.unknown_returns", self.tfm_unknown_returns),
            ("tfm.stale_returns", self.tfm_stale_returns),
            ("tfm.mismatched_returns", self.tfm_mismatched_returns),
            ("tfm.unfinished", self.tfm_unfinished),
            ("tfm.ambiguous_releases", self.tfm_ambiguous_releases),
            ("tfm.forced_retires", self.tfm_forced_retires),
            ("tfm.stale_releases", self.tfm_stale_releases),
            ("tfm.colliding_releases", self.tfm_colliding_releases),
            ("tfm.config_unlinked", self.tfm_config_unlinked),
            ("tfm.unobserved_boundary", self.tfm_unobserved_boundary),
            ("tfm.tombstone_evictions", self.tfm_tombstone_evictions),
            (
                "transport.agg_residual_unexplained",
                self.transport_residual,
            ),
            ("transport.close_backlog_bytes", self.close_backlog_bytes),
            ("driver.omitted", self.omitted),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .collect()
    }

    /// Total counted stage loss (saturating — an overflowed total reads
    /// huge, never wraps to a clean-looking zero).
    #[must_use]
    pub fn loss_total(&self) -> u64 {
        self.loss_stages()
            .iter()
            .fold(0u64, |sum, (_, count)| sum.saturating_add(*count))
    }
}

/// One human-report trailer line for the enrichment verdict
/// (T07-R2-09: shared by `watch` and `report --system` human —
/// the ledger's available/unavailable verdict is user-visible;
/// profiles that never snapshot say so, never stay silent).
#[must_use]
pub fn render_enrichment_line(enrichment: &Option<EnrichmentStatus>) -> String {
    match enrichment {
        Some(EnrichmentStatus::Available { entries, truncated }) => {
            format!("enrichment: available (entries={entries}, truncated={truncated})\n")
        }
        Some(EnrichmentStatus::Unavailable { reason }) => {
            format!("enrichment: unavailable (reason: {reason})\n")
        }
        None => "enrichment: not attempted (profile snapshots no registry)\n".to_owned(),
    }
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
    // evidence, any reducer evidence that never became a
    // trustworthy record (orphans, ambiguous, admission failures),
    // any callback-adapter loss (P4-N1: refused cover, orphans,
    // ambiguity gaps, tombstone evictions, stale callbacks — all
    // five vote, same as the backend buckets),
    // and any transform-lifetime loss (T07-05/R3: refused,
    // unadmitted, unjoined, or uncertain-identity transform
    // evidence corrupts the generations the report counts —
    // normal transform accounting stays unmapped, same as the
    // backend buckets; unbound destroys ride the inventory
    // counter below, never the loss vote — T07-R2-05).
    // Duplicates repeat known state — no information lost, never
    // flipping. A loss-clean ledger is still `Unknown`: internal
    // pairing cannot prove kernel hook-delivery (S04/G9 twin).
    // (T07-R3-02: an unbound destroy colliding with a live occupant
    // votes here — indeterminate identity, never inventory.)
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
        .saturating_add(ledger.reducer.admission_failed)
        .saturating_add(ledger.adapter.cover_refused)
        .saturating_add(ledger.adapter.callback_orphans)
        .saturating_add(ledger.adapter.ambiguous_keys)
        .saturating_add(ledger.adapter.tombstone_evictions)
        .saturating_add(ledger.adapter.stale_callbacks)
        .saturating_add(ledger.tfm_stats.submit_refused)
        .saturating_add(ledger.tfm_stats.tainted_refused)
        .saturating_add(ledger.tfm_stats.table_full)
        .saturating_add(ledger.tfm_stats.live_full)
        .saturating_add(ledger.tfm_stats.bad_records)
        .saturating_add(ledger.tfm_stats.unlinked_ops)
        .saturating_add(ledger.tfm_stats.unknown_returns)
        .saturating_add(ledger.tfm_stats.stale_returns)
        .saturating_add(ledger.tfm_stats.mismatched_returns)
        .saturating_add(ledger.tfm_stats.unfinished)
        .saturating_add(ledger.tfm_stats.ambiguous_releases)
        .saturating_add(ledger.tfm_stats.forced_retires)
        .saturating_add(ledger.tfm_stats.stale_releases)
        .saturating_add(ledger.tfm_stats.colliding_releases)
        .saturating_add(ledger.tfm_stats.config_unlinked)
        .saturating_add(ledger.tfm_stats.unobserved_boundary)
        .saturating_add(ledger.tfm_stats.tombstone_evictions);
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
    // T07-R2-05, narrowed T07-R3-02: unbound destroys at
    // UNOCCUPIED bases stay VISIBLE as inventory (expected
    // digest/shash releases share the counter with destroy-only
    // missed identities that never touched in-boundary state) —
    // verdict-neutral, never silent, never a loss vote. Unbound
    // destroys colliding with a live occupant vote loss via
    // `colliding_releases` in the sums above, never here.
    aggregate_counts.counters.push(counter(
        "unbound_destroy_inventory",
        ledger.tfm_stats.unknown_releases,
    ));
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
    // A clean transport needs BOTH a zero residual and an empty
    // close ring (P6r2-N1: backlog bytes never explain edge counts —
    // the two ride as separate honest counters below, and either
    // nonzero flips `Partial`).
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
    // Transform join-health (T07-05/R3) joins the same count:
    // unjoined/dangling/misjoined transform attempts and
    // uncertain-identity releases are correlation events too.
    // (T07-R2-08: D4 bound refusals, tainted/unlinked edges, and
    // twin-validation refusals join as well — a refused identity
    // or unjoinable edge breaks the join claim exactly like a
    // stale return. Only the TRANSFORM `tombstone_evictions` stays
    // out: eviction drops retired tombstones whose records already
    // emitted; any late edge for one surfaces via unknown/stale.
    // The ADAPTER's five counters all JOIN (P4-N1): refused cover,
    // orphan/stale callbacks, and ambiguity gaps are unjoinable
    // completion evidence, and adapter tombstone eviction voids
    // the retention the join claim rests on. Unbound
    // destroys at UNOCCUPIED bases stay out too (T07-R2-05,
    // narrowed T07-R3-02: expected digest/shash releases are
    // unjoinable BY DESIGN — no identity exists to join — so they
    // ride inventory, never the join claim); an unbound destroy
    // colliding with a live occupant JOINS (indeterminate identity
    // AT an identity — the join claim cannot stand).
    let correlation_events = ledger
        .decode
        .gaps_synthesized
        .saturating_add(ledger.decode.stale_returns)
        .saturating_add(ledger.decode.unknown_invoc_returns)
        .saturating_add(ledger.decode.submit_refused)
        .saturating_add(ledger.decode.bad_records)
        .saturating_add(ledger.reducer.ambiguous)
        .saturating_add(ledger.reducer.orphan)
        .saturating_add(ledger.adapter.cover_refused)
        .saturating_add(ledger.adapter.callback_orphans)
        .saturating_add(ledger.adapter.ambiguous_keys)
        .saturating_add(ledger.adapter.tombstone_evictions)
        .saturating_add(ledger.adapter.stale_callbacks)
        .saturating_add(ledger.tfm_stats.unknown_returns)
        .saturating_add(ledger.tfm_stats.stale_returns)
        .saturating_add(ledger.tfm_stats.mismatched_returns)
        .saturating_add(ledger.tfm_stats.submit_refused)
        .saturating_add(ledger.tfm_stats.tainted_refused)
        .saturating_add(ledger.tfm_stats.table_full)
        .saturating_add(ledger.tfm_stats.live_full)
        .saturating_add(ledger.tfm_stats.bad_records)
        .saturating_add(ledger.tfm_stats.unlinked_ops)
        .saturating_add(ledger.tfm_stats.unfinished)
        .saturating_add(ledger.tfm_stats.ambiguous_releases)
        .saturating_add(ledger.tfm_stats.forced_retires)
        .saturating_add(ledger.tfm_stats.stale_releases)
        .saturating_add(ledger.tfm_stats.colliding_releases)
        .saturating_add(ledger.tfm_stats.config_unlinked)
        .saturating_add(ledger.tfm_stats.unobserved_boundary);
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
    /// Wait for transport activity, returning by `max_wait` so the
    /// driver can service cancellation and its deadline. Readiness is
    /// only a hint; the next bounded drain remains authoritative. A
    /// `pending_writer` needs a bounded retry yield: reserved ring bytes
    /// can be readable to poll before their record is committed.
    fn wait_for_activity(
        &mut self,
        max_wait: Duration,
        pending_writer: bool,
    ) -> Result<(), LiveError>;
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

    fn wait_for_activity(
        &mut self,
        max_wait: Duration,
        pending_writer: bool,
    ) -> Result<(), LiveError> {
        self.backend
            .wait_for_activity(max_wait, pending_writer)
            .map_err(|err| backend_err("live lifecycle wait", err))
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
        // The aggregate profile never snapshots the registry.
        enrichment: None,
        // The aggregate profile runs no lifecycle reducer.
        lifecycle_totals: None,
    })
}

/// Per-round ring-drain visit cap, from actual wire sizes (P2/K05,
/// 2026-09-26: the old "48 B per frame" note belonged to the
/// aggregate `KCtl` control shape, never to lifecycle edges).
/// `LRING` is 262,144 bytes; one `LEdge` v5 (or `LTfm` v1
/// transform) record costs 112 payload bytes + the 8-byte ring
/// header = 120 bytes/frame (already 8-aligned), so a ringful
/// holds ≈2184 mixed records ≈ 1092 two-edge calls before other
/// traffic — fewer while a busy (reserved-uncommitted) record
/// holds space. 8192 visits cover ≈3.75 ringfuls plus margin,
/// still bounded; the sustained loop re-polls while records flow.
/// In-flight bounds behind the drain: decode 4096 / reducer 4096 /
/// completed-retention 4096 (the sensor arm; the transform tracker
/// shares the decode scale) — overflows are counted
/// (`admission_failed`, `retained_dropped`, `LLOSS`), never silent.
/// Rate/burst/interval/cap relation (P2r/C3: headroom, not just
/// rate, decides): with ring capacity C ≈ 2184 records and burst-start
/// occupancy O, a burst of B records arriving at rate A over a
/// consumer draining at rate D survives iff O + B·(1 − D/A) ≤ C
/// when D < A (the unconsumed remainder fits the C − O headroom;
/// e.g. B=3000 at A=1000/s over D=500/s peaks ≈1500, below C —
/// a slower consumer still survives); D ≥ A always survives.
/// Past the headroom, reservation fails loud. The display tick
/// (default 1000 ms) paces human progress only, never transport;
/// past 100,000 kept observations the session stops early with
/// counted omissions — detail duration ≤ 100000/R s at R
/// completions/s.
/// Long-running aggregates must not silently depend on unlimited
/// per-request retention: continuous summaries need the P6
/// versioned output contract (open gate — see the P2 report).
const LIFECYCLE_DRAIN_BUDGET: usize = 8192;

/// Sustained-drain rounds per tick (T07-R3-05): a tick re-polls
/// while records flow (or the writer holds one open) instead of
/// napping between single drains — a 1,000-lifetime burst emits
/// past one ringful in a few ms, and one drain per second drops
/// it. Each window is bounded to 8 rounds × 8192 visits;
/// past the cap the driver still services progress, omission cap,
/// and deadline stay live under endless flood — the session's own
/// guards, not the producer, bound the loop).
const LIFECYCLE_DRAIN_ROUNDS_PER_TICK: u32 = 8;

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
/// per-window SUSTAINED ring drain (rounds to quiet, capped —
/// T07-R3-05) → completed records → `decode` each (first error
/// aborts `Internal`), then stop-time `finish` reconciliation,
/// then `finalize` ONCE and the shared feed ONCE, then coverage from
/// the terminal ledger. NEVER finalizes per tick (D1/M1). Windows
/// wait on readiness when quiet; a busy record with no progress gets
/// a bounded retry delay. Display cadence never sets transport cadence.
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
    let mut last_display: Option<Instant> = None;
    let mut display_completed = 0u64;
    let mut display_records = 0u64;
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
        let now = sensor.now_ns()?;
        // Coverage interval walls come from the ring clock itself
        // (the snapshot precedent: measured `CLOCK_MONOTONIC`, no
        // separate clock read the ring cannot share).
        if first_tick {
            first_wall = now;
            first_tick = false;
        }
        // Sustained drain (T07-R3-05, the canary pattern ported
        // to production): re-poll IMMEDIATELY while records flow —
        // a burst past one ringful must meet a draining consumer,
        // not a napping one. Rounds stop at the first quiet round
        // (nothing consumed, no busy writer), at the round cap (the
        // window still elapses under endless flood), or promptly on
        // stop/omission/deadline/SIGINT (same guards as the window
        // edge below).
        let mut window_completed = 0u64;
        let mut window_records = 0u64;
        let mut window_quiet = false;
        for _ in 0..LIFECYCLE_DRAIN_ROUNDS_PER_TICK {
            let drained = sensor.drain_tick(LIFECYCLE_DRAIN_BUDGET)?;
            let completed = sensor.take_completed()?;
            window_completed += completed.len() as u64;
            window_records += drained.records as u64;
            decode_records(completed, &mut observations)?;
            interrupted |= SIGINT_SEEN.load(Ordering::Relaxed);
            if drained.records == 0 && !drained.busy {
                window_quiet = true;
                break;
            }
            if stop.load(Ordering::Relaxed)
                || interrupted
                || omitted.get() > 0
                || deadline.is_some_and(|end| Instant::now() >= end)
            {
                break;
            }
        }
        display_completed = display_completed.saturating_add(window_completed);
        display_records = display_records.saturating_add(window_records);
        let stopped = stop.load(Ordering::Relaxed)
            || interrupted
            || omitted.get() > 0
            || deadline.is_some_and(|end| Instant::now() >= end);
        let display_now = Instant::now();
        if stopped
            || last_display.is_none_or(|last| {
                display_now.duration_since(last) >= Duration::from_millis(tick_ms)
            })
        {
            barrier_id += 1;
            if let Some(report) = progress {
                // Human-only progress aggregates service windows between
                // display updates; stopping flushes the pending totals.
                report(barrier_id, display_completed, display_records);
            }
            display_completed = 0;
            display_records = 0;
            last_display = Some(display_now);
        }
        if stopped {
            break;
        }
        // A quiet snapshot is not a promise of an idle display interval.
        // Wait on the owned ring so newly committed data wakes collection.
        // Short bounded waits preserve cancellation/deadline service.
        if window_quiet || window_records == 0 {
            let max_wait = Duration::from_millis(STOP_POLL_MS.min(tick_ms));
            let max_wait = deadline.map_or(max_wait, |end| {
                max_wait.min(end.saturating_duration_since(Instant::now()))
            });
            sensor.wait_for_activity(max_wait, !window_quiet)?;
        }
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
    // T11/P6: session-attributable kernel loss is the post-session
    // absolute minus the pre-arm baseline (saturating — a backwards
    // counter reads zero here AND voids coverage through the miss
    // join; the envelope carries this session's loss, not the
    // machine's lifetime totals).
    let mut kernel_loss_delta = [0u64; 5];
    for (slot, (post, pre)) in kernel_loss_delta
        .iter_mut()
        .zip(ledger.kernel_loss.iter().zip(ledger.loss_baseline.iter()))
    {
        *slot = post.saturating_sub(*pre);
    }
    let lifecycle_totals = LifecycleTotals::from_ledger(
        &ledger,
        kernel_loss_delta,
        omitted.get(),
        unknown_terminals,
        close.backlog_bytes,
    );
    Ok(LiveOutcome {
        observations: report.take_observations(),
        summary,
        coverage,
        integrity,
        terminal_state: controller.state(),
        interrupted,
        // T07-R2-09: the ledger's enrichment verdict rides the
        // outcome to the user report (available/unavailable —
        // never dropped between sensor and render).
        enrichment: Some(ledger.enrichment.clone()),
        lifecycle_totals: Some(lifecycle_totals),
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
    let progress = |tick: u64, rows: u64, records: u64| {
        eprintln!("kryprobe: progress tick={tick} rows={rows} records={records}");
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
    fn enrichment_line_renders_all_three_arms() {
        // T07-R2-09: the public report surfaces the enrichment
        // verdict — available (with the entry-aware truncation
        // flag), unavailable (with the reason, never silent), or
        // not attempted (never a fabricated inventory).
        assert_eq!(
            render_enrichment_line(&Some(EnrichmentStatus::Available {
                entries: 3,
                truncated: false,
            })),
            "enrichment: available (entries=3, truncated=false)\n"
        );
        assert_eq!(
            render_enrichment_line(&Some(EnrichmentStatus::Available {
                entries: 1,
                truncated: true,
            })),
            "enrichment: available (entries=1, truncated=true)\n"
        );
        assert_eq!(
            render_enrichment_line(&Some(EnrichmentStatus::Unavailable {
                reason: "os error 2".to_owned(),
            })),
            "enrichment: unavailable (reason: os error 2)\n"
        );
        assert_eq!(
            render_enrichment_line(&None),
            "enrichment: not attempted (profile snapshots no registry)\n"
        );
    }

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
            edge_hits: [
                4, 4, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            adapter: kryprobe_privilege::kcrypto_lifecycle::async_adapter::AdapterStats::default(),
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
            agg_accepted: [
                4, 4, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            retained_dropped: 0,
            view_valid: true,
            loss_baseline: [0; 5],
            agg_baseline: [0; 22],
            prog_misses: Vec::new(),
            miss_current: Vec::new(),
            tfm_stats: kryprobe_privilege::kcrypto_lifecycle::tfm::TfmStats::default(),
            generations: Vec::new(),
            enrichment: EnrichmentStatus::Available {
                entries: 0,
                truncated: false,
            },
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
    fn from_ledger_carries_prog_miss_deltas() {
        // P6-N5 RED: per-program recursion-miss deltas vote in
        // count_loss — the envelope must carry them (reviewer loss
        // probe: delta 7 exported 0).
        let mut ledger = lifecycle_ledger_clean();
        ledger.prog_misses = vec![kryprobe_privilege::kcrypto_lifecycle::view::ProgMissDelta {
            section: "fsession/crypto_skcipher_encrypt".to_owned(),
            baseline: 0,
            current: 7,
        }];
        let totals = LifecycleTotals::from_ledger(&ledger, [0; 5], 0, 0, 0);
        assert_eq!(totals.loss_total(), 7, "prog-miss delta rides the export");
    }

    #[test]
    fn from_ledger_carries_every_tfm_loss_field() {
        // P6-N5 RED: every tfm loss field the coverage path counts
        // rides its own stage (reviewer probe: config_unlinked=3
        // exported 0; only 3 of 17 fields folded before).
        let mut ledger = lifecycle_ledger_clean();
        let tfm = &mut ledger.tfm_stats;
        tfm.submit_refused = 1;
        tfm.tainted_refused = 2;
        tfm.table_full = 3;
        tfm.live_full = 4;
        tfm.bad_records = 5;
        tfm.unlinked_ops = 6;
        tfm.unknown_returns = 7;
        tfm.stale_returns = 8;
        tfm.mismatched_returns = 9;
        tfm.unfinished = 10;
        tfm.ambiguous_releases = 11;
        tfm.forced_retires = 12;
        tfm.stale_releases = 13;
        tfm.colliding_releases = 14;
        tfm.config_unlinked = 15;
        tfm.unobserved_boundary = 16;
        tfm.tombstone_evictions = 17;
        let totals = LifecycleTotals::from_ledger(&ledger, [0; 5], 0, 0, 0);
        let stages = totals.loss_stages();
        for (stage, want) in [
            ("tfm.submit_refused", 1),
            ("tfm.tainted_refused", 2),
            ("tfm.table_full", 3),
            ("tfm.live_full", 4),
            ("tfm.bad_records", 5),
            ("tfm.unlinked_ops", 6),
            ("tfm.unknown_returns", 7),
            ("tfm.stale_returns", 8),
            ("tfm.mismatched_returns", 9),
            ("tfm.unfinished", 10),
            ("tfm.ambiguous_releases", 11),
            ("tfm.forced_retires", 12),
            ("tfm.stale_releases", 13),
            ("tfm.colliding_releases", 14),
            ("tfm.config_unlinked", 15),
            ("tfm.unobserved_boundary", 16),
            ("tfm.tombstone_evictions", 17),
        ] {
            assert!(
                stages.contains(&(stage, want)),
                "stage {stage}={want} rides: {stages:?}"
            );
        }
        assert_eq!(totals.loss_total(), 153, "every field sums");
    }

    #[test]
    fn from_ledger_carries_unexplained_transport_residual() {
        // P6-N5 RED: accepted-but-unconsumed edges with an empty
        // close ring are unexplained loss (reviewer probe: residual
        // 9 exported 0).
        let mut ledger = lifecycle_ledger_clean();
        ledger.agg_accepted[0] = ledger.agg_accepted[0].saturating_add(9);
        let totals = LifecycleTotals::from_ledger(&ledger, [0; 5], 0, 0, 0);
        assert!(
            totals
                .loss_stages()
                .contains(&("transport.agg_residual_unexplained", 9)),
            "residual rides: {:?}",
            totals.loss_stages()
        );
    }

    #[test]
    fn from_ledger_backlog_never_exonerates_residual() {
        // P6r2-N1 (coordinator-authorized pin update): backlog bytes
        // can never exonerate edge counts (128 bytes cannot explain
        // 73 112-byte edges, and framing is unobservable from
        // userspace) — the residual rides UNEXPLAINED under ANY
        // backlog, and the backlog measurement rides alongside as
        // its own honestly-labeled stage (both count toward the
        // clean rule, keeping `loss_total() == 0` honest).
        let mut ledger = lifecycle_ledger_clean();
        ledger.agg_accepted[0] = ledger.agg_accepted[0].saturating_add(9);
        let totals = LifecycleTotals::from_ledger(&ledger, [0; 5], 0, 0, 128);
        assert_eq!(totals.transport_residual, 9, "residual never suppressed");
        assert_eq!(totals.close_backlog_bytes, 128, "backlog rides");
        assert!(
            totals
                .loss_stages()
                .contains(&("transport.agg_residual_unexplained", 9)),
            "residual exports under backlog: {:?}",
            totals.loss_stages()
        );
        assert!(
            totals
                .loss_stages()
                .contains(&("transport.close_backlog_bytes", 128)),
            "backlog exports honestly labeled: {:?}",
            totals.loss_stages()
        );
        assert_eq!(totals.loss_total(), 137, "both stages count");
    }

    #[test]
    fn from_ledger_backlog_zero_branch_carries_residual_only() {
        // P6r2-N1: the empty-ring branch — the residual rides alone
        // and no backlog stage appears (zero stages stay absent).
        let mut ledger = lifecycle_ledger_clean();
        ledger.agg_accepted[0] = ledger.agg_accepted[0].saturating_add(9);
        let totals = LifecycleTotals::from_ledger(&ledger, [0; 5], 0, 0, 0);
        assert_eq!(totals.transport_residual, 9);
        assert_eq!(totals.close_backlog_bytes, 0);
        assert!(
            !totals
                .loss_stages()
                .iter()
                .any(|(stage, _)| *stage == "transport.close_backlog_bytes"),
            "zero backlog stays absent: {:?}",
            totals.loss_stages()
        );
        assert_eq!(totals.loss_total(), 9, "residual only");
    }

    #[test]
    fn from_ledger_lone_backlog_voids_clean() {
        // P6r2-N1: backlog WITHOUT residual is still counted loss
        // evidence (unmeasured-at-close bytes) — a lone nonzero
        // backlog voids `loss_total() == 0`, matching the coverage
        // flip (either nonzero flips `Partial`).
        let ledger = lifecycle_ledger_clean();
        let totals = LifecycleTotals::from_ledger(&ledger, [0; 5], 0, 0, 128);
        assert_eq!(totals.transport_residual, 0);
        assert_eq!(totals.close_backlog_bytes, 128);
        assert_eq!(totals.loss_total(), 128, "lone backlog counts");
    }

    #[test]
    fn from_ledger_bad_records_positive_control() {
        // Pins the already-working path the reviewer used as the
        // positive control (bad_records=4 exports 4).
        let mut ledger = lifecycle_ledger_clean();
        ledger.decode.bad_records = 4;
        let totals = LifecycleTotals::from_ledger(&ledger, [0; 5], 0, 0, 0);
        assert_eq!(totals.loss_total(), 4);
        assert!(totals.loss_stages().contains(&("decode.bad_records", 4)));
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
    fn p4r2_adapter_orphan_flips_count_correlation_and_commit() {
        // P4-N1: an observed-but-unjoinable callback is measured
        // loss — the count aggregate, the correlation join claim,
        // and (via commit_clean) the completion verdict all flip
        // Partial. Delivery-unmeasured is no longer the story.
        let mut ledger = lifecycle_ledger_clean();
        ledger.adapter.callback_orphans = 1;
        let interval = ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        };
        let got = lifecycle_coverage(&ledger, 9, 9, 6, &close_clean(), interval);
        assert_eq!(got.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(got.correlation.status, CoverageStatus::Partial);
        assert_eq!(got.completion.status, CoverageStatus::Partial);
    }

    #[test]
    fn p4r2_every_adapter_counter_votes_count_loss() {
        // P4-N1: each of the five adapter counters alone voids the
        // loss-clean count (unknown→Partial), exactly like every
        // other decode/reducer/tfm loss input.
        use kryprobe_privilege::kcrypto_lifecycle::async_adapter::AdapterStats;
        let names = [
            "cover_refused",
            "callback_orphans",
            "ambiguous_keys",
            "tombstone_evictions",
            "stale_callbacks",
        ];
        let sets: [fn(&mut AdapterStats); 5] = [
            |a| a.cover_refused = 1,
            |a| a.callback_orphans = 1,
            |a| a.ambiguous_keys = 1,
            |a| a.tombstone_evictions = 1,
            |a| a.stale_callbacks = 1,
        ];
        for (i, set) in sets.into_iter().enumerate() {
            let mut ledger = lifecycle_ledger_clean();
            set(&mut ledger.adapter);
            let interval = ValidityInterval {
                start_ns: 100,
                end_ns: Some(200),
            };
            let got = lifecycle_coverage(&ledger, 9, 9, 6, &close_clean(), interval);
            assert_eq!(
                got.aggregate_counts.status,
                CoverageStatus::Partial,
                "{} must vote count loss",
                names[i]
            );
            assert_eq!(
                got.correlation.status,
                CoverageStatus::Partial,
                "{} must vote correlation events",
                names[i]
            );
        }
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
        ledger.agg_accepted = [
            5, 4, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.detailed_events.status, CoverageStatus::Partial);
    }

    #[test]
    fn t0705_transform_loss_flips_counts_and_correlation() {
        // T07-05/R3: transform-lifetime loss reaches the public
        // report — D4 exhaustion flips counts to Partial (never a
        // clean verdict over missing identities), uncertain
        // identity flips correlation, and truth-only transform
        // traffic flips nothing. (T07-R2-08: every refusal flips
        // BOTH counts and correlation — a refused identity breaks
        // the join claim, never just the count.)
        let interval = ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        };
        // D4 live-table exhaustion: one refused identity.
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.live_full = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        // D4 pending-table exhaustion: same, both dimensions.
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.table_full = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        // Every other refusal/unjoinable class flips both too.
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.tainted_refused = 1;
        ledger.tfm_stats.bad_records = 1;
        ledger.tfm_stats.unlinked_ops = 1;
        ledger.decode.bad_records = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        assert!(
            coverage
                .correlation
                .counters
                .iter()
                .any(|c| c.name == "correlation_events" && c.value == 4),
            "all four refusals counted: {:?}",
            coverage.correlation.counters
        );
        // Uncertain identity: an ambiguous release corrupts the
        // generations the report counts AND the correlation claim.
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.ambiguous_releases = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        // Dangling-at-close: unmatched entry, correlation flips.
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.unfinished = 2;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        // Truth-only transform traffic (proved retires, joined
        // configs incl. errno verdicts, classified failures) flips
        // nothing: a busy-but-clean session reports clean.
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.admitted = 50;
        ledger.tfm_stats.completed = 50;
        ledger.tfm_stats.releases = 10;
        ledger.tfm_stats.retired = 10;
        ledger.tfm_stats.configs_joined = 20;
        ledger.tfm_stats.configs_failed = 2;
        ledger.tfm_stats.failed_allocs = 1;
        ledger.tfm_stats.noop_releases = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        assert_eq!(
            coverage.correlation.status,
            CoverageStatus::CompleteForDeclaredBoundary
        );
    }

    #[test]
    fn t07r205_unbound_destroys_are_inventory_not_loss() {
        // T07-R2-05 mixed traffic: routine digest/shash releases
        // (unbound destroys) during an otherwise clean capture
        // flip NOTHING — counts stay Unknown, correlation stays
        // Complete — while the magnitude stays visible on the
        // inventory counter. A missed identity that is USED still
        // flips both dimensions via its unobserved admission.
        let interval = ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        };
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.unknown_releases = 7;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Unknown);
        assert_eq!(
            coverage.correlation.status,
            CoverageStatus::CompleteForDeclaredBoundary
        );
        assert!(
            coverage
                .aggregate_counts
                .counters
                .iter()
                .any(|c| c.name == "unbound_destroy_inventory" && c.value == 7),
            "inventory magnitude visible: {:?}",
            coverage.aggregate_counts.counters
        );
        assert!(
            coverage
                .aggregate_counts
                .counters
                .iter()
                .any(|c| c.name == "count_loss" && c.value == 0),
            "no loss vote: {:?}",
            coverage.aggregate_counts.counters
        );
        // Preserved loss: the same session where the missed
        // identity was USED (op admission) flips both.
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.unknown_releases = 7;
        ledger.tfm_stats.unobserved_boundary = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
    }

    #[test]
    fn t07r302_colliding_destroys_vote_loss() {
        // T07-R3-02 public coverage: an unbound destroy at a base
        // WITH a live occupant is indeterminate identity evidence
        // (never digest inventory) — it votes loss on both
        // dimensions, exactly like the other uncertain-identity
        // release classes.
        let interval = ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        };
        let mut ledger = lifecycle_ledger_clean();
        ledger.tfm_stats.colliding_releases = 1;
        let coverage = lifecycle_coverage(&ledger, 2, 2, 6, &close_clean(), interval);
        assert_eq!(coverage.aggregate_counts.status, CoverageStatus::Partial);
        assert_eq!(coverage.correlation.status, CoverageStatus::Partial);
        assert!(
            coverage
                .aggregate_counts
                .counters
                .iter()
                .any(|c| c.name == "count_loss" && c.value == 1),
            "colliding votes loss: {:?}",
            coverage.aggregate_counts.counters
        );
        assert!(
            coverage
                .correlation
                .counters
                .iter()
                .any(|c| c.name == "correlation_events" && c.value == 1),
            "colliding is a correlation event: {:?}",
            coverage.correlation.counters
        );
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
