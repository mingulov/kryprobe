// SPDX-License-Identifier: GPL-3.0-or-later
//! `request-lifecycle` registry backend (T06 F8c): the edge-pairing
//! sensor behind the frozen 7-method [`Backend`] trait.
//!
//! One [`BackendId::KCrypto`] slot serves both profiles — registering
//! the second is a typed [`DuplicateBackend`], never a second capture
//! (structural exclusion within a session; the process-wide
//! [`SessionGuard`] covers cross-PROFILE bring-up — same-profile
//! concurrency still shares by design, see the guard docs). The driver feeds
//! completed [`RequestRecord`]s through [`lifecycle_event`] +
//! [`Backend::decode`]; the JSON envelope is validated strictly
//! (fail-closed [`BackendError::CorruptInput`]), so a foreign event fed here
//! refuses instead of misdecoding.

use crate::btf_resolve::resolve_lifecycle_ids;
use crate::kcrypto_backend::object::lifecycle_object_bytes;
use crate::kcrypto_backend::{btf_unsupported, charge, configured_error_to_backend};
use crate::kcrypto_lifecycle::profile::{LIFECYCLE_MAPS, LifecycleProfile, manifest};
use crate::kcrypto_lifecycle::sensor::{
    DrainOutcome, LifecycleLedger, LifecycleSensor, QuietOutcome,
};
use crate::kcrypto_lifecycle::view::prog_miss_delta_sum;
use crate::probe::{ProbeOutcome, fsession_capable};
use kryprobe_abi::{ABI_VERSION, BACKEND_KCRYPTO, EVENT_OBSERVATION, RawEventHeader};
use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendPlan, BackendRegistry, BackendSummary, ConfigureContext,
    DecodeContext, DetectContext, DetectedInstance, DuplicateBackend, FinalizeContext, PlanContext,
    RawEvent,
};
use kryprobe_core::budget::BudgetKind;
use kryprobe_core::enums::{BackendId, CallKind, CaptureMode, EvidencePhase, OperationClass};
use kryprobe_core::error::{
    BackendError, BudgetReason, InputReason, InternalError, UnsupportedReason,
};
use kryprobe_core::evidence::payload_keys as K;
use kryprobe_core::evidence::{IntegrityRef, IntegritySummary, NativeObservation, NativeResult};
use kryprobe_core::ids::{ObservationId, PlanGeneration};
use kryprobe_core::kcrypto::{RequestRecord, Terminal};
use kryprobe_core::plan::{CapabilityRequirements, OffsetProbe};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Lifecycle capabilities: kernel BTF (attach ids + prototype gate)
/// and the ring-buffer transport are required; uprobes/cookies are
/// not consulted.
pub static LIFECYCLE_CAPABILITIES: BackendCapabilities = BackendCapabilities {
    backend: BackendId::KCrypto,
    name: "kcrypto-lifecycle",
    required: CapabilityRequirements {
        uprobe_multi: false,
        cookies: false,
        ringbuf: true,
        btf: true,
    },
};

/// Staged bring-up inputs (H1(b) twin of the aggregate staging): the
/// live session stages the already-read object bytes + token so
/// `configure` skips the locator re-read.
struct StagedLifecycle {
    object: Option<Vec<u8>>,
    token: Option<File>,
}

/// The lifecycle backend: one sensor owner behind the frozen trait.
/// Ticks lock the sensor in place (no handle duplication — the sensor
/// is `!Clone` by design and the backend mutex is the single owner).
pub struct LifecycleBackend {
    state: Mutex<Option<(PlanGeneration, LifecycleSensor)>>,
    staged: Mutex<StagedLifecycle>,
    decoded: AtomicUsize,
    /// Driver-side observation-cap omissions (reported via
    /// [`Self::note_output_omissions`] before `finalize`, surfaced
    /// as `budget_omissions` — the driver drops decoded records the
    /// sensor counted, so the backend must attest them).
    output_omissions: AtomicU64,
}

impl std::fmt::Debug for LifecycleBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleBackend")
            .field("decoded", &self.decoded.load(Ordering::Relaxed))
            .field(
                "output_omissions",
                &self.output_omissions.load(Ordering::Relaxed),
            )
            .field(
                "configured",
                &self.state.try_lock().map(|s| s.is_some()).unwrap_or(false),
            )
            .finish()
    }
}

impl LifecycleBackend {
    /// Unconfigured backend: no sensor, zero decoded, nothing staged.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
            staged: Mutex::new(StagedLifecycle {
                object: None,
                token: None,
            }),
            decoded: AtomicUsize::new(0),
            output_omissions: AtomicU64::new(0),
        }
    }

    /// Stages the already-read object bytes + optional token (the live
    /// session calls this before `configure`; never redefines it).
    pub fn stage_session_inputs(&self, object: Vec<u8>, token: Option<File>) {
        let mut staged = self
            .staged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        staged.object = Some(object);
        staged.token = token;
    }

    /// Drains staged inputs (empty unless staged since the last drain).
    fn take_staged_inputs(&self) -> StagedLifecycle {
        let mut staged = self
            .staged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        StagedLifecycle {
            object: staged.object.take(),
            token: staged.token.take(),
        }
    }

    /// Runs `f` against the stashed sensor (the live tick path locks
    /// the single owner in place — no handle duplication). Ticks
    /// before a successful `configure` are a driver defect
    /// (`Internal`, the `session_sensor` precedent).
    fn with_sensor<T>(&self, f: impl FnOnce(&mut LifecycleSensor) -> T) -> Result<T, BackendError> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some((_, sensor)) = guard.as_mut() else {
            return Err(BackendError::Internal(InternalError::new(
                "lifecycle_sensor_unconfigured",
            )));
        };
        Ok(f(sensor))
    }

    /// Live attach count for the session coverage (the sensor's own
    /// link count — measured, never the manifest constant).
    pub fn attached_points(&self) -> Result<usize, BackendError> {
        self.with_sensor(|sensor| sensor.attached_points())
    }

    /// M2 read-after-ingest: re-verify sensor identity against the
    /// pre-arm baseline (full while attached, detached-shape after;
    /// see the sensor method). A mismatch voids the sticky verdict
    /// and surfaces the cause here — teardown proceeds regardless.
    pub fn verify_identity(&self) -> Result<(), BackendError> {
        let verified = self.with_sensor(|sensor| sensor.verify_identity())?;
        verified.map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "lifecycle_verify",
                &err.to_string(),
            ))
        })
    }

    /// Disarm-then-detach, step 1 (M1): the sensor proves the
    /// disarmed config before dropping links; a disarm failure still
    /// detaches but surfaces typed here.
    pub fn close_input(&self) -> Result<(), BackendError> {
        let disarm = self.with_sensor(|sensor| sensor.close_input())?;
        disarm.map_err(configured_error_to_backend)
    }

    /// Detach-then-drain, step 2: bounded quiet loop; records the
    /// exact close backlog into the core for the ledger.
    pub fn drain_quiet(&self) -> Result<QuietOutcome, BackendError> {
        let quiet = self.with_sensor(|sensor| sensor.drain_quiet())?;
        quiet.map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "lifecycle_drain",
                &err.to_string(),
            ))
        })
    }

    /// One live tick: drain up to `max_records` ring records into the
    /// terminal ledger.
    pub fn drain_tick(&self, max_records: usize) -> Result<DrainOutcome, BackendError> {
        let drained = self.with_sensor(|sensor| sensor.drain_once(max_records))?;
        drained.map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "lifecycle_drain",
                &err.to_string(),
            ))
        })
    }

    /// Wait for the single owned sensor's input, or yield for a pending
    /// writer after a drain made no progress. Never waits past `max_wait`.
    pub fn wait_for_activity(
        &self,
        max_wait: std::time::Duration,
        pending_writer: bool,
    ) -> Result<(), BackendError> {
        self.with_sensor(|sensor| sensor.wait_for_activity(max_wait, pending_writer))?
            .map_err(|err| {
                BackendError::Internal(InternalError::with_detail(
                    "lifecycle_wait",
                    &err.to_string(),
                ))
            })
    }

    /// Drain retained completions (decoded to observations by the tick).
    pub fn take_completed(&self) -> Result<Vec<RequestRecord>, BackendError> {
        self.with_sensor(|sensor| sensor.take_completed())
    }

    /// Stop-time reconciliation: drain pending truthless into
    /// retention. Returns nothing — read via [`Self::take_completed`]
    /// (one read path; a returning finish double-surfaced records).
    pub fn finish_stop(&self, stop_ns: u64) -> Result<(), BackendError> {
        self.with_sensor(|sensor| sensor.finish(stop_ns))
    }

    /// Snapshot the terminal ledger (finalize + coverage read this).
    pub fn lifecycle_ledger(&self) -> Result<LifecycleLedger, BackendError> {
        let ledger = self.with_sensor(|sensor| sensor.ledger())?;
        ledger.map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "lifecycle_finalize_read",
                &err.to_string(),
            ))
        })
    }
}

impl Default for LifecycleBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared registration handle (H1(b) twin): the registry owns one
/// clone for the frozen-trait lifecycle while the live session holds
/// this one for ticks — both name the SAME backend state.
#[derive(Debug, Clone)]
pub struct SharedLifecycleBackend {
    inner: std::sync::Arc<LifecycleBackend>,
}

impl SharedLifecycleBackend {
    /// Wraps a fresh unconfigured backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(LifecycleBackend::new()),
        }
    }
}

impl Default for SharedLifecycleBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for SharedLifecycleBackend {
    type Target = LifecycleBackend;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Backend for SharedLifecycleBackend {
    fn id(&self) -> BackendId {
        self.inner.id()
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        self.inner.capabilities()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        self.inner.detect(ctx)
    }

    fn plan(
        &self,
        ctx: &PlanContext<'_>,
        instance: &DetectedInstance,
        mode: CaptureMode,
    ) -> Result<BackendPlan, BackendError> {
        self.inner.plan(ctx, instance, mode)
    }

    fn configure(
        &self,
        ctx: &mut ConfigureContext<'_>,
        plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        self.inner.configure(ctx, plan)
    }

    fn decode(
        &self,
        ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        self.inner.decode(ctx, event)
    }

    fn finalize(&self, ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        self.inner.finalize(ctx)
    }

    fn note_output_omissions(&self, omitted: u64) {
        self.inner.note_output_omissions(omitted);
    }
}

/// Single registration helper without a live-held handle: the minimal
/// seam for decode/finalize tests that never bring up a sensor.
/// Production always uses [`register_lifecycle_shared`] (the live
/// session needs the handle to drive drains + finalize). Held gate:
/// no production caller by design — the shared variant is the
/// production entry, and this one keeps test registries minimal.
pub fn register_lifecycle(registry: &mut BackendRegistry) -> Result<(), DuplicateBackend> {
    registry.register(Box::new(LifecycleBackend::new()))
}

/// Shared registration (H1(b)): registers the backend AND returns a
/// live-held clone onto the same state. The CLI live session imports
/// this; never redefines it.
pub fn register_lifecycle_shared(
    registry: &mut BackendRegistry,
) -> Result<SharedLifecycleBackend, DuplicateBackend> {
    let shared = SharedLifecycleBackend::new();
    registry.register(Box::new(shared.clone()))?;
    Ok(shared)
}

/// Strict decode envelope: one completed request lifecycle as JSON
/// (manual `Value` walk — privilege takes no serde derive; the key
/// set is closed: unknown fields refuse, never skimmed).
struct LifecycleEnvelope {
    request_id: u64,
    terminal: ValidTerminal,
    duration_ns: Option<String>,
    tfm_id: Option<u64>,
}

/// Validated terminal kind plus the exact status.
#[derive(Clone, Copy)]
enum ValidTerminal {
    Sync(i32),
    Callback(i32),
    Unknown,
}

/// Parse + validate one envelope (fail-closed [`BackendError::CorruptInput`]
/// with the exact refusal; never a partial decode).
fn parse_lifecycle_envelope(payload: &[u8]) -> Result<LifecycleEnvelope, BackendError> {
    let input = |detail: String| {
        BackendError::CorruptInput(InputReason::with_detail("lifecycle_envelope", &detail))
    };
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|err| input(format!("not an envelope: {err}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| input("envelope is not an object".to_owned()))?;
    for key in obj.keys() {
        match key.as_str() {
            "request_id" | "terminal" | "status" | "duration_ns" | "tfm_id" => {}
            // Input-free (T05 `UnknownKey` precedent): the name is
            // untrusted input and could smuggle key material.
            _ => return Err(input("unknown envelope key present".to_owned())),
        }
    }
    let get = |key: &str| {
        obj.get(key)
            .ok_or_else(|| input(format!("missing envelope key: {key:?}")))
    };
    let request_id = get("request_id")?
        .as_u64()
        .ok_or_else(|| input("request_id is not a u64".to_owned()))?;
    let terminal_name = get("terminal")?
        .as_str()
        .ok_or_else(|| input("terminal is not a string".to_owned()))?;
    let status = match get("status")? {
        serde_json::Value::Null => None,
        v => Some(
            v.as_i64()
                .and_then(|n| i32::try_from(n).ok())
                .ok_or_else(|| input("status is not an i32".to_owned()))?,
        ),
    };
    let terminal = match (terminal_name, status) {
        ("sync", Some(status)) => ValidTerminal::Sync(status),
        ("callback", Some(status)) => ValidTerminal::Callback(status),
        ("unknown", None) => ValidTerminal::Unknown,
        _ => {
            // Input-free: the offered terminal word is untrusted
            // input — name the rule, never the value.
            return Err(input(
                "terminal/status mismatch: want sync|callback with i32 status, or unknown with null"
                    .to_owned(),
            ));
        }
    };
    let duration_ns = match get("duration_ns")? {
        serde_json::Value::Null => None,
        serde_json::Value::String(duration) => {
            let canonical = duration == "0"
                || (!duration.is_empty()
                    && !duration.starts_with('0')
                    && duration.bytes().all(|b| b.is_ascii_digit()));
            if !canonical || duration.parse::<u64>().is_err() {
                // Input-free: the offered string is untrusted input.
                return Err(input("duration_ns not a canonical u64 string".to_owned()));
            }
            Some(duration.clone())
        }
        _ => return Err(input("duration_ns is not a string|null".to_owned())),
    };
    let tfm_id = match get("tfm_id")? {
        serde_json::Value::Null => None,
        v => Some(
            v.as_u64()
                .ok_or_else(|| input("tfm_id is not a u64|null".to_owned()))?,
        ),
    };
    // T05 parity: an unobserved terminal carries neither status (ruled
    // out above) nor duration (a span without endpoints is fabricated
    // timing).
    if matches!(terminal, ValidTerminal::Unknown) && duration_ns.is_some() {
        return Err(input(
            "terminal 'unknown' must not carry a duration".to_owned(),
        ));
    }
    Ok(LifecycleEnvelope {
        request_id,
        terminal,
        duration_ns,
        tfm_id,
    })
}

/// One completed record → observation (pure over the validated
/// envelope + minted id). Grounded terminals (`Sync`/`Callback`)
/// complete with their exact status; `Unknown` enters (never
/// completes) with [`NativeResult::KCryptoUnknown`] — no status
/// exists, and a zero placeholder would fabricate success beside the
/// payload's explicit `"status": null`. Started/ended stay `None`:
/// T05 records carry spans, not absolute timestamps, and the backend
/// never fabricates per-request timing.
fn observation_for_lifecycle(env: &LifecycleEnvelope, id: ObservationId) -> NativeObservation {
    let terminal = &env.terminal;
    let (phase, call_kind, native_result, coverage) = match terminal {
        ValidTerminal::Sync(status) | ValidTerminal::Callback(status) => (
            EvidencePhase::Completed,
            CallKind::Operation,
            NativeResult::KCrypto { status: *status },
            K::COVERAGE_OBSERVED,
        ),
        ValidTerminal::Unknown => (
            EvidencePhase::Entered,
            CallKind::Unknown,
            NativeResult::KCryptoUnknown,
            K::COVERAGE_UNOBSERVED,
        ),
    };
    let terminal_name = match terminal {
        ValidTerminal::Sync(_) => "sync",
        ValidTerminal::Callback(_) => "callback",
        ValidTerminal::Unknown => "unknown",
    };
    let status_json = match terminal {
        ValidTerminal::Sync(status) | ValidTerminal::Callback(status) => {
            serde_json::json!(*status)
        }
        ValidTerminal::Unknown => serde_json::Value::Null,
    };
    let payload = serde_json::json!({
        K::ROW: "lifecycle",
        K::CAPTURE_PROFILE: K::CAPTURE_REQUEST_LIFECYCLE,
        K::ID: format!("lc:{}", env.request_id),
        K::TFM_ID: env.tfm_id,
        K::TERMINAL: terminal_name,
        K::STATUS: status_json,
        K::DURATION_NS: env.duration_ns,
        K::EVIDENCE: !matches!(terminal, ValidTerminal::Unknown),
        K::COUNT_UNIT: K::COUNT_REQUEST_LIFECYCLE,
        K::COMPLETION_COVERAGE: coverage,
    });
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase,
        call_kind,
        // The record carries no op (T06 validates sites but pairs
        // keys, never guesses encrypt-vs-decrypt): Unknown, never
        // guessed (the class_for_op precedent).
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result,
        started_ns: None,
        ended_ns: None,
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: payload,
    }
}

/// Build the [`RawEvent`] inputs for one completed record (the live
/// driver calls this; decode consumes the same bytes — no second
/// encoding). Envelope JSON is canonical by construction
/// (`u64::to_string`); the header reuses the kcrypto wire id +
/// observation kind with zero flags and zero attribution (system-wide
/// sensor: zeros are documented-unknown per C10, never fabricated).
#[must_use]
pub fn lifecycle_event(record: &RequestRecord) -> (RawEventHeader, Vec<u8>) {
    let (terminal, status) = match record.terminal {
        Terminal::Sync(status) => ("sync", Some(status)),
        Terminal::Callback(status) => ("callback", Some(status)),
        Terminal::Unknown => ("unknown", None),
    };
    let payload = serde_json::json!({
        "request_id": record.id,
        "terminal": terminal,
        "status": status,
        "duration_ns": record.duration_ns.map(|ns| ns.to_string()),
        "tfm_id": record.tfm_id,
    });
    let payload = serde_json::to_vec(&payload).unwrap_or_default();
    let header = RawEventHeader {
        abi_version: ABI_VERSION,
        backend_id: BACKEND_KCRYPTO,
        event_kind: EVENT_OBSERVATION,
        flags: 0,
        total_len: (size_of::<RawEventHeader>() + payload.len()) as u32,
        cpu: 0,
        session_cookie: 0,
        monotonic_ns: 0,
        tgid: 0,
        tid: 0,
        process_generation: 0,
        plan_generation: 0,
        reserved: 0,
    };
    (header, payload)
}

/// Final-ledger → integrity (every loss counter lands somewhere —
/// nothing silent; zeros are documented-absent paths, never gaps):
/// kernel reserve failures → ring; disabled/badkey/noslot (evidence
/// the kernel refused to record) → state inserts; fret (return
/// observed, value unreadable) → unmatched returns; retention drops
/// past the ledger bound → user queue; refused/bad/duplicate/
/// ambiguous evidence → state inserts; per-program recursion-miss
/// deltas (H2 — the kernel skipped whole runs, the ultimate
/// refused-to-record) → state inserts; unfinished-at-finish →
/// unmatched entries; unknown invocations + reducer orphans →
/// unmatched returns; reuse gaps + stale returns → correlation
/// overflows. A void identity verdict (M2 — the sensor's kernel
/// objects stopped matching the pre-arm baseline, so the session's
/// evidence is unattributed) lands one count in state inserts.
/// Transform-lifetime loss (T07-05/R3) joins the same buckets:
/// refused/unadmitted/twisted transform evidence (resubmits,
/// taint, D4 table/live refusals, twin drift, unreadable links)
/// → state inserts; dangling-at-close attempts → unmatched
/// entries; returns for no outstanding attempt → unmatched
/// returns; predated/mismatched joins → correlation overflows;
/// uncertain-identity events (ambiguous/forced/stale/colliding
/// releases, unlinked configs, unobserved-boundary attributions,
/// evicted tombstone history) → unknown generations. Unbound
/// destroys at UNOCCUPIED bases (`unknown_releases`) stay UNMAPPED
/// (T07-R2-05, narrowed T07-R3-02: expected digest/shash releases
/// share the counter with destroy-only missed identities that
/// never touched in-boundary state — inventory, never a loss
/// vote; a missed identity that is used/configured votes via its
/// admission or config counter instead, and an unbound destroy
/// colliding with a live occupant votes via
/// `colliding_releases`). Normal transform accounting
/// (admissions, completions, classified failures, proved retires,
/// joined configs incl. errno verdicts) is truth, not loss —
/// unmapped by design. Callback-adapter loss (P4-N1, contract
/// §10) joins the same buckets: refused cover → state inserts;
/// orphan callbacks → unmatched returns; ambiguity gaps + stale
/// callbacks → correlation overflows; tombstone FIFO evictions →
/// state evictions (the field's first input — transform HASH
/// slots still never evict, single generation driver).
/// `output_omissions` (driver-reported observation-cap drops) lands
/// in `budget_omissions`.
fn integrity_for_lifecycle(ledger: &LifecycleLedger, output_omissions: u64) -> IntegritySummary {
    let tfm = &ledger.tfm_stats;
    let adapter = &ledger.adapter;
    IntegritySummary {
        ring_reservation_failures: ledger.kernel_loss[0],
        user_queue_drops: ledger.retained_dropped,
        state_insert_failures: ledger
            .decode
            .submit_refused
            .saturating_add(ledger.decode.bad_records)
            .saturating_add(ledger.reducer.admission_failed)
            .saturating_add(ledger.reducer.duplicate)
            .saturating_add(ledger.reducer.ambiguous)
            .saturating_add(ledger.kernel_loss[1])
            .saturating_add(ledger.kernel_loss[2])
            .saturating_add(ledger.kernel_loss[4])
            .saturating_add(prog_miss_delta_sum(&ledger.prog_misses))
            .saturating_add(u64::from(!ledger.view_valid))
            .saturating_add(tfm.submit_refused)
            .saturating_add(tfm.tainted_refused)
            .saturating_add(tfm.table_full)
            .saturating_add(tfm.live_full)
            .saturating_add(tfm.bad_records)
            .saturating_add(tfm.unlinked_ops)
            // P4-N1 (adapter contract §10): refused cover is
            // evidence that failed to enter join state.
            .saturating_add(adapter.cover_refused),
        // P4-N1 (adapter contract §10): bounded-table eviction
        // finally has an input — adapter tombstone FIFO
        // evictions (transform HASH slots still never evict).
        state_evictions: adapter.tombstone_evictions,
        unmatched_entries: ledger.reducer.unfinished.saturating_add(tfm.unfinished),
        unmatched_returns: ledger
            .decode
            .unknown_invoc_returns
            .saturating_add(ledger.reducer.orphan)
            .saturating_add(ledger.kernel_loss[3])
            .saturating_add(tfm.unknown_returns)
            // P4-N1 (adapter contract §10): a completion observed
            // but joinable to nothing.
            .saturating_add(adapter.callback_orphans),
        correlation_overflows: ledger
            .decode
            .gaps_synthesized
            .saturating_add(ledger.decode.stale_returns)
            .saturating_add(tfm.stale_returns)
            .saturating_add(tfm.mismatched_returns)
            // P4-N1 (adapter contract §10): ambiguity gaps and
            // stale callbacks are correlation overflows.
            .saturating_add(adapter.ambiguous_keys)
            .saturating_add(adapter.stale_callbacks),
        unknown_generation_events: tfm
            .ambiguous_releases
            .saturating_add(tfm.forced_retires)
            .saturating_add(tfm.stale_releases)
            .saturating_add(tfm.config_unlinked)
            .saturating_add(tfm.unobserved_boundary)
            .saturating_add(tfm.colliding_releases)
            .saturating_add(tfm.tombstone_evictions),
        budget_omissions: output_omissions,
    }
}

impl Backend for LifecycleBackend {
    fn id(&self) -> BackendId {
        BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        &LIFECYCLE_CAPABILITIES
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        resolve_lifecycle_ids().map_err(|err| btf_unsupported(&err))?;
        // M2 detector gate (W8 floor 7.0+): a kernel that FAILED the
        // fsession capability probe refuses detection here (typed
        // `Unsupported` — no detect-then-fail-configure). `Denied`
        // (unprivileged load check) still detects: privilege arrives
        // at configure, and the loader re-refuses anything the probe
        // could not prove. (A missing attach target never reaches
        // this probe — `resolve_lifecycle_ids` above already refused.)
        if let ProbeOutcome::Failed { detail } = fsession_capable() {
            return Err(BackendError::Unsupported(UnsupportedReason::with_detail(
                "kcrypto_fsession_unavailable",
                &detail,
            )));
        }
        Ok(vec![DetectedInstance {
            backend: BackendId::KCrypto,
            object: None,
            detail: "system lifecycle sensor (3 fsession sites)".to_owned(),
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
            // One probe per required HOOK (entry + return edge) in
            // manifest order — 2 per required site, derived from
            // the manifest so new sites cannot strand the plan
            // (T07.4: 7 sites = 14 probes); offsets/cookies are
            // advisory (the attach runtime owns them) exactly like
            // the aggregate plan.
            probes: (0..manifest(LifecycleProfile::RequestLifecycle).required.len() * 2)
                .map(|ordinal| OffsetProbe {
                    file_offset: 0,
                    cookie: 0,
                    descriptor_id: ordinal as u32,
                })
                .collect(),
            required: LIFECYCLE_CAPABILITIES.required,
        })
    }

    fn configure(
        &self,
        ctx: &mut ConfigureContext<'_>,
        _plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        // Idempotent by generation (the aggregate idiom): same
        // generation re-calls are no-ops (no reload, no re-charge).
        {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some((generation, _)) = state.as_ref()
                && *generation == ctx.generation
            {
                return Ok(());
            }
        }
        // Staged inputs win (the live session stages the already-read
        // object bytes + token); else the direct path locates the
        // lifecycle object with no token. `staged` stays alive across
        // the load so the borrowed token fd cannot close mid-bring-up.
        let staged = self.take_staged_inputs();
        let object_bytes = match staged.object {
            Some(bytes) => bytes,
            None => lifecycle_object_bytes()?,
        };
        let token_fd = staged.token.as_ref().map(File::as_raw_fd);
        // May fail typed (incl. cross-profile SessionBusy from the
        // process guard inside bring_up — mapped like every other
        // ConfiguredError; bring_up is all-or-nothing so a failure
        // stashes nothing).
        let (sensor, points) = LifecycleSensor::bring_up(&object_bytes, token_fd)
            .map_err(configured_error_to_backend)?;
        // L6 loser (the aggregate idiom): a racing configure for this
        // generation already stashed — drop ours (sensor + guard),
        // report success, never double-charge.
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if let Some((generation, _)) = state.as_ref()
                && *generation == ctx.generation
            {
                return Ok(());
            }
            charge(ctx, BudgetKind::Links, points.len() as u64)?;
            charge(ctx, BudgetKind::StateEntries, LIFECYCLE_MAPS.len() as u64)?;
            *state = Some((ctx.generation, sensor));
        }
        Ok(())
    }

    fn decode(
        &self,
        ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        // Strict envelope (fail-closed Input); the JSON shape
        // discriminates by construction (a foreign binary event is not
        // an envelope), so no header check is needed (the aggregate
        // precedent checks payload only).
        let env = parse_lifecycle_envelope(event.payload)?;
        // Identity comes from the session issuer (unique across backends);
        // exhaustion refuses typed, never mints a duplicate.
        let id = ctx.id_issuer.issue().map_err(|exhausted| {
            BackendError::Exhausted(BudgetReason::with_detail(
                "observation_ids",
                &exhausted.to_string(),
            ))
        })?;
        let observation = observation_for_lifecycle(&env, id);
        // L5: pure counter — `Relaxed` suffices (no data rides it).
        self.decoded.fetch_add(1, Ordering::Relaxed);
        Ok(observation)
    }

    fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        let observations = self.decoded.load(Ordering::Relaxed) as u64;
        let guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some((_, sensor)) = guard.as_ref() else {
            // Pre-configure: no sensor to assess — counts echo,
            // sensor-side integrity pins zero (documented; never echo
            // the ctx baseline). Driver-reported cap omissions still
            // attest: the live driver reports before finalize even when
            // the sensor lives outside this backend (scripted/canary
            // sessions), and a reported drop must never read back as
            // zero. With no report this is exactly `default()`.
            let integrity = IntegritySummary {
                budget_omissions: self.output_omissions.load(Ordering::Relaxed),
                ..IntegritySummary::default()
            };
            return Ok(BackendSummary {
                backend: BackendId::KCrypto,
                observations,
                integrity,
            });
        };
        // End-of-session assessment over the live ledger (the sensor is
        // right here — no snapshot walk, no closing-count staging).
        let ledger = sensor.ledger().map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "lifecycle_finalize_read",
                &err.to_string(),
            ))
        })?;
        Ok(BackendSummary {
            backend: BackendId::KCrypto,
            observations,
            integrity: integrity_for_lifecycle(
                &ledger,
                self.output_omissions.load(Ordering::Relaxed),
            ),
        })
    }

    fn note_output_omissions(&self, omitted: u64) {
        self.output_omissions
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(omitted))
            })
            .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcrypto_lifecycle::decode::DecodeStats;
    use crate::kcrypto_lifecycle::sensor::EnrichmentStatus;
    use kryprobe_core::kcrypto::ReducerStats;

    fn ledger_with(kernel_loss: [u64; 5]) -> LifecycleLedger {
        LifecycleLedger {
            completed: Vec::new(),
            edge_hits: [0; 22],
            decode: DecodeStats::default(),
            adapter: crate::kcrypto_lifecycle::async_adapter::AdapterStats::default(),
            reducer: ReducerStats::default(),
            kernel_loss,
            agg_accepted: [0; 22],
            retained_dropped: 0,
            view_valid: true,
            loss_baseline: [0; 5],
            agg_baseline: [0; 22],
            prog_misses: Vec::new(),
            miss_current: Vec::new(),
            tfm_stats: crate::kcrypto_lifecycle::tfm::TfmStats::default(),
            generations: Vec::new(),
            enrichment: EnrichmentStatus::Available {
                entries: 0,
                truncated: false,
            },
        }
    }

    #[test]
    fn w2_every_kernel_loss_class_lands_somewhere() {
        // Round-2 (sol-M5/astra-M6): each LLOSS class maps to exactly
        // one integrity field — reserve→ring, disabled/badkey/noslot→
        // state inserts (evidence that failed to enter backend
        // state), fret→unmatched returns (return observed, value
        // unreadable). Nothing silent, nothing double-counted.
        let integrity = integrity_for_lifecycle(&ledger_with([7, 1, 2, 3, 4]), 0);
        assert_eq!(integrity.ring_reservation_failures, 7);
        assert_eq!(integrity.state_insert_failures, 1 + 2 + 4);
        assert_eq!(integrity.unmatched_returns, 3);
        assert_eq!(integrity.user_queue_drops, 0);
        assert_eq!(integrity.unmatched_entries, 0);
        assert_eq!(integrity.correlation_overflows, 0);
        assert_eq!(integrity.state_evictions, 0);
        assert_eq!(integrity.unknown_generation_events, 0);
        assert_eq!(integrity.budget_omissions, 0);
    }

    #[test]
    fn p4r2_adapter_losses_map_into_frozen_integrity() {
        // P4-N1 (contract §10): every adapter counter lands in the
        // frozen summary — cover refusals are evidence that failed
        // to enter join state, orphans are completions joinable to
        // nothing, ambiguity + stale are correlation overflows,
        // tombstone evictions are state evictions. Nothing silent.
        use crate::kcrypto_lifecycle::async_adapter::AdapterStats;
        let mut ledger = ledger_with([0; 5]);
        ledger.adapter = AdapterStats {
            cover_refused: 2,
            callback_orphans: 3,
            ambiguous_keys: 5,
            tombstone_evictions: 7,
            stale_callbacks: 11,
        };
        let integrity = integrity_for_lifecycle(&ledger, 0);
        assert_eq!(integrity.state_insert_failures, 2);
        assert_eq!(integrity.unmatched_returns, 3);
        assert_eq!(integrity.correlation_overflows, 16);
        assert_eq!(integrity.state_evictions, 7);
    }

    #[test]
    fn w8_void_identity_lands_one_state_insert() {
        // H2: a void M2 identity verdict attests in the integrity
        // summary (unattributed evidence counts as failed-to-enter
        // backend state); a valid session adds nothing.
        let mut ledger = ledger_with([0; 5]);
        ledger.view_valid = false;
        assert_eq!(integrity_for_lifecycle(&ledger, 0).state_insert_failures, 1);
        let ledger = ledger_with([0; 5]);
        assert_eq!(integrity_for_lifecycle(&ledger, 0).state_insert_failures, 0);
    }

    #[test]
    fn w9_prog_miss_deltas_land_in_state_inserts() {
        // Round-9 (sol/astra-Major 1): per-program recursion-miss
        // session deltas attest in state inserts (the kernel skipped
        // whole runs — refused-to-record); zero deltas add nothing.
        use crate::kcrypto_lifecycle::view::ProgMissDelta;
        let mut ledger = ledger_with([0; 5]);
        ledger.prog_misses = vec![
            ProgMissDelta {
                section: "fsession/a".to_owned(),
                baseline: 3,
                current: 5,
            },
            ProgMissDelta {
                section: "fsession/b".to_owned(),
                baseline: 0,
                current: 0,
            },
        ];
        assert_eq!(integrity_for_lifecycle(&ledger, 0).state_insert_failures, 2);
        let ledger = ledger_with([0; 5]);
        assert_eq!(integrity_for_lifecycle(&ledger, 0).state_insert_failures, 0);
    }

    #[test]
    fn t0705_transform_loss_lands_in_integrity_buckets() {
        // T07-05/R3: transform-lifetime loss joins the integrity
        // summary — D4 refusals refuse silently no more, and every
        // uncertain-identity event lands in unknown generations.
        // Normal transform accounting (proved retires, joined
        // configs incl. errno verdicts) is truth — unmapped.
        // (T07-R2-05, narrowed T07-R3-02: UNOCCUPIED unbound
        // destroys are inventory — the input below carries 10 and
        // the bucket must EXCLUDE them — while the 15 colliding
        // ones (live occupant) MUST land in the bucket.)
        use crate::kcrypto_lifecycle::tfm::TfmStats;
        let mut ledger = ledger_with([0; 5]);
        ledger.tfm_stats = TfmStats {
            live_full: 3,
            table_full: 1,
            submit_refused: 2,
            bad_records: 1,
            unfinished: 4,
            unknown_returns: 5,
            stale_returns: 6,
            mismatched_returns: 7,
            ambiguous_releases: 8,
            forced_retires: 9,
            unknown_releases: 10,
            stale_releases: 11,
            config_unlinked: 12,
            unobserved_boundary: 13,
            tombstone_evictions: 14,
            colliding_releases: 15,
            retired: 100,
            configs_joined: 200,
            configs_failed: 300,
            ..TfmStats::default()
        };
        let integrity = integrity_for_lifecycle(&ledger, 0);
        assert_eq!(integrity.state_insert_failures, 3 + 1 + 2 + 1);
        assert_eq!(integrity.unmatched_entries, 4);
        assert_eq!(integrity.unmatched_returns, 5);
        assert_eq!(integrity.correlation_overflows, 6 + 7);
        assert_eq!(
            integrity.unknown_generation_events,
            8 + 9 + 11 + 12 + 13 + 14 + 15,
            "unoccupied unbound destroys excluded, colliding included"
        );
        // Truth-only transform traffic keeps every loss bucket at
        // zero (a busy-but-clean session reports clean).
        let mut ledger = ledger_with([0; 5]);
        ledger.tfm_stats = TfmStats {
            admitted: 50,
            completed: 50,
            releases: 10,
            retired: 10,
            configs_joined: 20,
            configs_failed: 2,
            failed_allocs: 1,
            noop_releases: 1,
            ..TfmStats::default()
        };
        let integrity = integrity_for_lifecycle(&ledger, 0);
        assert_eq!(integrity.state_insert_failures, 0);
        assert_eq!(integrity.unmatched_entries, 0);
        assert_eq!(integrity.unmatched_returns, 0);
        assert_eq!(integrity.correlation_overflows, 0);
        assert_eq!(integrity.unknown_generation_events, 0);
    }

    #[test]
    fn w3_output_omissions_land_in_budget_omissions() {
        // Round-3 (sol/astra-M3): driver-reported cap drops surface
        // as `budget_omissions` — counted, never silently omitted.
        let integrity = integrity_for_lifecycle(&ledger_with([0; 5]), 41);
        assert_eq!(integrity.budget_omissions, 41);
        let backend = LifecycleBackend::new();
        backend.note_output_omissions(40);
        backend.note_output_omissions(1);
        assert_eq!(
            backend.output_omissions.load(Ordering::Relaxed),
            41,
            "reports accumulate saturating"
        );
    }
}
