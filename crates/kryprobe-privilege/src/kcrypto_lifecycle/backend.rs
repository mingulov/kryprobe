// SPDX-License-Identifier: GPL-3.0-or-later
//! `request-lifecycle` registry backend (T06 F8c): the edge-pairing
//! sensor behind the frozen 7-method [`Backend`] trait.
//!
//! One [`BackendId::KCrypto`] slot serves both profiles — registering
//! the second is a typed [`DuplicateBackend`], never a second capture
//! (structural exclusion within a session; the process-wide
//! [`SessionGuard`] covers cross-session bring-up). The driver feeds
//! completed [`RequestRecord`]s through [`lifecycle_event`] +
//! [`Backend::decode`]; the JSON envelope is validated strictly
//! (fail-closed [`BackendError::CorruptInput`]), so a foreign event fed here
//! refuses instead of misdecoding.

use crate::btf_resolve::resolve_lifecycle_ids;
use crate::kcrypto_backend::object::lifecycle_object_bytes;
use crate::kcrypto_backend::{btf_unsupported, charge, configured_error_to_backend};
use crate::kcrypto_lifecycle::profile::LIFECYCLE_MAPS;
use crate::kcrypto_lifecycle::sensor::{
    DrainOutcome, LifecycleLedger, LifecycleSensor, QuietOutcome,
};
use kryprobe_abi::{ABI_VERSION, BACKEND_KCRYPTO, EVENT_OBSERVATION, RawEventHeader};
use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendPlan, BackendRegistry, BackendSummary, ConfigureContext,
    DecodeContext, DetectContext, DetectedInstance, DuplicateBackend, FinalizeContext, PlanContext,
    RawEvent,
};
use kryprobe_core::budget::BudgetKind;
use kryprobe_core::enums::{BackendId, CallKind, CaptureMode, EvidencePhase, OperationClass};
use kryprobe_core::error::{BackendError, BudgetReason, InputReason, InternalError};
use kryprobe_core::evidence::payload_keys as K;
use kryprobe_core::evidence::{IntegrityRef, IntegritySummary, NativeObservation, NativeResult};
use kryprobe_core::ids::{ObservationId, PlanGeneration};
use kryprobe_core::kcrypto::{RequestRecord, Terminal};
use kryprobe_core::plan::{CapabilityRequirements, OffsetProbe};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

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
}

impl std::fmt::Debug for LifecycleBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleBackend")
            .field("decoded", &self.decoded.load(Ordering::Relaxed))
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

    /// Detach-then-drain, step 1: drop the attach links (no hook
    /// fires after; the closing drain converges).
    pub fn close_input(&self) -> Result<(), BackendError> {
        self.with_sensor(|sensor| sensor.close_input())
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
/// ambiguous evidence → state inserts; unfinished-at-finish →
/// unmatched entries; unknown keys + reducer orphans → unmatched
/// returns; reuse gaps + stale returns → correlation overflows.
/// Evictions/unknown generations/budget omissions pin zero (HASH
/// slots never evict, single generation driver, decode never
/// budget-omits).
fn integrity_for_lifecycle(ledger: &LifecycleLedger) -> IntegritySummary {
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
            .saturating_add(ledger.kernel_loss[4]),
        state_evictions: 0,
        unmatched_entries: ledger.reducer.unfinished,
        unmatched_returns: ledger
            .decode
            .unknown_key_returns
            .saturating_add(ledger.reducer.orphan)
            .saturating_add(ledger.kernel_loss[3]),
        correlation_overflows: ledger
            .decode
            .gaps_synthesized
            .saturating_add(ledger.decode.stale_returns),
        unknown_generation_events: 0,
        budget_omissions: 0,
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
        Ok(vec![DetectedInstance {
            backend: BackendId::KCrypto,
            object: None,
            detail: "system lifecycle sensor (4 fentry/fexit points)".to_owned(),
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
            // One probe per required hook in manifest order
            // (enc-entry, enc-return, dec-entry, dec-return);
            // offsets/cookies are advisory (the attach runtime owns
            // them) exactly like the aggregate plan.
            probes: (0..4)
                .map(|ordinal| OffsetProbe {
                    file_offset: 0,
                    cookie: 0,
                    descriptor_id: ordinal,
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
            // Pre-configure: no sensor to assess — counts echo, integrity
            // pins zero (documented; never echo the ctx baseline).
            return Ok(BackendSummary {
                backend: BackendId::KCrypto,
                observations,
                integrity: IntegritySummary::default(),
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
            integrity: integrity_for_lifecycle(&ledger),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcrypto_lifecycle::decode::DecodeStats;
    use kryprobe_core::kcrypto::ReducerStats;

    fn ledger_with(kernel_loss: [u64; 5]) -> LifecycleLedger {
        LifecycleLedger {
            completed: Vec::new(),
            edge_hits: [0; 4],
            decode: DecodeStats::default(),
            reducer: ReducerStats::default(),
            kernel_loss,
            agg_accepted: [0; 4],
            retained_dropped: 0,
        }
    }

    #[test]
    fn w2_every_kernel_loss_class_lands_somewhere() {
        // Round-2 (sol-M5/astra-M6): each LLOSS class maps to exactly
        // one integrity field — reserve→ring, disabled/badkey/noslot→
        // state inserts (evidence that failed to enter backend
        // state), fret→unmatched returns (return observed, value
        // unreadable). Nothing silent, nothing double-counted.
        let integrity = integrity_for_lifecycle(&ledger_with([7, 1, 2, 3, 4]));
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
}
