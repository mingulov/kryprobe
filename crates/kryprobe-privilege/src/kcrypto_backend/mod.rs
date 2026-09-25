// SPDX-License-Identifier: GPL-3.0-or-later
//! KCryptoBackend: kernel-crypto through the FROZEN 7-method trait (K2 Task 2).
//!
//! The backend owns the system-wide fexit sensor from `configure` (idempotent
//! by [`PlanGeneration`]: first call loads + attaches via
//! [`load_kcrypto_configured`], same-generation re-calls are no-ops), and
//! decodes Task-1 snapshot rows ([`parse_snapshot_row`]) into
//! [`NativeObservation`]s per the D8 tables. `finalize` maps D10 integrity
//! (ring drops + the `KTOT - ΣKAGG` insert gap) from a fresh snapshot of the
//! live sensor; pre-configure it counts without integrity (zeros).
//!
//! Row-kind decode shapes (all pinned by `tests/kcrypto_driver.rs`):
//! agg rows map the full D8 tables (symbol/call/phase/status/context +
//! identity in `backend_payload`); totals rows decode to a `Completed`
//! aggregate carrier (the read verdict, not an op verdict — per-class
//! outcomes ride the payload counts, and in the PARTIAL path the gap is
//! receipted in integrity while totals stay exact); ident rows decode to
//! `Discovered` first-seen markers (head-derived call/class/symbol, no
//! verdict). Inventory-only (`KFAM_ANY`) rows force `Selected` +
//! `not_applicable` + `execution: "unsupported"`, never crash, never silent.
//!
//! Privacy (kp2 S9): names/family/op/counts/results/timestamps/context-class
//! only; rows carry no keys/IV/plain/cipher/digests/buffers/pointers, and
//! neither do these observations. C10: `target`/`object`/`implementation`
//! stay `None`, never fabricated.
//!
//! No new privileged syscall sites: loading reuses
//! [`load_kcrypto_configured`], finalize reuses [`snapshot_rows`] +
//! [`crate::mapops::map_lookup_bytes`], decode is pure.
//!
//! K5 Task 3 adds the snapshot side of attribution: [`snapshot_who`]
//! walks `KWHO`/`KSTACK`/`KERR`/`KPARAMS` (map access reuses
//! [`crate::mapops`], like [`snapshot_rows`]) into [`WhoSnapshot`]s.
//! K5 Task 4 decodes those into `row="who"` observations
//! ([`observation_for_who`], pure over the snapshot + parsed table),
//! adds `key_hash`/`lat` to agg payloads, and merges `who_drops` into
//! finalize integrity.

pub(crate) mod integrity;
pub(crate) mod object;
pub(crate) mod observe;
pub(crate) mod snapshot_drops;
pub(crate) mod snapshot_who;

// 1A-M10: the pre-split `pub` surface, re-exported so
// `kcrypto_backend::X` paths keep resolving.
pub(crate) use integrity::{integrity_for_counts, integrity_for_snapshot};
pub(crate) use object::kcrypto_object_bytes;
pub use object::{
    LocateMiss, ObjectLocateError, kcrypto_object_candidates, lifecycle_object_candidates,
    locate_kcrypto_object_bytes, locate_kcrypto_object_identity, locate_lifecycle_object_bytes,
    pins_enforced, sha256_hex,
};
pub use observe::observation_for_who;
pub use snapshot_drops::{
    KDROP_DESTROY, KDROP_SITES, SnapshotError, fold_drop_lanes, snapshot_drops,
};
pub(crate) use snapshot_who::read_kwho_drops;
pub use snapshot_who::{WhoCache, WhoJoins, WhoSnapshot, snapshot_who, snapshot_who_cached};
// 1A-M10: unit-test-only helpers (the tests mod stayed whole in
// this file; production reaches them through the phases above).
#[cfg(test)]
pub(crate) use object::{PINNED_DIGESTS, pin_skip_warning, verify_object_pinned};
#[cfg(test)]
pub(crate) use observe::{name_from_words, symbol_for, unpack_head};
pub(crate) use observe::{observation_for_agg, observation_for_ident, observation_for_totals};
#[cfg(test)]
pub(crate) use snapshot_who::{fold_vwho, stack_ips_from_bytes};

use std::fs::File;
use std::os::fd::AsRawFd;
// 1A-M10: the unit tests stayed in this file, so their imports live
// here behind cfg(test); production names moved to the phases.
use crate::bpfloader::PointStatus;
use crate::btf_resolve::{
    AttachOutcome, BtfError, ConfiguredError, ConfiguredKcrypto, ConfiguredPoint, KCRYPTO_SYMBOLS,
    load_kcrypto_configured, resolve_btf_ids,
};
use crate::kcrypto_lifecycle::profile::{LifecycleProfile, SessionGuard, acquire_kcrypto_session};
#[cfg(test)]
use crate::kcrypto_snapshot::SnapshotRows;
use crate::kcrypto_snapshot::{ParsedRow, parse_snapshot_row, snapshot_rows};
#[cfg(test)]
use crate::mapops::MapOpsError;
#[cfg(test)]
use kryprobe_abi::kcrypto_agg::{
    KCTX_PROC, KFAM_AEAD, KFAM_AHASH, KFAM_ANY, KFAM_SHASH, KFAM_SK, KOP_ALLOC, KOP_DEC,
    KOP_DESTROY, KOP_DIGEST, KOP_ENC, KOP_FINUP, KRES_OK, VParams, VWho,
};
use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendPlan, BackendRegistry, BackendSummary, ConfigureContext,
    DecodeContext, DetectContext, DetectedInstance, DuplicateBackend, FinalizeContext, PlanContext,
    RawEvent,
};
use kryprobe_core::budget::BudgetKind;
use kryprobe_core::enums::{BackendId, CaptureMode};
use kryprobe_core::error::{
    BackendError, BudgetReason, DeniedReason, InternalError, SafetyReason, UnsupportedReason,
};
use kryprobe_core::evidence::{IntegritySummary, NativeObservation};
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::plan::{CapabilityRequirements, OffsetProbe};
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
/// Static descriptor: the kcrypto backend gates on BTF only (D2 — ringbuf
/// is universal past the floor, `uprobe_multi`/`cookies` are N/A to fexit).
pub const KCRYPTO_CAPABILITIES: BackendCapabilities = BackendCapabilities {
    backend: BackendId::KCrypto,
    name: "kcrypto",
    required: CapabilityRequirements {
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf: true,
    },
};

/// kcrypto BPF maps held per configured sensor: `KAGG`, `KTOT`, `KIDN`,
/// `KRING`, `KCFG` (K1 five) + `KWHO`/`KSTACK`/`KERR`/`KPARAMS` (K5
/// attribution four) + `KDROPS` (fix-wave pre-`KTOT` site counters) —
/// the `StateEntries` charge on first configure (the message contract
/// is maps-count, so the charge tracks the loaded map count).
const KCRYPTO_MAP_COUNT: u64 = 10;

/// Kernel-crypto backend: a system-wide fexit sensor owned by `configure`
/// plus a decode counter. `Send + Sync` via the mutex + atomics (the sensor
/// is fd-backed, no interior aliasing).
pub struct KCryptoBackend {
    state: Mutex<Option<(PlanGeneration, ConfiguredKcrypto)>>,
    staged: Mutex<StagedBringup>,
    decoded: AtomicUsize,
    session: Mutex<Option<SessionGuard>>,
}

/// One-shot bringup inputs staged by the live session (H1(b)/M2): the
/// already-read object bytes (no third locator read) plus the held
/// token file (token-only delegation loads through it). Drained
/// exactly once by the `configure` that loads; empty unless staged.
#[derive(Default)]
struct StagedBringup {
    object: Option<Vec<u8>>,
    token: Option<File>,
    closing: Option<ClosingCounts>,
}

/// Closing-tick counts staged by the live driver (M5): the finalize
/// fast path computes integrity from these plus one fresh
/// `KWHO_DROPS` read — no snapshot walk, no who walk. Generation-
/// tagged so stale counts can never serve another session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosingCounts {
    /// Session generation the counts belong to.
    pub generation: PlanGeneration,
    /// ΣKAGG calls over the closing tick (saturating).
    pub agg_calls: u64,
    /// KTOT calls (`None` when the closing tick had no totals).
    pub totals_calls: Option<u64>,
    /// Retained `KIDN_DROPS` from the closing snapshot.
    pub drops: u8,
}

impl std::fmt::Debug for KCryptoBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // L5: `Relaxed` counter read; `try_lock` (never blocks — a
        // `Debug` that deadlocks while its own mutex is held would be
        // a debugging nightmare).
        f.debug_struct("KCryptoBackend")
            .field("decoded", &self.decoded.load(Ordering::Relaxed))
            .field(
                "configured",
                &self.state.try_lock().map(|s| s.is_some()).unwrap_or(false),
            )
            .field(
                "session_held",
                &self
                    .session
                    .try_lock()
                    .map(|s| s.is_some())
                    .unwrap_or(false),
            )
            .finish()
    }
}

impl KCryptoBackend {
    /// Unconfigured backend: no sensor, zero decoded, nothing staged.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
            staged: Mutex::new(StagedBringup::default()),
            decoded: AtomicUsize::new(0),
            session: Mutex::new(None),
        }
    }

    /// Stages one-shot bringup inputs for the next loading `configure`
    /// (H1(b)/M2): live passes its already-read object bytes plus the
    /// held token file, so `configure` neither re-reads the object
    /// (M2's third read) nor loads privilege-only (token-only
    /// delegation works: the single sensor loads through the token).
    /// Overwrites any previous staging; drained exactly once.
    pub fn stage_session_inputs(&self, object: Vec<u8>, token: Option<File>) {
        let mut staged = self
            .staged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        staged.object = Some(object);
        staged.token = token;
    }

    /// Drains staged inputs (empty unless staged since the last drain).
    /// Leaves `closing` in place: it belongs to a later lifecycle
    /// stage (staged after the tick loop, consumed by `finalize`).
    fn take_staged_inputs(&self) -> StagedBringup {
        let mut staged = self
            .staged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        StagedBringup {
            object: staged.object.take(),
            token: staged.token.take(),
            closing: staged.closing,
        }
    }

    /// Stages closing-tick counts for the finalize fast path (M5).
    /// Overwrites any previous staging.
    pub fn stage_closing_counts(&self, closing: ClosingCounts) {
        self.staged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .closing = Some(closing);
    }

    /// Takes staged closing counts iff they belong to `generation`.
    /// A foreign generation discards them (stale counts never serve
    /// another session); a hit drains once.
    fn take_closing_for(&self, generation: PlanGeneration) -> Option<ClosingCounts> {
        let mut staged = self
            .staged
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match staged.closing {
            Some(closing) if closing.generation == generation => {
                staged.closing = None;
                Some(closing)
            }
            _ => {
                staged.closing = None;
                None
            }
        }
    }

    /// Hands the live tick loop its own handle onto the configured
    /// sensor (H1(b)): dup'd fds onto the SAME kernel sensor — one
    /// attach, one probe stream, one set of maps shared by ticks and
    /// finalize. Typed error before `configure` (never a handle to
    /// nothing); fd exhaustion surfaces as `Exhausted`, never a
    /// half-dup'd sensor.
    pub fn session_sensor(&self) -> Result<ConfiguredKcrypto, BackendError> {
        let guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some((_, sensor)) = guard.as_ref() else {
            return Err(BackendError::Internal(InternalError::new(
                "kcrypto_sensor_unconfigured",
            )));
        };
        sensor.try_clone().map_err(|err| {
            BackendError::Exhausted(BudgetReason::with_detail(
                "kcrypto_sensor_clone",
                &err.to_string(),
            ))
        })
    }
}

/// Shared ownership for the live session (H1(b)): live holds one
/// clone for the sensor accessor while the registry owns another for
/// the frozen-trait lifecycle — both name the SAME backend state, so
/// ticks and finalize share one sensor with no trait change. A local
/// wrapper (not a bare `Arc`) because the orphan rule forbids
/// implementing the foreign [`Backend`] trait for `Arc` directly.
#[derive(Debug, Clone)]
pub struct SharedKcryptoBackend {
    inner: std::sync::Arc<KCryptoBackend>,
}

impl SharedKcryptoBackend {
    /// Wraps a fresh unconfigured backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(KCryptoBackend::new()),
        }
    }

    /// Borrows the shared concrete backend (staging + sensor handle).
    #[must_use]
    pub fn backend(&self) -> &KCryptoBackend {
        &self.inner
    }
}

impl Default for SharedKcryptoBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for SharedKcryptoBackend {
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

impl Default for KCryptoBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Single registration helper (the CLI imports this; never redefines it).
pub fn register_kcrypto(registry: &mut BackendRegistry) -> Result<(), DuplicateBackend> {
    registry.register(Box::new(KCryptoBackend::new()))
}

/// Shared registration (H1(b)): registers the backend AND returns a
/// live-held clone onto the same state, so ticks and finalize share
/// one sensor. The CLI live session imports this; never redefines it.
pub fn register_kcrypto_shared(
    registry: &mut BackendRegistry,
) -> Result<SharedKcryptoBackend, DuplicateBackend> {
    let shared = SharedKcryptoBackend::new();
    registry.register(Box::new(shared.clone()))?;
    Ok(shared)
}

/// The live-held handle for the registered profile (T06 F8c): exactly
/// one `BackendId::KCrypto` backend per registry — registering the
/// second profile is a typed [`DuplicateBackend`], never a second
/// capture (structural exclusion within a session).
#[derive(Debug, Clone)]
pub enum ProfileBackend {
    /// Aggregate sensor handle (`api-returns`).
    ApiReturns(SharedKcryptoBackend),
    /// Edge-pairing sensor handle (`request-lifecycle`).
    RequestLifecycle(crate::kcrypto_lifecycle::backend::SharedLifecycleBackend),
}

/// Profile registration (T06 F8c): the ONE registry entry point —
/// registry and live entry points both select through this, so they
/// can never diverge. The CLI live session imports this; never
/// redefines it.
pub fn register_kcrypto_profile(
    registry: &mut BackendRegistry,
    profile: LifecycleProfile,
) -> Result<ProfileBackend, DuplicateBackend> {
    match profile {
        LifecycleProfile::ApiReturns => {
            register_kcrypto_shared(registry).map(ProfileBackend::ApiReturns)
        }
        LifecycleProfile::RequestLifecycle => {
            crate::kcrypto_lifecycle::backend::register_lifecycle_shared(registry)
                .map(ProfileBackend::RequestLifecycle)
        }
    }
}

/// Charge one budget kind, mapping refusal to a typed exhaustion error
/// (the [`SyntheticBackend`](kryprobe_core::synthetic::SyntheticBackend) pattern).
/// Shared with the lifecycle backend (same charging semantics).
pub(crate) fn charge(
    ctx: &mut ConfigureContext<'_>,
    kind: BudgetKind,
    amount: u64,
) -> Result<(), BackendError> {
    ctx.budget.charge(kind, amount).map_err(|omission| {
        let name = match kind {
            BudgetKind::Links => "links",
            BudgetKind::StateEntries => "state_entries",
            _ => "budget",
        };
        BackendError::Exhausted(BudgetReason::with_detail(name, &omission.to_string()))
    })
}

/// BTF resolution failure: the whole backend is unavailable (D4 — honest;
/// BTF-complete kernels carry all 9 long-standing APIs). Shared by `detect`
/// and the `Resolve` arm of [`configured_error_to_backend`], and by the
/// lifecycle backend's `detect` (same unavailability semantics).
pub(crate) fn btf_unsupported(err: &BtfError) -> BackendError {
    BackendError::Unsupported(UnsupportedReason::with_detail(
        "kcrypto_btf_unresolvable",
        &err.to_string(),
    ))
}

/// One configured point as `name=load-word` for error detail.
fn point_word(point: &ConfiguredPoint) -> String {
    let load = match &point.load {
        PointStatus::Loaded { .. } => match &point.attach {
            Some(AttachOutcome::Attached) => "loaded+attached".to_owned(),
            Some(AttachOutcome::Failed { detail }) => format!("loaded+attach-failed:{detail}"),
            None => "loaded+unattached".to_owned(),
        },
        PointStatus::Missing { .. } => "missing".to_owned(),
        PointStatus::Unsupported { detail, .. } => format!("unsupported:{detail}"),
    };
    format!("{}={load}", point.name)
}

/// Per-point outcomes joined for the `NoPointAttached` detail (diagnosable,
/// never swallowed — the K1 guarantee rides into the error).
fn points_summary(points: &[ConfiguredPoint]) -> String {
    format!(
        "{} points: {}",
        points.len(),
        points.iter().map(point_word).collect::<Vec<_>>().join(", ")
    )
}

/// Exact D5 error map: `Resolve → Unsupported`, `Load → Denied`,
/// `Configure → Internal` (post-load map-write failure is a defect marker),
/// `AttachSetup → Denied`, `NoPointAttached → Unsupported` iff every point
/// is `Missing` (whole backend unavailable — honest) else `Denied`,
/// `SessionBusy → Unsafe` (cross-profile exclusion). Shared with the
/// lifecycle backend (same taxonomy for both profiles' bring-up).
pub(crate) fn configured_error_to_backend(err: ConfiguredError) -> BackendError {
    match err {
        ConfiguredError::Resolve(inner) => btf_unsupported(&inner),
        ConfiguredError::Load(inner) => BackendError::Denied(DeniedReason::with_detail(
            "kcrypto_load_denied",
            &inner.to_string(),
        )),
        ConfiguredError::Configure(inner) => BackendError::Internal(InternalError::with_detail(
            "kcrypto_kcfg_write",
            &inner.to_string(),
        )),
        ConfiguredError::AttachSetup { detail } => {
            BackendError::Denied(DeniedReason::with_detail("kcrypto_attach_setup", &detail))
        }
        ConfiguredError::NoPointAttached { points } => {
            let detail = points_summary(&points);
            // Vacuous `all` on an empty vec yields Unsupported: no point
            // even attempted, so nothing was denied.
            if points
                .iter()
                .all(|p| matches!(p.load, PointStatus::Missing { .. }))
            {
                BackendError::Unsupported(UnsupportedReason::with_detail(
                    "kcrypto_no_point_attached",
                    &detail,
                ))
            } else {
                BackendError::Denied(DeniedReason::with_detail(
                    "kcrypto_no_point_attached",
                    &detail,
                ))
            }
        }
        ConfiguredError::SessionBusy { live, want } => {
            BackendError::Unsafe(SafetyReason::with_detail(
                "kcrypto_session_busy",
                &format!(
                    "'{}' is live, '{}' refused (no cross-profile capture)",
                    live.as_str(),
                    want.as_str()
                ),
            ))
        }
    }
}

impl Backend for KCryptoBackend {
    fn id(&self) -> BackendId {
        BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        &KCRYPTO_CAPABILITIES
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        resolve_btf_ids().map_err(|err| btf_unsupported(&err))?;
        Ok(vec![DetectedInstance {
            backend: BackendId::KCrypto,
            object: None,
            detail: "system kcrypto sensor (9 fexit points)".to_owned(),
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
            probes: KCRYPTO_SYMBOLS
                .iter()
                .enumerate()
                .map(|(ordinal, _)| OffsetProbe {
                    file_offset: 0,
                    cookie: 0,
                    descriptor_id: ordinal as u32,
                })
                .collect(),
            required: KCRYPTO_CAPABILITIES.required,
        })
    }

    fn configure(
        &self,
        ctx: &mut ConfigureContext<'_>,
        _plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        // Idempotent by generation: same-generation re-calls are no-ops
        // (no reload, no re-charge) so K3 can call per watch tick.
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
        // First call (or a new generation): claim the process share
        // for api-returns (no cross-profile capture: a live lifecycle
        // session refuses this typed). The local hold covers the
        // load; success stashes it with the sensor, failure drops it
        // (a failed bring-up holds nothing).
        let session = acquire_kcrypto_session(LifecycleProfile::ApiReturns).map_err(|busy| {
            BackendError::Unsafe(SafetyReason::with_detail(
                "kcrypto_session_busy",
                &busy.to_string(),
            ))
        })?;
        // First call (or a new generation): staged inputs win when
        // the live session staged them (H1(b)/M2 — the already-read
        // bytes skip the locator re-read; the staged token loads
        // token-only delegations), else the historical direct path:
        // locate + privileged load. `staged` stays alive across the
        // load so the borrowed token fd cannot close mid-bring-up.
        let staged = self.take_staged_inputs();
        let bytes = match staged.object {
            Some(bytes) => bytes,
            None => kcrypto_object_bytes()?,
        };
        let token_fd = staged.token.as_ref().map(File::as_raw_fd);
        let (sensor, _points) =
            load_kcrypto_configured(&bytes, token_fd).map_err(configured_error_to_backend)?;
        // Charge only after the load succeeds (a failed configure charges
        // nothing); the sensor stashes only after the charges land, so a
        // refused charge drops the fresh sensor and keeps prior state.
        // L6: the re-check + charges + stash run under one held lock —
        // a concurrent configure of the same generation that stashed
        // while this load ran turns this call into a no-op (the loser
        // drops its fresh sensor via RAII and charges nothing: no
        // double-load-survives, no double-charge). The slow load stays
        // outside the lock; the critical section is two in-memory
        // budget charges plus the stash (no lock ordering: the budget
        // is caller-owned `&mut`, never a mutex).
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some((generation, _)) = state.as_ref()
            && *generation == ctx.generation
        {
            return Ok(());
        }
        charge(ctx, BudgetKind::Links, sensor.links.len() as u64)?;
        charge(ctx, BudgetKind::StateEntries, KCRYPTO_MAP_COUNT)?;
        *state = Some((ctx.generation, sensor));
        // Stash the process hold with the sensor (replacing any prior
        // hold on generation change; the replaced guard's drop keeps
        // the count exact).
        *self
            .session
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some(session);
        Ok(())
    }

    fn decode(
        &self,
        ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        let parsed = parse_snapshot_row(event.payload)?;
        // Identity comes from the session issuer (unique across backends);
        // exhaustion refuses typed, never mints a duplicate.
        let id = ctx.id_issuer.issue().map_err(|exhausted| {
            BackendError::Exhausted(BudgetReason::with_detail(
                "observation_ids",
                &exhausted.to_string(),
            ))
        })?;
        let observation = match parsed {
            ParsedRow::Agg { kagg, vagg } => observation_for_agg(&kagg, &vagg, id),
            ParsedRow::Totals { vagg } => observation_for_totals(&vagg, id),
            ParsedRow::Ident { kctl } => observation_for_ident(&kctl, id),
        };
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
        let Some((generation, sensor)) = guard.as_ref() else {
            // Pre-configure: no sensor to assess — counts echo, integrity
            // pins zero (documented; never echo the ctx baseline).
            return Ok(BackendSummary {
                backend: BackendId::KCrypto,
                observations,
                integrity: IntegritySummary::default(),
            });
        };
        // Staged fast path (M5): the live driver staged closing-tick
        // counts, so integrity computes from those plus one fresh
        // `KWHO_DROPS` read — no snapshot walk, no who walk. The gap
        // agrees with the session coverage by construction (same
        // closing counts). Unstaged callers (driver tests, direct
        // use) fall through to the historical full assessment.
        if let Some(closing) = self.take_closing_for(*generation) {
            let who_drops = read_kwho_drops(sensor).map_err(|err| {
                BackendError::Internal(InternalError::with_detail(
                    "kcrypto_finalize_read",
                    &format!("who drops: {err}"),
                ))
            })?;
            return Ok(BackendSummary {
                backend: BackendId::KCrypto,
                observations,
                integrity: integrity_for_counts(
                    closing.agg_calls,
                    closing.totals_calls,
                    closing.drops,
                    who_drops,
                )?,
            });
        }
        // End-of-session assessment over a fresh snapshot (the ring drain
        // lands here too — the session is over, nothing else consumes it).
        let snap = snapshot_rows(sensor).map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "kcrypto_finalize_read",
                &format!("snapshot: {err}"),
            ))
        })?;
        // Retained read (M3): the fresh snapshot already carries
        // `KIDN_DROPS` — no second lookup of the key.
        let drops = snap.drops;
        // K5: attribution-insert loss joins the state-insert counter (the
        // who rows themselves decode per-tick in Task 5; finalize only
        // needs the loss count).
        let (_who_rows, who_drops) = snapshot_who(sensor).map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "kcrypto_finalize_read",
                &format!("who snapshot: {err}"),
            ))
        })?;
        Ok(BackendSummary {
            backend: BackendId::KCrypto,
            observations,
            integrity: integrity_for_snapshot(&snap, drops, who_drops)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpfloader::LoaderError;
    use kryprobe_abi::kcrypto_agg::kctl_pack_head;
    use kryprobe_core::ids::{IdIssuer, SessionId};

    fn unsupported_reason(err: &BackendError) -> (&'static str, Option<String>) {
        match err {
            BackendError::Unsupported(reason) => (reason.reason, reason.detail.clone()),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    fn denied_reason(err: &BackendError) -> (&'static str, Option<String>) {
        match err {
            BackendError::Denied(reason) => (reason.reason, reason.detail.clone()),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    fn internal_reason(err: &BackendError) -> (&'static str, Option<String>) {
        match err {
            BackendError::Internal(reason) => (reason.reason, reason.detail.clone()),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn error_map_covers_all_five_variants() {
        // Resolve -> Unsupported (shared with detect).
        let err = configured_error_to_backend(ConfiguredError::Resolve(BtfError::MissingFunc {
            name: "crypto_aead_encrypt".to_owned(),
        }));
        let (reason, detail) = unsupported_reason(&err);
        assert_eq!(reason, "kcrypto_btf_unresolvable");
        assert!(detail.expect("detail").contains("crypto_aead_encrypt"));

        // Load -> Denied.
        let err = configured_error_to_backend(ConfiguredError::Load(LoaderError::BadObject {
            reason: "truncated".to_owned(),
        }));
        let (reason, detail) = denied_reason(&err);
        assert_eq!(reason, "kcrypto_load_denied");
        assert!(detail.expect("detail").contains("truncated"));

        // Configure -> Internal (defect marker).
        let err =
            configured_error_to_backend(ConfiguredError::Configure(MapOpsError::UpdateFailed {
                stage: "kcfg".to_owned(),
                errno: 5,
            }));
        let (reason, _) = internal_reason(&err);
        assert_eq!(reason, "kcrypto_kcfg_write");

        // AttachSetup -> Denied.
        let err = configured_error_to_backend(ConfiguredError::AttachSetup {
            detail: "no cookies".to_owned(),
        });
        let (reason, detail) = denied_reason(&err);
        assert_eq!(reason, "kcrypto_attach_setup");
        assert_eq!(detail.as_deref(), Some("no cookies"));
    }

    fn point(name: &str, load: PointStatus, attach: Option<AttachOutcome>) -> ConfiguredPoint {
        ConfiguredPoint {
            name: name.to_owned(),
            load,
            attach,
        }
    }

    #[test]
    fn no_point_attached_splits_missing_vs_other() {
        // Every point Missing -> Unsupported (whole backend unavailable).
        let all_missing = ConfiguredError::NoPointAttached {
            points: vec![
                point(
                    "a",
                    PointStatus::Missing {
                        name: "a".to_owned(),
                    },
                    None,
                ),
                point(
                    "b",
                    PointStatus::Missing {
                        name: "b".to_owned(),
                    },
                    None,
                ),
            ],
        };
        let err = configured_error_to_backend(all_missing);
        let (reason, detail) = unsupported_reason(&err);
        assert_eq!(reason, "kcrypto_no_point_attached");
        assert_eq!(detail.as_deref(), Some("2 points: a=missing, b=missing"));

        // Any loaded-but-unattached point -> Denied.
        let failed_attach = ConfiguredError::NoPointAttached {
            points: vec![
                point(
                    "a",
                    PointStatus::Missing {
                        name: "a".to_owned(),
                    },
                    None,
                ),
                point(
                    "b",
                    PointStatus::Loaded {
                        name: "b".to_owned(),
                    },
                    Some(AttachOutcome::Failed {
                        detail: "EPERM".to_owned(),
                    }),
                ),
            ],
        };
        let err = configured_error_to_backend(failed_attach);
        let (reason, detail) = denied_reason(&err);
        assert_eq!(reason, "kcrypto_no_point_attached");
        assert_eq!(
            detail.as_deref(),
            Some("2 points: a=missing, b=loaded+attach-failed:EPERM")
        );

        // Load-level Unsupported is not Missing -> Denied.
        let unsupported = ConfiguredError::NoPointAttached {
            points: vec![point(
                "a",
                PointStatus::Unsupported {
                    name: "a".to_owned(),
                    detail: "verifier".to_owned(),
                },
                None,
            )],
        };
        let (reason, _) = denied_reason(&configured_error_to_backend(unsupported));
        assert_eq!(reason, "kcrypto_no_point_attached");

        // Empty vec: vacuous all-Missing -> Unsupported (nothing denied).
        let empty = ConfiguredError::NoPointAttached { points: vec![] };
        let (reason, detail) = unsupported_reason(&configured_error_to_backend(empty));
        assert_eq!(reason, "kcrypto_no_point_attached");
        assert_eq!(detail.as_deref(), Some("0 points: "));
    }

    #[test]
    fn symbol_table_pins_nine_rows() {
        let rows = [
            ((KFAM_SK, KOP_ENC), "crypto_skcipher_encrypt"),
            ((KFAM_SK, KOP_DEC), "crypto_skcipher_decrypt"),
            ((KFAM_AEAD, KOP_ENC), "crypto_aead_encrypt"),
            ((KFAM_AEAD, KOP_DEC), "crypto_aead_decrypt"),
            ((KFAM_AHASH, KOP_DIGEST), "crypto_ahash_digest"),
            ((KFAM_SHASH, KOP_DIGEST), "crypto_shash_digest"),
            ((KFAM_SHASH, KOP_FINUP), "crypto_shash_finup"),
            ((KFAM_ANY, KOP_ALLOC), "crypto_alloc_tfm_node"),
            ((KFAM_ANY, KOP_DESTROY), "crypto_destroy_tfm"),
        ];
        for ((fam, op), symbol) in rows {
            assert_eq!(symbol_for(fam, op), Some(symbol));
        }
        // Alloc/destroy name under every family; unknown pairs name nothing.
        for fam in [KFAM_ANY, KFAM_SK, KFAM_AEAD, KFAM_AHASH, KFAM_SHASH] {
            assert_eq!(symbol_for(fam, KOP_ALLOC), Some("crypto_alloc_tfm_node"));
            assert_eq!(symbol_for(fam, KOP_DESTROY), Some("crypto_destroy_tfm"));
        }
        assert_eq!(symbol_for(KFAM_SK, KOP_DIGEST), None);
        assert_eq!(symbol_for(KFAM_ANY, KOP_ENC), None);
        assert_eq!(symbol_for(KFAM_AEAD, KOP_FINUP), None);
    }

    fn vwho_lane(comm0: u8, tid: u32, stack: i32, calls: u64, first_ns: u64, last_ns: u64) -> VWho {
        let mut comm = [0u8; 16];
        comm[0] = comm0;
        VWho {
            comm,
            tid,
            uid: 1000,
            cgroup: 7,
            ppid: 1,
            pcomm: [b'p'; 16],
            stack,
            calls,
            first_ns,
            last_ns,
        }
    }

    #[test]
    fn fold_vwho_sums_calls_and_folds_stamps() {
        // 3 lanes: one idle (calls 0 — must not poison the first-min
        // even with nonzero stamps; live idle lanes are zero-stamped
        // since the Task-2 I-1 fix, so this pins the exclusion rule
        // beyond the current BPF shape), two busy. calls sums; first is
        // the min over BUSY lanes; last is the max; identity rides the
        // most-recent-writer lane (greatest last_ns).
        let lanes = [
            vwho_lane(b'a', 11, 5, 0, 100, 100), // idle lane
            vwho_lane(b'b', 12, 5, 3, 100, 300),
            vwho_lane(b'c', 13, 5, 7, 100, 200),
        ];
        let folded = fold_vwho(&lanes);
        assert_eq!(folded.calls, 10);
        assert_eq!(folded.first_ns, 100);
        assert_eq!(folded.last_ns, 300);
        assert_eq!(folded.comm[0], b'b', "identity from the last_ns=300 lane");
        assert_eq!(folded.tid, 12);
        assert_eq!(folded.uid, 1000);
        assert_eq!(folded.stack, 5);
    }

    #[test]
    fn fold_vwho_all_idle_folds_to_zero_stamps() {
        // No busy lane: stamps are 0 (never the insert-time min), calls 0.
        let lanes = [vwho_lane(b'a', 11, 5, 0, 100, 100)];
        let folded = fold_vwho(&lanes);
        assert_eq!(folded.calls, 0);
        assert_eq!(folded.first_ns, 0);
        assert_eq!(folded.last_ns, 100);
        assert_eq!((folded.tid, folded.uid), (11, 1000));
        // Empty lane slice (defensive: callers pass >= 1): all zero.
        let folded = fold_vwho(&[]);
        assert_eq!(folded.calls, 0);
        assert_eq!((folded.first_ns, folded.last_ns), (0, 0));
    }

    #[test]
    fn stack_ips_truncate_at_first_zero() {
        // 127-frame KSTACK value shape: frames, then zero padding.
        let mut bytes = [0u8; 1016];
        for (i, ip) in [0xfff1u64, 0xfff2, 0xfff3].iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&ip.to_le_bytes());
        }
        assert_eq!(
            stack_ips_from_bytes(&bytes),
            vec![0xfff1u64, 0xfff2, 0xfff3]
        );
        assert!(stack_ips_from_bytes(&[0u8; 1016]).is_empty());
        assert!(stack_ips_from_bytes(&[]).is_empty());
    }

    #[test]
    fn head_unpack_inverts_pack() {
        for fam in 0..=5u8 {
            for op in 0..=7u8 {
                for res in 0..=4u8 {
                    for ctx in 0..=4u8 {
                        assert_eq!(
                            unpack_head(kctl_pack_head(fam, op, res, ctx)),
                            (fam, op, res, ctx)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn locator_miss_message_keeps_k2_vocabulary() {
        let err = ObjectLocateError {
            env_dir: Some("/nope".to_owned()),
            misses: vec![
                LocateMiss {
                    candidate: PathBuf::from("/nope/kcrypto.bpf.o"),
                    error: "No such file or directory (os error 2)".to_owned(),
                },
                LocateMiss {
                    candidate: PathBuf::from("/exe/kryprobe-bpf/kcrypto.bpf.o"),
                    error: "No such file or directory (os error 2)".to_owned(),
                },
            ],
        };
        assert_eq!(
            err.to_string(),
            "object missing (tried KRYPROBE_BPF_DIR=/nope, \
             /nope/kcrypto.bpf.o: No such file or directory (os error 2); \
             /exe/kryprobe-bpf/kcrypto.bpf.o: No such file or directory (os error 2))"
        );
        let unset = ObjectLocateError {
            env_dir: None,
            misses: vec![LocateMiss {
                candidate: PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
                error: "No such file or directory (os error 2)".to_owned(),
            }],
        };
        assert!(
            unset
                .to_string()
                .starts_with("object missing (tried KRYPROBE_BPF_DIR=(unset), ")
        );
    }

    #[test]
    fn locator_candidates_cover_env_file_dir_and_unset() {
        // Real file tried as-is; missing path dir-joined; exe tier joins
        // the bundled subpath; dev tier always last.
        let scratch = kryprobe_testkit::TempDir::named("k3-1-backend-cand").expect("scratch");
        let file = scratch.path().join("cand.o");
        std::fs::write(&file, b"object").expect("write tmp file");
        let exe = PathBuf::from("/exe/dir");
        assert_eq!(
            kcrypto_object_candidates(file.to_str(), Some(exe.as_path()), false),
            vec![
                file.clone(),
                PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o"),
                PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
            ]
        );
        // Absent child of the same guard (never created).
        let missing = scratch.path().join("absent");
        assert_eq!(
            kcrypto_object_candidates(missing.to_str(), None, false),
            vec![
                missing.join("kcrypto.bpf.o"),
                PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
            ]
        );
    }

    #[test]
    fn locator_candidates_elevated_drops_env_and_dev_tiers() {
        // H-SEC-01: elevated processes (root/file caps) never steer on
        // env or CWD — exe-bundled tier only.
        let scratch = kryprobe_testkit::TempDir::named("k3-1-backend-cand-elev").expect("scratch");
        let file = scratch.path().join("cand.o");
        std::fs::write(&file, b"object").expect("write tmp file");
        let exe = PathBuf::from("/exe/dir");
        assert_eq!(
            kcrypto_object_candidates(file.to_str(), Some(exe.as_path()), true),
            vec![PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o")]
        );
        // Elevated + unknown exe dir: no tiers at all (never fabricated).
        assert!(kcrypto_object_candidates(Some("/tmp/x"), None, true).is_empty());
    }

    #[test]
    fn verify_object_pin_rules() {
        // Hex encoding pins the standard sha256("abc") vector.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Empty pins (dev build): verification skipped.
        assert!(verify_object_pinned(b"anything", &[]).is_ok());
        // Pinned digest matches.
        let digest = sha256_hex(b"release-object");
        assert!(verify_object_pinned(b"release-object", &[digest.as_str()]).is_ok());
        // Mismatch fails loud with the failure named.
        let err = verify_object_pinned(b"tampered-object", &[digest.as_str()])
            .expect_err("tampered bytes must not verify");
        assert!(err.contains("untrusted object"), "names the failure: {err}");
    }

    #[test]
    fn pin_skip_warning_names_dev_skip() {
        // Empty pin set: the skip is named (fail-open made visible).
        let warn = pin_skip_warning(true).expect("empty pins must warn");
        assert!(
            warn.contains("PINNED_DIGESTS") || warn.contains("pin"),
            "warning names the skipped control: {warn}"
        );
        // Pinned builds stay silent.
        assert_eq!(pin_skip_warning(false), None);
    }

    #[test]
    fn pins_enforced_tracks_baked_pins() {
        assert_eq!(pins_enforced(), !PINNED_DIGESTS.is_empty());
    }

    #[test]
    fn names_decode_nul_truncated() {
        let mut words = [0u64; 16];
        words[0] = u64::from_le_bytes(*b"cbc(aes)");
        words[1] = 0; // NUL terminates in the second word
        assert_eq!(name_from_words(&words), "cbc(aes)");
        assert_eq!(name_from_words(&[0u64; 16]), "");
        // No NUL in 128B: the whole field (kernel names always NUL-pad, but
        // the decoder never over-reads regardless).
        assert_eq!(name_from_words(&[0x6161_6161_6161_6161u64; 16]).len(), 128);
    }

    /// Hand 382B agg row with `calls` observations (3A-M-T7: the
    /// canonical builder; fills preserved from the old local copy).
    fn hand_agg(calls: u64) -> Vec<u8> {
        kryprobe_testkit::kcrypto_rows::agg_row_bytes(kryprobe_testkit::kcrypto_rows::AggSpec {
            family: KFAM_SK,
            op: KOP_ENC,
            result: KRES_OK,
            ctx: KCTX_PROC,
            name: b"cbc(aes)",
            drv: b"",
            calls,
            bytes: 0,
            ok: calls,
            errors: 0,
            queued: 0,
        })
    }

    /// Hand 122B totals row with `calls` observations (3A-M-T7:
    /// canonical builder; fills preserved from the old local copy).
    fn hand_totals(calls: u64) -> Vec<u8> {
        kryprobe_testkit::kcrypto_rows::totals_row_bytes(calls, 640, calls)
    }

    /// Cross-crate consistency (3A-M-T7): the canonical testkit
    /// builders mirror the wire consts — drift fails here, not as a
    /// mysterious decode rejection in a consumer suite.
    #[test]
    fn canonical_row_layout_matches_wire_consts() {
        use crate::kcrypto_snapshot::{
            IDENT_BYTES_LEN, ROW_BYTES_LEN, ROW_KIND_AGG, ROW_KIND_IDENT, ROW_KIND_TOTALS,
            SNAPSHOT_VERSION, TOTALS_BYTES_LEN,
        };
        use kryprobe_testkit::kcrypto_rows as canonical;
        assert_eq!(canonical::VERSION, SNAPSHOT_VERSION);
        assert_eq!(canonical::KIND_AGG, ROW_KIND_AGG);
        assert_eq!(canonical::KIND_TOTALS, ROW_KIND_TOTALS);
        assert_eq!(canonical::KIND_IDENT, ROW_KIND_IDENT);
        assert_eq!(canonical::AGG_LEN, ROW_BYTES_LEN);
        assert_eq!(canonical::TOTALS_LEN, TOTALS_BYTES_LEN);
        assert_eq!(canonical::IDENT_LEN, IDENT_BYTES_LEN);
    }

    fn hand_snapshot(agg_calls: &[u64], tot_calls: Option<u64>) -> SnapshotRows {
        SnapshotRows {
            rows: agg_calls
                .iter()
                .map(|c| crate::kcrypto_snapshot::RowBytes::new(hand_agg(*c)).expect("hand row"))
                .collect(),
            totals: tot_calls.map(|c| {
                crate::kcrypto_snapshot::TotalsBytes::new(hand_totals(c)).expect("hand totals")
            }),
            idents: vec![],
            overflow_identities: 0,
            drops: 0,
            monotonic_ns: 7,
        }
    }

    #[test]
    fn partial_path_gap_reports_with_totals_preserved() {
        // Gap > 0 -> state_insert_failures == gap (PARTIAL path, unpriv).
        let snap = hand_snapshot(&[10, 20], Some(40));
        let integrity = integrity_for_snapshot(&snap, 0, 0).expect("gap maps");
        assert_eq!(integrity.state_insert_failures, 10, "KTOT(40) - ΣKAGG(30)");
        assert_eq!(integrity.ring_reservation_failures, 0);
        // Healthy: no gap, drops ride through saturating.
        let snap = hand_snapshot(&[10, 20], Some(30));
        let integrity = integrity_for_snapshot(&snap, 3, 0).expect("healthy maps");
        assert_eq!(integrity.state_insert_failures, 0);
        assert_eq!(integrity.ring_reservation_failures, 3);
        // K5: who_drops merges into the state-insert counter (saturating).
        let snap = hand_snapshot(&[10, 20], Some(40));
        let integrity = integrity_for_snapshot(&snap, 0, 5).expect("who drops merge");
        assert_eq!(
            integrity.state_insert_failures, 15,
            "gap(10) + who_drops(5)"
        );
        let integrity = integrity_for_snapshot(&snap, 0, u64::MAX).expect("who drops saturate");
        assert_eq!(integrity.state_insert_failures, u64::MAX);
        // Totals missing: no baseline, no gap claim (live-impossible).
        let snap = hand_snapshot(&[10], None);
        let integrity = integrity_for_snapshot(&snap, 0, 0).expect("missing totals maps");
        assert_eq!(integrity.state_insert_failures, 0);
        // The other 7 counters pin zero with N/A reasons in code.
        assert_eq!(
            integrity,
            IntegritySummary {
                ring_reservation_failures: 0,
                state_insert_failures: 0,
                ..IntegritySummary::default()
            }
        );
        // Totals preserved: the totals row still decodes to a full
        // aggregate observation even on the PARTIAL path.
        let backend = KCryptoBackend::new();
        let totals =
            crate::kcrypto_snapshot::TotalsBytes::new(hand_totals(40)).expect("hand totals");
        let event = crate::kcrypto_snapshot::raw_event_for_totals(&totals);
        let issuer = IdIssuer::default();
        let baseline = IntegritySummary::default();
        let ctx = DecodeContext {
            session: SessionId::new(1),
            generation: PlanGeneration::new(1),
            integrity: &baseline,
            id_issuer: &issuer,
        };
        let obs = backend.decode(&ctx, event).expect("totals decodes");
        assert_eq!(obs.backend_payload["counts"]["calls"].as_u64(), Some(40));
        assert_eq!(obs.backend_payload["bytes"].as_u64(), Some(640));
    }

    #[test]
    fn kdrop_site_names_pin_eight() {
        // Fix wave (G-C1): the KDROPS site order is a BPF/userspace
        // contract — index order pins exactly (destroy is separately
        // keyed: it always skips via C7, never a loss signal).
        assert_eq!(
            KDROP_SITES,
            [
                "cfg_fail",
                "fret_fail",
                "arg_null",
                "chase_fail",
                "name_fail",
                "destroy_skip",
                "spare_6",
                "spare_7",
            ]
        );
        assert_eq!(KDROP_DESTROY, 5);
        assert_eq!(KDROP_SITES[KDROP_DESTROY], "destroy_skip");
    }

    #[test]
    fn integrity_for_counts_matches_snapshot_wrapper() {
        // M5: the staged fast path computes integrity from closing
        // counts — identical to the parse-then-compute wrapper.
        let snap = hand_snapshot(&[10, 20], Some(30));
        let via_snapshot = integrity_for_snapshot(&snap, 3, 5).expect("wrapper computes");
        let via_counts = integrity_for_counts(30, Some(30), 3, 5).expect("core computes");
        assert_eq!(via_counts, via_snapshot);
        assert_eq!(via_counts.ring_reservation_failures, 3);
        assert_eq!(via_counts.state_insert_failures, 5, "gap 0 + who 5");
        // Gap leg: totals beyond Σagg accrue as insert failures.
        let gapped = integrity_for_counts(30, Some(40), 0, 1).expect("gap");
        assert_eq!(gapped.state_insert_failures, 11, "gap 10 + who 1");
        // Missing totals: no baseline, no gap claim.
        let nobase = integrity_for_counts(30, None, 0, 2).expect("no baseline");
        assert_eq!(nobase.state_insert_failures, 2);
    }

    #[test]
    fn staged_closing_counts_match_generation_only() {
        // M5: staged closing counts serve only the generation they
        // were staged for; a foreign generation discards them (stale
        // counts never poison another session's integrity).
        let backend = KCryptoBackend::new();
        let generation = PlanGeneration::new(4);
        backend.stage_closing_counts(ClosingCounts {
            generation,
            agg_calls: 30,
            totals_calls: Some(30),
            drops: 3,
        });
        assert!(
            backend.take_closing_for(PlanGeneration::new(5)).is_none(),
            "foreign generation discards"
        );
        assert!(
            backend.take_closing_for(generation).is_none(),
            "discarded staging is gone for good"
        );
        backend.stage_closing_counts(ClosingCounts {
            generation,
            agg_calls: 30,
            totals_calls: Some(30),
            drops: 3,
        });
        let hit = backend
            .take_closing_for(generation)
            .expect("matching generation hits");
        assert_eq!(
            (hit.agg_calls, hit.totals_calls, hit.drops),
            (30, Some(30), 3)
        );
        assert!(
            backend.take_closing_for(generation).is_none(),
            "closing staging drains once"
        );
    }

    #[test]
    fn who_cache_hit_skips_rejoin_on_quiescent_row() {
        // H4: quiescent rows (same last_ns + stack id) reuse joins;
        // any advance or any new key rejoins. tgid-recycle safe: new
        // activity always advances last_ns (folded max), so a hit
        // implies an unchanged map entry.
        let mut cache = WhoCache::new();
        let joins = WhoJoins {
            stack_ips: vec![0xfff0, 0xfff1],
            first_errno: Some(-2),
            params: Some(VParams::default()),
        };
        assert_eq!(cache.lookup(7, 42, 100, 3), None, "cold miss");
        cache.store(7, 42, 100, 3, joins.clone());
        assert_eq!(
            cache.lookup(7, 42, 100, 3),
            Some(joins.clone()),
            "quiescent hit"
        );
        assert_eq!(
            cache.lookup(7, 42, 101, 3),
            None,
            "advanced last_ns rejoins"
        );
        assert_eq!(
            cache.lookup(7, 42, 100, 4),
            None,
            "changed stack id rejoins"
        );
        assert_eq!(cache.lookup(7, 43, 100, 3), None, "other tgid misses");
        assert_eq!(cache.lookup(8, 42, 100, 3), None, "other kh misses");
        // Restoring advances the entry (no unbounded growth: one
        // entry per live key; dead keys evaporate on process exit...
        // see the struct docs for the session bound).
        cache.store(7, 42, 101, 3, joins.clone());
        assert_eq!(cache.lookup(7, 42, 101, 3), Some(joins));
    }

    #[test]
    fn kdrop_fold_sums_percpu_lanes_saturating() {
        // Synthetic 3-CPU lanes: exact sum, short read refuses, overflow
        // saturates (never wraps — magnitude honesty at scale).
        let lanes: Vec<u8> = [10u64, 20, 30]
            .iter()
            .flat_map(|lane| lane.to_le_bytes())
            .collect();
        assert_eq!(fold_drop_lanes(&lanes, 3), Some(60));
        assert_eq!(fold_drop_lanes(&lanes, 4), None);
        assert_eq!(fold_drop_lanes(&lanes[..16], 3), None);
        let lanes: Vec<u8> = [u64::MAX, 1]
            .iter()
            .flat_map(|lane| lane.to_le_bytes())
            .collect();
        assert_eq!(fold_drop_lanes(&lanes, 2), Some(u64::MAX));
    }

    #[test]
    fn session_sensor_before_configure_is_typed_error() {
        // H1(b): the tick sensor comes from the configured backend —
        // before configure there is no sensor, typed (never a panic
        // or a silent empty handle).
        let backend = KCryptoBackend::new();
        let err = match backend.session_sensor() {
            Ok(_) => panic!("unconfigured backend has no sensor"),
            Err(err) => err,
        };
        match err {
            BackendError::Internal(reason) => {
                assert_eq!(reason.reason, "kcrypto_sensor_unconfigured")
            }
            other => panic!("expected Internal(unconfigured), got {other:?}"),
        }
    }

    #[test]
    fn staged_inputs_roundtrip_and_drain_once() {
        // H1(b)/M2: live stages its already-read object bytes + token
        // file; configure drains them exactly once (second drain is
        // empty — no stale reuse across generations).
        let backend = KCryptoBackend::new();
        let scratch = kryprobe_testkit::TempDir::named("k3-merge-stage").expect("scratch");
        let probe = scratch.path().join("probe");
        std::fs::write(&probe, b"token").expect("write probe");
        let file = std::fs::File::open(&probe).expect("open probe");
        backend.stage_session_inputs(vec![0x7f, b'E', b'L', b'F'], Some(file));
        let first = backend.take_staged_inputs();
        assert_eq!(first.object, Some(vec![0x7f, b'E', b'L', b'F']));
        assert!(first.token.is_some(), "staged token drains");
        let second = backend.take_staged_inputs();
        assert_eq!(second.object, None, "bytes drain once");
        assert!(second.token.is_none(), "token drains once");
    }
}
