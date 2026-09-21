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
//! [`map_lookup_bytes`], decode is pure.
//!
//! K5 Task 3 adds the snapshot side of attribution: [`snapshot_who`]
//! walks `KWHO`/`KSTACK`/`KERR`/`KPARAMS` (map access reuses
//! [`crate::mapops`], like [`snapshot_rows`]) into [`WhoSnapshot`]s.
//! K5 Task 4 decodes those into `row="who"` observations
//! ([`observation_for_who`], pure over the snapshot + parsed table),
//! adds `key_hash`/`lat` to agg payloads, and merges `who_drops` into
//! finalize integrity.

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use kryprobe_abi::kcrypto_agg::{
    KAgg, KCTL_IDENT, KCTL_OVERFLOW, KCTX_KTHREAD, KCTX_PROC, KCTX_SOFTIRQ, KCTX_UNKNOWN, KCtl,
    KFAM_AEAD, KFAM_AHASH, KFAM_ANY, KFAM_SHASH, KFAM_SK, KOP_ALLOC, KOP_DEC, KOP_DESTROY,
    KOP_DIGEST, KOP_ENC, KOP_FINUP, KRES_ERR, KRES_OK, KRES_QUEUED, KRES_UNOBSERVED, KWHO_DROPS,
    KWhoKey, VAgg, VParams, VWho, kctl_unpack_lens, kh_of, kwho_key_from_bytes, vparams_from_bytes,
    vwho_from_bytes,
};
use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendPlan, BackendRegistry, BackendSummary, ConfigureContext,
    DecodeContext, DetectContext, DetectedInstance, DuplicateBackend, FinalizeContext, PlanContext,
    RawEvent,
};
use kryprobe_core::budget::BudgetKind;
use kryprobe_core::enums::{BackendId, CallKind, CaptureMode, EvidencePhase, OperationClass};
use kryprobe_core::error::{
    BackendError, BudgetReason, DeniedReason, InternalError, UnsupportedReason,
};
use kryprobe_core::evidence::{
    IntegrityRef, IntegritySummary, NativeObservation, NativeResult, SafeTextId,
};
use kryprobe_core::ids::{ObservationId, PlanGeneration};
use kryprobe_core::plan::{CapabilityRequirements, OffsetProbe};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::bpfloader::PointStatus;
use crate::btf_resolve::{
    AttachOutcome, BtfError, ConfiguredError, ConfiguredKcrypto, ConfiguredPoint, KCRYPTO_SYMBOLS,
    load_kcrypto_configured, resolve_btf_ids,
};
use crate::kallsyms::{SymTable, symbolize_with};
use crate::kcrypto_snapshot::{ParsedRow, SnapshotRows, parse_snapshot_row, snapshot_rows};
use crate::mapops::{MapOpsError, map_get_next_key, map_lookup_bytes, possible_cpus};

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

/// Payload note on `UNOBSERVED` rows (unreachable-by-construction: only the
/// void destroy path carries this class, and it emits no rows).
const UNOBSERVED_NOTE: &str = "unobserved: void return carries no result class (destroy path)";

/// Kernel-crypto backend: a system-wide fexit sensor owned by `configure`
/// plus a decode counter. `Send + Sync` via the mutex + atomics (the sensor
/// is fd-backed, no interior aliasing).
pub struct KCryptoBackend {
    state: Mutex<Option<(PlanGeneration, ConfiguredKcrypto)>>,
    staged: Mutex<StagedBringup>,
    decoded: AtomicUsize,
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

/// Charge one budget kind, mapping refusal to a typed exhaustion error
/// (the [`SyntheticBackend`](kryprobe_core::synthetic::SyntheticBackend) pattern).
fn charge(
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
/// and the `Resolve` arm of [`configured_error_to_backend`].
fn btf_unsupported(err: &BtfError) -> BackendError {
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
/// is `Missing` (whole backend unavailable — honest) else `Denied`.
fn configured_error_to_backend(err: ConfiguredError) -> BackendError {
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
    }
}

// Pinned release-object digests (H-SEC-01), baked by build.rs from
// `KRYPROBE_PIN_DIGESTS`; empty in dev builds (pin check skipped).
include!(concat!(env!("OUT_DIR"), "/pinned_digests.rs"));

/// kcrypto object file name (tier-1 dir join + tier-2 bundled path).
const OBJECT_FILE_NAME: &str = "kcrypto.bpf.o";

/// Dev-object fallback, CWD-relative (tier 3; the K2 doctor spelling, kept
/// verbatim so dev runs from the workspace root keep working).
const DEV_OBJECT: &str = "target/kryprobe-bpf/kcrypto.bpf.o";

/// One tried candidate plus its exact fs error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocateMiss {
    /// Candidate path tried.
    pub candidate: PathBuf,
    /// Exact `fs::read` error text for this candidate.
    pub error: String,
}

/// Total locator miss: every candidate tried in order with exact fs errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectLocateError {
    /// Probed `KRYPROBE_BPF_DIR` value (`None` when unset).
    pub env_dir: Option<String>,
    /// Tried candidates in try order, each with its exact fs error.
    pub misses: Vec<LocateMiss>,
}

impl std::fmt::Display for ObjectLocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let misses = self
            .misses
            .iter()
            .map(|miss| format!("{}: {}", miss.candidate.display(), miss.error))
            .collect::<Vec<_>>()
            .join("; ");
        write!(
            f,
            "object missing (tried KRYPROBE_BPF_DIR={}, {})",
            self.env_dir.as_deref().unwrap_or("(unset)"),
            misses
        )
    }
}

impl std::error::Error for ObjectLocateError {}

/// Object candidates in D2 try order, pure over the inputs (unit-testable
/// without env mutation): `KRYPROBE_BPF_DIR` (a file tried as-is, else a
/// dir joined with `kcrypto.bpf.o`) → executable-dir
/// `kryprobe-bpf/kcrypto.bpf.o` (bundled; skipped when the exe dir is
/// unknown, never fabricated) → the CWD-relative dev object.
///
/// When `elevated`, env and CWD tiers are refused (H-SEC-01): only the
/// exe-bundled tier is returned, possibly nothing.
#[must_use]
pub fn kcrypto_object_candidates(
    env: Option<&str>,
    exe_dir: Option<&Path>,
    elevated: bool,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !elevated && let Some(value) = env {
        let candidate = PathBuf::from(value);
        if candidate.is_file() {
            out.push(candidate);
        } else {
            out.push(candidate.join(OBJECT_FILE_NAME));
        }
    }
    if let Some(dir) = exe_dir {
        out.push(dir.join("kryprobe-bpf").join(OBJECT_FILE_NAME));
    }
    if !elevated {
        out.push(PathBuf::from(DEV_OBJECT));
    }
    out
}

/// Lowercase hex sha256 of object bytes (H-SEC-01 pin check).
fn object_digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0xf) as usize] as char);
    }
    hex
}

/// Pin check (H-SEC-01): empty pins (dev build) skip verification;
/// otherwise the object sha256 must be pinned. Pure over inputs for
/// unit tests; production passes [`PINNED_DIGESTS`].
fn verify_object_pinned(bytes: &[u8], pins: &[&str]) -> Result<(), String> {
    if pins.is_empty() {
        return Ok(());
    }
    let digest = object_digest_hex(bytes);
    if pins.iter().any(|pin| *pin == digest) {
        Ok(())
    } else {
        Err(format!(
            "untrusted object (sha256 {digest} not in pinned release digests)"
        ))
    }
}

/// D2 consolidated locator, single-read form (replaces the probe/use
/// double-read, L-SEC-06): first readable AND pin-trusted candidate
/// wins; bytes return with the path so callers never re-open.
/// Untrusted (pin mismatch) candidates are misses, not errors.
pub fn locate_kcrypto_object_bytes() -> Result<(PathBuf, Vec<u8>), ObjectLocateError> {
    let elevated = crate::elevate::process_is_elevated();
    let env = std::env::var("KRYPROBE_BPF_DIR").ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let env_tier = if elevated { None } else { env.as_deref() };
    let mut misses = Vec::new();
    for candidate in kcrypto_object_candidates(env_tier, exe_dir.as_deref(), elevated) {
        let bytes = match std::fs::read(&candidate) {
            Ok(bytes) => bytes,
            Err(err) => {
                misses.push(LocateMiss {
                    candidate,
                    error: err.to_string(),
                });
                continue;
            }
        };
        if let Err(detail) = verify_object_pinned(&bytes, PINNED_DIGESTS) {
            misses.push(LocateMiss {
                candidate,
                error: detail,
            });
            continue;
        }
        return Ok((candidate, bytes));
    }
    if elevated {
        misses.push(LocateMiss {
            candidate: PathBuf::from("(refused: env/CWD tiers disabled when elevated)"),
            error: "refused".to_owned(),
        });
    }
    Err(ObjectLocateError {
        env_dir: env,
        misses,
    })
}

/// Read the kcrypto BPF object via the consolidated locator.
/// Missing/unreadable is `Unsupported` (environmental — the backend cannot
/// attach, honestly reported, never a defect). The reason name is the K2
/// spelling (stable surface).
fn kcrypto_object_bytes() -> Result<Vec<u8>, BackendError> {
    let (_path, bytes) = locate_kcrypto_object_bytes().map_err(|err| {
        BackendError::Unsupported(UnsupportedReason::with_detail(
            "kcrypto_object_unreadable",
            &err.to_string(),
        ))
    })?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// K5 attribution snapshot (Task 3; who-row DECODE is Task 4).
// ---------------------------------------------------------------------------

/// One snapshotted caller-identity row: the folded `KWHO` value plus its
/// joins (`KSTACK` frames, first errno, crypto params). Task 4 decodes
/// these into `row="who"` observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoSnapshot {
    /// The `KWHO` key (row hash + tgid).
    pub key: KWhoKey,
    /// The percpu-folded `KWHO` value (calls summed, stamps min/maxed,
    /// identity from the most-recent-writer lane).
    pub val: VWho,
    /// Kernel stack IPs for `val.stack` (truncated at the first zero;
    /// empty when `stack` is negative or the `KSTACK` row is absent).
    pub stack_ips: Vec<u64>,
    /// First nonzero return for `key.kh` (`None` when `KERR` has no row).
    pub first_errno: Option<i32>,
    /// Crypto params for `key.kh` (`None` when `KPARAMS` has no row —
    /// params chase skipped or `alg == 0`).
    pub params: Option<VParams>,
}

/// Attribution-snapshot failure: an underlying map walk/read failure
/// (stage + errno preserved). Per-row join misses degrade instead (empty
/// `stack_ips`, `None` errno/params — the snapshot caller rule: unjoined
/// is unknown, never misattributed, never fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Underlying map walk/read failure.
    Map(MapOpsError),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Map(err) => write!(f, "who snapshot: {err}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<MapOpsError> for SnapshotError {
    fn from(err: MapOpsError) -> Self {
        Self::Map(err)
    }
}

/// `KDROPS` site names by index (fix wave, G-C1): the BPF/userspace
/// order contract — index order pins exactly (see
/// `kdrop_site_names_pin_eight`). Sites 0–4 are unexpected loss;
/// `destroy_skip` is C7-expected (always skips, separately keyed);
/// spares are reserved (BPF never writes them).
pub const KDROP_SITES: [&str; 8] = [
    "cfg_fail",
    "fret_fail",
    "arg_null",
    "chase_fail",
    "name_fail",
    "destroy_skip",
    "spare_6",
    "spare_7",
];

/// `KDROPS` index of the destroy C7-expected skip (surfaced, but
/// excluded from loss verdicts — sites below this index are the
/// unexpected-loss set).
pub const KDROP_DESTROY: usize = 5;

/// Fold one `KDROPS` percpu read (`ncpu` LE `u64` lanes) into a site
/// total. `None` on a short read (a broken post-attach read must be
/// loud, never a silent partial sum). Saturating (never wraps —
/// magnitude honesty at scale).
#[must_use]
pub fn fold_drop_lanes(raw: &[u8], ncpu: usize) -> Option<u64> {
    if raw.len() < 8 * ncpu {
        return None;
    }
    let mut total = 0u64;
    for c in 0..ncpu {
        let mut word = [0u8; 8];
        word.copy_from_slice(&raw[c * 8..(c + 1) * 8]);
        total = total.saturating_add(u64::from_le_bytes(word));
    }
    Some(total)
}

/// Snapshot the `KDROPS` pre-`KTOT` drop sites of a configured sensor:
/// one percpu lookup + fold per site, in [`KDROP_SITES`] order.
/// Structural failures fail the whole snapshot (the [`snapshot_who`]
/// discipline: loud, never a silent zero).
pub fn snapshot_drops(sensor: &ConfiguredKcrypto) -> Result<[u64; 8], SnapshotError> {
    let ncpu = possible_cpus() as usize;
    let mut out = [0u64; 8];
    for (site, slot) in out.iter_mut().enumerate() {
        // SAFETY: KDROPS is PerCpuArray<u64> (bpf-kcrypto map def);
        // 8B × possible_cpus matches the kernel's write.
        let raw = unsafe {
            map_lookup_bytes(
                &sensor.loaded.maps.drops,
                &(site as u32).to_le_bytes(),
                8 * ncpu,
                "snapshot/drops",
            )
        }?;
        *slot = fold_drop_lanes(&raw, ncpu).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/drops-lane".to_owned(),
            errno: libc::EBADMSG,
        })?;
    }
    Ok(out)
}

/// Fold per-CPU `VWho` lanes into one total (the [`fold_vagg`](kryprobe_abi::kcrypto_agg::fold_vagg)
/// contract for who rows): `calls` sums saturating; `first_ns` is the
/// minimum over lanes with `calls > 0` (idle lanes hold `calls == 0`
/// with zero stamps — the BPF broadcasts a zero tallies+stamps insert
/// to every lane, then the re-lookup stamps only the inserting CPU's
/// lane — and must not poison the min); `last_ns` is the maximum; both
/// stamps are 0 when no lane observed anything. Identity fields come
/// from the most-recent-writer lane (greatest `last_ns`, first on
/// ties): `tid`/`comm` are last-writer per lane, the rest are
/// insert-identical across lanes. Total over any lane slice (empty
/// folds to zero).
fn fold_vwho(lanes: &[VWho]) -> VWho {
    let mut out = VWho::default();
    let mut first = u64::MAX;
    let mut any = false;
    let mut best = 0usize;
    for (i, lane) in lanes.iter().enumerate() {
        out.calls = out.calls.saturating_add(lane.calls);
        if lane.calls > 0 {
            any = true;
            first = first.min(lane.first_ns);
        }
        if lane.last_ns > out.last_ns {
            out.last_ns = lane.last_ns;
            best = i;
        }
    }
    out.first_ns = if any { first } else { 0 };
    if let Some(winner) = lanes.get(best) {
        out.comm = winner.comm;
        out.tid = winner.tid;
        out.uid = winner.uid;
        out.cgroup = winner.cgroup;
        out.ppid = winner.ppid;
        out.pcomm = winner.pcomm;
        out.stack = winner.stack;
    }
    out
}

/// Decode one `KSTACK` value (1016B = 127 LE u64 frames, zero-padded)
/// into the frame prefix: truncated at the FIRST zero (frames fill
/// contiguously from index 0, and 0 is never a valid kernel IP).
fn stack_ips_from_bytes(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    for i in 0..bytes.len() / 8 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        let ip = u64::from_le_bytes(word);
        if ip == 0 {
            break;
        }
        out.push(ip);
    }
    out
}

/// Read the `KIDN[KWHO_DROPS]` per-row identity drop counter (M5:
/// the finalize fast path's only map read). Absent key reads
/// healthy-zero; any other errno fails loud (same rule as the
/// `snapshot_who` tail this was extracted from).
fn read_kwho_drops(maps: &ConfiguredKcrypto) -> Result<u64, SnapshotError> {
    // SAFETY: KIDN is HashMap<u64, u8>; value_len 1 is exact.
    match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.ident,
            &KWHO_DROPS.to_le_bytes(),
            1,
            "snapshot/who-drops",
        )
    } {
        Ok(value) => Ok(u64::from(value.first().copied().unwrap_or(0))),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => Ok(0),
        Err(err) => Err(err.into()),
    }
}

/// Joined attribution for one who row: the three map joins
/// (`KSTACK`/`KERR`/`KPARAMS`) factored out so quiescent rows reuse
/// them from [`WhoCache`] instead of re-reading the maps (H4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WhoJoins {
    /// Kernel stack IPs for the row's stack id.
    pub stack_ips: Vec<u64>,
    /// First nonzero return for the row hash.
    pub first_errno: Option<i32>,
    /// Crypto params for the row hash.
    pub params: Option<VParams>,
}

/// Cross-tick who-join cache (H4): one entry per live `(kh, tgid)`
/// key, each pinned to the `(last_ns, stack)` it was joined at. A
/// hit reuses the joins (skips 3 map reads); any advance rejoins. The
/// entry count is bounded by the live `KWHO` key set (≤2048 map
/// entries); dead keys linger until the session ends (bounded, small:
/// ~100B per entry worst case).
///
/// Correctness: a hit requires the folded `last_ns` (max lane write
/// time) AND the stack id to be unchanged. Any new who-event for the
/// key advances `last_ns` (folded max), and all three joins derive
/// from the same events — so a hit implies an unchanged map entry
/// (tgid-recycle safe: recycled tgids with new activity advance the
/// stamp; quiescent keys keep valid joins).
#[derive(Debug, Default)]
pub struct WhoCache {
    entries: HashMap<(u64, u32), (u64, i32, WhoJoins)>,
}

impl WhoCache {
    /// Empty cache (cold: every row rejoins once).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Cached joins for a row stamped `(last_ns, stack)` (`None` =
    /// rejoin: cold key, advanced stamp, or changed stack id).
    #[must_use]
    pub fn lookup(&self, kh: u64, tgid: u32, last_ns: u64, stack: i32) -> Option<WhoJoins> {
        match self.entries.get(&(kh, tgid)) {
            Some((cached_ns, cached_stack, joins))
                if *cached_ns == last_ns && *cached_stack == stack =>
            {
                Some(joins.clone())
            }
            _ => None,
        }
    }

    /// Stores joins for a row stamped `(last_ns, stack)` (overwrites
    /// any previous entry for the key).
    pub fn store(&mut self, kh: u64, tgid: u32, last_ns: u64, stack: i32, joins: WhoJoins) {
        self.entries.insert((kh, tgid), (last_ns, stack, joins));
    }
}

/// Snapshot the K5 attribution maps of a configured sensor: full `KWHO`
/// walk (key iteration + percpu fold) with per-row `KSTACK`/`KERR`/
/// `KPARAMS` joins, plus the `KWHO_DROPS` insert-loss count. Map order.
///
/// Join-miss discipline (fail-soft, never fatal): a negative `stack`
/// (raw helper errno — no `KSTACK` row) or an absent `KSTACK` row yields
/// empty `stack_ips`; an absent `KERR`/`KPARAMS` row yields `None`.
/// `KSTACK` join for one stack id: kernel stack IPs, truncated at
/// the first zero; empty when the id is negative or the row is
/// absent. Other map errors fail loud.
fn join_stack(maps: &ConfiguredKcrypto, stack: i32) -> Result<Vec<u64>, SnapshotError> {
    if stack < 0 {
        return Ok(Vec::new());
    }
    // SAFETY: KSTACK is an aya StackTrace map: the kernel stack
    // value is 127 × u64 = 1016B, always.
    match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.stack,
            &(stack as u32).to_le_bytes(),
            1016,
            "snapshot/who-stack",
        )
    } {
        Ok(raw) => Ok(stack_ips_from_bytes(&raw)),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => Ok(Vec::new()),
        Err(err) => Err(err.into()),
    }
}

/// `KERR` + `KPARAMS` joins for one row hash: first errno + crypto
/// params (`None` each when the row is absent). Other map errors, or
/// a present-but-undecodable value, fail loud.
fn join_err_params(
    maps: &ConfiguredKcrypto,
    kh: u64,
) -> Result<(Option<i32>, Option<VParams>), SnapshotError> {
    // SAFETY: KERR is HashMap<u64, i32>; value_len 4 is exact.
    let first_errno = match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.err,
            &kh.to_le_bytes(),
            4,
            "snapshot/who-err",
        )
    } {
        Ok(raw) => {
            let word: [u8; 4] = raw.try_into().map_err(|_| MapOpsError::LookupFailed {
                stage: "snapshot/who-err".to_owned(),
                errno: libc::EBADMSG,
            })?;
            Some(i32::from_le_bytes(word))
        }
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => None,
        Err(err) => return Err(err.into()),
    };
    // SAFETY: KPARAMS is HashMap<u64, VParams>; VParams is 16B
    // (vparams_from_bytes).
    let params = match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.params,
            &kh.to_le_bytes(),
            16,
            "snapshot/who-params",
        )
    } {
        Ok(raw) => Some(
            vparams_from_bytes(&raw).ok_or_else(|| MapOpsError::LookupFailed {
                stage: "snapshot/who-params".to_owned(),
                errno: libc::EBADMSG,
            })?,
        ),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => None,
        Err(err) => return Err(err.into()),
    };
    Ok((first_errno, params))
}

/// Structural failures (walk errors, short reads, undecodable lanes)
/// fail the whole snapshot as [`SnapshotError::Map`] (a broken
/// post-attach read must be loud, never a silent zero).
pub fn snapshot_who(maps: &ConfiguredKcrypto) -> Result<(Vec<WhoSnapshot>, u64), SnapshotError> {
    snapshot_who_cached(maps, &mut WhoCache::new())
}

/// [`snapshot_who`] with a caller-held join cache (H4): quiescent
/// rows skip all three joins; changed rows join through the
/// within-tick `kh` dedup (same crypto identity across tgids looks
/// up `KERR`/`KPARAMS` once per tick, not once per row). The lane
/// buffer is hoisted out of the row loop (M8: one alloc per snapshot,
/// not per row).
pub fn snapshot_who_cached(
    maps: &ConfiguredKcrypto,
    cache: &mut WhoCache,
) -> Result<(Vec<WhoSnapshot>, u64), SnapshotError> {
    let ncpu = possible_cpus() as usize;
    let mut out = Vec::new();
    let mut lanes: Vec<VWho> = Vec::with_capacity(ncpu);
    let mut tick_err: HashMap<u64, (Option<i32>, Option<VParams>)> = HashMap::new();
    let mut key: Option<Vec<u8>> = None;
    loop {
        // SAFETY: KWHO key is KWhoKey, exactly 16B (bpf-kcrypto map def).
        let next = unsafe {
            map_get_next_key(
                &maps.loaded.maps.who,
                key.as_deref(),
                16,
                "snapshot/who-iter",
            )
        }?;
        let Some(k) = next else { break };
        let who_key = kwho_key_from_bytes(&k).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/who-key".to_owned(),
            errno: libc::EBADMSG,
        })?;
        // SAFETY: KWHO is PerCpuHashMap<KWhoKey, VWho>; VWho is 80B
        // (vwho_from_bytes); ncpu is possible_cpus.
        let raw =
            unsafe { map_lookup_bytes(&maps.loaded.maps.who, &k, 80 * ncpu, "snapshot/who-val") }?;
        lanes.clear();
        for c in 0..ncpu {
            let lane = raw
                .get(c * 80..(c + 1) * 80)
                .and_then(vwho_from_bytes)
                .ok_or_else(|| MapOpsError::LookupFailed {
                    stage: "snapshot/who-lane".to_owned(),
                    errno: libc::EBADMSG,
                })?;
            lanes.push(lane);
        }
        let val = fold_vwho(&lanes);
        let joins = match cache.lookup(who_key.kh, who_key.tgid, val.last_ns, val.stack) {
            Some(joins) => joins,
            None => {
                let stack_ips = join_stack(maps, val.stack)?;
                // `KERR`/`KPARAMS` key on `kh` alone: rows sharing one
                // crypto identity across tgids share these joins
                // within the tick.
                let (first_errno, params) = match tick_err.get(&who_key.kh) {
                    Some(cached) => *cached,
                    None => {
                        let joined = join_err_params(maps, who_key.kh)?;
                        tick_err.insert(who_key.kh, joined);
                        joined
                    }
                };
                let joins = WhoJoins {
                    stack_ips,
                    first_errno,
                    params,
                };
                cache.store(
                    who_key.kh,
                    who_key.tgid,
                    val.last_ns,
                    val.stack,
                    joins.clone(),
                );
                joins
            }
        };
        out.push(WhoSnapshot {
            key: who_key,
            val,
            stack_ips: joins.stack_ips,
            first_errno: joins.first_errno,
            params: joins.params,
        });
        key = Some(k);
    }
    let drops = read_kwho_drops(maps)?;
    Ok((out, drops))
}

// ---------------------------------------------------------------------------
// D8 decode tables (exact).
// ---------------------------------------------------------------------------

/// `(fam, op) → symbol`: the 9 D8 rows; `None` is honest-unknown (ANY+exec
/// and other live-impossible combos carry no symbol — the inventory marker
/// keeps them visible, never silent).
fn symbol_for(fam: u8, op: u8) -> Option<&'static str> {
    match op {
        KOP_ALLOC => Some("crypto_alloc_tfm_node"),
        KOP_DESTROY => Some("crypto_destroy_tfm"),
        KOP_ENC if fam == KFAM_SK => Some("crypto_skcipher_encrypt"),
        KOP_DEC if fam == KFAM_SK => Some("crypto_skcipher_decrypt"),
        KOP_ENC if fam == KFAM_AEAD => Some("crypto_aead_encrypt"),
        KOP_DEC if fam == KFAM_AEAD => Some("crypto_aead_decrypt"),
        KOP_DIGEST if fam == KFAM_AHASH => Some("crypto_ahash_digest"),
        KOP_DIGEST if fam == KFAM_SHASH => Some("crypto_shash_digest"),
        KOP_FINUP if fam == KFAM_SHASH => Some("crypto_shash_finup"),
        _ => None,
    }
}

/// `op → (call_kind, phase)`: ALLOC initializes (Selected), exec ops
/// complete on a terminal class else stay entered, DESTROY is the mapped
/// unreachable arm (unknown, Returned). Out-of-range ops degrade to
/// (unknown, Entered) — live-impossible (the BPF writes 1–6), never crash.
fn op_call_phase(op: u8, res: u8) -> (CallKind, EvidencePhase) {
    let terminal = res == KRES_OK || res == KRES_ERR;
    let entered_or_completed = if terminal {
        EvidencePhase::Completed
    } else {
        EvidencePhase::Entered
    };
    match op {
        KOP_ALLOC => (CallKind::Initialization, EvidencePhase::Selected),
        KOP_ENC | KOP_DEC | KOP_DIGEST => (CallKind::Operation, entered_or_completed),
        KOP_FINUP => (CallKind::Finalization, entered_or_completed),
        KOP_DESTROY => (CallKind::Unknown, EvidencePhase::Returned),
        _ => (CallKind::Unknown, EvidencePhase::Entered),
    }
}

/// `res → status`: canonical representatives (D9 — the sensor counts result
/// classes, not codes). Out-of-range classes degrade to 0 like UNOBSERVED.
fn status_for_res(res: u8) -> i32 {
    match res {
        KRES_OK => 0,
        KRES_ERR => -libc::EIO,
        KRES_QUEUED => -libc::EINPROGRESS,
        _ => 0,
    }
}

/// `op → operation class`: the frozen-schema 13-variant mapping for the six
/// kcrypto ops (transform lifecycle is key management; anything else is
/// unknown, never guessed).
fn class_for_op(op: u8) -> OperationClass {
    match op {
        KOP_ENC => OperationClass::Encrypt,
        KOP_DEC => OperationClass::Decrypt,
        KOP_DIGEST | KOP_FINUP => OperationClass::Digest,
        KOP_ALLOC | KOP_DESTROY => OperationClass::KeyManagement,
        _ => OperationClass::Unknown,
    }
}

fn family_name(fam: u8) -> &'static str {
    match fam {
        KFAM_ANY => "any",
        KFAM_SK => "skcipher",
        KFAM_AEAD => "aead",
        KFAM_AHASH => "ahash",
        KFAM_SHASH => "shash",
        _ => "unknown",
    }
}

fn op_name(op: u8) -> &'static str {
    match op {
        KOP_ALLOC => "alloc",
        KOP_DESTROY => "destroy",
        KOP_ENC => "encrypt",
        KOP_DEC => "decrypt",
        KOP_DIGEST => "digest",
        KOP_FINUP => "finup",
        _ => "unknown",
    }
}

fn result_name(res: u8) -> &'static str {
    match res {
        KRES_OK => "ok",
        KRES_ERR => "error",
        KRES_QUEUED => "queued",
        KRES_UNOBSERVED => "unobserved",
        _ => "unknown",
    }
}

/// `ctx → payload.context` (D8 verbatim spellings).
fn context_name(ctx: u8) -> &'static str {
    match ctx {
        KCTX_PROC => "process",
        KCTX_KTHREAD => "kthread",
        KCTX_SOFTIRQ => "softirq",
        KCTX_UNKNOWN => "unknown",
        _ => "unknown",
    }
}

/// `KCtl.val0` head unpack: the exact inverse of `kctl_pack_head`
/// (`fam | op<<8 | res<<16 | ctx<<24`).
fn unpack_head(val0: u64) -> (u8, u8, u8, u8) {
    (
        (val0 & 0xff) as u8,
        ((val0 >> 8) & 0xff) as u8,
        ((val0 >> 16) & 0xff) as u8,
        ((val0 >> 24) & 0xff) as u8,
    )
}

/// NUL-truncated kernel name from raw words (lossy: kernel names are ASCII;
/// empty on the alloc-path zero driver — never fabricated).
fn name_from_words(words: &[u64; 16]) -> String {
    let mut bytes = [0u8; 128];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Agg row → observation: the full D8 mapping. ANY-family rows force the
/// inventory shape (Selected / `execution: "unsupported"`); everything else
/// follows the op/res tables with identity in `backend_payload`.
fn observation_for_agg(kagg: &KAgg, vagg: &VAgg, id: ObservationId) -> NativeObservation {
    let (fam, op, res, ctx) = (kagg.fam(), kagg.op(), kagg.res(), kagg.ctx());
    let inventory = fam == KFAM_ANY;
    let (call_kind, mut phase) = op_call_phase(op, res);
    if inventory {
        phase = EvidencePhase::Selected;
    }
    // K5: the row hash (shared FNV-1a via `kryprobe-abi`, same bytes the
    // BPF hashed) so who-rows join; latency buckets pass through verbatim.
    let key_hash = kh_of(fam, op, res, ctx, &kagg.alg(), &kagg.drv());
    let mut payload = json!({
        "row": "agg",
        "key_hash": key_hash,
        "family": family_name(fam),
        "op": op_name(op),
        "result": result_name(res),
        "algorithm": name_from_words(&kagg.alg()),
        "driver": name_from_words(&kagg.drv()),
        "context": context_name(ctx),
        "counts": {"calls": vagg.calls, "ok": vagg.ok, "errors": vagg.errors, "queued": vagg.queued},
        "bytes": vagg.bytes,
        "lat": vagg.lat,
        "window": {"first_ns": vagg.first_ns, "last_ns": vagg.last_ns},
        "status_canonical": true,
    });
    if inventory {
        payload["execution"] = json!("unsupported");
    }
    if res == KRES_UNOBSERVED {
        payload["result_note"] = json!(UNOBSERVED_NOTE);
    }
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase,
        call_kind,
        operation_class: class_for_op(op),
        native_name: symbol_for(fam, op).and_then(SafeTextId::new),
        native_code: None,
        native_result: NativeResult::KCrypto {
            status: status_for_res(res),
        },
        started_ns: Some(vagg.first_ns),
        ended_ns: Some(vagg.last_ns),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: payload,
    }
}

/// Totals row → observation: the aggregate-completion carrier. Status 0 is
/// the READ verdict (KTOT landed intact), not an op verdict — per-class
/// outcomes ride the payload counts, and K3 renders classes, never codes.
fn observation_for_totals(vagg: &VAgg, id: ObservationId) -> NativeObservation {
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Completed,
        call_kind: CallKind::Unknown,
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(vagg.first_ns),
        ended_ns: Some(vagg.last_ns),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: json!({
            "row": "totals",
            "counts": {"calls": vagg.calls, "ok": vagg.ok, "errors": vagg.errors, "queued": vagg.queued},
            "bytes": vagg.bytes,
            "window": {"first_ns": vagg.first_ns, "last_ns": vagg.last_ns},
            "status_canonical": true,
        }),
    }
}

/// Ident row → observation: a first-seen marker (`Discovered`, no verdict).
/// Call/class/symbol derive from the in-record head (no map join); the
/// status echoes the head class for Rust consumers (the wire renders
/// `not_applicable` for pre-return phases either way).
fn observation_for_ident(kctl: &KCtl, id: ObservationId) -> NativeObservation {
    let (fam, op, res, ctx) = unpack_head(kctl.val0);
    let (alg_len, drv_len) = kctl_unpack_lens(kctl.val1);
    let (call_kind, _) = op_call_phase(op, res);
    let ident_kind = match kctl.kind {
        KCTL_IDENT => "ident",
        KCTL_OVERFLOW => "overflow",
        _ => "unknown",
    };
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Discovered,
        call_kind,
        operation_class: class_for_op(op),
        native_name: symbol_for(fam, op).and_then(SafeTextId::new),
        native_code: None,
        native_result: NativeResult::KCrypto {
            status: status_for_res(res),
        },
        started_ns: Some(kctl.val2),
        ended_ns: None,
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: json!({
            "row": "ident",
            "ident_kind": ident_kind,
            "key_hash": kctl.key_hash,
            "family": family_name(fam),
            "op": op_name(op),
            "result": result_name(res),
            "context": context_name(ctx),
            "name_lens": {"alg": alg_len, "drv": drv_len},
            "first_seen_ns": kctl.val2,
        }),
    }
}

/// `comm`/`pcomm` decode: raw `[u8; 16]` from the kernel, lossy UTF-8,
/// trimmed at the first NUL (same shape as [`name_from_words`]).
fn comm_str(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// `first_errno` render rule (Task 2 review M-1): `KERR` may hold queued
/// (`-EINPROGRESS`/`-EBUSY`) or positive-ok returns — render ONLY when the
/// value is < 0 and neither queued code, else omit (`None`).
fn render_first_errno(first_errno: Option<i32>) -> Option<i32> {
    first_errno.filter(|e| *e < 0 && *e != -libc::EINPROGRESS && *e != -libc::EBUSY)
}

/// Who row → observation: a caller-identity marker (`Discovered`, no
/// verdict — status pins neutral 0, and the wire renders `not_applicable`
/// for pre-return phases either way, as with idents).
///
/// Payload keys are exactly the K5 brief's list: `key_hash` (the row's
/// `kh`, straight from the `KWHO` key — joins the agg `key_hash`),
/// identity (`tgid`/`tid`/`comm`/`uid`/`cgroup`), parent
/// (`ppid`/`pcomm`), `stack` (`{id, frames: [{ip, sym|null}]}`,
/// symbolized through a shared [`SymTable`](crate::kallsyms::SymTable)), tallies
/// (`calls`/`first_ns`/`last_ns`), crypto params
/// (`blocksize`/`ivsize`/`min_keysize`/`max_keysize`), `first_errno`.
///
/// Omit-when-unresolved (never zero-filled in output): parent keys drop
/// when `ppid` is 0 with an all-zero `pcomm` (the BPF writes
/// both-or-neither, gated on `parent_ok`); params keys drop when `params`
/// is `None` (the BPF inserts `KPARAMS` iff `params_ok`, so an absent row
/// is unresolved); `first_errno` follows [`render_first_errno`]. The
/// `stack` block is never gated (a negative `id` is the raw helper errno
/// with empty `frames`; unresolvable syms are `null`, raw `ip` kept).
pub fn observation_for_who(
    who: &WhoSnapshot,
    id: ObservationId,
    table: &SymTable,
) -> NativeObservation {
    let parent_resolved = who.val.ppid != 0 || who.val.pcomm != [0u8; 16];
    let mut payload = json!({
        "row": "who",
        "key_hash": who.key.kh,
        "tgid": who.key.tgid,
        "tid": who.val.tid,
        "comm": comm_str(&who.val.comm),
        "uid": who.val.uid,
        "cgroup": who.val.cgroup,
        "stack": {
            "id": who.val.stack,
            "frames": symbolize_with(&who.stack_ips, table).into_iter().map(|frame| {
                json!({"ip": frame.ip, "sym": frame.sym})
            }).collect::<Vec<_>>(),
        },
        "calls": who.val.calls,
        "first_ns": who.val.first_ns,
        "last_ns": who.val.last_ns,
    });
    if parent_resolved {
        payload["ppid"] = json!(who.val.ppid);
        payload["pcomm"] = json!(comm_str(&who.val.pcomm));
    }
    if let Some(params) = &who.params {
        payload["blocksize"] = json!(params.blocksize);
        payload["ivsize"] = json!(params.ivsize);
        payload["min_keysize"] = json!(params.min_keysize);
        payload["max_keysize"] = json!(params.max_keysize);
    }
    if let Some(errno) = render_first_errno(who.first_errno) {
        payload["first_errno"] = json!(errno);
    }
    NativeObservation {
        id,
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Discovered,
        call_kind: CallKind::Unknown,
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(who.val.first_ns),
        ended_ns: Some(who.val.last_ns),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: payload,
    }
}

// ---------------------------------------------------------------------------
// D10 integrity mapping (exact).
// ---------------------------------------------------------------------------

/// D10 over snapshot data: `ring_reservation_failures ← drops`,
/// `state_insert_failures ← KTOT − ΣKAGG` calls gap `+ who_drops`
/// (saturating; the KAGG/KIDN-full volume plus the KWHO-family
/// attribution-insert loss — chase-failures skip KTOT so are excluded),
/// other 7 counters zero with N/A reasons. Pure over rows so the PARTIAL
/// path pins unprivileged; `finalize` wires it to a live snapshot.
fn integrity_for_snapshot(
    snap: &SnapshotRows,
    drops: u8,
    who_drops: u64,
) -> Result<IntegritySummary, BackendError> {
    let reparse = |err: BackendError| {
        BackendError::Internal(InternalError::with_detail(
            "kcrypto_finalize_read",
            &format!("row reparse: {err}"),
        ))
    };
    let mut agg_calls = 0u64;
    for row in &snap.rows {
        match parse_snapshot_row(&row.0).map_err(reparse)? {
            ParsedRow::Agg { vagg, .. } => {
                agg_calls = agg_calls.saturating_add(vagg.calls);
            }
            _ => {
                return Err(BackendError::Internal(InternalError::new(
                    "kcrypto_finalize_row_kind",
                )));
            }
        }
    }
    let totals_calls = match &snap.totals {
        // Array map: live-impossible; with no baseline, claim no gap.
        None => None,
        Some(totals) => match parse_snapshot_row(&totals.0).map_err(reparse)? {
            ParsedRow::Totals { vagg } => Some(vagg.calls),
            _ => {
                return Err(BackendError::Internal(InternalError::new(
                    "kcrypto_finalize_row_kind",
                )));
            }
        },
    };
    integrity_for_counts(agg_calls, totals_calls, drops, who_drops)
}

/// D10 over call counts (M5 core): `ring_reservation_failures ←
/// drops`, `state_insert_failures ← KTOT − ΣKAGG calls gap `+`
/// who_drops` (saturating). No baseline (missing totals) claims no
/// gap. Infallible in practice (`Result` keeps the wrapper's error
/// channel shape).
fn integrity_for_counts(
    agg_calls: u64,
    totals_calls: Option<u64>,
    drops: u8,
    who_drops: u64,
) -> Result<IntegritySummary, BackendError> {
    let gap = totals_calls.map_or(0, |totals| totals.saturating_sub(agg_calls));
    Ok(IntegritySummary {
        ring_reservation_failures: u64::from(drops),
        state_insert_failures: gap.saturating_add(who_drops),
        // N/A: v0.1 short-lived drain keeps no queue accounting (queue pins 0 via the shared feed).
        user_queue_drops: 0,
        // N/A: BPF maps never evict; full-map loss accrues above via the KTOT gap.
        state_evictions: 0,
        // N/A: single-edge fexit sensor (no entry/return pairing).
        unmatched_entries: 0,
        // N/A: single-edge fexit sensor (no entry/return pairing).
        unmatched_returns: 0,
        // N/A: no correlation state (C10-unattributed observations).
        correlation_overflows: 0,
        // N/A: single-generation sensor (generation guards configure, not events).
        unknown_generation_events: 0,
        // N/A: decode charges no budget (budgets gate configure only).
        budget_omissions: 0,
    })
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
        let file = std::env::temp_dir().join("kryprobe-k3-1-backend-cand.o");
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
        std::fs::remove_file(&file).ok();
        let missing = PathBuf::from("/tmp/kryprobe-k3-1-backend-absent-9f2");
        let _ = std::fs::remove_dir_all(&missing);
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
        let file = std::env::temp_dir().join("kryprobe-k3-1-backend-cand-elev.o");
        std::fs::write(&file, b"object").expect("write tmp file");
        let exe = PathBuf::from("/exe/dir");
        assert_eq!(
            kcrypto_object_candidates(file.to_str(), Some(exe.as_path()), true),
            vec![PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o")]
        );
        std::fs::remove_file(&file).ok();
        // Elevated + unknown exe dir: no tiers at all (never fabricated).
        assert!(kcrypto_object_candidates(Some("/tmp/x"), None, true).is_empty());
    }

    #[test]
    fn verify_object_pin_rules() {
        // Hex encoding pins the standard sha256("abc") vector.
        assert_eq!(
            object_digest_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Empty pins (dev build): verification skipped.
        assert!(verify_object_pinned(b"anything", &[]).is_ok());
        // Pinned digest matches.
        let digest = object_digest_hex(b"release-object");
        assert!(verify_object_pinned(b"release-object", &[digest.as_str()]).is_ok());
        // Mismatch fails loud with the failure named.
        let err = verify_object_pinned(b"tampered-object", &[digest.as_str()])
            .expect_err("tampered bytes must not verify");
        assert!(err.contains("untrusted object"), "names the failure: {err}");
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
            calls,
            bytes: 0,
            ok: calls,
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
        let probe =
            std::env::temp_dir().join(format!("kryprobe-k3-merge-stage-{}", std::process::id()));
        std::fs::write(&probe, b"token").expect("write probe");
        let file = std::fs::File::open(&probe).expect("open probe");
        backend.stage_session_inputs(vec![0x7f, b'E', b'L', b'F'], Some(file));
        let first = backend.take_staged_inputs();
        assert_eq!(first.object, Some(vec![0x7f, b'E', b'L', b'F']));
        assert!(first.token.is_some(), "staged token drains");
        let second = backend.take_staged_inputs();
        assert_eq!(second.object, None, "bytes drain once");
        assert!(second.token.is_none(), "token drains once");
        std::fs::remove_file(&probe).ok();
    }
}
