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
//! [`crate::mapops`], like [`snapshot_rows`]) into [`WhoSnapshot`]s;
//! who-row decode is Task 4.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use kryprobe_abi::kcrypto_agg::{
    KAgg, KCTL_IDENT, KCTL_OVERFLOW, KCTX_KTHREAD, KCTX_PROC, KCTX_SOFTIRQ, KCTX_UNKNOWN, KCtl,
    KFAM_AEAD, KFAM_AHASH, KFAM_ANY, KFAM_SHASH, KFAM_SK, KIDN_DROPS, KOP_ALLOC, KOP_DEC,
    KOP_DESTROY, KOP_DIGEST, KOP_ENC, KOP_FINUP, KRES_ERR, KRES_OK, KRES_QUEUED, KRES_UNOBSERVED,
    KWHO_DROPS, KWhoKey, VAgg, VParams, VWho, kctl_unpack_lens, kwho_key_from_bytes,
    vparams_from_bytes, vwho_from_bytes,
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

use crate::bpfloader::PointStatus;
use crate::btf_resolve::{
    AttachOutcome, BtfError, ConfiguredError, ConfiguredKcrypto, ConfiguredPoint, KCRYPTO_SYMBOLS,
    load_kcrypto_configured, resolve_btf_ids,
};
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
/// `KRING`, `KCFG` (the `StateEntries` charge on first configure).
const KCRYPTO_MAP_COUNT: u64 = 5;

/// Payload note on `UNOBSERVED` rows (unreachable-by-construction: only the
/// void destroy path carries this class, and it emits no rows).
const UNOBSERVED_NOTE: &str = "unobserved: void return carries no result class (destroy path)";

/// Kernel-crypto backend: a system-wide fexit sensor owned by `configure`
/// plus a decode counter. `Send + Sync` via the mutex + atomics (the sensor
/// is fd-backed, no interior aliasing).
pub struct KCryptoBackend {
    state: Mutex<Option<(PlanGeneration, ConfiguredKcrypto)>>,
    decoded: AtomicUsize,
}

impl std::fmt::Debug for KCryptoBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KCryptoBackend")
            .field("decoded", &self.decoded.load(Ordering::SeqCst))
            .field(
                "configured",
                &self.state.lock().map(|s| s.is_some()).unwrap_or(false),
            )
            .finish()
    }
}

impl KCryptoBackend {
    /// Unconfigured backend: no sensor, zero decoded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
            decoded: AtomicUsize::new(0),
        }
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
#[must_use]
pub fn kcrypto_object_candidates(env: Option<&str>, exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(value) = env {
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
    out.push(PathBuf::from(DEV_OBJECT));
    out
}

/// D2 consolidated locator (replaces both K2 copies): first readable
/// candidate wins; a total miss reports every tried path + fs error in
/// try order (the K2 doctor wrapper vocabulary is preserved).
pub fn locate_kcrypto_object() -> Result<PathBuf, ObjectLocateError> {
    let env = std::env::var("KRYPROBE_BPF_DIR").ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let mut misses = Vec::new();
    for candidate in kcrypto_object_candidates(env.as_deref(), exe_dir.as_deref()) {
        match std::fs::read(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(err) => misses.push(LocateMiss {
                candidate,
                error: err.to_string(),
            }),
        }
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
    let path = locate_kcrypto_object().map_err(|err| {
        BackendError::Unsupported(UnsupportedReason::with_detail(
            "kcrypto_object_unreadable",
            &err.to_string(),
        ))
    })?;
    std::fs::read(&path).map_err(|err| {
        BackendError::Unsupported(UnsupportedReason::with_detail(
            "kcrypto_object_unreadable",
            &format!("{}: {err}", path.display()),
        ))
    })
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

/// Fold per-CPU `VWho` lanes into one total (the [`fold_vagg`](kryprobe_abi::kcrypto_agg::fold_vagg)
/// contract for who rows): `calls` sums saturating; `first_ns` is the
/// minimum over lanes with `calls > 0` (idle lanes hold insert-time
/// stamps with `calls == 0` and must not poison the min — the BPF
/// broadcasts the insert value to every lane, then updates only the
/// inserting CPU's lane); `last_ns` is the maximum; both stamps are 0
/// when no lane observed anything. Identity fields come from the
/// most-recent-writer lane (greatest `last_ns`, first on ties):
/// `tid`/`comm` are last-writer per lane, the rest are insert-identical
/// across lanes. Total over any lane slice (empty folds to zero).
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

/// Snapshot the K5 attribution maps of a configured sensor: full `KWHO`
/// walk (key iteration + percpu fold) with per-row `KSTACK`/`KERR`/
/// `KPARAMS` joins, plus the `KWHO_DROPS` insert-loss count. Map order.
///
/// Join-miss discipline (fail-soft, never fatal): a negative `stack`
/// (raw helper errno — no `KSTACK` row) or an absent `KSTACK` row yields
/// empty `stack_ips`; an absent `KERR`/`KPARAMS` row yields `None`.
/// Structural failures (walk errors, short reads, undecodable lanes)
/// fail the whole snapshot as [`SnapshotError::Map`] (a broken
/// post-attach read must be loud, never a silent zero).
pub fn snapshot_who(maps: &ConfiguredKcrypto) -> Result<(Vec<WhoSnapshot>, u64), SnapshotError> {
    let ncpu = possible_cpus() as usize;
    let mut out = Vec::new();
    let mut key: Option<Vec<u8>> = None;
    loop {
        let next = map_get_next_key(
            &maps.loaded.maps.who,
            key.as_deref(),
            16,
            "snapshot/who-iter",
        )?;
        let Some(k) = next else { break };
        let who_key = kwho_key_from_bytes(&k).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/who-key".to_owned(),
            errno: libc::EBADMSG,
        })?;
        let raw = map_lookup_bytes(&maps.loaded.maps.who, &k, 80 * ncpu, "snapshot/who-val")?;
        let mut lanes = Vec::with_capacity(ncpu);
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
        let stack_ips = if val.stack >= 0 {
            match map_lookup_bytes(
                &maps.loaded.maps.stack,
                &(val.stack as u32).to_le_bytes(),
                1016,
                "snapshot/who-stack",
            ) {
                Ok(raw) => stack_ips_from_bytes(&raw),
                Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => Vec::new(),
                Err(err) => return Err(err.into()),
            }
        } else {
            Vec::new()
        };
        let first_errno = match map_lookup_bytes(
            &maps.loaded.maps.err,
            &who_key.kh.to_le_bytes(),
            4,
            "snapshot/who-err",
        ) {
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
        let params = match map_lookup_bytes(
            &maps.loaded.maps.params,
            &who_key.kh.to_le_bytes(),
            16,
            "snapshot/who-params",
        ) {
            Ok(raw) => Some(
                vparams_from_bytes(&raw).ok_or_else(|| MapOpsError::LookupFailed {
                    stage: "snapshot/who-params".to_owned(),
                    errno: libc::EBADMSG,
                })?,
            ),
            Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => None,
            Err(err) => return Err(err.into()),
        };
        out.push(WhoSnapshot {
            key: who_key,
            val,
            stack_ips,
            first_errno,
            params,
        });
        key = Some(k);
    }
    let drops = match map_lookup_bytes(
        &maps.loaded.maps.ident,
        &KWHO_DROPS.to_le_bytes(),
        1,
        "snapshot/who-drops",
    ) {
        Ok(value) => u64::from(value.first().copied().unwrap_or(0)),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => 0,
        Err(err) => return Err(err.into()),
    };
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
    let mut payload = json!({
        "row": "agg",
        "family": family_name(fam),
        "op": op_name(op),
        "result": result_name(res),
        "algorithm": name_from_words(&kagg.alg()),
        "driver": name_from_words(&kagg.drv()),
        "context": context_name(ctx),
        "counts": {"calls": vagg.calls, "ok": vagg.ok, "errors": vagg.errors, "queued": vagg.queued},
        "bytes": vagg.bytes,
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

// ---------------------------------------------------------------------------
// D10 integrity mapping (exact).
// ---------------------------------------------------------------------------

/// `KIDN[KIDN_DROPS]` ring-reserve counter: absent key reads healthy-zero
/// (the Task-1 idiom); any other map failure is a defect marker (a broken
/// post-attach read must be loud, never a silent zero).
fn finalize_drops(sensor: &ConfiguredKcrypto) -> Result<u8, BackendError> {
    match map_lookup_bytes(
        &sensor.loaded.maps.ident,
        &KIDN_DROPS.to_le_bytes(),
        1,
        "kcrypto_backend/finalize-drops",
    ) {
        Ok(value) => Ok(value.first().copied().unwrap_or(0)),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => Ok(0),
        Err(err) => Err(BackendError::Internal(InternalError::with_detail(
            "kcrypto_finalize_read",
            &err.to_string(),
        ))),
    }
}

/// D10 over snapshot data: `ring_reservation_failures ← drops`,
/// `state_insert_failures ← KTOT − ΣKAGG` calls gap (saturating; the
/// KAGG/KIDN-full volume — chase-failures skip KTOT so are excluded),
/// other 7 counters zero with N/A reasons. Pure over rows so the PARTIAL
/// path pins unprivileged; `finalize` wires it to a live snapshot.
fn integrity_for_snapshot(
    snap: &SnapshotRows,
    drops: u8,
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
    let gap = match &snap.totals {
        // Array map: live-impossible; with no baseline, claim no gap.
        None => 0,
        Some(totals) => match parse_snapshot_row(&totals.0).map_err(reparse)? {
            ParsedRow::Totals { vagg } => vagg.calls.saturating_sub(agg_calls),
            _ => {
                return Err(BackendError::Internal(InternalError::new(
                    "kcrypto_finalize_row_kind",
                )));
            }
        },
    };
    Ok(IntegritySummary {
        ring_reservation_failures: u64::from(drops),
        state_insert_failures: gap,
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
        // NOTE (accepted): the check and the stash are not atomic across
        // the load — two threads configuring the SAME new generation
        // concurrently could both load and both charge (the loser's
        // sensor drops via RAII: no leak, no half-state). Unreachable in
        // practice: the driver drives the lifecycle single-threaded and
        // no concurrent caller exists; re-check under the lock before
        // charging if that ever changes.
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
        // First call (or a new generation): direct-privileged bring-up.
        let bytes = kcrypto_object_bytes()?;
        let (sensor, _points) =
            load_kcrypto_configured(&bytes, None).map_err(configured_error_to_backend)?;
        // Charge only after the load succeeds (a failed configure charges
        // nothing); the sensor stashes only after the charges land, so a
        // refused charge drops the fresh sensor and keeps prior state.
        charge(ctx, BudgetKind::Links, sensor.links.len() as u64)?;
        charge(ctx, BudgetKind::StateEntries, KCRYPTO_MAP_COUNT)?;
        *self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Some((ctx.generation, sensor));
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
        self.decoded.fetch_add(1, Ordering::SeqCst);
        Ok(observation)
    }

    fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        let observations = self.decoded.load(Ordering::SeqCst) as u64;
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
        // End-of-session assessment over a fresh snapshot (the ring drain
        // lands here too — the session is over, nothing else consumes it).
        let snap = snapshot_rows(sensor).map_err(|err| {
            BackendError::Internal(InternalError::with_detail(
                "kcrypto_finalize_read",
                &format!("snapshot: {err}"),
            ))
        })?;
        let drops = finalize_drops(sensor)?;
        Ok(BackendSummary {
            backend: BackendId::KCrypto,
            observations,
            integrity: integrity_for_snapshot(&snap, drops)?,
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
        // 3 lanes: one idle (insert-time stamps, calls 0 — must not
        // poison the first-min), two busy. calls sums; first is the min
        // over BUSY lanes; last is the max; identity rides the
        // most-recent-writer lane (greatest last_ns).
        let lanes = [
            vwho_lane(b'a', 11, 5, 0, 100, 100), // idle inserter copy
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
            kcrypto_object_candidates(file.to_str(), Some(exe.as_path())),
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
            kcrypto_object_candidates(missing.to_str(), None),
            vec![
                missing.join("kcrypto.bpf.o"),
                PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
            ]
        );
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

    /// Hand 382B agg row with `calls` observations.
    fn hand_agg(calls: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(382);
        out.push(0x01);
        out.push(1);
        out.extend_from_slice(&[KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC]);
        out.extend_from_slice(b"cbc(aes)\0");
        out.extend_from_slice(&vec![0u8; 260 - 4 - 9]);
        out.extend_from_slice(&calls.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // bytes
        out.extend_from_slice(&calls.to_le_bytes()); // ok
        out.extend_from_slice(&[0u8; 120 - 24]);
        assert_eq!(out.len(), 382);
        out
    }

    /// Hand 122B totals row with `calls` observations.
    fn hand_totals(calls: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(122);
        out.push(0x01);
        out.push(2);
        out.extend_from_slice(&calls.to_le_bytes());
        out.extend_from_slice(&640u64.to_le_bytes()); // bytes
        out.extend_from_slice(&calls.to_le_bytes()); // ok
        out.extend_from_slice(&[0u8; 120 - 24]);
        assert_eq!(out.len(), 122);
        out
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
            monotonic_ns: 7,
        }
    }

    #[test]
    fn partial_path_gap_reports_with_totals_preserved() {
        // Gap > 0 -> state_insert_failures == gap (PARTIAL path, unpriv).
        let snap = hand_snapshot(&[10, 20], Some(40));
        let integrity = integrity_for_snapshot(&snap, 0).expect("gap maps");
        assert_eq!(integrity.state_insert_failures, 10, "KTOT(40) - ΣKAGG(30)");
        assert_eq!(integrity.ring_reservation_failures, 0);
        // Healthy: no gap, drops ride through saturating.
        let snap = hand_snapshot(&[10, 20], Some(30));
        let integrity = integrity_for_snapshot(&snap, 3).expect("healthy maps");
        assert_eq!(integrity.state_insert_failures, 0);
        assert_eq!(integrity.ring_reservation_failures, 3);
        // Totals missing: no baseline, no gap claim (live-impossible).
        let snap = hand_snapshot(&[10], None);
        let integrity = integrity_for_snapshot(&snap, 0).expect("missing totals maps");
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
}
