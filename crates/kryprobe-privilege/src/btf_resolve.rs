// SPDX-License-Identifier: GPL-3.0-or-later
//! vmlinux BTF resolver: func ids + struct-member offsets, unprivileged.
//!
//! [`resolve_btf_ids`] finds the 9 P0 kcrypto attach symbols
//! (`evidence/k0/P0-btf-ids.txt`) and [`resolve_offsets`] returns the 9
//! explicit-offset reads the BPF needs (K0 P2 chain + `task_struct.flags`
//! for the kthread classifier + the C2 AEAD/ahash length reads + the
//! `crypto_shash.base` link (6.12 moved it to byte 8 — G6 option (a):
//! loader-side resolution, no CO-RE relocations)) and asserts the C3
//! first-member links at 0. Both parse `/sys/kernel/btf/vmlinux` raw
//! (world-readable; no privilege, no bpftool subprocess) with a strict
//! sequential walker: every truncation, unknown kind, or misaligned
//! member offset is [`BtfError`], never a guess.
//!
//! Micro-borrow: none — direct decode against the BTF spec
//! (`Documentation/bpf/btf.rst`, UAPI `linux/btf.h`).
//!
//! K1 Task 3 adds the CONFIG injection: [`kconfig_from_offsets`] (pure
//! 9-offsets + K5 attribution offsets → 76B projection) and
//! [`load_kcrypto_configured`] (the single resolve → load → write-KCFG
//! → attach entry K2 calls). K5 Task 3 adds [`resolve_kcrypto_offsets`]
//! (fail-soft parent/params offsets + flags for the KCFG tail).

use crate::attach::OwnedLink;
use crate::bpfloader::{LoadedKcrypto, LoaderError, PointStatus, load_kcrypto};
use crate::btf::Btf;
use crate::local::LocalPrivilegedAuthority;
use crate::mapops::{MapOpsError, map_update_bytes};
use kryprobe_abi::kcrypto_agg::KConfig;
use kryprobe_core::attach::{CookieAllocator, GenerationGuard, LinkGroup};
use kryprobe_core::authority::AttachAuthority;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::program::ProgramId;
use std::collections::HashMap;
use std::os::fd::RawFd;
use std::path::Path;

/// vmlinux BTF image (world-readable on the K0 host and the 6.12 guest).
const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// `PF_KTHREAD` — "I am a kernel thread" task flag.
///
/// Value from Linux `include/linux/sched.h`:
/// `#define PF_KTHREAD 0x00200000 /* I am a kernel thread */`
/// (verified against the installed
/// `linux-headers-7.0.0-31-generic/include/linux/sched.h:1781`).
pub const PF_KTHREAD: u32 = 0x0020_0000;

/// The 9 P0 kcrypto attach symbols (`evidence/k0/P0-btf-ids.txt`).
/// Single-definition statics in the crypto core: the first `FUNC`
/// record with the name is the attach target (K0 took the same row).
pub const KCRYPTO_SYMBOLS: &[&str] = &[
    "crypto_alloc_tfm_node",
    "crypto_destroy_tfm",
    "crypto_skcipher_encrypt",
    "crypto_skcipher_decrypt",
    "crypto_aead_encrypt",
    "crypto_aead_decrypt",
    "crypto_ahash_digest",
    "crypto_shash_digest",
    "crypto_shash_finup",
];

/// BTF resolution failure: I/O, malformed image, a missing record,
/// or a moved first-member link (C3 — the BPF hardcodes 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfError {
    /// BTF image I/O failure.
    Io {
        /// Failure detail.
        detail: String,
    },
    /// BTF image is malformed.
    BadBtf {
        /// Rejection reason.
        reason: String,
    },
    /// Function record absent from BTF.
    MissingFunc {
        /// Missing function name.
        name: String,
    },
    /// Type record absent from BTF.
    MissingType {
        /// Missing type name.
        name: String,
    },
    /// Struct member absent from its type.
    MissingMember {
        /// Containing type name.
        type_name: String,
        /// Missing member name.
        member: String,
    },
    /// First-member link moved off offset 0 (the BPF hardcodes 0).
    FirstMemberMoved {
        /// Containing type name.
        type_name: String,
        /// Moved member name.
        member: String,
        /// Observed nonzero offset.
        offset: u32,
    },
    /// Function prototype incompatible with the lifecycle sensor's
    /// reads (arg0 must be a request pointer, return a 32-bit int).
    BadPrototype {
        /// Function name.
        name: String,
        /// Incompatibility detail.
        reason: String,
    },
}

impl std::fmt::Display for BtfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { detail } => write!(f, "BTF I/O: {detail}"),
            Self::BadBtf { reason } => write!(f, "malformed BTF: {reason}"),
            Self::MissingFunc { name } => write!(f, "BTF has no FUNC '{name}'"),
            Self::MissingType { name } => write!(f, "BTF has no struct '{name}'"),
            Self::MissingMember { type_name, member } => {
                write!(f, "BTF struct '{type_name}' has no member '{member}'")
            }
            Self::FirstMemberMoved {
                type_name,
                member,
                offset,
            } => {
                write!(
                    f,
                    "BTF struct '{type_name}' member '{member}' moved to byte {offset} (BPF hardcodes 0)"
                )
            }
            Self::BadPrototype { name, reason } => {
                write!(f, "BTF FUNC '{name}' prototype refused: {reason}")
            }
        }
    }
}

impl std::error::Error for BtfError {}

/// K5 attribution offsets: the 7 BPF parent/params chase offsets
/// (all u32 byte offsets) plus the two fail-soft gate flags.
///
/// Group-atomic by contract: `parent_ok` is true iff ALL three parent
/// members resolve (else all three offsets are 0); `params_ok` is true
/// iff ALL four params members resolve (else all four are 0). The BPF
/// gates each chase on its flag, and userspace omits the gated keys
/// when the flag is false — never zero-filled in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcryptoOffsets {
    /// `task_struct.real_parent` (bytes; K5 parent chase).
    pub task_real_parent: u32,
    /// `task_struct.tgid` (bytes; K5 parent chase).
    pub task_tgid: u32,
    /// `task_struct.comm` (bytes; K5 parent chase).
    pub task_comm: u32,
    /// `crypto_alg.cra_blocksize` (bytes; K5 crypto params).
    pub cra_blocksize: u32,
    /// `crypto_alg.cra_ivsize` (bytes; K5 crypto params).
    pub cra_ivsize: u32,
    /// `crypto_alg.cra_min_keysize` (bytes; K5 crypto params).
    pub cra_min_keysize: u32,
    /// `crypto_alg.cra_max_keysize` (bytes; K5 crypto params).
    pub cra_max_keysize: u32,
    /// True iff all three parent offsets resolved.
    pub parent_ok: bool,
    /// True iff all four params offsets resolved.
    pub params_ok: bool,
}

/// K5 attribution-offset resolution failure: the BTF image itself is
/// unreadable or malformed. Unresolvable MEMBERS never surface here —
/// they yield `*_ok=false` + zeros inside [`KcryptoOffsets`] (fail-soft).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// BTF image I/O failure.
    Io {
        /// Failure detail.
        detail: String,
    },
    /// BTF image is malformed.
    BadBtf {
        /// Rejection reason.
        reason: String,
    },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { detail } => write!(f, "BTF I/O: {detail}"),
            Self::BadBtf { reason } => write!(f, "malformed BTF: {reason}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Lossless promotion into the configured bring-up error (both variants
/// carry their text across; the fail-soft member cases never construct
/// a [`ResolveError`], so no information is dropped here).
impl From<ResolveError> for BtfError {
    fn from(err: ResolveError) -> Self {
        match err {
            ResolveError::Io { detail } => Self::Io { detail },
            ResolveError::BadBtf { reason } => Self::BadBtf { reason },
        }
    }
}

/// Explicit-offset reads for the kcrypto BPF (all u32 byte offsets):
/// the K0 P2 identity chain plus `task_struct.flags` (kthread via
/// [`PF_KTHREAD`]) plus the AEAD/ahash length reads (C2). Enter the BPF
/// via the CONFIG map (G6 option (a)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoOffsets {
    /// `skcipher_request.base`.
    pub sk_req_base: u32,
    /// `crypto_async_request.tfm`.
    pub async_tfm: u32,
    /// `crypto_tfm.__crt_alg`.
    pub tfm_alg: u32,
    /// `crypto_alg.cra_name`.
    pub alg_name: u32,
    /// `crypto_alg.cra_driver_name`.
    pub alg_drv: u32,
    /// `task_struct.flags`.
    pub task_flags: u32,
    /// `aead_request.cryptlen` (C2: AEAD bytes).
    pub aead_cryptlen_off: u32,
    /// `ahash_request.nbytes` (C2: ahash bytes).
    pub ahash_nbytes_off: u32,
    /// `crypto_shash.base` (shash tfm link; @0 on 7.0, @8 on 6.12 —
    /// CONFIG-resolved so the reorder resolves instead of refusing).
    pub shash_base: u32,
}

/// Process-lifetime vmlinux BTF image (H1(a)): the sysfs image is
/// boot-pinned (content-stable per boot; a reread mid-session could
/// only observe the same bytes), so one read serves every resolver in
/// the process. Failures are NOT cached (read-then-store: only a
/// successful read is stored) — a BTF that appears late still
/// resolves late. Two racing first readers may both read; one image
/// wins and both observe identical bytes.
static VMLINUX_BTF_BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// Shared BTF image bytes; the detail string keeps the exact
/// historical `{VMLINUX_BTF}: {err}` shape for all error channels.
fn vmlinux_btf_bytes() -> Result<&'static [u8], String> {
    if let Some(cached) = VMLINUX_BTF_BYTES.get() {
        return Ok(cached);
    }
    let bytes = std::fs::read(VMLINUX_BTF).map_err(|err| format!("{VMLINUX_BTF}: {err}"))?;
    Ok(VMLINUX_BTF_BYTES.get_or_init(|| bytes))
}

/// Resolve the 9 [`KCRYPTO_SYMBOLS`] to vmlinux BTF ids. Unprivileged.
/// Every symbol must resolve; the first missing one fails the whole
/// call (fail-closed: a half map would silently drop attach points).
pub fn resolve_btf_ids() -> Result<HashMap<String, u32>, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    resolve_btf_ids_from(bytes)
}

/// Resolve the 9 [`CryptoOffsets`] from vmlinux BTF. Unprivileged.
///
/// Fail-closed on the C3 first-member links: the BPF hardcodes 0 for
/// the four [`FIRST_MEMBER_LINKS`] below, so any nonzero live offset is
/// [`BtfError::FirstMemberMoved`] (a kernel struct reorder must refuse
/// here, never mis-chase in BPF). The retired fifth link
/// (`crypto_shash.base`) is CONFIG-resolved instead (see [`CryptoOffsets::shash_base`]):
/// a missing member still fails closed as [`BtfError::MissingMember`].
pub fn resolve_offsets() -> Result<CryptoOffsets, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    resolve_offsets_from(bytes)
}

/// Resolve the 7 K5 attribution offsets from vmlinux BTF. Unprivileged.
///
/// Fail-soft per group (never `Err` for members): each unresolvable
/// member zeroes its whole group (`parent_ok`/`params_ok` false + group
/// zeros). Hard [`ResolveError`] only when BTF itself is unreadable
/// (I/O) or malformed (parse) — the image both callers and the BPF
/// chase trust must be intact, or nothing resolves.
///
/// Params members resolve as DIRECT `crypto_alg` members (the BPF adds
/// these offsets to the chased `__crt_alg` pointer with no family
/// knowledge). On this kernel only `cra_blocksize` exists there: the
/// iv/keysize members live in the per-family containers at NEGATIVE,
/// family-DIFFERING offsets from the embedded `base` (bpftool-proven on
/// 7.0: skcipher min/max/iv 20/16/12 bytes BEFORE base, aead iv 12
/// bytes before base with no key members, hashes with neither) — so
/// no single base-relative
/// offset set could serve all families, and `params_ok=false` (with the
/// whole params group zeroed) is the CORRECT verdict here, not a gap:
/// emitting family-wrong params would be mislabeled garbage.
pub fn resolve_kcrypto_offsets() -> Result<KcryptoOffsets, ResolveError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| ResolveError::Io { detail })?;
    resolve_kcrypto_offsets_from(bytes)
}

/// All three bringup resolutions over one BTF image with ONE parse
/// (H1(a)): func ids + crypto offsets (fail-closed) + K5 groups
/// (fail-soft inside the struct, never `Err`). Only the parse and the
/// two fail-closed resolutions can fail, as [`BtfError`].
fn resolve_kcrypto_bringup_from(
    bytes: &[u8],
) -> Result<(HashMap<String, u32>, CryptoOffsets, KcryptoOffsets), BtfError> {
    let btf = Btf::parse(bytes)?;
    let ids = btf_ids_from_btf(&btf)?;
    let off = offsets_from_btf(&btf)?;
    // Fail-soft member cases ride INSIDE `k5` (flags + zeros); only a
    // BTF image that vanished mid-bring-up fails here (fail-closed: the
    // two resolutions above already trusted that same image).
    let k5 = kcrypto_offsets_from_btf(&btf);
    Ok((ids, off, k5))
}

/// [`resolve_kcrypto_offsets`] over an injected BTF image (test seam).
fn resolve_kcrypto_offsets_from(bytes: &[u8]) -> Result<KcryptoOffsets, ResolveError> {
    let btf = Btf::parse(bytes).map_err(|err| match err {
        BtfError::BadBtf { reason } => ResolveError::BadBtf { reason },
        // Defensive: the parser only emits `BadBtf` today; any other
        // shape still means "BTF unusable", with its text preserved.
        other => ResolveError::BadBtf {
            reason: other.to_string(),
        },
    })?;
    Ok(kcrypto_offsets_from_btf(&btf))
}

/// K5 group resolution over an already-parsed image (H1(a) combo
/// core). Infallible by design: any member error (missing
/// type/member, or a misaligned offset the BPF could not use) is
/// "unresolvable" → group fail-soft, never Err.
fn kcrypto_offsets_from_btf(btf: &Btf) -> KcryptoOffsets {
    // Any member error (missing type/member, or a misaligned offset the
    // BPF could not use) is "unresolvable" → group fail-soft, never Err.
    let parent = (
        btf.member_offset("task_struct", "real_parent").ok(),
        btf.member_offset("task_struct", "tgid").ok(),
        btf.member_offset("task_struct", "comm").ok(),
    );
    let params = (
        btf.member_offset("crypto_alg", "cra_blocksize").ok(),
        btf.member_offset("crypto_alg", "cra_ivsize").ok(),
        btf.member_offset("crypto_alg", "cra_min_keysize").ok(),
        btf.member_offset("crypto_alg", "cra_max_keysize").ok(),
    );
    let (parent_ok, (task_real_parent, task_tgid, task_comm)) = match parent {
        (Some(rp), Some(tgid), Some(comm)) => (true, (rp, tgid, comm)),
        _ => (false, (0, 0, 0)),
    };
    let (params_ok, (cra_blocksize, cra_ivsize, cra_min_keysize, cra_max_keysize)) = match params {
        (Some(bs), Some(iv), Some(min), Some(max)) => (true, (bs, iv, min, max)),
        _ => (false, (0, 0, 0, 0)),
    };
    KcryptoOffsets {
        task_real_parent,
        task_tgid,
        task_comm,
        cra_blocksize,
        cra_ivsize,
        cra_min_keysize,
        cra_max_keysize,
        parent_ok,
        params_ok,
    }
}

/// Pure CONFIG projection (K1 Task 3 head + K5 Task 3 tail): the 9
/// resolved offsets + [`PF_KTHREAD`] + zero pad → the 76B [`KConfig`]
/// in C2 word order, with the 7 K5 attribution offsets + flags
/// (`parent_ok`/`params_ok` nonzero iff the group resolved — a false
/// flag pairs with group zeros by [`resolve_kcrypto_offsets`]).
/// Total (no failure mode: every input word is copied verbatim).
#[must_use]
pub fn kconfig_from_offsets(off: CryptoOffsets, k5: KcryptoOffsets) -> KConfig {
    KConfig {
        sk_req_base: off.sk_req_base,
        async_tfm: off.async_tfm,
        tfm_alg: off.tfm_alg,
        alg_name: off.alg_name,
        alg_drv: off.alg_drv,
        task_flags: off.task_flags,
        pf_kthread: PF_KTHREAD,
        aead_cryptlen_off: off.aead_cryptlen_off,
        ahash_nbytes_off: off.ahash_nbytes_off,
        shash_base: off.shash_base,
        _pad: 0,
        task_real_parent: k5.task_real_parent,
        task_tgid: k5.task_tgid,
        task_comm: k5.task_comm,
        cra_blocksize: k5.cra_blocksize,
        cra_ivsize: k5.cra_ivsize,
        cra_min_keysize: k5.cra_min_keysize,
        cra_max_keysize: k5.cra_max_keysize,
        parent_ok: u8::from(k5.parent_ok),
        params_ok: u8::from(k5.params_ok),
        _pad2: [0, 0],
    }
}

/// Per-point attach outcome for a loaded kcrypto program.
///
/// Maps [`PointStatus::Loaded`] forward to the attach-time export the
/// Task-1 handoff promises `doctor`: `Missing`/`Unsupported` points
/// already degrade at load and carry no attach outcome (`None` on
/// [`ConfiguredPoint::attach`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachOutcome {
    /// Tracing link created; the point observes system-wide.
    Attached,
    /// Load succeeded but the link failed; `detail` is the refusal.
    Failed {
        /// Link refusal detail.
        detail: String,
    },
}

/// One configured attach point: load outcome + (when loaded) attach outcome.
///
/// `load` is the [`load_kcrypto`] verdict, never swallowed: K2 routes
/// `Missing`/`Unsupported` to its degraded-coverage export and
/// `Loaded`+`Attached` to live points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredPoint {
    /// Program name (carries the `fexit/<symbol>` section's program).
    pub name: String,
    /// Load outcome from [`load_kcrypto`].
    pub load: PointStatus,
    /// Attach outcome; `None` unless `load` is [`PointStatus::Loaded`].
    pub attach: Option<AttachOutcome>,
}

/// A fully configured kcrypto sensor: resolved, loaded, KCFG-written,
/// attached. RAII: drop detaches links, then closes progs/maps.
#[derive(Debug)]
pub struct ConfiguredKcrypto {
    /// Loaded maps + programs (only the programs that loaded).
    pub loaded: LoadedKcrypto,
    /// Live tracing links (only the points that attached), load order.
    pub links: Vec<(String, OwnedLink)>,
}

impl ConfiguredKcrypto {
    /// Duplicates the sensor handle (H1(b)): the clone snapshots the
    /// SAME kernel sensor (dup'd fds — no second attach, no double
    /// probe stream, no double map memory). Only used to hand the
    /// live tick loop its own handle onto the backend's sensor.
    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        let mut links = Vec::with_capacity(self.links.len());
        for (name, link) in &self.links {
            links.push((name.clone(), link.try_clone()?));
        }
        Ok(Self {
            loaded: self.loaded.try_clone()?,
            links,
        })
    }
}

/// Configured bring-up failure: resolution, load, KCFG write, group
/// minting, or a total attach failure. Per-point outcomes ride the
/// [`ConfiguredError::NoPointAttached`] variant (diagnosable, never
/// swallowed); every other stage fails before any point exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfiguredError {
    /// BTF resolution failed.
    Resolve(BtfError),
    /// Object load failed.
    Load(LoaderError),
    /// KCFG write failed.
    Configure(MapOpsError),
    /// Attach-group setup failed before any point existed.
    AttachSetup {
        /// Failure detail.
        detail: String,
    },
    /// No point attached; per-point outcomes ride along.
    NoPointAttached {
        /// Per-point load/attach outcomes (diagnosable).
        points: Vec<ConfiguredPoint>,
    },
    /// Another profile holds the process (no duplicate capture).
    SessionBusy {
        /// Profile currently live in this process.
        live: crate::kcrypto_lifecycle::profile::LifecycleProfile,
        /// Profile that was refused.
        want: crate::kcrypto_lifecycle::profile::LifecycleProfile,
    },
}

impl std::fmt::Display for ConfiguredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(err) => write!(f, "kcrypto resolve: {err}"),
            Self::Load(err) => write!(f, "kcrypto load: {err}"),
            Self::Configure(err) => write!(f, "kcrypto KCFG write: {err}"),
            Self::AttachSetup { detail } => {
                write!(f, "kcrypto attach setup: {detail}")
            }
            Self::NoPointAttached { points } => {
                write!(
                    f,
                    "kcrypto attach: no point attached ({} points)",
                    points.len()
                )
            }
            Self::SessionBusy { live, want } => {
                write!(
                    f,
                    "kcrypto session busy: '{}' is live, '{}' refused (no duplicate capture)",
                    live.as_str(),
                    want.as_str()
                )
            }
        }
    }
}

impl std::error::Error for ConfiguredError {}

impl ConfiguredError {
    /// Kernel errno when the bring-up error carries one, else `EIO`
    /// (generic I/O failure — the `bpf_sys::last_errno` fallback
    /// precedent). Moved here from the CLI (1B-M7): errno plumbing
    /// over privilege error types lives behind the boundary.
    #[must_use]
    pub fn bringup_errno(&self) -> i32 {
        match self {
            Self::Load(
                LoaderError::MapFailed { errno, .. } | LoaderError::LoadFailed { errno, .. },
            )
            | Self::Configure(
                MapOpsError::LookupFailed { errno, .. } | MapOpsError::UpdateFailed { errno, .. },
            ) => *errno,
            _ => libc::EIO,
        }
    }
}

/// Zero-identity object for system-wide groups (the fexit path never
/// reads it; same shape as the suite scaffolding).
pub(crate) fn system_object() -> ObjectRef {
    ObjectRef {
        dev: 0,
        ino: 0,
        size: 0,
        mtime: 0,
        role: ObjectRole::Executable,
    }
}

/// Single configured entry for K2: resolve BTF ids + offsets (+ K5
/// attribution offsets, fail-soft) → load → write KCFG → attach every
/// loaded point system-wide.
///
/// Physical order is resolve → load → write → attach (the KCFG write
/// needs the loaded map fd, so it cannot precede the load): KCFG lands
/// BEFORE any attach, so no observation runs unconfigured (the BPF
/// `pf_kthread` gate would skip it anyway).
///
/// `token_fd` reuses the [`load_kcrypto`] convention (`None` loads with
/// privilege, `Some` with a borrowed BPF token fd — threaded to map
/// create + prog load; `None` preserves today's behavior byte-for-byte).
/// The attach step carries no token field of its own (UAPI provides
/// none, and Task 1 proved the kernel demands no `link_create`
/// delegation: `DELEGATE_CMDS=map_create:prog_load`): a token-loaded
/// program remembers its token, and the kernel authorizes the fexit
/// link against it — so `Some` attaches work unprivileged against the
/// token-loaded progs, while `None` needs privilege as before.
/// Per-point outcomes surface in the returned [`ConfiguredPoint`]s in
/// parsed-program order (load verdict + attach verdict each).
///
/// Each link rides its own allocator-issued [`LinkGroup`] (generation
/// 1, single-shot bring-up issuance — the fexit attach ignores cookies
/// and only generation-guards, so group and guard share issuance and
/// never go stale) through the attach facet
/// (`AttachAuthority::attach_group` on [`LocalPrivilegedAuthority`]).
/// Each link group is labeled [`ProgramId::KCryptoFexit`] (1B-L3):
/// link groups, allowlist checks, and diagnostics identify kcrypto
/// programs as kcrypto — never as the uprobe self-probe.
///
/// Succeeds iff at least one point attaches (the load rule, mapped
/// forward); a total attach failure drops everything (RAII) and
/// returns the per-point outcomes in the error.
pub fn load_kcrypto_configured(
    object_bytes: &[u8],
    token_fd: Option<RawFd>,
) -> Result<(ConfiguredKcrypto, Vec<ConfiguredPoint>), ConfiguredError> {
    // H1(a): one shared image read (cached) + ONE parse serves all
    // three resolutions (was: 3 reads + 3 parses per load, 7 per
    // session with detect).
    let bytes =
        vmlinux_btf_bytes().map_err(|detail| ConfiguredError::Resolve(BtfError::Io { detail }))?;
    let (ids, off, k5) = resolve_kcrypto_bringup_from(bytes).map_err(ConfiguredError::Resolve)?;
    let entries: Vec<(String, u32)> = KCRYPTO_SYMBOLS
        .iter()
        .map(|name| ((*name).to_owned(), ids[*name]))
        .collect();
    let (loaded, statuses) =
        load_kcrypto(object_bytes, &entries, token_fd).map_err(ConfiguredError::Load)?;
    let cfg = kconfig_from_offsets(off, k5);
    map_update_bytes(
        &loaded.maps.config,
        &0u32.to_le_bytes(),
        &cfg.to_bytes(),
        "kcrypto_configured/kcfg",
    )
    .map_err(ConfiguredError::Configure)?;
    let authority = LocalPrivilegedAuthority;
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    let guard = GenerationGuard {
        generation: PlanGeneration::new(1),
    };
    let mut links: Vec<(String, OwnedLink)> = Vec::with_capacity(loaded.progs.len());
    let mut outcomes: Vec<(String, AttachOutcome)> = Vec::with_capacity(loaded.progs.len());
    for (name, prog) in &loaded.progs {
        let range = alloc
            .allocate(1)
            .map_err(|exhausted| ConfiguredError::AttachSetup {
                detail: format!("cookie range for {name}: {exhausted}"),
            })?;
        let group = LinkGroup::from_range(
            system_object(),
            ProgramId::KCryptoFexit,
            TargetScope::System,
            true,
            range,
        );
        match authority.attach_group(&group, &guard, prog, Path::new(""), &[]) {
            Ok(link) => {
                links.push((name.clone(), link));
                outcomes.push((name.clone(), AttachOutcome::Attached));
            }
            Err(err) => outcomes.push((
                name.clone(),
                AttachOutcome::Failed {
                    detail: err.to_string(),
                },
            )),
        }
    }
    let mut points = Vec::with_capacity(statuses.len());
    for status in &statuses {
        let attach = outcomes
            .iter()
            .find(|(name, _)| name == status.name())
            .map(|(_, outcome)| outcome.clone());
        points.push(ConfiguredPoint {
            name: status.name().to_owned(),
            load: status.clone(),
            attach,
        });
    }
    if links.is_empty() {
        return Err(ConfiguredError::NoPointAttached { points });
    }
    Ok((ConfiguredKcrypto { loaded, links }, points))
}

/// Resolve one struct-member byte offset from live vmlinux BTF.
/// Unprivileged. The exactness suite's C3 re-verification rides this
/// (same walker, same fail-closed errors — no second implementation).
pub fn resolve_member_offset(type_name: &str, member: &str) -> Result<u32, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    let btf = Btf::parse(bytes)?;
    btf.member_offset(type_name, member)
}

fn resolve_btf_ids_from(bytes: &[u8]) -> Result<HashMap<String, u32>, BtfError> {
    let btf = Btf::parse(bytes)?;
    btf_ids_from_btf(&btf)
}

/// Func-id resolution over an already-parsed image (H1(a): the
/// bringup combo parses once and shares the `Btf` across all three
/// resolutions instead of parsing per resolver).
fn btf_ids_from_btf(btf: &Btf) -> Result<HashMap<String, u32>, BtfError> {
    btf_ids_from_btf_for(btf, KCRYPTO_SYMBOLS)
}

/// Func-id resolution over an already-parsed image for an explicit
/// symbol list (T06 profile scoping: the caller names exactly the
/// symbols its profile needs — no more). Every symbol must resolve;
/// the first missing one fails the whole call (fail-closed: a half
/// map would silently drop attach points).
fn btf_ids_from_btf_for(btf: &Btf, symbols: &[&str]) -> Result<HashMap<String, u32>, BtfError> {
    let mut out = HashMap::with_capacity(symbols.len());
    for name in symbols {
        let id = btf.func_id(name)?.ok_or_else(|| BtfError::MissingFunc {
            name: (*name).to_owned(),
        })?;
        out.insert((*name).to_owned(), id);
    }
    Ok(out)
}

/// Resolve the request-lifecycle manifest's symbols to vmlinux BTF
/// ids (T06). Unprivileged. Profile-scoped: only the manifest's
/// required symbols resolve (today: the two api sites) — the full
/// 9-symbol api-returns set is a different profile's business.
/// Every resolved symbol's prototype is validated against the
/// sensor's reads (arg0 pointer, 32-bit int return); a name that
/// resolves with an incompatible shape refuses startup.
pub fn resolve_lifecycle_ids() -> Result<HashMap<String, u32>, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    resolve_lifecycle_ids_from(bytes)
}

/// Resolve + prototype-validate over an explicit BTF image (the
/// fixture seam: H02 drives synthetic images through this; the
/// vmlinux path above delegates after reading the bytes).
pub fn resolve_lifecycle_ids_from(bytes: &[u8]) -> Result<HashMap<String, u32>, BtfError> {
    use crate::kcrypto_lifecycle::profile::{LifecycleProfile, manifest};
    let btf = Btf::parse(bytes)?;
    let table = manifest(LifecycleProfile::RequestLifecycle);
    let symbols: Vec<&str> = table.required.iter().map(|s| s.symbol).collect();
    let ids = btf_ids_from_btf_for(&btf, &symbols)?;
    for name in &symbols {
        btf.lifecycle_proto_id(name)?;
    }
    Ok(ids)
}

/// C3 first-member links: struct/member pairs the BPF reads at
/// literal offset 0 (verified first members on the K1 host BTF; C
/// guarantees no padding before the initial member, so only a struct
/// reorder can move them — which fails closed below). The retired fifth
/// link (`crypto_shash.base`, @8 on 6.12) is CONFIG-resolved instead
/// ([`CryptoOffsets::shash_base`]).
pub const FIRST_MEMBER_LINKS: &[(&str, &str)] = &[
    ("aead_request", "base"),
    ("ahash_request", "base"),
    ("shash_desc", "tfm"),
    ("skcipher_request", "cryptlen"),
];

fn resolve_offsets_from(bytes: &[u8]) -> Result<CryptoOffsets, BtfError> {
    let btf = Btf::parse(bytes)?;
    offsets_from_btf(&btf)
}

/// Offset resolution over an already-parsed image (H1(a) combo core).
fn offsets_from_btf(btf: &Btf) -> Result<CryptoOffsets, BtfError> {
    let out = CryptoOffsets {
        sk_req_base: btf.member_offset("skcipher_request", "base")?,
        async_tfm: btf.member_offset("crypto_async_request", "tfm")?,
        tfm_alg: btf.member_offset("crypto_tfm", "__crt_alg")?,
        alg_name: btf.member_offset("crypto_alg", "cra_name")?,
        alg_drv: btf.member_offset("crypto_alg", "cra_driver_name")?,
        task_flags: btf.member_offset("task_struct", "flags")?,
        aead_cryptlen_off: btf.member_offset("aead_request", "cryptlen")?,
        ahash_nbytes_off: btf.member_offset("ahash_request", "nbytes")?,
        shash_base: btf.member_offset("crypto_shash", "base")?,
    };
    for (type_name, member) in FIRST_MEMBER_LINKS {
        let offset = btf.member_offset(type_name, member)?;
        if offset != 0 {
            return Err(BtfError::FirstMemberMoved {
                type_name: (*type_name).to_owned(),
                member: (*member).to_owned(),
                offset,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::{
        BTF_MAGIC, BTF_VERSION, Btf, KIND_FUNC, KIND_FUNC_PROTO, KIND_INT, KIND_STRUCT,
    };

    #[test]
    fn bringup_errno_prefers_carried_errno_else_eio() {
        // 1B-M7: errno plumbing lives here — carried errnos surface,
        // errno-less stages fall back to EIO (documented precedent).
        let carried = [
            ConfiguredError::Load(LoaderError::MapFailed {
                stage: "m".to_owned(),
                errno: 13,
            }),
            ConfiguredError::Load(LoaderError::LoadFailed {
                stage: "l".to_owned(),
                errno: 22,
                log: String::new(),
            }),
            ConfiguredError::Configure(MapOpsError::LookupFailed {
                stage: "k".to_owned(),
                errno: 2,
            }),
            ConfiguredError::Configure(MapOpsError::UpdateFailed {
                stage: "u".to_owned(),
                errno: 28,
            }),
        ];
        assert_eq!(
            carried
                .iter()
                .map(ConfiguredError::bringup_errno)
                .collect::<Vec<_>>(),
            vec![13, 22, 2, 28]
        );
        assert_eq!(
            ConfiguredError::AttachSetup {
                detail: "d".to_owned()
            }
            .bringup_errno(),
            libc::EIO
        );
    }

    /// Minimal synthetic BTF image builder (header + types + strtab).
    struct BtfBuild {
        strs: Vec<u8>,
        types: Vec<u8>,
    }

    impl BtfBuild {
        fn new() -> Self {
            Self {
                strs: vec![0],
                types: Vec::new(),
            }
        }

        fn str(&mut self, s: &str) -> u32 {
            let off = self.strs.len() as u32;
            self.strs.extend_from_slice(s.as_bytes());
            self.strs.push(0);
            off
        }

        fn word(&mut self, w: u32) {
            self.types.extend_from_slice(&w.to_le_bytes());
        }

        fn rec(&mut self, name: u32, kind: u8, vlen: u32, kind_flag: bool, size_ty: u32) {
            let flag = if kind_flag { 1u32 } else { 0 };
            self.word(name);
            self.word((u32::from(kind) << 24) | (vlen & 0xffff) | (flag << 31));
            self.word(size_ty);
        }

        fn member(&mut self, name: u32, ty: u32, bits: u32) {
            self.word(name);
            self.word(ty);
            self.word(bits);
        }

        fn finish(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            out.push(BTF_VERSION);
            out.push(0);
            out.extend_from_slice(&24u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.strs.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strs);
            out
        }
    }

    /// Synthetic image: FUNC `tfunc` (id 1), STRUCT `tstruct` (id 3)
    /// with `aaa`@0 and `bbb`@8, STRUCT `inner` (id 4) with `deep`@4,
    /// STRUCT `outer` (id 6) with `aaa`@0 + anonymous `inner`@4,
    /// STRUCT `bf` (id 7, kind-flagged) with `m1`@16.
    fn fixture() -> Vec<u8> {
        let mut b = BtfBuild::new();
        let o_func = b.str("tfunc");
        let o_struct = b.str("tstruct");
        let o_aaa = b.str("aaa");
        let o_bbb = b.str("bbb");
        let o_inner = b.str("inner");
        let o_deep = b.str("deep");
        let o_outer = b.str("outer");
        let o_bf = b.str("bf");
        let o_m1 = b.str("m1");
        // [1] FUNC tfunc -> [2], global linkage.
        b.rec(o_func, KIND_FUNC, 1, false, 2);
        // [2] FUNC_PROTO () -> [5].
        b.rec(0, KIND_FUNC_PROTO, 0, false, 5);
        // [3] STRUCT tstruct { aaa @0 bits, bbb @64 bits }.
        b.rec(o_struct, KIND_STRUCT, 2, false, 16);
        b.member(o_aaa, 5, 0);
        b.member(o_bbb, 5, 64);
        // [4] STRUCT inner { deep @32 bits }.
        b.rec(o_inner, KIND_STRUCT, 1, false, 8);
        b.member(o_deep, 5, 32);
        // [5] INT (member type).
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        // [6] STRUCT outer { aaa @0, <anon inner> @32 bits }.
        b.rec(o_outer, KIND_STRUCT, 2, false, 12);
        b.member(o_aaa, 5, 0);
        b.member(0, 4, 32);
        // [7] STRUCT bf, kind-flagged { m1: raw (0<<24)|128 bits }.
        b.rec(o_bf, KIND_STRUCT, 1, true, 24);
        b.member(o_m1, 5, 128);
        b.finish()
    }

    #[test]
    fn synthetic_ids_and_offsets_are_exact() {
        let bytes = fixture();
        let btf = Btf::parse(&bytes).expect("fixture must parse");
        assert_eq!(btf.func_id("tfunc").unwrap(), Some(1));
        assert_eq!(btf.func_id("nope").unwrap(), None);
        assert_eq!(btf.member_offset("tstruct", "aaa").unwrap(), 0);
        assert_eq!(btf.member_offset("tstruct", "bbb").unwrap(), 8);
        // Anonymous descent adds: outer.inner @4 + inner.deep @4.
        assert_eq!(btf.member_offset("outer", "deep").unwrap(), 8);
        // Kind-flagged bit offset: low 24 bits / 8.
        assert_eq!(btf.member_offset("bf", "m1").unwrap(), 16);
    }

    #[test]
    fn synthetic_missing_is_typed() {
        let bytes = fixture();
        let btf = Btf::parse(&bytes).expect("fixture must parse");
        assert!(matches!(
            btf.member_offset("nosuch", "aaa"),
            Err(BtfError::MissingType { .. })
        ));
        assert!(matches!(
            btf.member_offset("tstruct", "nosuch"),
            Err(BtfError::MissingMember { .. })
        ));
        assert!(matches!(
            resolve_btf_ids_from(&bytes),
            Err(BtfError::MissingFunc { .. })
        ));
    }

    #[test]
    fn hostile_images_fail_closed() {
        // Empty / truncated / bad-magic / bad-version.
        assert!(matches!(Btf::parse(&[]), Err(BtfError::BadBtf { .. })));
        assert!(matches!(
            Btf::parse(&[0u8; 10]),
            Err(BtfError::BadBtf { .. })
        ));
        let mut bytes = fixture();
        bytes[0] = 0x00;
        assert!(matches!(Btf::parse(&bytes), Err(BtfError::BadBtf { .. })));
        let mut bytes = fixture();
        bytes[2] = 0x7f;
        assert!(matches!(Btf::parse(&bytes), Err(BtfError::BadBtf { .. })));
        // Ranges past the end.
        for at in [8usize, 12, 16, 20] {
            let mut bytes = fixture();
            bytes[at..at + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
            assert!(matches!(Btf::parse(&bytes), Err(BtfError::BadBtf { .. })));
        }
        // Empty string section.
        let mut bytes = fixture();
        bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(Btf::parse(&bytes), Err(BtfError::BadBtf { .. })));
        // Unknown kind on the first record.
        let mut bytes = fixture();
        bytes[24 + 4..24 + 8].copy_from_slice(&((31u32) << 24).to_le_bytes());
        assert!(matches!(Btf::parse(&bytes), Err(BtfError::BadBtf { .. })));
        // Truncated image (cut mid-types).
        let bytes = fixture();
        assert!(matches!(
            Btf::parse(&bytes[..bytes.len() / 2]),
            Err(BtfError::BadBtf { .. })
        ));
    }

    #[test]
    fn misaligned_member_is_bad_btf() {
        // `bbb` at 7 bits: not byte-aligned, must fail closed (our 9
        // reads are all byte-aligned; a sub-byte offset is a wrong
        // assumption, never a guess). The ALIGNED sibling still
        // resolves: checks apply to the sought member only (K5:
        // `task_struct` bitfields must not break the parent chase).
        let mut bytes = fixture();
        // [3] aux starts at 24 (hdr) + 12 ([1]) + 12 ([2]) + 12 ([3] hdr).
        let m1_off_at = 24 + 12 + 12 + 12 + 12 + 8;
        bytes[m1_off_at..m1_off_at + 4].copy_from_slice(&7u32.to_le_bytes());
        let btf = Btf::parse(&bytes).expect("shape still parses");
        assert!(matches!(
            btf.member_offset("tstruct", "bbb"),
            Err(BtfError::BadBtf { .. })
        ));
        assert_eq!(btf.member_offset("tstruct", "aaa").unwrap(), 0);
    }

    /// Kind-flagged struct with a leading 1-bit field: `bf1` (width 1,
    /// bit 0) then `good` (width 0, bit 64 = byte 8).
    fn bitfield_fixture() -> Vec<u8> {
        let mut b = BtfBuild::new();
        let o_mixed = b.str("mixed");
        let o_bf1 = b.str("bf1");
        let o_good = b.str("good");
        // [1] INT (shared member type).
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        // [2] STRUCT mixed { bf1: 1-bit field, good @ byte 8 }.
        b.rec(o_mixed, KIND_STRUCT, 2, true, 16);
        b.member(o_bf1, 1, 1 << 24);
        b.member(o_good, 1, 64);
        b.finish()
    }

    #[test]
    fn sought_member_past_bitfield_resolves() {
        // The K5 `task_struct` shape: a bitfield BEFORE the sought
        // member skips (never fatal), and the sought member resolves.
        let bytes = bitfield_fixture();
        let btf = Btf::parse(&bytes).expect("fixture must parse");
        assert_eq!(btf.member_offset("mixed", "good").unwrap(), 8);
    }

    #[test]
    fn sought_bitfield_fails_closed() {
        // A bitfield has no byte offset to read: seeking one fails
        // closed (BTF spec: nonzero width in the high byte under the
        // kind flag), never a guessed byte read.
        let bytes = bitfield_fixture();
        let btf = Btf::parse(&bytes).expect("fixture must parse");
        assert!(matches!(
            btf.member_offset("mixed", "bf1"),
            Err(BtfError::BadBtf { .. })
        ));
    }

    #[test]
    fn pf_kthread_pins_cited_value() {
        // The value is verified against the installed kernel headers
        // (see the const docs); this pins it against accidental edits.
        assert_eq!(PF_KTHREAD, 0x0020_0000);
    }

    /// Synthetic crypto image: the 9 [`CryptoOffsets`] structs plus the
    /// 4 [`FIRST_MEMBER_LINKS`] members. `moved` relocates one member
    /// to byte 8 (fail-closed proof for C3 links; resolution proof for
    /// the CONFIG-resolved `crypto_shash.base`). `drop` omits one member
    /// entirely (missing-member fail-closed proof).
    fn crypto_fixture(moved: Option<(&str, &str)>) -> Vec<u8> {
        crypto_fixture_inner(moved, None)
    }

    fn crypto_fixture_inner(moved: Option<(&str, &str)>, drop: Option<(&str, &str)>) -> Vec<u8> {
        let mut b = BtfBuild::new();
        // [1] INT (shared member type).
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        let mut named = |name: &str, members: &[(&str, u32)]| {
            let kept: Vec<(&str, u32)> = members
                .iter()
                .copied()
                .filter(|(member, _)| drop != Some((name, *member)))
                .collect();
            let o_name = b.str(name);
            b.rec(o_name, KIND_STRUCT, kept.len() as u32, false, 256);
            for (member, byte) in kept {
                let at = if moved == Some((name, member)) {
                    8
                } else {
                    byte
                };
                let o_member = b.str(member);
                b.member(o_member, 1, at * 8);
            }
        };
        named("skcipher_request", &[("cryptlen", 0), ("base", 32)]);
        named("crypto_async_request", &[("tfm", 32)]);
        named("crypto_tfm", &[("__crt_alg", 32)]);
        named("crypto_alg", &[("cra_name", 60), ("cra_driver_name", 188)]);
        named("task_struct", &[("flags", 44)]);
        named("aead_request", &[("base", 0), ("cryptlen", 52)]);
        named("ahash_request", &[("base", 0), ("nbytes", 48)]);
        named("shash_desc", &[("tfm", 0)]);
        named("crypto_shash", &[("base", 0)]);
        b.finish()
    }

    #[test]
    fn synthetic_offsets_resolve_nine_exact() {
        let bytes = crypto_fixture(None);
        let off = resolve_offsets_from(&bytes).expect("crypto fixture resolves");
        assert_eq!(
            off,
            CryptoOffsets {
                sk_req_base: 32,
                async_tfm: 32,
                tfm_alg: 32,
                alg_name: 60,
                alg_drv: 188,
                task_flags: 44,
                aead_cryptlen_off: 52,
                ahash_nbytes_off: 48,
                shash_base: 0,
            }
        );
    }

    #[test]
    fn kconfig_from_offsets_lays_out_c2_words() {
        // Pure CONFIG projection (K1 Task 3 head + K5 Task 3 tail): the 9
        // resolved offsets + PF_KTHREAD + zero pad → the 76B KCFG wire
        // layout in C2 word order, with the K5 attribution offsets +
        // flags verbatim in the tail (a false flag pairs with group
        // zeros — here the params group is off, so its words are 0).
        let off = CryptoOffsets {
            sk_req_base: 32,
            async_tfm: 32,
            tfm_alg: 32,
            alg_name: 60,
            alg_drv: 188,
            task_flags: 44,
            aead_cryptlen_off: 52,
            ahash_nbytes_off: 48,
            shash_base: 8,
        };
        let k5 = KcryptoOffsets {
            task_real_parent: 1432,
            task_tgid: 1424,
            task_comm: 1648,
            cra_blocksize: 0,
            cra_ivsize: 0,
            cra_min_keysize: 0,
            cra_max_keysize: 0,
            parent_ok: true,
            params_ok: false,
        };
        let cfg = kconfig_from_offsets(off, k5);
        let mut want = [0u8; 76];
        for (i, word) in [
            32u32, 32, 32, 60, 188, 44, PF_KTHREAD, 52, 48, 8, 0, 1432, 1424, 1648, 0, 0, 0, 0,
        ]
        .iter()
        .enumerate()
        {
            want[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        want[72] = 1;
        want[73] = 0;
        assert_eq!(cfg.to_bytes(), want);
    }

    /// Synthetic K5 image: `task_struct` with the 3 parent members +
    /// `crypto_alg` with the 4 params members. `drop` omits one member
    /// entirely (group fail-soft proof).
    fn k5_fixture(drop: Option<(&str, &str)>) -> Vec<u8> {
        let mut b = BtfBuild::new();
        // [1] INT (shared member type).
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        let mut named = |name: &str, members: &[(&str, u32)]| {
            let kept: Vec<(&str, u32)> = members
                .iter()
                .copied()
                .filter(|(member, _)| drop != Some((name, *member)))
                .collect();
            let o_name = b.str(name);
            b.rec(o_name, KIND_STRUCT, kept.len() as u32, false, 4096);
            for (member, byte) in kept {
                let o_member = b.str(member);
                b.member(o_member, 1, byte * 8);
            }
        };
        named(
            "task_struct",
            &[("real_parent", 1432), ("tgid", 1424), ("comm", 1648)],
        );
        named(
            "crypto_alg",
            &[
                ("cra_blocksize", 36),
                ("cra_ivsize", 400),
                ("cra_min_keysize", 404),
                ("cra_max_keysize", 408),
            ],
        );
        b.finish()
    }

    #[test]
    fn synthetic_k5_offsets_resolve_exact() {
        let bytes = k5_fixture(None);
        let off = resolve_kcrypto_offsets_from(&bytes).expect("K5 fixture resolves");
        assert_eq!(
            off,
            KcryptoOffsets {
                task_real_parent: 1432,
                task_tgid: 1424,
                task_comm: 1648,
                cra_blocksize: 36,
                cra_ivsize: 400,
                cra_min_keysize: 404,
                cra_max_keysize: 408,
                parent_ok: true,
                params_ok: true,
            }
        );
    }

    #[test]
    fn synthetic_k5_missing_member_fails_soft_per_group() {
        // One missing parent member zeroes the PARENT group only (flags
        // + offsets); the params group still resolves fully.
        let bytes = k5_fixture(Some(("task_struct", "tgid")));
        let off = resolve_kcrypto_offsets_from(&bytes).expect("fail-soft never errs");
        assert!(!off.parent_ok);
        assert_eq!(
            (off.task_real_parent, off.task_tgid, off.task_comm),
            (0, 0, 0)
        );
        assert!(off.params_ok);
        assert_eq!(
            (
                off.cra_blocksize,
                off.cra_ivsize,
                off.cra_min_keysize,
                off.cra_max_keysize
            ),
            (36, 400, 404, 408)
        );
        // One missing params member zeroes the PARAMS group only (even
        // though `cra_blocksize` itself resolves — group-atomic).
        let bytes = k5_fixture(Some(("crypto_alg", "cra_ivsize")));
        let off = resolve_kcrypto_offsets_from(&bytes).expect("fail-soft never errs");
        assert!(off.parent_ok);
        assert_eq!(
            (off.task_real_parent, off.task_tgid, off.task_comm),
            (1432, 1424, 1648)
        );
        assert!(!off.params_ok);
        assert_eq!(
            (
                off.cra_blocksize,
                off.cra_ivsize,
                off.cra_min_keysize,
                off.cra_max_keysize
            ),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn synthetic_k5_malformed_btf_is_hard_err() {
        // Unreadable IMAGE (not members): truncated bytes fail hard as
        // `BadBtf` (fail-closed: nothing resolves off a broken image).
        let bytes = k5_fixture(None);
        let err = resolve_kcrypto_offsets_from(&bytes[..bytes.len() / 2])
            .expect_err("truncated image must fail");
        assert!(matches!(err, ResolveError::BadBtf { .. }), "got {err}");
    }

    #[test]
    fn shash_base_at_8_resolves_not_refuses() {
        // 6.12 layout (K4 task-4 refusal evidence, replicated 2x + BTF
        // cross-proven): `crypto_shash.base` @ 8. The shash base link is
        // CONFIG-resolved like the other offsets — resolution, not
        // refusal — so this fixture must RESOLVE with `shash_base == 8`.
        let bytes = crypto_fixture(Some(("crypto_shash", "base")));
        let off = resolve_offsets_from(&bytes).expect("6.12 shash layout must resolve");
        assert_eq!(off.shash_base, 8);
    }

    #[test]
    fn shash_base_missing_member_fails_closed() {
        // `crypto_shash` without `base`: resolution failure must still
        // fail closed with `MissingMember` (same exit-4 honesty as the
        // retired C3 refusal — a kernel that drops the member refuses
        // here, never mis-chases in BPF).
        let bytes = crypto_fixture_inner(None, Some(("crypto_shash", "base")));
        let err = resolve_offsets_from(&bytes).expect_err("missing shash.base must fail");
        assert_eq!(
            err,
            BtfError::MissingMember {
                type_name: "crypto_shash".to_owned(),
                member: "base".to_owned(),
            }
        );
    }

    #[test]
    fn moved_first_member_fails_closed() {
        // Every C3 link, moved to byte 8 in turn: each must be
        // FirstMemberMoved naming the exact struct/member/offset (never
        // a silently-resolved offset set).
        for (type_name, member) in FIRST_MEMBER_LINKS {
            let bytes = crypto_fixture(Some((type_name, member)));
            let err = resolve_offsets_from(&bytes).expect_err("moved link must fail");
            assert_eq!(
                err,
                BtfError::FirstMemberMoved {
                    type_name: (*type_name).to_owned(),
                    member: (*member).to_owned(),
                    offset: 8,
                },
                "link {type_name}.{member}"
            );
        }
    }

    /// Bringup fixture: the crypto structs (with K5 members merged in)
    /// plus all 9 [`KCRYPTO_SYMBOLS`] as FUNCs sharing one FUNC_PROTO.
    fn bringup_fixture() -> Vec<u8> {
        let mut b = BtfBuild::new();
        // [1] INT (shared member type), [2] FUNC_PROTO (shared).
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_FUNC_PROTO, 0, false, 1);
        // [3..11] the 9 FUNCs in symbol order.
        for name in KCRYPTO_SYMBOLS {
            let o_name = b.str(name);
            b.rec(o_name, KIND_FUNC, 1, false, 2);
        }
        let mut named = |name: &str, members: &[(&str, u32)]| {
            let o_name = b.str(name);
            b.rec(o_name, KIND_STRUCT, members.len() as u32, false, 4096);
            for (member, byte) in members {
                let o_member = b.str(member);
                b.member(o_member, 1, byte * 8);
            }
        };
        named("skcipher_request", &[("cryptlen", 0), ("base", 32)]);
        named("crypto_async_request", &[("tfm", 32)]);
        named("crypto_tfm", &[("__crt_alg", 32)]);
        named(
            "crypto_alg",
            &[
                ("cra_name", 60),
                ("cra_driver_name", 188),
                ("cra_blocksize", 36),
                ("cra_ivsize", 400),
                ("cra_min_keysize", 404),
                ("cra_max_keysize", 408),
            ],
        );
        named(
            "task_struct",
            &[
                ("flags", 44),
                ("real_parent", 1432),
                ("tgid", 1424),
                ("comm", 1648),
            ],
        );
        named("aead_request", &[("base", 0), ("cryptlen", 52)]);
        named("ahash_request", &[("base", 0), ("nbytes", 48)]);
        named("shash_desc", &[("tfm", 0)]);
        named("crypto_shash", &[("base", 0)]);
        b.finish()
    }

    #[test]
    fn bringup_combo_matches_split_resolvers() {
        // H1(a): one parse serves all three bringup resolutions —
        // identical results to the three separate resolvers.
        let bytes = bringup_fixture();
        let (ids, off, k5) = resolve_kcrypto_bringup_from(&bytes).expect("combo resolves");
        assert_eq!(ids, resolve_btf_ids_from(&bytes).expect("ids resolve"));
        assert_eq!(off, resolve_offsets_from(&bytes).expect("offsets resolve"));
        assert_eq!(
            k5,
            resolve_kcrypto_offsets_from(&bytes).expect("k5 resolves")
        );
        // Spot values pin the combo to the fixture (not just to the
        // split path): func ids in declaration order, crypto + k5.
        assert_eq!(ids["crypto_alloc_tfm_node"], 3);
        assert_eq!(ids["crypto_shash_finup"], 11);
        assert_eq!(
            off,
            CryptoOffsets {
                sk_req_base: 32,
                async_tfm: 32,
                tfm_alg: 32,
                alg_name: 60,
                alg_drv: 188,
                task_flags: 44,
                aead_cryptlen_off: 52,
                ahash_nbytes_off: 48,
                shash_base: 0,
            }
        );
        assert!(k5.parent_ok && k5.params_ok);
    }
}
