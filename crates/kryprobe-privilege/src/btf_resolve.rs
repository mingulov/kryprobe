// SPDX-License-Identifier: GPL-3.0-or-later
//! vmlinux BTF resolver: func ids + struct-member offsets, unprivileged.
//!
//! [`resolve_btf_ids`] finds the 9 P0 kcrypto attach symbols
//! (`evidence/k0/P0-btf-ids.txt`); [`resolve_aggregate_offsets`]
//! returns the 9 explicit-offset reads the aggregate BPF needs (K0 P2
//! chain + `task_struct.flags` for the kthread classifier + the C2
//! AEAD/ahash length reads + the `crypto_shash.base` link (6.12 moved
//! it to byte 8 — G6 option (a): loader-side resolution, no CO-RE
//! relocations)) and asserts the C3 first-member links at 0; and
//! [`resolve_lifecycle_offsets`] returns the shape-validated lifecycle
//! set (D3: per-consumer resolution, no shared union). All parse
//! `/sys/kernel/btf/vmlinux` raw
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
use crate::btf::{Btf, SplitBtf};
use crate::fd::OwnedFd;
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
/// Module BTF directory (world-readable; one file per BTF-carrying
/// module — absent file = module not loaded or built without BTF).
const MODULE_BTF_DIR: &str = "/sys/kernel/btf";

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
    /// Duplicate BTF definitions of one name with a chain linking a
    /// DIFFERENT def than the bound entry def (T07-R3-09): offsets
    /// from one def cannot be mixed with a chase rooted in another.
    IncompatibleDefinitions {
        /// Duplicated type name.
        type_name: String,
        /// Entry def id the offsets were bound to.
        entry_id: u32,
        /// Rival def id the chain links.
        linked_id: u32,
        /// Chain that links the rival def (e.g. `crypto_skcipher.base`).
        via: String,
    },
    /// Member/type search hit a traversal limit or a type cycle
    /// (T07-R3-10): the search is INCOMPLETE — never a proven
    /// absence. Mapping this to `MissingMember`/`MissingType` would
    /// let an unreachable `refcnt` select always-final mode and
    /// retire retained releases unconditionally.
    TraversalIncomplete {
        /// What was sought (member or type name).
        sought: String,
        /// Limit detail (cap depth or cycle id).
        detail: String,
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
            Self::IncompatibleDefinitions {
                type_name,
                entry_id,
                linked_id,
                via,
            } => {
                write!(
                    f,
                    "BTF '{type_name}' has rival definitions: offsets bound to id {entry_id} but {via} links id {linked_id}"
                )
            }
            Self::TraversalIncomplete { sought, detail } => {
                write!(f, "BTF search for '{sought}' incomplete: {detail}")
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

/// Explicit-offset reads for the aggregate kcrypto BPF (all u32 byte
/// offsets): the K0 P2 identity chain plus `task_struct.flags`
/// (kthread via [`PF_KTHREAD`]) plus the AEAD/ahash length reads
/// (C2). Enter the BPF via the CONFIG map (G6 option (a)).
///
/// D3: this is the AGGREGATE consumer's own set — the lifecycle's
/// `sk_base` prerequisite it never used is gone (it lives in
/// [`LifecycleOffsets` now), so an skcipher reorder refuses the
/// lifecycle sensor, never the aggregate one, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateOffsets {
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

/// Explicit-offset reads for the lifecycle BPF (all u32 byte
/// offsets): the transform chase (`tfm_alg`/`alg_drv`), the
/// frontend→base normalization (`sk_base`, shared with the
/// userspace tracker), the op request link (`req_base`/`req_tfm`,
/// first-seen admission), the op request-metadata reads
/// (`req_cryptlen`/`req_flags`, P3 entry-side scalars), and the
/// destroy refcount word (`refcnt_off`, meaningful only when
/// `refcnt_present`).
///
/// D3: the LIFECYCLE consumer's own set — arming no longer requires
/// the aggregate's legacy fields (`task_flags`, AEAD/hash lengths,
/// shash link), and every member is SHAPE-validated, not just
/// offset-resolved: pointers prove their pointee struct, embedded
/// bases prove their struct, the name proves its array extent, the
/// metadata words prove exact 4-byte scalars, and the refcount
/// proves its counter width. `refcnt_present` is soft
/// (7.2 dropped the field — absence means always-final mode, never
/// a refusal); every other member is fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleOffsets {
    /// `crypto_tfm.__crt_alg` (PTR at STRUCT `crypto_alg`).
    pub tfm_alg: u32,
    /// `crypto_alg.cra_driver_name` (byte ARRAY ≥ 64).
    pub alg_drv: u32,
    /// `crypto_skcipher.base` (embedded STRUCT `crypto_tfm`).
    pub sk_base: u32,
    /// `skcipher_request.base` (embedded STRUCT
    /// `crypto_async_request`).
    pub req_base: u32,
    /// `crypto_async_request.tfm` (PTR at STRUCT `crypto_tfm`).
    pub req_tfm: u32,
    /// `skcipher_request.cryptlen` (exact 4-byte scalar — the API
    /// input length the op programs chase at entry).
    pub req_cryptlen: u32,
    /// `crypto_async_request.flags` (exact 4-byte scalar — added to
    /// the chased base address, like `req_tfm`).
    pub req_flags: u32,
    /// `crypto_tfm.refcnt` (4-byte counter; 0 when absent).
    pub refcnt_off: u32,
    /// The kernel carries `crypto_tfm.refcnt` (false on 7.2+:
    /// unconditional destroy — the tracker retires every observed
    /// destroy).
    pub refcnt_present: bool,
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

/// Session-kfunc FUNC names (T06 W8): the two kfuncs the fsession BPF
/// calls through loader-rewritten stubs. Guest-proven present even
/// on 6.12.111 — kfunc presence is NOT the floor discriminator (the
/// FSESSION attach acceptance at load is); a missing kfunc still
/// refuses the rewrite fail-closed with the cause named.
pub const KFUNC_SYMBOLS: &[&str] = &["bpf_session_is_return", "bpf_session_cookie"];

/// Resolve the [`KFUNC_SYMBOLS`] to vmlinux BTF FUNC ids.
/// Unprivileged. Both must resolve; a missing kfunc fails the whole
/// call (fail-closed: a half rewrite would leave a sentinel the
/// verifier refuses, but the typed error here names the cause).
pub fn resolve_kfunc_ids() -> Result<HashMap<String, u32>, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    let btf = Btf::parse(bytes)?;
    btf_ids_from_btf_for(&btf, KFUNC_SYMBOLS)
}

/// Resolve the 9 [`AggregateOffsets`] from vmlinux BTF. Unprivileged.
///
/// Fail-closed on the C3 first-member links: the BPF hardcodes 0 for
/// the four [`FIRST_MEMBER_LINKS`] below, so any nonzero live offset is
/// [`BtfError::FirstMemberMoved`] (a kernel struct reorder must refuse
/// here, never mis-chase in BPF). The retired fifth link
/// (`crypto_shash.base`) is CONFIG-resolved instead (see
/// [`AggregateOffsets::shash_base`]): a missing member still fails
/// closed as [`BtfError::MissingMember`].
pub fn resolve_aggregate_offsets() -> Result<AggregateOffsets, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    resolve_aggregate_offsets_from(bytes)
}

/// Resolve the [`LifecycleOffsets`] from vmlinux BTF. Unprivileged.
///
/// D3: the lifecycle arm's OWN resolution — shape-validated per
/// member (pointers prove pointees, bases prove structs, the name
/// proves its extent, the refcount proves its width) and independent
/// of the aggregate's legacy fields. Only `refcnt` is soft (absent
/// on 7.2+ → always-final mode); every other gap fails the arm.
pub fn resolve_lifecycle_offsets() -> Result<LifecycleOffsets, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    resolve_lifecycle_offsets_from(bytes)
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
) -> Result<(HashMap<String, u32>, AggregateOffsets, KcryptoOffsets), BtfError> {
    let btf = Btf::parse(bytes)?;
    let ids = btf_ids_from_btf(&btf)?;
    let off = aggregate_offsets_from_btf(&btf)?;
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
pub fn kconfig_from_offsets(off: AggregateOffsets, k5: KcryptoOffsets) -> KConfig {
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
    /// Another profile holds the process (no cross-profile capture).
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
                    "kcrypto session busy: '{}' is live, '{}' refused (no cross-profile capture)",
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
/// ids (T06, grown by the T07.2 alloc site, the T07.3 destroy site,
/// and the T07.4 configuration sites). Unprivileged.
/// Profile-scoped: only the manifest's required symbols resolve —
/// the full 9-symbol api-returns set is a different profile's
/// business. Every resolved symbol's prototype is validated against
/// the sensor's reads for its shape (op: arg0 pointer, 32-bit int
/// return; alloc: `(name, type, mask)` args, tfm-pointer return;
/// destroy: `(mem, tfm)` pointers, void return; setkey:
/// `(frontend, key, len)` args, errno return; setauthsize:
/// `(aead, authsize)` args, errno return); a name that
/// resolves with an incompatible shape refuses startup.
/// T07-R4-N2: each prototype's STRUCT root must be the SAME bound
/// entry id the offsets resolver binds — a prototype pointing at a
/// rival same-named def refuses instead of keying the join on one
/// def while BPF reads at another's offsets.
pub fn resolve_lifecycle_ids() -> Result<HashMap<String, u32>, BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    resolve_lifecycle_ids_from(bytes)
}

/// Prototype root must be the bound entry def (T07-R4-N2): same
/// [`BtfError::IncompatibleDefinitions`] refusal the offsets
/// resolver raises for rival chain links.
fn require_proto_root(
    type_name: &str,
    entry_id: u32,
    pointee_id: u32,
    via: &str,
) -> Result<(), BtfError> {
    if pointee_id != entry_id {
        return Err(BtfError::IncompatibleDefinitions {
            type_name: type_name.to_owned(),
            entry_id,
            linked_id: pointee_id,
            via: via.to_owned(),
        });
    }
    Ok(())
}

/// Resolve + prototype-validate over an explicit BTF image (the
/// fixture seam: H02 drives synthetic images through this; the
/// vmlinux path above delegates after reading the bytes).
pub fn resolve_lifecycle_ids_from(bytes: &[u8]) -> Result<HashMap<String, u32>, BtfError> {
    use crate::kcrypto_lifecycle::profile::{LifecycleProfile, ProtoShape, manifest};
    let btf = Btf::parse(bytes)?;
    let table = manifest(LifecycleProfile::RequestLifecycle);
    let symbols: Vec<&str> = table.required.iter().map(|s| s.symbol).collect();
    let ids = btf_ids_from_btf_for(&btf, &symbols)?;
    // T07-R4-N2 single-definition roots: each prototype-referenced
    // STRUCT binds ONCE (first match — the same entry
    // `lifecycle_offsets_from_btf` binds); a prototype pointing at a
    // rival same-named def refuses below.
    let tfm_entry = btf.find_struct("crypto_tfm")?;
    let sk_entry = btf.find_struct("crypto_skcipher")?;
    let sreq_entry = btf.find_struct("skcipher_request")?;
    let aead_entry = btf.find_struct("crypto_aead")?;
    for site in table.required {
        let sym = site.symbol;
        match site.shape {
            ProtoShape::Op => {
                let (_, pointee) = btf.lifecycle_proto_id(site.symbol)?;
                require_proto_root(
                    "skcipher_request",
                    sreq_entry,
                    pointee,
                    &format!("{sym}.arg0"),
                )?;
            }
            ProtoShape::Alloc => {
                let (_, pointee) = btf.alloc_proto_id(site.symbol)?;
                require_proto_root(
                    "crypto_skcipher",
                    sk_entry,
                    pointee,
                    &format!("{sym}.return"),
                )?;
            }
            ProtoShape::Destroy => {
                let (_, pointee) = btf.destroy_proto_id(site.symbol)?;
                require_proto_root("crypto_tfm", tfm_entry, pointee, &format!("{sym}.arg1"))?;
            }
            ProtoShape::SetkeySk => {
                let (_, pointee) = btf.setkey_proto_id(site.symbol, "crypto_skcipher")?;
                require_proto_root("crypto_skcipher", sk_entry, pointee, &format!("{sym}.arg0"))?;
            }
            ProtoShape::SetAuthsize => {
                let (_, pointee) = btf.setauthsize_proto_id(site.symbol)?;
                require_proto_root("crypto_aead", aead_entry, pointee, &format!("{sym}.arg0"))?;
            }
            ProtoShape::SetkeyAead => {
                let (_, pointee) = btf.setkey_proto_id(site.symbol, "crypto_aead")?;
                require_proto_root("crypto_aead", aead_entry, pointee, &format!("{sym}.arg0"))?;
            }
        }
    }
    Ok(ids)
}

/// One optional callback site's resolve outcome (P4 contract §9):
/// attach-if-present, never gating — absence is quiet, drift is
/// loud, readiness carries the load inputs.
#[derive(Debug)]
pub enum CallbackSiteOutcome {
    /// Module BTF parsed, prototype pinned, BTF object fd open:
    /// the loader attaches `fentry/<symbol>` with this id + obj fd.
    Ready {
        /// Global BTF FUNC id (split-image address).
        func_id: u32,
        /// Module BTF object fd (`attach_btf_obj_fd` at load).
        obj_fd: OwnedFd,
    },
    /// Module BTF file absent (module not loaded or built without
    /// BTF): quiet skip — the sensor runs submit/return-only and
    /// the point records `Missing`, never a refusal.
    Absent,
    /// Module present but unusable (unreadable/ unparseable BTF,
    /// missing symbol, drifted prototype, rival def, or no BTF
    /// object): loud — the point records `Unsupported` with this
    /// detail, and bring-up continues without the site.
    Refused {
        /// Why the site refused (static-shaped, no BTF bytes).
        detail: String,
    },
}

/// Resolve the manifest's OPTIONAL callback sites (P4): per-site
/// outcomes, never fail-closed across sites (a refused callback
/// must not gate the sensor — only its own point records it).
/// Unprivileged reads (sysfs BTF) + one privileged step (the BTF
/// object fd, opened during bring-up): an `Err` here means the
/// SHARED base (vmlinux BTF) is unreadable — the required resolve
/// trips on that first in practice, so this `Err` is a diagnosed
/// race, never a silent skip.
pub fn resolve_callback_sites() -> Result<
    Vec<(
        crate::kcrypto_lifecycle::profile::CallbackSite,
        CallbackSiteOutcome,
    )>,
    BtfError,
> {
    use crate::kcrypto_lifecycle::profile::{CallbackShape, LifecycleProfile, manifest};
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    let base = Btf::parse(bytes)?;
    let sreq_entry = base.find_struct("skcipher_request")?;
    let table = manifest(LifecycleProfile::RequestLifecycle);
    let mut out = Vec::with_capacity(table.callbacks.len());
    for site in table.callbacks {
        let path = format!("{MODULE_BTF_DIR}/{}", site.module);
        let module_bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                out.push((*site, CallbackSiteOutcome::Absent));
                continue;
            }
            Err(err) => {
                out.push((
                    *site,
                    CallbackSiteOutcome::Refused {
                        detail: format!("{path}: {err}"),
                    },
                ));
                continue;
            }
        };
        let outcome = match Btf::parse(&module_bytes) {
            Ok(module) => {
                let split = SplitBtf::new(&base, &module);
                let proto = match site.shape {
                    CallbackShape::Cryptd => split.cryptd_proto_id(site.symbol, sreq_entry),
                    CallbackShape::FixtureOp => split.kxc_proto_id(site.symbol),
                };
                match proto {
                    Ok(func_id) => match find_module_btf(site.module) {
                        Ok(Some(obj_fd)) => CallbackSiteOutcome::Ready { func_id, obj_fd },
                        Ok(None) => CallbackSiteOutcome::Refused {
                            detail: format!(
                                "module BTF file present but no BTF object named '{}'",
                                site.module
                            ),
                        },
                        Err(errno) => CallbackSiteOutcome::Refused {
                            detail: format!("BTF object discovery errno {errno}"),
                        },
                    },
                    Err(err) => CallbackSiteOutcome::Refused {
                        detail: err.to_string(),
                    },
                }
            }
            Err(err) => CallbackSiteOutcome::Refused {
                detail: err.to_string(),
            },
        };
        out.push((*site, outcome));
    }
    Ok(out)
}

/// BTF object discovery (P4, privileged): iterate kernel BTF objects
/// and open the one whose kernel name is `module` (`vmlinux` for
/// the base image, the module name for module BTF). `Ok(None)` when
/// no object carries the name (raced unload, or a BTF file without
/// a live object — the caller refuses loud, never attaches blind).
/// Bounded (refuses past the cap instead of looping forever);
/// `ENOENT` mid-walk is a raced unload (skip, not evidence).
pub fn find_module_btf(module: &str) -> Result<Option<OwnedFd>, i32> {
    use crate::probe::bpf_sys::{btf_get_fd_by_id, btf_get_next_id, btf_kernel_name};
    const CAP: u32 = 65_536;
    let mut id = 0u32;
    let mut seen = 0u32;
    let mut name_buf = [0u8; 128];
    loop {
        let Some(next) = btf_get_next_id(id)? else {
            return Ok(None);
        };
        id = next;
        seen += 1;
        if seen > CAP {
            return Err(libc::ELOOP);
        }
        let fd = match btf_get_fd_by_id(next) {
            Ok(fd) => fd,
            Err(libc::ENOENT) => continue,
            Err(errno) => return Err(errno),
        };
        let name = match btf_kernel_name(fd.as_raw_fd(), &mut name_buf) {
            Ok(name) => name,
            // Raced unload (the fd's object vanished) — skip it.
            Err(libc::ENOENT) => continue,
            Err(errno) => return Err(errno),
        };
        if name == module {
            return Ok(Some(fd));
        }
    }
}

/// Resolve the fixture `op->req` chase (P4 arm input): the
/// `kxc_op.req` member byte offset plus the T08-`refcnt_present`
/// -style presence word. Absent module BTF reads `(0, false)` —
/// the honest fixture-absent verdict (the fixture program gates on
/// it and the loader cannot attach it either). Present
/// module BTF with an unresolvable member (missing struct/member,
/// non-pointer, wrong pointee, rival def) FAILS the arm —
/// absence is quiet, unreadability is loud (fail-closed twin
/// drift: a zeroed guess would mis-chase).
pub fn resolve_fixture_op_req() -> Result<(u32, bool), BtfError> {
    let bytes = vmlinux_btf_bytes().map_err(|detail| BtfError::Io { detail })?;
    let base = Btf::parse(bytes)?;
    let path = format!("{MODULE_BTF_DIR}/kcrypto_fixture");
    let module_bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((0, false)),
        Err(err) => {
            return Err(BtfError::Io {
                detail: format!("{path}: {err}"),
            });
        }
    };
    let module = Btf::parse(&module_bytes)?;
    let split = SplitBtf::new(&base, &module);
    let sk_entry = base.find_struct("skcipher_request")?;
    split.kxc_op_req(sk_entry).map(|off| (off, true))
}

/// C3 first-member links: struct/member pairs the BPF reads at
/// literal offset 0 (verified first members on the K1 host BTF; C
/// guarantees no padding before the initial member, so only a struct
/// reorder can move them — which fails closed below). The retired fifth
/// link (`crypto_shash.base`, @8 on 6.12) is CONFIG-resolved instead
/// ([`AggregateOffsets::shash_base`]).
pub const FIRST_MEMBER_LINKS: &[(&str, &str)] = &[
    ("aead_request", "base"),
    ("ahash_request", "base"),
    ("shash_desc", "tfm"),
    ("skcipher_request", "cryptlen"),
];

fn resolve_aggregate_offsets_from(bytes: &[u8]) -> Result<AggregateOffsets, BtfError> {
    let btf = Btf::parse(bytes)?;
    aggregate_offsets_from_btf(&btf)
}

/// Aggregate resolution over an already-parsed image (H1(a) combo core).
fn aggregate_offsets_from_btf(btf: &Btf) -> Result<AggregateOffsets, BtfError> {
    let out = AggregateOffsets {
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

/// Lifecycle resolution over an explicit BTF image (fixture seam;
/// the vmlinux path above delegates after reading the bytes).
fn resolve_lifecycle_offsets_from(bytes: &[u8]) -> Result<LifecycleOffsets, BtfError> {
    let btf = Btf::parse(bytes)?;
    lifecycle_offsets_from_btf(&btf)
}

/// Name-array extent the lifecycle BPF copy trusts (T07.2 wire
/// bound: 63 bytes + NUL — the resolver proves the member holds at
/// least this many bytes before the chase copies into it).
const LIFECYCLE_NAME_BOUND: u32 = 64;

/// Lifecycle resolution over an already-parsed image: shape-proving
/// (D3), not offset-only. Only the `refcnt` member is soft — its
/// ABSENCE resolves to always-final mode (7.2 dropped the field);
/// a present-but-misshapen `refcnt`, or any other gap, fails the
/// arm (fail closed: a half-proven chase mis-chases in BPF).
fn lifecycle_offsets_from_btf(btf: &Btf) -> Result<LifecycleOffsets, BtfError> {
    // T07-R3-09 single-definition threading: each entry name binds
    // ONCE (in the same consultation order as before, so missing-type
    // precedence is unchanged); every later consultation of the same
    // name resolves THROUGH the bound id, and every chained reference
    // must land on that SAME id — a chain linking a rival duplicate
    // def refuses instead of mixing offsets across defs.
    let tfm_entry = btf.find_struct("crypto_tfm")?;
    let alg_entry = btf.find_struct("crypto_alg")?;
    let sk_entry = btf.find_struct("crypto_skcipher")?;
    let sreq_entry = btf.find_struct("skcipher_request")?;
    let areq_entry = btf.find_struct("crypto_async_request")?;
    let (tfm_alg, alg_id) =
        btf.member_ptr_target_in(tfm_entry, "crypto_tfm", "__crt_alg", "crypto_alg")?;
    if alg_id != alg_entry {
        return Err(BtfError::IncompatibleDefinitions {
            type_name: "crypto_alg".to_owned(),
            entry_id: alg_entry,
            linked_id: alg_id,
            via: "crypto_tfm.__crt_alg".to_owned(),
        });
    }
    let alg_drv = btf.member_bytes_in(
        alg_entry,
        "crypto_alg",
        "cra_driver_name",
        LIFECYCLE_NAME_BOUND,
    )?;
    let (sk_base, sk_tfm_id) =
        btf.member_embedded_target_in(sk_entry, "crypto_skcipher", "base", "crypto_tfm")?;
    if sk_tfm_id != tfm_entry {
        return Err(BtfError::IncompatibleDefinitions {
            type_name: "crypto_tfm".to_owned(),
            entry_id: tfm_entry,
            linked_id: sk_tfm_id,
            via: "crypto_skcipher.base".to_owned(),
        });
    }
    let (req_base, req_areq_id) = btf.member_embedded_target_in(
        sreq_entry,
        "skcipher_request",
        "base",
        "crypto_async_request",
    )?;
    if req_areq_id != areq_entry {
        return Err(BtfError::IncompatibleDefinitions {
            type_name: "crypto_async_request".to_owned(),
            entry_id: areq_entry,
            linked_id: req_areq_id,
            via: "skcipher_request.base".to_owned(),
        });
    }
    let (req_tfm, req_tfm_id) =
        btf.member_ptr_target_in(areq_entry, "crypto_async_request", "tfm", "crypto_tfm")?;
    if req_tfm_id != tfm_entry {
        return Err(BtfError::IncompatibleDefinitions {
            type_name: "crypto_tfm".to_owned(),
            entry_id: tfm_entry,
            linked_id: req_tfm_id,
            via: "crypto_async_request.tfm".to_owned(),
        });
    }
    // P3 entry-side scalars (hard members — a missing/misshapen
    // length or flags word refuses the arm, never zero-chases):
    // `member_counter_in`'s INT path proves exact 4-byte value
    // width, which is the whole proof a u32 scalar needs.
    let req_cryptlen = btf.member_counter_in(sreq_entry, "skcipher_request", "cryptlen")?;
    let req_flags = btf.member_counter_in(areq_entry, "crypto_async_request", "flags")?;
    let (refcnt_off, refcnt_present) =
        match btf.member_counter_in(tfm_entry, "crypto_tfm", "refcnt") {
            Ok(off) => (off, true),
            // Soft absence: the whole TYPE missing means the BTF is too
            // old for the lifecycle sensor at all (the hard members
            // above already proved `crypto_tfm` exists, so a missing
            // TYPE here is unreachable — but match it soft anyway: it
            // can only mean "no refcount to read", never "sensor-safe").
            Err(BtfError::MissingMember { .. } | BtfError::MissingType { .. }) => (0, false),
            Err(other) => return Err(other),
        };
    Ok(LifecycleOffsets {
        tfm_alg,
        alg_drv,
        sk_base,
        req_base,
        req_tfm,
        req_cryptlen,
        req_flags,
        refcnt_off,
        refcnt_present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btf::{
        BTF_MAGIC, BTF_VERSION, Btf, KIND_FUNC, KIND_FUNC_PROTO, KIND_INT, KIND_PTR, KIND_STRUCT,
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

        /// INT type with explicit storage size + value encoding
        /// (bits/offset/encoding), for narrowed/shifted/malformed
        /// leaves. Ids stay positional, as in every fixture.
        fn int_enc(&mut self, name: &str, size: u32, bits: u32, offset: u32, encoding: u32) {
            let name_off = self.str(name);
            let data = (bits & 0xff) | ((offset & 0xff) << 16) | ((encoding & 0x0f) << 24);
            self.word(name_off);
            self.word(u32::from(KIND_INT) << 24);
            self.word(size);
            self.word(data);
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

    /// Minimal destroy-shape image (T07.3): [1] INT u32,
    /// [2] STRUCT `crypto_tfm`, [3] PTR→2, [4] STRUCT `other`,
    /// [5] PTR→4, [6] PTR→0 (`void *`), [7] FUNC_PROTO
    /// `(arg0, arg1) -> ret`, [8] FUNC `dstr`.
    fn destroy_fixture(ret: u32, arg0: u32, arg1: u32, nargs: u32) -> Vec<u8> {
        let mut b = BtfBuild::new();
        let o_int = b.str("u32");
        let o_tfm = b.str("crypto_tfm");
        let o_other = b.str("other");
        let o_dstr = b.str("dstr");
        b.rec(o_int, KIND_INT, 0, false, 4);
        b.word(0x0000_0020);
        b.rec(o_tfm, KIND_STRUCT, 0, false, 64);
        b.rec(0, KIND_PTR, 0, false, 2);
        b.rec(o_other, KIND_STRUCT, 0, false, 64);
        b.rec(0, KIND_PTR, 0, false, 4);
        b.rec(0, KIND_PTR, 0, false, 0);
        let params: Vec<u32> = if nargs == 2 {
            vec![arg0, arg1]
        } else {
            vec![arg0; nargs as usize]
        };
        b.rec(0, KIND_FUNC_PROTO, nargs, false, ret);
        for param in params {
            b.word(0);
            b.word(param);
        }
        b.rec(o_dstr, KIND_FUNC, 1, false, 7);
        b.finish()
    }

    #[test]
    fn destroy_wellformed_proto_resolves() {
        let bytes = destroy_fixture(0, 6, 3, 2);
        let btf = Btf::parse(&bytes).expect("fixture must parse");
        assert_eq!(btf.destroy_proto_id("dstr").expect("good destroy"), (8, 2));
    }

    #[test]
    fn destroy_misshapen_protos_refuse() {
        let bad = [
            // Non-void return: the exit run would read a status.
            (1, 6, 3, 2),
            // One arg: no tfm to read the refcount from.
            (0, 6, 3, 1),
            // INT mem: not a pointer at all.
            (0, 1, 3, 2),
            // INT tfm: the refcount read needs a pointer.
            (0, 6, 1, 2),
            // Tfm at the wrong struct: refcount from a stranger.
            (0, 6, 5, 2),
        ];
        for (ret, arg0, arg1, nargs) in bad {
            let bytes = destroy_fixture(ret, arg0, arg1, nargs);
            let btf = Btf::parse(&bytes).expect("fixture must parse");
            assert!(
                matches!(
                    btf.destroy_proto_id("dstr"),
                    Err(BtfError::BadPrototype { .. })
                ),
                "shape ({ret}, {arg0}, {arg1}, {nargs}) must refuse"
            );
        }
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

    /// Synthetic crypto image: the 9 [`AggregateOffsets`] structs plus the
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
        named("crypto_skcipher", &[("base", 8)]);
        b.finish()
    }

    /// Typed lifecycle fixture (D3): the five lifecycle structs with
    /// REAL member shapes, not the shared-INT typing of
    /// `crypto_fixture` — PTR links, an embedded STRUCT, a char
    /// ARRAY bound, and a refcount STRUCT. Ids in emission order:
    /// [1] INT u32, [2] INT char, [3] STRUCT `refcount_struct`,
    /// [4] ARRAY char[64], [5] STRUCT `crypto_alg`, [6] PTR→alg,
    /// [7] STRUCT `crypto_tfm`, [8] PTR→tfm,
    /// [9] STRUCT `crypto_async_request`,
    /// [10] STRUCT `skcipher_request`, [11] STRUCT `crypto_skcipher`.
    /// `patch` forces one member's type id (negative shapes);
    /// `drop` omits one member (absence probes).
    fn lifecycle_fixture(patch: Option<(&str, &str, u32)>, drop: Option<(&str, &str)>) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_PTR};
        let mut b = BtfBuild::new();
        // `patch` forces one member's type id (negative shapes);
        // `drop` omits one member (absence probes). Name strings
        // don't consume type ids, so interning up front is safe.
        let shape = |s: &str, m: &str, ty: u32| -> Option<u32> {
            if drop == Some((s, m)) {
                return None;
            }
            if let Some((ps, pm, pty)) = patch
                && (ps, pm) == (s, m)
            {
                return Some(pty);
            }
            Some(ty)
        };
        // [1] INT u32, [2] INT char (array index + element).
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        // [3] STRUCT refcount_struct { refs: [1] @0 }.
        let o_rc = b.str("refcount_struct");
        let o_refs = b.str("refs");
        b.rec(o_rc, KIND_STRUCT, 1, false, 4);
        b.member(o_refs, 1, 0);
        // [4] ARRAY char[64] (elem [2], index [1], 64 elems).
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [5] STRUCT crypto_alg { cra_driver_name: [4] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        let mut alg: Vec<(u32, u32, u32)> = Vec::new();
        if let Some(ty) = shape("crypto_alg", "cra_driver_name", 4) {
            alg.push((o_drv, ty, 188 * 8));
        }
        b.rec(o_alg, KIND_STRUCT, alg.len() as u32, false, 256);
        for (name, ty, bits) in alg {
            b.member(name, ty, bits);
        }
        // [6] PTR -> [5].
        b.rec(0, KIND_PTR, 0, false, 5);
        // [7] STRUCT crypto_tfm { __crt_alg: [6] @32, refcnt: [3] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        let mut tfm: Vec<(u32, u32, u32)> = Vec::new();
        if let Some(ty) = shape("crypto_tfm", "__crt_alg", 6) {
            tfm.push((o_crt, ty, 32 * 8));
        }
        if let Some(ty) = shape("crypto_tfm", "refcnt", 3) {
            tfm.push((o_refcnt, ty, 40 * 8));
        }
        b.rec(o_tfm, KIND_STRUCT, tfm.len() as u32, false, 64);
        for (name, ty, bits) in tfm {
            b.member(name, ty, bits);
        }
        // [8] PTR -> [7].
        b.rec(0, KIND_PTR, 0, false, 7);
        // [9] STRUCT crypto_async_request { tfm: [8] @32, flags: [1] @40 }.
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        let mut asy: Vec<(u32, u32, u32)> = Vec::new();
        if let Some(ty) = shape("crypto_async_request", "tfm", 8) {
            asy.push((o_tfm_m, ty, 32 * 8));
        }
        if let Some(ty) = shape("crypto_async_request", "flags", 1) {
            asy.push((o_flags, ty, 40 * 8));
        }
        b.rec(o_async, KIND_STRUCT, asy.len() as u32, false, 64);
        for (name, ty, bits) in asy {
            b.member(name, ty, bits);
        }
        // [10] STRUCT skcipher_request { cryptlen: [1] @0, base: [9] @32 }.
        let o_req = b.str("skcipher_request");
        let o_base = b.str("base");
        let o_cryptlen = b.str("cryptlen");
        let mut req: Vec<(u32, u32, u32)> = Vec::new();
        if let Some(ty) = shape("skcipher_request", "cryptlen", 1) {
            req.push((o_cryptlen, ty, 0));
        }
        if let Some(ty) = shape("skcipher_request", "base", 9) {
            req.push((o_base, ty, 32 * 8));
        }
        b.rec(o_req, KIND_STRUCT, req.len() as u32, false, 128);
        for (name, ty, bits) in req {
            b.member(name, ty, bits);
        }
        // [11] STRUCT crypto_skcipher { base: [7] @8 } (72 bytes:
        // the 64-byte embedded `base` must sit INSIDE the parent —
        // R4 containment refuses the old 64-byte lie, exactly like
        // real kernels, where `base` is the trailing member).
        let o_sk = b.str("crypto_skcipher");
        let o_sk_base = b.str("base");
        let mut sk: Vec<(u32, u32, u32)> = Vec::new();
        if let Some(ty) = shape("crypto_skcipher", "base", 7) {
            sk.push((o_sk_base, ty, 8 * 8));
        }
        b.rec(o_sk, KIND_STRUCT, sk.len() as u32, false, 72);
        for (name, ty, bits) in sk {
            b.member(name, ty, bits);
        }
        // [12] ARRAY char[8] (negative-extent patch target: a name
        // bound shorter than the BPF copy must refuse, not truncate
        // silently past the member).
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(8);
        b.finish()
    }

    #[test]
    fn synthetic_lifecycle_offsets_resolve_exact() {
        let bytes = lifecycle_fixture(None, None);
        let off = resolve_lifecycle_offsets_from(&bytes).expect("typed fixture resolves");
        assert_eq!(
            off,
            LifecycleOffsets {
                tfm_alg: 32,
                alg_drv: 188,
                sk_base: 8,
                req_base: 32,
                req_tfm: 32,
                req_cryptlen: 0,
                req_flags: 40,
                refcnt_off: 40,
                refcnt_present: true,
            }
        );
    }

    #[test]
    fn synthetic_lifecycle_wrong_shapes_refuse() {
        // PTR at the wrong pointee (tfm→crypto_tfm where the chase
        // needs crypto_alg): a valid offset with a lying type must
        // refuse — resolving it would mis-chase.
        let bytes = lifecycle_fixture(Some(("crypto_tfm", "__crt_alg", 8)), None);
        assert!(resolve_lifecycle_offsets_from(&bytes).is_err());
        // INT where the chase dereferences a PTR.
        let bytes = lifecycle_fixture(Some(("crypto_async_request", "tfm", 1)), None);
        assert!(resolve_lifecycle_offsets_from(&bytes).is_err());
        // INT where the chase reads an embedded STRUCT base.
        let bytes = lifecycle_fixture(Some(("crypto_skcipher", "base", 1)), None);
        assert!(resolve_lifecycle_offsets_from(&bytes).is_err());
        // Name ARRAY shorter than the 64-byte BPF copy bound.
        let bytes = lifecycle_fixture(Some(("crypto_alg", "cra_driver_name", 12)), None);
        assert!(resolve_lifecycle_offsets_from(&bytes).is_err());
        // Missing link member (not refcnt — refcnt absence is soft).
        let bytes = lifecycle_fixture(None, Some(("crypto_async_request", "tfm")));
        assert!(matches!(
            resolve_lifecycle_offsets_from(&bytes),
            Err(BtfError::MissingMember { .. })
        ));
    }

    #[test]
    fn synthetic_lifecycle_metadata_members_fail_closed() {
        // P3 entry-side scalars are hard members: a missing length
        // or flags word refuses the arm (never a zero-chase).
        let bytes = lifecycle_fixture(None, Some(("skcipher_request", "cryptlen")));
        assert!(matches!(
            resolve_lifecycle_offsets_from(&bytes),
            Err(BtfError::MissingMember { .. })
        ));
        let bytes = lifecycle_fixture(None, Some(("crypto_async_request", "flags")));
        assert!(matches!(
            resolve_lifecycle_offsets_from(&bytes),
            Err(BtfError::MissingMember { .. })
        ));
        // A PTR where the chase reads a u32 scalar refuses (lying type
        // with a valid offset would mis-chase exactly like the link
        // members above).
        let bytes = lifecycle_fixture(Some(("crypto_async_request", "flags", 8)), None);
        assert!(resolve_lifecycle_offsets_from(&bytes).is_err());
    }

    #[test]
    fn synthetic_lifecycle_refcnt_absence_is_soft_but_shape_is_hard() {
        // 7.2 has no `crypto_tfm.refcnt`: absence resolves soft
        // (always-final mode), never a missing-member error.
        let bytes = lifecycle_fixture(None, Some(("crypto_tfm", "refcnt")));
        let off = resolve_lifecycle_offsets_from(&bytes).expect("absence is soft");
        assert!(!off.refcnt_present);
        assert_eq!(off.refcnt_off, 0);
        // Present-but-wrong-shape (a PTR, not a counter) is drift,
        // not absence: fail closed.
        let bytes = lifecycle_fixture(Some(("crypto_tfm", "refcnt", 6)), None);
        assert!(resolve_lifecycle_offsets_from(&bytes).is_err());
    }

    /// Duplicate-`crypto_tfm` fixture (T07-R3-09): a divergent DECOY
    /// def (fully valid shape, `__crt_alg` @24) plus the REAL def (the
    /// `lifecycle_fixture` [7] layout: `__crt_alg` @32, refcnt @40).
    /// The `skcipher`/`async_request` chains ALWAYS link the REAL def
    /// (id-resolved at build time); `decoy_first` orders the decoy
    /// before the real def so first-match entry lookups hit the decoy
    /// while the chains root in the real def.
    fn lifecycle_dup_fixture(decoy_first: bool) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_PTR};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char.
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        // [3] STRUCT refcount_struct { refs: [1] @0 }.
        let o_rc = b.str("refcount_struct");
        let o_refs = b.str("refs");
        b.rec(o_rc, KIND_STRUCT, 1, false, 4);
        b.member(o_refs, 1, 0);
        // [4] ARRAY char[64].
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [5] STRUCT crypto_alg { cra_driver_name: [4] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 4, 188 * 8);
        // [6] PTR -> [5].
        b.rec(0, KIND_PTR, 0, false, 5);
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        // Next emitted id is 7; the two `crypto_tfm` defs take the next
        // two ids in `decoy_first` order.
        let real_id = if decoy_first { 8 } else { 7 };
        // REAL def: `__crt_alg` @32 (PTR -> crypto_alg), refcnt @40.
        let emit_real = |b: &mut BtfBuild| {
            b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
            b.member(o_crt, 6, 32 * 8);
            b.member(o_refcnt, 3, 40 * 8);
        };
        // DECOY def: valid shape, divergent `__crt_alg` @24.
        let emit_decoy = |b: &mut BtfBuild| {
            b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
            b.member(o_crt, 6, 24 * 8);
            b.member(o_refcnt, 3, 40 * 8);
        };
        if decoy_first {
            emit_decoy(&mut b);
            emit_real(&mut b);
        } else {
            emit_real(&mut b);
        }
        // PTR -> REAL def; async/sreq/sk chains root in the real def.
        let ptr_id = if decoy_first { 9 } else { 8 };
        b.rec(0, KIND_PTR, 0, false, real_id);
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, ptr_id, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let async_id = ptr_id + 1;
        let o_req = b.str("skcipher_request");
        let o_base = b.str("base");
        let o_cryptlen = b.str("cryptlen");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, async_id, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, real_id, 8 * 8);
        if !decoy_first {
            emit_decoy(&mut b);
        }
        b.finish()
    }

    #[test]
    fn synthetic_lifecycle_duplicate_tfm_divergent_chain_refuses() {
        // T07-R3-09: entry lookups first-match the DECOY (`__crt_alg`
        // @24) while the alloc/invoke chains root in the REAL def
        // (`__crt_alg` @32) — mixing the two would hand BPF a 24 the
        // real chase never proves. Refuse, naming the rival defs.
        let bytes = lifecycle_dup_fixture(true);
        assert!(matches!(
            resolve_lifecycle_offsets_from(&bytes),
            Err(BtfError::IncompatibleDefinitions { .. })
        ));
    }

    #[test]
    fn synthetic_lifecycle_duplicate_tfm_unreferenced_resolves() {
        // Mere duplication is NOT refusal: the divergent decoy sorts
        // AFTER the real def, every chain links the bound (first) def,
        // and resolution agrees with the single-def fixture exactly.
        let bytes = lifecycle_dup_fixture(false);
        let off = resolve_lifecycle_offsets_from(&bytes).expect("unreferenced dup resolves");
        assert_eq!(
            off,
            LifecycleOffsets {
                tfm_alg: 32,
                alg_drv: 188,
                sk_base: 8,
                req_base: 32,
                req_tfm: 32,
                req_cryptlen: 0,
                req_flags: 40,
                refcnt_off: 40,
                refcnt_present: true,
            }
        );
    }

    /// Lifecycle image whose `crypto_tfm` carries NO direct `refcnt`:
    /// the NAMED member sits `levels` anonymous carriers deep (T07-R3-10
    /// — each carrier is a 4-byte STRUCT with one anonymous member @0;
    /// the last level carries NAMED `refcnt: u32` @0). All other
    /// lifecycle members resolve exactly like `lifecycle_fixture`.
    fn lifecycle_deep_refcnt_fixture(levels: u32) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_PTR};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char, [3] ARRAY char[64].
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [4] STRUCT crypto_alg { cra_driver_name: [3] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 3, 188 * 8);
        // [5] PTR -> [4].
        b.rec(0, KIND_PTR, 0, false, 4);
        // [6] STRUCT crypto_tfm { __crt_alg: [5] @32, anon: [7] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 5, 32 * 8);
        b.member(0, 7, 40 * 8);
        // [7..7+levels): the anonymous chain (4-byte carriers).
        for i in 0..levels {
            if i + 1 == levels {
                b.rec(0, KIND_STRUCT, 1, false, 4);
                b.member(o_refcnt, 1, 0);
            } else {
                b.rec(0, KIND_STRUCT, 1, false, 4);
                b.member(0, 7 + i + 1, 0);
            }
        }
        // Trailing chains root in the REAL lane types: PTR -> [6],
        // async, sreq, sk (ids continue past the chain).
        let mut next = 7 + levels;
        b.rec(0, KIND_PTR, 0, false, 6);
        let ptr_id = next;
        next += 1;
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, ptr_id, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let async_id = next;
        let o_req = b.str("skcipher_request");
        let o_cryptlen = b.str("cryptlen");
        let o_base = b.str("base");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, async_id, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 6, 8 * 8);
        b.finish()
    }

    /// Lifecycle image whose `crypto_tfm` hides `refcnt` behind a
    /// SELF-CYCLIC anonymous carrier (T07-R3-10): carrier C's only
    /// member is anonymous of type C — the search never terminates
    /// with a proven answer.
    fn lifecycle_cyclic_refcnt_fixture() -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_PTR};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char, [3] ARRAY char[64].
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [4] STRUCT crypto_alg { cra_driver_name: [3] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 3, 188 * 8);
        // [5] PTR -> [4].
        b.rec(0, KIND_PTR, 0, false, 4);
        // [6] STRUCT crypto_tfm { __crt_alg: [5] @32, anon: [7] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 5, 32 * 8);
        b.member(0, 7, 40 * 8);
        // [7] STRUCT C { anon: [7] @0 } (self-cycle, 4 bytes).
        b.rec(0, KIND_STRUCT, 1, false, 4);
        b.member(0, 7, 0);
        // [8] PTR -> [6], [9] async, [10] sreq, [11] sk.
        b.rec(0, KIND_PTR, 0, false, 6);
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, 8, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let o_req = b.str("skcipher_request");
        let o_cryptlen = b.str("cryptlen");
        let o_base = b.str("base");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, 9, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 6, 8 * 8);
        b.finish()
    }

    #[test]
    fn synthetic_lifecycle_refcnt_behind_nine_anon_refuses_incomplete() {
        // T07-R3-10: `refcnt` 9 anonymous levels deep EXCEEDS the
        // 8-level search — an incomplete traversal must HARD-error,
        // never soft-absent (soft absence would select always-final
        // mode and retire retained releases unconditionally).
        let bytes = lifecycle_deep_refcnt_fixture(9);
        assert!(matches!(
            resolve_lifecycle_offsets_from(&bytes),
            Err(BtfError::TraversalIncomplete { .. })
        ));
    }

    #[test]
    fn synthetic_lifecycle_refcnt_behind_eight_anon_resolves() {
        // Boundary control: exactly 8 levels is the proven-searchable
        // limit — resolves with `refcnt` found at tfm-relative 40.
        let bytes = lifecycle_deep_refcnt_fixture(8);
        let off = resolve_lifecycle_offsets_from(&bytes).expect("8-deep search completes");
        assert!(off.refcnt_present);
        assert_eq!(off.refcnt_off, 40);
    }

    #[test]
    fn synthetic_lifecycle_refcnt_anon_cycle_refuses_incomplete() {
        // T07-R3-10: a self-cyclic anonymous carrier never yields a
        // proven answer — incomplete, not absent.
        let bytes = lifecycle_cyclic_refcnt_fixture();
        assert!(matches!(
            resolve_lifecycle_offsets_from(&bytes),
            Err(BtfError::TraversalIncomplete { .. })
        ));
    }

    #[test]
    fn synthetic_aggregate_offsets_resolve_nine_exact() {
        // D3: aggregate bring-up resolves its OWN 9 members — the
        // T07 `sk_base` prerequisite it never used is gone.
        let bytes = crypto_fixture(None);
        let off = resolve_aggregate_offsets_from(&bytes).expect("crypto fixture resolves");
        assert_eq!(
            off,
            AggregateOffsets {
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
        let off = AggregateOffsets {
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
        let off = resolve_aggregate_offsets_from(&bytes).expect("6.12 shash layout must resolve");
        assert_eq!(off.shash_base, 8);
    }

    #[test]
    fn shash_base_missing_member_fails_closed() {
        // `crypto_shash` without `base`: resolution failure must still
        // fail closed with `MissingMember` (same exit-4 honesty as the
        // retired C3 refusal — a kernel that drops the member refuses
        // here, never mis-chases in BPF).
        let bytes = crypto_fixture_inner(None, Some(("crypto_shash", "base")));
        let err = resolve_aggregate_offsets_from(&bytes).expect_err("missing shash.base must fail");
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
            let err = resolve_aggregate_offsets_from(&bytes).expect_err("moved link must fail");
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
        named("crypto_skcipher", &[("base", 8)]);
        b.finish()
    }

    #[test]
    fn bringup_combo_matches_split_resolvers() {
        // H1(a): one parse serves all three bringup resolutions —
        // identical results to the three separate resolvers.
        let bytes = bringup_fixture();
        let (ids, off, k5) = resolve_kcrypto_bringup_from(&bytes).expect("combo resolves");
        assert_eq!(ids, resolve_btf_ids_from(&bytes).expect("ids resolve"));
        assert_eq!(
            off,
            resolve_aggregate_offsets_from(&bytes).expect("offsets resolve")
        );
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
            AggregateOffsets {
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

    /// T07-R4-N1 fixture: full lifecycle image whose
    /// `crypto_tfm.refcnt` is a 4-byte kind-flagged UNION of a
    /// full-width `raw` u32 view and a 16-bit bitfield view at bit
    /// offset 8, in `raw_first` member order. The bitfield overlaps
    /// word 0 ([8,24) ⊂ [0,32)) without proving it.
    fn lifecycle_union_bitfield_fixture(raw_first: bool) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_UNION};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char.
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        // [3] UNION counter_u (kind-flagged): bitfield member word
        // carries (width << 24) | bit_offset per `linux/btf.h`.
        let v0 = b.str("v0");
        let v1 = b.str("v1");
        let u_name = b.str("counter_u");
        let bitfield_word = (16u32 << 24) | 8;
        b.rec(u_name, KIND_UNION, 2, true, 4);
        if raw_first {
            b.member(v0, 1, 0);
            b.member(v1, 1, bitfield_word);
        } else {
            b.member(v0, 1, bitfield_word);
            b.member(v1, 1, 0);
        }
        // [4] ARRAY char[64].
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [5] STRUCT crypto_alg { cra_driver_name: [4] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 4, 188 * 8);
        // [6] PTR -> [5].
        b.rec(0, KIND_PTR, 0, false, 5);
        // [7] STRUCT crypto_tfm { __crt_alg: [6] @32, refcnt: [3] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 6, 32 * 8);
        b.member(o_refcnt, 3, 40 * 8);
        // [8] PTR -> [7].
        b.rec(0, KIND_PTR, 0, false, 7);
        // [9] async, [10] sreq, [11] sk.
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, 8, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let o_req = b.str("skcipher_request");
        let o_cryptlen = b.str("cryptlen");
        let o_base = b.str("base");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, 9, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 7, 8 * 8);
        b.finish()
    }

    /// T07-R4-N1 fixture: full lifecycle image whose
    /// `crypto_tfm.refcnt` is a 4-byte UNION (no kind flag) of a
    /// full-width `raw` u32 view at bit 0 and a u16 view at bit
    /// offset 16, in `raw_first` member order. The u16 overlaps
    /// word 0 ([16,32) ⊂ [0,32)) without proving it.
    fn lifecycle_union_offset_fixture(raw_first: bool) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_UNION};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char, [3] INT u16.
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        b.int_enc("", 2, 16, 0, 1);
        // [4] UNION counter_u { raw @0, narrow @16 }.
        let v0 = b.str("v0");
        let v1 = b.str("v1");
        let u_name = b.str("counter_u");
        b.rec(u_name, KIND_UNION, 2, false, 4);
        if raw_first {
            b.member(v0, 1, 0);
            b.member(v1, 3, 16);
        } else {
            b.member(v0, 3, 16);
            b.member(v1, 1, 0);
        }
        // [5] ARRAY char[64].
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [6] STRUCT crypto_alg { cra_driver_name: [5] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 5, 188 * 8);
        // [7] PTR -> [6].
        b.rec(0, KIND_PTR, 0, false, 6);
        // [8] STRUCT crypto_tfm { __crt_alg: [7] @32, refcnt: [4] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 7, 32 * 8);
        b.member(o_refcnt, 4, 40 * 8);
        // [9] PTR -> [8].
        b.rec(0, KIND_PTR, 0, false, 8);
        // [10] async, [11] sreq, [12] sk.
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, 9, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let o_req = b.str("skcipher_request");
        let o_cryptlen = b.str("cryptlen");
        let o_base = b.str("base");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, 10, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 8, 8 * 8);
        b.finish()
    }

    #[test]
    fn synthetic_lifecycle_union_bitfield_raw_first_refuses() {
        let bytes = lifecycle_union_bitfield_fixture(true);
        assert!(
            resolve_lifecycle_offsets_from(&bytes).is_err(),
            "raw-first union must refuse the overlapping bitfield sibling"
        );
    }

    #[test]
    fn synthetic_lifecycle_union_bitfield_narrow_first_refuses() {
        let bytes = lifecycle_union_bitfield_fixture(false);
        assert!(
            resolve_lifecycle_offsets_from(&bytes).is_err(),
            "narrow-first union must refuse regardless of order"
        );
    }

    #[test]
    fn synthetic_lifecycle_union_offset_raw_first_refuses() {
        let bytes = lifecycle_union_offset_fixture(true);
        assert!(
            resolve_lifecycle_offsets_from(&bytes).is_err(),
            "raw-first union must refuse the overlapping u16-at-16 sibling"
        );
    }

    #[test]
    fn synthetic_lifecycle_union_offset_narrow_first_refuses() {
        let bytes = lifecycle_union_offset_fixture(false);
        assert!(
            resolve_lifecycle_offsets_from(&bytes).is_err(),
            "narrow-first union must refuse regardless of order"
        );
    }

    /// T07-R5-01 fixture: full lifecycle image whose
    /// `crypto_tfm.refcnt` is a 4-byte kind-flagged UNION of a
    /// full-width `raw` u32 view and a zero-type (VOID, id 0)
    /// 16-bit bitfield view at bit offset 8, in `raw_first`
    /// member order. The VOID sibling overlaps word 0 ([8,24)
    /// ⊂ [0,32)) without proving it — the `mtype == 0` early
    /// skip must not bypass the N1 overlap refusal.
    fn lifecycle_union_zerotype_fixture(raw_first: bool) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_UNION};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char.
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        // [3] UNION counter_u (kind-flagged): bitfield member word
        // carries (width << 24) | bit_offset per `linux/btf.h`.
        // The narrow sibling names type id 0 (VOID).
        let v0 = b.str("v0");
        let v1 = b.str("v1");
        let u_name = b.str("counter_u");
        let bitfield_word = (16u32 << 24) | 8;
        b.rec(u_name, KIND_UNION, 2, true, 4);
        if raw_first {
            b.member(v0, 1, 0);
            b.member(v1, 0, bitfield_word);
        } else {
            b.member(v0, 0, bitfield_word);
            b.member(v1, 1, 0);
        }
        // [4] ARRAY char[64].
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [5] STRUCT crypto_alg { cra_driver_name: [4] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 4, 188 * 8);
        // [6] PTR -> [5].
        b.rec(0, KIND_PTR, 0, false, 5);
        // [7] STRUCT crypto_tfm { __crt_alg: [6] @32, refcnt: [3] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 6, 32 * 8);
        b.member(o_refcnt, 3, 40 * 8);
        // [8] PTR -> [7].
        b.rec(0, KIND_PTR, 0, false, 7);
        // [9] async, [10] sreq, [11] sk.
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, 8, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let o_req = b.str("skcipher_request");
        let o_cryptlen = b.str("cryptlen");
        let o_base = b.str("base");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, 9, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 7, 8 * 8);
        b.finish()
    }

    #[test]
    fn synthetic_lifecycle_union_zerotype_raw_first_refuses() {
        let bytes = lifecycle_union_zerotype_fixture(true);
        let res = resolve_lifecycle_offsets_from(&bytes);
        assert!(
            res.is_err(),
            "raw-first union must refuse the overlapping zero-type sibling, got {res:?}"
        );
    }

    #[test]
    fn synthetic_lifecycle_union_zerotype_narrow_first_refuses() {
        let bytes = lifecycle_union_zerotype_fixture(false);
        let res = resolve_lifecycle_offsets_from(&bytes);
        assert!(
            res.is_err(),
            "narrow-first union must refuse the zero-type sibling regardless of order, got {res:?}"
        );
    }

    /// T07-R4-N2 fixture: full lifecycle image (layout chains on the
    /// entry defs + all 7 manifest prototypes valid) with a rival
    /// second `crypto_tfm` def `B` ([8], 4 bytes). When
    /// `destroy_rival` is set, `crypto_destroy_tfm`'s arg1 points at
    /// `B` while every layout chain references the entry def `A`
    /// ([7]); otherwise all roots agree on `A` (positive control).
    fn lifecycle_proto_rival_fixture(destroy_rival: bool) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_PTR};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char.
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        // [3] STRUCT refcount_struct { refs: [1] @0 }.
        let o_rc = b.str("refcount_struct");
        let o_refs = b.str("refs");
        b.rec(o_rc, KIND_STRUCT, 1, false, 4);
        b.member(o_refs, 1, 0);
        // [4] ARRAY char[64].
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [5] STRUCT crypto_alg { cra_driver_name: [4] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 4, 188 * 8);
        // [6] PTR -> [5].
        b.rec(0, KIND_PTR, 0, false, 5);
        // [7] STRUCT crypto_tfm A { __crt_alg: [6] @32, refcnt: [3] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 6, 32 * 8);
        b.member(o_refcnt, 3, 40 * 8);
        // [8] STRUCT crypto_tfm B (rival, 4 bytes, nonempty).
        let o_pad = b.str("pad");
        b.rec(o_tfm, KIND_STRUCT, 1, false, 4);
        b.member(o_pad, 1, 0);
        // [9] PTR -> [7].
        b.rec(0, KIND_PTR, 0, false, 7);
        // [10] STRUCT crypto_async_request { tfm: [9] @32, flags: [1] @40 }.
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, 9, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        // [11] STRUCT skcipher_request { cryptlen: [1] @0, base: [10] @32 }.
        let o_req = b.str("skcipher_request");
        let o_base = b.str("base");
        let o_cryptlen = b.str("cryptlen");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, 10, 32 * 8);
        // [12] STRUCT crypto_skcipher { base: [7] @8 }.
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 7, 8 * 8);
        // [13] STRUCT crypto_aead {} (prototype root only).
        let o_aead = b.str("crypto_aead");
        b.rec(o_aead, KIND_STRUCT, 0, false, 64);
        // [14] PTR -> [11] (op arg0), [15] PTR -> [12] (alloc
        // return, setkey-sk arg0), [16] PTR -> destroy target ([8]
        // rival or [7] entry), [17] PTR -> [13] (aead roots),
        // [18] PTR -> [2] (char/key/mem pointers).
        b.rec(0, KIND_PTR, 0, false, 11);
        b.rec(0, KIND_PTR, 0, false, 12);
        b.rec(0, KIND_PTR, 0, false, if destroy_rival { 8 } else { 7 });
        b.rec(0, KIND_PTR, 0, false, 13);
        b.rec(0, KIND_PTR, 0, false, 2);
        // [19] PROTO op (sreq *) -> s32.
        b.rec(0, KIND_FUNC_PROTO, 1, false, 1);
        b.word(0);
        b.word(14);
        // [20] PROTO alloc (char *, u32, u32) -> sk *.
        b.rec(0, KIND_FUNC_PROTO, 3, false, 15);
        b.word(0);
        b.word(18);
        b.word(0);
        b.word(1);
        b.word(0);
        b.word(1);
        // [21] PROTO destroy (mem *, tfm *) -> void.
        b.rec(0, KIND_FUNC_PROTO, 2, false, 0);
        b.word(0);
        b.word(18);
        b.word(0);
        b.word(16);
        // [22] PROTO setkey-sk (sk *, key *, u32) -> s32.
        b.rec(0, KIND_FUNC_PROTO, 3, false, 1);
        b.word(0);
        b.word(15);
        b.word(0);
        b.word(18);
        b.word(0);
        b.word(1);
        // [23] PROTO setauthsize (aead *, u32) -> s32.
        b.rec(0, KIND_FUNC_PROTO, 2, false, 1);
        b.word(0);
        b.word(17);
        b.word(0);
        b.word(1);
        // [24] PROTO setkey-aead (aead *, key *, u32) -> s32.
        b.rec(0, KIND_FUNC_PROTO, 3, false, 1);
        b.word(0);
        b.word(17);
        b.word(0);
        b.word(18);
        b.word(0);
        b.word(1);
        // [25..31] the 7 manifest FUNCs.
        for (name, proto) in [
            ("crypto_skcipher_encrypt", 19),
            ("crypto_skcipher_decrypt", 19),
            ("crypto_alloc_skcipher", 20),
            ("crypto_destroy_tfm", 21),
            ("crypto_skcipher_setkey", 22),
            ("crypto_aead_setauthsize", 23),
            ("crypto_aead_setkey", 24),
        ] {
            let o_name = b.str(name);
            b.rec(o_name, KIND_FUNC, 1, false, proto);
        }
        b.finish()
    }

    #[test]
    fn synthetic_lifecycle_ids_destroy_rival_root_refuses() {
        // The layout chains agree on the entry def, so the offsets
        // resolver passes — the refusal must come from the prototype
        // root binding (ids resolver), which sees destroy point at
        // the rival def.
        let bytes = lifecycle_proto_rival_fixture(true);
        let off = resolve_lifecycle_offsets_from(&bytes).expect("chains agree on A");
        assert_eq!(off.refcnt_off, 40);
        assert!(off.refcnt_present);
        let err = resolve_lifecycle_ids_from(&bytes)
            .expect_err("destroy rooted in the rival def must refuse");
        assert!(
            matches!(
                err,
                BtfError::IncompatibleDefinitions {
                    entry_id: 7,
                    linked_id: 8,
                    ..
                }
            ),
            "rival root must refuse as incompatible definitions, got {err:?}"
        );
    }

    #[test]
    fn synthetic_lifecycle_ids_all_entry_roots_resolve() {
        // Positive control: every prototype root points at the bound
        // entry def — both resolvers agree with exact offsets.
        let bytes = lifecycle_proto_rival_fixture(false);
        let ids = resolve_lifecycle_ids_from(&bytes).expect("all-A roots resolve");
        assert_eq!(ids.len(), 7);
        assert_eq!(ids["crypto_destroy_tfm"], 28);
        assert_eq!(
            resolve_lifecycle_offsets_from(&bytes).expect("all-A chains resolve"),
            LifecycleOffsets {
                tfm_alg: 32,
                alg_drv: 188,
                sk_base: 8,
                req_base: 32,
                req_tfm: 32,
                req_cryptlen: 0,
                req_flags: 40,
                refcnt_off: 40,
                refcnt_present: true,
            }
        );
    }

    /// T07-R4-02 fixture: full lifecycle image whose
    /// `crypto_tfm.refcnt` is a 4-byte UNION of a full-width `raw`
    /// u32 view and a malformed INT leaf declaring storage size
    /// `0x2000_0004` with a 32-bit zero-offset value, in `raw_first`
    /// member order. The wrapper (4 bytes) passes every extent
    /// gate, so the leaf reaches the size check directly: `size * 8`
    /// wraps to 32 in release (fail-open) and panics in debug/test.
    fn lifecycle_malformed_leaf_fixture(raw_first: bool) -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_UNION};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT char, [3] INT malformed size.
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.rec(0, KIND_INT, 0, false, 1);
        b.word(0x0100_0008);
        b.int_enc("", 0x2000_0004, 32, 0, 1);
        // [4] UNION counter_u { raw @0, bad @0 }.
        let v0 = b.str("v0");
        let v1 = b.str("v1");
        let u_name = b.str("counter_u");
        b.rec(u_name, KIND_UNION, 2, false, 4);
        if raw_first {
            b.member(v0, 1, 0);
            b.member(v1, 3, 0);
        } else {
            b.member(v0, 3, 0);
            b.member(v1, 1, 0);
        }
        // [5] ARRAY char[64].
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(64);
        // [6] STRUCT crypto_alg { cra_driver_name: [5] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 5, 188 * 8);
        // [7] PTR -> [6].
        b.rec(0, KIND_PTR, 0, false, 6);
        // [8] STRUCT crypto_tfm { __crt_alg: [7] @32, refcnt: [4] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 7, 32 * 8);
        b.member(o_refcnt, 4, 40 * 8);
        // [9] PTR -> [8].
        b.rec(0, KIND_PTR, 0, false, 8);
        // [10] async, [11] sreq, [12] sk.
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, 9, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let o_req = b.str("skcipher_request");
        let o_cryptlen = b.str("cryptlen");
        let o_base = b.str("base");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, 10, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 8, 8 * 8);
        b.finish()
    }

    /// T07-R4-02 fixture: full lifecycle image whose
    /// `cra_driver_name` is an EMPTY array (`nelems == 0`, so the
    /// member-extent gate computes `0 * size == 0` and lets the
    /// member through) of INTs declaring storage size `0x2000_0001`
    /// with an 8-bit zero-offset value. The element reaches the size
    /// check directly: `size * 8` wraps to 8 in release (where the
    /// later `nelems` gate still refuses) and panics in debug/test.
    fn lifecycle_malformed_element_fixture() -> Vec<u8> {
        use crate::btf::{KIND_ARRAY, KIND_PTR};
        let mut b = BtfBuild::new();
        // [1] INT u32, [2] INT malformed size.
        b.rec(0, KIND_INT, 0, false, 4);
        b.word(0x0100_0020);
        b.int_enc("", 0x2000_0001, 8, 0, 1);
        // [3] STRUCT refcount_struct { refs: [1] @0 }.
        let o_rc = b.str("refcount_struct");
        let o_refs = b.str("refs");
        b.rec(o_rc, KIND_STRUCT, 1, false, 4);
        b.member(o_refs, 1, 0);
        // [4] ARRAY [2] x 0 (empty: extent 0 passes the member
        // gate so the element itself reaches the size check).
        b.rec(0, KIND_ARRAY, 0, false, 0);
        b.word(2);
        b.word(1);
        b.word(0);
        // [5] STRUCT crypto_alg { cra_driver_name: [4] @188 }.
        let o_alg = b.str("crypto_alg");
        let o_drv = b.str("cra_driver_name");
        b.rec(o_alg, KIND_STRUCT, 1, false, 256);
        b.member(o_drv, 4, 188 * 8);
        // [6] PTR -> [5].
        b.rec(0, KIND_PTR, 0, false, 5);
        // [7] STRUCT crypto_tfm { __crt_alg: [6] @32, refcnt: [3] @40 }.
        let o_tfm = b.str("crypto_tfm");
        let o_crt = b.str("__crt_alg");
        let o_refcnt = b.str("refcnt");
        b.rec(o_tfm, KIND_STRUCT, 2, false, 64);
        b.member(o_crt, 6, 32 * 8);
        b.member(o_refcnt, 3, 40 * 8);
        // [8] PTR -> [7].
        b.rec(0, KIND_PTR, 0, false, 7);
        // [9] async, [10] sreq, [11] sk.
        let o_async = b.str("crypto_async_request");
        let o_tfm_m = b.str("tfm");
        let o_flags = b.str("flags");
        b.rec(o_async, KIND_STRUCT, 2, false, 64);
        b.member(o_tfm_m, 8, 32 * 8);
        b.member(o_flags, 1, 40 * 8);
        let o_req = b.str("skcipher_request");
        let o_cryptlen = b.str("cryptlen");
        let o_base = b.str("base");
        b.rec(o_req, KIND_STRUCT, 2, false, 128);
        b.member(o_cryptlen, 1, 0);
        b.member(o_base, 9, 32 * 8);
        let o_sk = b.str("crypto_skcipher");
        b.rec(o_sk, KIND_STRUCT, 1, false, 72);
        b.member(o_base, 7, 8 * 8);
        b.finish()
    }

    #[test]
    fn synthetic_lifecycle_malformed_leaf_raw_first_refuses() {
        let bytes = lifecycle_malformed_leaf_fixture(true);
        let err = resolve_lifecycle_offsets_from(&bytes)
            .expect_err("wrapping leaf size must refuse, never pass or panic");
        assert!(
            matches!(err, BtfError::BadBtf { ref reason } if reason.contains("bytes, not 4")),
            "size gate must refuse the wrapping leaf, got {err:?}"
        );
    }

    #[test]
    fn synthetic_lifecycle_malformed_leaf_narrow_first_refuses() {
        let bytes = lifecycle_malformed_leaf_fixture(false);
        let err = resolve_lifecycle_offsets_from(&bytes)
            .expect_err("wrapping leaf size must refuse, never pass or panic");
        assert!(
            matches!(err, BtfError::BadBtf { ref reason } if reason.contains("bytes, not 4")),
            "size gate must refuse the wrapping leaf, got {err:?}"
        );
    }

    #[test]
    fn synthetic_lifecycle_malformed_element_int_refuses() {
        let bytes = lifecycle_malformed_element_fixture();
        let err = resolve_lifecycle_offsets_from(&bytes)
            .expect_err("wrapping element size must refuse, never pass or panic");
        assert!(
            matches!(err, BtfError::BadBtf { ref reason } if reason.contains("bytes, not 1")),
            "size gate must refuse the wrapping element, got {err:?}"
        );
    }
}
