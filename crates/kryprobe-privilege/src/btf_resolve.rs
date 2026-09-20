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
//! 9-offsets → 76B projection, K1 44B head + zeroed K5 tail) and
//! [`load_kcrypto_configured`] (the single resolve → load → write-KCFG
//! → attach entry K2 calls).

use crate::attach::OwnedLink;
use crate::bpfloader::{LoadedKcrypto, LoaderError, PointStatus, load_kcrypto};
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
    Io {
        detail: String,
    },
    BadBtf {
        reason: String,
    },
    MissingFunc {
        name: String,
    },
    MissingType {
        name: String,
    },
    MissingMember {
        type_name: String,
        member: String,
    },
    FirstMemberMoved {
        type_name: String,
        member: String,
        offset: u32,
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
        }
    }
}

impl std::error::Error for BtfError {}

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

/// Resolve the 9 [`KCRYPTO_SYMBOLS`] to vmlinux BTF ids. Unprivileged.
/// Every symbol must resolve; the first missing one fails the whole
/// call (fail-closed: a half map would silently drop attach points).
pub fn resolve_btf_ids() -> Result<HashMap<String, u32>, BtfError> {
    let bytes = std::fs::read(VMLINUX_BTF).map_err(|err| BtfError::Io {
        detail: format!("{VMLINUX_BTF}: {err}"),
    })?;
    resolve_btf_ids_from(&bytes)
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
    let bytes = std::fs::read(VMLINUX_BTF).map_err(|err| BtfError::Io {
        detail: format!("{VMLINUX_BTF}: {err}"),
    })?;
    resolve_offsets_from(&bytes)
}

/// Pure CONFIG projection (K1 Task 3): the 9 resolved offsets +
/// [`PF_KTHREAD`] + zero pad → the 76B [`KConfig`] in C2 word order
/// (K5 appends the attribution tail, zeroed here: Task 3 resolves the
/// parent/params offsets + flags and fills them).
/// Total (no failure mode: every input word is copied verbatim).
#[must_use]
pub fn kconfig_from_offsets(off: CryptoOffsets) -> KConfig {
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
        // K5 attribution tail: zeros until Task 3 wires resolution
        // (`parent_ok == 0` / `params_ok == 0` = chases disabled,
        // fail-soft by construction).
        task_real_parent: 0,
        task_tgid: 0,
        task_comm: 0,
        cra_blocksize: 0,
        cra_ivsize: 0,
        cra_min_keysize: 0,
        cra_max_keysize: 0,
        parent_ok: 0,
        params_ok: 0,
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
    Failed { detail: String },
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
pub struct ConfiguredKcrypto {
    /// Loaded maps + programs (only the programs that loaded).
    pub loaded: LoadedKcrypto,
    /// Live tracing links (only the points that attached), load order.
    pub links: Vec<(String, OwnedLink)>,
}

/// Configured bring-up failure: resolution, load, KCFG write, group
/// minting, or a total attach failure. Per-point outcomes ride the
/// [`ConfiguredError::NoPointAttached`] variant (diagnosable, never
/// swallowed); every other stage fails before any point exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfiguredError {
    Resolve(BtfError),
    Load(LoaderError),
    Configure(MapOpsError),
    AttachSetup { detail: String },
    NoPointAttached { points: Vec<ConfiguredPoint> },
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
        }
    }
}

impl std::error::Error for ConfiguredError {}

/// Zero-identity object for system-wide groups (the fexit path never
/// reads it; same shape as the suite scaffolding).
fn system_object() -> ObjectRef {
    ObjectRef {
        dev: 0,
        ino: 0,
        size: 0,
        mtime: 0,
        role: ObjectRole::Executable,
    }
}

/// Single configured entry for K2: resolve BTF ids + offsets → load →
/// write KCFG → attach every loaded point system-wide.
///
/// Physical order is resolve → load → write → attach (the KCFG write
/// needs the loaded map fd, so it cannot precede the load): KCFG lands
/// BEFORE any attach, so no observation runs unconfigured (the BPF
/// `pf_kthread` gate would skip it anyway).
///
/// `token` reuses the [`load_kcrypto`] convention (`None` loads with
/// privilege, `Some` with a borrowed BPF token fd); the attach step
/// always needs privilege (the tracing link carries no token field).
/// Per-point outcomes surface in the returned [`ConfiguredPoint`]s in
/// parsed-program order (load verdict + attach verdict each).
///
/// Each link rides its own allocator-issued [`LinkGroup`] (generation
/// 1, single-shot bring-up issuance — the fexit attach ignores cookies
/// and only generation-guards, so group and guard share issuance and
/// never go stale) through the attach facet
/// (`AttachAuthority::attach_group` on [`LocalPrivilegedAuthority`]).
/// The program label rides `UprobeMultiSelfProbe` until a dedicated
/// `ProgramId` lands (K2's call; the attach path ignores it).
///
/// Succeeds iff at least one point attaches (the load rule, mapped
/// forward); a total attach failure drops everything (RAII) and
/// returns the per-point outcomes in the error.
pub fn load_kcrypto_configured(
    object_bytes: &[u8],
    token: Option<RawFd>,
) -> Result<(ConfiguredKcrypto, Vec<ConfiguredPoint>), ConfiguredError> {
    let ids = resolve_btf_ids().map_err(ConfiguredError::Resolve)?;
    let off = resolve_offsets().map_err(ConfiguredError::Resolve)?;
    let entries: Vec<(String, u32)> = KCRYPTO_SYMBOLS
        .iter()
        .map(|name| ((*name).to_owned(), ids[*name]))
        .collect();
    let (loaded, statuses) =
        load_kcrypto(object_bytes, &entries, token).map_err(ConfiguredError::Load)?;
    let cfg = kconfig_from_offsets(off);
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
            ProgramId::UprobeMultiSelfProbe,
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
    let bytes = std::fs::read(VMLINUX_BTF).map_err(|err| BtfError::Io {
        detail: format!("{VMLINUX_BTF}: {err}"),
    })?;
    let btf = Btf::parse(&bytes)?;
    btf.member_offset(type_name, member)
}

fn resolve_btf_ids_from(bytes: &[u8]) -> Result<HashMap<String, u32>, BtfError> {
    let btf = Btf::parse(bytes)?;
    let mut out = HashMap::with_capacity(KCRYPTO_SYMBOLS.len());
    for name in KCRYPTO_SYMBOLS {
        let id = btf.func_id(name)?.ok_or_else(|| BtfError::MissingFunc {
            name: (*name).to_owned(),
        })?;
        out.insert((*name).to_owned(), id);
    }
    Ok(out)
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

/// Raw BTF header length minimum (magic + version/flags + 5 u32s).
const BTF_HDR_MIN: usize = 24;
/// BTF magic (`0xEB9F`), little-endian.
const BTF_MAGIC: u16 = 0xEB9F;
/// BTF version the kernel writes.
const BTF_VERSION: u8 = 1;

/// BTF kinds (`linux/btf.h`): only the aux shapes matter here.
const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;

/// Anonymous-descent + typedef-chain depth cap (vmlinux nesting is ≤3;
/// the cap only bounds hostile images).
const DESCENT_CAP: usize = 8;

fn bad(reason: String) -> BtfError {
    BtfError::BadBtf { reason }
}

/// One decoded type header: ids are 1-based, `types[id - 1]`.
struct TypeRec {
    kind: u8,
    vlen: u32,
    kind_flag: bool,
    name_off: u32,
    size_or_type: u32,
    /// File offset of the aux records (past the 12-byte header).
    aux_at: usize,
}

/// Parsed BTF image: borrowed bytes + decoded type headers + strtab.
struct Btf<'a> {
    bytes: &'a [u8],
    types: Vec<TypeRec>,
    str_at: usize,
    str_len: usize,
}

fn read_u32(bytes: &[u8], at: usize, what: &str) -> Result<u32, BtfError> {
    bytes
        .get(at..at.saturating_add(4))
        .filter(|w| w.len() == 4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .ok_or_else(|| bad(format!("{what} at {at:#x} runs past the end")))
}

impl<'a> Btf<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, BtfError> {
        if bytes.len() < BTF_HDR_MIN {
            return Err(bad(format!("header truncated ({} bytes)", bytes.len())));
        }
        let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if magic != BTF_MAGIC {
            return Err(bad(format!("magic {magic:#x} is not BTF")));
        }
        if bytes[2] != BTF_VERSION {
            return Err(bad(format!("version {} is not BTF v1", bytes[2])));
        }
        let hdr_len = read_u32(bytes, 4, "hdr_len")? as usize;
        if hdr_len < BTF_HDR_MIN {
            return Err(bad(format!("hdr_len {hdr_len} is below 24")));
        }
        let word = |at: usize, what: &str| read_u32(bytes, at, what).map(|w| w as usize);
        let (type_off, type_len) = (word(8, "type_off")?, word(12, "type_len")?);
        let (str_off, str_len) = (word(16, "str_off")?, word(20, "str_len")?);
        let base = |off: usize, len: usize, what: &str| -> Result<(usize, usize), BtfError> {
            let start = hdr_len
                .checked_add(off)
                .ok_or_else(|| bad(format!("{what} offset overflows")))?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| bad(format!("{what} range overflows")))?;
            if end > bytes.len() {
                return Err(bad(format!("{what} range runs past the end")));
            }
            Ok((start, len))
        };
        let (type_at, type_len) = base(type_off, type_len, "type section")?;
        let (str_at, str_len) = base(str_off, str_len, "string section")?;
        // vmlinux strtab starts with the empty string; an empty table
        // cannot name anything, so refuse it outright.
        if str_len == 0 {
            return Err(bad("string section is empty".to_owned()));
        }
        let mut types = Vec::new();
        let mut pos = type_at;
        let type_end = type_at + type_len;
        while pos < type_end {
            if pos + 12 > type_end {
                return Err(bad(format!("type record at {pos:#x} is truncated")));
            }
            let name_off = read_u32(bytes, pos, "type name_off")?;
            let info = read_u32(bytes, pos + 4, "type info")?;
            let size_or_type = read_u32(bytes, pos + 8, "type size/type")?;
            let (kind, vlen, kind_flag) =
                (((info >> 24) & 0x1f) as u8, info & 0xffff, info >> 31 == 1);
            let aux_len = aux_len(kind, vlen)?;
            let aux_at = pos + 12;
            if aux_at + aux_len > type_end {
                return Err(bad(format!(
                    "type record at {pos:#x} aux runs past the end"
                )));
            }
            types.push(TypeRec {
                kind,
                vlen,
                kind_flag,
                name_off,
                size_or_type,
                aux_at,
            });
            pos = aux_at + aux_len;
        }
        Ok(Self {
            bytes,
            types,
            str_at,
            str_len,
        })
    }

    /// String-table bytes at `off` (NUL-terminated, bounds-checked).
    fn str_at(&self, off: u32) -> Result<&[u8], BtfError> {
        let start = (off as usize)
            .checked_add(self.str_at)
            .ok_or_else(|| bad(format!("string offset {off} overflows")))?;
        let end = self.str_at + self.str_len;
        if start >= end {
            return Err(bad(format!("string offset {off} is outside the table")));
        }
        let tail = &self.bytes[start..end];
        let len = tail
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| bad(format!("string at {off} is unterminated")))?;
        Ok(&tail[..len])
    }

    fn name_is(&self, rec: &TypeRec, want: &str) -> Result<bool, BtfError> {
        // Corrupt string refs fail closed (a skipped name could hide
        // the record we want and misreport it as missing).
        Ok(self.str_at(rec.name_off)? == want.as_bytes())
    }

    /// First `FUNC` id with `name` (id order; our 9 are single-definition).
    fn func_id(&self, name: &str) -> Result<Option<u32>, BtfError> {
        for (i, rec) in self.types.iter().enumerate() {
            if rec.kind == KIND_FUNC && self.name_is(rec, name)? {
                return Ok(Some(i as u32 + 1));
            }
        }
        Ok(None)
    }

    /// Byte offset of `member` in struct/union `type_name`, descending
    /// into anonymous members (offsets add). TYPEDEF names resolve to
    /// their struct; anything else is missing, never guessed.
    fn member_offset(&self, type_name: &str, member: &str) -> Result<u32, BtfError> {
        let root = self.find_struct(type_name)?;
        let mut path = [0u32; DESCENT_CAP + 1];
        self.member_at(root, member, 0, &mut path)?
            .ok_or_else(|| BtfError::MissingMember {
                type_name: type_name.to_owned(),
                member: member.to_owned(),
            })
    }

    /// Struct/union id for `name`, directly or through one TYPEDEF.
    /// TYPEDEF chains resolve iteratively (cap-bounded, cycle-guarded).
    fn find_struct(&self, name: &str) -> Result<u32, BtfError> {
        for (i, rec) in self.types.iter().enumerate() {
            if matches!(rec.kind, KIND_STRUCT | KIND_UNION) && self.name_is(rec, name)? {
                return Ok(i as u32 + 1);
            }
        }
        let mut next = None;
        for rec in &self.types {
            if rec.kind == KIND_TYPEDEF && self.name_is(rec, name)? {
                next = Some(rec.size_or_type);
                break;
            }
        }
        let mut seen = [0u32; DESCENT_CAP + 1];
        for depth in 0..=DESCENT_CAP {
            let Some(id) = next else { break };
            if id == 0 || seen[..depth].contains(&id) {
                break;
            }
            seen[depth] = id;
            let rec = self.rec(id)?;
            match rec.kind {
                KIND_STRUCT | KIND_UNION => return Ok(id),
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                    next = Some(rec.size_or_type);
                }
                _ => break,
            }
        }
        Err(BtfError::MissingType {
            name: name.to_owned(),
        })
    }

    fn rec(&self, id: u32) -> Result<&TypeRec, BtfError> {
        usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_sub(1))
            .and_then(|i| self.types.get(i))
            .ok_or_else(|| bad(format!("dangling type id {id}")))
    }

    /// Member search under struct/union `id`: `Ok(None)` when absent
    /// here (callers keep looking outward); misaligned offsets are
    /// `BadBtf` (fail-closed: our reads are all byte-aligned).
    fn member_at(
        &self,
        id: u32,
        member: &str,
        depth: usize,
        path: &mut [u32; DESCENT_CAP + 1],
    ) -> Result<Option<u32>, BtfError> {
        if depth > DESCENT_CAP || path[..depth].contains(&id) {
            return Ok(None);
        }
        path[depth] = id;
        let rec = self.rec(id)?;
        if !matches!(rec.kind, KIND_STRUCT | KIND_UNION) {
            return Ok(None);
        }
        for m in 0..rec.vlen as usize {
            let at = rec.aux_at + m * 12;
            let name_off = read_u32(self.bytes, at, "member name_off")?;
            let mtype = read_u32(self.bytes, at + 4, "member type")?;
            let raw = read_u32(self.bytes, at + 8, "member offset")?;
            // Bit offset: low 24 bits when the kind flag marks
            // bitfield packing, the whole word otherwise (BTF spec).
            let bits = if rec.kind_flag {
                raw & 0x00ff_ffff
            } else {
                raw
            };
            if !bits.is_multiple_of(8) {
                return Err(bad(format!(
                    "member at {at:#x} is not byte-aligned ({bits} bits)"
                )));
            }
            let base = bits / 8;
            if name_off != 0 && self.str_at(name_off)? == member.as_bytes() {
                return Ok(Some(base));
            }
            if name_off == 0 && mtype != 0 {
                // Anonymous member: descend into struct/union shapes
                // (through const/typedef wrappers), offsets add.
                let mut inner = Some(mtype);
                let mut seen = [0u32; DESCENT_CAP + 1];
                for d in 0..=DESCENT_CAP {
                    let Some(tid) = inner else { break };
                    if tid == 0 || seen[..d].contains(&tid) {
                        break;
                    }
                    seen[d] = tid;
                    let trec = self.rec(tid)?;
                    match trec.kind {
                        KIND_STRUCT | KIND_UNION => {
                            if let Some(off) = self.member_at(tid, member, depth + 1, path)? {
                                return Ok(Some(base.checked_add(off).ok_or_else(|| {
                                    bad("anonymous member offset overflows".to_owned())
                                })?));
                            }
                            break;
                        }
                        KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => {
                            inner = Some(trec.size_or_type);
                        }
                        _ => break,
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Aux byte length for one type record: fixed shapes assert `vlen == 0`
/// (anything else is malformed BTF); `FUNC`/`VAR` carry linkage
/// (0 static, 1 global) in `vlen`, not a count.
fn aux_len(kind: u8, vlen: u32) -> Result<usize, BtfError> {
    let fixed = |want: usize| {
        if vlen == 0 {
            Ok(want)
        } else {
            Err(bad(format!("kind {kind} carries unexpected vlen {vlen}")))
        }
    };
    let linkage = |want: usize| {
        if vlen <= 1 {
            Ok(want)
        } else {
            Err(bad(format!("kind {kind} carries bogus linkage {vlen}")))
        }
    };
    match kind {
        KIND_INT => fixed(4),
        KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
        | KIND_FLOAT | KIND_TYPE_TAG => fixed(0),
        KIND_FUNC => linkage(0),
        KIND_VAR => linkage(4),
        KIND_ARRAY => fixed(12),
        // `vlen` is 16 bits: `vlen * 12` (max 786,420) cannot
        // overflow `usize` on any supported target.
        KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => Ok(vlen as usize * 12),
        KIND_ENUM | KIND_FUNC_PROTO => Ok(vlen as usize * 8),
        KIND_DECL_TAG => fixed(4),
        other => Err(bad(format!("unknown BTF kind {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // assumption, never a guess).
        let mut bytes = fixture();
        // [3] aux starts at 24 (hdr) + 12 ([1]) + 12 ([2]) + 12 ([3] hdr).
        let m1_off_at = 24 + 12 + 12 + 12 + 12 + 8;
        bytes[m1_off_at..m1_off_at + 4].copy_from_slice(&7u32.to_le_bytes());
        let btf = Btf::parse(&bytes).expect("shape still parses");
        assert!(matches!(
            btf.member_offset("tstruct", "bbb"),
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
        // Pure CONFIG projection (K1 Task 3): the 9 resolved offsets +
        // PF_KTHREAD + zero pad → the 76B KCFG wire layout in C2 word
        // order (brief Step 1: KCFG bytes equal the resolved offsets;
        // K5 appends a zeroed attribution tail until Task 3 wires it).
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
        let cfg = kconfig_from_offsets(off);
        let mut want = [0u8; 76];
        for (i, word) in [32u32, 32, 32, 60, 188, 44, PF_KTHREAD, 52, 48, 8, 0]
            .iter()
            .enumerate()
        {
            want[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        // K5 tail: 7 zero offsets + zero flags + zero pad.
        assert_eq!(want[44..], [0u8; 32]);
        assert_eq!(cfg.to_bytes(), want);
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
}
