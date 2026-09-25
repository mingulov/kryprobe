// SPDX-License-Identifier: GPL-3.0-or-later
//! Named lifecycle profiles: manifest tables + gates (T06 H01).
//!
//! Two profiles share the loader machinery but never each other's
//! shape: `ApiReturns` keeps the frozen fexit-only contract (C1 —
//! adding a profile must not relax it), while `RequestLifecycle`
//! pairs entry+return edges per T04-qualified site. The program
//! limit derives from each profile's own manifest, never from the
//! other profile's cap.

use crate::bpfloader::{LoaderError, MapDims, PointStatus};
use kryprobe_abi::kcrypto_lifecycle::{LCONFIG_DISABLED, LCONFIG_MAGIC, LCONFIG_VERSION};

pub use crate::bpfloader::parse::parse_lifecycle_object;

/// Named capture profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LifecycleProfile {
    /// Frozen aggregate sensor: fexit-only object, 16-program cap
    /// (the default: selecting nothing keeps current behavior).
    #[default]
    ApiReturns,
    /// Edge-pairing sensor: one fsession program (paired
    /// entry/return runs) per required site.
    RequestLifecycle,
}

impl LifecycleProfile {
    /// Parse the exact CLI spelling (`api-returns` /
    /// `request-lifecycle`); anything else refuses (`None` → usage
    /// error at the call site, never a silent default).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "api-returns" => Some(Self::ApiReturns),
            "request-lifecycle" => Some(Self::RequestLifecycle),
            _ => None,
        }
    }

    /// CLI spelling of this profile.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiReturns => "api-returns",
            Self::RequestLifecycle => "request-lifecycle",
        }
    }
}

/// Cross-profile refusal: another profile holds the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBusy {
    /// Profile currently live in this process.
    pub live: LifecycleProfile,
    /// Profile that was refused.
    pub want: LifecycleProfile,
}

impl std::fmt::Display for SessionBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.live == self.want {
            write!(
                f,
                "kcrypto session busy: '{}' is live, second holder refused (single lifecycle sensor per process)",
                self.live.as_str(),
            )
        } else {
            write!(
                f,
                "kcrypto session busy: '{}' is live, '{}' refused (no cross-profile capture)",
                self.live.as_str(),
                self.want.as_str()
            )
        }
    }
}

impl std::error::Error for SessionBusy {}

/// Process-wide live profile + holder count (round-1 sol-M5/astra-M8:
/// no CROSS-PROFILE capture — the two profiles never capture together
/// in one process). `ApiReturns` holders share (aggregate concurrency
/// is unchanged by design — each session brings up its own sensor and
/// observes the same machine-wide calls through its own ledger), but
/// `RequestLifecycle` is single-owner (H5: a second lifecycle sensor
/// would double-capture through retired trampolines). The count
/// releases the process when the last holder of a profile drops.
static LIVE_PROFILE: std::sync::Mutex<(Option<LifecycleProfile>, usize)> =
    std::sync::Mutex::new((None, 0));

/// RAII holder of one profile's process share. Dropping releases one
/// hold; the last drop of a profile frees the process for the other.
#[derive(Debug)]
pub struct SessionGuard {
    profile: LifecycleProfile,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut live = LIVE_PROFILE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if live.0 == Some(self.profile) {
            live.1 = live.1.saturating_sub(1);
            if live.1 == 0 {
                live.0 = None;
            }
        }
    }
}

/// Acquire one hold of `profile`'s process share: succeeds when the
/// process is free or already holds `profile`; refuses typed when the
/// OTHER profile is live.
pub fn acquire_kcrypto_session(profile: LifecycleProfile) -> Result<SessionGuard, SessionBusy> {
    let mut live = LIVE_PROFILE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    match live.0 {
        None => {
            *live = (Some(profile), 1);
            Ok(SessionGuard { profile })
        }
        Some(held) if held == profile => {
            // H5 (W8): a second RequestLifecycle holder would attach a
            // duplicate sensor (mutual trampoline retirement +
            // double-capture of the same machine-wide calls), so the
            // lifecycle sensor is single-owner; ApiReturns sharing
            // stays (aggregate concurrency by design).
            if profile == LifecycleProfile::RequestLifecycle {
                return Err(SessionBusy {
                    live: held,
                    want: profile,
                });
            }
            live.1 += 1;
            Ok(SessionGuard { profile })
        }
        Some(held) => Err(SessionBusy {
            live: held,
            want: profile,
        }),
    }
}

/// Prototype shape the bring-up validators pin per site: the op
/// sites read `(request *) -> int`, the allocation sites read
/// `(name, type, mask) -> tfm *`, the destroy site reads
/// `(mem *, tfm *) -> void`, the setkey sites read
/// `(frontend *, key *, len) -> int`, and the setauthsize site
/// reads `(aead *, authsize) -> int`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoShape {
    /// `int (struct skcipher_request *)` (op sites).
    Op,
    /// `struct crypto_skcipher *(const char *, u32, u32)` (alloc sites).
    Alloc,
    /// `void (void *, struct crypto_tfm *)` (destroy site).
    Destroy,
    /// `int (struct crypto_skcipher *, const u8 *, unsigned int)`
    /// (skcipher-setkey site).
    SetkeySk,
    /// `int (struct crypto_aead *, unsigned int)` (setauthsize site).
    SetAuthsize,
    /// `int (struct crypto_aead *, const u8 *, unsigned int)`
    /// (aead-setkey site).
    SetkeyAead,
}

/// One required attach site: kernel symbol with a single fsession
/// program (W8: entry+return ride one link; both edges required).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredSite {
    /// Kernel function name (section suffix after `fsession/`).
    pub symbol: &'static str,
    /// Prototype shape the validator pins for this symbol.
    pub shape: ProtoShape,
}

/// The profile contract: name, required sites, frozen map table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileManifest {
    /// Profile name (sensor label).
    pub name: &'static str,
    /// Attach sites the object AND the kernel must supply; a missing
    /// required site refuses lifecycle startup (no per-point degrade).
    pub required: &'static [RequiredSite],
    /// Exact map table the object must carry (no missing, no extra).
    pub maps: &'static [(&'static str, MapDims)],
}

/// Program lanes per `LLOSS` class (BPF hook order: the 16
/// `LAGG_*` hooks, enc-sub first; class `c` occupies entries
/// `c * LLOSS_LANES_PER_CLASS..c * LLOSS_LANES_PER_CLASS + 16`).
pub const LLOSS_LANES_PER_CLASS: u32 = 16;
/// `LLOSS` entries: 5 classes × [`LLOSS_LANES_PER_CLASS`].
pub const LLOSS_ENTRIES: u32 = 5 * LLOSS_LANES_PER_CLASS;

/// Frozen lifecycle map table (W8 fsession grown to the T07-final
/// counter shape): config, edge ringbuf, per-CPU loss (5 classes ×
/// 16 hook lanes), the 16-lane per-CPU accepted-edge aggregate, and
/// the per-CPU per-program mint sequences (8 site-program lanes).
/// `LCTR` issues the per-program per-CPU sequences (one lane per
/// site program — an interrupt can run a different program on the
/// same CPU, so per-CPU alone lost updates); `LLOSS` lanes fold per
/// class in [`crate::kcrypto_lifecycle::sensor::fold_loss_lanes`];
/// `LAGG` reconciles against consumed edges + `LLOSS_RESERVE` after
/// a quiet drain. Pairing state is kernel-owned (the per-call
/// session cookie): no slot, quarantine, or overflow tables exist.
pub const LIFECYCLE_MAPS: &[(&str, MapDims)] = &[
    (
        "LCFG",
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 64,
            max_entries: 1,
        },
    ),
    (
        "LRING",
        MapDims {
            map_type: 27,
            key_size: 0,
            value_size: 0,
            max_entries: 262_144,
        },
    ),
    (
        "LLOSS",
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: LLOSS_ENTRIES,
        },
    ),
    (
        "LAGG",
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 16,
        },
    ),
    (
        "LCTR",
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 8,
        },
    ),
];

/// Required sites for `RequestLifecycle`: the T04-qualified api
/// sites plus the T07.2 skcipher allocation site (generation
/// assignment needs alloc entry/return capture) plus the T07.3
/// destroy site (retire needs destroy entry/return capture —
/// final-free proof, not inference) plus the T07.4 configuration
/// sites (epochs need setkey/setauthsize entry/return capture —
/// scalar lengths + errno, never key bytes).
const LIFECYCLE_REQUIRED: &[RequiredSite] = &[
    RequiredSite {
        symbol: "crypto_skcipher_encrypt",
        shape: ProtoShape::Op,
    },
    RequiredSite {
        symbol: "crypto_skcipher_decrypt",
        shape: ProtoShape::Op,
    },
    RequiredSite {
        symbol: "crypto_alloc_skcipher",
        shape: ProtoShape::Alloc,
    },
    RequiredSite {
        symbol: "crypto_destroy_tfm",
        shape: ProtoShape::Destroy,
    },
    RequiredSite {
        symbol: "crypto_skcipher_setkey",
        shape: ProtoShape::SetkeySk,
    },
    RequiredSite {
        symbol: "crypto_aead_setauthsize",
        shape: ProtoShape::SetAuthsize,
    },
    RequiredSite {
        symbol: "crypto_aead_setkey",
        shape: ProtoShape::SetkeyAead,
    },
];

/// The manifest for a profile.
#[must_use]
pub fn manifest(profile: LifecycleProfile) -> ProfileManifest {
    match profile {
        LifecycleProfile::ApiReturns => ProfileManifest {
            name: "api-returns",
            required: &[],
            maps: crate::bpfloader::KCRYPTO_MAPS,
        },
        LifecycleProfile::RequestLifecycle => ProfileManifest {
            name: "request-lifecycle",
            required: LIFECYCLE_REQUIRED,
            maps: LIFECYCLE_MAPS,
        },
    }
}

/// Program limit derived from the profile's own manifest: one program
/// per required site (T07.4 fsession: 7; `ApiReturns` keeps its frozen 16).
#[must_use]
pub fn max_programs(manifest: &ProfileManifest) -> usize {
    if manifest.required.is_empty() {
        return 16;
    }
    manifest.required.len()
}

/// Section allowlist for a profile: `fsession/X` (nonempty target)
/// for lifecycle (W8: fentry/fexit objects refuse here, fail-closed);
/// fexit-only for api-returns (C1 frozen).
#[must_use]
pub fn section_allowed(profile: LifecycleProfile, section: &str) -> bool {
    let target = |prefix: &str| {
        section
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty())
    };
    match profile {
        LifecycleProfile::ApiReturns => target("fexit/"),
        LifecycleProfile::RequestLifecycle => target("fsession/"),
    }
}

/// Required-site load gate: names every manifest site whose section
/// did not reach [`PointStatus::Loaded`] (missing section, missing
/// BTF id, or refused load all count — a refused point is not a
/// loaded point). Empty means lifecycle startup may proceed; the
/// loader refuses startup otherwise (no per-point degrade: a subset
/// of the sites cannot observe the full lifecycle).
#[must_use]
pub fn missing_required_points(statuses: &[(&str, &PointStatus)]) -> Vec<String> {
    let table = manifest(LifecycleProfile::RequestLifecycle);
    let mut out = Vec::new();
    for site in table.required {
        let section = format!("fsession/{}", site.symbol);
        let loaded = statuses
            .iter()
            .any(|(s, st)| *s == section && matches!(st, PointStatus::Loaded { .. }));
        if !loaded {
            out.push(section);
        }
    }
    out
}

/// Build the required-edge gate refusal: when a missing section failed
/// to LOAD, its typed error (errno + verifier tail) surfaces with the
/// section bound into the stage — never flattened into a shape
/// refusal (round-1 sol-m10/astra-m10). Shape-only misses (no load
/// attempted) stay [`LoaderError::BadObject`].
#[must_use]
pub fn required_gate_error(
    missing: &[String],
    load_errors: &[(String, LoaderError)],
) -> LoaderError {
    if let Some((section, err)) = missing
        .iter()
        .find_map(|name| load_errors.iter().find(|(s, _)| s == name))
    {
        return match err {
            LoaderError::LoadFailed { stage, errno, log } => LoaderError::LoadFailed {
                stage: format!("{section} ({stage})"),
                errno: *errno,
                log: log.clone(),
            },
            other => other.clone(),
        };
    }
    LoaderError::BadObject {
        reason: format!(
            "lifecycle startup refused: missing required edges [{}]",
            missing.join(", ")
        ),
    }
}

/// LCFG v3 arm bytes: magic/version/flags plus the BTF-resolved
/// chase offsets the transform programs need (`crypto_tfm.__crt_alg`
/// at 12, `crypto_alg.cra_driver_name` at 16, `crypto_skcipher.base`
/// at 20, `crypto_tfm.refcnt` at 24 + its presence word at 28,
/// `skcipher_request.base` at 32, `crypto_async_request.tfm` at
/// 36); the reserved tail stays zero. The arm refuses before
/// writing when resolution fails — these words are never zeroed
/// guesses (a zero offset is only written when BTF resolved zero,
/// and `refcnt_present` 0 is the honest 7.2 verdict, never a gap).
/// The loader reads the map back after writing and refuses startup
/// on mismatch (zeroed/unwritten configs fail closed).
#[must_use]
pub fn lifecycle_config_bytes(off: &crate::btf_resolve::LifecycleOffsets) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..4].copy_from_slice(&LCONFIG_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&LCONFIG_VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&off.tfm_alg.to_le_bytes());
    out[16..20].copy_from_slice(&off.alg_drv.to_le_bytes());
    out[20..24].copy_from_slice(&off.sk_base.to_le_bytes());
    out[24..28].copy_from_slice(&off.refcnt_off.to_le_bytes());
    out[28..32].copy_from_slice(&u32::from(off.refcnt_present).to_le_bytes());
    out[32..36].copy_from_slice(&off.req_base.to_le_bytes());
    out[36..40].copy_from_slice(&off.req_tfm.to_le_bytes());
    out
}

/// LCFG disarm bytes (D1): `current` with ONLY the flags word set
/// to [`LCONFIG_DISABLED`] — magic, version, offsets and tail
/// preserved bit-for-bit. The disarm path reads the live value and
/// writes this back (then readback-verifies exact equality), so the
/// chase words are immutable from arm until the map dies: a hook
/// racing the disarm observes the armed value or a flags-nonzero
/// value (gate closed), never valid offsets mixed with zeroed words
/// (the old whole-value zeroing admitted exactly that mixture — a
/// racing chase could read `sk_base` 0 with the other offsets valid
/// and copy kernel code bytes as a well-formed driver name).
/// Callers pass the live map value (normally the armed bytes, whose
/// flags are 0 — a one-byte delta); an unwritten/zeroed map disarms
/// to flags-only (gate still closed on magic), never to armed.
#[must_use]
pub fn disarm_config_bytes(current: &[u8; LCFG_VALUE_LEN]) -> [u8; LCFG_VALUE_LEN] {
    let mut out = *current;
    out[8..12].copy_from_slice(&LCONFIG_DISABLED.to_le_bytes());
    out
}

/// LCFG config refusal: magic/version/flags must match exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// Wrong magic (includes the all-zero unwritten map).
    BadMagic,
    /// Unsupported version.
    BadVersion,
    /// Unknown flag bits set.
    BadFlags,
}

/// Validate an LCFG config word triple before it arms the sensor.
/// Zeroed configurations fail closed ([`ConfigError::BadMagic`]).
pub fn validate_lifecycle_config(magic: u32, version: u32, flags: u32) -> Result<(), ConfigError> {
    if magic != LCONFIG_MAGIC {
        return Err(ConfigError::BadMagic);
    }
    if version != LCONFIG_VERSION {
        return Err(ConfigError::BadVersion);
    }
    if flags != 0 {
        return Err(ConfigError::BadFlags);
    }
    Ok(())
}

/// LCFG value width: the read-back buffer must hold exactly this many
/// bytes (the manifest `LCFG.value_size`; a short buffer is a kernel
/// overwrite of the stack tail — round-1 sol-M1/astra-M1).
pub const LCFG_VALUE_LEN: usize = 64;

/// Full read-back refusal: length plus every config word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigVerifyError {
    /// Read-back is not exactly [`LCFG_VALUE_LEN`] bytes (short reads
    /// fail closed — never verify a prefix).
    BadLength {
        /// Bytes actually read.
        got: usize,
    },
    /// Wrong magic (includes the all-zero unwritten map).
    BadMagic,
    /// Unsupported version.
    BadVersion,
    /// Unknown flag bits set.
    BadFlags,
    /// Tail mismatch against the written bytes (offset word or
    /// reserved byte — a corrupted offset would mis-chase in BPF).
    BadReserved {
        /// Offset of the first mismatching tail byte.
        offset: usize,
    },
}

/// Validate a full LCFG read-back against the bytes the arm wrote:
/// exact length, magic, version, zero flags, then byte equality
/// from 12..64 (offset words plus reserved tail). Any deviation
/// fails closed — the offsets steer BPF chases, so a shape-only
/// check would certify a mis-chasing sensor.
pub fn verify_lifecycle_config_bytes(
    bytes: &[u8],
    expected: &[u8; LCFG_VALUE_LEN],
) -> Result<(), ConfigVerifyError> {
    if bytes.len() != LCFG_VALUE_LEN {
        return Err(ConfigVerifyError::BadLength { got: bytes.len() });
    }
    let word = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    match validate_lifecycle_config(word(0), word(4), word(8)) {
        Ok(()) => {}
        Err(ConfigError::BadMagic) => return Err(ConfigVerifyError::BadMagic),
        Err(ConfigError::BadVersion) => return Err(ConfigVerifyError::BadVersion),
        Err(ConfigError::BadFlags) => return Err(ConfigVerifyError::BadFlags),
    }
    if let Some((offset, _)) = bytes
        .iter()
        .enumerate()
        .skip(12)
        .find(|(i, b)| **b != expected[*i])
    {
        return Err(ConfigVerifyError::BadReserved { offset });
    }
    Ok(())
}

/// Member-offset validation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldError {
    /// Zero or non-scalar width (only 1/2/4/8 read).
    BadWidth,
    /// `offset + width` overflows u32.
    Overflow,
    /// Member runs past the struct size.
    OutOfBounds,
}

/// Validate one BTF-resolved member read: scalar widths only (1/2/4/8;
/// width 8 is the pointer-slot convention), checked `offset + width`
/// against the base struct size. Pure over resolved values for tests.
///
/// H01 pins this before its users (task req 1/3): T06 reads no struct
/// members (arg0 travels as an opaque key), so the first production
/// caller arrives with the T07 identity-member reads — not dead code,
/// a held gate.
pub fn validate_member(struct_size: u32, offset: u32, width: u32) -> Result<(), FieldError> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(FieldError::BadWidth);
    }
    let end = offset.checked_add(width).ok_or(FieldError::Overflow)?;
    if end > struct_size {
        return Err(FieldError::OutOfBounds);
    }
    Ok(())
}
