// SPDX-License-Identifier: GPL-3.0-or-later
//! Token mechanism (1B-M8): discovery, pin probing, xattr codec, receipt.
//!
//! Shared by `live` + `doctor` + the `token` command: token discovery
//! ([`token_candidates`], [`usable_token`]), pin probing
//! ([`probe_pin`]), the exit-4 reason ([`no_mechanism_reason`]), the
//! xattr codec ([`encode_capability_xattr`],
//! [`decode_capability_xattr`]), receipt assembly
//! ([`mint_receipt_json`]) and UTC rendering ([`format_unix_utc`],
//! [`utc_now_string`]). Capability predicates live in
//! [`crate::runtime_facts`]; the `mint`/`status` dispatch in
//! [`crate::cmd_token`].

use kryprobe_privilege::token::obj_get;
use std::path::{Path, PathBuf};

/// BPF token pin path consumed by default (last in the
/// `--token` > `KRYPROBE_TOKEN` > default discovery order).
pub const DEFAULT_TOKEN_PIN: &str = "/sys/fs/bpf/kryprobe/token";

/// Env var overriding the default token pin (below explicit `--token`).
pub const TOKEN_ENV_VAR: &str = "KRYPROBE_TOKEN";

/// Capability numbers granted by `token mint` (linux/capability.h).
pub const CAP_PERFMON: u32 = 38;
/// Capability numbers granted by `token mint` (linux/capability.h).
pub const CAP_BPF: u32 = 39;

/// `security.capability` magic for the minted value: revision byte
/// `0x02` with the EFFECTIVE flag (bit 0) set.
///
/// VERIFIED empirically on this host (setcap/getcap roundtrip on
/// scratch copies in /tmp; see the Task 5 report): `setcap
/// cap_bpf,cap_perfmon+ep` yields magic bytes `01 00 00 02`, and
/// writing these exact 20 bytes via `setxattr` reads back as
/// `cap_perfmon,cap_bpf=ep` under `getcap`. The header's
/// `VFS_CAP_REVISION_3` (`0x03`) is NOT what the running
/// kernel/libcap pair emits — nothing on this host does — so the
/// encoder emits the proven form, never the remembered constant.
const XATTR_MAGIC_ETC: u32 = 0x0200_0001;

/// Pure `security.capability` encoder: 20-byte two-pair layout
/// (`magic_etc` LE + 2×{permitted LE, inheritable LE}; caps > 31
/// land in `data[1]`). Inheritable is always zero (the grant is
/// `+ep`, never `+i`); capability numbers ≥ 64 are unrepresentable
/// and ignored (no such Linux capability exists today).
#[must_use]
pub fn encode_capability_xattr(caps: &[u32]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..4].copy_from_slice(&XATTR_MAGIC_ETC.to_le_bytes());
    let mut permitted = [0u32; 2];
    for cap in caps {
        if *cap < 64 {
            permitted[(*cap / 32) as usize] |= 1 << (*cap % 32);
        }
    }
    out[4..8].copy_from_slice(&permitted[0].to_le_bytes());
    // out[8..12] stays zero (data[0].inheritable).
    out[12..16].copy_from_slice(&permitted[1].to_le_bytes());
    // out[16..20] stays zero (data[1].inheritable).
    out
}

/// Decodes a `security.capability` value into its permitted capability
/// numbers (ascending) plus the EFFECTIVE flag. Accepts the 12-byte
/// one-pair and 20-byte two-pair shapes with a `0x01`–`0x03` revision
/// byte; anything else is `None` (callers report, never crash).
#[must_use]
pub fn decode_capability_xattr(bytes: &[u8]) -> Option<(Vec<u32>, bool)> {
    let words: Vec<u32> = match bytes.len() {
        12 => vec![u32::from_le_bytes(bytes[4..8].try_into().ok()?)],
        20 => vec![
            u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            u32::from_le_bytes(bytes[12..16].try_into().ok()?),
        ],
        _ => return None,
    };
    Some((permitted_list(&words), effective_flag(bytes)?))
}

/// EFFECTIVE flag (bit 0 of `magic_etc`); `None` unless the revision
/// byte is a known `0x01`–`0x03`.
fn effective_flag(bytes: &[u8]) -> Option<bool> {
    let magic = u32::from_le_bytes(bytes[..4].try_into().ok()?);
    if !matches!(magic >> 24, 0x01..=0x03) {
        return None;
    }
    Some(magic & 1 == 1)
}

/// Permitted numbers for one/two LE words, ascending.
fn permitted_list(words: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    for (half, word) in words.iter().enumerate() {
        for bit in 0..32 {
            if word & (1 << bit) != 0 {
                out.push(half as u32 * 32 + bit);
            }
        }
    }
    out
}

/// Days since 1970-01-01 → civil (year, month, day): Howard Hinnant's
/// `civil_from_days` (public-domain algorithm, reimplemented against
/// the documented ranges, pinned by the epoch tests).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ` (UTC, std-only — no time dep).
#[must_use]
pub fn format_unix_utc(secs: u64) -> String {
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Current wall time as RFC3339 UTC (`[…]Z`; a clock before the epoch
/// — unreachable live — renders the epoch, never panics).
#[must_use]
pub fn utc_now_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|span| span.as_secs())
        .unwrap_or(0);
    format_unix_utc(secs)
}

/// Mint receipt JSON (the exact stdout object, also written to
/// `--receipt` when given).
#[must_use]
pub fn mint_receipt_json(binary: &str, kernel: &str, time: &str) -> String {
    serde_json::json!({
        "mechanism": "setcap",
        "binary": binary,
        "caps": ["cap_bpf", "cap_perfmon"],
        "effective": true,
        "kernel": kernel,
        "time": time,
    })
    .to_string()
}

/// Token discovery order, pure over its inputs: explicit `--token` >
/// `KRYPROBE_TOKEN` (already read by the caller) > default pin. Empty
/// env values are ignored (unset and empty behave alike).
#[must_use]
pub fn token_candidates(explicit: Option<&Path>, env: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(3);
    if let Some(path) = explicit {
        out.push(path.to_owned());
    }
    if let Some(value) = env.filter(|value| !value.is_empty()) {
        out.push(PathBuf::from(value));
    }
    out.push(PathBuf::from(DEFAULT_TOKEN_PIN));
    out
}

/// Discovery with the live env value (`KRYPROBE_TOKEN` read here;
/// non-UTF8 reads as unset — never a crash, never a misroute).
#[must_use]
pub fn resolve_token_candidates(explicit: Option<&Path>) -> Vec<PathBuf> {
    let env = std::env::var(TOKEN_ENV_VAR).ok();
    token_candidates(explicit, env.as_deref())
}

/// Pinned-token usability: `Usable` (retrievable now), `PresentUnusable`
/// (a path exists but `BPF_OBJ_GET` refuses it — corrupt pin, wrong
/// object, or permissions — with the kernel reason AND the real kernel
/// errno, never a fabricated one), `Absent` (nothing provable at the
/// path, including stat-denied parents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinState {
    /// `BPF_OBJ_GET` succeeds on the path.
    Usable,
    /// The path exists but retrieval fails (1B-M7: the real errno).
    PresentUnusable { reason: String, errno: i32 },
    /// No path stat (missing, or an unreadable parent like mode-700 bpffs).
    Absent,
}

/// Probes one pin path (retrieval first, existence second — an
/// unprovable path reports `Absent`, never a fabricated `present`).
/// Retrieval runs behind the privilege boundary
/// ([`kryprobe_privilege::token::obj_get`]).
#[must_use]
pub fn probe_pin(path: &Path) -> PinState {
    match obj_get(path) {
        Ok(_) => PinState::Usable,
        Err(errno) => match std::fs::symlink_metadata(path) {
            Ok(_) => PinState::PresentUnusable {
                reason: os_error_text(errno),
                errno,
            },
            Err(_) => PinState::Absent,
        },
    }
}

/// First usable token in discovery order (`None` when no candidate
/// retrieves — the caller reports [`no_mechanism_reason`]).
#[must_use]
pub fn usable_token(explicit: Option<&Path>) -> Option<std::fs::File> {
    resolve_token_candidates(explicit)
        .iter()
        .find_map(|candidate| obj_get(candidate).ok())
}

/// Render for a raw errno (`No such file or directory (os error 2)` —
/// the repo's exact-ENOENT idiom).
pub(crate) fn os_error_text(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// The honest exit-4 reason: the ruling sentence plus what was tried.
/// Names the highest-priority failed candidate (explicit `--token` /
/// `KRYPROBE_TOKEN` / default-pin state — all failed here, and the
/// user looks at the first one first).
#[must_use]
pub fn no_mechanism_reason(explicit: Option<&Path>) -> String {
    const HINT: &str =
        "no BPF capability: run 'kryprobe token mint' once as root, or supply --token";
    let env = std::env::var(TOKEN_ENV_VAR).ok().filter(|v| !v.is_empty());
    let detail = if let Some(path) = explicit {
        match obj_get(path) {
            // Racy but harmless: usable NOW (something pinned it between
            // the pre-flight probe and this message) — still name it.
            Ok(_) => format!("--token {} became usable; retry", path.display()),
            Err(errno) => format!(
                "--token {} unusable ({})",
                path.display(),
                os_error_text(errno)
            ),
        }
    } else if let Some(value) = env {
        match obj_get(Path::new(&value)) {
            Ok(_) => format!("KRYPROBE_TOKEN={value} became usable; retry"),
            Err(errno) => format!("KRYPROBE_TOKEN={value} unusable ({})", os_error_text(errno)),
        }
    } else {
        match std::fs::symlink_metadata(DEFAULT_TOKEN_PIN) {
            Ok(_) => format!("default pin {DEFAULT_TOKEN_PIN} present but unreadable"),
            Err(_) => format!("default pin {DEFAULT_TOKEN_PIN} absent"),
        }
    };
    format!("{HINT} ({detail})")
}
