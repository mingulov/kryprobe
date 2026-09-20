// SPDX-License-Identifier: GPL-3.0-or-later
//! `token mint|status`: the K5 mint-once delegation surface.
//!
//! Branch ruling (Task 1 proved init-ns token mint/consume is
//! kernel-refused): `token mint` implements the spec §3.3 `setcap`
//! fallback — a root one-shot writes a `security.capability` xattr
//! granting `cap_bpf,cap_perfmon+ep` on the kryprobe binary, and later
//! `watch`/`report`/`check` run unprivileged against the file
//! capabilities (the kernel's designed path for exactly this goal).
//! Token-FD loader paths (`--token` / `KRYPROBE_TOKEN` / default pin)
//! stay for the userns use-case; `token status` and the doctor
//! `token_delegated` probe report both mechanisms.
//!
//! Layout (shared by `live` + `doctor`, hence `pub`): token discovery
//! ([`token_candidates`], [`usable_token`]), pin probing
//! ([`probe_pin`]), capability predicates ([`caps_have_bpf`],
//! [`caps_allow_bpf_bringup`], [`process_has_bpf_caps`]), the exit-4
//! reason ([`no_mechanism_reason`]), the xattr codec
//! ([`encode_capability_xattr`], [`decode_capability_xattr`]), receipt
//! assembly ([`mint_receipt_json`]) and UTC rendering
//! ([`format_unix_utc`], [`utc_now_string`]).

use kryprobe_privilege::probe::bpf_sys;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
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

/// `BPF_OBJ_GET` command id (pinned-token retrieval; the attr is the
/// 16-byte `{pathname, bpf_fd, file_flags}` prefix of `union bpf_attr`).
const BPF_OBJ_GET: u32 = 7;

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

/// Capability names by number, 0–40, VERIFIED against
/// `/usr/include/linux/capability.h` + `capsh --decode` on this host
/// (bit 11 = `NET_BROADCAST`, 21 = `SYS_ADMIN`, 38 = `PERFMON`,
/// 39 = `BPF`, 40 = `CHECKPOINT_RESTORE`).
///
/// This deliberately does NOT reuse
/// [`kryprobe_privilege::probe::cap_names`]: that table used to omit
/// `CAP_NET_BROADCAST`, shifting every name from index 11 on by one
/// (fixed by the K5 wave — the shared table now decodes the same
/// verified order; dedup of the two tables is parked as
/// non-load-bearing, so this surface keeps its own copy).
const CAP_NAMES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// Lowercase capability name for the `status` csv (`cap_bpf` style,
/// matching the mint receipt); numbers past the table render `cap_<n>`
/// so nothing decodes silently blank.
#[must_use]
pub fn cap_display_name(cap: u32) -> String {
    CAP_NAMES
        .get(cap as usize)
        .map(|name| name.to_lowercase())
        .unwrap_or_else(|| format!("cap_{cap}"))
}

/// Uppercase names for a bitmask (the `cap_names` shape, verified
/// order; unknown high bits ignored — the shared-table precedent).
fn cap_names_verified(bits: u64) -> Vec<String> {
    CAP_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| bits & (1u64 << i) != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect()
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

/// Kernel release context (`/proc` read; `unknown` when unreadable —
/// receipt metadata only, never a gate).
fn os_release() -> String {
    let text = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    if text.is_empty() {
        String::from("unknown")
    } else {
        text
    }
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

/// `BPF_OBJ_GET` attr: `{pathname, bpf_fd, file_flags}` (16 bytes).
#[repr(C)]
struct ObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// Retrieves the pinned BPF object at `path` via `BPF_OBJ_GET`
/// (plain `open()` cannot reach bpffs objects — only the `bpf()`
/// syscall can). `Ok` holds the live fd; `Err` is the kernel errno
/// (`NUL` in the path maps to `EINVAL`, never a panic).
fn obj_get(path: &Path) -> Result<std::fs::File, i32> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    let mut attr = ObjGetAttr {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    // SAFETY: `attr` is 16 live bytes for the syscall; the kernel
    // copies the attr struct in and out (the `bpf()` contract).
    let ret = unsafe {
        bpf_sys::bpf(
            BPF_OBJ_GET,
            (&raw mut attr).cast::<std::os::raw::c_void>(),
            16,
        )
    };
    if ret < 0 {
        return Err(bpf_sys::last_errno());
    }
    // SAFETY: the kernel handed us a live fd; we own it from here.
    Ok(unsafe { std::fs::File::from_raw_fd(ret as i32) })
}

/// Pinned-token usability: `Usable` (retrievable now), `PresentUnusable`
/// (a path exists but `BPF_OBJ_GET` refuses it — corrupt pin, wrong
/// object, or permissions — with the kernel reason), `Absent`
/// (nothing provable at the path, including stat-denied parents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinState {
    /// `BPF_OBJ_GET` succeeds on the path.
    Usable,
    /// The path exists but retrieval fails (reason carried).
    PresentUnusable(String),
    /// No path stat (missing, or an unreadable parent like mode-700 bpffs).
    Absent,
}

/// Probes one pin path (retrieval first, existence second — an
/// unprovable path reports `Absent`, never a fabricated `present`).
#[must_use]
pub fn probe_pin(path: &Path) -> PinState {
    match obj_get(path) {
        Ok(_) => PinState::Usable,
        Err(errno) => match std::fs::symlink_metadata(path) {
            Ok(_) => PinState::PresentUnusable(os_error_text(errno)),
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

/// Effective capability names from CapEff (fail-closed: unreadable or
/// unparseable reads as no caps, never as privileged; verified order —
/// see [`CAP_NAMES`]).
#[must_use]
pub fn effective_cap_names() -> Vec<String> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:")
            && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
        {
            return cap_names_verified(bits);
        }
    }
    Vec::new()
}

/// Ruling-literal delegation predicate: effective `CAP_BPF` (the
/// doctor `token_delegated` pass condition — file caps granted by
/// `token mint` always include it).
#[must_use]
pub fn caps_have_bpf(caps: &[String]) -> bool {
    caps.iter().any(|cap| cap == "CAP_BPF")
}

/// Bring-up predicate: `CAP_BPF` or `CAP_SYS_ADMIN` (either loads BPF;
/// the live pre-flight must not refuse a process that can load).
#[must_use]
pub fn caps_allow_bpf_bringup(caps: &[String]) -> bool {
    caps.iter()
        .any(|cap| cap == "CAP_BPF" || cap == "CAP_SYS_ADMIN")
}

/// Bring-up predicate over the live process.
#[must_use]
pub fn process_has_bpf_caps() -> bool {
    caps_allow_bpf_bringup(&effective_cap_names())
}

/// Render for a raw errno (`No such file or directory (os error 2)` —
/// the repo's exact-ENOENT idiom).
fn os_error_text(errno: i32) -> String {
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

/// Mint target: `--bin` or the current exe (`/proc/self/exe` via
/// [`std::env::current_exe`]), always canonicalized (L-SEC-03):
/// symlinks resolve to the real binary (never the link), and
/// nonexistent paths are invalid input.
fn mint_target(bin: Option<&Path>) -> Result<PathBuf, String> {
    match bin {
        Some(path) => std::fs::canonicalize(path)
            .map_err(|err| format!("invalid --bin {}: {err}", path.display())),
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| std::fs::canonicalize(exe).ok())
            .ok_or_else(|| "cannot resolve current exe".to_owned()),
    }
}

/// Mint identity gate (L-SEC-03): granting file caps to anything but
/// the running kryprobe binary needs explicit `--force`. Pure over
/// canonical paths for unit tests; unresolvable self fails closed.
fn check_mint_identity(target: &Path, current: Option<&Path>, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    match current {
        Some(current) if current == target => Ok(()),
        _ => Err(format!(
            "refusing to grant caps to {} (not the running kryprobe binary; pass --force to override)",
            target.display()
        )),
    }
}

/// Runs `token mint`: root one-shot file-cap grant + receipt.
/// Exit 0 prints the receipt JSON to stdout (one object, nothing
/// else); hints ride stderr. Refusals: exit 4 without root, exit 2 on
/// a bad `--bin` path, a foreign-binary target without `--force`, or
/// receipt-overwrite without `--force`.
pub fn run_mint(
    bin: Option<&Path>,
    receipt: Option<&Path>,
    force: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // Root gate FIRST (baseline precedence): every unprivileged
    // invocation refuses exit 4 naming root, before any input
    // validation. The target resolves for the message only.
    let target = mint_target(bin);
    // SAFETY: idempotent getter.
    if unsafe { libc::geteuid() } != 0 {
        let what = match &target {
            Ok(target) => target.display().to_string(),
            Err(_) => bin
                .map(|bin| bin.display().to_string())
                .unwrap_or_else(|| String::from("current exe")),
        };
        let _ = writeln!(
            stderr,
            "token mint: needs root (euid != 0); run once as root to grant \
             cap_bpf,cap_perfmon on {what}"
        );
        return 4;
    }
    let target = match target {
        Ok(target) => target,
        Err(reason) => {
            let _ = writeln!(stderr, "token mint: {reason}");
            return 2;
        }
    };
    let current = std::env::current_exe()
        .ok()
        .and_then(|exe| std::fs::canonicalize(exe).ok());
    if let Err(reason) = check_mint_identity(&target, current.as_deref(), force) {
        let _ = writeln!(stderr, "token mint: {reason}");
        return 2;
    }
    if let Some(path) = receipt
        && !force
        && std::fs::symlink_metadata(path).is_ok()
    {
        let _ = writeln!(
            stderr,
            "token mint: receipt {} exists (pass --force to overwrite)",
            path.display()
        );
        return 2;
    }
    let granted = encode_capability_xattr(&[CAP_PERFMON, CAP_BPF]);
    if let Err(code) = write_caps(&target, &granted, stderr) {
        return code;
    }
    let text = format!(
        "{}\n",
        mint_receipt_json(&target.to_string_lossy(), &os_release(), &utc_now_string())
    );
    let _ = write!(stdout, "{text}");
    if let Some(path) = receipt
        && let Err(err) = kryprobe_report::write_str_atomic(path, &text)
    {
        let _ = writeln!(
            stderr,
            "token mint: granted caps on {} but cannot write receipt {}: {err:#}",
            target.display(),
            path.display()
        );
        return 1;
    }
    let _ = writeln!(
        stderr,
        "token mint: granted cap_bpf,cap_perfmon+ep on {} (mechanism=setcap)",
        target.display()
    );
    0
}

/// Writes the `security.capability` xattr through the privilege seam
/// ([`kryprobe_privilege::filecaps`], no shell — ADR-0002 Rule B
/// forbids the raw call here). A `NUL` path or `ENOENT` (bad `--bin`)
/// is invalid input (exit 2); unsupported filesystems are
/// environmental (exit 4); the rest is internal (1).
fn write_caps(target: &Path, granted: &[u8; 20], stderr: &mut dyn Write) -> Result<(), i32> {
    // NUL attribution happens HERE (a seam-level `EINVAL` could also
    // be a kernel value rejection — unreachable with our constant
    // bytes, but the message must not claim a NUL it never saw).
    if target.as_os_str().as_bytes().contains(&0) {
        let _ = writeln!(
            stderr,
            "token mint: invalid --bin {}: NUL byte in path",
            target.display()
        );
        return Err(2);
    }
    if let Err(errno) = kryprobe_privilege::filecaps::set_capability_xattr(target, granted) {
        return Err(write_caps_exit(target, errno, stderr));
    }
    Ok(())
}

fn write_caps_exit(target: &Path, errno: i32, stderr: &mut dyn Write) -> i32 {
    if errno == libc::ENOENT || errno == libc::ENOTDIR {
        let _ = writeln!(
            stderr,
            "token mint: no such binary {} ({})",
            target.display(),
            os_error_text(errno)
        );
        return 2;
    }
    if [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP, libc::ENOTSUP].contains(&errno) {
        let _ = writeln!(
            stderr,
            "token mint: setxattr security.capability on {} refused ({})",
            target.display(),
            os_error_text(errno)
        );
        return 4;
    }
    let _ = writeln!(
        stderr,
        "token mint: setxattr security.capability on {} failed ({})",
        target.display(),
        os_error_text(errno)
    );
    1
}

/// Reads one `security.capability` value through the privilege seam
/// ([`kryprobe_privilege::filecaps`] — ADR-0002 Rule B forbids the raw
/// call here).
fn read_caps(target: &Path) -> Result<Vec<u8>, i32> {
    kryprobe_privilege::filecaps::get_capability_xattr(target)
}

/// The `caps:` line for one target (missing xattr reads as no caps;
/// every other failure carries its reason — never a crash).
fn caps_line(target: &Path) -> String {
    let bytes = match read_caps(target) {
        Ok(bytes) => bytes,
        Err(errno) if errno == libc::ENODATA => {
            return String::from("caps: none not-effective");
        }
        Err(errno) => return format!("caps: unreadable ({})", os_error_text(errno)),
    };
    match decode_capability_xattr(&bytes) {
        Some((caps, effective)) => {
            let csv = if caps.is_empty() {
                String::from("none")
            } else {
                caps.iter()
                    .map(|cap| cap_display_name(*cap))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            format!(
                "caps: {csv} {}",
                if effective {
                    "effective"
                } else {
                    "not-effective"
                }
            )
        }
        None => format!(
            "caps: unreadable (bad security.capability: {} bytes)",
            bytes.len()
        ),
    }
}

/// Runs `token status`: file caps + default-pin usability. Never
/// requires privilege; unreadable inputs report with reasons, exit 0.
pub fn run_status(bin: Option<&Path>, stdout: &mut dyn Write) -> i32 {
    let target = match mint_target(bin) {
        Ok(target) => target,
        Err(reason) => {
            let _ = writeln!(stdout, "caps: unreadable ({reason})");
            let _ = writeln!(stdout, "pin: absent unreadable");
            return 0;
        }
    };
    let _ = writeln!(stdout, "{}", caps_line(&target));
    let pin = match probe_pin(Path::new(DEFAULT_TOKEN_PIN)) {
        PinState::Usable => "pin: present readable",
        PinState::PresentUnusable(_) => "pin: present unreadable",
        PinState::Absent => "pin: absent unreadable",
    };
    let _ = writeln!(stdout, "{pin}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kryprobe-k5-token-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn mint_target_canonicalizes_bin() {
        // L-SEC-03: --bin resolves through symlinks (never the link
        // itself); nonexistent paths are invalid input.
        let exe = std::env::current_exe().expect("current exe");
        let canonical = std::fs::canonicalize(&exe).expect("canonical exe");
        assert_eq!(mint_target(None).expect("self resolves"), canonical);
        let dir = scratch_dir("canon");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&exe, &link).expect("symlink");
        assert_eq!(mint_target(Some(&link)).expect("link resolves"), canonical);
        assert!(
            mint_target(Some(Path::new("/nonexistent-k5-token-zzz"))).is_err(),
            "nonexistent --bin is invalid"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mint_identity_requires_force_for_foreign_binary() {
        // L-SEC-03/H-T1: granting caps to anything but the running
        // kryprobe binary needs explicit --force.
        let this = PathBuf::from("/usr/local/bin/kryprobe");
        let other = PathBuf::from("/tmp/evil-helper");
        assert!(check_mint_identity(&this, Some(&this), false).is_ok());
        let err = check_mint_identity(&other, Some(&this), false)
            .expect_err("foreign binary needs --force");
        assert!(err.contains("--force"), "names the override: {err}");
        assert!(check_mint_identity(&other, Some(&this), true).is_ok());
        assert!(
            check_mint_identity(&other, None, false).is_err(),
            "unresolvable self fails closed without --force"
        );
        assert!(check_mint_identity(&other, None, true).is_ok());
    }
}
