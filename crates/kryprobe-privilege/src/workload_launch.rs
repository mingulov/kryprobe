// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 3 helper launch boundary: discover, confine, attest, and
//! serve the FIXED unprivileged workload helper.
//!
//! The launcher (this module) runs inside the privileged CLI process and
//! establishes the helper boundary BEFORE capture threads own authority
//! fds. The helper itself re-verifies the boundary before parsing any
//! metadata or request byte; the launcher verifies independently and
//! discards any response that fails verification.
//!
//! - Principal: kernel credentials (`/proc/self/status` `Uid:`/`Gid:`),
//!   never environment (`SUDO_UID`/`SUDO_USER` are untrusted). Root
//!   (uid or euid 0) has no trustworthy non-root principal in M1 —
//!   there is no principal-passing mechanism — so root keeps raw-ID
//!   capture with typed [`MetadataUnavailable::NoPrincipal`].
//! - Discovery: the fixed sibling `kryprobe-workload-helper` next to
//!   the running CLI executable. No `PATH` search, no metadata-selected
//!   paths, no environment override. Missing/non-regular files refuse.
//! - Identity pinning (C1 A1): preflight opens the helper
//!   (`O_RDONLY|O_NOFOLLOW|O_CLOEXEC`) and pins its file identity
//!   (device, inode, owner, mode, size). Every later spawn reopens
//!   the path the same way, requires the SAME identity, and executes
//!   the verified open file via `/proc/self/fd/N` — the kernel
//!   resolves the executable from the open file description, never
//!   from the pathname, so a replacement/rename/symlink-swap after
//!   preflight cannot reach `exec`: there is no check-to-exec window
//!   (the check and the exec share one open file description).
//!   Ownership is pinned, not restricted: the trust anchor is "the
//!   file verified at preflight" (production installs root-own the
//!   sibling at 0755 via `install.sh`).
//! - Confinement (child `pre_exec`, before `exec`): clear ambient caps,
//!   empty every capability set, set `no_new_privs`, close every fd
//!   except stdio and the pinned executable fd (which is `CLOEXEC`,
//!   so it never survives `exec` into the helper — the attested fd
//!   set stays stdio-only). Dropping privilege is always permitted,
//!   so this works identically with or without file caps on the CLI.
//! - Verification: `--attest --require-no-new-privs` first (the helper
//!   reports its boundary without touching metadata or stdin), then the
//!   serve run. The launcher checks uid/euid/gid/egid against the pinned
//!   principal, empty caps, `no_new_privs`, and the stdio-only fd set
//!   before consuming any metadata. The serve response additionally
//!   binds to its request ([`bind_response_to_request`]).
//! - Retries: [`MAX_HELPER_RETRIES`] past the initial attempt, on
//!   transport failures only (stall/crash). Typed helper refusals —
//!   including identity-mismatch refusals — are deterministic and
//!   never retried.
//!
//! [`MetadataUnavailable::NoPrincipal`]: kryprobe_core::workload::MetadataUnavailable::NoPrincipal
//! [`bind_response_to_request`]: kryprobe_core::workload::bind_response_to_request
//! [`MAX_HELPER_RETRIES`]: kryprobe_core::workload::MAX_HELPER_RETRIES

use kryprobe_core::workload::{
    MAX_HELPER_RETRIES, MAX_KERNEL_IDENTITY_BYTES, MAX_SNAPSHOT_RESPONSE_BYTES,
    MetadataUnavailable, SnapshotRequest, SnapshotResponse, bind_response_to_request,
    decode_response, encode_request,
};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed helper file name (sibling of the CLI executable, dev and
/// packaged layouts alike).
pub const HELPER_FILE_NAME: &str = "kryprobe-workload-helper";

/// Per-attempt wall bound for one helper invocation (attest or serve).
/// The helper's own stdin deadline (2 s) bounds slow senders; this
/// launcher-local bound covers helper compute + IPC. A lapse kills the
/// child and counts as a transport failure (retryable). This is a CLI
/// implementation bound, not contract: the frozen contract pins the
/// helper-side timeouts, never the launcher's wait.
pub const HELPER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll slice while waiting for the helper (bounded `try_wait` loop —
/// the wait ends on child exit or the attempt timeout, never later).
const WAIT_POLL: Duration = Duration::from_millis(10);

/// Pinned non-root principal: kernel UIDs/GIDs plus supplementary
/// groups. Groups are pinned-but-retained: dropping them needs
/// `CAP_SETGID`, which the file-cap CLI does not hold — they are the
/// principal's own groups, and the helper runs with the principal's
/// full identity (never more).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Real uid.
    pub uid: u32,
    /// Effective uid.
    pub euid: u32,
    /// Real gid.
    pub gid: u32,
    /// Effective gid.
    pub egid: u32,
    /// Supplementary group ids (pinned, retained).
    pub groups: Vec<u32>,
}

/// Parse the principal out of `/proc/self/status` text. `None` on any
/// missing or malformed identity field (fail closed, no partial
/// identity). Pure over text so tests pin it without root.
#[must_use]
pub fn principal_from_status_text(text: &str) -> Option<Principal> {
    let mut uid = None;
    let mut euid = None;
    let mut gid = None;
    let mut egid = None;
    let mut groups = None;
    for line in text.lines() {
        let (key, rest) = line.split_once(':')?;
        let value = rest.trim();
        match key {
            "Uid" => {
                let mut parts = value.split_whitespace();
                uid = parts.next()?.parse().ok();
                euid = parts.next()?.parse().ok();
            }
            "Gid" => {
                let mut parts = value.split_whitespace();
                gid = parts.next()?.parse().ok();
                egid = parts.next()?.parse().ok();
            }
            "Groups" => {
                let mut ids = Vec::new();
                for part in value.split_whitespace() {
                    ids.push(part.parse::<u32>().ok()?);
                }
                groups = Some(ids);
            }
            _ => {}
        }
    }
    Some(Principal {
        uid: uid?,
        euid: euid?,
        gid: gid?,
        egid: egid?,
        groups: groups?,
    })
}

/// Read the current principal from kernel state (`/proc/self/status`).
/// Environment identity is never consulted.
pub fn current_principal() -> Result<Principal, MetadataUnavailable> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|_| MetadataUnavailable::UnsupportedEnvironment)?;
    principal_from_status_text(&status).ok_or(MetadataUnavailable::UnsupportedEnvironment)
}

/// Execution-kernel scope tag `osrelease/boot_id` over one proc root —
/// the SAME convention the helper uses (`HostView::kernel_scope`):
/// trimmed fields, each non-empty, within 64 bytes, no
/// whitespace/control bytes, joined tag within the kernel-identity
/// bound. Capture must produce identical tags or every key mismatches.
pub fn kernel_scope_for_proc(proc_root: &Path) -> Result<String, MetadataUnavailable> {
    let release = read_bounded_text(&proc_root.join("sys/kernel/osrelease"), 4096)?;
    let boot_id = read_bounded_text(&proc_root.join("sys/kernel/random/boot_id"), 4096)?;
    let release = release.trim();
    let boot_id = boot_id.trim();
    for field in [release, boot_id] {
        if field.is_empty()
            || field.len() > 64
            || field
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(MetadataUnavailable::UnsupportedEnvironment);
        }
    }
    let scope = format!("{release}/{boot_id}");
    if scope.len() > MAX_KERNEL_IDENTITY_BYTES {
        return Err(MetadataUnavailable::UnsupportedEnvironment);
    }
    Ok(scope)
}

/// Current execution-kernel scope tag (production `/proc`).
pub fn current_kernel_scope() -> Result<String, MetadataUnavailable> {
    kernel_scope_for_proc(Path::new("/proc"))
}

/// Bounded small-file text read (never UTF-8-lossy on the tag path:
/// scope tags must be exact bytes).
fn read_bounded_text(path: &Path, max_bytes: usize) -> Result<String, MetadataUnavailable> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| {
            f.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
            Ok(())
        })
        .map_err(|_| MetadataUnavailable::UnsupportedEnvironment)?;
    if bytes.len() > max_bytes {
        return Err(MetadataUnavailable::UnsupportedEnvironment);
    }
    String::from_utf8(bytes).map_err(|_| MetadataUnavailable::UnsupportedEnvironment)
}

/// Fixed discovery: the helper is the sibling of `exe` (the CLI binary
/// path). Pure over paths; [`discover_helper`] applies it to the
/// running executable.
#[must_use]
pub fn helper_sibling_for(exe: &Path) -> PathBuf {
    exe.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(HELPER_FILE_NAME)
}

/// Discover the fixed helper next to the running CLI executable. The
/// candidate must exist and be a regular file — anything else
/// (missing, directory, symlink-to-nowhere) refuses [`MetadataUnavailable::HelperRefused`].
/// There is no search order and no override: one fixed path.
pub fn discover_helper() -> Result<PathBuf, MetadataUnavailable> {
    let exe = std::env::current_exe().map_err(|_| MetadataUnavailable::HelperRefused)?;
    let candidate = helper_sibling_for(&exe);
    match std::fs::symlink_metadata(&candidate) {
        Ok(meta) if meta.file_type().is_file() => Ok(candidate),
        _ => Err(MetadataUnavailable::HelperRefused),
    }
}

/// Pinned helper file identity, from the preflight open: the
/// (device, inode) pair plus ownership, full mode (including the
/// file-type bits), and size. Reopening the path must reproduce
/// every field or the image was replaced. A rename-swap always
/// changes the inode; delete-and-recreate with a reused inode still
/// trips on size/mode/owner unless the replacement is byte-equal in
/// every pinned field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperIdentity {
    /// Device id (`st_dev`).
    pub dev: u64,
    /// Inode number (`st_ino`).
    pub ino: u64,
    /// Owner uid (`st_uid`, pinned not restricted).
    pub uid: u32,
    /// Owner gid (`st_gid`, pinned not restricted).
    pub gid: u32,
    /// Full mode (`st_mode`, type bits included).
    pub mode: u32,
    /// File size (`st_size`).
    pub size: u64,
}

/// A helper path plus its pinned preflight identity. Spawns reopen
/// the path and require the same identity, then execute the
/// verified open file itself (fd-exec, never the pathname).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHelper {
    /// The verified helper path (also the child's `argv[0]`).
    pub path: PathBuf,
    /// The pinned preflight identity it must still match.
    pub identity: HelperIdentity,
}

impl PinnedHelper {
    /// Reopen the path and require the pinned identity: same open
    /// flags as the pin (`O_RDONLY|O_NOFOLLOW|O_CLOEXEC`), same
    /// file-type gate, every identity field equal. A mismatch (or a
    /// symlink, or a non-regular file) refuses
    /// [`MetadataUnavailable::HelperRefused`] — deterministic, never
    /// retried. The returned file is the `exec` target itself, so no
    /// pathname state after this open can affect which image runs.
    pub fn reopen(&self) -> Result<std::fs::File, MetadataUnavailable> {
        let (file, identity) =
            open_verified(&self.path).map_err(|_| MetadataUnavailable::HelperRefused)?;
        if identity != self.identity {
            return Err(MetadataUnavailable::HelperRefused);
        }
        Ok(file)
    }
}

/// Open one verified helper image: `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`
/// (a trailing symlink refuses — the fixed sibling is a regular
/// file), regular-file gate, `CLOEXEC` pinned explicitly, and the
/// fd parked at 3+ (never a stdio number). Static outcome: ok or
/// I/O error (callers map it to
/// [`MetadataUnavailable::HelperRefused`] without echoing the path).
fn open_verified(path: &Path) -> std::io::Result<(std::fs::File, HelperIdentity)> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    // Defense in depth: `std` already sets `CLOEXEC`; pin it
    // explicitly so the keep-fd can never survive `exec` into the
    // helper (the attested fd set stays stdio-only).
    // SAFETY: `fcntl` `F_SETFD` on a live owned fd.
    let mut fd = file.as_raw_fd();
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    if fd < 3 {
        // Only when stdio is closed (never in practice): park the
        // image fd above stdio so confinement keeps the right fd.
        // SAFETY: dups a live fd to 3+; the original closes on drop.
        fd = unsafe { libc::fcntl(fd, libc::F_DUPFD, 3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fresh owned fd, wrapped exactly once.
        file = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "helper is not a regular file",
        ));
    }
    Ok((
        file,
        HelperIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            size: meta.len(),
        },
    ))
}

/// Pin the helper image at `path`: verified open plus its identity.
/// The pin carries no open file (fstat fields only): each spawn
/// reopens and re-verifies via [`PinnedHelper::reopen`], then
/// fd-execs the just-verified file — check and exec share one open
/// file description, so no replacement window exists.
pub fn pin_helper(path: &Path) -> Result<PinnedHelper, MetadataUnavailable> {
    let (_, identity) = open_verified(path).map_err(|_| MetadataUnavailable::HelperRefused)?;
    Ok(PinnedHelper {
        path: path.to_path_buf(),
        identity,
    })
}

/// Pre-capture helper preflight: either a verified launch target
/// (helper + pinned identity + pinned principal + kernel scope) or
/// the typed reason metadata is unavailable. Never fails:
/// enrichment failure is data (capture proceeds with raw IDs),
/// never a session error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadPreflight {
    /// Verified helper path (`None` unless every check passed).
    pub helper: Option<PathBuf>,
    /// Pinned helper identity (`None` unless every check passed).
    /// The serve re-verifies it and fd-execs the same image.
    pub helper_identity: Option<HelperIdentity>,
    /// Pinned principal (`None` when even the principal is unusable).
    pub principal: Option<Principal>,
    /// Kernel scope tag for request keys (`None` when unreadable).
    pub kernel_scope: Option<String>,
    /// Typed unavailability (`None` exactly when launchable).
    pub unavailable: Option<MetadataUnavailable>,
}

impl WorkloadPreflight {
    /// True exactly when the helper may be served after capture.
    #[must_use]
    pub fn launchable(&self) -> bool {
        self.unavailable.is_none()
            && self.helper.is_some()
            && self.helper_identity.is_some()
            && self.principal.is_some()
            && self.kernel_scope.is_some()
    }
}

/// Establish the helper boundary before capture threads own authority
/// fds: principal (root refuses [`MetadataUnavailable::NoPrincipal`),
/// kernel scope, fixed discovery, and the `--attest` handshake. A
/// replaced helper fails attestation and refuses [`MetadataUnavailable::HelperRefused`].
/// `helper_override` runs the handshake against an explicit path and
/// exists ONLY for tests — production always passes `None` (fixed
/// discovery), so no caller can select the helper executable.
pub fn preflight_helper(helper_override: Option<&Path>) -> WorkloadPreflight {
    let fail = |unavailable: MetadataUnavailable| WorkloadPreflight {
        helper: None,
        helper_identity: None,
        principal: None,
        kernel_scope: None,
        unavailable: Some(unavailable),
    };
    let principal = match current_principal() {
        Ok(principal) => principal,
        Err(kind) => return fail(kind),
    };
    // The kernel scope tag is kernel state (readable at any uid):
    // establish it before the root refusal so raw-ID capture keeps
    // its execution-kernel binding even without a principal.
    let kernel_scope = match current_kernel_scope() {
        Ok(scope) => scope,
        Err(kind) => {
            let mut refused = fail(kind);
            refused.principal = Some(principal);
            return refused;
        }
    };
    // M1 has no principal-passing mechanism: root invocation cannot
    // name a trustworthy non-root principal (SUDO_* is untrusted), so
    // root keeps raw-ID capture. The helper enforces the same rule.
    if principal.uid == 0 || principal.euid == 0 {
        let mut refused = fail(MetadataUnavailable::NoPrincipal);
        refused.principal = Some(principal);
        refused.kernel_scope = Some(kernel_scope);
        return refused;
    }
    let helper = match helper_override {
        Some(path) => path.to_path_buf(),
        None => match discover_helper() {
            Ok(path) => path,
            Err(kind) => {
                let mut refused = fail(kind);
                refused.principal = Some(principal);
                refused.kernel_scope = Some(kernel_scope);
                return refused;
            }
        },
    };
    match attest_helper(&helper, &principal, HELPER_ATTEMPT_TIMEOUT) {
        Ok(identity) => WorkloadPreflight {
            helper: Some(helper),
            helper_identity: Some(identity),
            principal: Some(principal),
            kernel_scope: Some(kernel_scope),
            unavailable: None,
        },
        Err(kind) => {
            let mut refused = fail(kind);
            refused.principal = Some(principal);
            refused.kernel_scope = Some(kernel_scope);
            refused
        }
    }
}

/// The verified helper boundary, parsed from one attestation line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperAttestation {
    /// Real uid.
    pub uid: u32,
    /// Effective uid.
    pub euid: u32,
    /// Real gid.
    pub gid: u32,
    /// Effective gid.
    pub egid: u32,
    /// Empty capability sets (all four masks zero).
    pub caps_empty: bool,
    /// Whether `no_new_privs` is set.
    pub no_new_privs: bool,
    /// Inherited descriptor numbers (must be exactly stdio).
    pub fds: Vec<u32>,
}

/// Parse one `{"attestation":{...}}` line. Strict: missing or mistyped
/// fields refuse (a replaced binary's chatter never parses as an
/// attestation). Capability masks are decimal strings per the §5.4
/// integer convention.
pub fn parse_attestation_line(line: &str) -> Result<HelperAttestation, MetadataUnavailable> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|_| MetadataUnavailable::HelperRefused)?;
    let attestation = value
        .get("attestation")
        .and_then(serde_json::Value::as_object)
        .ok_or(MetadataUnavailable::HelperRefused)?;
    let id = |key: &str| {
        attestation
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(MetadataUnavailable::HelperRefused)
    };
    let caps = attestation
        .get("caps")
        .and_then(serde_json::Value::as_object)
        .ok_or(MetadataUnavailable::HelperRefused)?;
    let mut caps_empty = true;
    for key in ["eff", "prm", "inh", "amb"] {
        let mask = caps
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(MetadataUnavailable::HelperRefused)?;
        caps_empty &= mask == 0;
    }
    let no_new_privs = attestation
        .get("no_new_privs")
        .and_then(serde_json::Value::as_bool)
        .ok_or(MetadataUnavailable::HelperRefused)?;
    let fds = attestation
        .get("fds")
        .and_then(serde_json::Value::as_array)
        .ok_or(MetadataUnavailable::HelperRefused)?;
    let mut fd_list = Vec::with_capacity(fds.len());
    for fd in fds {
        fd_list.push(
            fd.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or(MetadataUnavailable::HelperRefused)?,
        );
    }
    Ok(HelperAttestation {
        uid: id("uid")?,
        euid: id("euid")?,
        gid: id("gid")?,
        egid: id("egid")?,
        caps_empty,
        no_new_privs,
        fds: fd_list,
    })
}

/// Verify the child boundary against the pinned principal: identity
/// equality, empty caps, `no_new_privs`, stdio-only fds. Static
/// outcome (no input echo): ok or [`MetadataUnavailable::HelperRefused`].
pub fn check_helper_attestation(
    attestation: &HelperAttestation,
    principal: &Principal,
) -> Result<(), MetadataUnavailable> {
    if attestation.uid != principal.uid
        || attestation.euid != principal.euid
        || attestation.gid != principal.gid
        || attestation.egid != principal.egid
    {
        return Err(MetadataUnavailable::HelperRefused);
    }
    if !attestation.caps_empty {
        return Err(MetadataUnavailable::HelperRefused);
    }
    if !attestation.no_new_privs {
        return Err(MetadataUnavailable::HelperRefused);
    }
    if attestation.fds != [0, 1, 2] {
        return Err(MetadataUnavailable::HelperRefused);
    }
    Ok(())
}

/// Parse one stderr `{"error":"<name>"}` line into the frozen
/// vocabulary. Unknown names are protocol violations ([`MetadataUnavailable::HelperRefused`]).
pub fn parse_error_line(line: &str) -> Result<MetadataUnavailable, MetadataUnavailable> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|_| MetadataUnavailable::HelperRefused)?;
    match value.get("error").and_then(serde_json::Value::as_str) {
        Some("no_principal") => Ok(MetadataUnavailable::NoPrincipal),
        Some("helper_refused") => Ok(MetadataUnavailable::HelperRefused),
        Some("budget_exceeded") => Ok(MetadataUnavailable::BudgetExceeded),
        Some("unsupported_environment") => Ok(MetadataUnavailable::UnsupportedEnvironment),
        Some("parse_failed") => Ok(MetadataUnavailable::ParseFailed),
        _ => Err(MetadataUnavailable::HelperRefused),
    }
}

/// Confine the child before `exec`: clear ambient caps, empty every
/// capability set, set `no_new_privs`, close every fd except stdio
/// and `keep` (the pinned executable fd — `CLOEXEC`, so it never
/// survives `exec` into the helper). Runs in `pre_exec` (after
/// `fork`, stdio already duped to 0/1/2): only async-signal-safe
/// calls, no allocation. Any failure aborts the child before `exec`
/// (the `Err` return blocks the exec).
///
/// # Safety
///
/// Called by `std` in the child after `fork`; the body uses raw
/// syscalls only.
fn confine_child(keep: RawFd) -> std::io::Result<()> {
    // Ambient first: clearing permitted sets while ambient bits linger
    // fails (ambient must stay within permitted+inheritable).
    // SAFETY: raw prctl numbers, no pointers.
    let cleared = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if cleared != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Empty every capability set (dropping privilege is always
    // permitted, with or without file caps on the parent). Raw
    // `capset` syscall: libc 0.2 exposes no typed binding.
    // SAFETY: stack header+data, version 3 (two data words cover the
    // full 64-bit mask); both outlive the syscall.
    let zeroed = unsafe {
        let mut header = CapHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::empty(), CapData::empty()];
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if zeroed != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // No privilege can return past this point (set-once, irreversible).
    // SAFETY: raw prctl numbers, no pointers.
    let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // FD allowlist: stdio survives, everything else closes. Authority
    // fds must never leak into the helper (BPF fds are not all
    // close-on-exec), so this closes by number, not by trust — and by
    // RANGE, not by the current soft `RLIMIT_NOFILE`: an fd parked
    // above a subsequently lowered soft limit still closes (C1 M1).
    // The pinned executable fd survives as two spans around it (it
    // is `CLOEXEC`, so `exec` drops it right after resolving the
    // image from it — the helper still sees stdio-only).
    // SAFETY: close_range by number only (async-signal-safe).
    let close_span = |first: u32, last: u32| -> std::io::Result<()> {
        if first > last {
            return Ok(());
        }
        // SAFETY: close_range by number only (async-signal-safe).
        let ranged = unsafe { libc::close_range(first, last, 0) };
        if ranged == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    let ranged: std::io::Result<()> = (|| {
        if keep < 3 {
            return close_span(3, u32::MAX);
        }
        let kept = keep as u32;
        close_span(3, kept - 1)?;
        close_span(kept + 1, u32::MAX)
    })();
    match ranged {
        Ok(()) => return Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => {}
        Err(err) => return Err(err),
    }
    // Pre-5.9 kernels lack close_range: best-effort close by number
    // up to the current ceiling (a high fd above a lowered soft
    // limit survives here — the M1 floor is 6.12+, where the range
    // path above always runs, so this never executes supported).
    // SAFETY: sysconf+close by number only.
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd > 0 { max_fd as i32 } else { 1024 };
    for fd in 3..max_fd {
        if fd == keep {
            continue;
        }
        // SAFETY: closing an unowned number is a harmless EBADF.
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

/// Linux capability version 3 (two data words cover the full
/// 64-bit mask). Named locally: the constant's libc spelling varies,
/// the ABI value does not.
#[allow(clippy::upper_case_acronyms)]
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Raw `capset` header (`__user_cap_header_struct` layout, version 3).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// Raw `capset` data word (`__user_cap_data_struct` layout).
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

impl CapData {
    /// Empty capability word (every set cleared).
    fn empty() -> Self {
        Self {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }
    }
}

/// Spawn the verified helper image with stdio pipes under
/// [`confine_child`]. `pinned` is the just-verified open file: the
/// child execs `/proc/self/fd/N` (the SAME open file description the
/// identity check statted — pathname state after the open cannot
/// affect which image runs), with `arg0` as the child's `argv[0]`
/// (the verified path, never the fd spelling, so diagnostics name
/// the real sibling). `stdin_mode` selects a piped stdin (serve) or
/// null stdin (attest). Callers pass the fixed flag vocabulary only;
/// `--metadata FILE` carries a launcher-CLI-selected path (never
/// helper- or file-selected): the helper takes no executable paths
/// and the launcher takes no metadata content.
fn spawn_confined(
    pinned: &std::fs::File,
    arg0: &Path,
    args: &[String],
    stdin_mode: Stdio,
) -> std::io::Result<std::process::Child> {
    let fd = pinned.as_raw_fd();
    debug_assert!(fd >= 3, "image fd parks above stdio");
    let exec_path = format!("/proc/self/fd/{fd}");
    let mut command = Command::new(&exec_path);
    command
        .arg0(arg0)
        .args(args)
        .stdin(stdin_mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: `confine_child` is async-signal-safe (raw syscalls, no
    // allocation, no locks) as `pre_exec` requires; `fd` is `Copy`.
    unsafe {
        command.pre_exec(move || confine_child(fd));
    }
    command.spawn()
}

/// Wait for the child up to `bound`, polling in [`WAIT_POLL`] slices.
/// A lapse kills the child, reaps it, and reports a stall (retryable
/// transport failure — never a hang, never an orphan).
fn wait_bounded(child: &mut std::process::Child, bound: Duration) -> WaitOutcome {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return WaitOutcome::Exited(status),
            Ok(None) => {
                if start.elapsed() >= bound {
                    let _ = child.kill();
                    let _ = child.wait();
                    return WaitOutcome::Stalled;
                }
                std::thread::sleep(WAIT_POLL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return WaitOutcome::WaitFailed;
            }
        }
    }
}

/// Bounded-wait outcome (no exit codes escape: callers map these to
/// typed unavailability with static detail).
enum WaitOutcome {
    /// The child exited (status inspected by the caller).
    Exited(std::process::ExitStatus),
    /// The bound lapsed; the child was killed and reaped.
    Stalled,
    /// The wait itself failed; the child was killed and reaped.
    WaitFailed,
}

/// Read one pipe to EOF with a hard cap (`cap + 1` probe idiom):
/// over-cap refuses [`MetadataUnavailable::BudgetExceeded`], I/O
/// failure refuses [`MetadataUnavailable::HelperRefused`].
fn read_capped(pipe: impl std::io::Read, cap: usize) -> Result<Vec<u8>, MetadataUnavailable> {
    use std::io::Read;
    let mut bytes = Vec::new();
    pipe.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MetadataUnavailable::HelperRefused)?;
    if bytes.len() > cap {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    Ok(bytes)
}

/// Run the `--attest` handshake: pin the helper image, fd-exec the
/// verified open file, and check the reported boundary without
/// touching metadata or stdin. Verifies exit 0, one parseable
/// stdout attestation, and the pinned boundary; returns the pinned
/// identity the serve must reproduce. Any deviation refuses
/// [`MetadataUnavailable::HelperRefused`]: a missing binary fails at
/// the pin, a replaced binary fails the handshake.
pub fn attest_helper(
    helper: &Path,
    principal: &Principal,
    bound: Duration,
) -> Result<HelperIdentity, MetadataUnavailable> {
    let pinned = pin_helper(helper)?;
    let image = pinned.reopen()?;
    let args = ["--attest".to_string(), "--require-no-new-privs".to_string()];
    let mut child = spawn_confined(&image, &pinned.path, &args, Stdio::null())
        .map_err(|_| MetadataUnavailable::HelperRefused)?;
    let stdout = child.stdout.take();
    let _stderr = child.stderr.take();
    match wait_bounded(&mut child, bound) {
        WaitOutcome::Exited(status) if status.success() => {}
        _ => return Err(MetadataUnavailable::HelperRefused),
    }
    let out = read_capped(stdout.expect("piped stdout"), 4096)?;
    let text = String::from_utf8(out).map_err(|_| MetadataUnavailable::HelperRefused)?;
    // The attestation is the only stdout line; anything else (empty,
    // chatter, truncation) refuses.
    let mut lines = text.lines();
    let Some(line) = lines.next() else {
        return Err(MetadataUnavailable::HelperRefused);
    };
    if lines.next().is_some() {
        return Err(MetadataUnavailable::HelperRefused);
    }
    let attestation = parse_attestation_line(line)?;
    check_helper_attestation(&attestation, principal)?;
    Ok(pinned.identity)
}

/// Outcome of one serve attempt: either a bound response or a
/// classified failure (retryable transport failure vs deterministic
/// typed refusal).
enum AttemptOutcome {
    /// Bound, verified response.
    Answered(SnapshotResponse),
    /// Retryable transport failure (stall/crash/wait failure).
    TransportFailed,
    /// Deterministic typed refusal (never retried).
    Refused(MetadataUnavailable),
}

/// Serve one snapshot request through a confined helper run: write the
/// encoded request to stdin, wait bounded, decode + bind the stdout
/// response, and verify the stderr attestation against the pinned
/// boundary before consuming anything. `metadata` is passed through
/// as `--metadata FILE` (the helper reads and validates it — the
/// launcher never parses metadata bytes). Pins the image fresh at
/// call time; the preflight-pinned path is
/// [`serve_pinned_snapshot`] (production serve re-verifies the
/// preflight pin, so a post-preflight replacement refuses).
pub fn serve_snapshot(
    helper: &Path,
    principal: &Principal,
    metadata: Option<&Path>,
    request: &SnapshotRequest,
) -> Result<SnapshotResponse, MetadataUnavailable> {
    serve_snapshot_with_bound(helper, principal, metadata, request, HELPER_ATTEMPT_TIMEOUT)
}

/// [`serve_snapshot`] with an explicit per-attempt bound (tests pin
/// short bounds; production uses [`HELPER_ATTEMPT_TIMEOUT`]).
pub fn serve_snapshot_with_bound(
    helper: &Path,
    principal: &Principal,
    metadata: Option<&Path>,
    request: &SnapshotRequest,
    bound: Duration,
) -> Result<SnapshotResponse, MetadataUnavailable> {
    let pinned = pin_helper(helper)?;
    serve_pinned_snapshot_with_bound(&pinned, principal, metadata, request, bound)
}

/// Serve one snapshot request through the preflight-pinned helper
/// image: every attempt (initial plus retries) reopens the path,
/// requires the pinned identity, and fd-execs the verified file —
/// the SAME image preflight verified, never a later replacement.
pub fn serve_pinned_snapshot(
    pinned: &PinnedHelper,
    principal: &Principal,
    metadata: Option<&Path>,
    request: &SnapshotRequest,
) -> Result<SnapshotResponse, MetadataUnavailable> {
    serve_pinned_snapshot_with_bound(pinned, principal, metadata, request, HELPER_ATTEMPT_TIMEOUT)
}

/// [`serve_pinned_snapshot`] with an explicit per-attempt bound
/// (tests pin short bounds; production uses
/// [`HELPER_ATTEMPT_TIMEOUT`]).
pub fn serve_pinned_snapshot_with_bound(
    pinned: &PinnedHelper,
    principal: &Principal,
    metadata: Option<&Path>,
    request: &SnapshotRequest,
    bound: Duration,
) -> Result<SnapshotResponse, MetadataUnavailable> {
    let mut attempts = 0u32;
    loop {
        match serve_once(pinned, principal, metadata, request, bound) {
            AttemptOutcome::Answered(response) => return Ok(response),
            AttemptOutcome::Refused(kind) => return Err(kind),
            AttemptOutcome::TransportFailed => {
                if attempts >= MAX_HELPER_RETRIES {
                    return Err(MetadataUnavailable::HelperRefused);
                }
                attempts += 1;
            }
        }
    }
}

/// One serve attempt (no retries here — the caller owns the budget).
fn serve_once(
    pinned: &PinnedHelper,
    principal: &Principal,
    metadata: Option<&Path>,
    request: &SnapshotRequest,
    bound: Duration,
) -> AttemptOutcome {
    let request_bytes = match encode_request(request) {
        Ok(bytes) => bytes,
        Err(kind) => return AttemptOutcome::Refused(kind),
    };
    // `--require-no-new-privs` pins installed-launcher mode: the
    // helper refuses unless confinement held (defense in depth behind
    // the launcher's own verification).
    let mut args = vec!["--require-no-new-privs".to_string()];
    if let Some(path) = metadata {
        args.push("--metadata".to_string());
        args.push(path.to_string_lossy().into_owned());
    }
    // Identity first: a post-pin replacement refuses here,
    // deterministically (never retried) — the exec below runs the
    // just-verified file, so no window remains.
    let image = match pinned.reopen() {
        Ok(image) => image,
        Err(kind) => return AttemptOutcome::Refused(kind),
    };
    let mut child = match spawn_confined(&image, &pinned.path, &args, Stdio::piped()) {
        Ok(child) => child,
        Err(_) => return AttemptOutcome::Refused(MetadataUnavailable::HelperRefused),
    };
    // Write the whole request, then close stdin (EOF frames the one
    // document). A broken pipe means the child died early — a crash,
    // retryable below via the exit status.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&request_bytes);
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let status = match wait_bounded(&mut child, bound) {
        WaitOutcome::Exited(status) => status,
        WaitOutcome::Stalled | WaitOutcome::WaitFailed => return AttemptOutcome::TransportFailed,
    };
    let out = match read_capped(stdout.expect("piped stdout"), MAX_SNAPSHOT_RESPONSE_BYTES) {
        Ok(bytes) => bytes,
        Err(kind) => return AttemptOutcome::Refused(kind),
    };
    let err = match read_capped(stderr.expect("piped stderr"), 65536) {
        Ok(bytes) => bytes,
        Err(kind) => return AttemptOutcome::Refused(kind),
    };
    let stderr_text = String::from_utf8_lossy(&err);
    // Typed refusal first: a stderr `{"error":"<name>"}` line is the
    // helper's deterministic verdict — honored, never retried.
    if let Some(kind) = stderr_text
        .lines()
        .find_map(|line| parse_error_line(line).ok())
    {
        return AttemptOutcome::Refused(kind);
    }
    if !status.success() {
        // Untyped nonzero exit (crash, signal, abort): retryable.
        return AttemptOutcome::TransportFailed;
    }
    // Exit 0 claims exactly one stdout document: decode, bind to the
    // request, and verify the stderr attestation BEFORE consuming the
    // response. A 0-exit with a bad body or a bad boundary is a
    // broken helper — deterministic, never retried.
    let response = match decode_response(&out) {
        Ok(response) => response,
        Err(kind) => return AttemptOutcome::Refused(kind),
    };
    if bind_response_to_request(request, &response).is_err() {
        return AttemptOutcome::Refused(MetadataUnavailable::HelperRefused);
    }
    let attested = stderr_text
        .lines()
        .find_map(|line| parse_attestation_line(line).ok());
    match attested {
        Some(attestation) => match check_helper_attestation(&attestation, principal) {
            Ok(()) => AttemptOutcome::Answered(response),
            Err(kind) => AttemptOutcome::Refused(kind),
        },
        None => AttemptOutcome::Refused(MetadataUnavailable::HelperRefused),
    }
}

/// NUL-truncated kernel name from raw `KAgg` words (re-exported for
/// the CLI export glue: the native join needs verbatim algorithm and
/// driver names, decoded exactly as the observation path decodes
/// them — one decoder, two callers, never a forked copy).
#[must_use]
pub fn kagg_names(kagg: &kryprobe_abi::kcrypto_agg::KAgg) -> (String, String) {
    (
        crate::kcrypto_backend::observe::name_from_words(&kagg.alg()),
        crate::kcrypto_backend::observe::name_from_words(&kagg.drv()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_core::workload::{
        KernelIdentity, MetadataSnapshot, SnapshotInterval, SnapshotKey,
    };
    use std::os::unix::fs::PermissionsExt;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const SCOPE: &str = "test-release/test-boot-id";

    fn principal_fixture() -> Principal {
        Principal {
            uid: 1000,
            euid: 1000,
            gid: 1000,
            egid: 1000,
            groups: vec![1000, 27],
        }
    }

    fn status_text() -> String {
        "Uid:\t1000\t1000\t1000\t1000\n\
         Gid:\t1000\t1000\t1000\t1000\n\
         Groups:\t1000 27 \n\
         CapEff:\t0000000000000000\n\
         NoNewPrivs:\t0\n"
            .to_string()
    }

    #[test]
    fn principal_parses_kernel_credentials() {
        assert_eq!(
            principal_from_status_text(&status_text()),
            Some(principal_fixture())
        );
        // Any missing or malformed identity field fails closed.
        assert_eq!(principal_from_status_text("Uid:\t1000\n"), None);
        assert_eq!(
            principal_from_status_text(&status_text().replace("1000", "abc")),
            None
        );
        assert_eq!(
            principal_from_status_text("Gid:\t1\t1\t1\t1\nGroups:\t1\n"),
            None
        );
        assert_eq!(principal_from_status_text(""), None);
    }

    #[test]
    fn kernel_scope_matches_helper_convention() {
        let scratch = kryprobe_testkit::TempDir::named("launch-scope").expect("scratch");
        let root = scratch.path().join("proc");
        let dir = root.join("sys/kernel/random");
        std::fs::create_dir_all(&dir).expect("proc fixture");
        std::fs::write(root.join("sys/kernel/osrelease"), "7.0.0-38-generic\n").expect("write");
        std::fs::write(dir.join("boot_id"), "deadbeef-uuid\n").expect("write");
        assert_eq!(
            kernel_scope_for_proc(&root).expect("scope"),
            "7.0.0-38-generic/deadbeef-uuid"
        );
        // Missing files, embedded whitespace, and over-bound fields
        // refuse (same convention as the helper's own tag).
        assert_eq!(
            kernel_scope_for_proc(&scratch.path().join("absent")),
            Err(MetadataUnavailable::UnsupportedEnvironment)
        );
        std::fs::write(root.join("sys/kernel/osrelease"), "has space\n").expect("write");
        assert_eq!(
            kernel_scope_for_proc(&root),
            Err(MetadataUnavailable::UnsupportedEnvironment)
        );
        std::fs::write(root.join("sys/kernel/osrelease"), "x".repeat(65)).expect("write");
        assert_eq!(
            kernel_scope_for_proc(&root),
            Err(MetadataUnavailable::UnsupportedEnvironment)
        );
    }

    #[test]
    fn helper_sibling_is_fixed_beside_exe() {
        assert_eq!(
            helper_sibling_for(Path::new("/usr/local/bin/kryprobe")),
            PathBuf::from("/usr/local/bin/kryprobe-workload-helper")
        );
        assert_eq!(
            helper_sibling_for(Path::new("kryprobe")),
            PathBuf::from("kryprobe-workload-helper")
        );
    }

    fn attestation_line(uid: u32, caps: &str, nnp: bool, fds: &str) -> String {
        format!(
            r#"{{"attestation":{{"uid":{uid},"euid":{uid},"gid":1000,"egid":1000,"caps":{{"eff":"{caps}","prm":"{caps}","inh":"{caps}","amb":"{caps}"}},"no_new_privs":{nnp},"fds":[{fds}]}}}}"#
        )
    }

    #[test]
    fn attestation_parses_strict_and_checks_pinned_boundary() {
        let principal = principal_fixture();
        let good =
            parse_attestation_line(&attestation_line(1000, "0", true, "0,1,2")).expect("parses");
        assert!(check_helper_attestation(&good, &principal).is_ok());
        // Every boundary deviation refuses: principal mismatch,
        // nonzero caps, clear no-new-privs, non-stdio fds.
        let wrong_user =
            parse_attestation_line(&attestation_line(1234, "0", true, "0,1,2")).expect("parses");
        assert_eq!(
            check_helper_attestation(&wrong_user, &principal),
            Err(MetadataUnavailable::HelperRefused)
        );
        for (caps, nnp, fds) in [
            ("1", true, "0,1,2"),
            ("0", false, "0,1,2"),
            ("0", true, "0,1,2,3"),
            ("0", true, "0,1"),
        ] {
            let att =
                parse_attestation_line(&attestation_line(1000, caps, nnp, fds)).expect("parses");
            assert_eq!(
                check_helper_attestation(&att, &principal),
                Err(MetadataUnavailable::HelperRefused),
                "caps={caps} nnp={nnp} fds=[{fds}] refuses"
            );
        }
        // Malformed lines never parse as attestations.
        for bad in [
            "not json",
            "{}",
            r#"{"attestation":{}}"#,
            &attestation_line(1000, "0x10", true, "0,1,2"),
        ] {
            assert_eq!(
                parse_attestation_line(bad),
                Err(MetadataUnavailable::HelperRefused),
                "line refuses: {bad}"
            );
        }
    }

    #[test]
    fn error_lines_map_frozen_names() {
        for (name, kind) in [
            ("no_principal", MetadataUnavailable::NoPrincipal),
            ("helper_refused", MetadataUnavailable::HelperRefused),
            ("budget_exceeded", MetadataUnavailable::BudgetExceeded),
            (
                "unsupported_environment",
                MetadataUnavailable::UnsupportedEnvironment,
            ),
            ("parse_failed", MetadataUnavailable::ParseFailed),
        ] {
            assert_eq!(
                parse_error_line(&format!(r#"{{"error":"{name}"}}"#)),
                Ok(kind)
            );
        }
        assert_eq!(
            parse_error_line(r#"{"error":"bogus"}"#),
            Err(MetadataUnavailable::HelperRefused)
        );
        assert_eq!(
            parse_error_line("garbage"),
            Err(MetadataUnavailable::HelperRefused)
        );
    }

    /// Built fixture binary: `<target>/debug/kryprobe_launch_fixture`
    /// next to the test executable's `deps` dir. Every all-target
    /// `cargo test` builds it (including the `xtask check` gate);
    /// focused `--lib`/`--test` runs must build it first
    /// (`cargo build -p kryprobe-privilege --bin
    /// kryprobe_launch_fixture`) — the assert says so loudly.
    fn fixture_binary_path() -> PathBuf {
        let test_exe = std::env::current_exe().expect("test exe");
        let bin = test_exe
            .parent()
            .expect("deps dir")
            .parent()
            .expect("profile dir")
            .join("kryprobe_launch_fixture");
        assert!(
            bin.is_file(),
            "fixture binary built at {} (run all-target `cargo test -p kryprobe-privilege`)",
            bin.display()
        );
        bin
    }

    /// Stage the fixture binary at `dir/name` with its stem sidecar
    /// (`<stem>.fixture.json`); returns the helper path. The sidecar
    /// selects attest/serve behavior (see the fixture's module docs).
    fn stage_fixture(dir: &Path, name: &str, sidecar: serde_json::Value) -> PathBuf {
        let dst = dir.join(name);
        std::fs::copy(fixture_binary_path(), &dst).expect("fixture staged");
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let stem = Path::new(name)
            .file_stem()
            .expect("stem")
            .to_string_lossy()
            .into_owned();
        std::fs::write(
            dir.join(format!("{stem}.fixture.json")),
            serde_json::to_string(&sidecar).expect("sidecar"),
        )
        .expect("sidecar written");
        dst
    }

    /// Rewrite the staged image with trailing padding: still a valid
    /// ELF (loaders ignore trailing bytes), but a different image by
    /// every identity field — the A/B replacement for the A1 oracle.
    fn pad_staged_image(path: &Path) {
        use std::io::Write;
        let mut image = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("image opens");
        image.write_all(&[0xA5u8; 1024]).expect("padding appends");
    }

    /// Hold one inheritable (non-cloexec) fd open like a BPF authority
    /// fd: without the close loop it would leak into the child.
    struct LeakedFd {
        fd: i32,
    }

    impl LeakedFd {
        fn open() -> Self {
            // SAFETY: open(2) on /dev/null, no O_CLOEXEC — the fd is
            // inheritable by construction; closed on drop.
            let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(fd >= 0, "leak fixture opens");
            Self { fd }
        }
    }

    impl Drop for LeakedFd {
        fn drop(&mut self) {
            // SAFETY: the fd came from the open above.
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[test]
    fn attest_success_verifies_real_confinement() {
        // End-to-end confinement proof: the fixture reports its
        // boundary honestly, and the parent holds a leaked
        // non-cloexec fd that must NOT reach the child. Fails if the
        // pre_exec confinement regresses (caps/nnp/fds) or the
        // principal pinning drifts.
        let scratch = kryprobe_testkit::TempDir::named("launch-attest-ok").expect("scratch");
        let helper = stage_fixture(scratch.path(), "helper", serde_json::json!({}));
        let _leaked = LeakedFd::open();
        let principal = current_principal().expect("test principal");
        assert_ne!(principal.uid, 0, "tests run non-root");
        attest_helper(&helper, &principal, Duration::from_secs(10)).expect("attests");
    }

    #[test]
    fn attest_replaced_or_missing_helper_refuses() {
        let scratch = kryprobe_testkit::TempDir::named("launch-attest-no").expect("scratch");
        let principal = principal_fixture();
        let garbage = stage_fixture(
            scratch.path(),
            "garbage",
            serde_json::json!({"attest_garbage": "totally a helper"}),
        );
        assert_eq!(
            attest_helper(&garbage, &principal, Duration::from_secs(10)),
            Err(MetadataUnavailable::HelperRefused)
        );
        let failing = stage_fixture(
            scratch.path(),
            "failing",
            serde_json::json!({"attest_exit": 2}),
        );
        assert_eq!(
            attest_helper(&failing, &principal, Duration::from_secs(10)),
            Err(MetadataUnavailable::HelperRefused)
        );
        assert_eq!(
            attest_helper(
                &scratch.path().join("absent"),
                &principal,
                Duration::from_secs(10)
            ),
            Err(MetadataUnavailable::HelperRefused)
        );
    }

    /// A1 oracle (Codex C1): a replacement swapped in after preflight
    /// — even one emitting a forged VALID handshake (the principal's
    /// own ids, empty caps, `no_new_privs`, stdio fds) plus a
    /// bindable canned response — refuses: the serve re-verifies the
    /// preflight pin and fd-execs the same image, never the pathname.
    /// (RED shown pre-fix with the script-fixture base-API probe
    /// `..._unpinned_probe`: the replacement served `Ok`.)
    #[test]
    fn replacement_after_preflight_with_forged_handshake_refuses() {
        let scratch = kryprobe_testkit::TempDir::named("launch-replace").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        let canned_path = scratch.path().join("canned.json");
        std::fs::write(&canned_path, &canned).expect("canned");
        let helper_path = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json"}),
        );
        let principal = current_principal().expect("test principal");
        assert_ne!(principal.uid, 0, "tests run non-root");
        let preflight = preflight_helper(Some(&helper_path));
        assert!(preflight.launchable(), "honest helper A preflights");
        let pinned = PinnedHelper {
            path: helper_path.clone(),
            identity: preflight.helper_identity.expect("preflight pins"),
        };
        // Replacement B: a padded copy of the same fixture — a
        // different image by every identity field (inode, size)
        // emitting a forged VALID handshake (the principal's own
        // real ids, empty caps, `no_new_privs`, stdio fds) plus the
        // bindable canned response. Handshake and bind both pass, so
        // only the identity pin can refuse it.
        std::fs::remove_file(&helper_path).expect("A removed");
        std::fs::copy(fixture_binary_path(), &helper_path).expect("B staged");
        std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        pad_staged_image(&helper_path);
        assert_eq!(
            serve_pinned_snapshot_with_bound(
                &pinned,
                &principal,
                None,
                &request,
                Duration::from_secs(10)
            ),
            Err(MetadataUnavailable::HelperRefused),
            "replacement after preflight refuses"
        );
        // Positive control: the pinned image itself still serves
        // through the same pinned path (pin, handshake, and bind all
        // agree when nothing was replaced).
        let helper_c = stage_fixture(
            scratch.path(),
            "helper-c",
            serde_json::json!({"canned": "canned.json"}),
        );
        let pinned_c = pin_helper(&helper_c).expect("C pins");
        assert!(
            serve_pinned_snapshot_with_bound(
                &pinned_c,
                &principal,
                None,
                &request,
                Duration::from_secs(10)
            )
            .is_ok(),
            "the pinned image itself serves"
        );
    }

    #[test]
    fn attest_wrong_principal_refuses() {
        let scratch = kryprobe_testkit::TempDir::named("launch-attest-user").expect("scratch");
        // Honest boundary except a fixed foreign uid: the pin holds.
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"forge_uid": 424242, "forge_euid": 424242}),
        );
        let principal = current_principal().expect("test principal");
        assert_eq!(
            attest_helper(&helper, &principal, Duration::from_secs(10)),
            Err(MetadataUnavailable::HelperRefused)
        );
    }

    /// M1 oracle (Codex C1): an inherited fd numbered above a
    /// subsequently lowered `RLIMIT_NOFILE` soft limit still closes.
    /// The old `sysconf(_SC_OPEN_MAX)` loop stops at the soft limit
    /// and leaks the high fd into the child; `close_range` does not
    /// consult the limit at all.
    #[test]
    fn spawn_closes_fds_above_lowered_soft_limit() {
        const HIGH_WANT: i32 = 512;
        const LOW_SOFT: u64 = 256;
        // SAFETY: open(2) on /dev/null, no O_CLOEXEC — inheritable
        // by construction, like a BPF authority fd.
        let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(devnull >= 0, "leak fixture opens");
        // A free high number (never clobber another live fd in this
        // shared test process).
        let mut high = HIGH_WANT;
        while unsafe { libc::fcntl(high, libc::F_GETFD) } != -1 {
            high += 1;
            assert!(high < 4096, "a free high fd exists");
        }
        assert_eq!(
            unsafe { libc::dup2(devnull, high) },
            high,
            "high fd parks above the lowered soft limit"
        );
        // RAII: the soft limit is process-global, so it restores on
        // every exit path (including panic); the parked fds close.
        // The lowered window is milliseconds and 256 fds still serve
        // every concurrent test's tempfiles.
        struct SoftLimitGuard {
            soft: u64,
            hard: u64,
            fds: Vec<i32>,
        }
        impl Drop for SoftLimitGuard {
            fn drop(&mut self) {
                let restore = libc::rlimit {
                    rlim_cur: self.soft,
                    rlim_max: self.hard,
                };
                // SAFETY: restores the saved ceiling (soft <= hard).
                unsafe {
                    libc::setrlimit(libc::RLIMIT_NOFILE, &restore);
                }
                for fd in &self.fds {
                    // SAFETY: each fd came from the opens above.
                    unsafe {
                        libc::close(*fd);
                    }
                }
            }
        }
        let mut saved = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the struct only.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved) },
            0,
            "reads the current ceiling"
        );
        assert!(
            saved.rlim_cur > high as u64,
            "soft limit starts above the probe fd"
        );
        let _guard = SoftLimitGuard {
            soft: saved.rlim_cur,
            hard: saved.rlim_max,
            fds: vec![devnull, high],
        };
        let lowered = libc::rlimit {
            rlim_cur: LOW_SOFT,
            rlim_max: saved.rlim_max,
        };
        // SAFETY: lowering the soft ceiling needs no privilege.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
            0,
            "soft limit lowers below the parked fd"
        );
        let ls = pinnable_ls();
        let image = ls.reopen().expect("ls reopens");
        let mut child = spawn_confined(
            &image,
            &ls.path,
            &["/proc/self/fd".to_string()],
            Stdio::null(),
        )
        .expect("spawns");
        let stdout = child.stdout.take().expect("piped");
        assert!(matches!(
            wait_bounded(&mut child, Duration::from_secs(10)),
            WaitOutcome::Exited(status) if status.success()
        ));
        let out = read_capped(stdout, 4096).expect("reads");
        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "0\n1\n2\n3\n",
            "child sees stdio + transient only (high fd closed)"
        );
    }

    /// A pinnable `ls` for the fd-allowlist proofs (fd-exec needs a
    /// real path, never a `PATH` search; `ls` may itself be a
    /// symlink to a coreutils shim, so resolve it first — test-only
    /// resolution, the pin still verifies the final image).
    fn pinnable_ls() -> PinnedHelper {
        ["/bin/ls", "/usr/bin/ls"]
            .iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .find_map(|path| pin_helper(&path).ok())
            .expect("a pinnable ls exists")
    }

    #[test]
    fn spawn_closes_non_cloexec_fds() {
        // The sharp fd-allowlist proof, no fixture protocol: `ls` sees
        // exactly stdio plus its own transient dir fd (lowest-free 3),
        // even though the parent holds a leaked inheritable fd.
        let _leaked = LeakedFd::open();
        let ls = pinnable_ls();
        let image = ls.reopen().expect("ls reopens");
        let mut child = spawn_confined(
            &image,
            &ls.path,
            &["/proc/self/fd".to_string()],
            Stdio::null(),
        )
        .expect("spawns");
        let stdout = child.stdout.take().expect("piped");
        assert!(matches!(
            wait_bounded(&mut child, Duration::from_secs(10)),
            WaitOutcome::Exited(status) if status.success()
        ));
        let out = read_capped(stdout, 4096).expect("reads");
        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "0\n1\n2\n3\n",
            "child sees stdio + transient only"
        );
    }

    fn test_request() -> SnapshotRequest {
        SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: vec![SnapshotKey {
                kernel_scope: SCOPE.to_string(),
                cgroup: 42,
                tgid: 100,
                start_ns: 555,
            }],
            capture_interval: None,
        }
    }

    fn canned_response_bytes(request: &SnapshotRequest) -> Vec<u8> {
        // A binding response, produced by the frozen pure resolver
        // (empty entries: the key resolves Unresolved — still bound).
        let snapshot = MetadataSnapshot {
            collector: "launch-test".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: 1,
                end_ns: 2,
            },
            kernel_identity: KernelIdentity::Known(SCOPE.to_string()),
            entries: Vec::new(),
        };
        let response = kryprobe_core::workload::resolve(request, &snapshot).expect("resolves");
        kryprobe_core::workload::encode_response(&response).expect("encodes")
    }

    #[test]
    fn serve_success_binds_response_and_passes_metadata_through() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-ok").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        let canned_path = scratch.path().join("canned.json");
        std::fs::write(&canned_path, &canned).expect("canned");
        let argv_log = scratch.path().join("argv.log");
        // The metadata file carries garbage content: serve still
        // succeeds, proving the launcher never parses metadata bytes
        // (the fixture ignores content; the real helper validates).
        let metadata = scratch.path().join("meta.json");
        std::fs::write(&metadata, b"{ not valid json").expect("garbage metadata");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json", "argv_log": "argv.log"}),
        );
        let _leaked = LeakedFd::open();
        let principal = current_principal().expect("test principal");
        let response = serve_snapshot_with_bound(
            &helper,
            &principal,
            Some(&metadata),
            &request,
            Duration::from_secs(10),
        )
        .expect("serves");
        assert_eq!(response.session_id, SESSION);
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, 42);
        let argv = std::fs::read_to_string(&argv_log).expect("argv logged");
        assert!(
            argv.contains("--metadata") && argv.contains("meta.json"),
            "metadata path passes through: {argv}"
        );
    }

    #[test]
    fn serve_typed_refusal_is_honored_without_retry() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-ref").expect("scratch");
        let counter = scratch.path().join("count");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"refuse": "no_principal", "count": "count"}),
        );
        let principal = current_principal().expect("test principal");
        assert_eq!(
            serve_snapshot_with_bound(
                &helper,
                &principal,
                None,
                &test_request(),
                Duration::from_secs(10)
            ),
            Err(MetadataUnavailable::NoPrincipal)
        );
        assert_eq!(
            std::fs::read_to_string(&counter)
                .expect("counter")
                .lines()
                .count(),
            1,
            "typed refusals never retry"
        );
    }

    #[test]
    fn serve_crash_retries_then_refuses() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-crash").expect("scratch");
        let counter = scratch.path().join("count");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"crash": true, "count": "count"}),
        );
        let principal = current_principal().expect("test principal");
        assert_eq!(
            serve_snapshot_with_bound(
                &helper,
                &principal,
                None,
                &test_request(),
                Duration::from_secs(10)
            ),
            Err(MetadataUnavailable::HelperRefused)
        );
        assert_eq!(
            std::fs::read_to_string(&counter)
                .expect("counter")
                .lines()
                .count() as u32,
            1 + MAX_HELPER_RETRIES,
            "crash retries the frozen budget, then refuses"
        );
    }

    #[test]
    fn serve_stall_kills_and_stays_bounded() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-stall").expect("scratch");
        let counter = scratch.path().join("count");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"stall_secs": 30, "count": "count"}),
        );
        let principal = current_principal().expect("test principal");
        let start = Instant::now();
        assert_eq!(
            serve_snapshot_with_bound(
                &helper,
                &principal,
                None,
                &test_request(),
                Duration::from_millis(300)
            ),
            Err(MetadataUnavailable::HelperRefused)
        );
        assert_eq!(
            std::fs::read_to_string(&counter)
                .expect("counter")
                .lines()
                .count() as u32,
            1 + MAX_HELPER_RETRIES,
            "stalls retry the frozen budget, then refuse"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the wait kills stalled children (bounded)"
        );
    }

    #[test]
    fn serve_unbound_response_refuses_without_retry() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-bind").expect("scratch");
        // A well-formed response for a FOREIGN session: decodes, but
        // never binds to this request.
        let mut foreign = test_request();
        foreign.session_id = "ffffffffffffffffffffffffffffffff".to_string();
        let canned = canned_response_bytes(&foreign);
        let canned_path = scratch.path().join("canned.json");
        std::fs::write(&canned_path, &canned).expect("canned");
        let counter = scratch.path().join("count");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json", "count": "count"}),
        );
        let principal = current_principal().expect("test principal");
        assert_eq!(
            serve_snapshot_with_bound(
                &helper,
                &principal,
                None,
                &test_request(),
                Duration::from_secs(10)
            ),
            Err(MetadataUnavailable::HelperRefused)
        );
        assert_eq!(
            std::fs::read_to_string(&counter)
                .expect("counter")
                .lines()
                .count(),
            1,
            "binding failures never retry"
        );
    }

    #[test]
    fn preflight_verifies_or_names_unavailability() {
        let scratch = kryprobe_testkit::TempDir::named("launch-preflight").expect("scratch");
        let helper = stage_fixture(scratch.path(), "helper", serde_json::json!({}));
        let principal = current_principal().expect("test principal");
        let good = preflight_helper(Some(&helper));
        if principal.uid == 0 || principal.euid == 0 {
            assert_eq!(good.unavailable, Some(MetadataUnavailable::NoPrincipal));
            assert!(!good.launchable());
        } else {
            assert_eq!(good.unavailable, None);
            assert!(good.launchable());
            assert_eq!(good.helper.as_deref(), Some(helper.as_path()));
            assert_eq!(
                good.helper_identity,
                Some(pin_helper(&helper).expect("pins").identity),
                "preflight pins the attested image"
            );
        }
        let missing = preflight_helper(Some(&scratch.path().join("absent")));
        // Discovery/attestation failure names the typed reason and
        // keeps the established principal + scope for the raw-ID path.
        assert_eq!(
            missing.unavailable,
            Some(MetadataUnavailable::HelperRefused)
        );
        assert!(!missing.launchable());
        assert!(missing.principal.is_some());
        assert!(missing.kernel_scope.is_some());
    }
}
