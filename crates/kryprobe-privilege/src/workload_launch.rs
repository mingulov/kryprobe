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
//! - Identity pinning (C1 A1, hardened C2 A1): preflight opens
//!   the helper (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`), enforces the
//!   trusted-image rule (owner root-or-euid, no group/other write —
//!   the installed and dev layouts alike), and pins its file
//!   identity (device, inode, owner, mode, size, sha256 content
//!   digest). Every later spawn reopens the path the same way,
//!   requires the SAME identity, and executes the verified open
//!   file via `/proc/self/fd/N` — the kernel resolves the
//!   executable from the open file description, never from the
//!   pathname, so a replacement/rename/symlink-swap after preflight
//!   cannot reach `exec`: there is no check-to-exec window (the
//!   check and the exec share one open file description). Stat
//!   fields alone cannot see an equal-length in-place rewrite of a
//!   writable inode; the digest can.
//! - Confinement (child `pre_exec`, before `exec`): found its own
//!   process group (group id == child pid; the parent claims it too,
//!   so kill paths SIGKILL descendants with precise membership),
//!   clear ambient caps, empty every capability set, set
//!   `no_new_privs`, close every fd except stdio and the pinned
//!   executable fd (which is `CLOEXEC`, so it never survives `exec`
//!   into the helper — the attested fd set stays stdio-only).
//!   Dropping privilege is always permitted, so this works
//!   identically with or without file caps on the CLI.
//! - Verification: `--attest --require-no-new-privs` first (the helper
//!   reports its boundary without touching metadata or stdin), then the
//!   serve run. The launcher checks uid/euid/gid/egid against the pinned
//!   principal, empty caps, `no_new_privs`, and the stdio-only fd set
//!   before consuming any metadata. The serve response additionally
//!   binds to its request ([`bind_response_to_request`]).
//! - Transport (finding C1): one `poll` loop writes stdin while draining
//!   stdout/stderr concurrently under a single overall deadline
//!   covering spawn, writes, reads, and reap. No wait-before-drain
//!   stall (a legal response larger than the pipe streams through)
//!   and no unbounded EOF read (a descendant retaining a pipe
//!   cannot outlive the deadline: every kill path SIGKILLs the
//!   child's process group — child plus descendants — then reaps
//!   the direct child; status peeks never reap, so the zombie
//!   anchors the group until disposition). Caps keep the old `cap +
//!   1` refusals; outcome classification is unchanged. Residual,
//!   documented not claimed: detached descendants of a SUCCESSFUL
//!   run (no pipes held) and new-session escapees are not killed.
//! - Retries: [`MAX_HELPER_RETRIES`] past the initial attempt, on
//!   transport failures only (stall/crash). Typed helper refusals —
//!   including identity-mismatch refusals — are deterministic and
//!   never retried.
//! - Diagnostics: each answered serve additionally parses exactly one
//!   bounded `{"helper_counters":{...}}` stderr record into the
//!   internal typed [`HelperDiagnostics`] (approved fixed numeric
//!   fields plus the saturation marker). Zero, duplicate, over-cap,
//!   or malformed records mark diagnostics unavailable ([`ServedSnapshot`]
//!   carries `None`) without weakening the valid response; no helper
//!   stderr text, path, payload byte, secret, or metadata string
//!   ever reaches the typed surface.
//!
//! [`MetadataUnavailable::NoPrincipal`]: kryprobe_core::workload::MetadataUnavailable::NoPrincipal
//! [`bind_response_to_request`]: kryprobe_core::workload::bind_response_to_request
//! [`MAX_HELPER_RETRIES`]: kryprobe_core::workload::MAX_HELPER_RETRIES

use kryprobe_core::workload::{
    MAX_HELPER_RETRIES, MAX_KERNEL_IDENTITY_BYTES, MAX_SNAPSHOT_RESPONSE_BYTES,
    MetadataUnavailable, SnapshotRequest, SnapshotResponse, bind_response_to_request,
    decode_response, encode_request,
};
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

/// Attest-stdout cap (one attestation line, never more).
const ATTEST_STDOUT_CAP: usize = 4096;

/// Stderr drain cap (attest ignores stderr content but must drain it:
/// an undrained pipe stalls a chatty child exactly like stdout).
const STDERR_DRAIN_CAP: usize = 65536;

/// Helper image size cap (bytes): the content digest reads the whole
/// image, so a hostile path must not balloon the read. 16 MiB is
/// multiples of the real helper; over-cap refuses like any
/// untrusted image.
const MAX_HELPER_IMAGE_BYTES: u64 = 16 * 1024 * 1024;

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
/// file-type bits), size, and the sha256 content digest. Reopening
/// the path must reproduce every field or the image was replaced. A
/// rename-swap always changes the inode; delete-and-recreate with a
/// reused inode trips on size/mode/owner/digest unless the
/// replacement is byte-equal in every pinned field; an equal-length
/// in-place rewrite trips the digest alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperIdentity {
    /// Device id (`st_dev`).
    pub dev: u64,
    /// Inode number (`st_ino`).
    pub ino: u64,
    /// Owner uid (`st_uid`): root (installed) or euid (dev) —
    /// anything else refuses at the open.
    pub uid: u32,
    /// Owner gid (`st_gid`, pinned; group-write refuses at the open).
    pub gid: u32,
    /// Full mode (`st_mode`, type bits included): group/other write
    /// refuses at the open.
    pub mode: u32,
    /// File size (`st_size`).
    pub size: u64,
    /// Content digest (sha256 of the image bytes, read from the same
    /// open file description that execs).
    pub sha256: [u8; 32],
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
    /// flags as the pin (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`),
    /// same file-type gate, every identity field equal. A mismatch (or a
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

/// Open one verified helper image: `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`
/// (a trailing symlink refuses — the fixed sibling is a regular
/// file; a FIFO opens without blocking and refuses below),
/// regular-file gate, `CLOEXEC` pinned explicitly, the fd
/// parked at 3+ (never a stdio number), the trusted-image rule
/// (owner root-or-euid, no group/other write), and the sha256
/// content digest read from the same open file description that
/// execs. Static outcome: ok or I/O error (callers map it to
/// [`MetadataUnavailable::HelperRefused`] without echoing the path).
fn open_verified(path: &Path) -> std::io::Result<(std::fs::File, HelperIdentity)> {
    use std::os::unix::fs::OpenOptionsExt;
    // `O_NONBLOCK`: a FIFO swapped in for the sibling must refuse
    // via the regular-file gate below, never hang this open (C2 C1 —
    // the open precedes any deadline, so blocking here is
    // unbounded). Regular files ignore the flag (reads and the
    // digest behave identically; the fd is `CLOEXEC`, gone at exec).
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
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
        // `F_DUPFD_CLOEXEC` — never plain `F_DUPFD`, which clears
        // `CLOEXEC`: the parked keep-fd must not survive `exec` into
        // the helper (a surviving fd breaks the stdio-only
        // attestation). Verified below, fail-closed.
        // SAFETY: dups a live fd to 3+; the original closes on drop.
        fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fcntl F_GETFD on a live owned fd.
        let parked_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if parked_flags < 0 || (parked_flags & libc::FD_CLOEXEC) == 0 {
            // SAFETY: fresh owned fd, closed exactly once.
            unsafe {
                libc::close(fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "parked image fd lost CLOEXEC",
            ));
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
    // Trusted-image rule (C2 A1): the owner is root (the installed
    // layout) or the caller's own euid (the dev layout: a
    // cargo-built helper next to the CLI), and NOBODY ELSE can write
    // it (no group/other write bits). A foreign-owned or
    // group/other-writable image refuses: another principal could
    // rewrite it under the pin. Owner-write stays allowed (0755 in
    // both layouts): the owner is the trust anchor's own principal,
    // and the content digest below catches any rewrite regardless.
    // SAFETY: geteuid takes no pointers and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if (meta.uid() != 0 && meta.uid() != euid) || (meta.mode() & 0o022) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "helper image is not a trusted image",
        ));
    }
    // Content pin (C2 A1): the sha256 of the SAME open file
    // description that execs. Stat fields cannot see an equal-length
    // in-place rewrite; the digest can. Bounded (a hostile path must
    // not balloon the read); over-cap refuses like any untrusted
    // image. fs-verity was considered and rejected: it needs
    // filesystem support plus install-time provisioning, while the
    // digest closes the demonstrated escape portably. Residual: a
    // writer racing INSIDE one reopen (between this hash and the
    // exec of the same fd) is outside the M1 model — that writer is
    // the owner's own principal (installed images are root-owned,
    // hence not caller-writable at all).
    use sha2::Digest as _;
    use std::io::Read as _;
    let mut content = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_HELPER_IMAGE_BYTES + 1)
        .read_to_end(&mut content)?;
    if content.len() as u64 > MAX_HELPER_IMAGE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "helper image exceeds the size cap",
        ));
    }
    let sha256: [u8; 32] = sha2::Sha256::digest(&content).into();
    Ok((
        file,
        HelperIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            size: meta.len(),
            sha256,
        },
    ))
}

/// Pin the helper image at `path`: verified open plus its identity.
/// The pin carries no open file (stat fields plus the content
/// digest): each spawn reopens and re-verifies via
/// [`PinnedHelper::reopen`], then fd-execs the just-verified file —
/// check and exec share one open file description, so no
/// replacement window exists.
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

/// Maximum bytes of one `{"helper_counters":{...}}` stderr record
/// the launcher parses (the honest full-field emission is under 1
/// KiB even with every counter at `u64::MAX`; past the cap the
/// record marks diagnostics unavailable, never a refusal).
pub const MAX_HELPER_DIAGNOSTICS_BYTES: usize = 4096;

/// Typed helper diagnostics: the approved fixed numeric counter
/// fields plus the explicit saturation marker, parsed at the
/// launcher boundary from exactly one bounded stderr record. Every
/// field is a `u64` counter or the saturation flag — IDs-only, never
/// paths, payload bytes, secrets, or metadata strings. `None` at the
/// serve boundary means unavailable, never all-zero measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperDiagnostics {
    /// Fresh positive-cache hits.
    pub positive_hits: u64,
    /// Positive-cache misses (absent or expired).
    pub positive_misses: u64,
    /// Fresh negative-cache hits (throttled re-scans).
    pub negative_hits: u64,
    /// Positive inserts accepted.
    pub inserts: u64,
    /// Positive inserts refused: cache full.
    pub insert_refused_full: u64,
    /// Negative inserts accepted.
    pub negative_inserts: u64,
    /// Negative inserts refused: cache full.
    pub negative_refused_full: u64,
    /// Tombstone inserts accepted.
    pub tombstone_inserts: u64,
    /// Tombstone inserts refused: store full.
    pub tombstone_refused_full: u64,
    /// Expired entries evicted on lookup.
    pub expired_evictions: u64,
    /// Pid lifetimes or objects changed under us.
    pub reuse_detected: u64,
    /// Scans skipped by the minimum refresh interval.
    pub refresh_throttled: u64,
    /// Keys left un-upgraded by the resolution deadline.
    pub deadline_trips: u64,
    /// Cgroup scans aborted at the directory budget.
    pub scan_budget_trips: u64,
    /// Symlink components refused during traversal.
    pub symlink_refused: u64,
    /// Permission denials observed.
    pub denied: u64,
    /// Non-host (relative/escaping/cross-device) paths refused.
    pub not_host_path: u64,
    /// Objects vanishing mid-traversal.
    pub gone_during_scan: u64,
    /// Pids whose hint no longer matches the captured cgroup (moved on).
    pub migration_skipped: u64,
    /// Pid lifetime records refused: table full.
    pub pid_lifetime_refused_full: u64,
    /// Whether any counter saturated (sticky).
    pub saturated: bool,
}

/// Generate the per-field checked-add folds inside
/// [`HelperDiagnostics::accumulate`].
macro_rules! accumulate_fields {
    ($acc:ident, $chunk:ident, $($field:ident;)*) => {
        $(
            HelperDiagnostics::sat_add(
                &mut $acc.$field,
                &mut $acc.saturated,
                $chunk.$field,
            );
        )*
    };
}

impl HelperDiagnostics {
    /// Zeroed diagnostics (the aggregation identity, never a
    /// measurement claim — only `Some` values reach the surface).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            positive_hits: 0,
            positive_misses: 0,
            negative_hits: 0,
            inserts: 0,
            insert_refused_full: 0,
            negative_inserts: 0,
            negative_refused_full: 0,
            tombstone_inserts: 0,
            tombstone_refused_full: 0,
            expired_evictions: 0,
            reuse_detected: 0,
            refresh_throttled: 0,
            deadline_trips: 0,
            scan_budget_trips: 0,
            symlink_refused: 0,
            denied: 0,
            not_host_path: 0,
            gone_during_scan: 0,
            migration_skipped: 0,
            pid_lifetime_refused_full: 0,
            saturated: false,
        }
    }

    /// Checked add of one counter with saturation: overflow pins the
    /// slot at `u64::MAX` and sets the sticky marker instead of
    /// wrapping.
    fn sat_add(slot: &mut u64, saturated: &mut bool, add: u64) {
        match slot.checked_add(add) {
            Some(next) => *slot = next,
            None => {
                *slot = u64::MAX;
                *saturated = true;
            }
        }
    }

    /// Fold one chunk's diagnostics into this aggregate: every
    /// counter adds checked (overflow saturates with the explicit
    /// marker), and either side's saturation sticks.
    pub fn accumulate(&mut self, chunk: &Self) {
        accumulate_fields! {
            self, chunk,
            positive_hits;
            positive_misses;
            negative_hits;
            inserts;
            insert_refused_full;
            negative_inserts;
            negative_refused_full;
            tombstone_inserts;
            tombstone_refused_full;
            expired_evictions;
            reuse_detected;
            refresh_throttled;
            deadline_trips;
            scan_budget_trips;
            symlink_refused;
            denied;
            not_host_path;
            gone_during_scan;
            migration_skipped;
            pid_lifetime_refused_full;
        }
        self.saturated |= chunk.saturated;
    }

    /// Strictly build the typed record from a parsed counters
    /// object: exactly the approved fields (no missing, no unknown),
    /// every counter a `u64`, the marker a `bool`. Anything else is
    /// not a measurement (`None`), never a refusal.
    fn from_object(map: &serde_json::Map<String, serde_json::Value>) -> Option<Self> {
        if map.len() != 21 {
            return None;
        }
        let num = |key: &str| map.get(key).and_then(serde_json::Value::as_u64);
        Some(Self {
            positive_hits: num("positive_hits")?,
            positive_misses: num("positive_misses")?,
            negative_hits: num("negative_hits")?,
            inserts: num("inserts")?,
            insert_refused_full: num("insert_refused_full")?,
            negative_inserts: num("negative_inserts")?,
            negative_refused_full: num("negative_refused_full")?,
            tombstone_inserts: num("tombstone_inserts")?,
            tombstone_refused_full: num("tombstone_refused_full")?,
            expired_evictions: num("expired_evictions")?,
            reuse_detected: num("reuse_detected")?,
            refresh_throttled: num("refresh_throttled")?,
            deadline_trips: num("deadline_trips")?,
            scan_budget_trips: num("scan_budget_trips")?,
            symlink_refused: num("symlink_refused")?,
            denied: num("denied")?,
            not_host_path: num("not_host_path")?,
            gone_during_scan: num("gone_during_scan")?,
            migration_skipped: num("migration_skipped")?,
            pid_lifetime_refused_full: num("pid_lifetime_refused_full")?,
            saturated: map.get("saturated").and_then(serde_json::Value::as_bool)?,
        })
    }
}

impl Default for HelperDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

/// One served snapshot: the bound response plus the helper's typed
/// diagnostics for that serve (`None` means unavailable — the
/// helper emitted no record, or the record was not exactly one
/// bounded well-formed measurement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedSnapshot {
    /// The bound, verified snapshot response.
    pub response: SnapshotResponse,
    /// Typed helper diagnostics for this serve, if measured.
    pub diagnostics: Option<HelperDiagnostics>,
}

/// Parse the typed diagnostics from one serve's stderr: exactly one
/// bounded `{"helper_counters":{...}}` record parses (strict fields,
/// no duplicates, no unknown keys); zero records, duplicate
/// records, over-cap records, or malformed records yield `None`
/// while the valid response keeps its existing meaning. Never
/// echoes input: the outcome is typed values or absence.
/// Candidacy is textual or decoded-key: any line carrying the
/// marker counts (so a truncated emission that no longer decodes
/// still voids the result), as does any line parsing as JSON with a
/// decoded `helper_counters` key (so an escaped envelope spelling
/// still counts as a second emission).
pub fn parse_helper_diagnostics(stderr_text: &str) -> Option<HelperDiagnostics> {
    let mut record: Option<&str> = None;
    for line in stderr_text.lines() {
        // Textual candidacy (P2 wave-e): any stderr line carrying the
        // marker is a counters emission — including a truncated one
        // that no longer decodes. Decoded-key candidacy (P2 wave-f):
        // a line parsing as JSON with a decoded `helper_counters`
        // key counts too, so an escaped envelope spelling
        // (`hel\u0070er_counters`) cannot evade the exactly-one rule.
        let is_candidate = line.contains("helper_counters")
            || serde_json::from_str::<serde_json::Value>(line)
                .is_ok_and(|value| value.get("helper_counters").is_some());
        if !is_candidate {
            continue;
        }
        if record.is_some() {
            return None;
        }
        record = Some(line);
    }
    let line = record?;
    if line.len() > MAX_HELPER_DIAGNOSTICS_BYTES {
        return None;
    }
    if json_has_duplicate_keys(line) {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let top = value.as_object()?;
    if top.len() != 1 {
        return None;
    }
    let counters = top.get("helper_counters")?.as_object()?;
    HelperDiagnostics::from_object(counters)
}

/// Whether one JSON line repeats an object key anywhere (envelope or
/// counters): `serde_json::Value` keeps last-wins, but a duplicated
/// counter is malformed input, never a measurement. The line passed
/// `serde_json` validation before this walk, so the structure walk
/// below agrees with the parsed value; keys compare decoded (an
/// escaped spelling of a repeated key still collides).
fn json_has_duplicate_keys(line: &str) -> bool {
    /// One open frame: objects collect decoded keys, arrays only
    /// nest (no keys to collide).
    enum Frame {
        Object(Vec<String>),
        Array,
    }
    let mut chars = line.chars().peekable();
    let mut stack: Vec<Frame> = Vec::new();
    while let Some(ch) = chars.next() {
        match ch {
            '{' => stack.push(Frame::Object(Vec::new())),
            '[' => stack.push(Frame::Array),
            '}' | ']' => match stack.pop() {
                Some(Frame::Object(keys)) if ch == '}' => {
                    let mut seen = std::collections::HashSet::new();
                    for key in &keys {
                        if !seen.insert(key) {
                            return true;
                        }
                    }
                }
                Some(Frame::Array) if ch == ']' => {}
                _ => return true,
            },
            '"' => {
                let Some(text) = json_unescape_string(&mut chars) else {
                    return true;
                };
                // Key position: the next non-space character is `:`.
                let mut probe = chars.clone();
                let is_key = matches!(probe.find(|c| !c.is_whitespace()), Some(':'));
                if is_key {
                    match stack.last_mut() {
                        Some(Frame::Object(keys)) => keys.push(text),
                        _ => return true,
                    }
                }
            }
            _ => {
                // Structural punctuation, whitespace, numbers and
                // literals carry no strings or braces; validation
                // already passed, so anything else just advances.
            }
        }
    }
    !stack.is_empty()
}

/// Consume one JSON string body (past the opening quote) into its
/// decoded value, handling every escape including `\u` pairs (an
/// escaped spelling of a repeated key still collides). Returns
/// `None` on truncation or a bad escape.
fn json_unescape_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    fn hex4(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u32> {
        let mut unit = 0u32;
        for _ in 0..4 {
            unit = unit * 16 + chars.next()?.to_digit(16)?;
        }
        Some(unit)
    }
    let mut text = String::new();
    loop {
        match chars.next()? {
            '"' => return Some(text),
            '\\' => match chars.next()? {
                '"' => text.push('"'),
                '\\' => text.push('\\'),
                '/' => text.push('/'),
                'b' => text.push('\u{0008}'),
                'f' => text.push('\u{000C}'),
                'n' => text.push('\n'),
                'r' => text.push('\r'),
                't' => text.push('\t'),
                'u' => {
                    let high = hex4(chars)?;
                    let point = if (0xD800..0xDC00).contains(&high) {
                        let (Some('\\'), Some('u')) = (chars.next(), chars.next()) else {
                            return None;
                        };
                        let low = hex4(chars)?;
                        if !(0xDC00..0xE000).contains(&low) {
                            return None;
                        }
                        0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                    } else {
                        high
                    };
                    text.push(char::from_u32(point)?);
                }
                _ => return None,
            },
            ch => text.push(ch),
        }
    }
}

/// Confine the child before `exec`: clear ambient caps, empty every
/// capability set, set `no_new_privs`, close every fd except stdio
/// and `keep` (the pinned executable fd — `CLOEXEC`, so it never
/// survives `exec` into the helper). `child_soft_limit` (tests only:
/// production passes `None`) lowers the child's own `RLIMIT_NOFILE`
/// soft ceiling before the close, proving the close never consults
/// the limit — process-global lowering would starve parallel tests
/// with `EMFILE`, so the limit applies to the child alone. Runs in
/// `pre_exec` (after `fork`, stdio already duped to 0/1/2): only
/// async-signal-safe calls, no allocation. Any failure aborts the
/// child before `exec` (the `Err` return blocks the exec).
///
/// # Safety
///
/// Called by `std` in the child after `fork`; the body uses raw
/// syscalls only.
fn confine_child(keep: RawFd, child_soft_limit: Option<u64>) -> std::io::Result<()> {
    // Process group first: the child founds its own group (group id
    // == child pid) so the launcher can SIGKILL the whole group —
    // child plus any descendants — without ever signaling its own
    // group. The parent runs the same `setpgid` after spawn (either
    // may win; `EACCES` after `exec` means the other's ran).
    // Failure here aborts before `exec`, so no descendant can ever
    // exist outside the group.
    // SAFETY: raw setpgid on self (async-signal-safe).
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Waitable-child ownership (child side): an inherited
    // `SIGCHLD=SIG_IGN` survives `exec` and would auto-reap this
    // child's own children — reset to `SIG_DFL` so the helper never
    // inherits auto-reap (the parent normalizes pre-spawn as well;
    // both ends pin ownership where it is required).
    // SAFETY: sigaction install of SIG_DFL on SIGCHLD only
    // (async-signal-safe).
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut dfl.sa_mask);
        dfl.sa_flags = 0;
        if libc::sigaction(libc::SIGCHLD, &dfl, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if let Some(soft) = child_soft_limit {
        // SAFETY: getrlimit/setrlimit by value on stack memory only.
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        lim.rlim_cur = soft as libc::rlim_t;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
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
/// null stdin (attest). `child_soft_limit` lowers the child's own
/// `RLIMIT_NOFILE` soft ceiling (tests only; production passes
/// `None` — see [`confine_child`]). Callers pass the fixed flag
/// vocabulary only; `--metadata FILE` carries a launcher-CLI-selected
/// path (never helper- or file-selected): the helper takes no
/// executable paths and the launcher takes no metadata content.
/// Establishes waitable-child ownership BEFORE spawning (see
/// [`ensure_waitable_sigchld`]).
fn spawn_confined(
    pinned: &std::fs::File,
    arg0: &Path,
    args: &[String],
    stdin_mode: Stdio,
    child_soft_limit: Option<u64>,
) -> std::io::Result<std::process::Child> {
    // Ownership BEFORE spawning: normalize an inherited auto-reaping
    // SIGCHLD disposition so this child is always waitable — the
    // zombie anchors every kill path. A failed normalization refuses
    // BEFORE any child exists (callers map the error to a typed
    // refusal): an unwaitable child would leave every kill path
    // aiming at plain numbers.
    ensure_waitable_sigchld()?;
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
        command.pre_exec(move || confine_child(fd, child_soft_limit));
    }
    let child = command.spawn()?;
    // Claim the child's process group from the parent side too (the
    // child claims it in `pre_exec`; either may win — see
    // `confine_child`). Errors ignored: `EACCES` means the child
    // already `exec`'d (its claim ran); `ESRCH` means it already
    // exited (no descendant is possible without a prior `exec`,
    // which implies the child's claim ran).
    // SAFETY: setpgid on a direct child pid, no pointers.
    unsafe {
        libc::setpgid(child.id() as libc::pid_t, child.id() as libc::pid_t);
    }
    Ok(child)
}

/// One bounded stdin write: the pipe plus the bytes still to send.
/// Dropped (EOF to the child) once everything is written — or on any
/// write error (a broken pipe means the child died early; the exit
/// status classifies it, exactly as before).
struct StdinJob {
    pipe: std::process::ChildStdin,
    bytes: Vec<u8>,
    written: usize,
}

/// Bounded-drain outcome (no exit codes escape: callers map these to
/// typed unavailability with static detail, exactly as before).
#[derive(Debug)]
enum DrainOutcome {
    /// Reaped exit status plus both drained pipes.
    Done {
        status: std::process::ExitStatus,
        out: Vec<u8>,
        err: Vec<u8>,
    },
    /// Stdout exceeded its cap (child killed and reaped).
    OverCapStdout,
    /// Stderr exceeded its cap (child killed and reaped).
    OverCapStderr,
    /// The deadline lapsed (child killed and reaped, retryable).
    Stalled,
    /// The wait itself failed (child killed and reaped, retryable).
    WaitFailed,
    /// A pipe read failed (child killed and reaped, deterministic).
    ReadFailed,
    /// Cleanup could not finish by the deadline: ownership unproven,
    /// the child possibly still alive — nothing signaled, nothing
    /// reaped (unknown liveness; a deterministic refusal, never a
    /// transport retry — see the `serve_once` mapping).
    CleanupIncomplete,
}

/// Require waitable children (parent side): an inherited
/// `SIGCHLD=SIG_IGN` survives `exec`, and while it (or
/// `SA_NOCLDWAIT`) is set every exiting child auto-reaps — no zombie
/// survives to anchor the kill paths, and `waitid` reports `ECHILD`
/// on plain numbers PID/PGID reuse can reassign. Reset exactly the
/// auto-reaping configurations to plain `SIG_DFL` before spawning;
/// any other disposition (including a handler without `NOCLDWAIT`)
/// is already waitable and stays untouched. Permanent by design: the
/// disposition at child-exit time governs auto-reap, so restoring
/// `SIG_IGN` before the reap would lose ownership again. `SIG_DFL`
/// for `SIGCHLD` discards the signal yet keeps the zombie waitable.
/// Returns `Err` when the install fails (e.g. a seccomp
/// `SECCOMP_RET_ERRNO` filter failing the syscall): the caller
/// refuses to spawn, since a child spawned under a still-auto-reaping
/// disposition would be unwaitable.
fn ensure_waitable_sigchld() -> std::io::Result<()> {
    // SAFETY: sigaction query only.
    let needs_install = unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current) != 0
            || current.sa_sigaction == libc::SIG_IGN
            || (current.sa_flags & libc::SA_NOCLDWAIT) != 0
    };
    if !needs_install {
        return Ok(());
    }
    install_waitable_sigchld()
}

/// Install plain `SIG_DFL` for `SIGCHLD` ([`ensure_waitable_sigchld`]
/// decided it is needed). The install result is authoritative: `Err`
/// (with the install `errno`) refuses the spawn.
fn install_waitable_sigchld() -> std::io::Result<()> {
    if sigchld_install_fault_injected() {
        // Simulated `SECCOMP_RET_ERRNO`-style install failure (see
        // the seam below): the refusal path below is production code.
        return Err(std::io::Error::from_raw_os_error(libc::EACCES));
    }
    // SAFETY: sigaction install of plain SIG_DFL on SIGCHLD.
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut dfl.sa_mask);
        dfl.sa_flags = 0;
        if libc::sigaction(libc::SIGCHLD, &dfl, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Test-only fault injection for [`install_waitable_sigchld`]: a real
/// install with valid arguments fails only under adversarial
/// conditions (e.g. a seccomp `SECCOMP_RET_ERRNO` filter), which no
/// test can arrange without harming the production syscall shape —
/// so the test build reads one opt-in variable at the install call
/// site and the production build hard-codes `false` (no environment
/// read, identical syscall sequence). The seam injects AT the
/// syscall boundary; the error return and the refuse-before-spawn
/// propagation it exercises are production code.
#[cfg(test)]
fn sigchld_install_fault_injected() -> bool {
    std::env::var_os("KRYPROBE_LAUNCH_FAIL_SIGCHLD_INSTALL").is_some_and(|v| v == "1")
}

/// Production build: fault injection is absent (see above).
#[cfg(not(test))]
fn sigchld_install_fault_injected() -> bool {
    false
}

/// Whether the child is still waitable (owned): raw `waitid` with
/// `WNOWAIT` never reaps, so only an already-reaped child reports
/// `ECHILD` — ownership lost (an external reap; inherited auto-reap
/// cannot happen once [`spawn_confined`] normalizes the
/// disposition), after which its pid/pgid are plain numbers reuse
/// can reassign. Success (running or zombie) keeps ownership;
/// interruptions retry to a verdict; `ECHILD`, `ESRCH`, and EVERY
/// other errno fail closed (no signals): ownership is lost or —
/// worse — unproven, and an unproven pid/pgid may already name
/// strangers. Interruptions retry only within `deadline`; sustained
/// past it, they fail closed to unowned (see
/// [`converge_ownership`]).
fn child_still_waitable(child: &std::process::Child, deadline: Instant) -> bool {
    converge_ownership(|| probe_child_once(child.id()), deadline)
}

/// Meaning of one failed ownership probe: interruptions carry no
/// verdict (retry); anything else is lost-or-unproven (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeFailure {
    /// Interrupted before any verdict — retry the probe.
    Interrupted,
    /// Ownership lost (reaped/gone) or unprovable — never signal.
    Unowned,
}

/// Classify one failed `waitid` ownership probe by `errno`:
/// `EINTR` retries; `ECHILD` (reaped) and `ESRCH` (gone) are
/// ownership loss; every other `errno` is ownership UNPROVEN — fail
/// closed. Pure (no syscalls) so the mapping itself is
/// unit-testable: real `waitid` on Linux reports non-children as
/// `ECHILD` (see `wait(2)`), so `ESRCH`/other errnos are not
/// constructible through the syscall itself.
fn classify_probe_failure(errno: libc::c_int) -> ProbeFailure {
    if errno == libc::EINTR {
        ProbeFailure::Interrupted
    } else {
        ProbeFailure::Unowned
    }
}

/// One raw `waitid` ownership probe (never reaps): `Ok(())` while
/// the child is still ours (running or zombie); failures classified
/// by [`classify_probe_failure`].
fn probe_child_once(pid: u32) -> Result<(), ProbeFailure> {
    // SAFETY: zeroed siginfo out-param; `WNOHANG` leaves `si_pid`
    // zero when nothing exited; `WNOWAIT` never reaps.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid on a direct child pid; WNOWAIT never reaps.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if waited == 0 {
        return Ok(());
    }
    // `last_os_error` always carries a code on Unix; the fallback is
    // unreachable — and it fails closed (`ECHILD` is unowned).
    let errno = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ECHILD);
    Err(classify_probe_failure(errno))
}

/// Retry one-shot ownership probes through interruptions to a
/// verdict WITHIN `deadline`: only a clean probe proves ownership;
/// a lost-or-unproven verdict fails closed — and so do
/// interruptions sustained past the deadline (an unproven pid/pgid
/// may already name strangers, so no verdict is worth an unbounded
/// wait; the caller reaps without signaling instead).
fn converge_ownership(
    mut probe: impl FnMut() -> Result<(), ProbeFailure>,
    deadline: Instant,
) -> bool {
    loop {
        match probe() {
            Ok(()) => return true,
            Err(ProbeFailure::Interrupted) => {
                if Instant::now() >= deadline {
                    return false;
                }
            }
            Err(ProbeFailure::Unowned) => return false,
        }
    }
}

/// Kill the whole child process group and reap the direct child
/// (never a hang, never an orphan, never a lingering descendant).
/// The child is normally unreaped here (exit peeks never reap —
/// see [`peek_child_exited`]), so its pid is still valid and the
/// group it founded in [`confine_child`] holds only our own
/// descendants: precise membership, never our own group. After
/// ownership loss (`ECHILD`: already reaped) the pid/pgid are plain
/// numbers — this MUST NOT signal them (PID/PGID reuse could aim at
/// unrelated processes), so the ownership probe below downgrades to
/// reap-only. Callers must never call this after a reap they
/// performed themselves (every call site below is peek-only until
/// this runs); the probe is the backstop for reaps this code did not
/// perform. Cleanup runs within `deadline` and reports
/// [`CleanupOutcome`]: the owned path kills then reaps boundedly
/// (denied signals/reaps report `Incomplete`, never a false
/// `Complete`); the unowned path reaps without signaling only until
/// the deadline, then reports incomplete (unknown liveness) instead
/// of blocking past it.
fn kill_and_reap(child: &mut std::process::Child, deadline: Instant) -> CleanupOutcome {
    kill_and_reap_gated(child, child_still_waitable(child, deadline), deadline)
}

/// Kill path with a pre-converged ownership verdict: `false` (lost
/// OR unproven) NEVER signals — bounded reap-only (see
/// [`reap_unowned_bounded`]). The verdict parameter is the
/// canary-family seam: production always passes the real converged
/// probe; tests drive `false` verdicts derived from each classified
/// `errno` through this real gating code. Returns whether cleanup
/// finished by `deadline`.
fn kill_and_reap_gated(
    child: &mut std::process::Child,
    owned: bool,
    deadline: Instant,
) -> CleanupOutcome {
    // Ownership gate: after ownership loss the numeric pid/pgid may
    // already name strangers — NEVER signal them.
    if !owned {
        return reap_unowned_bounded(child, deadline);
    }
    // The group dies first (descendants), then the child, then the
    // bounded reap. Signal errors are not trusted: liveness (the
    // reap) determines the outcome — denied signals leave a live
    // child, which the bounded reap reports as `Incomplete` (never
    // a false `Complete`); a zombie still reaps promptly.
    // SAFETY: killpg on the unreaped child's own group id.
    unsafe {
        libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = child.kill();
    // Post-signal reap is bounded and honest like the unowned path
    // (no further signals; `ECHILD` completes, anything else holds
    // to the deadline, then `Incomplete`) — plus a minimal 1 s grace
    // when the attempt deadline already passed (the `Stalled` entry):
    // a just-`SIGKILL`ed child needs a moment to become reaped, and
    // zero grace would falsely report `Incomplete` for a prompt reap
    // (denied signals still end `Incomplete`, bounded by the grace).
    let reap_deadline = if Instant::now() >= deadline {
        Instant::now() + Duration::from_secs(1)
    } else {
        deadline
    };
    reap_unowned_bounded(child, reap_deadline)
}

/// Sleep up to 1 ms without outliving `deadline` and without
/// retrying interruptions internally: a SINGLE `nanosleep` attempt
/// that returns immediately on `EINTR` so the caller re-checks the
/// deadline. (`std::thread::sleep` retries interrupted `nanosleep`
/// without consulting `Instant`, so an `EINTR` that leaves the
/// remainder unchanged traps past the deadline — this helper never
/// traps: normal sleeps still take the 1 ms slice; interruptions
/// wake early into the caller's deadline check.)
fn sleep_slice(deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return;
    }
    let slice = remaining.min(Duration::from_millis(1));
    let req = libc::timespec {
        tv_sec: slice.as_secs() as libc::time_t,
        // `subsec_nanos` fits `c_long` (under 1e9); the cast is exact.
        tv_nsec: libc::c_long::from(slice.subsec_nanos()),
    };
    let mut rem: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `nanosleep` with valid `req`/`rem` pointers; the return
    // (including `EINTR`) is intentionally not retried here.
    unsafe {
        libc::nanosleep(&req, &mut rem);
    }
}

/// Whether bounded cleanup finished: the reap-only path reports
/// honestly instead of blocking past the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupOutcome {
    /// Nothing outstanding: reaped, or already reaped elsewhere.
    Complete,
    /// The deadline lapsed with the child possibly still alive —
    /// ownership unproven (nothing signaled) or signals/reaps denied
    /// (nothing proven delivered/reaped). Unknown liveness: a refusal
    /// state, never a transport retry, never reported as success.
    Incomplete,
}

/// Reap-only bounded cleanup for lost-or-unproven ownership: poll a
/// non-signaling reap until the child exits or `deadline` lapses.
/// Never signals (the pid may name strangers); never blocks past
/// the deadline. A zombie reaps promptly — still ours to reap:
/// `try_wait` aims at our own `Child` handle, never a bare number.
/// Only `ECHILD` (already reaped: provably nothing outstanding)
/// completes early; any other wait failure holds to the deadline
/// like a live child (a denied `wait` proves nothing about
/// liveness), then reports [`CleanupOutcome::Incomplete`].
fn reap_unowned_bounded(child: &mut std::process::Child, deadline: Instant) -> CleanupOutcome {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return CleanupOutcome::Complete,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return CleanupOutcome::Incomplete;
                }
                sleep_slice(deadline);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                if Instant::now() >= deadline {
                    return CleanupOutcome::Incomplete;
                }
            }
            Err(err) if err.raw_os_error() == Some(libc::ECHILD) => {
                return CleanupOutcome::Complete;
            }
            Err(_) => {
                if Instant::now() >= deadline {
                    return CleanupOutcome::Incomplete;
                }
                sleep_slice(deadline);
            }
        }
    }
}

/// Bounded cleanup mapped onto a disposition: `complete` stands when
/// cleanup finished by `deadline`; an incomplete cleanup (deadline
/// lapsed with ownership unproven — liveness unknown, nothing
/// signaled, nothing reaped) overrides it. Unknown liveness
/// dominates every co-occurring verdict: reporting a content
/// verdict — or a retryable stall — while a possibly-live child
/// escapes containment would overclaim what this attempt proved.
fn kill_and_reap_mapped(
    child: &mut std::process::Child,
    deadline: Instant,
    complete: DrainOutcome,
) -> DrainOutcome {
    match kill_and_reap(child, deadline) {
        CleanupOutcome::Complete => complete,
        CleanupOutcome::Incomplete => DrainOutcome::CleanupIncomplete,
    }
}

/// Peek whether one child exited WITHOUT reaping (raw `waitid`
/// with `WEXITED|WNOHANG|WNOWAIT` — `WNOWAIT` is honored by
/// `waitid` only; `waitpid` rejects it with `EINVAL`): the zombie
/// stays unreaped, so its pid — and hence its process group — is
/// still provably ours when a kill path fires. The peek is a pure
/// boolean gate; the caller reaps at disposition and takes the
/// authoritative status from the reap. `Err` on wait failure.
fn peek_child_exited(child: &std::process::Child) -> std::io::Result<bool> {
    // SAFETY: zeroed siginfo out-param; `waitid` with `WNOHANG`
    // leaves `si_pid` zero when nothing exited.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid on a direct child pid; WNOWAIT never reaps.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if waited < 0 {
        let err = std::io::Error::last_os_error();
        // Interrupted: report still-running; the sliced poll loop
        // re-peeks within milliseconds.
        if err.raw_os_error() == Some(libc::EINTR) {
            return Ok(false);
        }
        return Err(err);
    }
    // SAFETY: reading the union field `waitid` just filled (or
    // the zero it left untouched when nothing exited).
    Ok(unsafe { info.si_pid() } != 0)
}

/// Mark one parent-side pipe fd nonblocking.
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl F_GETFL/F_SETFL on a live owned fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// One pipe's drain step.
enum PipeOutcome {
    /// Drained until it would block; more may come.
    Open,
    /// Clean EOF.
    Eof,
    /// Over the cap (`cap + 1` probe idiom).
    OverCap,
    /// I/O failure.
    Failed,
}

/// Read one pipe until it would block, EOF, over-cap, or failure.
/// Interrupted reads yield to the outer `poll` loop (`Open`) instead
/// of retrying inline: the outer loop re-polls (retrying the read)
/// after its deadline check, so a sustained interruption ends in a
/// bounded `Stalled` instead of trapping here past the deadline.
fn drain_pipe(
    pipe: &mut impl std::io::Read,
    acc: &mut Vec<u8>,
    chunk: &mut [u8],
    cap: usize,
) -> PipeOutcome {
    loop {
        match pipe.read(chunk) {
            Ok(0) => return PipeOutcome::Eof,
            Ok(n) => {
                acc.extend_from_slice(&chunk[..n]);
                if acc.len() > cap {
                    return PipeOutcome::OverCap;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                return PipeOutcome::Open;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return PipeOutcome::Open,
            Err(_) => return PipeOutcome::Failed,
        }
    }
}

/// One stdin write step.
enum StdinOutcome {
    /// All bytes written, or a fatal write error (drop stdin: a
    /// broken pipe means the child died early — the exit status
    /// classifies it, exactly as before).
    Done,
    /// Still pending (would-block, zero write, or an interruption
    /// yielded to the outer loop for its deadline check).
    Pending,
}

/// Write stdin bytes until done, would-block, or yield. Interrupted
/// writes yield to the outer `poll` loop (`Pending`) instead of
/// retrying inline: the outer loop re-polls (retrying the write)
/// after its deadline check, so a sustained interruption ends in a
/// bounded `Stalled` instead of trapping here past the deadline.
fn write_stdin_chunk(
    pipe: &mut impl std::io::Write,
    bytes: &[u8],
    written: &mut usize,
) -> StdinOutcome {
    while *written < bytes.len() {
        match pipe.write(&bytes[*written..]) {
            Ok(0) => return StdinOutcome::Pending,
            Ok(n) => *written += n,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return StdinOutcome::Pending;
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                return StdinOutcome::Pending;
            }
            Err(_) => return StdinOutcome::Done,
        }
    }
    StdinOutcome::Done
}

/// Drain one attempt under ONE overall deadline: stdin writes plus
/// concurrent stdout/stderr reads plus reap in a single `poll` loop.
/// No wait-before-drain stall (a legal response larger than the pipe
/// streams through while the child still runs) and no unbounded EOF
/// read (a descendant retaining a pipe cannot outlive the deadline:
/// every kill path SIGKILLs the child's process group, then reaps
/// the direct child). Status peeks never reap, so the zombie anchors
/// the group until disposition. Done requires the reaped status AND
/// both EOFs AND a finished stdin write; anything else ends by cap
/// or by deadline.
#[allow(clippy::too_many_arguments)]
fn drain_bounded(
    child: &mut std::process::Child,
    stdout: &mut std::process::ChildStdout,
    stderr: &mut std::process::ChildStderr,
    stdin: Option<StdinJob>,
    stdout_cap: usize,
    stderr_cap: usize,
    deadline: Instant,
) -> DrainOutcome {
    if set_nonblocking(stdout.as_raw_fd()).is_err()
        || set_nonblocking(stderr.as_raw_fd()).is_err()
        || stdin
            .as_ref()
            .is_some_and(|job| set_nonblocking(job.pipe.as_raw_fd()).is_err())
    {
        return kill_and_reap_mapped(child, deadline, DrainOutcome::WaitFailed);
    }
    let mut stdin = stdin;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    let mut exited = false;
    let mut chunk = [0u8; 8192];
    loop {
        if !exited {
            match peek_child_exited(child) {
                Ok(done) => exited = done,
                Err(_) => {
                    return kill_and_reap_mapped(child, deadline, DrainOutcome::WaitFailed);
                }
            }
        }
        if out_eof && err_eof && stdin.is_none() && exited {
            // Reap at disposition: the peek left a zombie (which
            // anchored the group until now). The reap is bounded to
            // the attempt deadline — `Child::wait` retries `EINTR`
            // forever, so a sustained interruption would hang here
            // even though the child is already dead. A zombie still
            // reaps promptly (`try_wait` succeeds immediately).
            let reaped = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            break None;
                        }
                        sleep_slice(deadline);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                        if Instant::now() >= deadline {
                            break None;
                        }
                    }
                    Err(err) if err.raw_os_error() == Some(libc::ECHILD) => {
                        // Already reaped elsewhere: no status to take —
                        // fail the reap immediately (cleanup below sees
                        // `ECHILD` and completes, so `WaitFailed` stands).
                        break None;
                    }
                    Err(_) => {
                        if Instant::now() >= deadline {
                            break None;
                        }
                        sleep_slice(deadline);
                    }
                }
            };
            let Some(reaped) = reaped else {
                return kill_and_reap_mapped(child, deadline, DrainOutcome::WaitFailed);
            };
            return DrainOutcome::Done {
                status: reaped,
                out,
                err,
            };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return kill_and_reap_mapped(child, deadline, DrainOutcome::Stalled);
        }
        // Poll what is still live (readers until EOF, stdin until
        // written); an empty set sleeps until the deadline.
        let idle = libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        };
        let mut watched = [idle, idle, idle];
        let mut live: usize = 0;
        let mut stdout_slot = None;
        let mut stderr_slot = None;
        let mut stdin_slot = None;
        if !out_eof {
            watched[live] = libc::pollfd {
                fd: stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            stdout_slot = Some(live);
            live += 1;
        }
        if !err_eof {
            watched[live] = libc::pollfd {
                fd: stderr.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            stderr_slot = Some(live);
            live += 1;
        }
        if let Some(job) = stdin.as_ref() {
            watched[live] = libc::pollfd {
                fd: job.pipe.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            stdin_slot = Some(live);
            live += 1;
        }
        // Slice the sleep: EOFs can precede the zombie state by a
        // scheduling window (pipes close during exit, the status
        // lands after), leaving an empty poll set while the child
        // is still alive — and an empty `poll` restarted by SIGCHLD
        // sleeps through to its timeout instead of reporting EINTR.
        // Ten-millisecond slices keep reap latency negligible while
        // the deadline still bounds the total.
        let slice = remaining.min(Duration::from_millis(10));
        let timeout_ms = i32::try_from(slice.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: poll over live stack fds only (`live` entries).
        let ready = unsafe { libc::poll(watched.as_mut_ptr(), live as libc::nfds_t, timeout_ms) };
        if ready < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return kill_and_reap_mapped(child, deadline, DrainOutcome::WaitFailed);
        }
        if stdin_slot.is_some_and(|slot| watched[slot].revents != 0)
            && let Some(job) = stdin.as_mut()
        {
            // Interruptions yield (`Pending`) so the next loop
            // iteration re-checks the deadline before retrying.
            if matches!(
                write_stdin_chunk(&mut job.pipe, &job.bytes, &mut job.written),
                StdinOutcome::Done
            ) {
                stdin = None;
            }
        }
        if stdout_slot.is_some_and(|slot| watched[slot].revents != 0) {
            match drain_pipe(stdout, &mut out, &mut chunk, stdout_cap) {
                PipeOutcome::Open => {}
                PipeOutcome::Eof => out_eof = true,
                PipeOutcome::OverCap => {
                    return kill_and_reap_mapped(child, deadline, DrainOutcome::OverCapStdout);
                }
                PipeOutcome::Failed => {
                    return kill_and_reap_mapped(child, deadline, DrainOutcome::ReadFailed);
                }
            }
        }
        if stderr_slot.is_some_and(|slot| watched[slot].revents != 0) {
            match drain_pipe(stderr, &mut err, &mut chunk, stderr_cap) {
                PipeOutcome::Open => {}
                PipeOutcome::Eof => err_eof = true,
                PipeOutcome::OverCap => {
                    return kill_and_reap_mapped(child, deadline, DrainOutcome::OverCapStderr);
                }
                PipeOutcome::Failed => {
                    return kill_and_reap_mapped(child, deadline, DrainOutcome::ReadFailed);
                }
            }
        }
    }
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
    let start = Instant::now();
    let mut child = spawn_confined(&image, &pinned.path, &args, Stdio::null(), None)
        .map_err(|_| MetadataUnavailable::HelperRefused)?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let deadline = start + bound;
    let (status, out) = match drain_bounded(
        &mut child,
        &mut stdout,
        &mut stderr,
        None,
        ATTEST_STDOUT_CAP,
        STDERR_DRAIN_CAP,
        deadline,
    ) {
        DrainOutcome::Done { status, out, .. } => (status, out),
        DrainOutcome::OverCapStdout => return Err(MetadataUnavailable::BudgetExceeded),
        DrainOutcome::OverCapStderr
        | DrainOutcome::Stalled
        | DrainOutcome::WaitFailed
        | DrainOutcome::ReadFailed
        | DrainOutcome::CleanupIncomplete => return Err(MetadataUnavailable::HelperRefused),
    };
    if !status.success() {
        return Err(MetadataUnavailable::HelperRefused);
    }
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
    /// Bound, verified response plus this serve's typed helper
    /// diagnostics (`None` when unavailable — never a refusal).
    /// Boxed: the served value dwarfs the other variants.
    Answered(Box<ServedSnapshot>),
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
    serve_pinned_snapshot_with_diagnostics(pinned, principal, metadata, request, bound)
        .map(|served| served.response)
}

/// [`serve_pinned_snapshot_with_bound`] returning the typed helper
/// diagnostics alongside the bound response: the same bound/retry
/// machinery (retries, pinning, cleanup, IO bounds unchanged) —
/// diagnostics ride the answered outcome and never fail it.
pub fn serve_pinned_snapshot_with_diagnostics(
    pinned: &PinnedHelper,
    principal: &Principal,
    metadata: Option<&Path>,
    request: &SnapshotRequest,
    bound: Duration,
) -> Result<ServedSnapshot, MetadataUnavailable> {
    let mut attempts = 0u32;
    loop {
        match serve_once(pinned, principal, metadata, request, bound) {
            AttemptOutcome::Answered(served) => return Ok(*served),
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
    let start = Instant::now();
    let mut child = match spawn_confined(&image, &pinned.path, &args, Stdio::piped(), None) {
        Ok(child) => child,
        Err(_) => return AttemptOutcome::Refused(MetadataUnavailable::HelperRefused),
    };
    // One overall deadline covers spawn, the stdin write, both
    // concurrent reads, and the reap — no wait-before-drain stall,
    // no unbounded EOF read.
    let stdin = child.stdin.take().map(|pipe| StdinJob {
        pipe,
        bytes: request_bytes,
        written: 0,
    });
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let deadline = start + bound;
    let (status, out, err) = match drain_bounded(
        &mut child,
        &mut stdout,
        &mut stderr,
        stdin,
        MAX_SNAPSHOT_RESPONSE_BYTES,
        STDERR_DRAIN_CAP,
        deadline,
    ) {
        DrainOutcome::Done { status, out, err } => (status, out, err),
        DrainOutcome::OverCapStdout | DrainOutcome::OverCapStderr => {
            return AttemptOutcome::Refused(MetadataUnavailable::BudgetExceeded);
        }
        DrainOutcome::Stalled | DrainOutcome::WaitFailed => {
            return AttemptOutcome::TransportFailed;
        }
        // Cleanup-incomplete is a deterministic refusal, never a
        // transport retry: the frozen `MetadataUnavailable` taxonomy
        // (ADR-0008) has no cleanup-incomplete variant — adding one
        // would be a contract edit — and `HelperRefused` is the
        // established typed refusal for a failed helper boundary.
        // Deterministic (not retried) because a denied ownership
        // probe is environmental, and retrying would stack
        // unknown-liveness children — each attempt's escapee
        // outliving its bound.
        DrainOutcome::ReadFailed | DrainOutcome::CleanupIncomplete => {
            return AttemptOutcome::Refused(MetadataUnavailable::HelperRefused);
        }
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
            // The typed diagnostics ride the verified answer: a
            // missing or malformed record marks diagnostics
            // unavailable (`None`) without touching the response.
            Ok(()) => AttemptOutcome::Answered(Box::new(ServedSnapshot {
                response,
                diagnostics: parse_helper_diagnostics(&stderr_text),
            })),
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

    /// Golden full-field counters object (the honest helper shape:
    /// every approved field present, `denied=1`/`migration_skipped=1`
    /// measured, saturation clear).
    fn full_counters_value() -> serde_json::Value {
        serde_json::json!({
            "positive_hits": 0, "positive_misses": 1, "negative_hits": 0,
            "inserts": 0, "insert_refused_full": 0,
            "negative_inserts": 0, "negative_refused_full": 0,
            "tombstone_inserts": 0, "tombstone_refused_full": 0,
            "expired_evictions": 0, "reuse_detected": 0,
            "refresh_throttled": 0, "deadline_trips": 0,
            "scan_budget_trips": 0, "symlink_refused": 0,
            "denied": 1, "not_host_path": 0, "gone_during_scan": 0,
            "migration_skipped": 1, "pid_lifetime_refused_full": 0,
            "saturated": false,
        })
    }

    /// One stderr diagnostics record over `counters`.
    fn diagnostics_line(counters: &serde_json::Value) -> String {
        format!(r#"{{"helper_counters":{counters}}}"#)
    }

    #[test]
    fn diagnostics_valid_full_record_parses() {
        let line = diagnostics_line(&full_counters_value());
        let stderr = format!("{}\n{line}\n", attestation_line(1000, "0", true, "0,1,2"));
        let parsed = parse_helper_diagnostics(&stderr).expect("parses");
        assert_eq!(
            parsed,
            HelperDiagnostics {
                positive_misses: 1,
                denied: 1,
                migration_skipped: 1,
                ..HelperDiagnostics::new()
            }
        );
        // A saturated honest record keeps its marker.
        let mut counters = full_counters_value();
        counters["saturated"] = serde_json::json!(true);
        counters["denied"] = serde_json::json!(18446744073709551615u64);
        let parsed = parse_helper_diagnostics(&diagnostics_line(&counters)).expect("parses");
        assert!(parsed.saturated);
        assert_eq!(parsed.denied, u64::MAX);
        // Byte-exact emission captured from the real helper (exit 0,
        // kernel-mismatch short-circuit, alphabetical key order):
        // every counter genuinely zero — a well-formed record still
        // parses to `Some` (absence is `None`; all-zero measured is
        // data, never confused with unavailable).
        let real = r#"{"helper_counters":{"deadline_trips":0,"denied":0,"expired_evictions":0,"gone_during_scan":0,"insert_refused_full":0,"inserts":0,"migration_skipped":0,"negative_hits":0,"negative_inserts":0,"negative_refused_full":0,"not_host_path":0,"pid_lifetime_refused_full":0,"positive_hits":0,"positive_misses":0,"refresh_throttled":0,"reuse_detected":0,"saturated":false,"scan_budget_trips":0,"symlink_refused":0,"tombstone_inserts":0,"tombstone_refused_full":0}}"#;
        assert_eq!(
            parse_helper_diagnostics(real),
            Some(HelperDiagnostics::new())
        );
    }

    #[test]
    fn diagnostics_absent_is_unavailable() {
        // Attestation and error lines are not diagnostics records.
        for stderr in [
            attestation_line(1000, "0", true, "0,1,2"),
            format!(
                "{}\n{}\n",
                attestation_line(1000, "0", true, "0,1,2"),
                r#"{"error":"helper_refused"}"#,
            ),
            String::new(),
            "not json\n".to_string(),
            diagnostics_line(&serde_json::json!({})),
        ] {
            assert_eq!(
                parse_helper_diagnostics(&stderr),
                None,
                "no well-formed record: {stderr:?}"
            );
        }
    }

    #[test]
    fn diagnostics_duplicate_records_refuse() {
        let line = diagnostics_line(&full_counters_value());
        // Two records — even two identical honest ones — are not
        // exactly one measurement.
        assert_eq!(parse_helper_diagnostics(&format!("{line}\n{line}\n")), None);
    }

    #[test]
    fn diagnostics_valid_plus_truncated_refuses_both_orders() {
        // P2 (wave-e): a truncated counters emission is still a
        // counters emission — valid + truncated in either order is
        // ambiguous input, never a measurement.
        let valid = diagnostics_line(&full_counters_value());
        let truncated = r#"{"helper_counters":{"#;
        for stderr in [
            format!("{valid}\n{truncated}\n"),
            format!("{truncated}\n{valid}\n"),
        ] {
            assert_eq!(
                parse_helper_diagnostics(&stderr),
                None,
                "valid+truncated refuses: {stderr:?}"
            );
        }
        // A lone truncated emission is not a measurement either.
        assert_eq!(parse_helper_diagnostics(truncated), None);
    }

    #[test]
    fn diagnostics_valid_plus_escaped_refuses_both_orders() {
        // P2 (wave-f): a JSON-escaped envelope spelling
        // (`hel\u0070er_counters` decodes to `helper_counters`) is
        // still a counters emission under the decoded-key rule —
        // valid + escaped in either order refuses.
        let valid = diagnostics_line(&full_counters_value());
        let escaped = format!(r#"{{"hel\u0070er_counters":{}}}"#, full_counters_value());
        assert!(
            !escaped.contains("helper_counters"),
            "fixture evades the literal marker"
        );
        for stderr in [
            format!("{valid}\n{escaped}\n"),
            format!("{escaped}\n{valid}\n"),
        ] {
            assert_eq!(
                parse_helper_diagnostics(&stderr),
                None,
                "valid+escaped refuses: {stderr:?}"
            );
        }
    }

    #[test]
    fn diagnostics_valid_plus_escaped_bad_refuses_both_orders() {
        // P2 (wave-f): the escaped second emission poisons even when
        // its own counters are malformed — any candidate failing
        // strict parse voids the result to `None`.
        let valid = diagnostics_line(&full_counters_value());
        let escaped_bad = r#"{"hel\u0070er_counters":{"denied":1}}"#;
        assert!(
            !escaped_bad.contains("helper_counters"),
            "fixture evades the literal marker"
        );
        for stderr in [
            format!("{valid}\n{escaped_bad}\n"),
            format!("{escaped_bad}\n{valid}\n"),
        ] {
            assert_eq!(
                parse_helper_diagnostics(&stderr),
                None,
                "valid+escaped-bad refuses: {stderr:?}"
            );
        }
        // A lone escaped malformed emission is not a measurement.
        assert_eq!(parse_helper_diagnostics(escaped_bad), None);
    }

    #[test]
    fn diagnostics_duplicate_keys_refuse() {
        let line = diagnostics_line(&full_counters_value());
        // A repeated counter key (last-wins would silently pick 2).
        let dup = line.replacen(r#""denied":1"#, r#""denied":1,"denied":2"#, 1);
        assert_ne!(dup, line, "fixture carries the replaced key");
        assert_eq!(parse_helper_diagnostics(&dup), None);
        // An escaped spelling of the repeated key still collides.
        let escaped = line.replacen(r#""denied":1"#, r#""denied":1,"\u0064denied":2"#, 1);
        assert_ne!(escaped, line, "fixture carries the replaced key");
        assert_eq!(parse_helper_diagnostics(&escaped), None);
        // A repeated envelope key refuses too.
        let envelope = format!(
            r#"{{"helper_counters":{c},"helper_counters":{c}}}"#,
            c = full_counters_value()
        );
        assert_eq!(parse_helper_diagnostics(&envelope), None);
    }

    #[test]
    fn diagnostics_unknown_or_missing_counters_refuse() {
        let line = diagnostics_line(&full_counters_value());
        // An unknown counter is not an approved field.
        let unknown = line.replacen(r#""saturated":false"#, r#""saturated":false,"evil":1"#, 1);
        assert_ne!(unknown, line, "fixture carries the replaced key");
        assert_eq!(parse_helper_diagnostics(&unknown), None);
        // A missing counter is not a complete measurement.
        let missing = line.replacen(r#""denied":1,"#, "", 1);
        assert_ne!(missing, line, "fixture carries the replaced key");
        assert_eq!(parse_helper_diagnostics(&missing), None);
        // An unknown envelope field refuses.
        let envelope = format!(
            r#"{{"helper_counters":{c},"x":1}}"#,
            c = full_counters_value()
        );
        assert_eq!(parse_helper_diagnostics(&envelope), None);
    }

    #[test]
    fn diagnostics_mistyped_counters_refuse() {
        let line = diagnostics_line(&full_counters_value());
        for bad in [
            line.replacen(r#""denied":1"#, r#""denied":true"#, 1),
            line.replacen(r#""denied":1"#, r#""denied":1.5"#, 1),
            line.replacen(r#""denied":1"#, r#""denied":"1""#, 1),
            line.replacen(r#""denied":1"#, r#""denied":-1"#, 1),
            line.replacen(r#""denied":1"#, r#""denied":null"#, 1),
            line.replacen(r#""saturated":false"#, r#""saturated":0"#, 1),
            line.replacen(r#""saturated":false"#, r#""saturated":"no""#, 1),
        ] {
            assert_ne!(bad, line, "fixture carries the replaced key");
            assert_eq!(parse_helper_diagnostics(&bad), None, "line: {bad}");
        }
        // A non-object counters value refuses.
        for counters in [
            serde_json::json!([]),
            serde_json::json!("x"),
            serde_json::json!(7),
            serde_json::Value::Null,
        ] {
            assert_eq!(
                parse_helper_diagnostics(&diagnostics_line(&counters)),
                None,
                "counters: {counters}"
            );
        }
    }

    #[test]
    fn diagnostics_oversized_record_refuses() {
        let line = diagnostics_line(&full_counters_value());
        assert!(
            line.len() < MAX_HELPER_DIAGNOSTICS_BYTES,
            "honest record fits the cap: {} bytes",
            line.len()
        );
        let padded = format!("{}{line}", " ".repeat(MAX_HELPER_DIAGNOSTICS_BYTES));
        assert_eq!(parse_helper_diagnostics(&padded), None);
        // Small padding still parses (JSON whitespace, under cap).
        assert!(
            parse_helper_diagnostics(&format!("  {line}  ")).is_some(),
            "whitespace-padded record parses"
        );
    }

    #[test]
    fn diagnostics_forged_strings_never_parse() {
        // A forged private path smuggled as a counter value or an
        // unknown field is not a measurement — and the typed
        // boundary returns absence, never the string.
        let line = diagnostics_line(&full_counters_value());
        let forged_value = line.replacen(
            r#""denied":1"#,
            r#""denied":"/proc/self/root/etc/shadow""#,
            1,
        );
        assert_eq!(parse_helper_diagnostics(&forged_value), None);
        let forged_field = line.replacen(
            r#""saturated":false"#,
            r#""saturated":false,"path":"/proc/self/root/etc/shadow""#,
            1,
        );
        assert_eq!(parse_helper_diagnostics(&forged_field), None);
    }

    #[test]
    fn diagnostics_accumulate_sums_and_saturates() {
        let mut acc = HelperDiagnostics::new();
        // Zero is the aggregation identity.
        acc.accumulate(&HelperDiagnostics::new());
        assert_eq!(acc, HelperDiagnostics::new());
        let mut chunk = HelperDiagnostics::new();
        chunk.denied = 1;
        chunk.migration_skipped = 2;
        acc.accumulate(&chunk);
        acc.accumulate(&chunk);
        assert_eq!(acc.denied, 2);
        assert_eq!(acc.migration_skipped, 4);
        assert_eq!(acc.positive_hits, 0);
        assert!(!acc.saturated);
        // Either side's saturation sticks.
        chunk.saturated = true;
        acc.accumulate(&chunk);
        assert!(acc.saturated);
        // Count overflow saturates with the explicit marker instead
        // of wrapping — never a small wrong sum.
        let mut full = HelperDiagnostics::new();
        full.denied = u64::MAX;
        let mut one = HelperDiagnostics::new();
        one.denied = 1;
        full.accumulate(&one);
        assert_eq!(full.denied, u64::MAX);
        assert!(full.saturated);
        assert_eq!(full.migration_skipped, 0);
    }

    /// Built fixture binary:
    /// `<target>/debug/examples/kryprobe_launch_fixture` next to the
    /// test executable's `deps` dir. The fixture is a Cargo *example*
    /// (test-only by construction: default `cargo build` never
    /// produces it, default `cargo install` never ships it —
    /// explicit selection (`--example`/`--examples`/`--all-targets`)
    /// can also build it). Every all-target `cargo test`
    /// builds it (including the `xtask check` gate); focused
    /// `--lib`/`--test` runs must build it first (`cargo build -p
    /// kryprobe-privilege --example kryprobe_launch_fixture`) — the
    /// assert says so loudly.
    fn fixture_binary_path() -> PathBuf {
        let test_exe = std::env::current_exe().expect("test exe");
        let bin = test_exe
            .parent()
            .expect("deps dir")
            .parent()
            .expect("profile dir")
            .join("examples")
            .join("kryprobe_launch_fixture");
        assert!(
            bin.is_file(),
            "fixture binary built at {} (run all-target `cargo test -p kryprobe-privilege`)",
            bin.display()
        );
        // Layout pin: the Cargo test-only gate IS this directory — a
        // fixture resolving anywhere else (e.g. back in the profile
        // dir as a `src/bin` target) would ship with normal builds.
        assert_eq!(
            bin.parent().and_then(|dir| dir.file_name()),
            Some(std::ffi::OsStr::new("examples")),
            "fixture resolves from Cargo examples (test-only)"
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

    /// Flip the trailing bytes of a staged image in place: same
    /// device, inode, owner, mode, and size — only the content
    /// changes. The window sits in trailing debug/symbol bytes, so
    /// the image still executes (the oracle's fresh-pin control
    /// proves it — a flip that broke execution would fail loudly
    /// there, never pass vacuously here).
    fn rewrite_image_tail_in_place(path: &Path) {
        use std::io::{Seek, SeekFrom, Write};
        const FLIP: usize = 256;
        let len = std::fs::metadata(path).expect("image stat").len();
        assert!(len > 512, "image dwarfs the flip window");
        let mut image = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("image opens for rewrite");
        image
            .seek(SeekFrom::Start(len - FLIP as u64))
            .expect("seeks");
        image.write_all(&[0x5Au8; FLIP]).expect("tail flips");
        image.flush().expect("rewrite lands");
    }

    /// A1 oracle (Codex C2): an equal-length in-place rewrite of a
    /// writable image refuses. Every stat field (device, inode,
    /// owner, mode, size) is UNCHANGED by the rewrite — asserted
    /// below — so only the content pin can refuse it.
    /// (RED pre-fix: the tampered image serves `Ok`.)
    #[test]
    fn in_place_rewrite_of_writable_image_refuses() {
        let scratch = kryprobe_testkit::TempDir::named("launch-rewrite").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let helper_path = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json"}),
        );
        let principal = current_principal().expect("test principal");
        assert_ne!(principal.uid, 0, "tests run non-root");
        let pinned = pin_helper(&helper_path).expect("pins");
        let before = std::fs::metadata(&helper_path).expect("stat");
        rewrite_image_tail_in_place(&helper_path);
        let after = std::fs::metadata(&helper_path).expect("stat");
        assert_eq!(before.len(), after.len(), "rewrite keeps the size");
        assert_eq!(before.mode(), after.mode(), "rewrite keeps the mode");
        assert_eq!(before.uid(), after.uid(), "rewrite keeps the owner");
        assert_eq!(before.gid(), after.gid(), "rewrite keeps the group");
        assert_eq!(
            serve_pinned_snapshot_with_bound(
                &pinned,
                &principal,
                None,
                &request,
                Duration::from_secs(10)
            ),
            Err(MetadataUnavailable::HelperRefused),
            "in-place rewrite refuses"
        );
        // Positive control: the rewritten image still runs and
        // serves under a FRESH pin — the refusal above is the pin,
        // not a broken binary.
        let repinned = pin_helper(&helper_path).expect("rewritten image re-pins");
        assert!(
            serve_pinned_snapshot_with_bound(
                &repinned,
                &principal,
                None,
                &request,
                Duration::from_secs(10)
            )
            .is_ok(),
            "rewritten image serves under a fresh pin"
        );
    }

    /// A1 trust oracle (Codex C2): a group/other-writable image is
    /// not a trusted image — pinning refuses. Owner-writable 0755
    /// (dev layout) and root-owned 0755 (installed layout) pin fine;
    /// writability that ANOTHER principal could use never does.
    /// (RED pre-fix: the writable image pins.)
    #[test]
    fn writable_helper_image_refuses_to_pin() {
        let scratch = kryprobe_testkit::TempDir::named("launch-trust").expect("scratch");
        let trusted = stage_fixture(scratch.path(), "trusted", serde_json::json!({}));
        assert!(pin_helper(&trusted).is_ok(), "0755 self-owned pins");
        // The installed layout pins too: root-owned 0755 while this
        // process runs non-root (owner differs from euid).
        assert_ne!(
            current_principal().expect("test principal").uid,
            0,
            "tests run non-root"
        );
        let _installed_shape = pinnable_ls();
        for (name, mode) in [("group-writable", 0o775), ("other-writable", 0o776)] {
            let path = stage_fixture(scratch.path(), name, serde_json::json!({}));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(
                pin_helper(&path),
                Err(MetadataUnavailable::HelperRefused),
                "mode {mode:o} refuses to pin"
            );
        }
    }

    /// Executable-identity characterization (Codex C2): the kernel
    /// resolves the executed file from the open file description —
    /// `/proc/pid/exe` names the REAL image even when `argv[0]` is a
    /// forged label naming a nonexistent file. The launcher verifies
    /// the image, never the label. (Green throughout: pins the
    /// as-built property for Stage 4.)
    #[test]
    fn executed_identity_compares_by_exe_not_argv0() {
        let scratch = kryprobe_testkit::TempDir::named("launch-exe-label").expect("scratch");
        let sidecar = serde_json::json!({"stall_secs": 30});
        let helper = stage_fixture(scratch.path(), "helper", sidecar.clone());
        // The fixture locates its sidecar from `argv[0]` (test
        // isolation), so the forged label gets its own sidecar copy;
        // the label file itself never exists.
        std::fs::write(
            scratch.path().join("evil-label.fixture.json"),
            serde_json::to_string(&sidecar).expect("sidecar"),
        )
        .expect("label sidecar written");
        let forged = scratch.path().join("evil-label");
        assert!(!forged.exists(), "the label names no file");
        let pinned = pin_helper(&helper).expect("pins");
        let image = pinned.reopen().expect("reopens");
        // Serve path with a held stdin: the child blocks reading its
        // request (30 s stall backstop), so the parent reads the exe
        // link at leisure — no race with a fast exit.
        let mut child = spawn_confined(
            &image,
            &forged,
            &["--require-no-new-privs".to_string()],
            Stdio::piped(),
            None,
        )
        .expect("spawns");
        // Wait for the exec first: pre-exec the link still names
        // this test binary (fork/exec is async). The wait keys on
        // "no longer us", never on the expected value — the
        // assertions below then pin the property.
        let me = std::env::current_exe().expect("test exe");
        let exec_deadline = Instant::now() + Duration::from_secs(10);
        let exe = loop {
            match std::fs::read_link(format!("/proc/{}/exe", child.id())) {
                Ok(target) if target != me => break target,
                Ok(_) => {
                    assert!(
                        Instant::now() < exec_deadline,
                        "child execs promptly (still pre-exec at the deadline)"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => match child.try_wait().expect("try_wait") {
                    Some(status) => panic!("child died before the exe read: {status}"),
                    None => {
                        assert!(
                            Instant::now() < exec_deadline,
                            "exe link reads while the child lives"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                },
            }
        };
        assert_eq!(
            kill_and_reap(&mut child, generous_deadline()),
            CleanupOutcome::Complete,
            "owned cleanup of the live child completes"
        );
        let canonical = std::fs::canonicalize(&helper).expect("canonical helper");
        assert_eq!(
            exe, canonical,
            "exe names the executed image, not the argv[0] label"
        );
        assert_ne!(
            exe.file_name(),
            forged.file_name(),
            "exe is independent of the label"
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

    /// M1 oracle (Codex C1): an inherited fd numbered above the
    /// child's lowered `RLIMIT_NOFILE` soft limit still closes. The
    /// old `sysconf(_SC_OPEN_MAX)` loop stops at the soft limit and
    /// leaks the high fd into the child; `close_range` does not
    /// consult the limit at all. The limit lowers in the CHILD
    /// (`pre_exec`, via [`spawn_confined`]) — never process-global,
    /// which would starve parallel tests with `EMFILE`.
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
        // RAII: the parked fds close on every exit path.
        struct ParkedFds(Vec<i32>);
        impl Drop for ParkedFds {
            fn drop(&mut self) {
                for fd in &self.0 {
                    // SAFETY: each fd came from the opens above.
                    unsafe {
                        libc::close(*fd);
                    }
                }
            }
        }
        let _parked = ParkedFds(vec![devnull, high]);
        let ls = pinnable_ls();
        let image = ls.reopen().expect("ls reopens");
        let mut child = spawn_confined(
            &image,
            &ls.path,
            &["/proc/self/fd".to_string()],
            Stdio::null(),
            Some(LOW_SOFT),
        )
        .expect("spawns");
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let deadline = Instant::now() + Duration::from_secs(10);
        match drain_bounded(
            &mut child,
            &mut stdout,
            &mut stderr,
            None,
            4096,
            4096,
            deadline,
        ) {
            DrainOutcome::Done { status, out, .. } => {
                assert!(status.success(), "ls exits clean");
                assert_eq!(
                    String::from_utf8(out).expect("utf-8"),
                    "0\n1\n2\n3\n",
                    "child sees stdio + transient only (high fd closed)"
                );
            }
            other => panic!("drains cleanly: {other:?}"),
        }
    }

    /// Wait for a child with a hard bound: timeout kills, reaps,
    /// and reports `None` — probe oracles never hang the suite even
    /// when the launch path regresses into a hang.
    fn wait_bounded(
        child: &mut std::process::Child,
        bound: Duration,
    ) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + bound;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return Some(status),
                None => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    /// M1-dupfd oracle (Codex C2): a closed-stdio subprocess launch
    /// keeps stdio-only confinement — the helper attests fds exactly
    /// `[0,1,2]`. When the image open lands on fd 0–2 the launcher
    /// parks it above stdio; a park that clears `CLOEXEC` (plain
    /// `F_DUPFD`) survives `exec` and the attestation refuses. The
    /// probe re-execs this test binary (unique filter + one thread)
    /// so the stdio-closing probe runs single-threaded: no sibling
    /// thread can claim the closed numbers mid-probe.
    /// (RED pre-fix: the keep-fd leaks and the child attests
    /// `[0,1,2,3]`.)
    #[test]
    fn closed_stdio_launch_keeps_stdio_only_confinement() {
        if std::env::var("KRYPROBE_LAUNCH_CLOSED_STDIO_CHILD").is_ok() {
            closed_stdio_child();
            return;
        }
        closed_stdio_parent();
    }

    /// Closed-stdio child: close 0–2, attest, log the verdict to the
    /// parent-provided file, restore stdio for the harness, assert.
    fn closed_stdio_child() {
        let helper = std::env::var("KRYPROBE_LAUNCH_CLOSED_STDIO_HELPER").expect("helper path");
        let log = std::env::var("KRYPROBE_LAUNCH_CLOSED_STDIO_LOG").expect("log path");
        // SAFETY: closing stdio in this single-threaded probe child.
        for fd in [0, 1, 2] {
            unsafe {
                libc::close(fd);
            }
        }
        let principal = current_principal().expect("test principal");
        let result = attest_helper(Path::new(&helper), &principal, Duration::from_secs(10));
        std::fs::write(&log, format!("{result:?}")).expect("probe log");
        // Restore stdio before asserting: failure detail goes to the
        // log file the parent quotes, never to closed fds.
        for want in [0, 1, 2] {
            // SAFETY: open(2) on /dev/null; single-threaded, so the
            // lowest free number is exactly `want`.
            let got = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
            assert_eq!(got, want, "stdio restores cleanly");
        }
        assert!(
            result.is_ok(),
            "closed-stdio launch attests stdio-only: {result:?}"
        );
    }

    /// Closed-stdio parent: stage the fixture, re-exec this test
    /// binary as the probe child, bound its wait, quote its log.
    fn closed_stdio_parent() {
        const PROBE: &str = "closed_stdio_launch_keeps_stdio_only_confinement";
        let scratch = kryprobe_testkit::TempDir::named("launch-closed-stdio").expect("scratch");
        let helper = stage_fixture(scratch.path(), "helper", serde_json::json!({}));
        let log_path = scratch.path().join("probe.log");
        let test_exe = std::env::current_exe().expect("test exe");
        let mut child = Command::new(&test_exe)
            .arg(PROBE)
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env("KRYPROBE_LAUNCH_CLOSED_STDIO_CHILD", "1")
            .env("KRYPROBE_LAUNCH_CLOSED_STDIO_HELPER", &helper)
            .env("KRYPROBE_LAUNCH_CLOSED_STDIO_LOG", &log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("probe child spawns");
        let status = wait_bounded(&mut child, Duration::from_secs(30));
        let probe_log =
            std::fs::read_to_string(&log_path).unwrap_or_else(|_| "(no probe log)".to_string());
        let Some(status) = status else {
            panic!("closed-stdio probe child timed out (log: {probe_log})");
        };
        assert!(
            status.success(),
            "closed-stdio launch keeps stdio-only confinement (child {status}, probe: {probe_log})"
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
            None,
        )
        .expect("spawns");
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let deadline = Instant::now() + Duration::from_secs(10);
        match drain_bounded(
            &mut child,
            &mut stdout,
            &mut stderr,
            None,
            4096,
            4096,
            deadline,
        ) {
            DrainOutcome::Done { status, out, .. } => {
                assert!(status.success(), "ls exits clean");
                assert_eq!(
                    String::from_utf8(out).expect("utf-8"),
                    "0\n1\n2\n3\n",
                    "child sees stdio + transient only"
                );
            }
            other => panic!("drains cleanly: {other:?}"),
        }
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
    fn serve_with_diagnostics_surfaces_denied_and_migration() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-diag").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json", "counters": full_counters_value()}),
        );
        let principal = current_principal().expect("test principal");
        let served = serve_pinned_snapshot_with_diagnostics(
            &pin_helper(&helper).expect("pins"),
            &principal,
            None,
            &request,
            Duration::from_secs(10),
        )
        .expect("serves");
        // The valid unresolved response keeps its meaning.
        assert_eq!(served.response.session_id, SESSION);
        assert_eq!(served.response.associations.len(), 1);
        assert_eq!(
            served.response.associations[0].evidence.status,
            kryprobe_core::workload::AttributionStatus::Unresolved
        );
        // The approved counters surface typed.
        let diagnostics = served.diagnostics.expect("diagnostics measured");
        assert_eq!(diagnostics.denied, 1);
        assert_eq!(diagnostics.migration_skipped, 1);
        assert_eq!(diagnostics.positive_misses, 1);
        assert!(!diagnostics.saturated);
    }

    #[test]
    fn serve_diagnostics_malformed_keeps_valid_response() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-diagbad").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        for counters_line in [
            "not json at all",
            r#"{"helper_counters":{"denied":1}}"#,
            &diagnostics_line(&serde_json::json!({"denied": "x"})),
        ] {
            let helper = stage_fixture(
                scratch.path(),
                "helper",
                serde_json::json!({"canned": "canned.json", "counters_line": counters_line}),
            );
            let principal = current_principal().expect("test principal");
            let served = serve_pinned_snapshot_with_diagnostics(
                &pin_helper(&helper).expect("pins"),
                &principal,
                None,
                &request,
                Duration::from_secs(10),
            )
            .expect("serves");
            assert_eq!(served.response.session_id, SESSION);
            assert_eq!(
                served.diagnostics, None,
                "malformed record marks unavailable: {counters_line}"
            );
        }
    }

    #[test]
    fn serve_diagnostics_valid_plus_truncated_marks_unavailable_both_orders() {
        // P2 (wave-e) at the serve boundary: the helper emits a valid
        // record plus a truncated counters line (either order) — the
        // valid response keeps its meaning, diagnostics go unavailable.
        // The verbatim `counters_line` sidecar carries an embedded
        // newline, so the fixture emits two stderr lines.
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-diagtrunc").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let valid = diagnostics_line(&full_counters_value());
        let truncated = r#"{"helper_counters":{"#;
        for (order, counters_line) in [
            ("valid-first", format!("{valid}\n{truncated}")),
            ("truncated-first", format!("{truncated}\n{valid}")),
        ] {
            let helper = stage_fixture(
                scratch.path(),
                &format!("helper-{order}"),
                serde_json::json!({"canned": "canned.json", "counters_line": counters_line}),
            );
            let principal = current_principal().expect("test principal");
            let served = serve_pinned_snapshot_with_diagnostics(
                &pin_helper(&helper).expect("pins"),
                &principal,
                None,
                &request,
                Duration::from_secs(10),
            )
            .expect("serves");
            assert_eq!(served.response.session_id, SESSION);
            assert_eq!(
                served.diagnostics, None,
                "valid+truncated marks unavailable ({order})"
            );
        }
    }

    #[test]
    fn serve_diagnostics_valid_plus_escaped_marks_unavailable_both_orders() {
        // P2 (wave-f) at the serve boundary: the helper emits a valid
        // record plus an escaped-envelope counters line (either
        // order) — the valid response keeps its meaning, diagnostics
        // go unavailable.
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-diagesc").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let valid = diagnostics_line(&full_counters_value());
        let escaped = format!(r#"{{"hel\u0070er_counters":{}}}"#, full_counters_value());
        assert!(
            !escaped.contains("helper_counters"),
            "fixture evades the literal marker"
        );
        for (order, counters_line) in [
            ("valid-first", format!("{valid}\n{escaped}")),
            ("escaped-first", format!("{escaped}\n{valid}")),
        ] {
            let helper = stage_fixture(
                scratch.path(),
                &format!("helper-{order}"),
                serde_json::json!({"canned": "canned.json", "counters_line": counters_line}),
            );
            let principal = current_principal().expect("test principal");
            let served = serve_pinned_snapshot_with_diagnostics(
                &pin_helper(&helper).expect("pins"),
                &principal,
                None,
                &request,
                Duration::from_secs(10),
            )
            .expect("serves");
            assert_eq!(served.response.session_id, SESSION);
            assert_eq!(
                served.diagnostics, None,
                "valid+escaped marks unavailable ({order})"
            );
        }
    }

    #[test]
    fn serve_diagnostics_absent_is_unavailable() {
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-diagabs").expect("scratch");
        let request = test_request();
        // The echo path emits no counters line at all.
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"echo_unresolved": true}),
        );
        let principal = current_principal().expect("test principal");
        let served = serve_pinned_snapshot_with_diagnostics(
            &pin_helper(&helper).expect("pins"),
            &principal,
            None,
            &request,
            Duration::from_secs(10),
        )
        .expect("serves");
        assert_eq!(served.response.session_id, SESSION);
        assert_eq!(served.diagnostics, None);
        // The canned default (`{}`) is not a measurement either.
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json"}),
        );
        let served = serve_pinned_snapshot_with_diagnostics(
            &pin_helper(&helper).expect("pins"),
            &principal,
            None,
            &request,
            Duration::from_secs(10),
        )
        .expect("serves");
        assert_eq!(served.diagnostics, None);
    }

    #[test]
    fn serve_response_only_caller_preserved_with_counters() {
        // Old response-only callers keep their shape (bare
        // `SnapshotResponse`) even when the helper emits counters.
        let scratch = kryprobe_testkit::TempDir::named("launch-serve-compat").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json", "counters": full_counters_value()}),
        );
        let principal = current_principal().expect("test principal");
        let response: SnapshotResponse =
            serve_snapshot_with_bound(&helper, &principal, None, &request, Duration::from_secs(10))
                .expect("serves");
        assert_eq!(response.session_id, SESSION);
        assert_eq!(response.associations.len(), 1);
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

    /// C1 oracle (Codex C2): replacing the sibling with a FIFO
    /// (no writer) refuses fast — the verified open never blocks on
    /// a FIFO; the regular-file gate refuses it. The serve runs on a
    /// thread with a hard join bound, so a blocking-open regression
    /// FAILS instead of hanging the suite (the leaked thread dies
    /// with the test process).
    /// (RED pre-fix: the open blocks; the join times out.)
    #[test]
    fn fifo_sibling_replacement_refuses_without_hang() {
        use std::os::unix::ffi::OsStrExt;
        let scratch = kryprobe_testkit::TempDir::named("launch-fifo").expect("scratch");
        let helper_path = stage_fixture(scratch.path(), "helper", serde_json::json!({}));
        let principal = current_principal().expect("test principal");
        let pinned = pin_helper(&helper_path).expect("pins");
        std::fs::remove_file(&helper_path).expect("staged image removed");
        // A writerless FIFO at the sibling path: a blocking open
        // hangs here forever (pre-fix RED).
        let path_c = std::ffi::CString::new(helper_path.as_os_str().as_bytes()).expect("c path");
        // SAFETY: mkfifo on a scratch path; no writer ever opens it.
        assert_eq!(
            unsafe { libc::mkfifo(path_c.as_ptr(), 0o644) },
            0,
            "fifo swaps in"
        );
        let request = test_request();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let start = Instant::now();
        std::thread::spawn(move || {
            let outcome = serve_pinned_snapshot_with_bound(
                &pinned,
                &principal,
                None,
                &request,
                Duration::from_millis(300),
            );
            let _ = done_tx.send(outcome);
        });
        let outcome = done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("serve returns without hanging on the FIFO open");
        assert_eq!(
            outcome,
            Err(MetadataUnavailable::HelperRefused),
            "FIFO sibling refuses"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "refusal is fast (no hang): {:?}",
            start.elapsed()
        );
    }

    /// C1 oracle (a): a legal response larger than a shrunk pipe
    /// streams through concurrent drain. Wait-before-drain deadlocks
    /// it (the child blocks filling the pipe while the parent waits
    /// for the exit that never comes) and refuses after retries.
    #[test]
    fn large_legal_response_with_small_pipe_succeeds() {
        use kryprobe_core::workload::{
            AttributionStatus, BindingProvenance, ContainerRef, KernelIdentity, MetadataEntry,
            MetadataSnapshot, PodRef, SnapshotInterval, SnapshotKey, SnapshotRequest,
            ValidityInterval, WorkloadOrigin, encode_request,
        };
        let scratch = kryprobe_testkit::TempDir::named("launch-big-pipe").expect("scratch");
        // Twelve keys, each answered by a full-facet covering entry:
        // the response is legal but far larger than one page.
        let mut keys = Vec::new();
        let mut entries = Vec::new();
        for i in 0..12u64 {
            keys.push(SnapshotKey {
                kernel_scope: SCOPE.to_string(),
                cgroup: 100 + i,
                tgid: 1000 + i as u32,
                start_ns: 555,
            });
            entries.push(MetadataEntry {
                container: Some(ContainerRef {
                    runtime: "docker://host-a".to_string(),
                    id: "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57"
                        .to_string(),
                    lifetime: None,
                }),
                pod: Some(PodRef {
                    cluster: "cluster-a".to_string(),
                    uid: format!("pod-uid-{i:04}"),
                    name: format!("web-{i}"),
                    namespace: "production".to_string(),
                }),
                cluster: Some("cluster-a".to_string()),
                node: Some("node-a".to_string()),
                ancestor_container: Some(ContainerRef {
                    runtime: "docker://host-kind".to_string(),
                    id: "90f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb99"
                        .to_string(),
                    lifetime: None,
                }),
                display_name: None,
                cgroup_id: Some(100 + i),
                binding: BindingProvenance {
                    method: kryprobe_core::workload::METHOD_METADATA_FILE.to_string(),
                    source: WorkloadOrigin::OperatorMetadataFile,
                    status: AttributionStatus::Asserted,
                    validity: Some(ValidityInterval::monotonic(50, 2000)),
                },
            });
        }
        let request = SnapshotRequest {
            session_id: SESSION.to_string(),
            keys,
            capture_interval: Some(SnapshotInterval {
                start_ns: 100,
                end_ns: 1000,
            }),
        };
        encode_request(&request).expect("request itself is legal");
        let snapshot = MetadataSnapshot {
            collector: "launch-test".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: 100,
                end_ns: 1000,
            },
            kernel_identity: KernelIdentity::Known(SCOPE.to_string()),
            entries,
        };
        let response = kryprobe_core::workload::resolve(&request, &snapshot).expect("resolves");
        assert!(
            response
                .associations
                .iter()
                .all(|assoc| assoc.evidence.status == AttributionStatus::Asserted),
            "every key asserts"
        );
        let canned = kryprobe_core::workload::encode_response(&response).expect("encodes");
        assert!(
            canned.len() > 4096,
            "response exceeds the shrunk pipe: {} bytes",
            canned.len()
        );
        assert!(
            canned.len() <= MAX_SNAPSHOT_RESPONSE_BYTES,
            "response stays legal: {} bytes",
            canned.len()
        );
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({
                "canned": "canned.json",
                "shrink_pipes": 4096,
                "pipe_report": "pipes.txt",
            }),
        );
        let principal = current_principal().expect("test principal");
        let served =
            serve_snapshot_with_bound(&helper, &principal, None, &request, Duration::from_secs(2))
                .expect("large legal response streams through concurrent drain");
        assert_eq!(served.associations.len(), 12);
        // The backpressure was real: both pipes held one page.
        assert_eq!(
            std::fs::read_to_string(scratch.path().join("pipes.txt")).expect("pipe report"),
            "4096\n4096\n",
            "pipes really shrunk (no vacuous green)"
        );
    }

    /// C1 oracle (b): an exited child whose descendant retains the
    /// pipes terminates by the deadline — refusal, never hang. The
    /// old EOF read after the wait blocks forever here (no EOF ever
    /// arrives), so this hangs pre-fix (RED via timeout). The
    /// launcher also kills the pipe-retaining descendants
    /// (process-group kill at the deadline): the oracle asserts
    /// every recorded retainer is dead — the old test-side SIGKILL
    /// sweep proved nothing about the launcher.
    #[test]
    fn exited_child_with_pipe_retaining_descendant_terminates_by_deadline() {
        let scratch = kryprobe_testkit::TempDir::named("launch-retainer").expect("scratch");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"spawn_retainer": {"sleep_secs": 30, "pidfile": "pids"}}),
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
            Err(MetadataUnavailable::HelperRefused),
            "pipe-retaining descendant refuses by deadline"
        );
        // Three attempts bounded by 300 ms each: elapsed far below
        // the 30 s retainer sleep proves the deadline (not EOF)
        // ended every attempt.
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "terminates by deadline: {:?}",
            start.elapsed()
        );
        let pids_path = scratch.path().join("pids");
        let pids = std::fs::read_to_string(&pids_path).expect("retainer pids logged");
        assert_eq!(
            pids.lines().count() as u32,
            1 + MAX_HELPER_RETRIES,
            "every attempt spawned (and outlived) its child"
        );
        // Launcher-cleanup proof (Codex C2): every retainer must
        // be DEAD — the launcher SIGKILLs the child's process group
        // at each attempt's deadline. The sleepers cannot self-exit
        // before 30 s and the serve above returned in ~1 s, so death
        // here proves launcher cleanup, not self-exit. Poll briefly:
        // SIGKILL delivery is async and the reparented orphans reap
        // via init. (RED pre-group-kill: the sleepers outlive the
        // serve; the poll times out.)
        for line in pids.lines() {
            let pid: i32 = line.trim().parse().expect("retainer pid parses");
            let gone_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                // SAFETY: kill(pid, 0) probes existence only. Our
                // own same-uid descendants: 0 means alive-or-zombie;
                // any error (ESRCH, or a stranger's reused pid we
                // cannot signal) means OUR retainer is gone.
                let alive = unsafe { libc::kill(pid, 0) } == 0;
                if !alive {
                    break;
                }
                assert!(
                    Instant::now() < gone_deadline,
                    "launcher kills retainer {pid} (still alive 5 s after the serve)"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// C3-G blocker oracle (a): a serve under an inherited
    /// `SIGCHLD=SIG_IGN` still answers. The disposition survives
    /// exec, so without launcher-side normalization every exited
    /// helper auto-reaps: `waitid` reports `ECHILD`, the drain
    /// refuses, and the serve degrades to `HelperRefused`. The probe
    /// re-execs this test binary (unique filter + one thread, like
    /// the closed-stdio oracle); the `pre_exec` installs `SIG_IGN`
    /// post-fork so the child INHERITS it across `exec` — the
    /// parent's own disposition is never touched (this suite shares
    /// one process; a process-global `SIG_IGN` window would
    /// auto-reap sibling tests' children). The child asserts the
    /// hostile disposition arrived (no vacuous green), then serves.
    /// (RED pre-fix: the child serve refuses and the probe exits
    /// nonzero.)
    #[test]
    fn sigchld_ignored_inheritance_still_serves() {
        if std::env::var("KRYPROBE_LAUNCH_SIGCHLD_CHILD").is_ok() {
            sigchld_ignored_child();
            return;
        }
        sigchld_ignored_parent();
    }

    /// SIGCHLD-ignored child: prove the hostile disposition arrived
    /// across exec, serve one canned request, log the verdict for
    /// the parent to quote.
    fn sigchld_ignored_child() {
        let helper = std::env::var("KRYPROBE_LAUNCH_SIGCHLD_HELPER").expect("helper path");
        let log = std::env::var("KRYPROBE_LAUNCH_SIGCHLD_LOG").expect("log path");
        // SAFETY: sigaction query only.
        let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current) },
            0,
            "can query SIGCHLD disposition"
        );
        assert_eq!(
            current.sa_sigaction,
            libc::SIG_IGN,
            "hostile SIGCHLD=SIG_IGN survived exec (no vacuous green)"
        );
        let principal = current_principal().expect("test principal");
        let request = test_request();
        let result = serve_snapshot_with_bound(
            Path::new(&helper),
            &principal,
            None,
            &request,
            Duration::from_secs(10),
        );
        std::fs::write(&log, format!("{result:?}")).expect("probe log");
        let response = result.expect("serve answers under inherited SIGCHLD=SIG_IGN");
        assert_eq!(response.session_id, SESSION);
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, 42);
    }

    /// SIGCHLD-ignored parent: stage the canned fixture, re-exec
    /// this test binary with `SIG_IGN` installed post-fork (inherited
    /// across exec), bound the wait, quote the probe log.
    fn sigchld_ignored_parent() {
        const PROBE: &str = "sigchld_ignored_inheritance_still_serves";
        let scratch = kryprobe_testkit::TempDir::named("launch-sigchld").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json"}),
        );
        let log_path = scratch.path().join("probe.log");
        let test_exe = std::env::current_exe().expect("test exe");
        let mut command = Command::new(&test_exe);
        command
            .arg(PROBE)
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env("KRYPROBE_LAUNCH_SIGCHLD_CHILD", "1")
            .env("KRYPROBE_LAUNCH_SIGCHLD_HELPER", &helper)
            .env("KRYPROBE_LAUNCH_SIGCHLD_LOG", &log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: pre_exec installs SIG_IGN for SIGCHLD only (raw
        // sigaction, async-signal-safe); exec preserves SIG_IGN.
        unsafe {
            command.pre_exec(|| {
                let mut ign: libc::sigaction = std::mem::zeroed();
                ign.sa_sigaction = libc::SIG_IGN;
                libc::sigemptyset(&mut ign.sa_mask);
                ign.sa_flags = 0;
                if libc::sigaction(libc::SIGCHLD, &ign, std::ptr::null_mut()) != 0 {
                    std::process::abort();
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("probe child spawns");
        let status = wait_bounded(&mut child, Duration::from_secs(30));
        let probe_log =
            std::fs::read_to_string(&log_path).unwrap_or_else(|_| "(no probe log)".to_string());
        let Some(status) = status else {
            panic!("sigchld-ignored probe child timed out (log: {probe_log})");
        };
        assert!(
            status.success(),
            "serve stays waitable under inherited SIGCHLD=SIG_IGN (child {status}, probe: {probe_log})"
        );
    }

    /// C3-G blocker oracle (b): cleanup after ownership loss NEVER
    /// signals numeric IDs. A production-spawned `sleep` leader is
    /// killed and reaped (the post-`ECHILD` state: its pid/pgid are
    /// plain numbers again) while a second `sleep` — spawned raw
    /// with a `pre_exec` that joins the leader's group (a parent
    /// cannot `setpgid` a child after its `exec`) — holds membership
    /// in that group. `kill_and_reap` on the reaped leader must send
    /// nothing: the canary stays alive. (RED pre-fix: `killpg` on
    /// the dead leader's pgid SIGKILLs the canary.)
    #[test]
    fn cleanup_after_ownership_loss_signals_nothing() {
        let leader_bin = pinnable_sleep();
        let image = leader_bin.reopen().expect("sleep reopens");
        let mut leader = spawn_confined(
            &image,
            &leader_bin.path,
            &["30".to_string()],
            Stdio::null(),
            None,
        )
        .expect("leader spawns");
        let leader_id = leader.id();
        let leader_pid = leader_id as libc::pid_t;
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "leader really alive"
        );
        // Canary: raw spawn (test scaffolding, not the launcher —
        // only its group membership matters), joining the leader's
        // group in `pre_exec` (before its own exec).
        let mut canary_command = Command::new(&leader_bin.path);
        canary_command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: pre_exec setpgid-on-self only (async-signal-safe).
        unsafe {
            canary_command.pre_exec(move || {
                if libc::setpgid(0, leader_pid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut canary = canary_command.spawn().expect("canary spawns");
        // Setup proof (no vacuous green): the canary really joined
        // the leader's group ...
        assert_eq!(
            // SAFETY: getpgid on a live direct child pid.
            unsafe { libc::getpgid(canary.id() as libc::pid_t) },
            leader_pid,
            "canary holds membership in the leader's group"
        );
        // ... then the leader is killed and reaped: ownership lost.
        leader.kill().expect("leader dies");
        leader.wait().expect("leader reaps");
        // SAFETY: zeroed siginfo out-param; WNOWAIT never reaps.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid on the reaped leader pid; WNOWAIT never reaps.
        let waited = unsafe {
            libc::waitid(
                libc::P_PID,
                leader_id,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(waited, -1, "reaped leader is no longer waitable");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD),
            "post-reap state is ECHILD (ownership lost)"
        );
        // The oracle: cleanup of the ownership-less leader sends no
        // signal — the canary must stay alive for a full window
        // (SIGKILL delivery is near-instant, so any signaling would
        // show long before the window lapses).
        assert_eq!(
            kill_and_reap(&mut leader, generous_deadline()),
            CleanupOutcome::Complete,
            "reaped-leader cleanup completes (nothing outstanding)"
        );
        let window = Instant::now() + Duration::from_secs(1);
        loop {
            assert_eq!(
                canary.try_wait().expect("try_wait"),
                None,
                "canary survives cleanup-after-ownership-loss (killpg hit a dead pgid)"
            );
            if Instant::now() >= window {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = canary.kill();
        let _ = canary.wait();
    }

    /// A pinnable `sleep` for the ownership-loss oracle (same
    /// test-only resolution as [`pinnable_ls`]: absolute path, never
    /// a `PATH` search; symlinks resolved first).
    fn pinnable_sleep() -> PinnedHelper {
        ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .find_map(|path| pin_helper(&path).ok())
            .expect("a pinnable sleep exists")
    }

    /// C4-review oracle (item 1): a failed SIGCHLD normalization
    /// refuses BEFORE any child exists. The probe re-execs this test
    /// binary twice (unique filter + one thread, like the closed-stdio
    /// oracle): the refusal child (fault ON) installs `SIG_IGN`
    /// directly — it is single-purpose, so no sibling test shares
    /// its process — and must observe a typed refusal plus an
    /// untouched spawn sentinel; the control child (fault OFF) must
    /// spawn and serve cleanly. (RED pre-fix: the fault is ignored,
    /// the refusal spawn succeeds, the child exits nonzero.)
    #[test]
    fn sigchld_normalization_failure_refuses_before_spawn() {
        if std::env::var("KRYPROBE_LAUNCH_SIGCHLD_FAIL_CHILD").is_ok() {
            sigchld_normalization_failure_child();
            return;
        }
        sigchld_normalization_failure_parent();
    }

    /// Normalization-failure child: install the hostile
    /// disposition (this re-exec child is single-purpose — no
    /// sibling test shares its process), then run the refusal probe
    /// or the positive-control probe according to the inherited
    /// fault flag (set only via the parent's spawn environment —
    /// never mutated in-process).
    fn sigchld_normalization_failure_child() {
        let helper = std::env::var("KRYPROBE_LAUNCH_SIGCHLD_FAIL_HELPER").expect("helper path");
        let log = std::env::var("KRYPROBE_LAUNCH_SIGCHLD_FAIL_LOG").expect("log path");
        // Hostile disposition, installed directly: this re-exec
        // child is single-purpose, so no sibling test can observe
        // the process-global window.
        // SAFETY: sigaction install + query on SIGCHLD in this probe child.
        unsafe {
            let mut ign: libc::sigaction = std::mem::zeroed();
            ign.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut ign.sa_mask);
            ign.sa_flags = 0;
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, &ign, std::ptr::null_mut()),
                0,
                "probe installs SIG_IGN"
            );
            let mut current: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current),
                0,
                "can query SIGCHLD disposition"
            );
            assert_eq!(
                current.sa_sigaction,
                libc::SIG_IGN,
                "normalization is genuinely needed (no vacuous green)"
            );
        }
        if std::env::var("KRYPROBE_LAUNCH_FAIL_SIGCHLD_INSTALL").is_ok_and(|v| v == "1") {
            sigchld_failure_refusal_probe(Path::new(&helper), Path::new(&log));
        } else {
            sigchld_failure_control_probe(Path::new(&helper), Path::new(&log));
        }
    }

    /// Shell probe command for the normalization-failure oracles:
    /// any spawn of it touches `sentinel` (argv-carried path — no
    /// shell quoting). Returns the open image, its path, and argv.
    fn sigchld_failure_touch_command(sentinel: &Path) -> (std::fs::File, PathBuf, [String; 4]) {
        let sh_path = ["/bin/sh", "/usr/bin/sh"]
            .iter()
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .next()
            .expect("a shell exists");
        let sh_image = std::fs::File::open(&sh_path).expect("shell opens");
        let args = [
            "-c".to_string(),
            "touch \"$1\"".to_string(),
            "sh".to_string(),
            sentinel.to_string_lossy().into_owned(),
        ];
        (sh_image, sh_path, args)
    }

    /// Refusal probe (fault ON): normalization is needed but the
    /// install fails → typed refusal, zero spawns — through both
    /// the choke point and the public serve path.
    fn sigchld_failure_refusal_probe(helper: &Path, log: &Path) {
        let scratch =
            kryprobe_testkit::TempDir::named("launch-sigchld-fail-child").expect("scratch");
        let sentinel = scratch.path().join("spawned");
        let (sh_image, sh_path, touch_args) = sigchld_failure_touch_command(&sentinel);
        let refused = spawn_confined(&sh_image, &sh_path, &touch_args, Stdio::null(), None);
        assert!(
            refused.is_err(),
            "failed normalization refuses before spawn: {refused:?}"
        );
        // Grace window: a spawn would have touched the sentinel in
        // milliseconds; its continued absence proves zero spawns.
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !sentinel.exists(),
            "refused spawn leaves zero processes (sentinel untouched)"
        );
        // Same refusal through the public serve path: typed
        // (`HelperRefused`) and never retried. Zero-spawn follows
        // from the choke-point proof above (one `spawn_confined`).
        let principal = current_principal().expect("test principal");
        let serve_result = serve_snapshot_with_bound(
            helper,
            &principal,
            None,
            &test_request(),
            Duration::from_secs(10),
        );
        assert_eq!(
            serve_result,
            Err(MetadataUnavailable::HelperRefused),
            "failed normalization is a typed serve refusal"
        );
        std::fs::write(log, format!("refused={refused:?} serve={serve_result:?}"))
            .expect("probe log");
    }

    /// Positive-control probe (fault OFF): the same spawns succeed
    /// under the same hostile disposition, so the refusals above
    /// came from the injected install failure — and the sentinel
    /// mechanism genuinely detects spawns.
    fn sigchld_failure_control_probe(helper: &Path, log: &Path) {
        let scratch =
            kryprobe_testkit::TempDir::named("launch-sigchld-fail-control").expect("scratch");
        let sentinel = scratch.path().join("spawned");
        let (sh_image, sh_path, touch_args) = sigchld_failure_touch_command(&sentinel);
        let mut spawned = spawn_confined(&sh_image, &sh_path, &touch_args, Stdio::null(), None)
            .expect("spawn succeeds without the fault");
        let status = spawned.wait().expect("reaps");
        assert!(status.success(), "sentinel command exits cleanly");
        assert!(sentinel.exists(), "sentinel detects a real spawn (control)");
        let principal = current_principal().expect("test principal");
        let response = serve_snapshot_with_bound(
            helper,
            &principal,
            None,
            &test_request(),
            Duration::from_secs(10),
        )
        .expect("serve answers without the fault");
        assert_eq!(response.session_id, SESSION);
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, 42);
        std::fs::write(log, format!("control ok: session {}", response.session_id))
            .expect("probe log");
    }

    /// Normalization-failure parent: stage the canned fixture, run
    /// the refusal child (fault ON) then the control child (fault
    /// OFF), bound both waits, quote both logs.
    fn sigchld_normalization_failure_parent() {
        const PROBE: &str = "sigchld_normalization_failure_refuses_before_spawn";
        let scratch = kryprobe_testkit::TempDir::named("launch-sigchld-fail").expect("scratch");
        let request = test_request();
        let canned = canned_response_bytes(&request);
        std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
        let helper = stage_fixture(
            scratch.path(),
            "helper",
            serde_json::json!({"canned": "canned.json"}),
        );
        let log_path = scratch.path().join("probe.log");
        let test_exe = std::env::current_exe().expect("test exe");
        for (label, fault) in [("refusal", true), ("control", false)] {
            let mut command = Command::new(&test_exe);
            command
                .arg(PROBE)
                .arg("--test-threads=1")
                .arg("--nocapture")
                .env("KRYPROBE_LAUNCH_SIGCHLD_FAIL_CHILD", "1")
                .env("KRYPROBE_LAUNCH_SIGCHLD_FAIL_HELPER", &helper)
                .env("KRYPROBE_LAUNCH_SIGCHLD_FAIL_LOG", &log_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if fault {
                command.env("KRYPROBE_LAUNCH_FAIL_SIGCHLD_INSTALL", "1");
            }
            let mut child = command.spawn().expect("probe child spawns");
            let status = wait_bounded(&mut child, Duration::from_secs(30));
            let probe_log =
                std::fs::read_to_string(&log_path).unwrap_or_else(|_| "(no probe log)".to_string());
            let Some(status) = status else {
                panic!("sigchld-failure {label} child timed out (log: {probe_log})");
            };
            assert!(
                status.success(),
                "sigchld-failure {label} child succeeds (child {status}, probe: {probe_log})"
            );
        }
    }

    /// C4-review oracle (item 2): probe-`errno` classification fails
    /// closed — interruptions retry, EVERYTHING else (reaped, gone,
    /// or unproven) is unowned. Pure mapping, exhaustive over the
    /// errnos that matter.
    #[test]
    fn probe_errno_classification_fails_closed() {
        assert_eq!(
            classify_probe_failure(libc::EINTR),
            ProbeFailure::Interrupted,
            "interruption retries"
        );
        for errno in [
            libc::ECHILD,
            libc::ESRCH,
            libc::EINVAL,
            libc::EPERM,
            libc::EACCES,
            libc::EFAULT,
        ] {
            assert_eq!(
                classify_probe_failure(errno),
                ProbeFailure::Unowned,
                "errno {errno} fails closed"
            );
        }
    }

    /// Generous deadline for verdict-shape tests: their probes
    /// converge instantly (scripted verdicts, single syscalls), so
    /// any far-future bound works — the bound ITSELF is pinned by
    /// the sustained-interruptions and live-child oracles below.
    fn generous_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// C4-review oracle (item 2): convergence retries interruptions
    /// and still converges — to owned after a clean probe, to
    /// unowned after a terminal verdict — and a terminal verdict
    /// never re-probes.
    #[test]
    fn probe_convergence_retries_interruptions() {
        let mut script = [
            Err(ProbeFailure::Interrupted),
            Err(ProbeFailure::Interrupted),
            Ok(()),
        ]
        .into_iter();
        assert!(
            converge_ownership(
                || script.next().expect("scripted probe"),
                generous_deadline()
            ),
            "interruptions converge to the eventual verdict"
        );
        let mut script = [Err(ProbeFailure::Interrupted), Err(ProbeFailure::Unowned)].into_iter();
        assert!(
            !converge_ownership(
                || script.next().expect("scripted probe"),
                generous_deadline()
            ),
            "interruption then loss converges to unowned"
        );
        assert!(
            !converge_ownership(
                {
                    let mut calls = 0u32;
                    move || {
                        calls += 1;
                        assert_eq!(calls, 1, "a terminal verdict never re-probes");
                        Err(classify_probe_failure(libc::ESRCH))
                    }
                },
                generous_deadline()
            ),
            "ESRCH converges to unowned without re-probing"
        );
    }

    /// Positive control for the real probe path: a live child probes
    /// owned, a reaped child probes lost (`ECHILD`).
    #[test]
    fn ownership_probe_follows_real_waitid() {
        let sleep = pinnable_sleep();
        let image = sleep.reopen().expect("sleep reopens");
        let mut child = spawn_confined(
            &image,
            &sleep.path,
            &["30".to_string()],
            Stdio::null(),
            None,
        )
        .expect("spawns");
        assert!(
            child_still_waitable(&child, generous_deadline()),
            "live child probes owned"
        );
        child.kill().expect("dies");
        child.wait().expect("reaps");
        assert!(
            !child_still_waitable(&child, generous_deadline()),
            "reaped child probes lost"
        );
    }

    /// C4-review oracle (item 2, `ESRCH` representative): a
    /// fail-closed verdict never signals — even while the leader's
    /// pid is STILL OURS (dead-but-unreaped zombie, group held by
    /// the canary). The verdict travels from the scripted `errno`
    /// through the REAL classifier + convergence loop into the REAL
    /// kill gate; only the `waitid`-returns-`ESRCH` link is
    /// unconstructible on Linux (`wait(2)` reports non-children as
    /// `ECHILD`), so it is documented, not mocked.
    #[test]
    fn fail_closed_esrch_verdict_signals_nothing() {
        canary_survives_fail_closed_verdict(libc::ESRCH, "ESRCH");
    }

    /// C4-review oracle (item 2, non-`EINTR` unknown-`errno`
    /// representative): same proof for an unproven-ownership
    /// `errno` (`EINVAL`).
    #[test]
    fn fail_closed_unknown_errno_verdict_signals_nothing() {
        canary_survives_fail_closed_verdict(libc::EINVAL, "EINVAL");
    }

    /// Shared canary body for the fail-closed verdict oracles:
    /// leader killed but left unreaped (zombie — still provably
    /// ours), canary holding membership in the leader's group; the
    /// gated cleanup with the `errno`-derived verdict must send
    /// nothing for a full 1 s window. A closing `killpg` on the dead
    /// pgid is the sensitivity control: it MUST reach the canary,
    /// proving the window detects signaling (the exact pre-fix RED
    /// mechanism, on purpose).
    fn canary_survives_fail_closed_verdict(errno: libc::c_int, label: &str) {
        let leader_bin = pinnable_sleep();
        let image = leader_bin.reopen().expect("sleep reopens");
        let mut leader = spawn_confined(
            &image,
            &leader_bin.path,
            &["30".to_string()],
            Stdio::null(),
            None,
        )
        .expect("leader spawns");
        let leader_id = leader.id();
        let leader_pid = leader_id as libc::pid_t;
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "{label}: leader really alive"
        );
        // Canary: raw spawn (test scaffolding, not the launcher —
        // only its group membership matters), joining the leader's
        // group in `pre_exec` (before its own exec).
        let mut canary_command = Command::new(&leader_bin.path);
        canary_command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: pre_exec setpgid-on-self only (async-signal-safe).
        unsafe {
            canary_command.pre_exec(move || {
                if libc::setpgid(0, leader_pid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut canary = canary_command.spawn().expect("canary spawns");
        // Setup proof (no vacuous green): the canary really joined
        // the leader's group ...
        assert_eq!(
            // SAFETY: getpgid on a live direct child pid.
            unsafe { libc::getpgid(canary.id() as libc::pid_t) },
            leader_pid,
            "{label}: canary holds membership in the leader's group"
        );
        // ... then the leader is killed but NOT reaped: a zombie
        // still provably ours (the peek never reaps — `try_wait`
        // here would reap it).
        leader.kill().expect("leader dies");
        let death_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if peek_child_exited(&leader).expect("peek") {
                break;
            }
            assert!(
                Instant::now() < death_deadline,
                "{label}: leader dies promptly"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // The verdict: scripted errno through the REAL classifier +
        // convergence loop (a terminal verdict must not re-probe).
        let owned = converge_ownership(
            {
                let mut calls = 0u32;
                move || {
                    calls += 1;
                    assert_eq!(calls, 1, "{label}: terminal verdict never re-probes");
                    Err(classify_probe_failure(errno))
                }
            },
            generous_deadline(),
        );
        assert!(!owned, "{label}: verdict fails closed");
        // The oracle: gated cleanup sends nothing — the canary stays
        // alive for a full window (SIGKILL delivery is near-instant,
        // so any signaling would show long before the window lapses).
        assert_eq!(
            kill_and_reap_gated(&mut leader, owned, generous_deadline()),
            CleanupOutcome::Complete,
            "{label}: zombie reaps under the fail-closed verdict"
        );
        let window = Instant::now() + Duration::from_secs(1);
        loop {
            assert_eq!(
                canary.try_wait().expect("try_wait"),
                None,
                "{label}: canary survives fail-closed cleanup"
            );
            if Instant::now() >= window {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Sensitivity control: the same `killpg` the gate just
        // refused MUST reach the canary now — proving the window
        // above detects signaling (the pre-fix RED mechanism).
        // SAFETY: killpg on the dead leader's group, held only by our canary.
        unsafe {
            libc::killpg(leader_pid, libc::SIGKILL);
        }
        let gone_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if canary.try_wait().expect("try_wait").is_some() {
                break;
            }
            assert!(
                Instant::now() < gone_deadline,
                "{label}: control killpg reaches the canary"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = canary.wait();
    }

    /// C5-review oracle (bounded cleanup, `EPERM` representative): a
    /// terminal unproven-ownership verdict with a LIVE stalled child
    /// must still honor the attempt bound — and must still signal
    /// nothing. The verdict travels the REAL classifier +
    /// convergence loop; the child is a real confined `sleep 8`
    /// (alive at cleanup time — setup-proven, no vacuous green).
    /// (RED pre-fix: the unowned arm's blocking `wait` follows the
    /// CHILD's 8 s lifetime, failing the 3 s bound assert with an
    /// ~8 s elapsed.)
    #[test]
    fn unproven_ownership_live_child_cleanup_is_bounded() {
        let leader_bin = pinnable_sleep();
        let image = leader_bin.reopen().expect("sleep reopens");
        let mut leader = spawn_confined(
            &image,
            &leader_bin.path,
            &["8".to_string()],
            Stdio::null(),
            None,
        )
        .expect("spawns");
        // Setup proof (no vacuous green): the leader is really alive
        // when cleanup runs — a fast exit would reap promptly and
        // hand a false boundedness green to the blocking wait.
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "leader is live (stalled) at cleanup time"
        );
        // The verdict: scripted `EPERM` through the REAL classifier +
        // convergence loop (a terminal verdict never re-probes).
        let owned = converge_ownership(
            {
                let mut calls = 0u32;
                move || {
                    calls += 1;
                    assert_eq!(calls, 1, "terminal verdict never re-probes");
                    Err(classify_probe_failure(libc::EPERM))
                }
            },
            generous_deadline(),
        );
        assert!(!owned, "EPERM fails closed to unowned");
        // The oracle: cleanup returns within the attempt bound even
        // though the child stays alive — and signals nothing (the
        // leader survives; it IS its own group, so survival proves
        // neither `killpg` nor `kill` fired). The outcome is
        // incomplete, honestly: liveness unknown, nothing reaped.
        let start = Instant::now();
        let outcome = kill_and_reap_gated(&mut leader, owned, start + Duration::from_millis(500));
        let elapsed = start.elapsed();
        assert_eq!(
            outcome,
            CleanupOutcome::Incomplete,
            "live-child cleanup reports incomplete (never success-with-unknown-children)"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "unowned cleanup honors the attempt bound (blocked {elapsed:?} on a live child)"
        );
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "leader survives fail-closed cleanup (nothing signaled)"
        );
        let _ = leader.kill();
        let _ = leader.wait();
    }

    /// C5-review oracle (bounded EINTR retry): sustained
    /// interruptions must still converge within the attempt bound —
    /// to unowned (fail closed), never by spinning forever. (RED
    /// pre-fix: the retry loop has no deadline, so the probe thread
    /// never finishes and the bound assert fails; the spinner dies
    /// with the test binary.)
    #[test]
    fn probe_convergence_sustained_interruptions_stay_bounded() {
        let start = Instant::now();
        let owned = converge_ownership(
            || Err(ProbeFailure::Interrupted),
            start + Duration::from_millis(200),
        );
        let elapsed = start.elapsed();
        assert!(
            !owned,
            "sustained interruptions converge to unowned (fail closed)"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "sustained interruptions converge within the bound (took {elapsed:?})"
        );
    }

    /// Guard (green pre- and post-fix): an unproven-ownership verdict
    /// over an EXITED child still reaps promptly — bounding the wait
    /// must not turn reap-only into give-up-always. (`EPERM`
    /// representative through the REAL classifier + convergence.)
    #[test]
    fn unproven_ownership_zombie_still_reaps_promptly() {
        let leader_bin = pinnable_sleep();
        let image = leader_bin.reopen().expect("sleep reopens");
        let mut leader = spawn_confined(
            &image,
            &leader_bin.path,
            &["30".to_string()],
            Stdio::null(),
            None,
        )
        .expect("spawns");
        // Setup proof (no vacuous green): really a zombie — dead but
        // not yet reaped (the peek never reaps) — when cleanup runs.
        leader.kill().expect("leader dies");
        let death_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if peek_child_exited(&leader).expect("peek") {
                break;
            }
            assert!(Instant::now() < death_deadline, "leader dies promptly");
            std::thread::sleep(Duration::from_millis(5));
        }
        let owned = converge_ownership(
            {
                let mut calls = 0u32;
                move || {
                    calls += 1;
                    assert_eq!(calls, 1, "terminal verdict never re-probes");
                    Err(classify_probe_failure(libc::EPERM))
                }
            },
            generous_deadline(),
        );
        assert!(!owned, "EPERM fails closed to unowned");
        let start = Instant::now();
        let outcome = kill_and_reap_gated(&mut leader, owned, generous_deadline());
        let elapsed = start.elapsed();
        assert_eq!(
            outcome,
            CleanupOutcome::Complete,
            "zombie cleanup completes under the fail-closed verdict"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "exited-child cleanup returns promptly (took {elapsed:?})"
        );
        assert!(
            leader.try_wait().expect("try_wait").is_some(),
            "zombie reaps under the fail-closed verdict (still ours to reap)"
        );
    }

    /// Seccomp `AUDIT_ARCH_X86_64` (kernel ABI: `EM_X86_64` +
    /// 64-bit + little-endian; `libc` 0.2 exposes no audit-arch
    /// constants, so the value is pinned here — test-only fault
    /// injection, never production).
    const SECCOMP_AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

    /// Install one seccomp errno filter in THIS process only (the
    /// isolated re-exec child — never the shared harness): `prctl`
    /// `NO_NEW_PRIVS` plus `SECCOMP_MODE_FILTER` with `prog`. Panics
    /// when the install fails (no silent vacuous green: a missing
    /// filter would let the faulted syscalls succeed).
    fn install_seccomp_filter(prog: &[libc::sock_filter]) {
        // SAFETY: `prctl` by value; `prog` outlives the install call.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0,
            "test child pins NO_NEW_PRIVS for the seccomp filter"
        );
        let prog_struct = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: `prctl` install with a live filter pointer.
        let installed = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog_struct as *const libc::sock_fprog as libc::c_ulong,
                0,
                0,
            )
        };
        assert_eq!(
            installed,
            0,
            "seccomp errno filter installs: {:?}",
            std::io::Error::last_os_error()
        );
    }

    /// C6-review oracle (Blocker 1): an `EINTR` that leaves the
    /// sleep remainder unchanged must not trap unproven-ownership
    /// cleanup past the attempt deadline. The probe re-execs this
    /// test binary (unique filter + one thread): the child spawns a
    /// live `sleep 8` leader, derives a `false` verdict from a
    /// scripted `EPERM` through the REAL classifier + convergence,
    /// installs a seccomp filter faulting `nanosleep` /
    /// `clock_nanosleep` to `EINTR` in the CHILD ONLY, then runs the
    /// REAL gated cleanup with a 500 ms deadline. (RED pre-fix:
    /// `thread::sleep` retries the faulted `nanosleep` forever — the
    /// child hangs until the parent's 30 s bound kills it.)
    #[test]
    fn unowned_cleanup_interrupted_sleep_stays_bounded() {
        if std::env::var("KRYPROBE_LAUNCH_SLEEP_EINTR_CHILD").is_ok() {
            interrupted_sleep_child();
            return;
        }
        interrupted_sleep_parent();
    }

    /// Interrupted-sleep child: live leader, false verdict, faulted
    /// sleeps, bounded `Incomplete` + leader survival.
    fn interrupted_sleep_child() {
        let log = std::env::var("KRYPROBE_LAUNCH_SLEEP_EINTR_LOG").expect("log path");
        let leader_bin = pinnable_sleep();
        let image = leader_bin.reopen().expect("sleep reopens");
        let mut leader = spawn_confined(
            &image,
            &leader_bin.path,
            &["8".to_string()],
            Stdio::null(),
            None,
        )
        .expect("spawns");
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "leader is live (stalled) at cleanup time"
        );
        // False verdict: scripted `EPERM` through the REAL classifier
        // + convergence (terminal, never re-probes).
        let owned = converge_ownership(
            {
                let mut calls = 0u32;
                move || {
                    calls += 1;
                    assert_eq!(calls, 1, "terminal verdict never re-probes");
                    Err(classify_probe_failure(libc::EPERM))
                }
            },
            generous_deadline(),
        );
        assert!(!owned, "EPERM fails closed to unowned");
        // Fault `nanosleep` + `clock_nanosleep` to `EINTR` in THIS
        // child only (the leader forked before the filter, so it
        // sleeps normally). BPF indexes: 0:LD arch, 1:JEQ arch,
        // 2:LD nr, 3:JEQ nanosleep, 4:JEQ clock_nanosleep, 5:ALLOW,
        // 6:ERRNO|EINTR.
        let prog = unsafe {
            [
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 4),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    SECCOMP_AUDIT_ARCH_X86_64,
                    0,
                    3,
                ),
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    libc::SYS_nanosleep as u32,
                    2,
                    0,
                ),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    libc::SYS_clock_nanosleep as u32,
                    1,
                    0,
                ),
                libc::BPF_STMT(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ALLOW,
                ),
                libc::BPF_STMT(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ERRNO | (libc::EINTR as u32),
                ),
            ]
        };
        install_seccomp_filter(&prog);
        // No `thread::sleep` past this point (it would trap on the RED
        // tree inside the filter — the production call below is the
        // only sleeper, and the fixed tree bounds it).
        let start = Instant::now();
        let outcome = kill_and_reap_gated(&mut leader, owned, start + Duration::from_millis(500));
        let elapsed = start.elapsed();
        assert_eq!(
            outcome,
            CleanupOutcome::Incomplete,
            "interrupted-sleep cleanup reports incomplete (never success-with-unknown-children)"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "interrupted-sleep cleanup honors the attempt bound (blocked {elapsed:?})"
        );
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "leader survives fail-closed cleanup (nothing signaled)"
        );
        std::fs::write(&log, format!("incomplete elapsed={elapsed:?}")).expect("probe log");
        // Hygiene: kills + waits are unfiltered (only sleeps fault),
        // so the leader dies promptly.
        let _ = leader.kill();
        let _ = leader.wait();
    }

    /// Interrupted-sleep parent: re-exec the probe child, bound the
    /// wait, quote the log.
    fn interrupted_sleep_parent() {
        const PROBE: &str = "unowned_cleanup_interrupted_sleep_stays_bounded";
        let scratch = kryprobe_testkit::TempDir::named("launch-sleep-eintr").expect("scratch");
        let log_path = scratch.path().join("probe.log");
        let test_exe = std::env::current_exe().expect("test exe");
        let mut child = Command::new(&test_exe)
            .arg(PROBE)
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env("KRYPROBE_LAUNCH_SLEEP_EINTR_CHILD", "1")
            .env("KRYPROBE_LAUNCH_SLEEP_EINTR_LOG", &log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("probe child spawns");
        let status = wait_bounded(&mut child, Duration::from_secs(30));
        let probe_log =
            std::fs::read_to_string(&log_path).unwrap_or_else(|_| "(no probe log)".to_string());
        let Some(status) = status else {
            panic!("interrupted-sleep probe child timed out (log: {probe_log})");
        };
        assert!(
            status.success(),
            "interrupted-sleep cleanup stays bounded (child {status}, probe: {probe_log})"
        );
    }

    /// C6-review oracle (Blocker 2a): denied signals on a live
    /// owned child must NOT report `Complete`. The probe re-execs:
    /// the child spawns a live `sleep 8` leader (proven ownership via
    /// the REAL probe) plus an unrelated canary, installs a seccomp
    /// filter faulting `kill` with `SIGKILL` to `EPERM` in the CHILD
    /// ONLY (`SIGTERM` stays allowed for hygiene), then runs the REAL
    /// `kill_and_reap` with a 500 ms deadline. (RED pre-fix: the
    /// blocking wait follows the child's 8 s lifetime, then falsely
    /// reports `Complete`.)
    #[test]
    fn owned_cleanup_denied_signals_report_incomplete() {
        if std::env::var("KRYPROBE_LAUNCH_KILL_EPERM_CHILD").is_ok() {
            denied_signals_child();
            return;
        }
        denied_signals_parent();
    }

    /// Denied-signals child: live leader + canary, faulted `SIGKILL`,
    /// bounded `Incomplete` + both survive.
    fn denied_signals_child() {
        let log = std::env::var("KRYPROBE_LAUNCH_KILL_EPERM_LOG").expect("log path");
        let leader_bin = pinnable_sleep();
        let image = leader_bin.reopen().expect("sleep reopens");
        let mut leader = spawn_confined(
            &image,
            &leader_bin.path,
            &["8".to_string()],
            Stdio::null(),
            None,
        )
        .expect("spawns");
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "leader is live (stalled) at cleanup time"
        );
        // Unrelated-process sentinel: raw `sleep` in the test child's
        // group (NOT the leader's group — `killpg` must never reach
        // it even when signals succeed).
        let mut canary = Command::new(&leader_bin.path)
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("canary spawns");
        assert_eq!(
            canary.try_wait().expect("try_wait"),
            None,
            "canary is live at cleanup time"
        );
        // Proven ownership via the REAL probe (live child).
        assert!(
            child_still_waitable(&leader, generous_deadline()),
            "live leader probes owned (no vacuous unowned green)"
        );
        // Fault `kill` with `SIGKILL` to `EPERM` in THIS child only
        // (`killpg` uses the `kill` syscall, so both fault; `SIGTERM`
        // stays allowed for hygiene). BPF indexes: 0:LD arch, 1:JEQ
        // arch, 2:LD nr, 3:JEQ kill, 4:LD sig, 5:JEQ SIGKILL,
        // 6:ALLOW, 7:ERRNO|EPERM. Signal at `args[1]` low (offset 24).
        let prog = unsafe {
            [
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 4),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    SECCOMP_AUDIT_ARCH_X86_64,
                    0,
                    4,
                ),
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    libc::SYS_kill as u32,
                    0,
                    2,
                ),
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 24),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    libc::SIGKILL as u32,
                    1,
                    0,
                ),
                libc::BPF_STMT(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ALLOW,
                ),
                libc::BPF_STMT(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
                ),
            ]
        };
        install_seccomp_filter(&prog);
        // Setup proof that the fault bites: `SIGKILL` denied,
        // `SIGTERM` allowed (raw syscalls, no `Child::kill` past the
        // filter — it sends the faulted `SIGKILL`).
        let denied = unsafe { libc::kill(leader.id() as libc::pid_t, libc::SIGKILL) };
        assert_eq!(denied, -1, "SIGKILL faults under the filter");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM),
            "the fault errno is EPERM (no vacuous green)"
        );
        let start = Instant::now();
        let outcome = kill_and_reap(&mut leader, start + Duration::from_millis(500));
        let elapsed = start.elapsed();
        // Log before asserting (the RED tree fails below — the parent
        // quotes this log as the timing + false-`Complete` proof).
        std::fs::write(&log, format!("{outcome:?} elapsed={elapsed:?}")).expect("probe log");
        assert_eq!(
            outcome,
            CleanupOutcome::Incomplete,
            "denied-signal cleanup reports incomplete (never a false Complete)"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "denied-signal cleanup honors the attempt bound (blocked {elapsed:?})"
        );
        assert_eq!(
            leader.try_wait().expect("try_wait"),
            None,
            "leader survives denied-signal cleanup (kills denied)"
        );
        assert_eq!(
            canary.try_wait().expect("try_wait"),
            None,
            "unrelated canary survives denied-signal cleanup"
        );
        // Hygiene via allowed `SIGTERM` (raw — `Child::kill` would
        // send the faulted `SIGKILL`), then unfiltered waits.
        unsafe {
            libc::kill(leader.id() as libc::pid_t, libc::SIGTERM);
            libc::kill(canary.id() as libc::pid_t, libc::SIGTERM);
        }
        let _ = leader.wait();
        let _ = canary.wait();
    }

    /// Denied-signals parent: re-exec the probe child, bound the
    /// wait, quote the log.
    fn denied_signals_parent() {
        const PROBE: &str = "owned_cleanup_denied_signals_report_incomplete";
        let scratch = kryprobe_testkit::TempDir::named("launch-kill-eperm").expect("scratch");
        let log_path = scratch.path().join("probe.log");
        let test_exe = std::env::current_exe().expect("test exe");
        let mut child = Command::new(&test_exe)
            .arg(PROBE)
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env("KRYPROBE_LAUNCH_KILL_EPERM_CHILD", "1")
            .env("KRYPROBE_LAUNCH_KILL_EPERM_LOG", &log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("probe child spawns");
        let status = wait_bounded(&mut child, Duration::from_secs(30));
        let probe_log =
            std::fs::read_to_string(&log_path).unwrap_or_else(|_| "(no probe log)".to_string());
        let Some(status) = status else {
            panic!("denied-signals probe child timed out (log: {probe_log})");
        };
        assert!(
            status.success(),
            "denied-signal cleanup reports incomplete (child {status}, probe: {probe_log})"
        );
    }

    /// C6-review oracle (Blocker 2b): a sustained `EINTR` on the
    /// Done-path reap must not hang past the attempt deadline. The
    /// probe re-execs: the child spawns a `sleep` leader, kills it to
    /// a zombie (proven via `waitid`, which stays allowed), installs
    /// a seccomp filter faulting `wait4` to `EINTR` in the CHILD ONLY,
    /// then runs the REAL `drain_bounded` (EOF pipes, no stdin, 500
    /// ms deadline). (RED pre-fix: `Child::wait` retries the faulted
    /// `wait4` forever — the child hangs until the parent's 30 s
    /// bound kills it.) Liveness past the filter avoids `wait4`
    /// (`try_wait` faults): the zombie is proven via `waitid`, the
    /// canary via `kill(pid, 0)`.
    #[test]
    fn done_reap_interrupted_wait_stays_bounded() {
        if std::env::var("KRYPROBE_LAUNCH_WAIT_EINTR_CHILD").is_ok() {
            interrupted_wait_child();
            return;
        }
        interrupted_wait_parent();
    }

    /// Interrupted-wait child: zombie leader + canary, faulted
    /// `wait4`, bounded `CleanupIncomplete` (never `Done`, never a
    /// hang).
    fn interrupted_wait_child() {
        let log = std::env::var("KRYPROBE_LAUNCH_WAIT_EINTR_LOG").expect("log path");
        let leader_bin = pinnable_sleep();
        let image = leader_bin.reopen().expect("sleep reopens");
        let mut leader = spawn_confined(
            &image,
            &leader_bin.path,
            &["30".to_string()],
            Stdio::null(),
            None,
        )
        .expect("spawns");
        // Unrelated-process sentinel (raw `sleep`, test-child group).
        let mut canary = Command::new(&leader_bin.path)
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("canary spawns");
        assert_eq!(
            canary.try_wait().expect("try_wait"),
            None,
            "canary is live at drain time"
        );
        // Zombie setup (pre-filter): kill, then prove dead-but-
        // unreaped via the `waitid` peek (which never reaps).
        leader.kill().expect("leader dies");
        let death_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if peek_child_exited(&leader).expect("peek") {
                break;
            }
            assert!(
                Instant::now() < death_deadline,
                "leader dies promptly (no vacuous live green)"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut stdout = leader.stdout.take().expect("piped stdout");
        let mut stderr = leader.stderr.take().expect("piped stderr");
        // Fault `wait4` (61) to `EINTR` in THIS child only (`waitid`
        // stays allowed for the peek/probe; kills stay allowed).
        // BPF indexes: 0:LD arch, 1:JEQ arch, 2:LD nr, 3:JEQ wait4,
        // 4:ALLOW, 5:ERRNO|EINTR.
        let prog = unsafe {
            [
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 4),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    SECCOMP_AUDIT_ARCH_X86_64,
                    0,
                    2,
                ),
                libc::BPF_STMT((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    libc::SYS_wait4 as u32,
                    1,
                    0,
                ),
                libc::BPF_STMT(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ALLOW,
                ),
                libc::BPF_STMT(
                    (libc::BPF_RET | libc::BPF_K) as u16,
                    libc::SECCOMP_RET_ERRNO | (libc::EINTR as u32),
                ),
            ]
        };
        install_seccomp_filter(&prog);
        // Setup proof that the fault bites (`try_wait` uses `wait4`)
        // while the `waitid` peek still works.
        assert_eq!(
            leader
                .try_wait()
                .expect_err("try_wait faults under the filter")
                .raw_os_error(),
            Some(libc::EINTR),
            "the fault errno is EINTR (no vacuous green)"
        );
        assert!(
            peek_child_exited(&leader).expect("waitid peek stays allowed"),
            "zombie still visible via waitid past the filter"
        );
        // No `wait4` past this point except through the production
        // drain below (it bounds the fault); liveness uses `waitid`
        // and `kill(pid, 0)`.
        let start = Instant::now();
        let outcome = drain_bounded(
            &mut leader,
            &mut stdout,
            &mut stderr,
            None,
            4096,
            4096,
            start + Duration::from_millis(500),
        );
        let elapsed = start.elapsed();
        assert!(
            matches!(outcome, DrainOutcome::CleanupIncomplete),
            "interrupted Done reap refuses boundedly (got {outcome:?}, never Done)"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "interrupted Done reap honors the attempt bound (blocked {elapsed:?})"
        );
        // The zombie was never reaped (waits faulted) — still visible
        // via `waitid`; the canary never signaled (drain signals
        // nothing on this path — still alive via `kill(pid, 0)`).
        assert!(
            peek_child_exited(&leader).expect("peek"),
            "unreaped zombie still visible via waitid"
        );
        // SAFETY: `kill(pid, 0)` probes existence without signaling.
        assert_eq!(
            unsafe { libc::kill(canary.id() as libc::pid_t, 0) },
            0,
            "unrelated canary survives interrupted Done reap"
        );
        std::fs::write(&log, format!("cleanup-incomplete elapsed={elapsed:?}")).expect("probe log");
        // Hygiene without `wait4` (faulted): `SIGTERM` the canary
        // (allowed) and exit — both zombies orphan to init, which
        // reaps them. No live strays (leader already dead, canary
        // dying); no waits attempted.
        unsafe {
            libc::kill(canary.id() as libc::pid_t, libc::SIGTERM);
        }
        std::mem::forget(canary);
        std::mem::forget(leader);
    }

    /// Interrupted-wait parent: re-exec the probe child, bound the
    /// wait, quote the log.
    fn interrupted_wait_parent() {
        const PROBE: &str = "done_reap_interrupted_wait_stays_bounded";
        let scratch = kryprobe_testkit::TempDir::named("launch-wait-eintr").expect("scratch");
        let log_path = scratch.path().join("probe.log");
        let test_exe = std::env::current_exe().expect("test exe");
        let mut child = Command::new(&test_exe)
            .arg(PROBE)
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env("KRYPROBE_LAUNCH_WAIT_EINTR_CHILD", "1")
            .env("KRYPROBE_LAUNCH_WAIT_EINTR_LOG", &log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("probe child spawns");
        let status = wait_bounded(&mut child, Duration::from_secs(30));
        let probe_log =
            std::fs::read_to_string(&log_path).unwrap_or_else(|_| "(no probe log)".to_string());
        let Some(status) = status else {
            panic!("interrupted-wait probe child timed out (log: {probe_log})");
        };
        assert!(
            status.success(),
            "interrupted Done reap stays bounded (child {status}, probe: {probe_log})"
        );
    }

    /// A `Read` that is always interrupted (sustained `EINTR`):
    /// the pipe-drain oracle's fault source (no syscalls — the
    /// interruption path is pure logic past the `read` return).
    struct AlwaysInterruptedRead;

    impl std::io::Read for AlwaysInterruptedRead {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(libc::EINTR))
        }
    }

    /// C6-review oracle (Blocker 3, reads): a sustained interruption
    /// on a pipe read must yield to the outer loop instead of
    /// trapping past the deadline. The faulted drain runs on a
    /// thread with a 3 s join bound: the fixed tree returns `Open`
    /// immediately (the outer loop re-polls after its deadline
    /// check); the RED tree spins inline forever (the join times
    /// out and the spinner dies with the test binary — same shape as
    /// the J sustained-interruptions RED).
    #[test]
    fn interrupted_pipe_read_yields_to_deadline() {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let start = Instant::now();
        std::thread::spawn(move || {
            let mut pipe = AlwaysInterruptedRead;
            let mut acc = Vec::new();
            let mut chunk = [0u8; 64];
            let open = matches!(
                drain_pipe(&mut pipe, &mut acc, &mut chunk, 4096),
                PipeOutcome::Open
            );
            let _ = done_tx.send((open, acc.len()));
        });
        let (open, acc_len) = done_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("interrupted read yields instead of trapping past the bound");
        let elapsed = start.elapsed();
        assert!(open, "interrupted read yields Open to the outer loop");
        assert_eq!(acc_len, 0, "no bytes accumulate across interruptions");
        assert!(
            elapsed < Duration::from_secs(3),
            "interrupted read yields promptly (took {elapsed:?})"
        );
        // Positive control (no overcorrection): a normal read still
        // drains — data, then would-block.
        struct DataThenBlocked {
            sent: bool,
        }
        impl std::io::Read for DataThenBlocked {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.sent {
                    self.sent = true;
                    buf[..2].copy_from_slice(b"ok");
                    return Ok(2);
                }
                Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
            }
        }
        // `EAGAIN` maps to `WouldBlock`, which the drain treats as
        // "open, more may come".
        let mut pipe = DataThenBlocked { sent: false };
        let mut acc = Vec::new();
        let mut chunk = [0u8; 64];
        assert!(
            matches!(
                drain_pipe(&mut pipe, &mut acc, &mut chunk, 4096),
                PipeOutcome::Open
            ),
            "normal reads still drain to Open"
        );
        assert_eq!(acc, b"ok", "drained bytes preserved");
    }

    /// A `Write` that is always interrupted (sustained `EINTR`).
    struct AlwaysInterruptedWrite;

    impl std::io::Write for AlwaysInterruptedWrite {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(libc::EINTR))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// C6-review oracle (Blocker 3, writes): a sustained interruption
    /// on a stdin write must yield to the outer loop instead of
    /// trapping past the deadline. Same thread + join-bound shape as
    /// the read oracle above.
    #[test]
    fn interrupted_stdin_write_yields_to_deadline() {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let start = Instant::now();
        std::thread::spawn(move || {
            let mut pipe = AlwaysInterruptedWrite;
            let bytes = vec![7u8; 128];
            let mut written = 0usize;
            let pending = matches!(
                write_stdin_chunk(&mut pipe, &bytes, &mut written),
                StdinOutcome::Pending
            );
            let _ = done_tx.send((pending, written));
        });
        let (pending, written) = done_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("interrupted write yields instead of trapping past the bound");
        let elapsed = start.elapsed();
        assert!(
            pending,
            "interrupted write yields Pending to the outer loop"
        );
        assert_eq!(written, 0, "no bytes advance across interruptions");
        assert!(
            elapsed < Duration::from_secs(3),
            "interrupted write yields promptly (took {elapsed:?})"
        );
        // Positive control (no overcorrection): a normal write still
        // completes.
        struct AcceptAll;
        impl std::io::Write for AcceptAll {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut pipe = AcceptAll;
        let bytes = vec![7u8; 128];
        let mut written = 0usize;
        assert!(
            matches!(
                write_stdin_chunk(&mut pipe, &bytes, &mut written),
                StdinOutcome::Done
            ),
            "normal writes still complete"
        );
        assert_eq!(written, 128, "all bytes advance");
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
