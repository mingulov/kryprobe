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
//!   the helper (`O_RDONLY|O_NOFOLLOW|O_CLOEXEC`), enforces the
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
//! - Transport (finding C1): one `poll` loop writes stdin while draining
//!   stdout/stderr concurrently under a single overall deadline
//!   covering spawn, writes, reads, and reap. No wait-before-drain
//!   stall (a legal response larger than the pipe streams through)
//!   and no unbounded EOF read (a descendant retaining a pipe
//!   cannot outlive the deadline). Caps keep the old `cap + 1`
//!   refusals; outcome classification is unchanged.
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
/// file), regular-file gate, `CLOEXEC` pinned explicitly, the fd
/// parked at 3+ (never a stdio number), the trusted-image rule
/// (owner root-or-euid, no group/other write), and the sha256
/// content digest read from the same open file description that
/// execs. Static outcome: ok or I/O error (callers map it to
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
fn spawn_confined(
    pinned: &std::fs::File,
    arg0: &Path,
    args: &[String],
    stdin_mode: Stdio,
    child_soft_limit: Option<u64>,
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
        command.pre_exec(move || confine_child(fd, child_soft_limit));
    }
    command.spawn()
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
}

/// Kill and reap unconditionally (never a hang, never an orphan).
fn kill_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
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

/// Read one pipe until it would block, EOF, over-cap, or failure
/// (interrupted reads retry, as `read_to_end` did).
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
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return PipeOutcome::Open,
            Err(_) => return PipeOutcome::Failed,
        }
    }
}

/// Drain one attempt under ONE overall deadline: stdin writes plus
/// concurrent stdout/stderr reads plus reap in a single `poll` loop.
/// No wait-before-drain stall (a legal response larger than the pipe
/// streams through while the child still runs) and no unbounded EOF
/// read (a descendant retaining a pipe cannot outlive the deadline:
/// the child is already reaped and the pipes drain until the lapse).
/// Done requires the reaped status AND both EOFs AND a finished
/// stdin write; anything else ends by cap or by deadline.
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
        kill_and_reap(child);
        return DrainOutcome::WaitFailed;
    }
    let mut stdin = stdin;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut out_eof = false;
    let mut err_eof = false;
    let mut status: Option<std::process::ExitStatus> = None;
    let mut chunk = [0u8; 8192];
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exited)) => status = Some(exited),
                Ok(None) => {}
                Err(_) => {
                    kill_and_reap(child);
                    return DrainOutcome::WaitFailed;
                }
            }
        }
        if out_eof
            && err_eof
            && stdin.is_none()
            && let Some(status) = status
        {
            return DrainOutcome::Done { status, out, err };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            kill_and_reap(child);
            return DrainOutcome::Stalled;
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
            kill_and_reap(child);
            return DrainOutcome::WaitFailed;
        }
        if stdin_slot.is_some_and(|slot| watched[slot].revents != 0)
            && let Some(job) = stdin.as_mut()
        {
            let mut fatal = false;
            while job.written < job.bytes.len() {
                match job.pipe.write(&job.bytes[job.written..]) {
                    Ok(0) => break,
                    Ok(n) => job.written += n,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        // Broken pipe: the child died early — drop
                        // stdin and let the exit status decide.
                        fatal = true;
                        break;
                    }
                }
            }
            if fatal || job.written >= job.bytes.len() {
                stdin = None;
            }
        }
        if stdout_slot.is_some_and(|slot| watched[slot].revents != 0) {
            match drain_pipe(stdout, &mut out, &mut chunk, stdout_cap) {
                PipeOutcome::Open => {}
                PipeOutcome::Eof => out_eof = true,
                PipeOutcome::OverCap => {
                    kill_and_reap(child);
                    return DrainOutcome::OverCapStdout;
                }
                PipeOutcome::Failed => {
                    kill_and_reap(child);
                    return DrainOutcome::ReadFailed;
                }
            }
        }
        if stderr_slot.is_some_and(|slot| watched[slot].revents != 0) {
            match drain_pipe(stderr, &mut err, &mut chunk, stderr_cap) {
                PipeOutcome::Open => {}
                PipeOutcome::Eof => err_eof = true,
                PipeOutcome::OverCap => {
                    kill_and_reap(child);
                    return DrainOutcome::OverCapStderr;
                }
                PipeOutcome::Failed => {
                    kill_and_reap(child);
                    return DrainOutcome::ReadFailed;
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
        | DrainOutcome::ReadFailed => return Err(MetadataUnavailable::HelperRefused),
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
        DrainOutcome::ReadFailed => {
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

    /// Built fixture binary:
    /// `<target>/debug/examples/kryprobe_launch_fixture` next to the
    /// test executable's `deps` dir. The fixture is a Cargo *example*
    /// (test-only by construction: `cargo build` never produces it,
    /// `cargo install` never ships it). Every all-target `cargo test`
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
        kill_and_reap(&mut child);
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
    /// arrives), so this hangs pre-fix (RED via timeout).
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
        // Hygiene: reap the orphaned sleepers we own (best effort —
        // they self-exit after 30 s regardless).
        for line in pids.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                // SAFETY: SIGKILL to a recorded direct grandchild pid.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
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
