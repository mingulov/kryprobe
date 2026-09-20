// SPDX-License-Identifier: GPL-3.0-or-later
//! BPF token plumbing: delegation axes, fd passing, tokenized loads (T8).
//!
//! A token is an operation scope, not target confinement (Phase A): it
//! carries which BPF commands/maps/programs/attach types the holder may
//! use. [`TokenHandle::axes`] is verified from the kernel at mint time
//! and again at receive time; any mismatch fails closed.

pub mod mint;
mod scm;
pub mod smoke;
mod spawn;
mod userns;

pub use mint::{MintedToken, live_bpf_ids, mint_smoke_token};
pub use smoke::run_smoke_roundtrip;
pub use spawn::spawn_smoke_worker;

use crate::bpfloader::{LoadedSpine, LoaderError};
use crate::fd::OwnedFd;
use crate::local::LocalPrivilegedAuthority;
use crate::probe::bpf_sys;
use kryprobe_core::ProgramId;
use kryprobe_core::authority::BpfLoadAuthority;
use std::ffi::CString;
use std::fmt;
use std::os::fd::{BorrowedFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Delegation axes from `allowed_*` fdinfo lines (all `0x`-hex `u64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenAxes {
    pub cmds: u64,
    pub maps: u64,
    pub progs: u64,
    pub attachs: u64,
}

impl TokenAxes {
    /// Exact axes the smoke lane delegates (Phase A gate: `map_create` +
    /// `prog_load`, array/percpu/ringbuf maps, kprobe progs, uprobe-multi).
    /// Live-verified (T17): each delegate name sets exactly `1 << type`,
    /// so maps is bits 2,6,27 (array, percpu_array, ringbuf).
    pub fn smoke_expected() -> Self {
        Self {
            cmds: 0x21,
            maps: 0x8000044,
            progs: 0x4,
            attachs: 0x1000000000000,
        }
    }
}

/// Fail-closed token errors: every variant carries stage or errno detail.
#[derive(Debug)]
pub enum TokenError {
    BadFd,
    Parse {
        field: &'static str,
    },
    Denied {
        stage: &'static str,
        errno: i32,
    },
    /// The smoke worker exited nonzero (never a skip).
    WorkerExit {
        code: i32,
    },
    /// BPF ids leaked across the roundtrip (`"maps"` or `"progs"`).
    Leaked {
        kind: &'static str,
    },
    /// BPF id scan aborted: host churned under the sweep (bound hit or
    /// ids went non-monotonic). Never a skip and never clean — the lane
    /// fails honestly instead of crying leak or false-clean.
    ScanAborted {
        stage: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFd => write!(f, "token fd out of range"),
            Self::Parse { field } => write!(f, "token fdinfo: bad {field}"),
            Self::Denied { stage, errno } => write!(f, "token {stage}: errno {errno}"),
            Self::WorkerExit { code } => write!(f, "smoke worker exited {code}"),
            Self::Leaked { kind } => write!(f, "smoke roundtrip leaked {kind}"),
            Self::ScanAborted { stage, reason } => {
                write!(f, "token {stage}: id scan aborted ({reason})")
            }
        }
    }
}

impl std::error::Error for TokenError {}

/// Parses the four `allowed_*` fdinfo lines; missing/malformed fails closed.
pub fn parse_token_fdinfo(text: &str) -> Result<TokenAxes, TokenError> {
    fn field(text: &str, key: &'static str) -> Result<u64, TokenError> {
        for line in text.lines() {
            let Some(rest) = line.strip_prefix(key) else {
                continue;
            };
            let value = rest
                .strip_prefix(':')
                .ok_or(TokenError::Parse { field: key })?
                .trim();
            let hex = value
                .strip_prefix("0x")
                .ok_or(TokenError::Parse { field: key })?;
            if hex.is_empty() {
                return Err(TokenError::Parse { field: key });
            }
            return u64::from_str_radix(hex, 16).map_err(|_| TokenError::Parse { field: key });
        }
        Err(TokenError::Parse { field: key })
    }
    Ok(TokenAxes {
        cmds: field(text, "allowed_cmds")?,
        maps: field(text, "allowed_maps")?,
        progs: field(text, "allowed_progs")?,
        attachs: field(text, "allowed_attachs")?,
    })
}

/// Parses the OUTER id of inner 0 from a `/proc/self/uid_map`-style
/// map: the middle field of the `inner == 0` line (`inner outer
/// count`). `None` when no line maps inner 0, or on ANY malformed
/// line (fail closed: the worker refuses when it cannot prove a
/// non-root outer identity).
pub fn parse_id_map_outer(text: &str) -> Option<u32> {
    let mut outer = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (inner, candidate, count) = (fields.next()?, fields.next()?, fields.next()?);
        if fields.next().is_some() {
            return None;
        }
        let inner = inner.parse::<u32>().ok()?;
        count.parse::<u32>().ok()?;
        let candidate = candidate.parse::<u32>().ok()?;
        if inner == 0 && outer.is_none() {
            outer = Some(candidate);
        }
    }
    outer
}

/// Reads live delegation axes for `fd` from `/proc/self/fdinfo`.
pub fn read_token_axes(fd: RawFd) -> Result<TokenAxes, TokenError> {
    if fd < 0 {
        return Err(TokenError::BadFd);
    }
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).map_err(|err| {
        TokenError::Denied {
            stage: "fdinfo",
            errno: err.raw_os_error().unwrap_or(libc::EIO),
        }
    })?;
    parse_token_fdinfo(&text)
}

/// An owned BPF token fd with its kernel-verified delegation axes.
#[derive(Debug)]
pub struct TokenHandle {
    fd: OwnedFd,
    axes: TokenAxes,
}

impl TokenHandle {
    /// Wraps a mint-time fd after verifying its live axes match `want`.
    pub(crate) fn verified(fd: OwnedFd, want: TokenAxes) -> Result<Self, TokenError> {
        let axes = read_token_axes(fd.as_raw_fd())?;
        if axes != want {
            return Err(TokenError::Denied {
                stage: "axes-mismatch",
                errno: libc::EPROTO,
            });
        }
        Ok(Self { fd, axes })
    }

    /// Kernel-verified delegation axes.
    pub fn axes(&self) -> TokenAxes {
        self.axes
    }

    /// Raw token fd for token-aware `bpf()` attrs (crate-internal: the
    /// fd must only reach syscalls, never be duplicated out).
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Sends this token fd over a unix socket via `SCM_RIGHTS`.
    pub fn send_via(&self, sock: BorrowedFd<'_>) -> Result<(), TokenError> {
        scm::send_fd(sock, self.fd.as_raw_fd())
    }

    /// Receives a token fd and verifies its live axes match `want`.
    pub fn recv_via(sock: BorrowedFd<'_>, want: TokenAxes) -> Result<Self, TokenError> {
        let fd = scm::recv_fd(sock)?;
        Self::verified(fd, want)
    }
}

/// Loads the spine object using `token` instead of privilege: the load
/// facet's token path, not a second loader.
pub fn load_with_token(
    object: &std::path::Path,
    token: &TokenHandle,
) -> Result<LoadedSpine, LoaderError> {
    let bytes = std::fs::read(object).map_err(|err| LoaderError::BadObject {
        reason: format!("cannot read {}: {err}", object.display()),
    })?;
    load_bytes_with_token(&bytes, token)
}

/// [`load_with_token`] for callers that already hold the object bytes
/// (the smoke worker receives the object over an fd, never a path).
pub fn load_bytes_with_token(
    bytes: &[u8],
    token: &TokenHandle,
) -> Result<LoadedSpine, LoaderError> {
    LocalPrivilegedAuthority.load_program_with_token(ProgramId::UprobeMultiSelfProbe, bytes, token)
}

/// `BPF_OBJ_GET` command id (pinned-token retrieval; the attr is the
/// 16-byte `{pathname, bpf_fd, file_flags}` prefix of `union bpf_attr`).
const BPF_OBJ_GET: u32 = 7;

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
///
/// Moved here from the CLI (1B-M7): the `bpf()` call and its errno
/// live behind the privilege boundary; callers render the errno.
pub fn obj_get(path: &Path) -> Result<std::fs::File, i32> {
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

#[cfg(test)]
mod tests {
    use super::obj_get;
    use super::parse_id_map_outer;

    #[test]
    fn obj_get_nul_path_is_inval_without_syscall() {
        // 1B-M7: NUL never reaches the kernel — unprivileged check.
        let bad = std::path::Path::new("/sys/fs/bpf/\0/x");
        assert_eq!(obj_get(bad).expect_err("NUL path refuses"), libc::EINVAL);
    }

    /// Outer-id extraction: the mint ns (`0 65534 1`) and init ns
    /// (`0 0 4294967295`) shapes, plus kernel column padding.
    #[test]
    fn id_map_outer_cases() {
        assert_eq!(parse_id_map_outer("0 65534 1\n"), Some(65534));
        assert_eq!(
            parse_id_map_outer("         0      65534          1\n"),
            Some(65534)
        );
        assert_eq!(parse_id_map_outer("0 0 4294967295\n"), Some(0));
        assert_eq!(parse_id_map_outer("0 1000 1"), Some(1000));
    }

    /// Malformed maps fail closed (`None` → worker refuses).
    #[test]
    fn id_map_outer_rejects_garbage() {
        for bad in [
            "",
            "\n",
            "0 65534\n",
            "0 65534 1 2\n",
            "0 bogus 1\n",
            "bogus 65534 1\n",
            "0 65534 bogus\n",
            "0 -1 1\n",
            "0 4294967296 1\n",
            // A garbage second line poisons the whole map, even when
            // the first line is well-formed (strict: every line parsed).
            "0 65534 1\nbogus\n",
            "0 65534 1\n1 2\n",
        ] {
            assert_eq!(parse_id_map_outer(bad), None, "must reject {bad:?}");
        }
    }

    /// T18-review: multi-line maps match the `inner == 0` line, not
    /// the first line; a map with no inner-0 line proves nothing.
    #[test]
    fn id_map_outer_matches_inner_zero_line() {
        assert_eq!(
            parse_id_map_outer("1 100000 1000\n0 65534 1\n"),
            Some(65534)
        );
        assert_eq!(
            parse_id_map_outer("0 65534 1\n1 100000 1000\n"),
            Some(65534)
        );
        assert_eq!(parse_id_map_outer("1 100000 1000\n2 200000 1000\n"), None);
    }
}
