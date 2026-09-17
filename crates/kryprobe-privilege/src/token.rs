// SPDX-License-Identifier: GPL-3.0-or-later
//! BPF token plumbing: delegation axes, fd passing, tokenized loads (T8).
//!
//! A token is an operation scope, not target confinement (Phase A): it
//! carries which BPF commands/maps/programs/attach types the holder may
//! use. [`TokenHandle::axes`] is verified from the kernel at mint time
//! and again at receive time; any mismatch fails closed.

pub mod mint;
mod scm;

pub use mint::{live_bpf_ids, mint_smoke_token};

use crate::bpfloader::{LoadedSpine, LoaderError, instantiate_with_token, parse_spine_object};
use crate::fd::OwnedFd;
use std::fmt;
use std::os::fd::{BorrowedFd, RawFd};

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
    pub fn smoke_expected() -> Self {
        Self {
            cmds: 0x21,
            maps: 0x8400044,
            progs: 0x4,
            attachs: 0x1000000000000,
        }
    }
}

/// Fail-closed token errors: every variant carries stage or errno detail.
#[derive(Debug)]
pub enum TokenError {
    BadFd,
    Parse { field: &'static str },
    Denied { stage: &'static str, errno: i32 },
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFd => write!(f, "token fd out of range"),
            Self::Parse { field } => write!(f, "token fdinfo: bad {field}"),
            Self::Denied { stage, errno } => write!(f, "token {stage}: errno {errno}"),
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

/// Loads the spine object using `token` instead of privilege: the shared
/// [`instantiate_with_token`] path, not a second loader.
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
    let parsed = parse_spine_object(bytes)?;
    instantiate_with_token(&parsed, Some(token.as_raw_fd()))
}
