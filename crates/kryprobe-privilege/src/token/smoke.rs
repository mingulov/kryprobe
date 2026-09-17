// SPDX-License-Identifier: GPL-3.0-or-later
//! Whole token-smoke roundtrip as a library call (T10 extraction).
//!
//! Mint → pass the token over a socketpair → spawn the deprivileged
//! worker → assert a clean exit and zero leaked maps/programs. The T8
//! lane test and `kryprobe selftest token-smoke` share this path; the
//! only caller-side duties are privilege/kernel gating and skip policy.

use super::spawn::spawn_smoke_worker;
use super::{TokenAxes, TokenError};
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::last_errno;
use std::os::fd::BorrowedFd;
use std::path::Path;

use super::mint::{live_bpf_ids, mint_smoke_token};

fn socketpair() -> Result<(OwnedFd, OwnedFd), TokenError> {
    let mut pair = [0; 2];
    // SAFETY: valid out-param pair; both fds owned on success.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    if rc != 0 {
        return Err(TokenError::Denied {
            stage: "socketpair",
            errno: last_errno(),
        });
    }
    // SAFETY: freshly returned owned fds.
    unsafe { Ok((OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1]))) }
}

fn open_read(path: &Path, stage: &'static str) -> Result<OwnedFd, TokenError> {
    let cstr = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| TokenError::BadFd)?;
    // SAFETY: read-only open; fd owned below on success.
    let fd = unsafe { libc::open(cstr.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(TokenError::Denied {
            stage,
            errno: last_errno(),
        });
    }
    // SAFETY: freshly returned owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Runs the full roundtrip; returns the verified delegation axes.
/// Mint denials surface for caller skip policy; worker failures and
/// leaks are hard errors (never skips).
pub fn run_smoke_roundtrip(worker_exe: &Path, object: &Path) -> Result<TokenAxes, TokenError> {
    let token = mint_smoke_token()?;
    let (maps_before, progs_before) = live_bpf_ids()?;
    let (reader, writer) = socketpair()?;
    // SAFETY: borrowed for the send window; `writer` dropped right after.
    let sock = unsafe { BorrowedFd::borrow_raw(writer.as_raw_fd()) };
    token.send_via(sock)?;
    drop(writer);
    // Stable fd numbers for the child (libc-open: no CLOEXEC, survives exec).
    let exe = open_read(worker_exe, "open-worker")?;
    let obj = open_read(object, "open-object")?;
    let code = spawn_smoke_worker(exe.as_raw_fd(), reader.as_raw_fd(), obj.as_raw_fd())?;
    drop(reader);
    if code != 0 {
        return Err(TokenError::WorkerExit { code });
    }
    let (maps_after, progs_after) = live_bpf_ids()?;
    if maps_before != maps_after {
        return Err(TokenError::Leaked { kind: "maps" });
    }
    if progs_before != progs_after {
        return Err(TokenError::Leaked { kind: "progs" });
    }
    Ok(token.axes())
}
