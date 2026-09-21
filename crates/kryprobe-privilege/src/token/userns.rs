// SPDX-License-Identifier: GPL-3.0-or-later
//! BPF token mint inside a child user namespace: the kernel-selftest
//! split flow (T17).
//!
//! WHY a child userns: the kernel refuses `BPF_TOKEN_CREATE` from the
//! initial user namespace with EOPNOTSUPP by design (sole site in
//! `kernel/bpf/token.c`), so minting in the caller's (init) namespace
//! fails on every host. The mint syscall must execute inside a
//! non-init userns.
//!
//! WHY the split (child fsopen, parent mount, child mint): `fsopen`
//! pins the new superblock's ownership to the opener's userns, and
//! `BPF_TOKEN_CREATE` checks the minter's userns against the bpffs
//! superblock's. An init-ns `fsopen` followed by a child mint would
//! fail with EPERM (userns mismatch), so the child opens the fs
//! context itself, the privileged parent configures and mounts it,
//! and the child mints on the resulting dir fd. This mirrors the
//! kernel selftest sequence (`create_and_enter_userns`, fsopen in the
//! new ns, configure, mount, `token_create`).
//!
//! Transport: a `SOCK_SEQPACKET` socketpair (datagram boundaries
//! preserved) with `SCM_RIGHTS` fd passing. Message kinds are one
//! leading byte: `R` ready, `G` go, `S` +fs fd, `D` +dir fd,
//! `K` +token fd +u64 userns inode, `E` +errno +stage (child errors).
//! The parent writes the child's `uid_map`/`gid_map` ("0 65534 1",
//! each in exactly one `write(2)`, `setgroups` denied first), so
//! in-ns root is outer `nobody`; the child never proceeds before the
//! parent's `G`, and strict request/response alternation plus
//! EOF-on-drop means neither side can hang: every error path closes
//! or transfers each fd exactly once and reaps the child.
//!
//! T18: the parent pins the mint ns via `/proc/<pid>/ns/user` while
//! the child is deterministically alive (blocked awaiting `D`), so
//! the smoke worker can join the SAME ns the token was minted in
//! (token USE is `ns_capable`-bound to the mint ns).

use super::TokenError;
use super::mint::instantiate_bpffs;
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{BPF_TOKEN_CREATE, TokenAttr, bpf, last_errno};
use core::ffi::{c_char, c_void};
use std::ffi::CString;
use std::os::fd::RawFd;

/// Child unshared + mapped-handshake pending: "ready for id maps".
const KIND_READY: u8 = b'R';
/// Parent finished the id maps: "proceed to fsopen".
const KIND_GO: u8 = b'G';
/// Carries the fs-context fd (opened in the mint userns).
const KIND_FS: u8 = b'S';
/// Carries the mounted bpffs root dir fd.
const KIND_DIR: u8 = b'D';
/// Carries the token fd + the minter's userns inode (`u64`, native-endian).
const KIND_TOKEN: u8 = b'K';
/// Child failure: `errno` (`i32`, native-endian) + stage id byte.
const KIND_ERROR: u8 = b'E';

/// `KIND_ERROR` stage ids. These ride in the error message's stage
/// slot (byte 5), NOT the kind slot (byte 0), so their overlap with
/// the `KIND_*` byte values is intentional, not a collision.
const STAGE_UNSHARE: u8 = b'U';
const STAGE_HANDSHAKE: u8 = b'G';
const STAGE_DROP: u8 = b'P';
const STAGE_FSOPEN: u8 = b'F';
const STAGE_SEND_FS: u8 = b'S';
const STAGE_RECV_DIR: u8 = b'D';
const STAGE_NS_READ: u8 = b'N';
const STAGE_TOKEN: u8 = b'T';

/// `KIND_TOKEN` payload length: kind + `u64` inode.
const TOKEN_MSG_LEN: usize = 9;
/// `KIND_ERROR` payload length: kind + `i32` errno + stage.
const ERROR_MSG_LEN: usize = 6;
/// Largest payload any message carries (`KIND_TOKEN`).
const MAX_PAYLOAD: usize = 16;

/// Manual `cmsghdr` layout, mirroring `scm.rs` (64-bit Linux only).
const CMSG_HDRLEN: usize = 16;
/// `CMSG_LEN(sizeof(int))`: header + one fd.
const CMSG_LEN: usize = 20;
/// `CMSG_SPACE(sizeof(int))`: length rounded up to alignment.
const CMSG_SPACE: usize = 24;

/// Compile-time pin of the manual cmsg layout (64-bit Linux only).
const _: () = assert!(size_of::<libc::cmsghdr>() == CMSG_HDRLEN, "cmsghdr layout");

/// One received datagram. Ownership: `fd` is an open, solely-owned fd
/// iff `>= 0`; every consumer below either wraps it in an `OwnedFd`
/// or closes it before returning, so no path leaks.
#[derive(Debug)]
struct Datagram {
    len: usize,
    fd: RawFd,
    bytes: [u8; MAX_PAYLOAD],
}

/// Child stage id (from a `KIND_ERROR` message) to parent stage name.
/// Token-create keeps the historic `"token-create"` stage so the
/// honest-denial mapping (EOPNOTSUPP/EPERM/EACCES) is unchanged.
fn child_stage_name(id: u8) -> &'static str {
    match id {
        STAGE_UNSHARE => "userns-unshare",
        STAGE_HANDSHAKE => "userns-handshake",
        STAGE_DROP => "userns-drop",
        STAGE_FSOPEN => "userns-fsopen",
        STAGE_SEND_FS => "userns-send-fs",
        STAGE_RECV_DIR => "userns-recv-dir",
        STAGE_NS_READ => "userns-ns-read",
        STAGE_TOKEN => "token-create",
        b'K' => "userns-send-token",
        _ => "userns-child",
    }
}

/// Sends one datagram with an optional fd. Stack buffers only, so the
/// post-fork child may call this (async-signal-safe syscalls only).
fn send_msg(sock: RawFd, payload: &[u8], fd: RawFd) -> Result<(), TokenError> {
    let mut cmsg = [0u8; CMSG_SPACE];
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 1,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    msg.msg_iov = std::ptr::addr_of!(iov).cast_mut();
    if fd >= 0 {
        cmsg[0..8].copy_from_slice(&CMSG_LEN.to_ne_bytes());
        cmsg[8..12].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
        cmsg[12..16].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
        cmsg[16..20].copy_from_slice(&fd.to_ne_bytes());
        msg.msg_control = cmsg.as_mut_ptr().cast();
        msg.msg_controllen = CMSG_SPACE;
    }
    // SAFETY: msg borrows live iov/cmsg/payload; copied synchronously.
    let rc = unsafe { libc::sendmsg(sock, &msg, 0) };
    // `SOCK_SEQPACKET` sends whole datagrams or fails: a short count
    // is a protocol violation, never a partial send to resume.
    let ok = usize::try_from(rc).is_ok_and(|n| n == payload.len());
    if !ok {
        return Err(TokenError::Denied {
            stage: "userns-send",
            errno: last_errno(),
        });
    }
    Ok(())
}

/// The cmsg header as `(cmsg_len, level, type)` (64-bit Linux layout).
fn cmsg_header(cmsg: &[u8; CMSG_SPACE]) -> (usize, i32, i32) {
    (
        usize::from_ne_bytes([
            cmsg[0], cmsg[1], cmsg[2], cmsg[3], cmsg[4], cmsg[5], cmsg[6], cmsg[7],
        ]),
        i32::from_ne_bytes([cmsg[8], cmsg[9], cmsg[10], cmsg[11]]),
        i32::from_ne_bytes([cmsg[12], cmsg[13], cmsg[14], cmsg[15]]),
    )
}

/// Closes every fd number a truncated datagram's control buffer
/// reports. Only slots fully present in the RECEIVED bytes are touched
/// (the claimed length only narrows: padding past it is never offered
/// to `close`), and only when the header names `SCM_RIGHTS`. A mangled
/// header has no trustworthy fd numbers to close; the kernel drops
/// undelivered fds on control truncation anyway, so those need no close.
/// Child-safe (`close` only).
fn close_reported_fds(cmsg: &[u8; CMSG_SPACE], controllen: usize) {
    if controllen < CMSG_LEN {
        return;
    }
    let (len_field, level, kind) = cmsg_header(cmsg);
    if level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
        return;
    }
    // Received bytes bound the slots (the `min` keeps this panic-free
    // even if the kernel ever reported more than the passed buffer);
    // the claimed length narrows past padding (a one-fd cmsg arrives in
    // 24 bytes but claims only one fd slot — the padding must never be
    // closed, it decodes to stdin).
    let avail = controllen.min(CMSG_SPACE).saturating_sub(CMSG_HDRLEN);
    let claimed = len_field.saturating_sub(CMSG_HDRLEN);
    let slots = avail.min(claimed) / 4;
    for i in 0..slots {
        let off = CMSG_HDRLEN + 4 * i;
        let fd = i32::from_ne_bytes([cmsg[off], cmsg[off + 1], cmsg[off + 2], cmsg[off + 3]]);
        close_stray(fd);
    }
}

/// Receives one datagram. Stack buffers only; child-safe like
/// [`send_msg`]. Truncation fails closed: `MSG_TRUNC` (payload larger
/// than [`MAX_PAYLOAD`]) or `MSG_CTRUNC` (control larger than one fd)
/// is a protocol violation, never a short datagram to accept. A
/// truncated datagram can still carry installed fds (measured: the
/// kernel installs every fd whose bytes fit), so reported slots are
/// closed on the error path via [`close_reported_fds`], never leaked.
fn recv_msg(sock: RawFd) -> Result<Datagram, TokenError> {
    let mut cmsg = [0u8; CMSG_SPACE];
    let mut bytes = [0u8; MAX_PAYLOAD];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg.as_mut_ptr().cast(),
        msg_controllen: CMSG_SPACE,
        msg_flags: 0,
    };
    // `MSG_CMSG_CLOEXEC`: receipts (fs/token fds) are CLOEXEC at
    // creation, so they can never leak through a later exec (spawn
    // discipline); the child end never execs either way.
    // SAFETY: msg borrows live iov/cmsg; kernel fills them synchronously.
    let rc = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if rc < 0 {
        return Err(TokenError::Denied {
            stage: "userns-recv",
            errno: last_errno(),
        });
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        close_reported_fds(&cmsg, msg.msg_controllen);
        return Err(TokenError::Denied {
            stage: "userns-trunc",
            errno: libc::EPROTO,
        });
    }
    let len = usize::try_from(rc).map_err(|_| TokenError::Denied {
        stage: "userns-recv",
        errno: libc::EPROTO,
    })?;
    let mut fd = -1;
    if msg.msg_controllen >= CMSG_LEN {
        let (len_field, level, kind) = cmsg_header(&cmsg);
        if len_field != CMSG_LEN || level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
            return Err(TokenError::Denied {
                stage: "userns-cmsg",
                errno: libc::EPROTO,
            });
        }
        fd = i32::from_ne_bytes([cmsg[16], cmsg[17], cmsg[18], cmsg[19]]);
        if fd < 0 {
            return Err(TokenError::Denied {
                stage: "userns-fd",
                errno: libc::EPROTO,
            });
        }
    }
    Ok(Datagram { len, fd, bytes })
}

/// Closes an attached fd that a message should not have carried.
/// Async-signal-safe (`close` only): shared by parent and child.
fn close_stray(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: `fd` is open and solely owned by this datagram.
        unsafe {
            libc::close(fd);
        }
    }
}

/// Validates a plain (fd-less, 1-byte) message; a stray fd is closed,
/// never leaked. Child-safe (see [`close_stray`]).
fn expect_plain(dg: &Datagram, kind: u8, stage: &'static str) -> Result<(), TokenError> {
    if dg.fd >= 0 || dg.len != 1 || dg.bytes[0] != kind {
        close_stray(dg.fd);
        return Err(TokenError::Denied {
            stage,
            errno: libc::EPROTO,
        });
    }
    Ok(())
}

/// Folds a child `KIND_ERROR` message into its typed error, closing a
/// stray fd. Returns `None` for non-error messages (fd untouched, for
/// the caller's own validation). Child-safe.
fn child_error(dg: &Datagram) -> Option<TokenError> {
    if dg.len != ERROR_MSG_LEN || dg.bytes[0] != KIND_ERROR {
        return None;
    }
    close_stray(dg.fd);
    let errno = i32::from_ne_bytes([dg.bytes[1], dg.bytes[2], dg.bytes[3], dg.bytes[4]]);
    Some(TokenError::Denied {
        stage: child_stage_name(dg.bytes[5]),
        errno,
    })
}

/// Parses a `/proc/self/ns/user` link target (`user:[4026531837]`) to
/// its inode. Pure (no syscalls, no allocation): shared by parent and
/// child, unit-tested below.
fn parse_userns_link(bytes: &[u8]) -> Option<u64> {
    let rest = bytes.strip_prefix(b"user:[")?;
    let digits = rest.strip_suffix(b"]")?;
    if digits.is_empty() {
        return None;
    }
    let mut ino = 0u64;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        ino = ino.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(ino)
}

/// The caller's own userns inode (parent side).
fn own_userns_inode() -> Result<u64, TokenError> {
    let mut buf = [0u8; 64];
    // SAFETY: `buf` is a live out-param of the passed length.
    let rc = unsafe {
        libc::readlink(
            c"/proc/self/ns/user".as_ptr(),
            buf.as_mut_ptr().cast::<c_char>(),
            buf.len(),
        )
    };
    if rc <= 0 {
        return Err(TokenError::Denied {
            stage: "userns-self",
            errno: last_errno(),
        });
    }
    // `readlink` guarantees `rc <= bufsiz`; the `min` keeps the slice
    // panic-free even if that contract ever broke (fail closed below).
    let n = usize::try_from(rc).unwrap_or(0).min(buf.len());
    parse_userns_link(&buf[..n]).ok_or(TokenError::Denied {
        stage: "userns-self",
        errno: libc::EPROTO,
    })
}

/// Best-effort child error report (send failures are ignored: the
/// parent observes EOF/short reads fail-closed anyway). Child-safe.
fn send_err(sock: RawFd, errno: i32, stage: u8) {
    let mut msg = [0u8; ERROR_MSG_LEN];
    msg[0] = KIND_ERROR;
    msg[1..5].copy_from_slice(&errno.to_ne_bytes());
    msg[5] = stage;
    let _ = send_msg(sock, &msg, -1);
}

/// Child failure path: report `errno` + `STAGE_*` to the parent,
/// then exit 1. Diverging (`-> !`) so an error site can never emit
/// a report without exiting (or exit without reporting). Child-safe.
fn fail(sock: RawFd, stage: u8, errno: i32) -> ! {
    send_err(sock, errno, stage);
    // SAFETY: terminal child exit; no cleanup runs.
    unsafe { libc::_exit(1) }
}

/// The mint child: unshares, fsopens, and mints. Runs post-fork with
/// NO exec, so (like `spawn.rs`'s child) it calls ONLY
/// async-signal-safe functions — raw syscalls, stack buffers, `_exit`
/// — never allocation, stdio, or locks. `sock` is the child's
/// socketpair end; the parent's end is already closed.
fn child_main(sock: RawFd) -> ! {
    // New userns (the TOKEN_CREATE gate) plus a mountns (isolation for
    // the fs context; the parent's fsmount is detached, never attached
    // anywhere, so no mount table is touched either way).
    // SAFETY: unshare takes flags only.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        fail(sock, STAGE_UNSHARE, last_errno());
    }
    // Ready: the parent now writes our id maps, then sends `G`. We
    // must not fsopen before the maps exist (unmapped ids own nothing).
    if send_msg(sock, &[KIND_READY], -1).is_err() {
        // SAFETY: terminal child exit; no cleanup runs.
        unsafe { libc::_exit(1) };
    }
    let go_ok = recv_msg(sock)
        .map(|dg| expect_plain(&dg, KIND_GO, "userns-handshake").is_ok())
        .unwrap_or(false);
    if !go_ok {
        fail(sock, STAGE_HANDSHAKE, libc::EPROTO);
    }
    // Drop to in-ns root (= outer NOBODY under the parent's
    // "0 65534 1" maps): the minter keeps ns privilege for the mint
    // but owns no outer identity. No `setgroups`: the parent wrote
    // "deny" for us, so it would fail EPERM here (probed). The unshare
    // above ran as root, so no unprivileged-userns lockdown applies.
    // SAFETY: setgid/setuid take ids only; no syscalls intervene
    // before the errno below is captured.
    if unsafe { libc::setgid(0) } != 0 || unsafe { libc::setuid(0) } != 0 {
        fail(sock, STAGE_DROP, last_errno());
    }
    // `fsopen` HERE, in the new userns: this pins superblock ownership
    // to the mint ns. An init-ns fsopen would EPERM the mint below.
    let fs = match super::mint::fsopen_bpf() {
        Ok(fs) => fs,
        Err(TokenError::Denied { errno, .. }) => {
            fail(sock, STAGE_FSOPEN, errno);
        }
        Err(_) => {
            fail(sock, STAGE_FSOPEN, libc::EPROTO);
        }
    };
    if send_msg(sock, &[KIND_FS], fs.as_raw_fd()).is_err() {
        drop(fs);
        fail(sock, STAGE_SEND_FS, libc::EPROTO);
    }
    // The parent holds its own copy now; close before minting.
    drop(fs);
    // The configured bpffs root dir fd from the parent.
    let dir = match recv_msg(sock) {
        Ok(dg) if dg.len == 1 && dg.bytes[0] == KIND_DIR && dg.fd >= 0 => dg.fd,
        Ok(dg) => {
            close_stray(dg.fd);
            fail(sock, STAGE_RECV_DIR, libc::EPROTO);
        }
        Err(_) => {
            fail(sock, STAGE_RECV_DIR, libc::EPROTO);
        }
    };
    // Observe our userns inode immediately before the mint: the parent
    // pins the ordering on this (mint outside the caller's userns).
    let mut ns_buf = [0u8; 64];
    // SAFETY: `ns_buf` is a live out-param of the passed length.
    let ns_len = unsafe {
        libc::readlink(
            c"/proc/self/ns/user".as_ptr(),
            ns_buf.as_mut_ptr().cast::<c_char>(),
            ns_buf.len(),
        )
    };
    let ns_len = usize::try_from(ns_len).unwrap_or(0).min(ns_buf.len());
    let ino = parse_userns_link(&ns_buf[..ns_len]);
    let Some(ino) = ino else {
        // SAFETY: `dir` is open and owned here.
        unsafe { libc::close(dir) };
        fail(sock, STAGE_NS_READ, libc::EPROTO);
    };
    let mut attr = TokenAttr {
        flags: 0,
        bpffs_fd: dir as u32,
    };
    // SAFETY: `attr` is a live stack struct; size matches its type.
    let ret = unsafe {
        bpf(
            BPF_TOKEN_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<TokenAttr>() as u32,
        )
    };
    // Capture BEFORE closing `dir`: even a benign syscall between the
    // mint and the read could clobber the errno this reports.
    let ret_errno = last_errno();
    // SAFETY: `dir` is open and owned here.
    unsafe {
        libc::close(dir);
    }
    // Syscall fds fit `RawFd` by construction; anything else fails closed.
    let token = RawFd::try_from(ret).unwrap_or(-1);
    if token < 0 {
        fail(sock, STAGE_TOKEN, ret_errno);
    }
    let mut msg = [0u8; TOKEN_MSG_LEN];
    msg[0] = KIND_TOKEN;
    msg[1..9].copy_from_slice(&ino.to_ne_bytes());
    if send_msg(sock, &msg, token).is_err() {
        // SAFETY: `token` is open and owned here.
        unsafe { libc::close(token) };
        // SAFETY: terminal child exit; no cleanup runs.
        unsafe { libc::_exit(1) };
    }
    // SAFETY: `token` is open; the parent holds its own copy now.
    unsafe {
        libc::close(token);
    }
    // SAFETY: terminal child exit; no cleanup runs.
    unsafe { libc::_exit(0) };
}

/// `SOCK_SEQPACKET` pair: datagram boundaries preserved, `CLOEXEC` so
/// no later exec (the smoke worker spawn) can inherit these.
fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd), TokenError> {
    let mut pair = [0; 2];
    // SAFETY: valid out-param pair; both fds owned on success.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(TokenError::Denied {
            stage: "userns-socketpair",
            errno: last_errno(),
        });
    }
    // SAFETY: freshly returned owned fds.
    unsafe { Ok((OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1]))) }
}

/// Writes one id-map file for the child pid. Exactly ONE `write(2)`:
/// `uid_map`/`gid_map` accept a single write total (a second returns
/// EPERM even as root), so the whole mapping goes in one call.
fn write_id_map(
    pid: i32,
    file: &'static str,
    content: &[u8],
    stage: &'static str,
) -> Result<(), TokenError> {
    let path = format!("/proc/{pid}/{file}");
    let cstr = CString::new(path).map_err(|_| TokenError::BadFd)?;
    // SAFETY: `O_WRONLY` open; fd owned below and closed on all paths.
    // `O_CLOEXEC` (spawn discipline): short-lived, but no reason to
    // leave it inheritable.
    let fd = unsafe { libc::open(cstr.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(TokenError::Denied {
            stage,
            errno: last_errno(),
        });
    }
    // SAFETY: `content` is live; single write, then unconditional close.
    let rc = unsafe { libc::write(fd, content.as_ptr().cast::<c_void>(), content.len()) };
    let errno = last_errno();
    // SAFETY: `fd` is open and owned here.
    unsafe {
        libc::close(fd);
    }
    if !usize::try_from(rc).is_ok_and(|n| n == content.len()) {
        return Err(TokenError::Denied { stage, errno });
    }
    Ok(())
}

/// Opens the mint child's live userns. Call exactly at `S`-receipt:
/// the child is deterministically alive then (blocked awaiting `D`),
/// and the returned fd pins the ns after the child exits, so the
/// smoke worker can join it. `CLOEXEC`: the worker must never
/// inherit the join handle.
fn open_child_userns(pid: i32) -> Result<OwnedFd, TokenError> {
    let path = format!("/proc/{pid}/ns/user");
    let cstr = CString::new(path).map_err(|_| TokenError::BadFd)?;
    // SAFETY: read-only open; fd owned below on success.
    let fd = unsafe { libc::open(cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(TokenError::Denied {
            stage: "userns-ns-open",
            errno: last_errno(),
        });
    }
    // SAFETY: freshly returned owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Reaps the mint child (EINTR-retried, mirroring `spawn.rs`). The
/// exit status itself is ignored: protocol messages are authoritative,
/// and a child that already delivered its token but died before
/// `_exit(0)` still minted a valid token.
fn reap(pid: i32) -> Result<(), TokenError> {
    let mut status = 0;
    loop {
        // SAFETY: waits for the direct child above; retries on EINTR.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(());
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(TokenError::Denied {
                stage: "userns-wait",
                errno,
            });
        }
    }
}

/// Where the mint syscall executed, for the ordering pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MintObservation {
    /// Userns inode the child observed immediately before minting.
    pub mint_userns: u64,
    /// Caller-side userns inode (init ns in the normal root flow).
    pub caller_userns: u64,
}

/// Split-flow mint output: the token fd, the pinned mint ns (for the
/// smoke worker to join), and where the mint ran (for the ordering pin).
pub(crate) struct MintOutput {
    pub token: OwnedFd,
    pub ns: OwnedFd,
    pub obs: MintObservation,
}

/// Parent side of the split flow: handshake, id maps, mount the
/// child's fs context, collect the token + mint observation. `sock`
/// is the parent's socketpair end; `pid` the mint child.
fn parent_protocol(sock: RawFd, pid: i32) -> Result<(OwnedFd, OwnedFd, u64), TokenError> {
    // `R`: the child unshared (or `E` if the unshare itself failed).
    let dg = recv_msg(sock)?;
    if let Some(err) = child_error(&dg) {
        return Err(err);
    }
    expect_plain(&dg, KIND_READY, "userns-ready")?;
    // Id maps: `setgroups` FIRST (`gid_map` requires "deny"), then one
    // single-write mapping each. Minimal "0 65534 1": in-ns root is
    // outer nobody (T18: minter and worker own no outer privilege).
    write_id_map(pid, "setgroups", b"deny", "userns-setgroups")?;
    write_id_map(pid, "uid_map", b"0 65534 1", "userns-uidmap")?;
    write_id_map(pid, "gid_map", b"0 65534 1", "userns-gidmap")?;
    send_msg(sock, &[KIND_GO], -1)?;
    // `S` + fs fd: configure + mount parent-side (delegate strings,
    // CREATE, fsmount, root dir fd), exactly as the direct mint did.
    let dg = recv_msg(sock)?;
    if let Some(err) = child_error(&dg) {
        return Err(err);
    }
    if dg.len != 1 || dg.bytes[0] != KIND_FS || dg.fd < 0 {
        close_stray(dg.fd);
        return Err(TokenError::Denied {
            stage: "userns-fs",
            errno: libc::EPROTO,
        });
    }
    // Pin the mint ns NOW: the child is blocked awaiting `D`, so this
    // cannot race its exit; the fd outlives the child below.
    let ns = open_child_userns(pid)?;
    // SAFETY: kernel-allocated fresh fd from the child, solely owned here.
    let fs = unsafe { OwnedFd::from_raw_fd(dg.fd) };
    let dir = instantiate_bpffs(&fs)?;
    drop(fs);
    send_msg(sock, &[KIND_DIR], dir.as_raw_fd())?;
    drop(dir);
    // `K` + token fd + mint-userns inode.
    let dg = recv_msg(sock)?;
    if let Some(err) = child_error(&dg) {
        return Err(err);
    }
    if dg.len != TOKEN_MSG_LEN || dg.bytes[0] != KIND_TOKEN || dg.fd < 0 {
        close_stray(dg.fd);
        return Err(TokenError::Denied {
            stage: "userns-token",
            errno: libc::EPROTO,
        });
    }
    let mint_userns = u64::from_ne_bytes([
        dg.bytes[1],
        dg.bytes[2],
        dg.bytes[3],
        dg.bytes[4],
        dg.bytes[5],
        dg.bytes[6],
        dg.bytes[7],
        dg.bytes[8],
    ]);
    if mint_userns == 0 {
        close_stray(dg.fd);
        return Err(TokenError::Denied {
            stage: "userns-token",
            errno: libc::EPROTO,
        });
    }
    // Same-ns pin: the pinned fd must be the ns the child minted in
    // (an nsfs fd's inode IS its namespace's inode).
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is a live out-param; `ns` is open.
    let stat_ok = unsafe { libc::fstat(ns.as_raw_fd(), &mut stat) } == 0;
    if !stat_ok || stat.st_ino as u64 != mint_userns {
        close_stray(dg.fd);
        return Err(TokenError::Denied {
            stage: "userns-ns-pin",
            errno: libc::EPROTO,
        });
    }
    // SAFETY: kernel-allocated fresh fd from the child, solely owned here.
    let token = unsafe { OwnedFd::from_raw_fd(dg.fd) };
    Ok((token, ns, mint_userns))
}

/// Mints a token via the split flow: the `BPF_TOKEN_CREATE` syscall
/// executes in a child user namespace, outside the caller's. Returns
/// the token fd, the pinned mint ns, plus where the mint ran (the
/// caller pins `mint_userns != caller_userns` fail-closed).
pub(crate) fn mint_token_via_userns() -> Result<MintOutput, TokenError> {
    let (parent_end, child_end) = seqpacket_pair()?;
    let caller_userns = own_userns_inode()?;
    // SAFETY: fork; parent runs the protocol below, child enters
    // `child_main` (async-signal-safe only) or `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(TokenError::Denied {
            stage: "userns-fork",
            errno: last_errno(),
        });
    }
    if pid == 0 {
        drop(parent_end);
        child_main(child_end.as_raw_fd());
    }
    drop(child_end);
    let result = parent_protocol(parent_end.as_raw_fd(), pid);
    // Drop the socket BEFORE the wait: a still-blocked child observes
    // EOF and exits, so the reap below cannot hang.
    drop(parent_end);
    let reaped = reap(pid);
    match (result, reaped) {
        (Ok((token, ns, mint_userns)), Ok(())) => Ok(MintOutput {
            token,
            ns,
            obs: MintObservation {
                mint_userns,
                caller_userns,
            },
        }),
        // The protocol error is authoritative; the reap already ran.
        (Err(err), _) => Err(err),
        // Mint delivered but the child vanished unreaped: fail closed
        // (the token fd drops here, never escapes unaccounted).
        (Ok(_), Err(err)) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userns_link_parse_cases() {
        assert_eq!(parse_userns_link(b"user:[4026531837]"), Some(4026531837));
        assert_eq!(parse_userns_link(b"user:[0]"), Some(0));
        assert_eq!(
            parse_userns_link(b"user:[18446744073709551615]"),
            Some(u64::MAX)
        );
        for bad in [
            b"".as_slice(),
            b"user:[]",
            b"user:[abc]",
            b"user:[12x]",
            b"mnt:[4026531837]",
            b"user:[4026531837",
            b"user:4026531837]",
            b"user:[18446744073709551616]",
        ] {
            assert_eq!(parse_userns_link(bad), None, "must reject {bad:?}");
        }
    }

    #[test]
    fn child_stage_names_cover_protocol_ids() {
        for (id, name) in [
            (b'U', "userns-unshare"),
            (b'G', "userns-handshake"),
            (b'P', "userns-drop"),
            (b'F', "userns-fsopen"),
            (b'S', "userns-send-fs"),
            (b'D', "userns-recv-dir"),
            (b'N', "userns-ns-read"),
            (b'T', "token-create"),
            (b'K', "userns-send-token"),
        ] {
            assert_eq!(child_stage_name(id), name);
        }
        assert_eq!(child_stage_name(b'?'), "userns-child");
    }

    /// The `STAGE_*` consts must keep their historic wire bytes: the
    /// parent decodes the stage slot with the same consts, so a drift
    /// would be self-consistent inside one binary yet break any
    /// cross-version reader of the error message.
    #[test]
    fn stage_consts_match_wire_bytes() {
        assert_eq!(
            (
                STAGE_UNSHARE,
                STAGE_HANDSHAKE,
                STAGE_DROP,
                STAGE_FSOPEN,
                STAGE_SEND_FS,
                STAGE_RECV_DIR,
                STAGE_NS_READ,
                STAGE_TOKEN,
            ),
            (b'U', b'G', b'P', b'F', b'S', b'D', b'N', b'T'),
        );
    }

    /// Payload + fd roundtrip over the seqpacket pair (unprivileged).
    #[test]
    fn msg_roundtrip_unprivileged_case() {
        let (a, b) = seqpacket_pair().expect("socketpair");
        // SAFETY: read-only probe fd, closed below.
        let probe = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(probe >= 0, "open /dev/null");
        let mut payload = [0u8; TOKEN_MSG_LEN];
        payload[0] = KIND_TOKEN;
        payload[1..9].copy_from_slice(&0x1122_3344_5566_7788u64.to_ne_bytes());
        send_msg(a.as_raw_fd(), &payload, probe).expect("send with fd");
        let dg = recv_msg(b.as_raw_fd()).expect("recv with fd");
        // SAFETY: `probe` is open and owned here; closed after the
        // receive so its number cannot be reused by `dg.fd` early.
        unsafe {
            libc::close(probe);
        }
        assert_eq!(dg.len, TOKEN_MSG_LEN);
        assert_eq!(dg.bytes[0], KIND_TOKEN);
        assert_eq!(
            u64::from_ne_bytes([
                dg.bytes[1],
                dg.bytes[2],
                dg.bytes[3],
                dg.bytes[4],
                dg.bytes[5],
                dg.bytes[6],
                dg.bytes[7],
                dg.bytes[8],
            ]),
            0x1122_3344_5566_7788u64
        );
        assert!(dg.fd >= 0 && dg.fd != probe);
        assert!(
            crate::fd::cloexec_flag_set(dg.fd),
            "mint-protocol receipts must be CLOEXEC (spawn discipline)"
        );
        // SAFETY: freshly received owned fd.
        let got = unsafe { OwnedFd::from_raw_fd(dg.fd) };
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `stat` is a live out-param; `got` is open.
        assert_eq!(unsafe { libc::fstat(got.as_raw_fd(), &mut stat) }, 0);
        drop(got);
        // Plain message the other way.
        send_msg(b.as_raw_fd(), &[KIND_GO], -1).expect("send plain");
        let dg = recv_msg(a.as_raw_fd()).expect("recv plain");
        expect_plain(&dg, KIND_GO, "test").expect("plain ok");
    }

    /// Counts `/proc/self/fd` entries pointing at `target`: a stray-fd
    /// leak probe scoped to one unique file, so parallel tests' fd
    /// churn cannot skew it (process-wide fd counts would flake).
    fn fd_refs_to(target: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok()?.path().read_link().ok())
                    .filter(|link| link == target)
                    .count()
            })
            .unwrap_or(0)
    }

    /// A uniquely-named scratch file whose fd refs the leak probe
    /// counts. The guard owns cleanup (RAII, including on failure).
    fn stray_probe_file(
        tag: &str,
    ) -> (kryprobe_testkit::TempDir, std::path::PathBuf, std::fs::File) {
        let scratch =
            kryprobe_testkit::TempDir::named(&format!("r3-stray-{tag}")).expect("stray probe dir");
        let path = scratch.path().join("probe.tmp");
        let file = std::fs::File::create(&path).expect("stray probe file");
        (scratch, path, file)
    }

    /// An over-long payload (`MSG_TRUNC`) with an attached fd fails
    /// closed (never a short datagram to accept) without leaking the
    /// stray fd. Unprivileged.
    #[test]
    fn recv_truncated_payload_fails_closed_without_leak_case() {
        let (a, b) = seqpacket_pair().expect("socketpair");
        let (_scratch, path, probe) = stray_probe_file("payload");
        let probe_fd = std::os::fd::AsRawFd::as_raw_fd(&probe);
        let before = fd_refs_to(&path);
        assert_eq!(before, 1, "one held probe ref");
        for _ in 0..16 {
            let big = [0xA5u8; MAX_PAYLOAD + 8];
            send_msg(a.as_raw_fd(), &big, probe_fd).expect("send oversized");
            let err = recv_msg(b.as_raw_fd()).unwrap_err();
            assert!(
                matches!(err, TokenError::Denied { stage, errno }
                    if stage == "userns-trunc" && errno == libc::EPROTO),
                "truncated payload must fail closed, got {err}"
            );
        }
        assert_eq!(
            fd_refs_to(&path),
            before,
            "truncated recvs must not leak fds"
        );
        drop(probe);
    }

    /// Overflowing control data (`MSG_CTRUNC`: three fds against the
    /// one-fd buffer) fails closed without leaking. Unprivileged.
    #[test]
    fn recv_truncated_control_fails_closed_without_leak_case() {
        let (a, b) = seqpacket_pair().expect("socketpair");
        let (_scratch, path, f0) = stray_probe_file("control");
        // Three opens of the same unique file: every stray copy the
        // kernel installs is countable via the link target.
        let f1 = f0.try_clone().expect("clone probe");
        let f2 = f0.try_clone().expect("clone probe");
        use std::os::fd::AsRawFd as _;
        let probes = [f0.as_raw_fd(), f1.as_raw_fd(), f2.as_raw_fd()];
        // Three fds need 32 control bytes against the 24-byte buffer.
        let mut cmsg = [0u8; 32];
        cmsg[0..8].copy_from_slice(&28usize.to_ne_bytes());
        cmsg[8..12].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
        cmsg[12..16].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
        for (i, fd) in probes.iter().enumerate() {
            cmsg[16 + 4 * i..20 + 4 * i].copy_from_slice(&fd.to_ne_bytes());
        }
        let byte = [KIND_GO];
        let iov = libc::iovec {
            iov_base: byte.as_ptr().cast_mut().cast(),
            iov_len: 1,
        };
        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::addr_of!(iov).cast_mut(),
            msg_iovlen: 1,
            msg_control: cmsg.as_mut_ptr().cast(),
            msg_controllen: cmsg.len(),
            msg_flags: 0,
        };
        let before = fd_refs_to(&path);
        assert_eq!(before, 3, "three held probe refs");
        for _ in 0..16 {
            // SAFETY: msg borrows live iov/cmsg; copied synchronously.
            let rc = unsafe { libc::sendmsg(a.as_raw_fd(), &msg, 0) };
            assert_eq!(rc, 1, "send 3-fd datagram");
            let err = recv_msg(b.as_raw_fd()).unwrap_err();
            assert!(
                matches!(err, TokenError::Denied { stage, errno }
                    if stage == "userns-trunc" && errno == libc::EPROTO),
                "truncated control must fail closed, got {err}"
            );
        }
        assert_eq!(
            fd_refs_to(&path),
            before,
            "truncated recvs must not leak fds"
        );
        drop((f0, f1, f2));
    }

    /// `close_reported_fds` closes exactly the claimed slots with
    /// bytes present: padding past the claimed length is never closed
    /// (it decodes to fd 0 = stdin for a one-fd cmsg), while every
    /// reported slot of a multi-fd cmsg is (the truncated-control test
    /// above pins the two-slot kernel delivery end to end).
    #[test]
    fn close_reported_fds_narrows_to_claimed_slots_case() {
        fn is_open(fd: RawFd) -> bool {
            // SAFETY: `F_GETFD` only reads flags.
            (unsafe { libc::fcntl(fd, libc::F_GETFD) }) >= 0
        }
        let (_scratch, path, keep) = stray_probe_file("slots");
        use std::os::fd::AsRawFd as _;
        let keep_fd = keep.as_raw_fd();
        // Slot fd: a second open of the probe file, closed by the helper.
        let doomed = std::fs::File::open(&path).expect("reopen probe");
        let doomed_fd = doomed.as_raw_fd();
        // Ownership passes to the helper's close below.
        std::mem::forget(doomed);
        // One-fd header claiming one slot; padding encodes the LIVE
        // canary: a padding-closing bug would kill `keep_fd`.
        let mut cmsg = [0u8; CMSG_SPACE];
        cmsg[0..8].copy_from_slice(&CMSG_LEN.to_ne_bytes());
        cmsg[8..12].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
        cmsg[12..16].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
        cmsg[16..20].copy_from_slice(&doomed_fd.to_ne_bytes());
        cmsg[20..24].copy_from_slice(&keep_fd.to_ne_bytes());
        close_reported_fds(&cmsg, CMSG_SPACE);
        // The slot close is pinned by the ref count below, not by
        // probing `doomed_fd`: closed numbers recycle process-wide
        // under parallel tests, so an `is_open` check there would flake.
        assert!(is_open(keep_fd), "padding past the claim must never close");
        assert_eq!(fd_refs_to(&path), 1, "exactly the canary survives");
        drop(keep);
    }

    /// The ns-join handle is CLOEXEC at creation (the worker must
    /// never inherit it); self-pid keeps this unprivileged-safe.
    #[test]
    fn child_userns_handle_is_cloexec_case() {
        let pid = i32::try_from(std::process::id()).expect("pid fits");
        let ns = open_child_userns(pid).expect("open own userns");
        assert!(
            crate::fd::cloexec_flag_set(ns.as_raw_fd()),
            "ns handle must be CLOEXEC"
        );
    }

    /// A nonexistent pid denies without touching anything real.
    #[test]
    fn id_map_write_invalid_pid_case() {
        let err = write_id_map(i32::MAX, "uid_map", b"0 0 1", "userns-uidmap").unwrap_err();
        assert!(
            matches!(err, TokenError::Denied { .. }),
            "bad pid must deny, got {err}"
        );
    }

    /// Regression pin for T17: the mint syscall must be observed
    /// outside the caller's userns. Root-only (needs the id maps);
    /// incapable kernels skip honestly via `Denied`.
    #[test]
    fn mint_observed_outside_caller_userns_case() {
        // SAFETY: idempotent getter.
        if unsafe { libc::geteuid() } != 0 {
            println!("SKIP: userns-mint ordering proof needs euid == 0");
            return;
        }
        let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let release = crate::probe::parse_kernel_release(raw.trim()).unwrap_or((0, 0));
        if release < (6, 9) {
            println!("SKIP: token delegation needs kernel 6.9+, have {release:?}");
            return;
        }
        match mint_token_via_userns() {
            Ok(output) => {
                assert_ne!(
                    output.obs.mint_userns, output.obs.caller_userns,
                    "mint must run outside the caller userns"
                );
                assert_ne!(output.obs.mint_userns, 0, "mint userns must be observed");
                assert_ne!(
                    output.obs.caller_userns, 0,
                    "caller userns must be observed"
                );
                // The pinned nsfd must be the mint ns itself.
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: `stat` is a live out-param; the ns fd is open.
                assert_eq!(
                    unsafe { libc::fstat(output.ns.as_raw_fd(), &mut stat) },
                    0,
                    "ns fd must fstat"
                );
                assert_eq!(
                    stat.st_ino as u64, output.obs.mint_userns,
                    "pinned ns must be the mint ns"
                );
                println!(
                    "PASS: mint userns {} outside caller userns {}",
                    output.obs.mint_userns, output.obs.caller_userns
                );
                drop(output);
            }
            Err(TokenError::Denied { errno, stage }) => {
                println!("SKIP: kernel denied split-flow mint at {stage} (errno {errno})");
            }
            Err(err) => panic!("mint failed dishonestly: {err}"),
        }
    }
}
