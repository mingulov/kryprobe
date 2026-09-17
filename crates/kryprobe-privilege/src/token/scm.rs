// SPDX-License-Identifier: GPL-3.0-or-later
//! `SCM_RIGHTS` fd passing over unix sockets (T8).
//!
//! Manual `cmsghdr` layout (no libc CMSG helpers): on 64-bit Linux the
//! header is 16 bytes (`len:u64 level:i32 type:i32`), the fd sits at
//! offset 16, `cmsg_len` is 20, and the control buffer is 24 bytes.
//! The `size_of` assert guards the layout assumption at runtime.

use super::TokenError;
use crate::fd::OwnedFd;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

/// `sizeof(cmsghdr)` on 64-bit Linux; fd payload starts here.
const CMSG_HDRLEN: usize = 16;
/// `CMSG_LEN(sizeof(int))`: header + one fd.
const CMSG_LEN: usize = 20;
/// `CMSG_SPACE(sizeof(int))`: length rounded up to alignment.
const CMSG_SPACE: usize = 24;

/// Sends one fd over `sock` with a single payload byte.
pub(super) fn send_fd(sock: BorrowedFd<'_>, fd: RawFd) -> Result<(), TokenError> {
    assert_eq!(size_of::<libc::cmsghdr>(), CMSG_HDRLEN, "cmsghdr layout");
    let mut cmsg = [0u8; CMSG_SPACE];
    cmsg[0..8].copy_from_slice(&CMSG_LEN.to_ne_bytes());
    cmsg[8..12].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
    cmsg[12..16].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
    cmsg[16..20].copy_from_slice(&fd.to_ne_bytes());
    let byte = b"x";
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
        msg_controllen: CMSG_SPACE,
        msg_flags: 0,
    };
    // SAFETY: msg borrows live iov/cmsg; kernel copies synchronously.
    let rc = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
    if rc != 1 {
        return Err(TokenError::Denied {
            stage: "scm-send",
            errno: crate::probe::bpf_sys::last_errno(),
        });
    }
    Ok(())
}

/// Receives one fd; short reads and malformed cmsgs fail closed.
pub(super) fn recv_fd(sock: BorrowedFd<'_>) -> Result<OwnedFd, TokenError> {
    assert_eq!(size_of::<libc::cmsghdr>(), CMSG_HDRLEN, "cmsghdr layout");
    let closed = |stage: &'static str, errno: i32| TokenError::Denied { stage, errno };
    let mut cmsg = [0u8; CMSG_SPACE];
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
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
    // SAFETY: msg borrows live iov/cmsg; kernel fills them synchronously.
    let rc = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if rc < 0 {
        return Err(closed("scm-recv", crate::probe::bpf_sys::last_errno()));
    }
    if rc != 1 || msg.msg_controllen < CMSG_LEN {
        return Err(closed("scm-short", libc::EPROTO));
    }
    let len = usize::from_ne_bytes(cmsg[0..8].try_into().expect("len width"));
    let level = i32::from_ne_bytes(cmsg[8..12].try_into().expect("level width"));
    let kind = i32::from_ne_bytes(cmsg[12..16].try_into().expect("type width"));
    if len != CMSG_LEN || level != libc::SOL_SOCKET || kind != libc::SCM_RIGHTS {
        return Err(closed("scm-cmsg", libc::EPROTO));
    }
    let fd = i32::from_ne_bytes(cmsg[16..20].try_into().expect("fd width"));
    if fd < 0 {
        return Err(closed("scm-fd", libc::EPROTO));
    }
    // SAFETY: kernel-allocated fresh fd, solely owned from here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::{recv_fd, send_fd};
    use std::os::fd::BorrowedFd;

    /// The manual cmsg layout must roundtrip a real fd (runs unprivileged).
    #[test]
    fn fd_roundtrip_case() {
        let mut pair = [0; 2];
        // SAFETY: valid out-param pair; closed below.
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) },
            0
        );
        // SAFETY: borrowed for the call window; closed below.
        let (a, b) = unsafe {
            (
                BorrowedFd::borrow_raw(pair[0]),
                BorrowedFd::borrow_raw(pair[1]),
            )
        };
        // SAFETY: read-only probe fd, closed below.
        let probe = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(probe >= 0, "open /dev/null");
        send_fd(a, probe).expect("send fd");
        let got = recv_fd(b).expect("receive fd");
        assert!(got.as_raw_fd() >= 0 && got.as_raw_fd() != probe);
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `stat` is a live out-param; `got` is open.
        assert_eq!(unsafe { libc::fstat(got.as_raw_fd(), &mut stat) }, 0);
        drop(got);
        // SAFETY: all three fds owned here, closed exactly once.
        unsafe {
            libc::close(probe);
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
    }
}
