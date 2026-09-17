// SPDX-License-Identifier: GPL-3.0-or-later
//! RAII file-descriptor guard: every BPF/object FD closes on all paths.
//!
//! `OwnedFd` owns one raw fd and closes it in `Drop`, so early returns
//! and error paths cannot leak descriptors. It is deliberately minimal
//! (no `std::os::fd::OwnedFd` alias) to keep close-semantics explicit.

use std::os::fd::{AsRawFd, RawFd};

/// Owns a raw file descriptor; closes it on drop.
#[derive(Debug)]
pub struct OwnedFd {
    fd: RawFd,
}

impl OwnedFd {
    /// Takes ownership of an open fd.
    ///
    /// # Safety
    ///
    /// The caller must guarantee `fd` is open, valid, and not owned
    /// elsewhere; this guard becomes the sole owner and will close it.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Borrows the raw descriptor without transferring ownership.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // Best effort: nothing to do with a close failure during drop.
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}
