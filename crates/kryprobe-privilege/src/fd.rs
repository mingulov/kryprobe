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

    /// Duplicates the fd with `CLOEXEC` set atomically (`fcntl`
    /// `F_DUPFD_CLOEXEC`): the clone refers to the same file but never
    /// survives an `exec`. A plain `dup` would clear the flag (T16
    /// B11); see the fd-hygiene discipline in `token::spawn`.
    pub fn try_clone_cloexec(&self) -> std::io::Result<Self> {
        // SAFETY: `F_DUPFD_CLOEXEC` from lowest-free 0 returns a fresh
        // owned fd or -1.
        let dup = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: freshly returned owned fd.
        Ok(unsafe { Self::from_raw_fd(dup) })
    }
}

/// Whether `FD_CLOEXEC` is set on `fd` (test-only probe pinning the
/// per-site CLOEXEC flags of the spawn discipline).
#[cfg(test)]
pub(crate) fn cloexec_flag_set(fd: RawFd) -> bool {
    // SAFETY: `F_GETFD` only reads flags; -1 reads no flag.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    flags >= 0 && flags & libc::FD_CLOEXEC != 0
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLOEXEC clone refers to the same file and carries the flag
    /// (a plain `open` does not); the source guard keeps its own fd.
    #[test]
    fn try_clone_cloexec_case() {
        // SAFETY: read-only probe fd, solely owned from here.
        let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(raw >= 0, "open /dev/null");
        // SAFETY: `raw` is open and solely owned from here.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        assert!(
            !cloexec_flag_set(owned.as_raw_fd()),
            "plain open carries no CLOEXEC"
        );
        let clone = owned.try_clone_cloexec().expect("cloexec dup");
        assert_ne!(clone.as_raw_fd(), owned.as_raw_fd());
        assert!(
            cloexec_flag_set(clone.as_raw_fd()),
            "clone must carry CLOEXEC"
        );
        let ino = |fd: RawFd| {
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `stat` is a live out-param; fd is open.
            assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0);
            stat.st_ino
        };
        assert_eq!(
            ino(clone.as_raw_fd()),
            ino(owned.as_raw_fd()),
            "clone refers to the same file"
        );
    }

    /// A bad fd errors instead of forging a guard (fail closed).
    #[test]
    fn try_clone_cloexec_bad_fd_case() {
        // SAFETY: -1 is never dereferenced; fcntl fails first, and
        // `Drop` skips negative fds.
        let bad = unsafe { OwnedFd::from_raw_fd(-1) };
        assert!(bad.try_clone_cloexec().is_err(), "bad fd must fail");
        assert!(!cloexec_flag_set(-1), "bad fd reads no flag");
    }
}
