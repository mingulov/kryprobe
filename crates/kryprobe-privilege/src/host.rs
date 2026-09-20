// SPDX-License-Identifier: GPL-3.0-or-later
//! Host identity and errno classifiers (1B-M7).
//!
//! The CLI renders host facts but must not name errnos or call `libc`
//! itself (ADR-0002 Rule B): euid checks and errno classification live
//! here behind typed/plain-bool APIs, and only real syscall errnos flow
//! back to renderers — nothing here invents one.

/// True when the process runs as root (euid 0).
#[must_use]
pub fn euid_is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

/// True for missing-path errnos (`ENOENT`/`ENOTDIR`): bad input paths.
#[must_use]
pub fn errno_is_missing(errno: i32) -> bool {
    errno == libc::ENOENT || errno == libc::ENOTDIR
}

/// True for refusal errnos (`EPERM`/`EACCES`/`EOPNOTSUPP`/`ENOTSUP`):
/// the kernel or filesystem refused the operation.
#[must_use]
pub fn errno_is_refused(errno: i32) -> bool {
    [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP, libc::ENOTSUP].contains(&errno)
}

/// True when an xattr read found no value (`ENODATA`): absent attribute.
#[must_use]
pub fn errno_is_absent_xattr(errno: i32) -> bool {
    errno == libc::ENODATA
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifiers_partition_common_errnos() {
        // Each classifier fires on its own errnos and stays silent on
        // the others' (a refusal must never read as missing input).
        for errno in [libc::ENOENT, libc::ENOTDIR] {
            assert!(errno_is_missing(errno));
            assert!(!errno_is_refused(errno));
            assert!(!errno_is_absent_xattr(errno));
        }
        for errno in [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP, libc::ENOTSUP] {
            assert!(!errno_is_missing(errno));
            assert!(errno_is_refused(errno));
            assert!(!errno_is_absent_xattr(errno));
        }
        assert!(!errno_is_missing(libc::ENODATA));
        assert!(!errno_is_refused(libc::ENODATA));
        assert!(errno_is_absent_xattr(libc::ENODATA));
        // Unrelated errnos classify nowhere (callers treat them as
        // internal failures, never as input/refusal).
        for errno in [libc::EIO, libc::EINVAL, 0] {
            assert!(!errno_is_missing(errno));
            assert!(!errno_is_refused(errno));
            assert!(!errno_is_absent_xattr(errno));
        }
    }

    #[test]
    fn euid_matches_libc() {
        // SAFETY: idempotent getter.
        assert_eq!(euid_is_root(), unsafe { libc::geteuid() } == 0);
    }
}
