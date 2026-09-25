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

/// Set when SIGINT arrives after [`install_sigint_flag`] (4B-M5): the
/// live tick loop polls this alongside the session stop flag, so an
/// interrupted capture finalizes and renders partial (exit 3) instead
/// of dying mid-capture with no evidence.
pub static SIGINT_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Records SIGINT arrival in [`SIGINT_SEEN`]: the only async-signal
/// work is one relaxed atomic store, which is signal-safe.
extern "C" fn sigint_flag(_sig: libc::c_int) {
    SIGINT_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Installs the SIGINT recorder ([`SIGINT_SEEN`]) with `SA_RESTART`
/// (in-flight syscalls resume; the tick loop observes the flag at
/// its next poll) and clears any stale arrival. Idempotent.
/// The CLI owns no `libc` (ADR-0002 Rule B) — signal handling lives
/// here behind this plain call.
pub fn install_sigint_flag() -> std::io::Result<()> {
    // SAFETY: zeroed `sigaction` (empty mask) + a signal-safe handler;
    // `sigaction` with valid args reports failure via its return.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sigint_flag as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// `CLOCK_MONOTONIC` now in nanoseconds (unprivileged; the ring-clock
/// domain — lifecycle session walls and the `finish` stop stamp).
/// The CLI owns no `libc` (ADR-0002 Rule B), so the syscall lives
/// here behind this plain call; the single unsafe site for both this
/// and the snapshot walls.
pub fn monotonic_ns() -> std::io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer; `CLOCK_MONOTONIC` is always supported.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((ts.tv_sec.max(0) as u64) * 1_000_000_000 + (ts.tv_nsec.max(0) as u64))
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

    #[test]
    fn sigint_install_raise_sets_flag() {
        // 4B-M5: the installed handler records arrival; the test
        // restores the default disposition + clears the flag so no
        // other test observes either.
        super::install_sigint_flag().expect("installs");
        assert!(!super::SIGINT_SEEN.load(std::sync::atomic::Ordering::Relaxed));
        // SAFETY: `raise` to self with a plain-flag handler installed.
        unsafe {
            assert_eq!(libc::raise(libc::SIGINT), 0);
        }
        assert!(super::SIGINT_SEEN.load(std::sync::atomic::Ordering::Relaxed));
        // SAFETY: restoring the default disposition, no handler state.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        super::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
