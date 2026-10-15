// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared spawn hygiene for helper integration tests.
//!
//! `std::process::Command` does NOT close non-CLOEXEC fds in the child:
//! anything the test process inherited (CI runner log pipes, daemon
//! sockets) reaches the helper, whose stdio-only attestation then
//! refuses with `helper_refused`. Every helper spawn in tests must call
//! [`scrub_inherited_fds`] first so the child starts clean, the way the
//! production launcher spawns it.

/// Mark every non-stdio fd close-on-exec so no inherited descriptor
/// leaks into spawned helpers.
///
/// Safe to call repeatedly and concurrently with sibling spawns: fds the
/// test harness itself opened are already CLOEXEC (re-marking is a
/// no-op), and only statically-inherited (ancestor) fds change state.
/// Vanished fds (closed by a racing sibling thread) are skipped: a
/// closed fd cannot leak.
pub fn scrub_inherited_fds() {
    scrub_inherited_fds_inner();
}

#[cfg(target_os = "linux")]
fn scrub_inherited_fds_inner() {
    let dir = match std::fs::read_dir("/proc/self/fd") {
        Ok(dir) => dir,
        Err(_) => return,
    };
    for entry in dir.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(fd) = name.parse::<std::os::unix::io::RawFd>() else {
            continue;
        };
        if fd <= 2 {
            continue;
        }
        // SAFETY: F_GETFD only reads the descriptor flags word; no
        // memory effects. A racing close surfaces as EBADF below.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            assert_vanished(fd, "F_GETFD");
            continue;
        }
        if flags & libc::FD_CLOEXEC == 0 {
            // SAFETY: F_SETFD only replaces the flags word read above;
            // no memory effects. A racing close surfaces as EBADF below.
            let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
            if rc != 0 {
                assert_vanished(fd, "F_SETFD");
            }
        }
    }
}

/// Panic unless `fd` vanished under us (closed by a racing sibling
/// thread): a closed fd cannot leak, but any other fcntl failure must
/// fail loudly instead of masking as a later `helper_refused`.
#[cfg(target_os = "linux")]
fn assert_vanished(fd: std::os::unix::io::RawFd, op: &str) {
    let err = std::io::Error::last_os_error();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EBADF),
        "{op} on fd {fd} failed unexpectedly: {err}"
    );
}

#[cfg(not(target_os = "linux"))]
fn scrub_inherited_fds_inner() {
    // No /proc/self/fd elsewhere, and the helper refuses there with
    // unsupported_environment before any fd check runs — so spawns
    // there cannot reach this path meaningfully. The regression suite
    // is gated Linux-only; nothing else calls this off Linux.
}
