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
        // SAFETY: fcntl F_SETFD/F_GETFD on a numeric /proc/self/fd entry
        // touches only that descriptor's flags; no memory effects. A
        // racing close surfaces as EBADF, which means "already clean".
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            continue;
        }
        if flags & libc::FD_CLOEXEC == 0 {
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn scrub_inherited_fds_inner() {
    // No /proc/self/fd elsewhere; the helper's attestation is
    // Linux-only too, so spawns there cannot hit the fd check.
}
