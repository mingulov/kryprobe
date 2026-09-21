// SPDX-License-Identifier: GPL-3.0-or-later
//! Smoke-worker spawn: fork, join the mint ns, drop, `fexecve` (T18).
//!
//! Shared by the T8 lane test and `kryprobe selftest token-smoke`. The
//! child calls ONLY async-signal-safe functions before exec, so this is
//! safe under a multithreaded parent (test runner or CLI). The parent
//! never mutates its own environment: the worker marker travels in a
//! private `envp` built pre-fork, so no `setenv` race can occur.
//!
//! T18: the child joins the mint userns (`setns` while still root,
//! the only joiner the kernel allows in) and drops to in-ns root,
//! which the mint ns maps to outer `nobody` ("0 65534 1"). The worker
//! detects the joined ns and skips its own unshare (which a userns
//! lockdown would deny); its outer-identity gate still refuses any
//! outer-root execution.
//!
//! Fd-hygiene discipline (T16 B1/B11): the ENFORCEMENT is the child's
//! `close_range` sweep — after the join + drop, before `fexecve`, the
//! child closes every fd ≥ 3 except the three passed fds (image,
//! socket, object); any sweep failure `_exit`s 124 instead of execing
//! dirty. Without this the deprivileged worker would inherit every
//! non-CLOEXEC parent fd, INCLUDING the live token fd (still owned by
//! the mint guard across the spawn), bypassing the SCM_RIGHTS +
//! axes-verification path. Kernel floor 6.12 ⇒ `close_range` (5.9+)
//! is always present: no fallback, fail closed.
//!
//! CLOEXEC-by-default everywhere else is defense-in-depth, so a stray
//! fd can only ever leak INTO this spawn (where the sweep kills it),
//! never through a future exec elsewhere. Deliberate non-CLOEXEC
//! exceptions (all must survive this exec, all dropped right after):
//! the `socketpair` ends + image/object opens in `smoke.rs`. Pinned
//! CLOEXEC at creation: drain's map clone (`F_DUPFD_CLOEXEC`, B11),
//! the mint `SOCK_SEQPACKET` pair (`SOCK_CLOEXEC`), the ns-join handle
//! and id-map writers (`O_CLOEXEC`), the bpffs mount root
//! (`O_CLOEXEC`, `FSMOUNT_CLOEXEC`), every SCM_RIGHTS receipt
//! (`MSG_CMSG_CLOEXEC`, both `recvmsg` sites). Kernel-CLOEXEC by
//! construction (no flag needed): `bpf()` fds, `pidfd_open` fds.
//! `std` (`File`, `Command`) sets CLOEXEC on everything it opens.

use super::TokenError;
use crate::probe::bpf_sys::last_errno;
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

/// Worker marker, appended to the private `envp` (never the parent env).
const WORKER_MARKER: &CStr = c"KRYPROBE_SMOKE_WORKER=1";
/// Exit code when the mint-ns join itself fails (distinct from 126/127).
const EXIT_NS_FAILED: i32 = 125;
/// Exit code when the privilege drop itself fails (distinct from 127).
const EXIT_DROP_FAILED: i32 = 126;
/// Exit code when the fd-hygiene sweep itself fails (distinct from
/// 125/126/127): the child refuses to exec dirty.
const EXIT_FDS_FAILED: i32 = 124;

/// Spawns the smoke worker with `exe_fd` as its image, `sock_fd` carrying
/// the token, and `obj_fd` carrying the object bytes. Returns the worker
/// exit code; fork/wait failures fail closed.
/// Private `envp`: current entries plus the worker marker.
fn build_envp() -> Vec<*const libc::c_char> {
    unsafe extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }
    // Reading the table is safe (nothing in this codebase writes the
    // environment); the parent's own environment is never modified.
    // SAFETY: `environ` is a live NUL-terminated table; entries are only
    // borrowed until the child execs or exits.
    let mut envp: Vec<*const libc::c_char> = Vec::new();
    unsafe {
        let mut entry = std::ptr::addr_of_mut!(environ).read();
        while !entry.is_null() && !(*entry).is_null() {
            envp.push(*entry);
            entry = entry.add(1);
        }
    }
    envp.push(WORKER_MARKER.as_ptr());
    envp.push(std::ptr::null());
    envp
}

/// Sorted, deduped keep-list for [`close_stray_fds`]: the three
/// passed fds ≥ 3 as `(array, count)` (stdio is always kept, so the
/// 0..2 range and negatives are dropped here). Pure: unit-tested
/// below; the child runs it on a stack array only.
fn sorted_keep_fds(exe_fd: RawFd, sock_fd: RawFd, obj_fd: RawFd) -> ([u32; 3], usize) {
    let mut keeps = [exe_fd, sock_fd, obj_fd];
    keeps.sort_unstable();
    let mut out = [0u32; 3];
    let mut n = 0;
    for fd in keeps {
        let Ok(fd) = u32::try_from(fd) else {
            continue;
        };
        if fd < 3 || (n > 0 && out[n - 1] == fd) {
            continue;
        }
        out[n] = fd;
        n += 1;
    }
    (out, n)
}

/// Closes every fd ≥ 3 except the three passed fds, via `close_range`
/// over the gaps around the sorted keep-list. Async-signal-safe (a
/// stack-array sort + syscalls only — no allocation, no locks), so
/// the post-fork child may call it. `false` on ANY failure (fail
/// closed: the caller `_exit`s instead of execing dirty).
fn close_stray_fds(exe_fd: RawFd, sock_fd: RawFd, obj_fd: RawFd) -> bool {
    let (keeps, n) = sorted_keep_fds(exe_fd, sock_fd, obj_fd);
    let mut first: u32 = 3;
    for keep in &keeps[..n] {
        if *keep > first {
            // SAFETY: closes a live fd range; no out-params.
            if unsafe { libc::close_range(first, keep - 1, 0) } != 0 {
                return false;
            }
        }
        // Sorted ascending, so `first <= *keep`; `*keep <= i32::MAX`
        // (it converted from a `RawFd`), so `+ 1` cannot overflow.
        first = keep + 1;
    }
    // SAFETY: closes the tail range; no out-params.
    unsafe { libc::close_range(first, u32::MAX, 0) == 0 }
}

/// Spawns the smoke worker INSIDE the mint userns `ns_fd`: the
/// child joins the ns, drops to in-ns root (= outer nobody), and
/// execs the worker image. See the module docs for the ordering.
pub fn spawn_smoke_worker(
    exe_fd: RawFd,
    sock_fd: RawFd,
    obj_fd: RawFd,
    ns_fd: RawFd,
) -> Result<i32, TokenError> {
    // All allocation happens parent-side, before fork.
    // 1A-L1: fd numbers cannot contain NUL, so these never fail —
    // but the error type is `Result`, not panic-shaped (same
    // `BadFd` mapping as the sibling `userns.rs` CString sites).
    let argv0 = CString::new(format!("/proc/self/fd/{exe_fd}")).map_err(|_| TokenError::BadFd)?;
    let arg_sock = CString::new(sock_fd.to_string()).map_err(|_| TokenError::BadFd)?;
    let arg_obj = CString::new(obj_fd.to_string()).map_err(|_| TokenError::BadFd)?;
    let argv = [
        argv0.as_c_str(),
        c"--fd",
        arg_sock.as_c_str(),
        c"--object-fd",
        arg_obj.as_c_str(),
    ];
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());
    let envp = build_envp();
    // SAFETY: fork; parent waits below, child execs or `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(TokenError::Denied {
            stage: "fork",
            errno: last_errno(),
        });
    }
    if pid == 0 {
        // SAFETY: async-signal-safe only: setgroups (while still root
        // in the init ns: after `setns` it is EPERM, probed), then the
        // mint-ns join (root-only: the kernel admits no unprivileged
        // joiner), then the in-ns drop to 0 (= outer nobody), then the
        // fd-hygiene sweep (B1: without it the worker inherits the
        // live token fd), then fexecve or `_exit`. Every step checked:
        // a silent failed join, drop, or sweep would exec the worker
        // with the wrong identity or the wrong fds.
        unsafe {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                libc::_exit(EXIT_DROP_FAILED);
            }
            if libc::setns(ns_fd, libc::CLONE_NEWUSER) != 0 {
                libc::_exit(EXIT_NS_FAILED);
            }
            if libc::setgid(0) != 0 || libc::setuid(0) != 0 {
                libc::_exit(EXIT_DROP_FAILED);
            }
            if !close_stray_fds(exe_fd, sock_fd, obj_fd) {
                libc::_exit(EXIT_FDS_FAILED);
            }
            libc::fexecve(exe_fd, argv_ptr.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    loop {
        // SAFETY: waits for the direct child above; retries on EINTR.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        let errno = last_errno();
        if errno != libc::EINTR {
            return Err(TokenError::Denied {
                stage: "waitpid",
                errno,
            });
        }
    }
    if !libc::WIFEXITED(status) {
        return Err(TokenError::Denied {
            stage: "worker-signal",
            errno: libc::EPROTO,
        });
    }
    Ok(libc::WEXITSTATUS(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep-list shaping: sorted ascending, deduped, stdio-range and
    /// negative fds dropped (stdio is always kept, negatives kept out).
    #[test]
    fn keep_list_sorted_deduped_case() {
        assert_eq!(sorted_keep_fds(9, 5, 7), ([5, 7, 9], 3));
        assert_eq!(sorted_keep_fds(7, 7, 9), ([7, 9, 0], 2));
        assert_eq!(sorted_keep_fds(3, 4, 5), ([3, 4, 5], 3));
        assert_eq!(sorted_keep_fds(-1, 0, 2), ([0, 0, 0], 0));
        assert_eq!(sorted_keep_fds(-1, 1, 6), ([6, 0, 0], 1));
        assert_eq!(sorted_keep_fds(-1, -1, -1), ([0, 0, 0], 0));
    }

    /// End-to-end fd-hygiene proof (Linux): a forked child runs the
    /// REAL `close_stray_fds`, then inventories every fd number below
    /// the live `RLIMIT_NOFILE` with `fcntl(F_GETFD)` and exits 0 iff
    /// exactly stdio + the three keeps are open. A non-CLOEXEC marker
    /// fd — shaped like the pre-fix token fd — must NOT survive, and
    /// neither must any fd the test runner holds.
    ///
    /// The child calls ONLY async-signal-safe functions (a
    /// multithreaded test runner forbids allocation and locks
    /// post-fork): `close_range` via the real helper, `getrlimit`,
    /// `fcntl`, `_exit`. No `getdents` (that would need a new raw
    /// `libc::syscall` site, banned by ADR-0002 rule A). A limit above
    /// the scan cap fails LOUD (exit 14), never silently vacuous.
    #[test]
    #[cfg(target_os = "linux")]
    fn spawn_child_inherits_only_intended_fds() {
        // SAFETY: read-only stand-ins, closed below; deliberately NO
        // O_CLOEXEC, so this proves close_range, not the flag.
        let exe = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let sock = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let obj = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let marker = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(
            exe >= 3 && sock >= 3 && obj >= 3 && marker >= 3,
            "stand-ins must sit above stdio"
        );
        // SAFETY: fork; the child inventories then `_exit`s, the parent
        // reaps below.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: async-signal-safe only (see doc comment).
            unsafe {
                if !close_stray_fds(exe, sock, obj) {
                    libc::_exit(10);
                }
                // The kernel hands out no fd numbered at or above the
                // live `RLIMIT_NOFILE`, so probing below it is
                // exhaustive; the cap bounds the scan on absurd hosts.
                let mut rlim = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) != 0 {
                    libc::_exit(13);
                }
                const SCAN_MAX: u64 = 1 << 20;
                if rlim.rlim_cur > SCAN_MAX {
                    libc::_exit(14);
                }
                let mut seen = [false; 6];
                let mut ok = true;
                let mut fd: RawFd = 0;
                // `fd` stays below 2^20: the `+ 1` cannot overflow and
                // the `as u64` cannot wrap (fd is never negative).
                while (fd as u64) < rlim.rlim_cur {
                    // SAFETY: `F_GETFD` only reads flags.
                    let open = libc::fcntl(fd, libc::F_GETFD) >= 0;
                    if open {
                        if fd == 0 && !seen[0] {
                            seen[0] = true;
                        } else if fd == 1 && !seen[1] {
                            seen[1] = true;
                        } else if fd == 2 && !seen[2] {
                            seen[2] = true;
                        } else if fd == exe && !seen[3] {
                            seen[3] = true;
                        } else if fd == sock && !seen[4] {
                            seen[4] = true;
                        } else if fd == obj && !seen[5] {
                            seen[5] = true;
                        } else {
                            // Stray (the marker, a leaked runner fd):
                            // hygiene failed.
                            ok = false;
                            break;
                        }
                    }
                    fd += 1;
                }
                let pass = ok && seen.iter().all(|s| *s);
                libc::_exit(if pass { 0 } else { 1 });
            }
        }
        let mut status = 0;
        loop {
            // SAFETY: waits for the direct child above; retries on EINTR.
            let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
            if rc == pid {
                break;
            }
            assert_eq!(last_errno(), libc::EINTR, "waitpid failed");
        }
        // SAFETY: all four fds owned here, closed exactly once.
        unsafe {
            libc::close(exe);
            libc::close(sock);
            libc::close(obj);
            libc::close(marker);
        }
        assert!(libc::WIFEXITED(status), "child must exit");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child must inherit exactly stdio + the three keeps"
        );
    }

    #[test]
    fn envp_appends_marker_and_terminates() {
        let before = std::env::var("KRYPROBE_SMOKE_WORKER");
        let envp = build_envp();
        assert!(envp.len() >= 2, "envp must hold marker + NUL");
        assert!(envp[..envp.len() - 2].iter().all(|p| !p.is_null()));
        assert_eq!(envp[envp.len() - 2], WORKER_MARKER.as_ptr());
        assert!(envp[envp.len() - 1].is_null());
        // The parent's own environment is untouched by the builder.
        assert_eq!(std::env::var("KRYPROBE_SMOKE_WORKER"), before);
    }
}
