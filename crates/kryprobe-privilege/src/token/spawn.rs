// SPDX-License-Identifier: GPL-3.0-or-later
//! Smoke-worker spawn: fork, drop to `nobody`, `fexecve` (T10 extraction).
//!
//! Shared by the T8 lane test and `kryprobe selftest token-smoke`. The
//! child calls ONLY async-signal-safe functions before exec, so this is
//! safe under a multithreaded parent (test runner or CLI). The parent
//! never mutates its own environment: the worker marker travels in a
//! private `envp` built pre-fork, so no `setenv` race can occur.

use super::TokenError;
use crate::probe::bpf_sys::last_errno;
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

/// Unprivileged target user/group for the smoke worker (`nobody`).
const NOBODY: u32 = 65534;
/// Worker marker, appended to the private `envp` (never the parent env).
const WORKER_MARKER: &CStr = c"KRYPROBE_SMOKE_WORKER=1";
/// Exit code when the privilege drop itself fails (distinct from 127).
const EXIT_DROP_FAILED: i32 = 126;

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

pub fn spawn_smoke_worker(exe_fd: RawFd, sock_fd: RawFd, obj_fd: RawFd) -> Result<i32, TokenError> {
    // All allocation happens parent-side, before fork.
    let argv0 = CString::new(format!("/proc/self/fd/{exe_fd}")).expect("argv0 cstr");
    let arg_sock = CString::new(sock_fd.to_string()).expect("sock cstr");
    let arg_obj = CString::new(obj_fd.to_string()).expect("obj cstr");
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
        // SAFETY: async-signal-safe only: setgroups/setgid/setuid (all
        // checked: a silent failed drop would exec the worker with the
        // parent's privilege), then fexecve or `_exit`.
        unsafe {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(NOBODY) != 0
                || libc::setuid(NOBODY) != 0
            {
                libc::_exit(EXIT_DROP_FAILED);
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
