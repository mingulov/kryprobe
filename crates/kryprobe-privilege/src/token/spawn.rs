// SPDX-License-Identifier: GPL-3.0-or-later
//! Smoke-worker spawn: fork, drop to `nobody`, `fexecve` (T10 extraction).
//!
//! Shared by the T8 lane test and `kryprobe selftest token-smoke`. The
//! child calls ONLY async-signal-safe functions before exec, so this is
//! safe under a multithreaded parent (test runner or CLI).

use super::TokenError;
use crate::probe::bpf_sys::last_errno;
use std::os::fd::RawFd;

/// Spawns the smoke worker with `exe_fd` as its image, `sock_fd` carrying
/// the token, and `obj_fd` carrying the object bytes. Returns the worker
/// exit code; fork/wait failures fail closed.
pub fn spawn_smoke_worker(exe_fd: RawFd, sock_fd: RawFd, obj_fd: RawFd) -> Result<i32, TokenError> {
    unsafe extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }
    // All allocation happens parent-side, before fork.
    // SAFETY: unique var name no other thread touches; set once pre-fork.
    unsafe {
        std::env::set_var("KRYPROBE_SMOKE_WORKER", "1");
    }
    let argv0 = std::ffi::CString::new(format!("/proc/self/fd/{exe_fd}")).expect("argv0 cstr");
    let arg_sock = std::ffi::CString::new(sock_fd.to_string()).expect("sock cstr");
    let arg_obj = std::ffi::CString::new(obj_fd.to_string()).expect("obj cstr");
    let argv = [
        argv0.as_c_str(),
        c"--fd",
        arg_sock.as_c_str(),
        c"--object-fd",
        arg_obj.as_c_str(),
    ];
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());
    // SAFETY: one pointer-sized read of the process environment table.
    let envp = unsafe { std::ptr::addr_of_mut!(environ).read() };
    // SAFETY: fork; parent waits below, child execs or `_exit`s.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(TokenError::Denied {
            stage: "fork",
            errno: last_errno(),
        });
    }
    if pid == 0 {
        // SAFETY: async-signal-safe only: setgid/setuid/fexecve/_exit.
        unsafe {
            libc::setgid(65534);
            libc::setuid(65534);
            libc::fexecve(exe_fd, argv_ptr.as_ptr(), envp.cast_const().cast());
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
