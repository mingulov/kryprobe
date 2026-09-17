// SPDX-License-Identifier: GPL-3.0-or-later
//! T8: token fdinfo parsing, token plumbing, and the root token smoke lane.
//!
//! [`smoke`] runs the full roundtrip only as root on a token-capable kernel;
//! everywhere else it skips honestly like every other BPF lane. The worker
//! is spawned via fork + setuid(nobody) + `fexecve`, so it never depends on
//! filesystem traversal permissions.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use kryprobe_privilege::token::TokenAxes;
use kryprobe_privilege::token::parse_token_fdinfo;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// fdinfo table (pure; runs everywhere)
// ---------------------------------------------------------------------------

const SAMPLE: &str = "pos:\t0\nflags:\t02000002\nmnt_id:\t17\nino:\t42\n\
    allowed_cmds:\t0x21\nallowed_maps:\t0x8400044\nallowed_progs:\t0x4\n\
    allowed_attachs:\t0x1000000000000\n";

#[test]
fn fdinfo_case() {
    let axes = parse_token_fdinfo(SAMPLE).expect("parse sample");
    assert_eq!(axes, TokenAxes::smoke_expected());
}

#[test]
fn fdinfo_missing_case() {
    for (name, body) in [
        ("empty", ""),
        (
            "no_cmds",
            "allowed_maps:\t0x1\nallowed_progs:\t0x1\nallowed_attachs:\t0x1\n",
        ),
        (
            "no_attachs",
            "allowed_cmds:\t0x1\nallowed_maps:\t0x1\nallowed_progs:\t0x1\n",
        ),
    ] {
        assert!(parse_token_fdinfo(body).is_err(), "{name} must fail");
    }
}

#[test]
fn fdinfo_bad_value_case() {
    let bad = SAMPLE.replace("0x21", "bogus");
    assert!(parse_token_fdinfo(&bad).is_err(), "non-hex must fail");
    assert!(
        parse_token_fdinfo(
            "allowed_cmds:\t0x1\nallowed_maps:\t0x1\n\
         allowed_progs:\t0x1\nallowed_attachs:\t"
        )
        .is_err(),
        "bare key must fail"
    );
}

// ---------------------------------------------------------------------------
// plumbing errors (fail-closed, runs everywhere)
// ---------------------------------------------------------------------------

#[test]
fn bad_fd_plumbing_case() {
    use kryprobe_privilege::token::{TokenError, read_token_axes};
    use std::os::fd::{AsRawFd, BorrowedFd};
    // SAFETY: never dereferenced; read fails before use.
    let bad = unsafe { BorrowedFd::borrow_raw(-7) };
    let err = read_token_axes(bad.as_raw_fd()).unwrap_err();
    assert!(matches!(err, TokenError::BadFd));
}

#[test]
fn mint_denied_unprivileged_case() {
    use kryprobe_privilege::token::{TokenError, mint_smoke_token};
    // SAFETY: idempotent getter.
    if unsafe { libc::geteuid() } == 0 {
        println!("SKIP: unprivileged-mint proof needs euid != 0 (see smoke)");
        return;
    }
    let err = mint_smoke_token().unwrap_err();
    assert!(
        matches!(err, TokenError::Denied { errno, .. } if errno == libc::EPERM || errno == libc::EACCES),
        "unprivileged mint must deny, got {err}"
    );
}

// ---------------------------------------------------------------------------
// root roundtrip smoke (gated; honest skip)
// ---------------------------------------------------------------------------

/// Workspace-relative path of the built spine object (bpf_pipeline idiom).
fn spine_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/kryprobe-bpf/spine.bpf.o")
}

/// Debug path of the token_worker fixture binary (spine_fixture idiom).
fn worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/token_worker")
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn smoke() {
    // SAFETY: idempotent getter.
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIP: token smoke lane requires root (euid != 0)");
        return;
    }
    run_roundtrip();
}

#[cfg(target_os = "linux")]
fn run_roundtrip() {
    use kryprobe_privilege::token::{TokenError, live_bpf_ids, mint_smoke_token};
    use std::os::fd::AsFd;

    let object = spine_object_path();
    assert!(
        object.is_file(),
        "missing BPF spine object at {} — run `cargo xtask test bpf`",
        object.display()
    );
    // Token delegation needs 6.9+; older kernels skip the lane honestly.
    let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let release = kryprobe_privilege::probe::parse_kernel_release(raw.trim()).unwrap_or((0, 0));
    if release < (6, 9) {
        println!("SKIP: token delegation needs kernel 6.9+, have {release:?}");
        return;
    }
    let token = match mint_smoke_token() {
        Ok(token) => token,
        Err(TokenError::Denied { errno, .. })
            if [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP].contains(&errno) =>
        {
            println!("SKIP: kernel denied token mint (errno {errno})");
            return;
        }
        Err(err) => panic!("smoke: mint failed dishonestly: {err}"),
    };
    // Phase A authority gate: exact expected delegation axes.
    assert_eq!(token.axes(), TokenAxes::smoke_expected(), "smoke axes");

    let (maps_before, progs_before) = live_bpf_ids().expect("id scan before");

    let exe = worker_path();
    assert!(
        exe.is_file(),
        "missing token_worker at {} — run `cargo xtask test bpf`",
        exe.display()
    );
    let (reader, writer) = make_socketpair();
    token.send_via(writer.as_fd()).expect("send token fd");
    drop(writer);

    // Stable fd numbers for the child (libc-open: no CLOEXEC, survives exec).
    let exe_c = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()).expect("exe cstr");
    let obj_c = std::ffi::CString::new(object.as_os_str().as_encoded_bytes()).expect("object cstr");
    // SAFETY: read-only opens; fds owned below and closed after fork.
    let exe_fd = unsafe { libc::open(exe_c.as_ptr(), libc::O_RDONLY) };
    let obj_fd = unsafe { libc::open(obj_c.as_ptr(), libc::O_RDONLY) };
    assert!(exe_fd >= 0 && obj_fd >= 0, "parent cannot open fixture fds");
    let reader_fd = reader.as_fd().as_raw_fd();
    let code = spawn_worker_nobody(exe_fd, reader_fd, obj_fd);
    // SAFETY: parent-owned copies; the child holds its own post-fork.
    unsafe {
        libc::close(exe_fd);
        libc::close(obj_fd);
    }
    drop(reader);
    assert_eq!(code, 0, "token_worker exit code");

    let (maps_after, progs_after) = live_bpf_ids().expect("id scan after");
    assert_eq!(maps_before, maps_after, "no leaked maps");
    assert_eq!(progs_before, progs_after, "no leaked progs");
    drop(token);
}

/// Forks, drops the child to `nobody:nogroup`, and `fexecve`s the worker.
/// Returns the worker exit code. The child calls ONLY async-signal-safe
/// functions before exec (safe under a multithreaded test runner).
#[cfg(target_os = "linux")]
fn spawn_worker_nobody(exe_fd: i32, sock_fd: i32, obj_fd: i32) -> i32 {
    unsafe extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }
    // All allocation happens parent-side, before fork.
    // SAFETY: unique var name no other thread touches; set once pre-fork.
    unsafe {
        std::env::set_var("KRYPROBE_SMOKE_WORKER", "1");
    }
    let argv0 = std::ffi::CString::new(format!("/proc/self/fd/{exe_fd}")).expect("argv0");
    let arg_sock = std::ffi::CString::new(sock_fd.to_string()).expect("sock");
    let arg_obj = std::ffi::CString::new(obj_fd.to_string()).expect("obj");
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
    assert!(pid >= 0, "fork failed");
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
        assert!(rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR));
    }
    assert!(
        libc::WIFEXITED(status),
        "worker did not exit cleanly: {status}"
    );
    libc::WEXITSTATUS(status)
}

#[cfg(not(target_os = "linux"))]
fn run_roundtrip() {
    println!("SKIP: token smoke lane is Linux-only");
}

#[cfg(target_os = "linux")]
fn make_socketpair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut pair = [0; 2];
    // SAFETY: valid out-param pair; both fds owned on success.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair");
    // SAFETY: freshly returned owned fds.
    unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) }
}

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
