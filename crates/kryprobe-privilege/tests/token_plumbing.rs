// SPDX-License-Identifier: GPL-3.0-or-later
//! T8: token fdinfo parsing, token plumbing, and the root token smoke lane.
//!
//! [`smoke`] runs the full roundtrip only as root on a token-capable kernel;
//! everywhere else it skips honestly like every other BPF lane. The roundtrip
//! mechanics live in [`kryprobe_privilege::token::run_smoke_roundtrip`]
//! (shared with `kryprobe selftest token-smoke`); this lane only gates.
//!
//! SERIAL LANE (B6): no concurrent BPF loads on the host during [`smoke`] —
//! the extras-only leak comparison tolerates ambient teardown, but a
//! concurrent loader's ids report `Leaked` honestly.

use kryprobe_privilege::token::TokenAxes;
use kryprobe_privilege::token::parse_token_fdinfo;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// fdinfo table (pure; runs everywhere)
// ---------------------------------------------------------------------------

const SAMPLE: &str = "pos:\t0\nflags:\t02000002\nmnt_id:\t17\nino:\t42\n\
    allowed_cmds:\t0x21\nallowed_maps:\t0x8000044\nallowed_progs:\t0x4\n\
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
// spawn + worker gates (runs everywhere; binary-dependent parts skip)
// ---------------------------------------------------------------------------

/// Bad fds never reach exec: as root the mint-ns join fails first
/// (125), before the drop (126) and the image exec (127);
/// unprivileged the group-drop already fails closed (126) — the
/// group-drop must precede the join (`setgroups` is EPERM after
/// `setns`). Either way the parent observes an exit code, never a
/// silent privileged child.
#[test]
#[cfg(target_os = "linux")]
fn spawn_ns_join_fails_closed() {
    use kryprobe_privilege::token::spawn_smoke_worker;
    // SAFETY: idempotent getter.
    let root = unsafe { libc::geteuid() } == 0;
    let code = spawn_smoke_worker(-1, -1, -1, -1).expect("spawn must report");
    assert_eq!(code, if root { 125 } else { 126 }, "join/drop outcome");
}

#[test]
fn worker_direct_without_marker() {
    let exe = worker_path();
    if !exe.is_file() {
        println!("SKIP: token_worker not built (run `cargo xtask test bpf`)");
        return;
    }
    let status = std::process::Command::new(&exe)
        .env_remove("KRYPROBE_SMOKE_WORKER")
        .output()
        .expect("spawn worker")
        .status;
    assert_eq!(status.code(), Some(2), "direct run must exit 2 (usage)");
}

/// In-ns worker path (T18): spawned INTO the mint ns with a
/// token-less socket (peer closed) and a bogus object, the worker
/// must sail past the outer-identity gate (not 3) and the userns
/// stage (not 6) and fail honestly at token receive (5). Root +
/// 6.9 + fixtures; incapable kernels skip via mint `Denied`.
#[test]
fn worker_in_mint_ns_skips_unshare() {
    use kryprobe_privilege::token::{TokenError, mint_smoke_token, spawn_smoke_worker};
    // SAFETY: idempotent getter.
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIP: in-ns worker proof needs euid == 0");
        return;
    }
    let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let release = kryprobe_privilege::probe::parse_kernel_release(raw.trim()).unwrap_or((0, 0));
    if release < (6, 9) {
        println!("SKIP: token delegation needs kernel 6.9+, have {release:?}");
        return;
    }
    let exe = worker_path();
    if !exe.is_file() {
        println!("SKIP: token_worker not built (run `cargo xtask test bpf`)");
        return;
    }
    let minted = match mint_smoke_token() {
        Ok(minted) => minted,
        Err(TokenError::Denied { errno, .. })
            if [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP].contains(&errno) =>
        {
            println!("SKIP: kernel denied split-flow mint (errno {errno})");
            return;
        }
        Err(err) => panic!("mint failed dishonestly: {err}"),
    };
    // Socket with the peer closed: the worker's token recv fails
    // closed (exit 5) instead of blocking forever.
    let mut pair = [0; 2];
    // SAFETY: valid out-param pair; both ends closed below.
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) },
        0
    );
    // SAFETY: `pair[1]` is open and owned here.
    unsafe {
        libc::close(pair[1]);
    }
    // SAFETY: read-only probe fd, closed below.
    let obj = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    assert!(obj >= 0, "open /dev/null");
    let exe_cstr =
        std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()).expect("worker path cstr");
    // Stable fd numbers for the child (libc-open: no CLOEXEC, survives exec).
    // SAFETY: read-only image fd, closed below.
    let exe_fd = unsafe { libc::open(exe_cstr.as_ptr(), libc::O_RDONLY) };
    assert!(exe_fd >= 0, "open worker image");
    let code = spawn_smoke_worker(exe_fd, pair[0], obj, minted.ns_fd()).expect("spawn must report");
    // SAFETY: all three fds owned here, closed exactly once.
    unsafe {
        libc::close(exe_fd);
        libc::close(pair[0]);
        libc::close(obj);
    }
    assert_eq!(
        code, 5,
        "in-ns worker must reach the token stage (exit 5), got {code}"
    );
}

#[test]
fn worker_refuses_outer_root() {
    // SAFETY: idempotent getters.
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIP: outer-root proof needs euid == 0");
        return;
    }
    let exe = worker_path();
    if !exe.is_file() {
        println!("SKIP: token_worker not built (run `cargo xtask test bpf`)");
        return;
    }
    let status = std::process::Command::new(&exe)
        .args(["--fd", "9", "--object-fd", "9"])
        .env("KRYPROBE_SMOKE_WORKER", "1")
        .output()
        .expect("spawn worker")
        .status;
    assert_eq!(status.code(), Some(3), "outer root must exit 3");
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
    use kryprobe_privilege::token::{TokenError, run_smoke_roundtrip};

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
    let exe = worker_path();
    assert!(
        exe.is_file(),
        "missing token_worker at {} — run `cargo xtask test bpf`",
        exe.display()
    );
    match run_smoke_roundtrip(&exe, &object) {
        // Phase A authority gate: exact expected delegation axes.
        Ok(axes) => assert_eq!(axes, TokenAxes::smoke_expected(), "smoke axes"),
        Err(TokenError::Denied { errno, .. })
            if [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP].contains(&errno) =>
        {
            println!("SKIP: kernel denied token mint (errno {errno})");
        }
        Err(err) => panic!("smoke failed dishonestly: {err}"),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_roundtrip() {
    println!("SKIP: token smoke lane is Linux-only");
}
