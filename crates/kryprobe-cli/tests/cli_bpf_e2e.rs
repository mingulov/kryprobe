// SPDX-License-Identifier: GPL-3.0-or-later
//! T10: privileged CLI lane (`#[ignore]`, run via `cargo xtask test bpf`).

use std::path::PathBuf;
use std::process::Command;

fn kryprobe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kryprobe"))
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn selftest_bpf_clean_or_denied() {
    let output = Command::new(kryprobe())
        .args(["selftest", "bpf", "--calls", "20000"])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    match output.status.code() {
        Some(0) => assert!(stderr.contains("reconcile: clean"), "stderr: {stderr}"),
        Some(3) => assert!(stderr.contains("Denied{"), "stderr: {stderr}"),
        Some(code) => panic!("unexpected exit {code}: {stderr}"),
        None => panic!("killed by signal: {stderr}"),
    }
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn selftest_token_smoke_needs_root() {
    // SAFETY: idempotent getter.
    if unsafe { libc::geteuid() } == 0 {
        println!("SKIP: non-root proof needs euid != 0 (root path runs in T12)");
        return;
    }
    let output = Command::new(kryprobe())
        .args(["selftest", "token-smoke"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    assert!(stderr.contains("needs root"), "stderr: {stderr}");
}
