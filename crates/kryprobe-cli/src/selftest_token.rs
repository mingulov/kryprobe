// SPDX-License-Identifier: GPL-3.0-or-later
//! `selftest token-smoke`: root token roundtrip (exit 0/1/4).
//!
//! Non-root exits 4 (`needs root`) before touching anything; root runs
//! the shared [`run_smoke_roundtrip`](kryprobe_privilege::token::run_smoke_roundtrip)
//! path. Mint denials on incapable kernels also exit 4; worker failures
//! and leaks are exit 1 (never silent, never skips).

use crate::cmd_selftest::{locate_bpf_object, sibling_binary};
use kryprobe_privilege::host as priv_host;
use kryprobe_privilege::token::{TokenError, run_smoke_roundtrip};
use std::io::Write;

/// Runs `selftest token-smoke`.
pub fn run(stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    // Root gate via the privilege boundary (1B-M7: no `libc::` here).
    if !priv_host::euid_is_root() {
        let _ = writeln!(stderr, "selftest token-smoke: needs root (euid != 0)");
        return 4;
    }
    let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let release = kryprobe_privilege::probe::parse_kernel_release(raw.trim()).unwrap_or((0, 0));
    if release < (6, 9) {
        let _ = writeln!(
            stderr,
            "selftest token-smoke: needs kernel 6.9+, have {release:?}"
        );
        return 4;
    }
    let Some(worker) = sibling_binary("token_worker", "KRYPROBE_TOKEN_WORKER") else {
        let _ = writeln!(stderr, "selftest token-smoke: missing token_worker sibling");
        return 4;
    };
    let Some(object) = locate_bpf_object() else {
        let _ = writeln!(
            stderr,
            "selftest token-smoke: missing object (run `cargo xtask build --bpf`)"
        );
        return 4;
    };
    match run_smoke_roundtrip(&worker, &object) {
        Ok(_) => {
            let _ = writeln!(stdout, "token-smoke: pass");
            0
        }
        // Refusal classification lives behind the boundary (1B-M7).
        Err(TokenError::Denied { errno, .. }) if priv_host::errno_is_refused(errno) => {
            let _ = writeln!(
                stderr,
                "selftest token-smoke: kernel denied mint (errno {errno})"
            );
            4
        }
        Err(err) => {
            let _ = writeln!(stderr, "selftest token-smoke: {err}");
            1
        }
    }
}
