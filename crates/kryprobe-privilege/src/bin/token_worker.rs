// SPDX-License-Identifier: GPL-3.0-or-later
//! T8 smoke worker: deprivileged token load (spawned ONLY by the smoke test).
//!
//! Hidden entry contract: exact argv `[bin, --fd, SOCK, --object-fd, OBJ]`
//! plus `KRYPROBE_SMOKE_WORKER=1` in the environment; direct execution
//! without both exits 2. The parent drops to `nobody` before exec, so the
//! worker refuses to run when its outer euid or egid is 0 (exit 3).
//!
//! Flow: read object bytes → parse (exit 7 on fixture corruption) → join
//! a user namespace (exit 6) → receive + verify the token (exit 5) →
//! tokenized load (exit 4 on `LoaderError`, exit 0 + `TOKEN-LOAD-PASS`).
//! Exit codes: 0 pass, 2 usage, 3 outer-root, 4 load-fail, 5 token-fail,
//! 6 userns-fail, 7 fixture-fail.

#![allow(clippy::cast_possible_wrap)]

use kryprobe_privilege::bpfloader::LoaderError;
use kryprobe_privilege::token::{TokenAxes, TokenHandle};
use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::unix::io::FromRawFd;

fn usage() -> ! {
    eprintln!("usage: token_worker --fd SOCK --object-fd OBJ");
    std::process::exit(2);
}

fn parse_fd(text: &str) -> i32 {
    match text.parse::<i32>() {
        Ok(fd) if fd >= 0 => fd,
        _ => usage(),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() != 5 || argv[1] != "--fd" || argv[3] != "--object-fd" {
        usage();
    }
    if std::env::var("KRYPROBE_SMOKE_WORKER").as_deref() != Ok("1") {
        usage();
    }
    let sock = parse_fd(&argv[2]);
    let obj = parse_fd(&argv[4]);

    // SAFETY: idempotent getters.
    let (outer_uid, outer_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    if outer_uid == 0 || outer_gid == 0 {
        eprintln!("token_worker: refusing to run with outer root uid/gid");
        std::process::exit(3);
    }

    // Object bytes first: a corrupt fixture must read as fixture-fail
    // (7), never as load-fail (4); the load arms below route by kind.
    let mut bytes = Vec::new();
    // SAFETY: parent-passed open fd, solely owned from here.
    let mut file = unsafe { std::fs::File::from_raw_fd(obj) };
    if file.read_to_end(&mut bytes).is_err() || bytes.len() > (4 << 20) {
        eprintln!("token_worker: cannot read object bytes");
        std::process::exit(7);
    }

    // SAFETY: unshare takes flags only; maps are plain file writes.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        eprintln!("token_worker: unshare failed");
        std::process::exit(6);
    }
    let wrote = std::fs::write("/proc/self/setgroups", "deny").is_ok()
        && std::fs::write("/proc/self/uid_map", format!("0 {outer_uid} 1")).is_ok()
        && std::fs::write("/proc/self/gid_map", format!("0 {outer_gid} 1")).is_ok();
    // SAFETY: idempotent getter.
    if !wrote || unsafe { libc::geteuid() } != 0 {
        eprintln!("token_worker: userns maps failed");
        std::process::exit(6);
    }

    // SAFETY: parent-passed open socket; borrowed, never closed here.
    let sock_ref = unsafe { BorrowedFd::borrow_raw(sock) };
    let token = match TokenHandle::recv_via(sock_ref, TokenAxes::smoke_expected()) {
        Ok(token) => token,
        Err(err) => {
            eprintln!("token_worker: token receive failed: {err}");
            std::process::exit(5);
        }
    };
    let axes = token.axes();
    println!(
        "TOKEN-AXES cmds={:#x} maps={:#x} progs={:#x} attachs={:#x}",
        axes.cmds, axes.maps, axes.progs, axes.attachs
    );

    match kryprobe_privilege::token::load_bytes_with_token(&bytes, &token) {
        Ok(_loaded) => {
            println!("TOKEN-LOAD-PASS");
            println!("NOTE: token is not target confinement (Phase A scope-all)");
            std::process::exit(0);
        }
        Err(LoaderError::MapFailed { stage, errno }) => {
            eprintln!("TOKEN-LOAD-FAIL stage={stage} errno={errno}");
            std::process::exit(4);
        }
        Err(LoaderError::LoadFailed { stage, errno, .. }) => {
            eprintln!("TOKEN-LOAD-FAIL stage={stage} errno={errno}");
            std::process::exit(4);
        }
        Err(other) => {
            eprintln!("token_worker: fixture failed: {other}");
            std::process::exit(7);
        }
    }
}
