// SPDX-License-Identifier: GPL-3.0-or-later
//! T8 smoke worker: deprivileged token load (spawned ONLY by the smoke test).
//!
//! Hidden entry contract: exact argv `[bin, --fd, SOCK, --object-fd, OBJ]`
//! plus `KRYPROBE_SMOKE_WORKER=1` in the environment; direct execution
//! without both exits 2. The spawner joins the mint userns and drops to
//! in-ns root (= outer `nobody`) before exec, so an euid of 0 here is
//! EXPECTED: the worker proves its outer identity from its id maps and
//! refuses to run when either outer id is 0 (exit 3).
//!
//! Flow: read object bytes → parse (exit 7 on fixture corruption) →
//! in-ns already (spawned joined) else join a user namespace (exit 6)
//! → receive + verify the token (exit 5) → tokenized load (exit 4 on
//! load-fail or allowlist denial, exit 7 on fixture corruption,
//! exit 0 + `TOKEN-LOAD-PASS`).
//! Exit codes: 0 pass, 2 usage, 3 outer-root, 4 load-fail/denied,
//! 5 token-fail, 6 userns-fail, 7 fixture-fail.

#![allow(clippy::cast_possible_wrap)]

use kryprobe_privilege::bpfloader::LoaderError;
use kryprobe_privilege::token::{TokenAxes, TokenHandle, parse_id_map_outer};
use std::io::Read;
use std::os::fd::BorrowedFd;
use std::os::unix::io::FromRawFd;

fn usage() -> ! {
    eprintln!("usage: token_worker --fd SOCK --object-fd OBJ");
    std::process::exit(2);
}

fn parse_fd(text: &str) -> i32 {
    match parse_fd_value(text) {
        Some(fd) => fd,
        None => usage(),
    }
}

/// Pure fd validation: only fds outside stdio (0/1/2) satisfy the
/// hidden-entry contract — the spawner passes fresh socket/object fds,
/// never stdin/stdout/stderr.
fn parse_fd_value(text: &str) -> Option<i32> {
    text.parse::<i32>().ok().filter(|fd| *fd >= 3)
}

/// Maximum accepted object size (4 MiB).
const MAX_OBJECT_BYTES: usize = 4 << 20;

/// Reads the object with a hard cap: at most `MAX_OBJECT_BYTES + 1`
/// bytes are ever buffered (the `+1` is the oversize probe), so a
/// hostile oversized object refuses instead of OOMing the worker.
fn read_object_capped<R: Read>(reader: R) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Outer id from a `/proc/self/{uid,gid}_map` file; `None` when the
/// file is missing or malformed (fail closed: the caller refuses).
fn read_outer_id(path: &str) -> Option<u32> {
    parse_id_map_outer(&std::fs::read_to_string(path).ok()?)
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
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // In-ns detection: the spawner execs us as in-ns root, so euid 0
    // means "already joined" (outer identity proven from the maps);
    // any other euid keeps the legacy self-unshare path below.
    let in_ns = euid == 0;
    if in_ns {
        // Outer root — or an unreadable map — refuses exactly like
        // the legacy gate: exit 3, same message. An attacker running
        // us as root in their OWN ns maps outer 0 and still refuses;
        // any other ns still needs the kernel's token authorization.
        let outer = (
            read_outer_id("/proc/self/uid_map"),
            read_outer_id("/proc/self/gid_map"),
        );
        if !matches!(outer, (Some(uid), Some(gid)) if uid != 0 && gid != 0) {
            eprintln!("token_worker: refusing to run with outer root uid/gid");
            std::process::exit(3);
        }
    } else if egid == 0 {
        eprintln!("token_worker: refusing to run with outer root uid/gid");
        std::process::exit(3);
    }

    // Object bytes first: a corrupt fixture must read as fixture-fail
    // (7), never as load-fail (4); the load arms below route by kind.
    // SAFETY: parent-passed open fd, solely owned from here.
    let mut file = unsafe { std::fs::File::from_raw_fd(obj) };
    let bytes = match read_object_capped(&mut file) {
        Ok(bytes) if bytes.len() <= MAX_OBJECT_BYTES => bytes,
        _ => {
            eprintln!("token_worker: cannot read object bytes");
            std::process::exit(7);
        }
    };

    if !in_ns {
        // SAFETY: unshare takes flags only; maps are plain file writes.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            eprintln!("token_worker: unshare failed");
            std::process::exit(6);
        }
        let wrote = std::fs::write("/proc/self/setgroups", "deny").is_ok()
            && std::fs::write("/proc/self/uid_map", format!("0 {euid} 1")).is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {egid} 1")).is_ok();
        // SAFETY: idempotent getter.
        if !wrote || unsafe { libc::geteuid() } != 0 {
            eprintln!("token_worker: userns maps failed");
            std::process::exit(6);
        }
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
        // X16: unreachable (the worker always passes the allowlisted
        // self-probe id), but a forbidden program must never read as
        // fixture corruption: distinct marker, load-path exit code.
        Err(LoaderError::NotAllowed { id }) => {
            eprintln!("TOKEN-LOAD-DENIED program={id:?}");
            std::process::exit(4);
        }
        Err(other) => {
            eprintln!("token_worker: fixture failed: {other}");
            std::process::exit(7);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn fd_values_reject_stdio() {
        for bad in ["0", "1", "2", "-1", "", "fd", "3x"] {
            assert_eq!(parse_fd_value(bad), None, "input {bad:?} must refuse");
        }
        for (text, want) in [("3", 3), ("4", 4), ("1023", 1023)] {
            assert_eq!(parse_fd_value(text), Some(want));
        }
    }

    #[test]
    fn capped_read_accepts_up_to_cap() {
        let bytes =
            read_object_capped(Cursor::new(vec![0x7f; MAX_OBJECT_BYTES])).expect("exact cap");
        assert_eq!(bytes.len(), MAX_OBJECT_BYTES);
        let bytes = read_object_capped(Cursor::new(vec![1, 2, 3])).expect("small object");
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn capped_read_detects_oversize_without_unbounded_buffer() {
        // Infinite input: the read returns promptly with exactly the
        // cap plus the oversize probe byte — never an OOM-sized Vec.
        let bytes = read_object_capped(std::io::repeat(0x7f)).expect("bounded read");
        assert_eq!(bytes.len(), MAX_OBJECT_BYTES + 1);
        assert!(bytes.len() > MAX_OBJECT_BYTES, "caller must refuse this");
    }
}
