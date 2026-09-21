// SPDX-License-Identifier: GPL-3.0-or-later
//! Program-load, self-link, and token probe rows (T6c1 split).

use super::bpf_sys::{
    BPF_LINK_CREATE, BPF_PROG_LOAD, BPF_PROG_TYPE_KPROBE, BPF_TOKEN_CREATE, BPF_TRACE_UPROBE_MULTI,
    Insn, LinkUprobeMulti, ProgAttr, TokenAttr, bpf, denied_or_skipped, fd_or_errno, last_errno,
};
use crate::elfread::{ElfBytes, MmapGuard, symbol_file_offset};
use crate::fd::OwnedFd;
use crate::probe::ProbeOutcome;
use core::ffi::c_void;
use std::ffi::CString;

fn load_minimal(attach_type: u32) -> Result<OwnedFd, i32> {
    // mov r0, 0; exit
    let insns = [
        Insn {
            code: 0xb7,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
        Insn {
            code: 0x95,
            dst_src: 0,
            off: 0,
            imm: 0,
        },
    ];
    let license = b"GPL\0";
    let mut attr = ProgAttr {
        prog_type: BPF_PROG_TYPE_KPROBE,
        insn_cnt: 2,
        insns: (&raw const insns).addr() as u64,
        license: (&raw const license).addr() as u64,
        rest: [0; 20],
    };
    // uapi offset 68 is expected_attach_type: high half of rest[5].
    attr.rest[5] = (attach_type as u64) << 32;
    // SAFETY: `attr` (+ pointed-to insns/license) outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_PROG_LOAD,
            (&raw mut attr).cast::<c_void>(),
            size_of::<ProgAttr>() as u32,
        )
    };
    fd_or_errno(ret)
}

/// Loads a 2-insn program, plain kprobe type and uprobe_multi variant.
pub fn prog_load_minimal() -> ProbeOutcome {
    let first = load_minimal(0);
    let second = load_minimal(BPF_TRACE_UPROBE_MULTI);
    match (&first, &second) {
        (Ok(_), _) => ProbeOutcome::pass("minimal kprobe program loaded"),
        (_, Ok(_)) => ProbeOutcome::pass("minimal uprobe_multi program loaded"),
        (Err(e1), Err(e2)) => {
            let errno = if *e1 == libc::EPERM || *e1 == libc::EACCES {
                *e1
            } else {
                *e2
            };
            denied_or_skipped("prog_load", errno)
        }
    }
}

fn libc_path() -> Option<String> {
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            if let Some(path) = line.split_whitespace().last()
                && path.contains("libc")
                && path.ends_with(".so.6")
                && path.starts_with('/')
            {
                return Some(path.to_string());
            }
        }
    }
    for known in [
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ] {
        if std::path::Path::new(known).exists() {
            return Some(known.to_string());
        }
    }
    None
}

fn libc_symbol_offset(path: &str) -> Option<u64> {
    let guard = MmapGuard::open(path).ok()?;
    for name in ["malloc", "free", "open"] {
        if let Ok(Some(off)) = symbol_file_offset(guard.bytes(), name) {
            return Some(off);
        }
    }
    None
}

/// Pid-filtered uprobe_multi link against own libc; detached immediately.
pub fn uprobe_multi_link_self() -> ProbeOutcome {
    let Some(path) = libc_path() else {
        return ProbeOutcome::skipped("no libc path found for self");
    };
    let Some(offset) = libc_symbol_offset(&path) else {
        return ProbeOutcome::skipped("no libc symbol offset resolved");
    };
    let path_c = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return ProbeOutcome::skipped("libc path not NUL-safe"),
    };
    let prog = match load_minimal(BPF_TRACE_UPROBE_MULTI) {
        Ok(p) => p,
        Err(errno) => return denied_or_skipped("uprobe_multi_link_self", errno),
    };
    let offsets = [offset];
    let mut attr = LinkUprobeMulti {
        prog_fd: prog.as_raw_fd() as u32,
        target: 0,
        attach_type: BPF_TRACE_UPROBE_MULTI,
        link_flags: 0,
        path: path_c.as_ptr() as u64,
        offsets: (&raw const offsets).addr() as u64,
        ref_ctr_offsets: 0,
        cookies: 0,
        cnt: 1,
        um_flags: 0,
        pid: unsafe { libc::getpid() } as u32,
        pad: 0,
    };
    // SAFETY: `attr` (+ path/offsets pointees) outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkUprobeMulti>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(_link) => ProbeOutcome::pass("uprobe_multi self-link created and detached"),
        Err(errno) => denied_or_skipped("uprobe_multi_link_self", errno),
    }
}

/// Cookie attach is subsumed by the uprobe_multi self-link result.
pub fn attach_cookies() -> ProbeOutcome {
    match uprobe_multi_link_self() {
        ProbeOutcome::Pass { detail } => {
            ProbeOutcome::pass(format!("cookie attach subsumed by uprobe_multi: {detail}"))
        }
        ProbeOutcome::Denied { errno, .. } => ProbeOutcome::denied("attach_cookies", errno),
        ProbeOutcome::Skipped { reason } => ProbeOutcome::skipped(format!(
            "uprobe_multi unresolved, cookies unknown: {reason}"
        )),
        // Unreachable today (`uprobe_multi_link_self` never fails) —
        // passed through with context if it ever does.
        ProbeOutcome::Failed { detail } => ProbeOutcome::failed(format!(
            "uprobe_multi unresolved, cookies unknown: {detail}"
        )),
    }
}

/// Info-only: is `BPF_TOKEN_CREATE` recognized by this kernel?
pub fn token_create_exists() -> ProbeOutcome {
    let mut attr = TokenAttr {
        flags: 0,
        bpffs_fd: u32::MAX,
    };
    // SAFETY: `attr` is a live stack struct; size matches its type.
    let ret = unsafe {
        bpf(
            BPF_TOKEN_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<TokenAttr>() as u32,
        )
    };
    if ret >= 0 {
        let _owned = unsafe { OwnedFd::from_raw_fd(ret as i32) };
        return ProbeOutcome::pass("BPF_TOKEN_CREATE accepted call");
    }
    match last_errno() {
        e if e == libc::EBADF => {
            ProbeOutcome::pass("BPF_TOKEN_CREATE recognized (EBADF on bad bpffs fd)")
        }
        e if e == libc::EPERM || e == libc::EACCES => {
            ProbeOutcome::pass("BPF_TOKEN_CREATE recognized (denied without privilege)")
        }
        e if e == libc::EINVAL => ProbeOutcome::skipped(
            "BPF_TOKEN_CREATE indeterminate (EINVAL: unknown cmd or rejected args)",
        ),
        e if e == libc::EOPNOTSUPP => ProbeOutcome::skipped("BPF_TOKEN_CREATE not supported"),
        e => ProbeOutcome::skipped(format!("BPF_TOKEN_CREATE unexpected errno {e}")),
    }
}
