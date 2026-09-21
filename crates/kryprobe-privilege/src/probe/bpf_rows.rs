// SPDX-License-Identifier: GPL-3.0-or-later
//! Kernel/bpf()-syscall/map probe rows (T6c1 split).

use super::bpf_sys::{
    BPF_MAP_CREATE, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_RINGBUF, MapAttr, bpf, denied_or_skipped,
    fd_or_errno, last_errno,
};
use super::decoders::parse_kernel_release;
use crate::fd::OwnedFd;
use crate::probe::{KERNEL_FLOOR, ProbeOutcome};
use core::ffi::c_void;

/// Pure compare of the running kernel against the 6.12 floor.
pub fn kernel_release() -> ProbeOutcome {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return ProbeOutcome::skipped("uname failed");
    }
    let raw = uts
        .release
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect::<Vec<u8>>();
    let text = String::from_utf8_lossy(&raw);
    match parse_kernel_release(&text) {
        Some(v) if v >= KERNEL_FLOOR => {
            ProbeOutcome::pass(format!("kernel {}.{} >= 6.12 floor", v.0, v.1))
        }
        Some(v) => ProbeOutcome::denied(
            format!("kernel_release {}.{} below 6.12 floor", v.0, v.1),
            0,
        ),
        None => ProbeOutcome::skipped(format!("unparseable release '{text}'")),
    }
}

/// `BPF_MAP_CREATE` with empty args: EINVAL proves the syscall exists.
pub fn bpf_syscall() -> ProbeOutcome {
    // SAFETY: null attr with size 0 copies nothing; kernel rejects args.
    let ret = unsafe { bpf(BPF_MAP_CREATE, std::ptr::null_mut(), 0) };
    if ret >= 0 {
        let _owned = unsafe { OwnedFd::from_raw_fd(ret as i32) };
        return ProbeOutcome::pass("bpf() accepted empty MAP_CREATE");
    }
    let errno = last_errno();
    if errno == libc::EPERM || errno == libc::EACCES {
        ProbeOutcome::denied("bpf_syscall", errno)
    } else if errno == libc::EINVAL {
        ProbeOutcome::pass("bpf() present (EINVAL on empty args)")
    } else {
        ProbeOutcome::skipped(format!("bpf() unexpected errno {errno}"))
    }
}

/// Creates a real one-entry ARRAY map; the fd closes via RAII.
pub fn map_create() -> ProbeOutcome {
    let mut attr = MapAttr {
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: 1,
    };
    // SAFETY: `attr` is a live stack struct; size matches its type.
    let ret = unsafe {
        bpf(
            BPF_MAP_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<MapAttr>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(_fd) => ProbeOutcome::pass("ARRAY map created"),
        Err(errno) => denied_or_skipped("map_create", errno),
    }
}

/// Creates a real RINGBUF map; the fd closes via RAII.
pub fn ringbuf_create() -> ProbeOutcome {
    let mut attr = MapAttr {
        map_type: BPF_MAP_TYPE_RINGBUF,
        key_size: 0,
        value_size: 0,
        max_entries: 4096,
    };
    // SAFETY: `attr` is a live stack struct; size matches its type.
    let ret = unsafe {
        bpf(
            BPF_MAP_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<MapAttr>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(_fd) => ProbeOutcome::pass("RINGBUF map created"),
        Err(errno) => denied_or_skipped("ringbuf_create", errno),
    }
}
