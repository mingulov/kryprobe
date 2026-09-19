// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw `bpf()` syscall plumbing + UAPI attr layouts (T6c1 split).
//!
//! Micro-borrow: the `BPF_LINK_CREATE uprobe_multi` attr layout and the
//! `expected_attach_type = BPF_TRACE_UPROBE_MULTI` requirement follow the
//! osslscope `bpf-sys` pattern (reimplemented against UAPI `linux/bpf.h`).
//!
//! Errno discipline: `libc::syscall` returns -1 with the code in
//! thread-local errno (NOT `-errno` as the return value), so every error
//! path must call [`last_errno`] immediately after the syscall.

use crate::fd::OwnedFd;
use crate::probe::ProbeOutcome;
use std::os::raw::{c_long, c_void};

pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_LINK_CREATE: u32 = 28;
pub const BPF_TOKEN_CREATE: u32 = 36;
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
pub const BPF_TRACE_UPROBE_MULTI: u32 = 48;
/// `BPF_OBJ_PIN` command id (R2: the attr must be exactly 20 bytes).
pub const BPF_OBJ_PIN: u32 = 6;
/// `BPF_PROG_TYPE_TRACING` program type id (fentry, K1).
pub const BPF_PROG_TYPE_TRACING: u32 = 26;
/// `BPF_TRACE_FENTRY` expected attach type id (K1).
pub const BPF_TRACE_FENTRY: u32 = 24;
/// Required in map/prog flags when a token fd rides the attr.
pub const BPF_F_TOKEN_FD: u32 = 1 << 16;

/// Raw `bpf(cmd, attr, size)`; returns the fd or -1 (see [`last_errno`]).
///
/// # Safety
///
/// `attr` must point to `size` readable/writable bytes for the duration of
/// the syscall (the kernel copies the attr struct in and out).
pub unsafe fn bpf(cmd: u32, attr: *mut c_void, size: u32) -> c_long {
    unsafe { libc::syscall(libc::SYS_bpf, cmd as c_long, attr, size as c_long) }
}

/// Thread-local errno captured right after a failed syscall.
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Converts a raw syscall return into `Ok(fd)` or `Err(errno)`.
pub fn fd_or_errno(ret: c_long) -> Result<OwnedFd, i32> {
    if ret < 0 {
        Err(last_errno())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
    }
}

/// EPERM/EACCES is an honest capability denial; anything else is Skipped.
pub fn denied_or_skipped(stage: &str, errno: i32) -> ProbeOutcome {
    if errno == libc::EPERM || errno == libc::EACCES {
        ProbeOutcome::denied(stage, errno)
    } else {
        ProbeOutcome::skipped(format!("{stage} unexpected errno {errno}"))
    }
}

#[repr(C)]
pub struct MapAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Insn {
    pub code: u8,
    pub dst_src: u8,
    pub off: i16,
    pub imm: i32,
}

#[repr(C)]
pub struct ProgAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub rest: [u64; 20],
}

#[repr(C)]
pub struct TokenAttr {
    pub flags: u32,
    pub bpffs_fd: u32,
}

#[repr(C)]
pub struct LinkUprobeMulti {
    pub prog_fd: u32,
    pub target: u32,
    pub attach_type: u32,
    pub link_flags: u32,
    pub path: u64,
    pub offsets: u64,
    pub ref_ctr_offsets: u64,
    pub cookies: u64,
    pub cnt: u32,
    pub um_flags: u32,
    pub pid: u32,
    pub pad: u32,
}

/// `BPF_LINK_CREATE` tracing-attach attr (64 bytes, UAPI order): the
/// `target_btf_id` union variant + zero tail. `target_btf_id` is 0: the
/// kernel attaches to the load-time `attach_btf_id` (R1 —
/// `evidence/k0/P1-attach-matrix.txt`; explicit nonzero ids fail EINVAL
/// on the K0 host, strace-verified).
#[repr(C)]
pub struct LinkTracing {
    pub prog_fd: u32,
    pub target_fd: u32,
    pub attach_type: u32,
    pub flags: u32,
    pub target_btf_id: u32,
    pub pad: u32,
    pub cookie: u64,
    pub tail: [u64; 4],
}

const _: () = assert!(size_of::<LinkTracing>() == 64);
