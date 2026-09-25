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
use core::ffi::{c_long, c_void};

/// `BPF_MAP_CREATE` command id.
pub const BPF_MAP_CREATE: u32 = 0;
/// `BPF_PROG_LOAD` command id.
pub const BPF_PROG_LOAD: u32 = 5;
/// `BPF_LINK_CREATE` command id.
pub const BPF_LINK_CREATE: u32 = 28;
/// `BPF_TOKEN_CREATE` command id.
pub const BPF_TOKEN_CREATE: u32 = 36;
/// `BPF_PROG_TYPE_KPROBE` program type id.
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
/// `BPF_MAP_TYPE_ARRAY` map type id.
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_MAP_TYPE_RINGBUF` map type id.
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
/// `BPF_TRACE_UPROBE_MULTI` expected attach type id.
pub const BPF_TRACE_UPROBE_MULTI: u32 = 48;
/// `BPF_OBJ_PIN` command id (R2: the attr must be exactly 20 bytes).
pub const BPF_OBJ_PIN: u32 = 6;
/// `BPF_PROG_TYPE_TRACING` program type id (fexit, K1 Task 2; the
/// Task-1 fentry shape migrated to exit-edge tracing per ruling C1).
pub const BPF_PROG_TYPE_TRACING: u32 = 26;
/// `BPF_TRACE_FEXIT` expected attach type id (K1 Task 2, C1).
pub const BPF_TRACE_FEXIT: u32 = 25;
/// `BPF_TRACE_FENTRY` expected attach type id (T06 lifecycle entry edge).
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

/// `BPF_MAP_CREATE` attr, UAPI field order.
#[repr(C)]
#[derive(Debug)]
pub struct MapAttr {
    /// Map type id.
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum entries.
    pub max_entries: u32,
}

/// One 8-byte BPF instruction, UAPI layout.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Insn {
    /// Opcode.
    pub code: u8,
    /// Packed dst (low nibble) / src (high nibble) registers.
    pub dst_src: u8,
    /// Signed jump/data offset.
    pub off: i16,
    /// Immediate constant.
    pub imm: i32,
}

/// `BPF_PROG_LOAD` attr prefix, UAPI field order.
#[repr(C)]
#[derive(Debug)]
pub struct ProgAttr {
    /// Program type id.
    pub prog_type: u32,
    /// Instruction count.
    pub insn_cnt: u32,
    /// Userspace pointer to the instruction stream.
    pub insns: u64,
    /// Userspace pointer to the NUL-terminated license string.
    pub license: u64,
    /// Zero tail (log buffer, kern version, attach ids, …).
    pub rest: [u64; 20],
}

/// `BPF_TOKEN_CREATE` attr, UAPI field order.
#[repr(C)]
#[derive(Debug)]
pub struct TokenAttr {
    /// Creation flags.
    pub flags: u32,
    /// Bpffs mount fd the token delegates.
    pub bpffs_fd: u32,
}

/// `BPF_LINK_CREATE uprobe_multi` attr, UAPI field order.
#[repr(C)]
#[derive(Debug)]
pub struct LinkUprobeMulti {
    /// Program fd to link.
    pub prog_fd: u32,
    /// Target fd (unused for uprobe_multi, zero).
    pub target: u32,
    /// Expected attach type (`BPF_TRACE_UPROBE_MULTI`).
    pub attach_type: u32,
    /// Link creation flags.
    pub link_flags: u32,
    /// Userspace pointer to the target path string.
    pub path: u64,
    /// Userspace pointer to the offsets array.
    pub offsets: u64,
    /// Userspace pointer to the ref-counter offsets array.
    pub ref_ctr_offsets: u64,
    /// Userspace pointer to the cookies array.
    pub cookies: u64,
    /// Offset/cookie array length.
    pub cnt: u32,
    /// Uprobe-multi flags.
    pub um_flags: u32,
    /// Target pid filter (0 for all).
    pub pid: u32,
    /// Padding, must be zero.
    pub pad: u32,
}

/// `BPF_LINK_CREATE` tracing-attach attr (64 bytes, UAPI order): the
/// `target_btf_id` union variant + zero tail. `target_btf_id` is 0: the
/// kernel attaches to the load-time `attach_btf_id` (R1 —
/// `evidence/k0/P1-attach-matrix.txt`; explicit nonzero ids fail EINVAL
/// on the K0 host, strace-verified).
#[repr(C)]
#[derive(Debug)]
pub struct LinkTracing {
    /// Program fd to link.
    pub prog_fd: u32,
    /// Target object fd.
    pub target_fd: u32,
    /// Expected attach type (`BPF_TRACE_FEXIT`).
    pub attach_type: u32,
    /// Link creation flags.
    pub flags: u32,
    /// Target BTF id (0: use the load-time `attach_btf_id`).
    pub target_btf_id: u32,
    /// Padding, must be zero.
    pub pad: u32,
    /// Attach cookie.
    pub cookie: u64,
    /// Zero tail.
    pub tail: [u64; 4],
}

const _: () = assert!(size_of::<LinkTracing>() == 64);
