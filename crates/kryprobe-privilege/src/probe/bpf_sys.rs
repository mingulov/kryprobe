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
use std::os::fd::RawFd;

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
/// `BPF_TRACE_FENTRY` expected attach type id (T06 lifecycle entry edge,
/// pre-W8; retained as a UAPI constant).
pub const BPF_TRACE_FENTRY: u32 = 24;
/// `BPF_TRACE_FSESSION` expected attach type id (T06 W8 lifecycle
/// session; floor 7.0+ — value 58 verified on v7.0, v7.0.14, v7.2
/// and v7.2.6 UAPI headers).
pub const BPF_TRACE_FSESSION: u32 = 58;
/// Required in map/prog flags when a token fd rides the attr.
pub const BPF_F_TOKEN_FD: u32 = 1 << 16;
/// `BPF_OBJ_GET_INFO_BY_FD` command id (M2 sensor identity).
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
/// `BPF_LINK_GET_NEXT_ID` command id (H4 foreign-link enumeration).
pub const BPF_LINK_GET_NEXT_ID: u32 = 31;
/// `BPF_LINK_GET_FD_BY_ID` command id (H4 foreign-link enumeration).
pub const BPF_LINK_GET_FD_BY_ID: u32 = 30;
/// `BPF_LINK_TYPE_TRACING` link type id (fentry/fexit/fsession links).
pub const BPF_LINK_TYPE_TRACING: u32 = 2;
/// `BPF_BTF_GET_FD_BY_ID` command id (P4 module-BTF object fd for
/// `attach_btf_obj_fd`; 19 — counted in the UAPI `bpf_cmd` enum,
/// never renumbered).
pub const BPF_BTF_GET_FD_BY_ID: u32 = 19;
/// `BPF_BTF_GET_NEXT_ID` command id (P4 module-BTF discovery).
pub const BPF_BTF_GET_NEXT_ID: u32 = 23;

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

/// `BPF_OBJ_GET_INFO_BY_FD` attr (16 bytes, UAPI order).
#[repr(C)]
#[derive(Debug)]
pub struct ObjInfoAttr {
    /// Object fd to describe.
    pub bpf_fd: u32,
    /// In: info buffer length. Out: kernel struct length.
    pub info_len: u32,
    /// Userspace pointer to the info buffer.
    pub info: u64,
}

const _: () = assert!(size_of::<ObjInfoAttr>() == 16);

/// Fetch kernel info for `fd` into `buf`; returns the kernel's struct
/// length (`info_len` out). The kernel copies `min(in, struct)` and
/// reports the full struct size — the caller validates the returned
/// length covers every field it reads (M2: `info_len` + identity,
/// never fdinfo).
pub fn obj_get_info(fd: RawFd, buf: &mut [u8]) -> Result<u32, i32> {
    let mut attr = ObjInfoAttr {
        bpf_fd: fd as u32,
        info_len: buf.len() as u32,
        info: buf.as_mut_ptr() as u64,
    };
    // SAFETY: attr + buffer outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_OBJ_GET_INFO_BY_FD,
            (&raw mut attr).cast::<c_void>(),
            size_of::<ObjInfoAttr>() as u32,
        )
    };
    if ret < 0 {
        Err(last_errno())
    } else {
        Ok(attr.info_len)
    }
}

/// `BPF_LINK_GET_NEXT_ID` attr (16 bytes, UAPI order).
#[repr(C)]
#[derive(Debug)]
pub struct LinkNextIdAttr {
    /// Iterate past this link id.
    pub start_id: u32,
    /// Out: next link id.
    pub next_id: u32,
    /// Open flags (zero).
    pub open_flags: u32,
    /// Token fd for `GET_FD_BY_ID` (unused here, zero).
    pub token_fd: i32,
}

const _: () = assert!(size_of::<LinkNextIdAttr>() == 16);

/// Next link id past `start_id`; `Ok(None)` at iteration end
/// (`ENOENT` is the documented terminator, not an error). Privileged
/// (root enumeration for the H4 foreign-link exclusion).
pub fn link_get_next_id(start_id: u32) -> Result<Option<u32>, i32> {
    let mut attr = LinkNextIdAttr {
        start_id,
        next_id: 0,
        open_flags: 0,
        token_fd: 0,
    };
    // SAFETY: attr outlives the syscall.
    let ret = unsafe {
        bpf(
            BPF_LINK_GET_NEXT_ID,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkNextIdAttr>() as u32,
        )
    };
    if ret < 0 {
        let errno = last_errno();
        if errno == libc::ENOENT {
            Ok(None)
        } else {
            Err(errno)
        }
    } else {
        Ok(Some(attr.next_id))
    }
}

/// Open a link fd by id (H4 enumeration; privileged). Returns the
/// owned fd or the kernel errno (`ENOENT` = raced with detach).
pub fn link_get_fd_by_id(link_id: u32) -> Result<OwnedFd, i32> {
    let mut attr = LinkNextIdAttr {
        start_id: link_id,
        next_id: 0,
        open_flags: 0,
        token_fd: 0,
    };
    // SAFETY: attr outlives the syscall.
    let ret = unsafe {
        bpf(
            BPF_LINK_GET_FD_BY_ID,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkNextIdAttr>() as u32,
        )
    };
    fd_or_errno(ret)
}

/// Next BTF object id past `start_id`; `Ok(None)` at iteration end
/// (`ENOENT` is the documented terminator, not an error).
/// Privileged (module-BTF discovery for the P4 callback attach).
pub fn btf_get_next_id(start_id: u32) -> Result<Option<u32>, i32> {
    let mut attr = LinkNextIdAttr {
        start_id,
        next_id: 0,
        open_flags: 0,
        token_fd: 0,
    };
    // SAFETY: attr outlives the syscall.
    let ret = unsafe {
        bpf(
            BPF_BTF_GET_NEXT_ID,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkNextIdAttr>() as u32,
        )
    };
    if ret < 0 {
        let errno = last_errno();
        if errno == libc::ENOENT {
            Ok(None)
        } else {
            Err(errno)
        }
    } else {
        Ok(Some(attr.next_id))
    }
}

/// Open a BTF object fd by id (P4 module-BTF discovery;
/// privileged). Returns the owned fd or the kernel errno
/// (`ENOENT` = raced with unload).
pub fn btf_get_fd_by_id(btf_id: u32) -> Result<OwnedFd, i32> {
    let mut attr = LinkNextIdAttr {
        start_id: btf_id,
        next_id: 0,
        open_flags: 0,
        token_fd: 0,
    };
    // SAFETY: attr outlives the syscall.
    let ret = unsafe {
        bpf(
            BPF_BTF_GET_FD_BY_ID,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkNextIdAttr>() as u32,
        )
    };
    fd_or_errno(ret)
}

/// `struct bpf_btf_info` the name read consumes whole (UAPI
/// `linux/bpf.h`: `btf` u64 @0, `btf_size` u32 @8, `id` u32 @12,
/// `name` u64 @16, `name_len` u32 @24, `kernel_btf` u32 @28 — 32
/// bytes; only the `name` output is read, the rest is the honest
/// full-struct shape so the kernel's name fill always applies).
const BTF_INFO_LEN: usize = 32;

/// Read a BTF object's kernel name (P4: module-BTF discovery
/// matches `name` against the manifest module — `vmlinux` for the
/// base image, the module name for module BTF). `name_buf` is the
/// bounded name sink (module names fit 64; the caller sizes it).
/// Fails closed on short info, a missing NUL, or invalid UTF-8 —
/// never a truncated match.
pub fn btf_kernel_name(fd: RawFd, name_buf: &mut [u8]) -> Result<String, i32> {
    let mut info = [0u8; BTF_INFO_LEN];
    info[16..24].copy_from_slice(&(name_buf.as_mut_ptr() as u64).to_le_bytes());
    info[24..28].copy_from_slice(&(name_buf.len() as u32).to_le_bytes());
    let got = obj_get_info(fd, &mut info)?;
    if (got as usize) < BTF_INFO_LEN {
        return Err(libc::EIO);
    }
    let name_len = u32::from_le_bytes([info[24], info[25], info[26], info[27]]) as usize;
    if name_len == 0 || name_len > name_buf.len() {
        return Err(libc::EIO);
    }
    let name = name_buf
        .iter()
        .position(|b| *b == 0)
        .and_then(|nul| name_buf.get(..nul))
        .ok_or(libc::EIO)?;
    String::from_utf8(name.to_vec()).map_err(|_| libc::EIO)
}
