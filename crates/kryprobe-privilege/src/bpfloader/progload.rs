// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw `BPF_PROG_LOAD` primitive, plain and tokenized (T8).
//!
//! `token: None` builds the short attr, `Some(fd)` the token-extended
//! attr with `BPF_F_TOKEN_FD` in `prog_flags` (required by UAPI when a
//! token fd is provided). Attr sizes are compile-time asserted.
//!
//! K1 adds [`prog_load_fexit_raw`]: `TRACING` + expected `FEXIT` +
//! per-prog `attach_btf_id` (R1 — `evidence/k0/P1-attach-matrix.txt`; the
//! Task-1 fentry shape migrated to exit-edge tracing per ruling C1).

use crate::probe::bpf_sys::{
    BPF_F_TOKEN_FD, BPF_PROG_LOAD, BPF_PROG_TYPE_KPROBE, BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT,
    BPF_TRACE_UPROBE_MULTI, bpf,
};
use std::os::fd::RawFd;
use std::os::raw::{c_long, c_void};

/// Verifier log verbosity (2 = verbose).
const LOG_LEVEL: u32 = 2;

/// Verifier log verbosity for kcrypto loads (1 = errors + stats).
///
/// The 9 kcrypto programs are loop-bearing (~600 insns each: key
/// zero/hash/name-scan loops), and their level-2 verbose log exceeds
/// ANY reasonable buffer (measured: overflows even 64MiB) — at which
/// point the kernel fails the load with `ENOSPC` instead of truncating
/// (the verbose log must be complete to be useful). Level 1 keeps the
/// error + verdict lines the `LoadFailed` tail needs while bounding the
/// volume to ~100 bytes on success
/// (`evidence/k1-2/step3-enospc-rootcause.txt`). The loop-free spine
/// keeps level 2 (frozen behavior).
const KCRYPTO_LOG_LEVEL: u32 = 1;

/// `BPF_PROG_LOAD` attr through `expected_attach_type` (72 bytes, UAPI order).
#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// Token-extended prog attr through `prog_token_fd` (148 bytes, UAPI order).
#[repr(C)]
struct TokenProgAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_union: u32,
    core_relo_cnt: u32,
    fd_array: u64,
    core_relos: u64,
    core_relo_rec_size: u32,
    log_true_size: u32,
    token_fd: i32,
}

/// Bytes handed to the kernel for the token prog attr: the 148-byte UAPI
/// prefix, not the 4-byte alignment tail `repr(C)` appends.
const TOKEN_PROG_ATTR_LEN: u32 = 148;

const _: () = assert!(size_of::<ProgLoadAttr>() == 72);
const _: () = assert!(size_of::<TokenProgAttr>() == 152);

/// `BPF_PROG_LOAD` attr for fexit through the attach union (116 bytes,
/// UAPI order): the K0-proven non-token shape (`attach_btf_id` at load,
/// no prog BTF — `evidence/k0/P1-attach-matrix.txt` R1).
#[repr(C)]
struct FexitProgAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_union: u32,
}

/// Bytes handed to the kernel for the fexit prog attr: the 116-byte
/// UAPI prefix, not the 4-byte alignment tail `repr(C)` appends.
const FEXIT_PROG_ATTR_LEN: u32 = 116;

const _: () = assert!(size_of::<FexitProgAttr>() == 120);

static LICENSE: &[u8; 4] = b"GPL\0";

fn prog_name16(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Raw `BPF_PROG_LOAD`; `log` receives the verifier log. Returns fd or -1.
///
/// Crate-private: reached only via the load facet's instantiate path.
pub(crate) fn prog_load_raw(
    name: &str,
    insn_bytes: &[u8],
    insn_cnt: u32,
    log: &mut [u8],
    token: Option<RawFd>,
) -> c_long {
    // SAFETY: attr + pointees (insns, license, log) outlive the syscall.
    unsafe {
        if let Some(token_fd) = token {
            let mut attr = TokenProgAttr {
                prog_type: BPF_PROG_TYPE_KPROBE,
                insn_cnt,
                insns: insn_bytes.as_ptr() as u64,
                license: LICENSE.as_ptr() as u64,
                log_level: LOG_LEVEL,
                log_size: log.len() as u32,
                log_buf: log.as_mut_ptr() as u64,
                kern_version: 0,
                prog_flags: BPF_F_TOKEN_FD,
                prog_name: prog_name16(name),
                prog_ifindex: 0,
                expected_attach_type: BPF_TRACE_UPROBE_MULTI,
                prog_btf_fd: 0,
                func_info_rec_size: 0,
                func_info: 0,
                func_info_cnt: 0,
                line_info_rec_size: 0,
                line_info: 0,
                line_info_cnt: 0,
                attach_btf_id: 0,
                attach_union: 0,
                core_relo_cnt: 0,
                fd_array: 0,
                core_relos: 0,
                core_relo_rec_size: 0,
                log_true_size: 0,
                token_fd,
            };
            bpf(
                BPF_PROG_LOAD,
                (&raw mut attr).cast::<c_void>(),
                TOKEN_PROG_ATTR_LEN,
            )
        } else {
            let mut attr = ProgLoadAttr {
                prog_type: BPF_PROG_TYPE_KPROBE,
                insn_cnt,
                insns: insn_bytes.as_ptr() as u64,
                license: LICENSE.as_ptr() as u64,
                log_level: LOG_LEVEL,
                log_size: log.len() as u32,
                log_buf: log.as_mut_ptr() as u64,
                kern_version: 0,
                prog_flags: 0,
                prog_name: prog_name16(name),
                prog_ifindex: 0,
                expected_attach_type: BPF_TRACE_UPROBE_MULTI,
            };
            bpf(
                BPF_PROG_LOAD,
                (&raw mut attr).cast::<c_void>(),
                size_of::<ProgLoadAttr>() as u32,
            )
        }
    }
}

/// Raw `BPF_PROG_LOAD` for one fexit program; `log` receives the
/// verifier log. Returns fd or -1.
///
/// `TRACING(26)` + expected `FEXIT(25)` + per-prog `attach_btf_id` at
/// load (R1); `token: None` builds the 116-byte attr, `Some(fd)` the
/// token-extended attr. No prog BTF (K0 P1 attaches without it).
///
/// Crate-private: reached only via [`load_kcrypto`](super::instantiate::load_kcrypto).
pub(crate) fn prog_load_fexit_raw(
    name: &str,
    insn_bytes: &[u8],
    insn_cnt: u32,
    attach_btf_id: u32,
    log: &mut [u8],
    token: Option<RawFd>,
) -> c_long {
    // SAFETY: attr + pointees (insns, license, log) outlive the syscall.
    unsafe {
        if let Some(token_fd) = token {
            let mut attr = TokenProgAttr {
                prog_type: BPF_PROG_TYPE_TRACING,
                insn_cnt,
                insns: insn_bytes.as_ptr() as u64,
                license: LICENSE.as_ptr() as u64,
                log_level: KCRYPTO_LOG_LEVEL,
                log_size: log.len() as u32,
                log_buf: log.as_mut_ptr() as u64,
                kern_version: 0,
                prog_flags: BPF_F_TOKEN_FD,
                prog_name: prog_name16(name),
                prog_ifindex: 0,
                expected_attach_type: BPF_TRACE_FEXIT,
                prog_btf_fd: 0,
                func_info_rec_size: 0,
                func_info: 0,
                func_info_cnt: 0,
                line_info_rec_size: 0,
                line_info: 0,
                line_info_cnt: 0,
                attach_btf_id,
                attach_union: 0,
                core_relo_cnt: 0,
                fd_array: 0,
                core_relos: 0,
                core_relo_rec_size: 0,
                log_true_size: 0,
                token_fd,
            };
            bpf(
                BPF_PROG_LOAD,
                (&raw mut attr).cast::<c_void>(),
                TOKEN_PROG_ATTR_LEN,
            )
        } else {
            let mut attr = FexitProgAttr {
                prog_type: BPF_PROG_TYPE_TRACING,
                insn_cnt,
                insns: insn_bytes.as_ptr() as u64,
                license: LICENSE.as_ptr() as u64,
                log_level: KCRYPTO_LOG_LEVEL,
                log_size: log.len() as u32,
                log_buf: log.as_mut_ptr() as u64,
                kern_version: 0,
                prog_flags: 0,
                prog_name: prog_name16(name),
                prog_ifindex: 0,
                expected_attach_type: BPF_TRACE_FEXIT,
                prog_btf_fd: 0,
                func_info_rec_size: 0,
                func_info: 0,
                func_info_cnt: 0,
                line_info_rec_size: 0,
                line_info: 0,
                line_info_cnt: 0,
                attach_btf_id,
                attach_union: 0,
            };
            bpf(
                BPF_PROG_LOAD,
                (&raw mut attr).cast::<c_void>(),
                FEXIT_PROG_ATTR_LEN,
            )
        }
    }
}
