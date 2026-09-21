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
//!
//! K5 Task 3 extracts the three constructors ([`plain_prog_attr`],
//! [`plain_fexit_attr`], [`token_prog_attr`]): the raw loaders call them
//! verbatim, and the unit tests pin their shapes with a fake fd (no
//! privilege, no syscall).

use crate::probe::bpf_sys::{
    BPF_F_TOKEN_FD, BPF_PROG_LOAD, BPF_PROG_TYPE_KPROBE, BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT,
    BPF_TRACE_UPROBE_MULTI, bpf,
};
use core::ffi::{c_long, c_void};
use std::os::fd::RawFd;

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
pub(crate) struct ProgLoadAttr {
    pub(crate) prog_type: u32,
    pub(crate) insn_cnt: u32,
    pub(crate) insns: u64,
    pub(crate) license: u64,
    pub(crate) log_level: u32,
    pub(crate) log_size: u32,
    pub(crate) log_buf: u64,
    pub(crate) kern_version: u32,
    pub(crate) prog_flags: u32,
    pub(crate) prog_name: [u8; 16],
    pub(crate) prog_ifindex: u32,
    pub(crate) expected_attach_type: u32,
}

/// Token-extended prog attr through `prog_token_fd` (148 bytes, UAPI order).
#[repr(C)]
pub(crate) struct TokenProgAttr {
    pub(crate) prog_type: u32,
    pub(crate) insn_cnt: u32,
    pub(crate) insns: u64,
    pub(crate) license: u64,
    pub(crate) log_level: u32,
    pub(crate) log_size: u32,
    pub(crate) log_buf: u64,
    pub(crate) kern_version: u32,
    pub(crate) prog_flags: u32,
    pub(crate) prog_name: [u8; 16],
    pub(crate) prog_ifindex: u32,
    pub(crate) expected_attach_type: u32,
    pub(crate) prog_btf_fd: u32,
    pub(crate) func_info_rec_size: u32,
    pub(crate) func_info: u64,
    pub(crate) func_info_cnt: u32,
    pub(crate) line_info_rec_size: u32,
    pub(crate) line_info: u64,
    pub(crate) line_info_cnt: u32,
    pub(crate) attach_btf_id: u32,
    pub(crate) attach_union: u32,
    pub(crate) core_relo_cnt: u32,
    pub(crate) fd_array: u64,
    pub(crate) core_relos: u64,
    pub(crate) core_relo_rec_size: u32,
    pub(crate) log_true_size: u32,
    pub(crate) token_fd: i32,
}

/// Bytes handed to the kernel for the token prog attr: the 148-byte UAPI
/// prefix, not the 4-byte alignment tail `repr(C)` appends.
pub(crate) const TOKEN_PROG_ATTR_LEN: u32 = 148;

const _: () = assert!(size_of::<ProgLoadAttr>() == 72);
const _: () = assert!(size_of::<TokenProgAttr>() == 152);

/// `BPF_PROG_LOAD` attr for fexit through the attach union (116 bytes,
/// UAPI order): the K0-proven non-token shape (`attach_btf_id` at load,
/// no prog BTF — `evidence/k0/P1-attach-matrix.txt` R1).
#[repr(C)]
pub(crate) struct FexitProgAttr {
    pub(crate) prog_type: u32,
    pub(crate) insn_cnt: u32,
    pub(crate) insns: u64,
    pub(crate) license: u64,
    pub(crate) log_level: u32,
    pub(crate) log_size: u32,
    pub(crate) log_buf: u64,
    pub(crate) kern_version: u32,
    pub(crate) prog_flags: u32,
    pub(crate) prog_name: [u8; 16],
    pub(crate) prog_ifindex: u32,
    pub(crate) expected_attach_type: u32,
    pub(crate) prog_btf_fd: u32,
    pub(crate) func_info_rec_size: u32,
    pub(crate) func_info: u64,
    pub(crate) func_info_cnt: u32,
    pub(crate) line_info_rec_size: u32,
    pub(crate) line_info: u64,
    pub(crate) line_info_cnt: u32,
    pub(crate) attach_btf_id: u32,
    pub(crate) attach_union: u32,
}

/// Bytes handed to the kernel for the fexit prog attr: the 116-byte
/// UAPI prefix, not the 4-byte alignment tail `repr(C)` appends.
pub(crate) const FEXIT_PROG_ATTR_LEN: u32 = 116;

const _: () = assert!(size_of::<FexitProgAttr>() == 120);

static LICENSE: &[u8; 4] = b"GPL\0";

fn prog_name16(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// One program load's attr inputs: the values both the plain and the
/// token constructors project (pointers as `u64`, exactly as the attrs
/// carry them; `attach_btf_id` is 0 unless fexit).
pub(crate) struct ProgSpec<'a> {
    pub(crate) prog_type: u32,
    pub(crate) name: &'a str,
    pub(crate) insns_ptr: u64,
    pub(crate) insn_cnt: u32,
    pub(crate) log_level: u32,
    pub(crate) log_ptr: u64,
    pub(crate) log_len: u32,
    pub(crate) expected_attach_type: u32,
    pub(crate) attach_btf_id: u32,
}

/// Plain 72-byte spine attr (the `None` path: privilege, today's bytes).
pub(crate) fn plain_prog_attr(spec: &ProgSpec<'_>) -> ProgLoadAttr {
    ProgLoadAttr {
        prog_type: spec.prog_type,
        insn_cnt: spec.insn_cnt,
        insns: spec.insns_ptr,
        license: LICENSE.as_ptr() as u64,
        log_level: spec.log_level,
        log_size: spec.log_len,
        log_buf: spec.log_ptr,
        kern_version: 0,
        prog_flags: 0,
        prog_name: prog_name16(spec.name),
        prog_ifindex: 0,
        expected_attach_type: spec.expected_attach_type,
    }
}

/// Token-extended 148-byte prog attr (both spine and fexit `Some`
/// paths): `BPF_F_TOKEN_FD` is REQUIRED in `prog_flags` whenever
/// `token_fd` rides along (UAPI — the kernel refuses the attr without
/// it). No prog BTF (K0 P1 attaches without it).
pub(crate) fn token_prog_attr(spec: &ProgSpec<'_>, token_fd: RawFd) -> TokenProgAttr {
    TokenProgAttr {
        prog_type: spec.prog_type,
        insn_cnt: spec.insn_cnt,
        insns: spec.insns_ptr,
        license: LICENSE.as_ptr() as u64,
        log_level: spec.log_level,
        log_size: spec.log_len,
        log_buf: spec.log_ptr,
        kern_version: 0,
        prog_flags: BPF_F_TOKEN_FD,
        prog_name: prog_name16(spec.name),
        prog_ifindex: 0,
        expected_attach_type: spec.expected_attach_type,
        prog_btf_fd: 0,
        func_info_rec_size: 0,
        func_info: 0,
        func_info_cnt: 0,
        line_info_rec_size: 0,
        line_info: 0,
        line_info_cnt: 0,
        attach_btf_id: spec.attach_btf_id,
        attach_union: 0,
        core_relo_cnt: 0,
        fd_array: 0,
        core_relos: 0,
        core_relo_rec_size: 0,
        log_true_size: 0,
        token_fd,
    }
}

/// Plain 116-byte fexit attr (the `None` path: privilege, the K0-proven
/// non-token shape with per-prog `attach_btf_id` at load).
pub(crate) fn plain_fexit_attr(spec: &ProgSpec<'_>) -> FexitProgAttr {
    FexitProgAttr {
        prog_type: spec.prog_type,
        insn_cnt: spec.insn_cnt,
        insns: spec.insns_ptr,
        license: LICENSE.as_ptr() as u64,
        log_level: spec.log_level,
        log_size: spec.log_len,
        log_buf: spec.log_ptr,
        kern_version: 0,
        prog_flags: 0,
        prog_name: prog_name16(spec.name),
        prog_ifindex: 0,
        expected_attach_type: spec.expected_attach_type,
        prog_btf_fd: 0,
        func_info_rec_size: 0,
        func_info: 0,
        func_info_cnt: 0,
        line_info_rec_size: 0,
        line_info: 0,
        line_info_cnt: 0,
        attach_btf_id: spec.attach_btf_id,
        attach_union: 0,
    }
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
            let mut attr = token_prog_attr(
                &ProgSpec {
                    prog_type: BPF_PROG_TYPE_KPROBE,
                    name,
                    insns_ptr: insn_bytes.as_ptr() as u64,
                    insn_cnt,
                    log_level: LOG_LEVEL,
                    log_ptr: log.as_mut_ptr() as u64,
                    log_len: log.len() as u32,
                    expected_attach_type: BPF_TRACE_UPROBE_MULTI,
                    attach_btf_id: 0,
                },
                token_fd,
            );
            bpf(
                BPF_PROG_LOAD,
                (&raw mut attr).cast::<c_void>(),
                TOKEN_PROG_ATTR_LEN,
            )
        } else {
            let mut attr = plain_prog_attr(&ProgSpec {
                prog_type: BPF_PROG_TYPE_KPROBE,
                name,
                insns_ptr: insn_bytes.as_ptr() as u64,
                insn_cnt,
                log_level: LOG_LEVEL,
                log_ptr: log.as_mut_ptr() as u64,
                log_len: log.len() as u32,
                expected_attach_type: BPF_TRACE_UPROBE_MULTI,
                attach_btf_id: 0,
            });
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
            let mut attr = token_prog_attr(
                &ProgSpec {
                    prog_type: BPF_PROG_TYPE_TRACING,
                    name,
                    insns_ptr: insn_bytes.as_ptr() as u64,
                    insn_cnt,
                    log_level: KCRYPTO_LOG_LEVEL,
                    log_ptr: log.as_mut_ptr() as u64,
                    log_len: log.len() as u32,
                    expected_attach_type: BPF_TRACE_FEXIT,
                    attach_btf_id,
                },
                token_fd,
            );
            bpf(
                BPF_PROG_LOAD,
                (&raw mut attr).cast::<c_void>(),
                TOKEN_PROG_ATTR_LEN,
            )
        } else {
            let mut attr = plain_fexit_attr(&ProgSpec {
                prog_type: BPF_PROG_TYPE_TRACING,
                name,
                insns_ptr: insn_bytes.as_ptr() as u64,
                insn_cnt,
                log_level: KCRYPTO_LOG_LEVEL,
                log_ptr: log.as_mut_ptr() as u64,
                log_len: log.len() as u32,
                expected_attach_type: BPF_TRACE_FEXIT,
                attach_btf_id,
            });
            bpf(
                BPF_PROG_LOAD,
                (&raw mut attr).cast::<c_void>(),
                FEXIT_PROG_ATTR_LEN,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Never a real fd: constructors never syscall, so this value only
    /// proves fd placement (never dereferenced, never closed).
    const FAKE_FD: RawFd = 123_456_789;

    fn spine_spec() -> ProgSpec<'static> {
        ProgSpec {
            prog_type: BPF_PROG_TYPE_KPROBE,
            name: "entry",
            insns_ptr: 0x1000,
            insn_cnt: 7,
            log_level: LOG_LEVEL,
            log_ptr: 0x2000,
            log_len: 1024,
            expected_attach_type: BPF_TRACE_UPROBE_MULTI,
            attach_btf_id: 0,
        }
    }

    fn fexit_spec() -> ProgSpec<'static> {
        ProgSpec {
            prog_type: BPF_PROG_TYPE_TRACING,
            name: "fexit_crypto",
            insns_ptr: 0x3000,
            insn_cnt: 600,
            log_level: KCRYPTO_LOG_LEVEL,
            log_ptr: 0x4000,
            log_len: 2048,
            expected_attach_type: BPF_TRACE_FEXIT,
            attach_btf_id: 4242,
        }
    }

    #[test]
    fn kernel_attr_lens_pin_uapi_prefixes() {
        // The kernel lengths exclude the `repr(C)` alignment tails (148,
        // not 152; 116, not 120): pin them so an accidental `size_of`
        // swap fails here instead of E2BIG at load.
        assert_eq!(TOKEN_PROG_ATTR_LEN, 148);
        assert_eq!(FEXIT_PROG_ATTR_LEN, 116);
    }

    #[test]
    fn plain_spine_attr_is_todays_72_bytes() {
        // The spine `None` path: frozen bytes (flags 0, uprobe-multi
        // attach, level-2 log) — any drift breaks privileged loads.
        let spec = spine_spec();
        let attr = plain_prog_attr(&spec);
        assert_eq!(attr.prog_type, BPF_PROG_TYPE_KPROBE);
        assert_eq!(attr.insn_cnt, 7);
        assert_eq!(attr.insns, 0x1000);
        assert_eq!(attr.log_level, LOG_LEVEL);
        assert_eq!(attr.log_size, 1024);
        assert_eq!(attr.log_buf, 0x2000);
        assert_eq!(attr.prog_flags, 0);
        assert_eq!(&attr.prog_name[..5], b"entry");
        assert_eq!(attr.prog_name[5], 0);
        assert_eq!(attr.expected_attach_type, BPF_TRACE_UPROBE_MULTI);
        assert_eq!(size_of::<ProgLoadAttr>(), 72);
    }

    #[test]
    fn plain_fexit_attr_carries_attach_btf_id() {
        // The fexit `None` path: TRACING + FEXIT + per-prog id at load
        // (R1), flags 0, level-1 log — the K0-proven shape.
        let spec = fexit_spec();
        let attr = plain_fexit_attr(&spec);
        assert_eq!(attr.prog_type, BPF_PROG_TYPE_TRACING);
        assert_eq!(attr.attach_btf_id, 4242);
        assert_eq!(attr.expected_attach_type, BPF_TRACE_FEXIT);
        assert_eq!(attr.prog_flags, 0);
        assert_eq!(attr.log_level, KCRYPTO_LOG_LEVEL);
        assert_eq!(size_of::<FexitProgAttr>(), 120);
    }

    #[test]
    fn token_attr_carries_flag_fd_and_id() {
        // Both `Some` paths share this shape: flag set (the kernel
        // EINVALs without it), fake fd placed, attach id carried for
        // fexit (0 for spine), no prog BTF.
        for spec in [spine_spec(), fexit_spec()] {
            let attr = token_prog_attr(&spec, FAKE_FD);
            assert_eq!(attr.prog_flags, BPF_F_TOKEN_FD);
            assert_eq!(attr.token_fd, FAKE_FD);
            assert_eq!(attr.attach_btf_id, spec.attach_btf_id);
            assert_eq!(attr.prog_btf_fd, 0);
            assert_eq!(attr.log_true_size, 0);
            assert_eq!(size_of::<TokenProgAttr>(), 152);
        }
        let spine = token_prog_attr(&spine_spec(), FAKE_FD);
        assert_eq!(spine.prog_type, BPF_PROG_TYPE_KPROBE);
        assert_eq!(spine.log_level, LOG_LEVEL);
        let fexit = token_prog_attr(&fexit_spec(), FAKE_FD);
        assert_eq!(fexit.prog_type, BPF_PROG_TYPE_TRACING);
        assert_eq!(fexit.log_level, KCRYPTO_LOG_LEVEL);
    }
}
