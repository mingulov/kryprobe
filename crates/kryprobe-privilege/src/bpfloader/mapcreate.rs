// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw `BPF_MAP_CREATE` primitive, plain and tokenized (T8).
//!
//! `token: None` builds the 16-byte short attr, `Some(fd)` the 80-byte
//! token-extended attr with `BPF_F_TOKEN_FD` in `map_flags` (required
//! by UAPI when a token fd is provided). Sizes compile-time asserted.

use crate::probe::bpf_sys::{BPF_F_TOKEN_FD, BPF_MAP_CREATE, MapAttr, bpf};
use std::os::fd::RawFd;
use std::os::raw::{c_long, c_void};

/// Token-extended map attr through `map_token_fd` (80 bytes, UAPI order).
#[repr(C)]
struct TokenMapAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key: u32,
    btf_value: u32,
    btf_vmlinux: u32,
    map_extra: u64,
    value_btf_fd: i32,
    token_fd: i32,
}

const _: () = assert!(size_of::<TokenMapAttr>() == 80);

/// Raw `BPF_MAP_CREATE`; returns the fd or -1 (see `last_errno`).
pub fn map_create_raw(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    token: Option<RawFd>,
) -> c_long {
    // SAFETY: `attr` is a live stack struct; size matches its type.
    unsafe {
        if let Some(token_fd) = token {
            let mut attr = TokenMapAttr {
                map_type,
                key_size,
                value_size,
                max_entries,
                map_flags: BPF_F_TOKEN_FD,
                inner_map_fd: 0,
                numa_node: 0,
                map_name: [0; 16],
                map_ifindex: 0,
                btf_fd: 0,
                btf_key: 0,
                btf_value: 0,
                btf_vmlinux: 0,
                map_extra: 0,
                value_btf_fd: -1,
                token_fd,
            };
            bpf(
                BPF_MAP_CREATE,
                (&raw mut attr).cast::<c_void>(),
                size_of::<TokenMapAttr>() as u32,
            )
        } else {
            let mut attr = MapAttr {
                map_type,
                key_size,
                value_size,
                max_entries,
            };
            bpf(
                BPF_MAP_CREATE,
                (&raw mut attr).cast::<c_void>(),
                size_of::<MapAttr>() as u32,
            )
        }
    }
}
