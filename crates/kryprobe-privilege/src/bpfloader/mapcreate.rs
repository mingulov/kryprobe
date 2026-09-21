// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw `BPF_MAP_CREATE` primitive, plain and tokenized (T8).
//!
//! `token: None` builds the 16-byte short attr, `Some(fd)` the 80-byte
//! token-extended attr with `BPF_F_TOKEN_FD` in `map_flags` (required
//! by UAPI when a token fd is provided). Sizes compile-time asserted.
//!
//! K5 Task 3 extracts the two constructors ([`plain_map_attr`],
//! [`token_map_attr`): [`map_create_raw`] calls them verbatim, and the
//! unit tests pin their shapes with a fake fd (no privilege, no
//! syscall — the flag/fd/size assertions below run unprivileged).

use crate::probe::bpf_sys::{BPF_F_TOKEN_FD, BPF_MAP_CREATE, MapAttr, bpf};
use core::ffi::{c_long, c_void};
use std::os::fd::RawFd;

/// Token-extended map attr through `map_token_fd` (80 bytes, UAPI order).
#[repr(C)]
pub(crate) struct TokenMapAttr {
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
    pub(crate) inner_map_fd: u32,
    pub(crate) numa_node: u32,
    pub(crate) map_name: [u8; 16],
    pub(crate) map_ifindex: u32,
    pub(crate) btf_fd: u32,
    pub(crate) btf_key: u32,
    pub(crate) btf_value: u32,
    pub(crate) btf_vmlinux: u32,
    pub(crate) map_extra: u64,
    pub(crate) value_btf_fd: i32,
    pub(crate) token_fd: i32,
}

const _: () = assert!(size_of::<TokenMapAttr>() == 80);

/// Plain 16-byte map attr (the `None` path: privilege, today's bytes).
pub(crate) fn plain_map_attr(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> MapAttr {
    MapAttr {
        map_type,
        key_size,
        value_size,
        max_entries,
    }
}

/// Token-extended 80-byte map attr: `BPF_F_TOKEN_FD` is REQUIRED in
/// `map_flags` whenever `token_fd` rides along (UAPI — the kernel
/// refuses the attr without it), and `value_btf_fd` stays -1 (no BTF).
pub(crate) fn token_map_attr(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    token_fd: RawFd,
) -> TokenMapAttr {
    TokenMapAttr {
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
    }
}

/// Raw `BPF_MAP_CREATE`; returns the fd or -1 (see `last_errno`).
///
/// Crate-private: reached only via the load facet's instantiate path.
pub(crate) fn map_create_raw(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    token: Option<RawFd>,
) -> c_long {
    // SAFETY: `attr` is a live stack struct; size matches its type.
    unsafe {
        if let Some(token_fd) = token {
            let mut attr = token_map_attr(map_type, key_size, value_size, max_entries, token_fd);
            bpf(
                BPF_MAP_CREATE,
                (&raw mut attr).cast::<c_void>(),
                size_of::<TokenMapAttr>() as u32,
            )
        } else {
            let mut attr = plain_map_attr(map_type, key_size, value_size, max_entries);
            bpf(
                BPF_MAP_CREATE,
                (&raw mut attr).cast::<c_void>(),
                size_of::<MapAttr>() as u32,
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

    #[test]
    fn plain_attr_is_todays_16_bytes() {
        // The `None` path: dims verbatim, 16 bytes — byte-for-byte the
        // pre-token behavior (any drift here breaks privileged loads).
        let attr = plain_map_attr(2, 4, 76, 1);
        assert_eq!(attr.map_type, 2);
        assert_eq!(attr.key_size, 4);
        assert_eq!(attr.value_size, 76);
        assert_eq!(attr.max_entries, 1);
        assert_eq!(size_of::<MapAttr>(), 16);
    }

    #[test]
    fn token_attr_carries_flag_and_fd() {
        // The `Some` path: dims verbatim, `BPF_F_TOKEN_FD` set (the
        // kernel EINVALs without it), fake fd in `token_fd`, BTF fds
        // off, 80 bytes.
        let attr = token_map_attr(2, 4, 76, 1, FAKE_FD);
        assert_eq!(attr.map_type, 2);
        assert_eq!(attr.key_size, 4);
        assert_eq!(attr.value_size, 76);
        assert_eq!(attr.max_entries, 1);
        assert_eq!(attr.map_flags, BPF_F_TOKEN_FD);
        assert_eq!(attr.token_fd, FAKE_FD);
        assert_eq!(attr.value_btf_fd, -1);
        assert_eq!(attr.map_name, [0; 16]);
        assert_eq!(attr.map_extra, 0);
        assert_eq!(size_of::<TokenMapAttr>(), 80);
    }
}
