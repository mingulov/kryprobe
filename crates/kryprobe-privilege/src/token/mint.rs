// SPDX-License-Identifier: GPL-3.0-or-later
//! Root-side token minting over a private bpffs mount (T8).
//!
//! Follows the kernel selftests/bpf `token` flow: `fsopen("bpf")`,
//! four `delegate_*` strings, `FSCONFIG_CMD_CREATE`, `fsmount`, then
//! `BPF_TOKEN_CREATE` on the mount fd. Syscall numbers come from libc;
//! the `linux/mount.h` command constants are spelled out (verified).

use super::{TokenAxes, TokenError, TokenHandle};
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{BPF_TOKEN_CREATE, TokenAttr, bpf, fd_or_errno, last_errno};
use std::os::raw::{c_long, c_void};

/// `linux/mount.h`: set a string mount parameter.
const FSCONFIG_SET_STRING: c_long = 1;
/// `linux/mount.h`: create (or reuse) the superblock.
const FSCONFIG_CMD_CREATE: c_long = 6;
/// `linux/mount.h`: close-on-exec mount fd.
const FSMOUNT_CLOEXEC: c_long = 1;

/// Smoke-lane delegation: trailing atoms use the kernel's lowercase
/// enum-name suffixes (`map_create`, `array`, `kprobe`, `trace_uprobe_multi`).
/// `percpu_array`/`ringbuf` follow the same rule (T12 root run confirms).
const DELEGATES: [(&[u8], &[u8]); 4] = [
    (b"delegate_cmds\0", b"map_create:prog_load\0"),
    (b"delegate_maps\0", b"array:percpu_array:ringbuf\0"),
    (b"delegate_progs\0", b"kprobe\0"),
    (b"delegate_attachs\0", b"trace_uprobe_multi\0"),
];

fn syscall_fd(stage: &'static str, ret: c_long) -> Result<OwnedFd, TokenError> {
    fd_or_errno(ret).map_err(|errno| TokenError::Denied { stage, errno })
}

/// Mints the smoke-lane token; verifies live axes before returning.
pub fn mint_smoke_token() -> Result<TokenHandle, TokenError> {
    // SAFETY: fsopen("bpf", 0) takes no out-params.
    let fs = syscall_fd("fsopen", unsafe {
        libc::syscall(libc::SYS_fsopen, c"bpf".as_ptr(), 0)
    })?;
    for (key, value) in DELEGATES {
        // SAFETY: NUL-terminated key/value, copied in synchronously.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                c_long::from(fs.as_raw_fd()),
                FSCONFIG_SET_STRING,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        };
        if rc != 0 {
            return Err(TokenError::Denied {
                stage: "fsconfig",
                errno: last_errno(),
            });
        }
    }
    // SAFETY: CREATE takes no key/value pointers.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            c_long::from(fs.as_raw_fd()),
            FSCONFIG_CMD_CREATE,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(TokenError::Denied {
            stage: "fsconfig-create",
            errno: last_errno(),
        });
    }
    // SAFETY: fsmount takes fds/flags only.
    let mnt = syscall_fd("fsmount", unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            c_long::from(fs.as_raw_fd()),
            FSMOUNT_CLOEXEC,
            0,
        )
    })?;
    let mut attr = TokenAttr {
        flags: 0,
        bpffs_fd: mnt.as_raw_fd() as u32,
    };
    // SAFETY: `attr` is a live stack struct; size matches its type.
    let ret = unsafe {
        bpf(
            BPF_TOKEN_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<TokenAttr>() as u32,
        )
    };
    let fd = syscall_fd("token-create", ret)?;
    TokenHandle::verified(fd, TokenAxes::smoke_expected())
}

/// `BPF_*_GET_*_ID` attr: `{start,next,open_flags,fd_token}` (16 bytes).
#[repr(C)]
struct IdScanAttr {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
    fd_by_id_token: i32,
}

const _: () = assert!(size_of::<IdScanAttr>() == 16);

const BPF_PROG_GET_NEXT_ID: u32 = 11;
const BPF_MAP_GET_NEXT_ID: u32 = 12;

/// Live `(map_ids, prog_ids)` for the T8 leak assertion (sorted ascending).
pub fn live_bpf_ids() -> Result<(Vec<u32>, Vec<u32>), TokenError> {
    fn scan(cmd: u32, stage: &'static str) -> Result<Vec<u32>, TokenError> {
        let mut ids = Vec::new();
        let mut start = 0u32;
        loop {
            let mut attr = IdScanAttr {
                start_id: start,
                next_id: 0,
                open_flags: 0,
                fd_by_id_token: -1,
            };
            // SAFETY: `attr` is a live stack struct; size matches its type.
            let rc = unsafe {
                bpf(
                    cmd,
                    (&raw mut attr).cast::<c_void>(),
                    size_of::<IdScanAttr>() as u32,
                )
            };
            if rc != 0 {
                let errno = last_errno();
                if errno == libc::ENOENT {
                    return Ok(ids);
                }
                return Err(TokenError::Denied { stage, errno });
            }
            if attr.next_id == 0 || attr.next_id <= start {
                return Ok(ids);
            }
            start = attr.next_id;
            ids.push(start);
        }
    }
    Ok((
        scan(BPF_MAP_GET_NEXT_ID, "id-scan-map")?,
        scan(BPF_PROG_GET_NEXT_ID, "id-scan-prog")?,
    ))
}
