// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw uprobe-multi link groups: scope-checked attach + RAII links (T7c2).

use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{
    BPF_LINK_CREATE, BPF_TRACE_UPROBE_MULTI, LinkUprobeMulti, bpf, fd_or_errno,
};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{GenerationGuard, LinkGroup};
use std::ffi::CString;
use std::os::raw::c_void;
use std::path::Path;

/// `BPF_F_UPROBE_MULTI_RETURN`: link flag selecting return probes.
const UPROBE_MULTI_RETURN: u32 = 1 << 0;

/// Link-group attach failure: rejection or syscall errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    Rejected { reason: String },
    LinkFailed { stage: String, errno: i32 },
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { reason } => write!(f, "attach rejected: {reason}"),
            Self::LinkFailed { stage, errno } => {
                write!(f, "link create failed at {stage}: errno {errno}")
            }
        }
    }
}

impl std::error::Error for AttachError {}

/// RAII uprobe-multi link: drop closes (detaches) it.
#[derive(Debug)]
pub struct OwnedLink {
    _fd: OwnedFd,
}

impl OwnedLink {
    /// Borrows the link fd without transferring ownership.
    pub fn as_raw_fd(&self) -> i32 {
        self._fd.as_raw_fd()
    }
}

/// Attach one [`LinkGroup`]: scope-checked, generation-guarded link.
///
/// Cookies are `(generation << 32) | offset_index`. Only `Pid` scope is
/// supported by the spine; entry vs return selects `um_flags`.
pub fn attach_group(
    group: &LinkGroup,
    guard: &GenerationGuard,
    prog_fd: &OwnedFd,
    object: &Path,
    offsets: &[u64],
) -> Result<OwnedLink, AttachError> {
    if guard.is_stale(group.generation) {
        return Err(AttachError::Rejected {
            reason: format!(
                "stale plan generation: group {}, guard {}",
                group.generation, guard.generation
            ),
        });
    }
    let pid = match group.scope {
        TargetScope::Pid { pid } => pid,
        _ => {
            return Err(AttachError::Rejected {
                reason: "spine supports Pid scope only".to_owned(),
            });
        }
    };
    if offsets.is_empty() {
        return Err(AttachError::Rejected {
            reason: "link group has no offsets".to_owned(),
        });
    }
    let path = object.to_string_lossy().into_owned();
    let path_c = CString::new(path).map_err(|_| AttachError::Rejected {
        reason: "object path is not NUL-safe".to_owned(),
    })?;
    let generation = u64::from(group.generation.get());
    let cookies: Vec<u64> = (0..offsets.len() as u64)
        .map(|i| (generation << 32) | i)
        .collect();
    let mut attr = LinkUprobeMulti {
        prog_fd: prog_fd.as_raw_fd() as u32,
        target: 0,
        attach_type: BPF_TRACE_UPROBE_MULTI,
        link_flags: 0,
        path: path_c.as_ptr() as u64,
        offsets: offsets.as_ptr() as u64,
        ref_ctr_offsets: 0,
        cookies: cookies.as_ptr() as u64,
        cnt: offsets.len() as u32,
        um_flags: if group.entry { 0 } else { UPROBE_MULTI_RETURN },
        pid,
        pad: 0,
    };
    // SAFETY: attr + pointees (path, offsets, cookies) outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkUprobeMulti>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(fd) => Ok(OwnedLink { _fd: fd }),
        Err(errno) => Err(AttachError::LinkFailed {
            stage: "uprobe_multi_link".to_owned(),
            errno,
        }),
    }
}
