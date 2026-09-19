// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw uprobe-multi link groups: scope-checked attach + RAII links (T7c2).

use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{
    BPF_LINK_CREATE, BPF_TRACE_UPROBE_MULTI, LinkUprobeMulti, bpf, fd_or_errno,
};
use kryprobe_core::attach::{COUNT_SLOTS, cookie_for};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{GenerationGuard, LinkGroup};
use std::ffi::CString;
use std::os::raw::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `BPF_F_UPROBE_MULTI_RETURN`: link flag selecting return probes.
/// Crate-visible so the decoy harness's test-local wide attach stamps
/// the same flag instead of minting its own copy.
pub(crate) const UPROBE_MULTI_RETURN: u32 = 1 << 0;

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

    /// Wraps an already-created link fd. Crate-private, for the decoy
    /// harness's test-local wide attach only: it performs no attach
    /// and no authorization, so the facet's pid-0 refusal still guards
    /// every link the facet itself creates.
    pub(crate) fn from_fd(fd: OwnedFd) -> Self {
        Self { _fd: fd }
    }
}

/// Attach one [`LinkGroup`]: scope-checked, generation-guarded link.
///
/// Cookies are `(generation << 32) | (index_base + offset_index)` over the
/// group's allocator-issued range, so concurrent groups never conflate
/// `COUNT[idx]`. Only `Pid` scope is supported by the uprobe spine;
/// entry vs return selects `um_flags`. `System` is system-wide kernel
/// probes (kcrypto fentry, kp2 §3), not a pid filter: it rejects here
/// with a pointer at the fentry path and never touches a cgroup path
/// (the scope carries none).
///
/// Crate-private: the only external entry is the attach facet
/// (`AttachAuthority::attach_group` on `LocalPrivilegedAuthority`).
pub(crate) fn attach_group(
    group: &LinkGroup,
    guard: &GenerationGuard,
    prog_fd: &OwnedFd,
    object: &Path,
    offsets: &[u64],
) -> Result<OwnedLink, AttachError> {
    if guard.is_stale(group.generation()) {
        return Err(AttachError::Rejected {
            reason: format!(
                "stale plan generation: group {}, guard {}",
                group.generation(),
                guard.generation
            ),
        });
    }
    let pid = match group.scope {
        TargetScope::Pid { pid } => pid,
        TargetScope::System => {
            return Err(AttachError::Rejected {
                reason:
                    "System scope is system-wide (kcrypto fentry); spine supports Pid scope only"
                        .to_owned(),
            });
        }
        _ => {
            return Err(AttachError::Rejected {
                reason: "spine supports Pid scope only".to_owned(),
            });
        }
    };
    // pid 0 on uprobe-multi link-create attaches ALL processes: reject
    // here so a zero pid can never widen a single-target scope
    // system-wide at the authorization boundary.
    if pid == 0 {
        return Err(AttachError::Rejected {
            reason: "pid 0 rejected: uprobe-multi pid 0 attaches all processes".to_owned(),
        });
    }
    if offsets.is_empty() {
        return Err(AttachError::Rejected {
            reason: "link group has no offsets".to_owned(),
        });
    }
    // The authorization boundary re-validates the allocation: a stray or
    // lying base must refuse here, never alias another group's slots or
    // lean on the BPF index drop. Groups built in-process are
    // issuance-only, but deserialized groups can carry any base, so this
    // check stays. Saturating u64 math: no wrap for any inputs.
    if u64::from(group.index_base()).saturating_add(offsets.len() as u64) > u64::from(COUNT_SLOTS) {
        return Err(AttachError::Rejected {
            reason: format!(
                "cookie index range overflows {} slots: base {} + {} offsets",
                COUNT_SLOTS,
                group.index_base(),
                offsets.len()
            ),
        });
    }
    // Raw bytes, never lossy: a lossy conversion could resolve onto the
    // wrong file. Non-UTF8 and interior-NUL reject with distinct reasons.
    let raw = object.as_os_str().as_bytes();
    std::str::from_utf8(raw).map_err(|_| AttachError::Rejected {
        reason: "object path is not valid UTF-8".to_owned(),
    })?;
    let path_c = CString::new(raw).map_err(|_| AttachError::Rejected {
        reason: "object path is not NUL-safe".to_owned(),
    })?;
    let cookies: Vec<u64> = (0..offsets.len() as u32)
        .map(|i| cookie_for(group.generation(), group.index_base() + i))
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

#[cfg(test)]
mod tests {
    use super::COUNT_SLOTS;
    use crate::bpfloader::SPINE_MAPS;

    #[test]
    fn count_slots_match_frozen_spine_dims() {
        // Chain pin: the loader asserts the object against SPINE_MAPS, and
        // this asserts the allocator's index space against SPINE_MAPS, so
        // the BPF COUNT map, the loader, and the allocator agree on 64.
        let count = SPINE_MAPS
            .iter()
            .find(|(name, _)| *name == "COUNT")
            .map(|(_, dims)| *dims)
            .expect("SPINE_MAPS carries COUNT");
        assert_eq!(count.max_entries, COUNT_SLOTS);
    }
}
