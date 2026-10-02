// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw uprobe-multi link groups: scope-checked attach + RAII links (T7c2).

use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{
    BPF_LINK_CREATE, BPF_TRACE_FENTRY, BPF_TRACE_FEXIT, BPF_TRACE_FSESSION, BPF_TRACE_UPROBE_MULTI,
    LinkTracing, LinkUprobeMulti, bpf, fd_or_errno,
};
use core::ffi::c_void;
use kryprobe_core::attach::{COUNT_SLOTS, cookie_for};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{GenerationGuard, LinkGroup};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `BPF_F_UPROBE_MULTI_RETURN`: link flag selecting return probes.
/// Crate-visible so the decoy harness's test-local wide attach stamps
/// the same flag instead of minting its own copy.
pub(crate) const UPROBE_MULTI_RETURN: u32 = 1 << 0;

/// Link-group attach failure: rejection or syscall errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    /// Admission rejected the scope.
    Rejected {
        /// Rejection reason.
        reason: String,
    },
    /// Link creation syscall failed.
    LinkFailed {
        /// Attach stage that failed.
        stage: String,
        /// Kernel errno.
        errno: i32,
    },
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
/// `COUNT[idx]`. The uprobe spine serves `Pid` scope (entry vs return
/// selects `um_flags`); `System` is system-wide kernel probes (kcrypto
/// fexit, kp2 §3), not a pid filter: it builds a tracing `LINK_CREATE`
/// (attach type 25, `target_btf_id` 0, 64-byte attr per R1) and never touches
/// `object`/`offsets` (fexit attaches are whole-function; the scope
/// carries no path, and non-empty inputs reject fail-closed).
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
    if group.scope == TargetScope::System {
        return attach_fexit(prog_fd, object, offsets);
    }
    let pid = match group.scope {
        TargetScope::Pid { pid } => pid,
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

/// Tracing `LINK_CREATE` attr constructor (K5 Task 3 extraction):
/// attach type 25 (`FEXIT`), `target_btf_id` 0 (the kernel binds the
/// load-time `attach_btf_id`), 64-byte attr (R1 —
/// `evidence/k0/P1-attach-matrix.txt`). No cookie: kcrypto attribution
/// is in-BPF.
///
/// Deliberately token-free: UAPI provides NO token field for
/// `BPF_LINK_CREATE` (verified against the installed `linux/bpf.h`: the
/// struct ends at the attach union), and K5 Task 1 proved the kernel
/// demands no `link_create` delegation
/// (`DELEGATE_CMDS=map_create:prog_load`). A token-loaded program
/// remembers its token, and the kernel authorizes the fexit link
/// against it — so this constructor takes no token, and the `Some` and
/// `None` loader paths emit byte-identical link attrs by construction.
/// [`attach_fexit`] calls this verbatim; the unit test pins the shape.
pub(crate) fn fexit_link_attr(prog_fd: RawFd) -> LinkTracing {
    LinkTracing {
        prog_fd: prog_fd as u32,
        target_fd: 0,
        attach_type: BPF_TRACE_FEXIT,
        flags: 0,
        target_btf_id: 0,
        pad: 0,
        cookie: 0,
        tail: [0; 4],
    }
}

/// Tracing `LINK_CREATE` attr constructor, session split (T06 W8):
/// the same 64-byte R1 shape as [`fexit_link_attr`], with the
/// caller-supplied attach type (`FSESSION` for lifecycle session
/// programs; `FENTRY`/`FEXIT` retained for the frozen api-returns
/// path). Any other attach type refuses instead of emitting a
/// malformed attr. Token-free like the fexit twin (UAPI has no
/// token field for link create).
pub(crate) fn tracing_link_attr(
    prog_fd: RawFd,
    attach_type: u32,
) -> Result<LinkTracing, AttachError> {
    if attach_type != BPF_TRACE_FSESSION
        && attach_type != BPF_TRACE_FENTRY
        && attach_type != BPF_TRACE_FEXIT
    {
        return Err(AttachError::Rejected {
            reason: format!(
                "tracing link needs FSESSION(58), FENTRY(24) or FEXIT(25) attach type, got {attach_type}"
            ),
        });
    }
    Ok(LinkTracing {
        prog_fd: prog_fd as u32,
        target_fd: 0,
        attach_type,
        flags: 0,
        target_btf_id: 0,
        pad: 0,
        cookie: 0,
        tail: [0; 4],
    })
}

/// Attach one tracing program system-wide with an explicit attach
/// type (T06 lifecycle entry/exit split).
///
/// Same authorization as [`attach_group`]'s System arm (generation
/// guard + System-only + empty coords), reached crate-internally by
/// the lifecycle bring-up; the shared [`AttachAuthority`] facet
/// contract stays minimal per its SECURITY rationale. `attach_type`
/// is `FENTRY` for entry programs, `FEXIT` for return programs (any
/// other value refuses via [`tracing_link_attr`]).
pub(crate) fn attach_group_tracing(
    group: &LinkGroup,
    guard: &GenerationGuard,
    prog_fd: &OwnedFd,
    attach_type: u32,
) -> Result<OwnedLink, AttachError> {
    if group.generation() != guard.generation {
        return Err(AttachError::Rejected {
            reason: format!(
                "stale plan generation (group={} vs current={})",
                group.generation(),
                guard.generation
            ),
        });
    }
    if group.scope != TargetScope::System {
        return Err(AttachError::Rejected {
            reason: format!("tracing attach needs System scope, got {:?}", group.scope),
        });
    }
    let mut attr = tracing_link_attr(prog_fd.as_raw_fd(), attach_type)?;
    // SAFETY: attr outlives the syscall; no pointees.
    let ret = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkTracing>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(fd) => Ok(OwnedLink { _fd: fd }),
        Err(errno) => Err(AttachError::LinkFailed {
            stage: "tracing_link".to_owned(),
            errno,
        }),
    }
}

/// Attach one fexit program system-wide (K1 Task 2, C1; K0 G4).
///
/// Tracing `LINK_CREATE` via [`fexit_link_attr`]. `object`/`offsets`
/// must be empty (a confused caller passing uprobe coordinates to a
/// whole-function attach rejects here, before any syscall).
fn attach_fexit(
    prog_fd: &OwnedFd,
    object: &Path,
    offsets: &[u64],
) -> Result<OwnedLink, AttachError> {
    // Both rejections name the fexit path and the Pid-scope owner of
    // uprobe coordinates. The parenthetical keeps the FROZEN
    // `attach_gates` pins (`Rejected` + "System"/"fentry"/"Pid scope",
    // before any object access): Task 2 may not touch that file's
    // expectations, so the migrated message retains the `fentry` token
    // in a historically-true clause instead of renaming it away.
    if !offsets.is_empty() {
        return Err(AttachError::Rejected {
            reason: "System scope fexit attach takes no offsets (whole functions, same no-coords rule as the fentry path it replaces; only spine Pid scope takes offsets)".to_owned(),
        });
    }
    if !object.as_os_str().is_empty() {
        return Err(AttachError::Rejected {
            reason:
                "System scope fexit attach carries no object path (same rule as the fentry path it replaces; only spine Pid scope reads one)"
                    .to_owned(),
        });
    }
    let mut attr = fexit_link_attr(prog_fd.as_raw_fd());
    // SAFETY: attr outlives the syscall; no pointees.
    let ret = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkTracing>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(fd) => Ok(OwnedLink { _fd: fd }),
        Err(errno) => Err(AttachError::LinkFailed {
            stage: "fexit_link".to_owned(),
            errno,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::COUNT_SLOTS;
    use crate::bpfloader::SPINE_MAPS;

    /// A borrowed-then-owned /dev/null fd: never a real prog fd, but the
    /// rejection paths below return before any syscall reads it.
    fn null_fd() -> super::OwnedFd {
        // SAFETY: read-only probe fd, solely owned from here.
        let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(raw >= 0, "open /dev/null");
        // SAFETY: `raw` is open and solely owned from here.
        unsafe { super::OwnedFd::from_raw_fd(raw) }
    }

    #[test]
    fn system_rejects_uprobe_coordinates() {
        // Offsets and object paths are meaningless for whole-function
        // fexit attaches: both reject before any syscall (unprivileged).
        let fd = null_fd();
        let err = super::attach_fexit(&fd, std::path::Path::new(""), &[7])
            .expect_err("non-empty offsets must reject");
        assert!(matches!(err, super::AttachError::Rejected { .. }), "{err}");
        let err = super::attach_fexit(&fd, std::path::Path::new("/bin/true"), &[])
            .expect_err("non-empty object must reject");
        assert!(matches!(err, super::AttachError::Rejected { .. }), "{err}");
    }

    #[test]
    fn fexit_link_attr_is_token_free_64_bytes() {
        // The link attr carries NO token field (UAPI has none; Task 1
        // proved no `link_create` delegation): the constructor takes no
        // token, so token and privileged paths emit identical bytes by
        // construction. Pins the R1 shape (FEXIT, load-time id bind).
        let attr = super::fexit_link_attr(99);
        assert_eq!(attr.prog_fd, 99);
        assert_eq!(attr.target_fd, 0);
        assert_eq!(attr.attach_type, super::BPF_TRACE_FEXIT);
        assert_eq!(attr.flags, 0);
        assert_eq!(attr.target_btf_id, 0);
        assert_eq!(attr.cookie, 0);
        assert_eq!(attr.tail, [0; 4]);
        assert_eq!(size_of::<super::LinkTracing>(), 64);
    }

    #[test]
    fn tracing_link_attr_pins_entry_and_exit_shapes() {
        // T06 split: the lifecycle dispatch builds one link attr per
        // edge — FENTRY for entry programs, FEXIT for return programs
        // (same 64-byte R1 shape, token-free); any other attach type
        // refuses instead of emitting a malformed attr.
        let entry = super::tracing_link_attr(99, super::BPF_TRACE_FENTRY)
            .expect("FENTRY is a tracing attach type");
        assert_eq!(entry.prog_fd, 99);
        assert_eq!(entry.attach_type, super::BPF_TRACE_FENTRY);
        assert_eq!(entry.target_btf_id, 0);
        let exit = super::tracing_link_attr(99, super::BPF_TRACE_FEXIT)
            .expect("FEXIT is a tracing attach type");
        assert_eq!(exit.attach_type, super::BPF_TRACE_FEXIT);
        assert_ne!(entry.attach_type, exit.attach_type);
        let err = super::tracing_link_attr(99, 26).expect_err("prog type is not an attach type");
        assert!(matches!(err, super::AttachError::Rejected { .. }), "{err}");
    }

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
