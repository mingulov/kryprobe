// SPDX-License-Identifier: GPL-3.0-or-later
//! Attach gates: rejection order before any link syscall (via the attach facet).
//!
//! Stale generation, non-Pid scope, pid zero, empty offsets,
//! index-range overflow, and NUL-unsafe paths all reject before the
//! `BPF_LINK_CREATE` syscall; a bad prog fd proves the kernel-error
//! mapping. All run unprivileged.

use kryprobe_core::attach::{CookieAllocator, GenerationGuard, LinkGroup};
use kryprobe_core::authority::AttachAuthority;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::program::ProgramId;
use kryprobe_privilege::LocalPrivilegedAuthority;
use kryprobe_privilege::attach::AttachError;
use kryprobe_privilege::fd::OwnedFd;
use std::path::PathBuf;

fn object() -> ObjectRef {
    ObjectRef {
        dev: 0,
        ino: 0,
        size: 0,
        mtime: 0,
        role: ObjectRole::Executable,
    }
}

fn group(scope: TargetScope) -> LinkGroup {
    group_at_base(scope, 0)
}

/// Group issued at `base`: skip `base` slots, then take the 1-slot
/// group range. Groups are issuance-only, so even hostile-shape cases
/// (base 63 + overlong offsets) are built through the allocator.
fn group_at_base(scope: TargetScope, base: u32) -> LinkGroup {
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    if base > 0 {
        alloc
            .allocate(base as usize)
            .expect("skip to the wanted base fits");
    }
    let range = alloc.allocate(1).expect("group range fits");
    debug_assert_eq!(range.base(), base);
    LinkGroup::from_range(
        object(),
        ProgramId::UprobeMultiSelfProbe,
        scope,
        true,
        range,
    )
}

fn guard(generation: u32) -> GenerationGuard {
    GenerationGuard {
        generation: PlanGeneration::new(generation),
    }
}

/// Never a real fd: the link syscall fails EBADF before use.
fn bad_prog_fd() -> OwnedFd {
    // SAFETY: never dereferenced; the bpf() call fails first.
    unsafe { OwnedFd::from_raw_fd(-1) }
}

#[test]
fn stale_generation_rejected_first() {
    // Stale guard wins over scope + object checks (both bogus here).
    let err = LocalPrivilegedAuthority
        .attach_group(
            &group(TargetScope::Tree { root: 1 }),
            &guard(2),
            &bad_prog_fd(),
            &PathBuf::from("/nonexistent-kryprobe-object"),
            &[0x1000],
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("stale")),
        "got {err}"
    );
}

#[test]
fn non_pid_scopes_rejected_before_object_access() {
    for scope in [
        TargetScope::Tree { root: 1 },
        TargetScope::Cgroup {
            path: "/sys/fs/cgroup".to_owned(),
        },
        TargetScope::OwnedRun,
    ] {
        let err = LocalPrivilegedAuthority
            .attach_group(
                &group(scope),
                &guard(1),
                &bad_prog_fd(),
                &PathBuf::from("/nonexistent-kryprobe-object"),
                &[0x1000],
            )
            .unwrap_err();
        assert!(
            matches!(err, AttachError::Rejected { ref reason } if reason.contains("Pid scope")),
            "got {err}"
        );
    }
}

#[test]
fn pid_zero_rejected_before_syscall() {
    // pid 0 on uprobe-multi link-create attaches ALL processes: a zero
    // pid must reject at the authorization boundary, never widen a
    // single-target scope system-wide. Rejected (not LinkFailed/EBADF
    // from the bad prog fd) proves no syscall ran.
    let err = LocalPrivilegedAuthority
        .attach_group(
            &group(TargetScope::Pid { pid: 0 }),
            &guard(1),
            &bad_prog_fd(),
            &PathBuf::from("/nonexistent-kryprobe-object"),
            &[0x1000],
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("pid 0")),
        "got {err}"
    );
}

#[test]
fn empty_offsets_rejected() {
    let err = LocalPrivilegedAuthority
        .attach_group(
            &group(TargetScope::Pid { pid: 1 }),
            &guard(1),
            &bad_prog_fd(),
            &PathBuf::from("/nonexistent-kryprobe-object"),
            &[],
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("no offsets")),
        "got {err}"
    );
}

#[test]
fn index_range_overflow_rejected_before_syscall() {
    // Base 63 + 2 offsets overflows 64 slots; base 63 + 64 offsets
    // proves the boundary distrusts the caller-controlled offsets
    // length too. Both reject, never alias another group's slots or
    // lean on the BPF index drop. (A hostile u32::MAX base is no longer
    // expressible in-process — issuance-only construction — and the
    // saturating u64 range math cannot wrap for any offsets length.)
    let offsets_two = vec![0x1000, 0x2000];
    let offsets_many = vec![0x1000; 64];
    for offsets in [&offsets_two, &offsets_many] {
        let over = group_at_base(TargetScope::Pid { pid: 1 }, 63);
        let err = LocalPrivilegedAuthority
            .attach_group(
                &over,
                &guard(1),
                &bad_prog_fd(),
                &PathBuf::from("/nonexistent-kryprobe-object"),
                offsets,
            )
            .unwrap_err();
        assert!(
            matches!(err, AttachError::Rejected { ref reason } if reason.contains("index range")),
            "63 + {} offsets: got {err}",
            offsets.len()
        );
    }
}

#[test]
fn exact_fit_index_range_reaches_syscall() {
    // Base 63 + 1 offset exactly fills 64 slots: validation passes and
    // the bad prog fd proves the syscall was reached (LinkFailed/EBADF,
    // not Rejected).
    let exe = std::env::current_exe().expect("own exe");
    let edge = group_at_base(
        TargetScope::Pid {
            pid: std::process::id(),
        },
        63,
    );
    let err = LocalPrivilegedAuthority
        .attach_group(&edge, &guard(1), &bad_prog_fd(), &exe, &[0x1000])
        .unwrap_err();
    assert!(
        matches!(err, AttachError::LinkFailed { errno, .. } if errno == libc::EBADF),
        "got {err}"
    );
}

#[test]
fn nul_in_path_rejected() {
    let err = LocalPrivilegedAuthority
        .attach_group(
            &group(TargetScope::Pid { pid: 1 }),
            &guard(1),
            &bad_prog_fd(),
            &PathBuf::from("bad\0path"),
            &[0x1000],
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("NUL-safe") && !reason.contains("UTF-8")),
        "got {err}"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_path_rejected_before_syscall() {
    // 0xFF is never valid UTF-8: must reject, not lossy-convert onto a
    // neighbouring path. Rejected (not LinkFailed/EBADF) proves no syscall.
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let raw = OsString::from_vec(b"/nonexistent-kryprobe-\xff-object".to_vec());
    let err = LocalPrivilegedAuthority
        .attach_group(
            &group(TargetScope::Pid { pid: 1 }),
            &guard(1),
            &bad_prog_fd(),
            &PathBuf::from(raw),
            &[0x1000],
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("UTF-8") && !reason.contains("NUL-safe")),
        "got {err}"
    );
}

#[test]
fn bad_prog_fd_maps_kernel_errno() {
    // Own pid + own exe: only the prog fd is wrong, so the kernel
    // must answer EBADF through the typed mapping.
    let exe = std::env::current_exe().expect("own exe");
    let err = LocalPrivilegedAuthority
        .attach_group(
            &group(TargetScope::Pid {
                pid: std::process::id(),
            }),
            &guard(1),
            &bad_prog_fd(),
            &exe,
            &[0x1000],
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::LinkFailed { ref stage, errno } if stage == "uprobe_multi_link" && errno == libc::EBADF),
        "got {err}"
    );
}
