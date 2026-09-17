// SPDX-License-Identifier: GPL-3.0-or-later
//! Attach gates: rejection order before any link syscall.
//!
//! Stale generation, non-Pid scope, empty offsets, and NUL-unsafe
//! paths all reject before the `BPF_LINK_CREATE` syscall; a bad prog
//! fd proves the kernel-error mapping. All run unprivileged.

use kryprobe_core::attach::{GenerationGuard, LinkGroup};
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::program::ProgramId;
use kryprobe_privilege::attach::{AttachError, attach_group};
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
    LinkGroup {
        object: object(),
        program: ProgramId::UprobeMultiSelfProbe,
        scope,
        entry: true,
        generation: PlanGeneration::new(1),
    }
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
    let err = attach_group(
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
        let err = attach_group(
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
fn empty_offsets_rejected() {
    let err = attach_group(
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
fn nul_in_path_rejected() {
    let err = attach_group(
        &group(TargetScope::Pid { pid: 1 }),
        &guard(1),
        &bad_prog_fd(),
        &PathBuf::from("bad\0path"),
        &[0x1000],
    )
    .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("NUL-safe")),
        "got {err}"
    );
}

#[test]
fn bad_prog_fd_maps_kernel_errno() {
    // Own pid + own exe: only the prog fd is wrong, so the kernel
    // must answer EBADF through the typed mapping.
    let exe = std::env::current_exe().expect("own exe");
    let err = attach_group(
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
