// SPDX-License-Identifier: GPL-3.0-or-later
//! Facet inspect on own pid matches /proc/self/exe; dead pid is TargetGone.

use std::os::unix::fs::MetadataExt;

use kryprobe_core::authority::TargetInspectionAuthority;
use kryprobe_privilege::{InspectError, LocalPrivilegedAuthority};

#[test]
fn inspect_self_matches_proc_self_exe() {
    let pid = std::process::id();
    let snap = match LocalPrivilegedAuthority.inspect(pid) {
        Ok(snap) => snap,
        Err(err) => panic!("facet inspect(self) must succeed: {err}"),
    };
    assert_eq!(snap.pid, pid);
    assert!(snap.starttime > 0, "starttime must be nonzero");
    assert!(snap.maps_lines > 0, "maps must have lines");
    assert!(
        !snap.maps_first_dev.is_empty(),
        "first maps device must be present"
    );
    let meta = std::fs::symlink_metadata("/proc/self/exe").expect("self exe metadata");
    assert_eq!(snap.exe_dev, meta.dev());
    assert_eq!(snap.exe_ino, meta.ino());
    assert_eq!(snap.exe_size, meta.size());
}

#[test]
fn inspect_dead_pid_is_target_gone() {
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn true helper");
    let pid = child.id();
    child.wait().expect("wait for true helper");
    assert!(
        matches!(
            LocalPrivilegedAuthority.inspect(pid),
            Err(InspectError::TargetGone)
        ),
        "reaped pid {pid} must be TargetGone"
    );
}
