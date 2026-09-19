// SPDX-License-Identifier: GPL-3.0-or-later
//! Fan-out gates: Tree/Cgroup scope resolution through the fan-out helper.
//!
//! `LocalPrivilegedAuthority::resolve_scope` admits Tree/Cgroup members
//! through the inspect facet (one member = one future Pid link); every
//! rejection below is an honest `Rejected`, never a silent subset. All
//! run unprivileged.

use kryprobe_core::attach::{CookieAllocator, LinkGroup};
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::program::ProgramId;
use kryprobe_privilege::LocalPrivilegedAuthority;
use kryprobe_privilege::attach::AttachError;
use kryprobe_privilege::fanout::FanoutPlan;

fn self_pid() -> u32 {
    std::process::id()
}

fn template(scope: TargetScope) -> LinkGroup {
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    let range = alloc.allocate(1).expect("fixture range fits");
    LinkGroup::from_range(
        ObjectRef {
            dev: 0,
            ino: 0,
            size: 0,
            mtime: 0,
            role: ObjectRole::Executable,
        },
        ProgramId::UprobeMultiSelfProbe,
        scope,
        true,
        range,
    )
}

#[test]
fn tree_self_allowed_and_contains_root() {
    let plan = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Tree { root: self_pid() }, u64::MAX)
        .expect("own tree must resolve");
    assert!(
        plan.members.iter().any(|m| m.pid == self_pid()),
        "members must contain the root: {plan:?}"
    );
    assert!(plan.members.windows(2).all(|w| w[0].pid < w[1].pid));
    assert!(
        plan.members.iter().all(|m| m.starttime > 0),
        "admitted members carry a starttime identity: {plan:?}"
    );
}

#[test]
fn tree_missing_root_rejected() {
    let err = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Tree { root: u32::MAX }, u64::MAX)
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("gone")),
        "got {err}"
    );
}

#[test]
fn tree_zero_root_rejected() {
    let err = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Tree { root: 0 }, u64::MAX)
        .unwrap_err();
    assert!(matches!(err, AttachError::Rejected { .. }), "got {err}");
}

#[test]
fn pid_scope_rejected_as_not_fanout() {
    // Pid attaches directly via attach_group; fan-out is for Tree/Cgroup.
    let err = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Pid { pid: self_pid() }, u64::MAX)
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("directly")),
        "got {err}"
    );
}

#[test]
fn system_scope_skips_fanout() {
    // System-wide kernel probes have no members to enumerate (kp2 §3):
    // resolve and refresh both refuse as non-fan-out scopes without
    // touching any cgroup path (the scope carries none).
    let err = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::System, u64::MAX)
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("System")
            && reason.contains("fan-out")
            && reason.contains("Tree/Cgroup")),
        "got {err}"
    );
    let plan = FanoutPlan {
        scope: TargetScope::System,
        members: Vec::new(),
        exited_during_resolve: 0,
    };
    let err = LocalPrivilegedAuthority
        .refresh_fanout(&plan, u64::MAX)
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("System")
            && reason.contains("fan-out")),
        "got {err}"
    );
}

#[test]
fn owned_run_rejected() {
    let err = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::OwnedRun, u64::MAX)
        .unwrap_err();
    // Pins the T12 decline pointer: no session spawner exists (declined
    // for want of a backend consumer), so fan-out stays Tree/Cgroup-only.
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("declined")
            && reason.contains("Tree/Cgroup")),
        "got {err}"
    );
}

#[test]
fn cgroup_empty_path_rejected() {
    let err = LocalPrivilegedAuthority
        .resolve_scope(
            &TargetScope::Cgroup {
                path: String::new(),
            },
            u64::MAX,
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("empty")),
        "got {err}"
    );
}

#[test]
fn cgroup_missing_path_rejected() {
    let err = LocalPrivilegedAuthority
        .resolve_scope(
            &TargetScope::Cgroup {
                path: "/nonexistent-kryprobe-cgroup".to_owned(),
            },
            u64::MAX,
        )
        .unwrap_err();
    assert!(matches!(err, AttachError::Rejected { .. }), "got {err}");
}

#[test]
fn cgroup_fixture_allowed_with_exit_receipt() {
    // Synthetic cgroup tree: self (admitted) + a never-lived pid
    // (exit receipt) + a nested empty child (recursion proof).
    let dir = std::env::temp_dir().join(format!("kryprobe-fanout-{}", self_pid()));
    let child = dir.join("nested");
    std::fs::create_dir_all(&child).expect("fixture dirs");
    std::fs::write(
        dir.join("cgroup.procs"),
        format!("{}\n{}\n", self_pid(), u32::MAX),
    )
    .expect("root cgroup.procs");
    std::fs::write(child.join("cgroup.procs"), "").expect("nested cgroup.procs");
    let plan = LocalPrivilegedAuthority.resolve_scope(
        &TargetScope::Cgroup {
            path: dir.to_string_lossy().into_owned(),
        },
        u64::MAX,
    );
    std::fs::remove_dir_all(&dir).ok();
    let plan: FanoutPlan = plan.expect("fixture cgroup must resolve");
    assert_eq!(
        plan.members.iter().map(|m| m.pid).collect::<Vec<_>>(),
        vec![self_pid()],
        "{plan:?}"
    );
    assert_eq!(plan.exited_during_resolve, 1, "{plan:?}");
}

#[test]
fn cgroup_plain_dir_rejected() {
    // A directory without cgroup.procs is not a cgroup.
    let dir = std::env::temp_dir().join(format!("kryprobe-fanout-plain-{}", self_pid()));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let err = LocalPrivilegedAuthority.resolve_scope(
        &TargetScope::Cgroup {
            path: dir.to_string_lossy().into_owned(),
        },
        u64::MAX,
    );
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        matches!(err, Err(AttachError::Rejected { .. })),
        "got {err:?}"
    );
}

#[test]
fn tree_budget_zero_rejected() {
    let err = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Tree { root: self_pid() }, 0)
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("budget")),
        "got {err}"
    );
}

#[test]
fn refresh_stable_tree_reports_no_changes() {
    let plan = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Tree { root: self_pid() }, u64::MAX)
        .expect("own tree must resolve");
    let (next, refresh) = LocalPrivilegedAuthority
        .refresh_fanout(&plan, u64::MAX)
        .expect("stable refresh must succeed");
    assert!(refresh.added.is_empty(), "{refresh:?}");
    assert!(refresh.exited.is_empty(), "{refresh:?}");
    assert_eq!(next.members, plan.members);
    assert_eq!(next.exited_during_resolve, plan.exited_during_resolve);
}

#[test]
fn refresh_budget_shrink_rejected() {
    let plan = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Tree { root: self_pid() }, u64::MAX)
        .expect("own tree must resolve");
    let err = LocalPrivilegedAuthority
        .refresh_fanout(&plan, 0)
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("budget")),
        "got {err}"
    );
}

#[test]
fn link_groups_mirror_template_as_pid() {
    let plan = LocalPrivilegedAuthority
        .resolve_scope(&TargetScope::Tree { root: self_pid() }, u64::MAX)
        .expect("own tree must resolve");
    let groups = plan.link_groups(&template(TargetScope::Tree { root: self_pid() }));
    assert_eq!(groups.len(), plan.members.len());
    for (group, member) in groups.iter().zip(plan.members.iter()) {
        assert_eq!(group.scope, TargetScope::Pid { pid: member.pid });
        assert_eq!(group.generation(), PlanGeneration::new(1));
        assert_eq!(group.program, ProgramId::UprobeMultiSelfProbe);
        assert!(group.entry);
    }
}
