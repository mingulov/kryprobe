// SPDX-License-Identifier: GPL-3.0-or-later
//! Userspace fan-out for `Tree`/`Cgroup` scopes (FU4).
//!
//! One uprobe-multi link filters on one pid, so a tree or cgroup
//! attaches as one link per member pid through the unchanged Pid path.
//! This module resolves a scope to admitted members: enumerate
//! candidates (`/proc` task children, `cgroup.procs` trees), then admit
//! each through the inspection facet. Policy (see
//! `docs/attach-policy.md`): a denied live member rejects the whole
//! scope (never a silent subset); an exited member is skipped with an
//! exact receipt; admission beyond budget rejects without partial
//! attach. Follow-fork is re-resolution plus a membership diff.
//!
//! Crate-private entries: the only external entries are the inherent
//! helpers `LocalPrivilegedAuthority::resolve_scope`/`refresh_fanout`.
//! Fan-out is deliberately NOT a facet method (X15, see `AttachAuthority`):
//! it composes the inspect facet over unprivileged enumeration, so future
//! brokers reuse this helper instead of reimplementing Tree/Cgroup policy.

use crate::attach::AttachError;
use crate::inspect::{InspectError, TargetSnapshot};
use kryprobe_core::attach::LinkGroup;
use kryprobe_core::plan::TargetScope;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;

fn rejected(reason: String) -> AttachError {
    AttachError::Rejected { reason }
}

/// One admitted fan-out member: pid pinned to its starttime identity
/// (ADR-0003: identity is (pid, start-time), never numeric pid alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FanoutMember {
    /// Admitted process ID.
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat` at admit time.
    pub starttime: u64,
}

/// Admitted scope resolution: members plus honesty receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutPlan {
    /// The scope this plan was resolved from.
    pub scope: TargetScope,
    /// Admitted members, sorted by pid, deduplicated.
    pub members: Vec<FanoutMember>,
    /// Candidates that exited between enumeration and admission.
    pub exited_during_resolve: u64,
}

/// Follow-fork refresh diff between two resolutions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutRefresh {
    /// Members present now that were absent before, by pid.
    pub added: Vec<FanoutMember>,
    /// Members absent now (exited or reused pid), by pid.
    pub exited: Vec<FanoutMember>,
}

impl FanoutPlan {
    /// One Pid-scoped link group per member from a template.
    ///
    /// The template provides object, program, entry, generation, and its
    /// allocator-issued `index_base`; each group replaces the scope with
    /// its member pid so every link flows through the unchanged Pid
    /// attach path. Members deliberately share the template's range (one
    /// logical group, one range): per-member index attribution would
    /// need TGID multiplexing, which CONFIG's single pinned TGID cannot
    /// express today.
    #[must_use]
    pub fn link_groups(&self, template: &LinkGroup) -> Vec<LinkGroup> {
        self.members
            .iter()
            .map(|member| template.with_scope(TargetScope::Pid { pid: member.pid }))
            .collect()
    }
}

/// Parse a whitespace-separated pid list (children, cgroup.procs).
fn parse_pids(text: &str, what: &str) -> Result<Vec<u32>, AttachError> {
    let mut out = Vec::new();
    for token in text.split_whitespace() {
        match token.parse::<u32>() {
            Ok(pid) => out.push(pid),
            Err(_) => {
                return Err(rejected(format!("unparseable pid in {what}: {token:?}")));
            }
        }
    }
    Ok(out)
}

/// Enumerate a process tree via `/proc/<pid>/task/*/children`.
///
/// The root must exist; descendants that exit mid-walk are skipped
/// (admission re-checks liveness), but an unreadable-for-permission
/// file rejects: a silently missed live descendant would be a silent
/// subset.
fn enumerate_tree(root: u32) -> Result<Vec<u32>, AttachError> {
    if root == 0 {
        return Err(rejected("tree root 0 is not a process".to_owned()));
    }
    match std::fs::read_dir(format!("/proc/{root}/task")) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(rejected(format!("tree root gone: pid {root}")));
        }
        Err(err) => {
            return Err(rejected(format!(
                "cannot enumerate tree under pid {root}: {err}"
            )));
        }
    }
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut queue: Vec<u32> = vec![root];
    seen.insert(root);
    while let Some(pid) = queue.pop() {
        let task_dir = match std::fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(dir) => dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(rejected(format!(
                    "cannot enumerate tasks of pid {pid}: {err}"
                )));
            }
        };
        for task in task_dir {
            let task = match task {
                Ok(entry) => entry,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(rejected(format!(
                        "cannot enumerate tasks of pid {pid}: {err}"
                    )));
                }
            };
            let children_path = task.path().join("children");
            let text = match std::fs::read_to_string(&children_path) {
                Ok(text) => text,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(rejected(format!(
                        "cannot read children of pid {pid}: {err}"
                    )));
                }
            };
            for child in parse_pids(&text, &format!("children of pid {pid}"))? {
                if seen.insert(child) {
                    queue.push(child);
                }
            }
        }
    }
    Ok(seen.into_iter().collect())
}

/// Enumerate a cgroup subtree via recursive `cgroup.procs` reads.
///
/// Symlinks are not followed and visited (dev, ino) pairs are skipped,
/// so bind mounts cannot cycle the walk. A missing `cgroup.procs` at
/// the root rejects (not a cgroup); deeper misses are rmdir races and
/// skip; permission failures reject at any depth.
fn enumerate_cgroup(path: &str) -> Result<Vec<u32>, AttachError> {
    if path.is_empty() {
        return Err(rejected("cgroup scope has an empty path".to_owned()));
    }
    if path.contains('\0') {
        return Err(rejected("cgroup path is not NUL-safe".to_owned()));
    }
    let root = std::path::PathBuf::from(path);
    match std::fs::symlink_metadata(&root) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(rejected(format!("cgroup path is not a directory: {path}"))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(rejected(format!("cgroup path gone: {path}")));
        }
        Err(err) => return Err(rejected(format!("cannot read cgroup path {path}: {err}"))),
    }
    let mut members: BTreeSet<u32> = BTreeSet::new();
    let mut visited: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut stack: Vec<std::path::PathBuf> = vec![root];
    let mut at_root = true;
    while let Some(dir) = stack.pop() {
        let meta = match std::fs::symlink_metadata(&dir) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(rejected(format!(
                    "cannot read cgroup dir {}: {err}",
                    dir.display()
                )));
            }
        };
        if !meta.is_dir() || !visited.insert((meta.dev(), meta.ino())) {
            continue;
        }
        match std::fs::read_to_string(dir.join("cgroup.procs")) {
            Ok(text) => {
                for pid in parse_pids(&text, &format!("{} cgroup.procs", dir.display()))? {
                    members.insert(pid);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if at_root {
                    return Err(rejected(format!(
                        "not a cgroup (no cgroup.procs): {}",
                        dir.display()
                    )));
                }
            }
            Err(err) => {
                return Err(rejected(format!(
                    "cannot read {} cgroup.procs: {err}",
                    dir.display()
                )));
            }
        }
        at_root = false;
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(rejected(format!(
                    "cannot list cgroup dir {}: {err}",
                    dir.display()
                )));
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(rejected(format!(
                        "cannot list cgroup dir {}: {err}",
                        dir.display()
                    )));
                }
            };
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(rejected(format!(
                        "cannot list cgroup dir {}: {err}",
                        dir.display()
                    )));
                }
            };
            if kind.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    Ok(members.into_iter().collect())
}

/// Admit enumerated candidates through the inspection facet.
///
/// `root` (tree scopes) must admit: a gone or denied root rejects the
/// whole scope. Other gone candidates are exit races: skipped with an
/// exact count. Any other denied candidate rejects the whole scope —
/// a live-but-unseen member would be a silent subset. Admission beyond
/// `max_targets` rejects without partial attach.
fn admit_enumerated(
    root: Option<u32>,
    candidates: &[u32],
    max_targets: u64,
    inspect: &impl Fn(u32) -> Result<TargetSnapshot, InspectError>,
) -> Result<(Vec<FanoutMember>, u64), AttachError> {
    let mut ordered: Vec<u32> = candidates.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    let mut members = Vec::new();
    let mut exited: u64 = 0;
    for pid in ordered {
        match inspect(pid) {
            Ok(snapshot) => members.push(FanoutMember {
                pid,
                starttime: snapshot.starttime,
            }),
            Err(InspectError::TargetGone) if Some(pid) != root => {
                exited = exited.saturating_add(1);
            }
            Err(InspectError::TargetGone) => {
                return Err(rejected(format!("tree root gone: pid {pid}")));
            }
            Err(InspectError::Denied { stage }) => {
                return Err(rejected(format!(
                    "member pid {pid} denied at stage {stage}: refusing silent subset"
                )));
            }
        }
    }
    if members.len() as u64 > max_targets {
        return Err(rejected(format!(
            "scope admits {} targets over budget {max_targets}: refusing partial attach",
            members.len()
        )));
    }
    Ok((members, exited))
}

/// Resolve a fan-out scope: enumerate, then admit each member.
///
/// `Pid` attaches directly via the link path (no fan-out to resolve),
/// and `OwnedRun` has no session spawner (declined: no backend
/// consumer — the selftest fixture's ad-hoc spawn is the only
/// observed-target spawn); both reject honestly here.
pub(crate) fn resolve_with(
    scope: &TargetScope,
    max_targets: u64,
    inspect: &impl Fn(u32) -> Result<TargetSnapshot, InspectError>,
) -> Result<FanoutPlan, AttachError> {
    let (root, candidates) = match scope {
        TargetScope::Tree { root } => (Some(*root), enumerate_tree(*root)?),
        TargetScope::Cgroup { path } => (None, enumerate_cgroup(path)?),
        TargetScope::Pid { .. } => {
            return Err(rejected(
                "Pid scope attaches directly; fan-out is for Tree/Cgroup".to_owned(),
            ));
        }
        TargetScope::OwnedRun => {
            return Err(rejected(
                "OwnedRun has no session spawner (declined: no backend consumer); fan-out is for Tree/Cgroup"
                    .to_owned(),
            ));
        }
    };
    let (members, exited_during_resolve) =
        admit_enumerated(root, &candidates, max_targets, inspect)?;
    Ok(FanoutPlan {
        scope: scope.clone(),
        members,
        exited_during_resolve,
    })
}

/// Membership diff by (pid, starttime) identity: a reused pid shows as
/// an exited old member plus an added new one, never a silent carry.
fn diff_members(old: &[FanoutMember], new: &[FanoutMember]) -> FanoutRefresh {
    let key = |member: &FanoutMember| (member.pid, member.starttime);
    let before: BTreeSet<(u32, u64)> = old.iter().map(key).collect();
    let after: BTreeSet<(u32, u64)> = new.iter().map(key).collect();
    let mut added: Vec<FanoutMember> = new
        .iter()
        .filter(|member| !before.contains(&key(member)))
        .copied()
        .collect();
    let mut exited: Vec<FanoutMember> = old
        .iter()
        .filter(|member| !after.contains(&key(member)))
        .copied()
        .collect();
    added.sort_by_key(|member| member.pid);
    exited.sort_by_key(|member| member.pid);
    FanoutRefresh { added, exited }
}

/// Follow-fork refresh: re-resolve the plan's scope and diff.
///
/// A failed refresh returns `Err` and leaves the caller's plan
/// untouched (fail-closed on the last good membership). The new plan
/// accumulates the exit receipt so refresh churn stays visible.
pub(crate) fn refresh_with(
    plan: &FanoutPlan,
    max_targets: u64,
    inspect: &impl Fn(u32) -> Result<TargetSnapshot, InspectError>,
) -> Result<(FanoutPlan, FanoutRefresh), AttachError> {
    let mut next = resolve_with(&plan.scope, max_targets, inspect)?;
    let refresh = diff_members(&plan.members, &next.members);
    next.exited_during_resolve = next
        .exited_during_resolve
        .saturating_add(plan.exited_during_resolve);
    Ok((next, refresh))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(pid: u32, starttime: u64) -> TargetSnapshot {
        TargetSnapshot {
            pid,
            starttime,
            exe_dev: 0,
            exe_ino: 0,
            exe_size: 0,
            maps_lines: 0,
            maps_first_dev: String::new(),
            yama_scope: 0,
            caps: String::new(),
        }
    }

    /// Stub inspect: `gone` pids exited, `denied` pids refuse, rest admit
    /// with starttime == pid (distinct nonzero identities).
    fn stub(gone: &[u32], denied: &[u32]) -> impl Fn(u32) -> Result<TargetSnapshot, InspectError> {
        let gone = gone.to_vec();
        let denied = denied.to_vec();
        move |pid| {
            if gone.contains(&pid) {
                Err(InspectError::TargetGone)
            } else if denied.contains(&pid) {
                Err(InspectError::Denied {
                    stage: "maps".to_owned(),
                })
            } else {
                Ok(snapshot(pid, u64::from(pid)))
            }
        }
    }

    #[test]
    fn admit_all_ok_members_sorted_and_deduped() {
        let (members, exited) =
            admit_enumerated(None, &[9, 3, 3, 7], 8, &stub(&[], &[])).expect("admit");
        assert_eq!(exited, 0);
        assert_eq!(
            members.iter().map(|m| m.pid).collect::<Vec<_>>(),
            vec![3, 7, 9]
        );
        assert!(members.iter().all(|m| m.starttime == u64::from(m.pid)));
    }

    #[test]
    fn admit_gone_members_skip_with_exact_count() {
        let (members, exited) =
            admit_enumerated(None, &[3, 4, 5], 8, &stub(&[4], &[])).expect("admit");
        assert_eq!(exited, 1);
        assert_eq!(
            members.iter().map(|m| m.pid).collect::<Vec<_>>(),
            vec![3, 5]
        );
    }

    #[test]
    fn admit_denied_member_rejects_whole_scope() {
        let err = admit_enumerated(None, &[3, 4, 5], 8, &stub(&[], &[4])).unwrap_err();
        assert!(
            matches!(err, AttachError::Rejected { ref reason } if reason.contains("pid 4")
                && reason.contains("denied")
                && reason.contains("silent subset")),
            "got {err}"
        );
    }

    #[test]
    fn admit_gone_root_rejects() {
        let err = admit_enumerated(Some(3), &[3, 4], 8, &stub(&[3], &[])).unwrap_err();
        assert!(
            matches!(err, AttachError::Rejected { ref reason } if reason.contains("root")),
            "got {err}"
        );
    }

    #[test]
    fn admit_denied_root_rejects() {
        let err = admit_enumerated(Some(3), &[3, 4], 8, &stub(&[], &[3])).unwrap_err();
        assert!(
            matches!(err, AttachError::Rejected { ref reason } if reason.contains("pid 3")),
            "got {err}"
        );
    }

    #[test]
    fn admit_over_budget_rejects_without_partial() {
        let err = admit_enumerated(None, &[3, 4, 5], 2, &stub(&[], &[])).unwrap_err();
        assert!(
            matches!(err, AttachError::Rejected { ref reason } if reason.contains("budget")),
            "got {err}"
        );
    }

    #[test]
    fn admit_empty_scope_allowed_as_zero_links() {
        let (members, exited) = admit_enumerated(None, &[], 8, &stub(&[], &[])).expect("admit");
        assert!(members.is_empty());
        assert_eq!(exited, 0);
    }

    #[test]
    fn budget_counts_admitted_not_candidates() {
        // One candidate already exited: two admitted fits a budget of two.
        let (members, _) = admit_enumerated(None, &[3, 4, 5], 2, &stub(&[4], &[])).expect("admit");
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn diff_reports_added_exited_and_reused_pid() {
        let old = vec![
            FanoutMember {
                pid: 3,
                starttime: 30,
            },
            FanoutMember {
                pid: 4,
                starttime: 40,
            },
            FanoutMember {
                pid: 5,
                starttime: 50,
            },
        ];
        let new = vec![
            FanoutMember {
                pid: 4,
                starttime: 40,
            },
            FanoutMember {
                pid: 5,
                starttime: 51,
            },
            FanoutMember {
                pid: 6,
                starttime: 60,
            },
        ];
        let refresh = diff_members(&old, &new);
        assert_eq!(
            refresh.added,
            vec![
                FanoutMember {
                    pid: 5,
                    starttime: 51,
                },
                FanoutMember {
                    pid: 6,
                    starttime: 60,
                },
            ]
        );
        assert_eq!(
            refresh.exited,
            vec![
                FanoutMember {
                    pid: 3,
                    starttime: 30,
                },
                FanoutMember {
                    pid: 5,
                    starttime: 50,
                },
            ]
        );
    }

    #[test]
    fn parse_pids_rejects_garbage() {
        assert!(parse_pids("12 34\n", "test").is_ok());
        assert!(parse_pids("", "test").unwrap().is_empty());
        assert!(matches!(
            parse_pids("12 nope", "test"),
            Err(AttachError::Rejected { .. })
        ));
    }
}
