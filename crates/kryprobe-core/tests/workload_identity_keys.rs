// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2A RED tests (gap G03): container/runtime/lifetime identities
//! must not collapse, and unresolved identities must never promote.
//!
//! These tests fail against the Task01 contract (`identity_key()` returns
//! `"unresolved"` for every container-only identity and `qualify_join()`
//! promotes it to `Unique`) and pass after the Stage 2A identity-key fix.

use kryprobe_core::workload::{IdentityKey, JoinQualification, WorkloadIdentity};
use std::collections::HashMap;

const RUNTIME_A: &str = "docker://host-a/var/run/docker.sock";
const RUNTIME_B: &str = "docker://host-b/var/run/docker.sock";
const ID_1: &str = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
const ID_2: &str = "9c4d2f7a8b1e4a6c9d0f3b5a7c8e1d2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b1c3";

fn container(runtime: &str, id: &str, lifetime: Option<&str>) -> WorkloadIdentity {
    WorkloadIdentity::container(runtime, id, lifetime)
}

/// Two full container IDs on the same runtime are distinct identities.
#[test]
fn two_full_container_ids_on_one_runtime_are_distinct() {
    let a = container(RUNTIME_A, ID_1, Some("lifetime-a"));
    let b = container(RUNTIME_A, ID_2, Some("lifetime-b"));
    assert!(a.is_resolved());
    assert!(b.is_resolved());
    assert_ne!(a.identity_keys(), b.identity_keys());
    assert!(matches!(
        kryprobe_core::workload::qualify_join(&[a, b]),
        JoinQualification::Ambiguous(_)
    ));
}

/// One container ID on two runtime instances is distinct: the ID alone is
/// not an identity without its runtime scope.
#[test]
fn one_container_id_on_two_runtimes_is_distinct() {
    let a = container(RUNTIME_A, ID_1, Some("lifetime-a"));
    let b = container(RUNTIME_B, ID_1, Some("lifetime-a"));
    assert_ne!(a.identity_keys(), b.identity_keys());
    assert!(matches!(
        kryprobe_core::workload::qualify_join(&[a, b]),
        JoinQualification::Ambiguous(_)
    ));
}

/// An unresolved identity (no established associations) can never promote
/// to `Unique` — alone, or alongside other unresolved identities.
#[test]
fn unresolved_identity_cannot_promote_to_unique() {
    let none = WorkloadIdentity::none();
    assert!(!none.is_resolved());
    assert!(none.identity_keys().is_empty());
    assert!(matches!(
        kryprobe_core::workload::qualify_join(&[none.clone()]),
        JoinQualification::Unresolved
    ));
    assert!(matches!(
        kryprobe_core::workload::qualify_join(&[none.clone(), none]),
        JoinQualification::Unresolved
    ));
    assert!(matches!(
        kryprobe_core::workload::qualify_join(&[]),
        JoinQualification::None
    ));
}

/// A container restart (same runtime + ID, new lifetime) does not inherit
/// counts keyed by the old lifetime.
#[test]
fn same_name_replacement_does_not_inherit_counts() {
    let before = container(RUNTIME_A, ID_1, Some("lifetime-before"));
    let after = container(RUNTIME_A, ID_1, Some("lifetime-after"));
    assert_ne!(before.identity_keys(), after.identity_keys());

    let mut counts: HashMap<Vec<IdentityKey>, u64> = HashMap::new();
    counts.insert(before.identity_keys(), 30);
    assert_eq!(counts.get(&after.identity_keys()), None);
}

/// Delimiter games must not merge distinct identities: a structured key
/// carries components, never an ambiguous joined string.
#[test]
fn delimiter_collision_does_not_merge() {
    let a = WorkloadIdentity::pod("cluster:a", "api", "production", "uid-c");
    let b = WorkloadIdentity::pod("cluster", "api", "production", "a:uid-c");
    assert_ne!(a.identity_keys(), b.identity_keys());
    assert!(matches!(
        kryprobe_core::workload::qualify_join(&[a, b]),
        JoinQualification::Ambiguous(_)
    ));
}

/// A container-only identity (no pod) resolves on its own evidence: it is
/// neither `unresolved` nor merged with other container-only identities.
#[test]
fn container_only_identity_resolves_without_pod() {
    let a = container(RUNTIME_A, ID_1, Some("lifetime-a"));
    assert!(a.is_resolved());
    match kryprobe_core::workload::qualify_join(std::slice::from_ref(&a)) {
        JoinQualification::Unique(identity) => assert_eq!(identity.identity_keys(), a.identity_keys()),
        other => panic!("container-only identity must qualify unique, got {other:?}"),
    }
}
