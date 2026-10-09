// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Task 01 contract tests (ADR-0008): scope partition, pod identity,
//! kernel-metadata validation. RED first: `kryprobe_core::workload` does
//! not exist yet, so this file must fail to compile before the contract
//! lands and pass after.

use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, BindingProvenance, ContextIdentity, ExecutionKind,
    KernelIdentity, METHOD_METADATA_FILE, MetadataEntry, MetadataSnapshot, Relationship,
    ScopeDecision, ScopePartition, SnapshotErrorCode, SnapshotInterval, SnapshotKey,
    SnapshotRequest, ValidityInterval, WorkloadIdentity, WorkloadOrigin,
};

/// An unknown selector match is its own population: it never counts as a
/// confirmed match and never disappears from the observed total.
#[test]
fn unknown_match_is_not_match() {
    let partition = ScopePartition::from_counts(70, 20, 10).expect("valid partition");
    assert_eq!(partition.matched(), 70);
    assert_eq!(partition.nonmatched(), 20);
    assert_eq!(partition.unknown_match(), 10);
    assert_eq!(partition.observed(), 100);
    // Unknowns stay visible and separate under decision mapping.
    assert_eq!(partition.decision_for_known(true), ScopeDecision::Match);
    assert_eq!(partition.decision_for_known(false), ScopeDecision::NonMatch);
    assert_eq!(partition.decision_for_unknown(), ScopeDecision::Unknown);
    assert_ne!(
        partition.decision_for_unknown(),
        ScopeDecision::Match,
        "unknown must not collapse into match"
    );
    // The partition invariant holds with checked arithmetic, and overflow
    // refuses instead of wrapping.
    assert!(ScopePartition::from_counts(u64::MAX, 1, 0).is_err());
    assert!(ScopePartition::from_counts(1, u64::MAX, 1).is_err());
}

/// Pod identity is the UID: deleting and recreating a pod under the same
/// name/namespace yields a NEW identity; counts keyed by the old UID must
/// not transfer.
#[test]
fn pod_name_reuse_requires_new_uid() {
    let old = WorkloadIdentity::pod("cluster-a", "api-7c9d", "production", "uid-1111");
    let same_name_new_uid =
        WorkloadIdentity::pod("cluster-a", "api-7c9d", "production", "uid-2222");
    let same_uid = WorkloadIdentity::pod("cluster-a", "api-7c9d", "production", "uid-1111");
    assert_ne!(
        old.identity_keys(),
        same_name_new_uid.identity_keys(),
        "name reuse with a new UID must not reuse the identity"
    );
    assert_eq!(
        old.identity_keys(),
        same_uid.identity_keys(),
        "same UID keeps the identity"
    );
    assert!(old.same_selection_name(&same_name_new_uid));
}

/// Kernel-side metadata that contradicts its own validity rules is
/// rejected typed: a `verified` claim without a verified method, and a
/// cgroup-ID-looking name promoted past `candidate`, must both fail.
#[test]
fn wrong_kernel_metadata_is_rejected() {
    // Verified status requires the captured_cgroup method plus a validity
    // interval; anything else is a contradiction.
    let bad_verified = AttributionEvidence::new(
        Relationship::HookContext,
        "metadata_label",
        WorkloadOrigin::OperatorMetadataFile,
        AttributionStatus::Verified,
        None,
    );
    assert!(bad_verified.validate().is_err());

    let good_verified = AttributionEvidence::new(
        Relationship::HookContext,
        "captured_cgroup",
        WorkloadOrigin::KernelCapture,
        AttributionStatus::Verified,
        Some(ValidityInterval::monotonic(100, 200)),
    );
    assert!(good_verified.validate().is_ok());

    // The resolver REALLY compares kernels: a captured key from kernel A
    // served from a snapshot taken on kernel B refuses with a typed
    // kernel-mismatch error — the metadata names are never applied.
    let request = SnapshotRequest {
        session_id: "0123456789abcdef0123456789abcdef".to_string(),
        keys: vec![SnapshotKey {
            kernel_scope: "kernel-A-boot-1111".to_string(),
            cgroup: 43812,
            tgid: 1000,
            start_ns: 555,
        }],
    };
    let foreign_snapshot = MetadataSnapshot {
        collector: "docker-fixture-v1".to_string(),
        snapshot_interval: SnapshotInterval {
            start_ns: 1000,
            end_ns: 2000,
        },
        kernel_identity: KernelIdentity::Known("kernel-B-boot-2222".to_string()),
        entries: vec![MetadataEntry {
            container: None,
            pod: None,
            cluster: None,
            node: None,
            ancestor_container: None,
            display_name: Some("web-0".to_string()),
            cgroup_id: Some(43812),
            binding: BindingProvenance {
                method: METHOD_METADATA_FILE.to_string(),
                source: WorkloadOrigin::OperatorMetadataFile,
                status: AttributionStatus::Asserted,
                validity: None,
            },
        }],
    };
    let response =
        kryprobe_core::workload::resolve(&request, &foreign_snapshot).expect("resolver runs");
    assert!(response.associations.is_empty());
    assert_eq!(response.errors.len(), 1);
    assert_eq!(response.errors[0].code, SnapshotErrorCode::KernelMismatch);

    // A container-ID-looking cgroup name is a candidate until checked:
    // promoting it to verified without a check refuses. Full IDs only:
    // an abbreviated prefix is not even a candidate.
    let candidate = ContextIdentity::new(7, 43812, 1000, 1000, 555, ExecutionKind::Proc);
    let full_id = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
    assert_eq!(
        candidate.qualified_container_candidate(full_id),
        Some(full_id)
    );
    assert!(
        candidate
            .qualified_container_candidate("70f16eb35cd4")
            .is_none()
    );
    assert!(candidate.promote_candidate_unchecked().is_err());
}
