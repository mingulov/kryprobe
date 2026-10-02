// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Task 01 contract tests (ADR-0008): scope partition, pod identity,
//! kernel-metadata validation. RED first: `kryprobe_core::workload` does
//! not exist yet, so this file must fail to compile before the contract
//! lands and pass after.

use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, ContextIdentity, ExecutionKind, ScopeDecision,
    ScopePartition, WorkloadIdentity, WorkloadOrigin,
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
        old.identity_key(),
        same_name_new_uid.identity_key(),
        "name reuse with a new UID must not reuse the identity"
    );
    assert_eq!(
        old.identity_key(),
        same_uid.identity_key(),
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
        "hook_context",
        "metadata_label",
        WorkloadOrigin::OperatorMetadataFile,
        AttributionStatus::Verified,
        None,
    );
    assert!(bad_verified.validate().is_err());

    let good_verified = AttributionEvidence::new(
        "hook_context",
        "captured_cgroup",
        WorkloadOrigin::KernelCapture,
        AttributionStatus::Verified,
        Some((100, 200)),
    );
    assert!(good_verified.validate().is_ok());

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
