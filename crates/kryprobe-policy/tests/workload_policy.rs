// SPDX-License-Identifier: GPL-3.0-or-later
//! Workload-scoped policy contract (M1 Stage 2D): exact-cgroup and
//! full-container-identity selectors over typed observed rows, exact
//! weighted-call partitions, and the frozen unknown-handling truth
//! table (spec §5.5/§5.6, ADR-0012).
//!
//! Fixture populations mirror the frozen Stage 2A v2 fixtures in
//! `kryprobe-report/tests/fixtures/workload-v2/` (same cgroup ids,
//! call weights, container ids, and selector/partition shapes); the
//! typed rows here are the policy-crate projection Stage 3 maps the
//! validated report into. System-wide policy behavior stays covered
//! separately by `policy_matrix.rs`.

use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{IntegrityRef, NativeObservation, NativeResult};
use kryprobe_core::ids::ObservationId;
use kryprobe_core::workload::{
    AttributionEvidence, ContextIdentity, ExecutionKind, Relationship, ValidityInterval,
    WorkloadIdentity,
};
use kryprobe_policy::workload::{
    CaptureIntegrity, ScopedError, ScopedRow, ScopedVerdict, WorkloadSelector, evaluate_scoped,
    scope_rows,
};
use kryprobe_policy::{Policy, parse_policy};

// ---------------------------------------------------------------------------
// Fixtures (mirror the frozen v2 fixtures)
// ---------------------------------------------------------------------------

/// Frozen container id A from `matching-violation.json`.
const ID_A: &str = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
/// Frozen container id B from `matching-violation.json`.
const ID_B: &str = "9c4d2f7a8b1e4a6c9d0f3b5a7c8e1d2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b1c3d";
const RUNTIME: &str = "docker://host-a";

fn agg_obs(id: u64, algorithm: &str, driver: &str, result: &str) -> NativeObservation {
    agg_obs_full(id, algorithm, driver, result, None, None)
}

fn agg_obs_full(
    id: u64,
    algorithm: &str,
    driver: &str,
    result: &str,
    uid: Option<u64>,
    comm: Option<&str>,
) -> NativeObservation {
    let mut payload = serde_json::json!({
        "row": "agg",
        "family": "skcipher",
        "op": "encrypt",
        "result": result,
        "algorithm": algorithm,
        "driver": driver,
        "context": "process",
    });
    if let Some(uid) = uid {
        payload["uid"] = serde_json::json!(uid);
    }
    if let Some(comm) = comm {
        payload["comm"] = serde_json::json!(comm);
    }
    NativeObservation {
        id: ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Returned,
        call_kind: CallKind::Operation,
        operation_class: OperationClass::Encrypt,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(100),
        ended_ns: Some(200),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: payload,
    }
}

fn context(cgroup: u64) -> ContextIdentity {
    ContextIdentity::new(7, cgroup, 1000, 1000, 555, ExecutionKind::Proc)
}

fn asserted() -> AttributionEvidence {
    AttributionEvidence::asserted_metadata(
        Relationship::HookContext,
        kryprobe_core::workload::METHOD_METADATA_FILE,
        Some(ValidityInterval::monotonic(100, 200)),
    )
}

fn unresolved() -> AttributionEvidence {
    AttributionEvidence::unresolved(Relationship::HookContext)
}

fn row<'a>(
    calls: u64,
    cgroup: u64,
    identity: WorkloadIdentity,
    evidence: AttributionEvidence,
    observation: &'a NativeObservation,
) -> ScopedRow<'a> {
    ScopedRow {
        calls,
        context: context(cgroup),
        identity,
        evidence,
        observation,
    }
}

fn deny_algorithm(algorithm: &str) -> Policy {
    parse_policy(&format!(
        "version: 1\nrules:\n  - id: no-bad-alg\n    source: kernel-crypto\n    match:\n      stage: returned\n      algorithm: {algorithm}\n    decision: deny\n",
    ))
    .expect("deny policy parses")
}

fn deny_result(result: &str) -> Policy {
    parse_policy(&format!(
        "version: 1\nrules:\n  - id: no-bad-result\n    source: kernel-crypto\n    match:\n      stage: returned\n      result: {result}\n    decision: deny\n",
    ))
    .expect("deny policy parses")
}

/// Every scoped verdict carries its exit intent (spec §5.6).
fn intent(verdict: &ScopedVerdict<'_>) -> i32 {
    verdict.exit_intent()
}

// ---------------------------------------------------------------------------
// Required truth-table tests
// ---------------------------------------------------------------------------

#[test]
fn unknown_match_is_not_match() {
    // Mirrors `unknown-match.json`: cgroup selector 43812 over
    // 20 matched / 20 nonmatched / 10 unknown (cgroup 0) calls.
    // The forbidden algorithm lives ONLY in the unknown row: it
    // cannot convict the selected workload (no violation), but the
    // unknown weight keeps the check inconclusive (exit 3, not 0).
    let selected = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let other = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let unknown = agg_obs(3, "ecb(des)", "des_generic", "ok");
    let rows = [
        row(20, 43812, WorkloadIdentity::none(), unresolved(), &selected),
        row(20, 43813, WorkloadIdentity::none(), unresolved(), &other),
        row(10, 0, WorkloadIdentity::none(), unresolved(), &unknown),
    ];
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 20);
    assert_eq!(scoped.partition.nonmatched(), 20);
    assert_eq!(scoped.partition.unknown_match(), 10);
    assert_eq!(scoped.partition.observed(), 50);

    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    assert!(
        matches!(verdict, ScopedVerdict::Inconclusive { .. }),
        "unknown-only algorithm is inconclusive, got {verdict:?}"
    );
    assert_eq!(intent(&verdict), 3);
}

#[test]
fn unknown_owner_prevents_clean_scoped_check() {
    // Container selector over one resolved row plus one row whose
    // container owner is unresolved: no violation, complete capture,
    // but the unknown owner blocks exit 0.
    let owned = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let ownerless = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(
            20,
            43812,
            WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
            asserted(),
            &owned,
        ),
        row(
            10,
            43813,
            WorkloadIdentity::none(),
            unresolved(),
            &ownerless,
        ),
    ];
    let selector = WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 20);
    assert_eq!(scoped.partition.unknown_match(), 10);

    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    assert_eq!(intent(&verdict), 3);
}

#[test]
fn matching_violation_survives_unrelated_gap() {
    // Mirrors `matching-violation.json`: the forbidden algorithm is
    // definitely in the selected container. The violation stands
    // (exit 10) even with partial capture integrity and unrelated
    // unknown weight.
    let bad = agg_obs(1, "ecb(des)", "des_generic", "ok");
    let good = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let unknown = agg_obs(3, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(
            20,
            43812,
            WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
            asserted(),
            &bad,
        ),
        row(
            30,
            43813,
            WorkloadIdentity::container(RUNTIME, ID_B, Some("lifetime-b")),
            asserted(),
            &good,
        ),
        row(10, 0, WorkloadIdentity::none(), unresolved(), &unknown),
    ];
    let selector = WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector");
    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Partial,
    )
    .expect("evaluates");
    match &verdict {
        ScopedVerdict::Violation { rule, .. } => assert_eq!(rule, "no-bad-alg"),
        other => panic!("violation must stand over gaps, got {other:?}"),
    }
    assert_eq!(intent(&verdict), 10);
}

#[test]
fn shared_first_errno_does_not_convict_context() {
    // One native identity shared across contexts: the error result
    // observed in another cgroup must not convict the selected
    // cgroup, whose own rows are clean. Neither nonmatched nor
    // unknown rows convict.
    let clean = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let faulty = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "error");
    let unknown = agg_obs(3, "cbc(aes)", "cbc-aes-aesni", "error");
    let rows = [
        row(20, 43812, WorkloadIdentity::none(), unresolved(), &clean),
        row(20, 43813, WorkloadIdentity::none(), unresolved(), &faulty),
        row(10, 0, WorkloadIdentity::none(), unresolved(), &unknown),
    ];
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict = evaluate_scoped(
        &deny_result("error"),
        &selector,
        &rows,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    assert!(
        !matches!(verdict, ScopedVerdict::Violation { .. }),
        "other-context results never convict the selection, got {verdict:?}"
    );
    assert_eq!(intent(&verdict), 3);

    // Without the unknown row the same selection is clean.
    let verdict = evaluate_scoped(
        &deny_result("error"),
        &selector,
        &rows[..2],
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    assert!(matches!(verdict, ScopedVerdict::Clean { .. }));
    assert_eq!(intent(&verdict), 0);
}

#[test]
fn nested_cgroup_selection_is_exact() {
    // Nested groups: selecting the parent matches ONLY the parent
    // row — descendants never join an exact-cgroup selection.
    let parent = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let child = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(20, 100, WorkloadIdentity::none(), unresolved(), &parent),
        row(30, 200, WorkloadIdentity::none(), unresolved(), &child),
    ];
    let select_parent = WorkloadSelector::cgroup(100).expect("parent selector");
    let scoped = scope_rows(&select_parent, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 20);
    assert_eq!(scoped.partition.nonmatched(), 30);
    assert_eq!(scoped.partition.unknown_match(), 0);

    let select_child = WorkloadSelector::cgroup(200).expect("child selector");
    let scoped = scope_rows(&select_child, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 30);
    assert_eq!(scoped.partition.nonmatched(), 20);
}

#[test]
fn sibling_selections_do_not_double_count() {
    // Each row lands in exactly one bucket per selection, and
    // sibling selections tile the observed population without
    // overlap or loss.
    let a = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let b = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(20, 100, WorkloadIdentity::none(), unresolved(), &a),
        row(30, 200, WorkloadIdentity::none(), unresolved(), &b),
    ];
    let sel_a = WorkloadSelector::cgroup(100).expect("selector");
    let sel_b = WorkloadSelector::cgroup(200).expect("selector");
    let scoped_a = scope_rows(&sel_a, &rows).expect("scopes");
    let scoped_b = scope_rows(&sel_b, &rows).expect("scopes");
    assert_eq!(
        scoped_a.partition.matched() + scoped_b.partition.matched(),
        scoped_a.partition.observed()
    );
    assert_eq!(scoped_a.partition.observed(), 50);
    assert_eq!(scoped_b.partition.observed(), 50);
    // Per-row decisions agree with the weights.
    for (scoped, matched_cgroup) in [(&scoped_a, 100), (&scoped_b, 200)] {
        for (index, decision) in scoped.decisions.iter().enumerate() {
            let expected = rows[index].context.cgroup == matched_cgroup;
            assert_eq!(
                *decision,
                if expected {
                    kryprobe_core::workload::ScopeDecision::Match
                } else {
                    kryprobe_core::workload::ScopeDecision::NonMatch
                }
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Exit intents: clean, invalid, unusable, internal
// ---------------------------------------------------------------------------

#[test]
fn complete_matching_population_satisfying_policy_is_clean() {
    // Mirrors `complete-raw-ids.json` weights: every observed call is
    // definitely classified, capture is complete, no rule fires.
    let a = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let b = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(20, 43812, WorkloadIdentity::none(), unresolved(), &a),
        row(30, 43813, WorkloadIdentity::none(), unresolved(), &b),
    ];
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    assert!(matches!(verdict, ScopedVerdict::Clean { .. }));
    assert_eq!(intent(&verdict), 0);
}

#[test]
fn empty_selection_is_clean_not_inconclusive() {
    // A selector matching nothing is inapplicable, not unevaluable
    // (system-wide precedent): complete capture with no unknown
    // weight is clean.
    let a = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [row(20, 43812, WorkloadIdentity::none(), unresolved(), &a)];
    let selector = WorkloadSelector::cgroup(99999).expect("cgroup selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 0);
    assert_eq!(scoped.partition.nonmatched(), 20);
    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    assert_eq!(intent(&verdict), 0);
}

#[test]
fn partial_capture_without_violation_is_inconclusive() {
    // No matching violation plus a possibly-matching capture gap
    // (unproven ledger at integration) cannot be clean.
    let a = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [row(20, 43812, WorkloadIdentity::none(), unresolved(), &a)];
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Partial,
    )
    .expect("evaluates");
    match &verdict {
        ScopedVerdict::Inconclusive { missing, .. } => {
            assert!(missing.contains(&"capture-gap".to_string()), "{missing:?}");
        }
        other => panic!("partial capture must be inconclusive, got {other:?}"),
    }
    assert_eq!(intent(&verdict), 3);
}

#[test]
fn invalid_rows_refuse_with_exit_intent_2() {
    // A row contradicting the frozen observation rules (resolved
    // identity with an unusable status) is invalid input, never a
    // silent non-match.
    let obs = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let bad = row(
        20,
        43812,
        WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
        unresolved(),
        &obs,
    );
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let err = scope_rows(&selector, &[bad]).expect_err("invalid row refuses");
    assert_eq!(err.exit_intent(), 2);
}

#[test]
fn unusable_capture_refuses_with_exit_intent_4() {
    // Capture errors return before evaluation (CLI precedent): even
    // rows carrying a definite violation cannot establish a verdict
    // on an unusable capture.
    let bad = agg_obs(1, "ecb(des)", "des_generic", "ok");
    let rows = [row(20, 43812, WorkloadIdentity::none(), unresolved(), &bad)];
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let err = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Unusable,
    )
    .expect_err("unusable capture refuses");
    assert!(matches!(err, ScopedError::UnusableCapture));
    assert_eq!(err.exit_intent(), 4);
}

#[test]
fn invalid_input_beats_unusable_capture() {
    // Usage errors precede capture errors (CLI precedent: the policy
    // parses before capture, exit 2 even on an unusable lane).
    let obs = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let bad = row(
        20,
        43812,
        WorkloadIdentity::container(RUNTIME, ID_A, None),
        unresolved(),
        &obs,
    );
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let err = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &[bad],
        CaptureIntegrity::Unusable,
    )
    .expect_err("invalid input refuses first");
    assert_eq!(err.exit_intent(), 2);
}

#[test]
fn partition_overflow_is_internal_with_exit_intent_1() {
    // Individually valid weights whose sum is unrepresentable are an
    // internal failure (exit 1), never a wrapped partition.
    let a = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let b = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(u64::MAX, 43812, WorkloadIdentity::none(), unresolved(), &a),
        row(1, 43813, WorkloadIdentity::none(), unresolved(), &b),
    ];
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let err = scope_rows(&selector, &rows).expect_err("overflow refuses");
    assert!(matches!(err, ScopedError::Internal(_)));
    assert_eq!(err.exit_intent(), 1);
}

// ---------------------------------------------------------------------------
// Selector refusal and identity semantics
// ---------------------------------------------------------------------------

#[test]
fn cgroup_zero_refuses() {
    // cgroup 0 is the unreadable marker (frozen zero convention),
    // never a selectable cgroup.
    assert!(WorkloadSelector::cgroup(0).is_err());
}

#[test]
fn abbreviated_container_id_refuses() {
    // Abbreviated ids refuse explicitly (spec §5.5): only full
    // 64-char ids select.
    assert!(WorkloadSelector::container(RUNTIME, "70f16eb35cd4", None).is_err());
    assert!(WorkloadSelector::container(RUNTIME, ID_A, None).is_ok());
}

#[test]
fn non_hex_container_id_refuses() {
    let non_hex = "g".repeat(64);
    assert!(WorkloadSelector::container(RUNTIME, &non_hex, None).is_err());
    let upper = ID_A.to_uppercase();
    assert!(WorkloadSelector::container(RUNTIME, &upper, None).is_err());
}

#[test]
fn empty_or_oversize_runtime_refuses() {
    assert!(WorkloadSelector::container("", ID_A, None).is_err());
    let big = "r".repeat(257);
    assert!(WorkloadSelector::container(&big, ID_A, None).is_err());
}

#[test]
fn unsupported_selector_kinds_refuse() {
    // Pod, runtime, subtree, and name selectors refuse explicitly in
    // M1 (M2+ work); no silent fallback to another scope.
    for kind in [
        "pod",
        "pod-uid",
        "runtime",
        "subtree",
        "name",
        "cgroup-path",
    ] {
        let err = WorkloadSelector::unsupported_kind(kind);
        assert_eq!(err.exit_intent(), 2, "kind {kind}");
    }
}

#[test]
fn container_selector_without_lifetime_matches_any_lifetime() {
    // Frozen by `matching-violation.json`: the lifetime-less
    // selector matches the lifetime-a row (matched=20) while the
    // other id stays nonmatched (30).
    let bad = agg_obs(1, "ecb(des)", "des_generic", "ok");
    let good = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(
            20,
            43812,
            WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
            asserted(),
            &bad,
        ),
        row(
            30,
            43813,
            WorkloadIdentity::container(RUNTIME, ID_B, Some("lifetime-b")),
            asserted(),
            &good,
        ),
    ];
    let selector = WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 20);
    assert_eq!(scoped.partition.nonmatched(), 30);
    assert_eq!(scoped.partition.unknown_match(), 0);
}

#[test]
fn container_selector_lifetime_refuses() {
    // D10: lifetime narrowing is not representable on the amended M1
    // report wire (`selectors.container` carries runtime+id only), so
    // a lifetime-bearing selector refuses explicitly (exit 2) instead
    // of narrowing or silently dropping the lifetime (dropping would
    // change scope).
    let err = WorkloadSelector::container(RUNTIME, ID_A, Some("lifetime-a"))
        .expect_err("lifetime-bearing selector refuses");
    assert_eq!(err.exit_intent(), 2);
    assert!(
        !err.to_string().contains("lifetime-a"),
        "refusal withholds input bytes: {err}"
    );
}

#[test]
fn container_selector_without_lifetime_matches_across_lifetimes() {
    // Positive control: the lifetime-less selector matches the same
    // runtime+id across observed lifetimes (a, b) and an unobserved
    // lifetime — cross-lifetime matching still works after the D10
    // refusal (the wire cannot narrow, so the selector never does).
    let a = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let b = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let c = agg_obs(3, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(
            10,
            43812,
            WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
            asserted(),
            &a,
        ),
        row(
            10,
            43813,
            WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-b")),
            asserted(),
            &b,
        ),
        row(
            10,
            43814,
            WorkloadIdentity::container(RUNTIME, ID_A, None),
            asserted(),
            &c,
        ),
    ];
    let selector = WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 30);
    assert_eq!(scoped.partition.nonmatched(), 0);
    assert_eq!(scoped.partition.unknown_match(), 0);
}

#[test]
fn container_selector_ignores_pod_only_rows_as_unknown() {
    // A pod-only association establishes no container key: under a
    // container selector the row is unknown, never a match.
    let obs = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [row(
        10,
        43812,
        WorkloadIdentity::pod("cluster-a", "api", "production", "uid-1"),
        asserted(),
        &obs,
    )];
    let selector = WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 0);
    assert_eq!(scoped.partition.unknown_match(), 10);
}

#[test]
fn ambiguous_attribution_is_unknown() {
    // Ambiguous status (competing candidates, counts split) can never
    // establish a definite container match.
    let obs = agg_obs(1, "ecb(des)", "des_generic", "ok");
    let ambiguous = AttributionEvidence::new(
        Relationship::HookContext,
        kryprobe_core::workload::METHOD_UNRESOLVED,
        kryprobe_core::workload::WorkloadOrigin::Unknown,
        kryprobe_core::workload::AttributionStatus::Ambiguous,
        None,
    );
    let rows = [row(10, 43812, WorkloadIdentity::none(), ambiguous, &obs)];
    let selector = WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.unknown_match(), 10);
    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    assert_eq!(intent(&verdict), 3);
}

#[test]
fn verified_and_stale_associations_are_definite() {
    // Verified kernel bindings and stale (outlived-validity but
    // established) assertions both support definite comparison.
    let verified_obs = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let stale_obs = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let verified = AttributionEvidence::verified_kernel_capture(
        Relationship::HookContext,
        ValidityInterval::monotonic(100, 200),
    );
    let stale = AttributionEvidence::new(
        Relationship::HookContext,
        kryprobe_core::workload::METHOD_METADATA_FILE,
        kryprobe_core::workload::WorkloadOrigin::OperatorMetadataFile,
        kryprobe_core::workload::AttributionStatus::Stale,
        Some(ValidityInterval::monotonic(100, 200)),
    );
    let rows = [
        row(
            10,
            43812,
            WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
            verified,
            &verified_obs,
        ),
        row(
            10,
            43813,
            WorkloadIdentity::container(RUNTIME, ID_B, Some("lifetime-b")),
            stale,
            &stale_obs,
        ),
    ];
    let selector = WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector");
    let scoped = scope_rows(&selector, &rows).expect("scopes");
    assert_eq!(scoped.partition.matched(), 10);
    assert_eq!(scoped.partition.nonmatched(), 10);
    assert_eq!(scoped.partition.unknown_match(), 0);
}

// ---------------------------------------------------------------------------
// Rule-evaluator reuse: PID/UID/comm meanings preserved in scope
// ---------------------------------------------------------------------------

#[test]
fn scoped_uid_rule_ignores_nonmatched_rows() {
    // The existing exact-u32 `uid` key keeps its meaning under a
    // selector: a root row outside the selection never convicts.
    let user_obs = agg_obs_full(1, "cbc(aes)", "cbc-aes-aesni", "ok", Some(1000), None);
    let root_obs = agg_obs_full(2, "cbc(aes)", "cbc-aes-aesni", "ok", Some(0), None);
    let rows = [
        row(20, 43812, WorkloadIdentity::none(), unresolved(), &user_obs),
        row(20, 43813, WorkloadIdentity::none(), unresolved(), &root_obs),
    ];
    let policy = parse_policy(
        "version: 1\nrules:\n  - id: no-root-crypto\n    source: kernel-crypto\n    match:\n      stage: returned\n      uid: 0\n    decision: deny\n",
    )
    .expect("uid policy parses");
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict =
        evaluate_scoped(&policy, &selector, &rows, CaptureIntegrity::Complete).expect("evaluates");
    assert_eq!(intent(&verdict), 0);

    // The same rule fires when the selected row itself is root.
    let selector = WorkloadSelector::cgroup(43813).expect("cgroup selector");
    let verdict =
        evaluate_scoped(&policy, &selector, &rows, CaptureIntegrity::Complete).expect("evaluates");
    assert_eq!(intent(&verdict), 10);
}

#[test]
fn scoped_comm_glob_keeps_d5_meaning() {
    // The existing D5 `comm` glob keeps its meaning under a
    // selector: `py*` matches the selected `python3` row only.
    let py_obs = agg_obs_full(1, "cbc(aes)", "cbc-aes-aesni", "ok", None, Some("python3"));
    let nginx_obs = agg_obs_full(2, "cbc(aes)", "cbc-aes-aesni", "ok", None, Some("nginx"));
    let rows = [
        row(20, 43812, WorkloadIdentity::none(), unresolved(), &py_obs),
        row(
            20,
            43813,
            WorkloadIdentity::none(),
            unresolved(),
            &nginx_obs,
        ),
    ];
    let policy = parse_policy(
        "version: 1\nrules:\n  - id: no-py-crypto\n    source: kernel-crypto\n    match:\n      stage: returned\n      comm: 'py*'\n    decision: deny\n",
    )
    .expect("comm policy parses");
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict =
        evaluate_scoped(&policy, &selector, &rows, CaptureIntegrity::Complete).expect("evaluates");
    assert_eq!(intent(&verdict), 10);

    let selector = WorkloadSelector::cgroup(43813).expect("cgroup selector");
    let verdict =
        evaluate_scoped(&policy, &selector, &rows, CaptureIntegrity::Complete).expect("evaluates");
    assert_eq!(intent(&verdict), 0);
}

#[test]
fn unevaluable_rule_within_scope_is_inconclusive() {
    // Fail-closed specifiedness (H-SEC-02) applies within the
    // selected scope: a deny rule constraining `uid` with matching
    // in-scope rows but no fully-specified one cannot be clean.
    let obs = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [row(20, 43812, WorkloadIdentity::none(), unresolved(), &obs)];
    let policy = parse_policy(
        "version: 1\nrules:\n  - id: needs-uid\n    source: kernel-crypto\n    match:\n      stage: returned\n      uid: 1000\n    decision: deny\n",
    )
    .expect("uid policy parses");
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict =
        evaluate_scoped(&policy, &selector, &rows, CaptureIntegrity::Complete).expect("evaluates");
    match &verdict {
        ScopedVerdict::Inconclusive { missing, .. } => {
            assert!(
                missing.contains(&"evidence-shape".to_string()),
                "{missing:?}"
            );
        }
        other => panic!("unevaluable rule must be inconclusive, got {other:?}"),
    }
    assert_eq!(intent(&verdict), 3);
}

#[test]
fn report_rules_never_violate_in_scope() {
    // `report` decisions never violate, scoped or system-wide.
    let obs = agg_obs(1, "ecb(des)", "des_generic", "ok");
    let rows = [row(20, 43812, WorkloadIdentity::none(), unresolved(), &obs)];
    let policy = parse_policy(
        "version: 1\nrules:\n  - id: watch-des\n    source: kernel-crypto\n    match:\n      stage: returned\n      algorithm: ecb(des)\n    decision: report\n",
    )
    .expect("report policy parses");
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict =
        evaluate_scoped(&policy, &selector, &rows, CaptureIntegrity::Complete).expect("evaluates");
    assert_eq!(intent(&verdict), 0);
}

#[test]
fn violation_carries_partition_and_obs_ids() {
    // The scoped violation names the rule, matched observations,
    // representative native identity, and the exact partition.
    let bad = agg_obs(7, "ecb(des)", "des_generic", "ok");
    let good = agg_obs(8, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(20, 43812, WorkloadIdentity::none(), unresolved(), &bad),
        row(20, 43813, WorkloadIdentity::none(), unresolved(), &good),
    ];
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let verdict = evaluate_scoped(
        &deny_algorithm("ecb(des)"),
        &selector,
        &rows,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    match &verdict {
        ScopedVerdict::Violation {
            rule,
            obs_ids,
            algorithm,
            driver,
            partition,
            ..
        } => {
            assert_eq!(rule, "no-bad-alg");
            assert_eq!(obs_ids.len(), 1);
            assert_eq!(obs_ids[0], ObservationId::new(7));
            assert_eq!(algorithm, "ecb(des)");
            assert_eq!(driver, "des_generic");
            assert_eq!(partition.observed(), 40);
            assert_eq!(partition.matched(), 20);
        }
        other => panic!("expected violation, got {other:?}"),
    }
    assert_eq!(intent(&verdict), 10);
}

/// SEM02 at the scoped-policy ingress: a cgroup-zero row carrying a
/// resolved identity is invalid input (exit 2), never a silent
/// non-match — scoped rows reuse the shared observation rule.
#[test]
fn cgroup_zero_identity_refuses_scoped_rows() {
    let obs = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let bad = row(
        50,
        0,
        WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
        asserted(),
        &obs,
    );
    let selector = WorkloadSelector::cgroup(43812).expect("cgroup selector");
    let err = scope_rows(&selector, &[bad]).expect_err("resolved cgroup-zero refuses");
    assert_eq!(err.exit_intent(), 2);
    // Positive control: the same shape unresolved scopes to unknown.
    let unknown_obs = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [row(
        10,
        0,
        WorkloadIdentity::none(),
        unresolved(),
        &unknown_obs,
    )];
    let scoped = scope_rows(&selector, &rows).expect("unresolved cgroup-zero scopes");
    assert_eq!(scoped.partition.unknown_match(), 10);
}

/// F04 shared-classifier pin: `scope_rows` partitions exactly as the
/// shared core classifier decides per row, so scoped policy, report
/// assembly, and replay decode recompute from one rule.
#[test]
fn scope_rows_agrees_with_shared_classifier() {
    use kryprobe_core::workload::{ScopeDecision, ScopePartition, decide_workload_scope};
    let owned = agg_obs(1, "cbc(aes)", "cbc-aes-aesni", "ok");
    let other = agg_obs(2, "cbc(aes)", "cbc-aes-aesni", "ok");
    let unknown = agg_obs(3, "cbc(aes)", "cbc-aes-aesni", "ok");
    let rows = [
        row(
            20,
            43812,
            WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a")),
            asserted(),
            &owned,
        ),
        row(
            30,
            43813,
            WorkloadIdentity::container(RUNTIME, ID_B, Some("lifetime-b")),
            asserted(),
            &other,
        ),
        row(10, 0, WorkloadIdentity::none(), unresolved(), &unknown),
    ];
    for selector in [
        WorkloadSelector::cgroup(43812).expect("cgroup selector"),
        WorkloadSelector::container(RUNTIME, ID_A, None).expect("container selector"),
    ] {
        let scoped = scope_rows(&selector, &rows).expect("scopes");
        let (mut matched, mut nonmatched, mut unknown_match) = (0u64, 0u64, 0u64);
        for (row, decision) in rows.iter().zip(scoped.decisions.iter()) {
            let shared =
                decide_workload_scope(&selector, &row.context, &row.identity, &row.evidence);
            assert_eq!(
                *decision, shared,
                "per-row decision matches the shared rule"
            );
            match shared {
                ScopeDecision::Match => matched += row.calls,
                ScopeDecision::NonMatch => nonmatched += row.calls,
                ScopeDecision::Unknown => unknown_match += row.calls,
            }
        }
        assert_eq!(
            scoped.partition,
            ScopePartition::from_counts(matched, nonmatched, unknown_match).expect("valid"),
            "partition matches the shared fold under {selector:?}"
        );
    }
}
