// SPDX-License-Identifier: GPL-3.0-or-later
//! Policy engine contract: YAML shape, match dimensions, 3-state verdicts.

use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegrityRef, NativeObservation, NativeResult,
    ValidityInterval,
};
use kryprobe_core::ids::ObservationId;
use kryprobe_policy::{PolicyVerdict, evaluate, parse_policy};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn obs(
    id: u64,
    backend: BackendId,
    phase: EvidencePhase,
    payload: serde_json::Value,
) -> NativeObservation {
    NativeObservation {
        id: ObservationId::new(id),
        backend,
        target: None,
        object: None,
        implementation: None,
        phase,
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

fn agg_payload(
    family: &str,
    op: &str,
    result: &str,
    algorithm: &str,
    driver: &str,
    context: &str,
) -> serde_json::Value {
    serde_json::json!({
        "row": "agg",
        "family": family,
        "op": op,
        "result": result,
        "algorithm": algorithm,
        "driver": driver,
        "context": context,
        "counts": {"calls": 3, "ok": 3, "errors": 0, "queued": 0},
        "bytes": 300,
        "window": {"first_ns": 100, "last_ns": 200},
        "status_canonical": true,
    })
}

#[allow(clippy::too_many_arguments)]
fn agg_obs(
    id: u64,
    phase: EvidencePhase,
    family: &str,
    op: &str,
    result: &str,
    algorithm: &str,
    driver: &str,
    context: &str,
) -> NativeObservation {
    obs(
        id,
        BackendId::KCrypto,
        phase,
        agg_payload(family, op, result, algorithm, driver, context),
    )
}

fn totals_obs(id: u64) -> NativeObservation {
    // Totals carry `Completed` (the D3 exclusion is load-bearing here).
    obs(
        id,
        BackendId::KCrypto,
        EvidencePhase::Completed,
        serde_json::json!({
            "row": "totals",
            "counts": {"calls": 10, "ok": 10, "errors": 0, "queued": 0},
            "bytes": 1000,
            "window": {"first_ns": 100, "last_ns": 200},
            "status_canonical": true,
        }),
    )
}

fn ident_obs(id: u64) -> NativeObservation {
    obs(
        id,
        BackendId::KCrypto,
        EvidencePhase::Discovered,
        serde_json::json!({
            "row": "ident",
            "ident_kind": "ident",
            "key_hash": 1234,
            "family": "skcipher",
            "op": "encrypt",
            "result": "ok",
            "context": "process",
            "name_lens": {"alg": 8, "drv": 5},
            "first_seen_ns": 100,
        }),
    )
}

fn interval() -> ValidityInterval {
    ValidityInterval {
        start_ns: 100,
        end_ns: Some(200),
    }
}

fn dim(status: CoverageStatus) -> DimensionCoverage {
    DimensionCoverage::new(status, interval())
}

fn complete_coverage() -> CoverageSummary {
    let complete = || dim(CoverageStatus::CompleteForDeclaredBoundary);
    CoverageSummary {
        target_population: complete(),
        object_discovery: complete(),
        attachment: complete(),
        aggregate_counts: complete(),
        detailed_events: complete(),
        attribution: complete(),
        correlation: complete(),
        completion: complete(),
    }
}

fn gapped_coverage() -> CoverageSummary {
    let mut coverage = complete_coverage();
    coverage.attachment = dim(CoverageStatus::Partial);
    coverage.aggregate_counts = dim(CoverageStatus::Unknown);
    coverage
}

fn policy_yaml(rules: &str) -> String {
    format!("version: 1\nrules:\n{rules}")
}

fn deny_rule(id: &str, source: &str, matches: &str, decision: &str) -> String {
    format!("  - id: {id}\n    source: {source}\n    match:\n{matches}    decision: {decision}\n")
}

// ---------------------------------------------------------------------------
// YAML shape
// ---------------------------------------------------------------------------

#[test]
fn yaml_kp2_example_parses_exact() {
    let text = "version: 1\n\
                \n\
                rules:\n\
                \x20 - id: no-kernel-md5\n\
                \x20   source: kernel-crypto\n\
                \x20   match:\n\
                \x20     stage: executed\n\
                \x20     algorithm: md5\n\
                \x20   decision: deny\n\
                \n\
                \x20 - id: only-aesni-for-xts\n\
                \x20   source: kernel-crypto\n\
                \x20   match:\n\
                \x20     family: skcipher\n\
                \x20     algorithm: \"xts(aes)\"\n\
                \x20     driver_not: \"xts-aes-aesni\"\n\
                \x20   decision: deny\n\
                \n\
                \x20 - id: no-generic-aes-in-this-baseline\n\
                \x20   source: kernel-crypto\n\
                \x20   match:\n\
                \x20     driver: \"aes-generic\"\n\
                \x20   decision: report\n";
    let policy = parse_policy(text).expect("kp2 example parses");
    assert_eq!(policy.version, 1);
    assert_eq!(policy.rules.len(), 3);
    assert_eq!(policy.rules[0].id, "no-kernel-md5");
    assert_eq!(policy.rules[0].source, "kernel-crypto");
    assert_eq!(policy.rules[0].match_spec.algorithm.as_deref(), Some("md5"));
    assert_eq!(
        policy.rules[1].match_spec.driver_not.as_deref(),
        Some("xts-aes-aesni")
    );
    assert_eq!(policy.rules[2].decision, kryprobe_policy::Decision::Report);
}

#[test]
fn yaml_unknown_keys_and_versions_rejected_never_ignored() {
    let rule = deny_rule("r", "kernel-crypto", "      algorithm: md5\n", "deny");
    let cases = [
        // Unknown keys at every level.
        (
            format!("version: 1\nrules:\n{rule}extra: 1\n"),
            "top-level unknown key",
        ),
        (
            policy_yaml(
                "  - id: r\n    source: kernel-crypto\n    match:\n      algorithm: md5\n    decision: deny\n    extra: 1\n",
            ),
            "rule unknown key",
        ),
        (
            policy_yaml(&deny_rule(
                "r",
                "kernel-crypto",
                "      algorithm: md5\n      bogus: x\n",
                "deny",
            )),
            "match unknown key",
        ),
        // Wrong versions.
        ("version: 2\nrules: []\n".to_owned(), "version 2"),
        ("version: 0\nrules: []\n".to_owned(), "version 0"),
        ("rules: []\n".to_owned(), "missing version"),
        ("version: one\nrules: []\n".to_owned(), "string version"),
        // Missing required rule keys.
        (
            policy_yaml(
                "  - source: kernel-crypto\n    match:\n      algorithm: md5\n    decision: deny\n",
            ),
            "missing id",
        ),
        (
            policy_yaml("  - id: r\n    match:\n      algorithm: md5\n    decision: deny\n"),
            "missing source",
        ),
        (
            policy_yaml("  - id: r\n    source: kernel-crypto\n    decision: deny\n"),
            "missing match",
        ),
        (
            policy_yaml("  - id: r\n    source: kernel-crypto\n    match:\n      algorithm: md5\n"),
            "missing decision",
        ),
        ("version: 1\n".to_owned(), "missing rules"),
        // Unknown enum values fail closed (a silently-never-matching
        // rule would be silent non-enforcement).
        (
            policy_yaml(&deny_rule(
                "r",
                "kernel-crypto",
                "      algorithm: md5\n",
                "block",
            )),
            "bad decision",
        ),
        (
            policy_yaml(&deny_rule(
                "r",
                "kernel-crypto",
                "      stage: running\n",
                "deny",
            )),
            "bad stage",
        ),
        // Malformed YAML.
        ("version: [1\n".to_owned(), "malformed yaml"),
        ("".to_owned(), "empty doc"),
    ];
    for (text, what) in cases {
        assert!(
            parse_policy(&text).is_err(),
            "{what} must be rejected: {text:?}"
        );
    }
}

#[test]
fn yaml_empty_rules_and_empty_match_accepted() {
    let policy = parse_policy("version: 1\nrules: []\n").expect("empty rules parse");
    assert!(policy.rules.is_empty());
    let text = policy_yaml(
        "  - id: deny-all\n    source: kernel-crypto\n    match: {}\n    decision: deny\n",
    );
    let policy = parse_policy(&text).expect("empty match parses");
    assert!(policy.rules[0].match_spec.is_empty());
}

// ---------------------------------------------------------------------------
// Match dimensions (D3/D4/D5)
// ---------------------------------------------------------------------------

fn eval_deny(matches: &str, observations: &[NativeObservation]) -> PolicyVerdict {
    let text = policy_yaml(&deny_rule("r", "kernel-crypto", matches, "deny"));
    let policy = parse_policy(&text).expect("rule parses");
    evaluate(&policy, observations, &complete_coverage())
}

fn is_violation(verdict: &PolicyVerdict) -> bool {
    matches!(verdict, PolicyVerdict::Violation { .. })
}

#[test]
fn algorithm_exact_and_glob() {
    let md5 = || {
        agg_obs(
            1,
            EvidencePhase::Completed,
            "shash",
            "digest",
            "ok",
            "md5",
            "md5-generic",
            "process",
        )
    };
    let cases = [
        ("      algorithm: md5\n", true, "exact hit"),
        ("      algorithm: sha512\n", false, "exact miss"),
        ("      algorithm: \"*md5*\"\n", true, "star hit"),
        ("      algorithm: \"m?5\"\n", true, "question hit"),
        ("      algorithm: \"m?4\"\n", false, "question miss"),
        ("      algorithm: \"md*\"\n", true, "prefix star"),
        ("      algorithm: \"*sha*\"\n", false, "star miss"),
        // No character classes: brackets are literal.
        ("      algorithm: \"[m]d5\"\n", false, "class is literal"),
    ];
    for (matches, hit, what) in cases {
        assert_eq!(
            is_violation(&eval_deny(matches, &[md5()])),
            hit,
            "{what}: {matches:?}"
        );
    }
}

#[test]
fn driver_and_driver_not() {
    let ob = || {
        agg_obs(
            1,
            EvidencePhase::Completed,
            "skcipher",
            "encrypt",
            "ok",
            "cbc(aes)",
            "xts-aes-aesni",
            "process",
        )
    };
    // `driver`: glob match.
    assert!(is_violation(&eval_deny(
        "      driver: \"xts-aes-aesni\"\n",
        &[ob()]
    )));
    assert!(is_violation(&eval_deny(
        "      driver: \"*-aesni\"\n",
        &[ob()]
    )));
    assert!(!is_violation(&eval_deny(
        "      driver: \"aes-generic\"\n",
        &[ob()]
    )));
    // `driver_not`: matches when the glob does NOT match.
    assert!(!is_violation(&eval_deny(
        "      driver_not: \"xts-aes-aesni\"\n",
        &[ob()]
    )));
    assert!(!is_violation(&eval_deny(
        "      driver_not: \"*-aesni\"\n",
        &[ob()]
    )));
    assert!(is_violation(&eval_deny(
        "      driver_not: \"aes-generic\"\n",
        &[ob()]
    )));
}

#[test]
fn family_operation_result_context_match_payload_names() {
    let ob = || {
        agg_obs(
            1,
            EvidencePhase::Completed,
            "aead",
            "decrypt",
            "error",
            "gcm(aes)",
            "aesni",
            "softirq",
        )
    };
    for (matches, what) in [
        ("      family: aead\n", "family"),
        ("      operation: decrypt\n", "operation reads payload op"),
        (
            "      result: error\n",
            "result ok/error/queued/unobserved/unknown",
        ),
        ("      context: softirq\n", "context"),
        ("      family: \"ae*\"\n", "family glob"),
        ("      operation: \"decryp?\"\n", "operation glob"),
    ] {
        assert!(is_violation(&eval_deny(matches, &[ob()])), "{what}");
    }
    for (matches, what) in [
        ("      family: skcipher\n", "family miss"),
        ("      operation: encrypt\n", "operation miss"),
        ("      result: ok\n", "result miss"),
        ("      context: process\n", "context miss"),
    ] {
        assert!(!is_violation(&eval_deny(matches, &[ob()])), "{what}");
    }
}

#[test]
fn result_names_grounded_from_result_name() {
    // Every `result_name()` spelling matches literally.
    for result in ["ok", "error", "queued", "unobserved", "unknown"] {
        let ob = agg_obs(
            1,
            EvidencePhase::Completed,
            "skcipher",
            "encrypt",
            result,
            "cbc(aes)",
            "aesni",
            "process",
        );
        assert!(
            is_violation(&eval_deny(&format!("      result: {result}\n"), &[ob])),
            "result {result}"
        );
    }
    // Anything else never matches real payloads.
    let ob = agg_obs(
        1,
        EvidencePhase::Completed,
        "skcipher",
        "encrypt",
        "ok",
        "cbc(aes)",
        "aesni",
        "process",
    );
    assert!(!is_violation(&eval_deny("      result: failed\n", &[ob])));
}

#[test]
fn stage_selected_vs_executed_per_d3() {
    let agg = |phase| {
        agg_obs(
            1, phase, "skcipher", "alloc", "ok", "cbc(aes)", "", "process",
        )
    };
    // selected ⟺ phase == Selected (on agg rows).
    assert!(is_violation(&eval_deny(
        "      stage: selected\n",
        &[agg(EvidencePhase::Selected)]
    )));
    for phase in [
        EvidencePhase::Entered,
        EvidencePhase::Returned,
        EvidencePhase::Completed,
    ] {
        assert!(
            !is_violation(&eval_deny("      stage: selected\n", &[agg(phase)])),
            "selected rejects {phase:?}"
        );
    }
    // executed ⟺ row=agg ∧ phase ∈ {Entered, Returned, Completed}.
    for phase in [
        EvidencePhase::Entered,
        EvidencePhase::Returned,
        EvidencePhase::Completed,
    ] {
        assert!(
            is_violation(&eval_deny("      stage: executed\n", &[agg(phase)])),
            "executed accepts {phase:?}"
        );
    }
    assert!(!is_violation(&eval_deny(
        "      stage: executed\n",
        &[agg(EvidencePhase::Selected)]
    )));
}

#[test]
fn totals_and_ident_rows_never_match_any_stage() {
    // Totals carry Completed: without the explicit exclusion they
    // would match `executed` — carriers/markers must not.
    for matches in ["      stage: selected\n", "      stage: executed\n"] {
        assert!(
            !is_violation(&eval_deny(matches, &[totals_obs(1)])),
            "totals vs {matches:?}"
        );
        assert!(
            !is_violation(&eval_deny(matches, &[ident_obs(1)])),
            "ident vs {matches:?}"
        );
    }
}

#[test]
fn module_never_matches_kcrypto() {
    // Even with a module key smuggled into a kcrypto payload, D4
    // holds: module is not captured for kernel-crypto v0.1.
    let mut payload = agg_payload("skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process");
    payload["module"] = serde_json::json!("aesni_intel");
    let kcrypto = obs(
        1,
        BackendId::KCrypto,
        EvidencePhase::Completed,
        payload.clone(),
    );
    assert!(!is_violation(&eval_deny(
        "      module: aesni_intel\n",
        &[kcrypto]
    )));
    assert!(!is_violation(&eval_deny(
        "      module: \"*\"\n",
        &[obs(
            2,
            BackendId::KCrypto,
            EvidencePhase::Completed,
            payload
        )]
    )));
    // Import-shaped observations (non-kcrypto backend, matching
    // source) match by glob.
    let import = obs(
        3,
        BackendId::Synthetic,
        EvidencePhase::Completed,
        serde_json::json!({
            "row": "agg",
            "module": "aesni_intel",
        }),
    );
    for (matches, what) in [
        ("      module: aesni_intel\n", "exact"),
        ("      module: \"aesni_*\"\n", "glob"),
    ] {
        let text = policy_yaml(&deny_rule("r", "synthetic", matches, "deny"));
        let policy = parse_policy(&text).expect("parses");
        assert!(
            is_violation(&evaluate(
                &policy,
                std::slice::from_ref(&import),
                &complete_coverage(),
            )),
            "{what}"
        );
    }
}

#[test]
fn rule_matches_only_if_all_present_keys_match() {
    let ob = agg_obs(
        1,
        EvidencePhase::Completed,
        "skcipher",
        "encrypt",
        "ok",
        "cbc(aes)",
        "aesni",
        "process",
    );
    assert!(is_violation(&eval_deny(
        "      stage: executed\n      family: skcipher\n      operation: encrypt\n      algorithm: \"cbc(aes)\"\n      driver: aesni\n      result: ok\n      context: process\n",
        std::slice::from_ref(&ob),
    )));
    // One miss anywhere vetoes.
    assert!(!is_violation(&eval_deny(
        "      family: skcipher\n      driver: aes-generic\n",
        std::slice::from_ref(&ob),
    )));
    assert!(!is_violation(&eval_deny(
        "      stage: executed\n      algorithm: sha512\n",
        std::slice::from_ref(&ob),
    )));
    assert!(!is_violation(&eval_deny(
        "      stage: selected\n      family: skcipher\n      operation: encrypt\n",
        &[ob],
    )));
}

#[test]
fn rule_source_must_match_observation_source() {
    let ob = agg_obs(
        1,
        EvidencePhase::Completed,
        "shash",
        "digest",
        "ok",
        "md5",
        "md5-generic",
        "process",
    );
    let text = policy_yaml(&deny_rule("r", "openssl", "      algorithm: md5\n", "deny"));
    let policy = parse_policy(&text).expect("parses");
    assert!(
        matches!(
            evaluate(&policy, &[ob], &complete_coverage()),
            PolicyVerdict::Clean
        ),
        "other-source rule never matches kcrypto data"
    );
}

#[test]
fn empty_match_matches_every_observation_of_source() {
    let observations = vec![
        agg_obs(
            1,
            EvidencePhase::Completed,
            "skcipher",
            "encrypt",
            "ok",
            "cbc(aes)",
            "aesni",
            "process",
        ),
        totals_obs(2),
    ];
    let text = policy_yaml(
        &deny_rule("deny-all", "kernel-crypto", "", "deny")
            .replace("    match:\n", "    match: {}\n"),
    );
    let policy = parse_policy(&text).expect("parses");
    match evaluate(&policy, &observations, &complete_coverage()) {
        PolicyVerdict::Violation { rule, obs_ids, .. } => {
            assert_eq!(rule, "deny-all");
            assert_eq!(obs_ids.len(), 2);
        }
        other => panic!("vacuous AND matches all, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3-state verdicts (D7)
// ---------------------------------------------------------------------------

#[test]
fn violation_carries_rule_ids_names_and_evidence() {
    let observations = vec![
        agg_obs(
            1,
            EvidencePhase::Completed,
            "skcipher",
            "encrypt",
            "ok",
            "cbc(aes)",
            "aesni",
            "process",
        ),
        agg_obs(
            2,
            EvidencePhase::Completed,
            "shash",
            "digest",
            "ok",
            "md5",
            "md5-generic",
            "kthread",
        ),
        agg_obs(
            3,
            EvidencePhase::Completed,
            "shash",
            "digest",
            "ok",
            "md5",
            "md5-generic",
            "process",
        ),
    ];
    let text = policy_yaml(&deny_rule(
        "no-kernel-md5",
        "kernel-crypto",
        "      stage: executed\n      algorithm: md5\n",
        "deny",
    ));
    let policy = parse_policy(&text).expect("parses");
    match evaluate(&policy, &observations, &complete_coverage()) {
        PolicyVerdict::Violation {
            rule,
            obs_ids,
            algorithm,
            driver,
            context,
            evidence,
        } => {
            assert_eq!(rule, "no-kernel-md5");
            assert_eq!(obs_ids, vec![ObservationId::new(2), ObservationId::new(3)]);
            // Representative names come from the first matched observation.
            assert_eq!(algorithm, "md5");
            assert_eq!(driver, "md5-generic");
            assert_eq!(context, "kthread");
            assert_eq!(evidence.len(), 2);
            assert_eq!(evidence[0].id, ObservationId::new(2));
        }
        other => panic!("deny match must violate, got {other:?}"),
    }
}

#[test]
fn first_matching_deny_wins_in_policy_order() {
    let observations = vec![agg_obs(
        1,
        EvidencePhase::Completed,
        "shash",
        "digest",
        "ok",
        "md5",
        "md5-generic",
        "process",
    )];
    let text = policy_yaml(&format!(
        "{}{}",
        deny_rule("first", "kernel-crypto", "      algorithm: md5\n", "deny"),
        deny_rule("second", "kernel-crypto", "      family: shash\n", "deny"),
    ));
    let policy = parse_policy(&text).expect("parses");
    match evaluate(&policy, &observations, &complete_coverage()) {
        PolicyVerdict::Violation { rule, .. } => assert_eq!(rule, "first"),
        other => panic!("must violate, got {other:?}"),
    }
}

#[test]
fn report_match_never_violates() {
    let observations = vec![agg_obs(
        1,
        EvidencePhase::Completed,
        "skcipher",
        "encrypt",
        "ok",
        "cbc(aes)",
        "aes-generic",
        "process",
    )];
    let text = policy_yaml(&deny_rule(
        "watch-generic",
        "kernel-crypto",
        "      driver: \"aes-generic\"\n",
        "report",
    ));
    let policy = parse_policy(&text).expect("parses");
    assert!(
        matches!(
            evaluate(&policy, &observations, &complete_coverage()),
            PolicyVerdict::Clean
        ),
        "report match is not a violation"
    );
}

#[test]
fn no_match_with_complete_coverage_is_clean() {
    let observations = vec![agg_obs(
        1,
        EvidencePhase::Completed,
        "skcipher",
        "encrypt",
        "ok",
        "cbc(aes)",
        "aesni",
        "process",
    )];
    let text = policy_yaml(&deny_rule(
        "r",
        "kernel-crypto",
        "      algorithm: md5\n",
        "deny",
    ));
    let policy = parse_policy(&text).expect("parses");
    assert!(matches!(
        evaluate(&policy, &observations, &complete_coverage()),
        PolicyVerdict::Clean
    ));
    // Empty policy over a healthy capture is clean too.
    let empty = parse_policy("version: 1\nrules: []\n").expect("parses");
    assert!(matches!(
        evaluate(&empty, &observations, &complete_coverage()),
        PolicyVerdict::Clean
    ));
}

#[test]
fn no_match_with_gaps_is_inconclusive_naming_dims() {
    let observations = vec![agg_obs(
        1,
        EvidencePhase::Completed,
        "skcipher",
        "encrypt",
        "ok",
        "cbc(aes)",
        "aesni",
        "process",
    )];
    let text = policy_yaml(&deny_rule(
        "r",
        "kernel-crypto",
        "      algorithm: md5\n",
        "deny",
    ));
    let policy = parse_policy(&text).expect("parses");
    match evaluate(&policy, &observations, &gapped_coverage()) {
        PolicyVerdict::Inconclusive { missing_dims } => {
            assert_eq!(missing_dims, vec!["attachment", "aggregate_counts"]);
        }
        other => panic!("gaps must be inconclusive, got {other:?}"),
    }
}

#[test]
fn violation_stands_when_other_dims_partial() {
    // kp2 §8: a real observation is a finding even when other
    // coverage is partial — findings stand.
    let observations = vec![agg_obs(
        1,
        EvidencePhase::Completed,
        "shash",
        "digest",
        "ok",
        "md5",
        "md5-generic",
        "process",
    )];
    let text = policy_yaml(&deny_rule(
        "r",
        "kernel-crypto",
        "      algorithm: md5\n",
        "deny",
    ));
    let policy = parse_policy(&text).expect("parses");
    assert!(
        matches!(
            evaluate(&policy, &observations, &gapped_coverage()),
            PolicyVerdict::Violation { .. }
        ),
        "violation stands over partial coverage"
    );
}
