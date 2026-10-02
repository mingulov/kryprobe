// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict acceptance for a quiet fixture's non-atomic API-return report.
//! Unknown consistency/delivery/completion is expected; measured loss is not waived.

use kryprobe_core::enums::CoverageStatus;
use kryprobe_core::evidence::{CoverageDimension, CoverageSummary, IntegritySummary};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn assert_report(doc: &Value) {
    let observations = doc["observations"].as_array().expect("observations");
    let calls = |row: &str| {
        observations
            .iter()
            .filter(|o| o["backend_payload"]["row"] == row)
            .try_fold(0u64, |sum, o| {
                sum.checked_add(
                    o["backend_payload"]["counts"]["calls"]
                        .as_u64()
                        .expect("calls"),
                )
            })
            .expect("fixture call sum does not overflow")
    };
    let (agg_calls, totals_calls) = (calls("agg"), calls("totals"));
    assert_eq!(
        observations
            .iter()
            .filter(|o| o["backend_payload"]["row"] == "totals")
            .count(),
        1,
        "one terminal totals sample"
    );
    assert_eq!(doc["verdict"]["status"], "partial", "{doc}");
    assert_eq!(
        doc["verdict"]["missing"],
        json!(["capture-integrity", "completion"]),
        "no additional missing dimension: {doc}"
    );
    let coverage: CoverageSummary =
        serde_json::from_value(doc["coverage"].clone()).expect("typed coverage");
    let integrity: IntegritySummary =
        serde_json::from_value(doc["integrity"].clone()).expect("typed integrity");
    assert_eq!(integrity, IntegritySummary::default(), "no measured loss");
    for kind in CoverageDimension::ALL {
        let dim = coverage.dimension(kind);
        let expected = match kind {
            CoverageDimension::AggregateCounts
            | CoverageDimension::DetailedEvents
            | CoverageDimension::Completion => CoverageStatus::Unknown,
            _ => CoverageStatus::CompleteForDeclaredBoundary,
        };
        assert_eq!(dim.status, expected, "{kind:?}: {dim:?}");
        assert!(dim.omissions.is_empty(), "{kind:?}: {dim:?}");
        assert!(dim.interval.end_ns.is_some(), "closed interval: {dim:?}");
        let counters: BTreeMap<_, _> = dim
            .counters
            .iter()
            .map(|counter| (counter.name.as_str(), counter.value))
            .collect();
        assert_eq!(counters.len(), dim.counters.len(), "unique counters");
        for (&name, &value) in &counters {
            match name {
                "probes_attached" | "probes_expected" => assert_eq!(value, 9),
                "uncovered:kernel_delivery_unmeasured"
                | "uncovered:completion_unobserved"
                | "uncovered:aggregate_snapshot_not_quiescent" => {
                    assert_eq!(value, 1);
                }
                "snapshot_agg_calls" => assert_eq!(value, agg_calls),
                "snapshot_totals_calls" => assert_eq!(value, totals_calls),
                "observations_decoded" => assert!(value > 0),
                "predrop_destroy_skip" => {} // documented destroy-only inventory
                _ => assert_eq!(value, 0, "unexpected counter {name} in {kind:?}"),
            }
        }
        let required: &[(&str, u64)] = match kind {
            CoverageDimension::Attachment => &[("probes_attached", 9), ("probes_expected", 9)],
            CoverageDimension::AggregateCounts => &[
                ("snapshot_agg_calls", agg_calls),
                ("snapshot_totals_calls", totals_calls),
                // Zero skew is a quiet-fixture acceptance condition only;
                // it is never an insertion-loss or exactness assertion.
                ("ktot_gap", 0),
                ("snapshot_gap_unreconciled", 0),
                ("uncovered:aggregate_snapshot_not_quiescent", 1),
                ("uncovered:kernel_delivery_unmeasured", 1),
                ("predrop_cfg_fail", 0),
                ("predrop_fret_fail", 0),
                ("predrop_arg_null", 0),
                ("predrop_chase_fail", 0),
                ("predrop_name_fail", 0),
                ("predrop_spare_6", 0),
                ("predrop_spare_7", 0),
            ],
            CoverageDimension::DetailedEvents => &[
                ("ring_drops", 0),
                ("overflow_identities", 0),
                ("user_queue_drops", 0),
                ("terminal_backlog_bytes", 0),
                ("terminal_busy", 0),
                ("uncovered:aggregate_snapshot_not_quiescent", 1),
                ("uncovered:kernel_delivery_unmeasured", 1),
            ],
            CoverageDimension::Attribution => &[("who_drops", 0)],
            CoverageDimension::Completion => &[("uncovered:completion_unobserved", 1)],
            _ => &[],
        };
        for (name, value) in required {
            assert_eq!(counters.get(name), Some(value), "required {kind:?}/{name}");
        }
    }
    assert_eq!(agg_calls, totals_calls, "quiet fixture operands agree");
    let mut operations = 0;
    for row in observations {
        let payload = &row["backend_payload"];
        if matches!(payload["row"].as_str(), Some("agg" | "totals")) {
            assert_eq!(payload["capture_profile"], "api-returns");
            assert_eq!(payload["count_unit"], "api_invocation_return");
            assert_eq!(payload["completion_coverage"], "unobserved");
            let calls = payload["counts"]["calls"].as_u64().expect("calls");
            if payload["row"] == "totals" {
                assert_eq!(row["phase"], "returned", "totals are not completion");
            } else if payload["family"] == "any" {
                // The sensor's family-agnostic allocation/destroy inventory
                // has Selected phase, even when the allocation result is known.
                assert_eq!(row["phase"], "selected");
                assert_eq!(payload["execution"], "unsupported");
                match payload["op"].as_str() {
                    Some("alloc") => {
                        assert!(matches!(payload["result"].as_str(), Some("ok" | "error")))
                    }
                    Some("destroy") => assert_eq!(payload["result"], "unobserved"),
                    _ => panic!("unexpected inventory: {row}"),
                }
            } else {
                assert_eq!(row["phase"], "returned", "API return is not completion");
                assert!(
                    matches!(
                        (payload["family"].as_str(), payload["op"].as_str()),
                        (Some("skcipher" | "aead"), Some("encrypt" | "decrypt"))
                            | (Some("ahash" | "shash"), Some("digest"))
                            | (Some("shash"), Some("finup"))
                    ),
                    "supported operation: {row}"
                );
                assert!(matches!(
                    payload["result"].as_str(),
                    Some("ok" | "error" | "queued")
                ));
                assert!(
                    payload.get("execution").is_none(),
                    "operation is not unsupported inventory"
                );
                operations += calls;
            }
        }
    }
    assert!(operations > 0, "positive API-return evidence");
}

#[test]
fn partial_acceptance_rejects_loss_and_fabricated_completeness() {
    use kryprobe_core::evidence::{DimensionCounter, DimensionCoverage, ValidityInterval};
    let dim = DimensionCoverage::new(
        CoverageStatus::CompleteForDeclaredBoundary,
        ValidityInterval {
            start_ns: 1,
            end_ns: Some(2),
        },
    );
    let mut coverage = serde_json::Map::new();
    for kind in CoverageDimension::ALL {
        coverage.insert(
            kind.as_core_str().to_owned(),
            serde_json::to_value(&dim).unwrap(),
        );
    }
    let lists: &[(&str, &[(&str, u64)])] = &[
        (
            "attachment",
            &[("probes_attached", 9), ("probes_expected", 9)],
        ),
        (
            "aggregate_counts",
            &[
                ("ktot_gap", 0),
                ("snapshot_agg_calls", 2),
                ("snapshot_totals_calls", 2),
                ("snapshot_gap_unreconciled", 0),
                ("uncovered:aggregate_snapshot_not_quiescent", 1),
                ("uncovered:kernel_delivery_unmeasured", 1),
                ("predrop_cfg_fail", 0),
                ("predrop_fret_fail", 0),
                ("predrop_arg_null", 0),
                ("predrop_chase_fail", 0),
                ("predrop_name_fail", 0),
                ("predrop_spare_6", 0),
                ("predrop_spare_7", 0),
            ],
        ),
        (
            "detailed_events",
            &[
                ("ring_drops", 0),
                ("overflow_identities", 0),
                ("user_queue_drops", 0),
                ("terminal_backlog_bytes", 0),
                ("terminal_busy", 0),
                ("uncovered:aggregate_snapshot_not_quiescent", 1),
                ("uncovered:kernel_delivery_unmeasured", 1),
            ],
        ),
        ("attribution", &[("who_drops", 0)]),
        (
            "completion",
            &[
                ("observations_decoded", 1),
                ("uncovered:completion_unobserved", 1),
            ],
        ),
    ];
    for (name, counters) in lists {
        if !matches!(*name, "attachment" | "attribution") {
            coverage[*name]["status"] = json!("unknown");
        }
        coverage[*name]["counters"] = serde_json::to_value(
            counters
                .iter()
                .map(|(name, value)| DimensionCounter {
                    name: (*name).to_owned(),
                    value: *value,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    }
    let doc = json!({
        "coverage": coverage,
        "integrity": IntegritySummary::default(),
        "verdict": {"status": "partial", "missing": ["capture-integrity", "completion"]},
        "observations": [{"phase": "returned", "backend_payload": {
            "row": "agg", "capture_profile": "api-returns", "count_unit": "api_invocation_return",
            "family": "skcipher", "op": "encrypt", "result": "ok",
            "completion_coverage": "unobserved", "counts": {"calls": 1},
        }}, {"phase": "selected", "backend_payload": {
            "row": "agg", "capture_profile": "api-returns", "count_unit": "api_invocation_return",
            "family": "any", "op": "alloc", "result": "ok", "execution": "unsupported",
            "completion_coverage": "unobserved", "counts": {"calls": 1},
        }}, {"phase": "returned", "backend_payload": {
            "row": "totals", "capture_profile": "api-returns", "count_unit": "api_invocation_return",
            "completion_coverage": "unobserved", "counts": {"calls": 2},
        }}],
    });
    assert_report(&doc);
    for (pointer, value) in [
        ("/integrity/user_queue_drops", json!("1")),
        ("/coverage/detailed_events/counters/0/value", json!("1")),
        ("/coverage/aggregate_counts/counters/0/value", json!("1")),
        ("/coverage/aggregate_counts/counters/1/value", json!("1")),
        ("/coverage/aggregate_counts/counters/2/value", json!("1")),
        ("/coverage/aggregate_counts/counters/4/value", json!("0")),
        ("/coverage/detailed_events/counters/2/value", json!("1")),
        ("/coverage/detailed_events/counters/3/value", json!("1")),
        ("/coverage/detailed_events/counters/4/value", json!("1")),
        (
            "/coverage/completion/status",
            json!("complete_for_declared_boundary"),
        ),
        ("/verdict/status", json!("complete")),
        ("/observations/0/phase", json!("completed")),
        ("/observations/0/backend_payload/op", json!("alloc")),
        (
            "/observations/0/backend_payload/result",
            json!("unobserved"),
        ),
        ("/observations/1/phase", json!("returned")),
        (
            "/observations/1/backend_payload/execution",
            json!("supported"),
        ),
        ("/observations/1/backend_payload/op", json!("encrypt")),
        ("/observations/2/phase", json!("completed")),
    ] {
        let mut bad = doc.clone();
        *bad.pointer_mut(pointer).expect("mutation target") = value;
        assert!(
            std::panic::catch_unwind(|| assert_report(&bad)).is_err(),
            "accepted {pointer}"
        );
    }
    let mut inventory_only = doc.clone();
    inventory_only["observations"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    // Keep the diagnostic operands consistent so this control reaches the
    // positive-operation requirement instead of failing on sample mismatch.
    inventory_only["observations"][1]["backend_payload"]["counts"]["calls"] = json!(1);
    inventory_only["coverage"]["aggregate_counts"]["counters"][1]["value"] = json!("1");
    inventory_only["coverage"]["aggregate_counts"]["counters"][2]["value"] = json!("1");
    assert!(
        std::panic::catch_unwind(|| assert_report(&inventory_only)).is_err(),
        "inventory and totals alone cannot prove positive operation evidence"
    );
}
