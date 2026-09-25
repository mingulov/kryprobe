// SPDX-License-Identifier: GPL-3.0-or-later
//! Live-render tests (moved with the tables from the CLI, 1B-H2/1B-M8).

use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegrityRef, NativeObservation, NativeResult,
    ValidityInterval,
};
use kryprobe_core::ids::ObservationId;
use kryprobe_report::live_render::{render_lifecycle_block, render_watch_tables, trailer_dims};
use kryprobe_report::{lifecycle_v1_payload, validate_lifecycle_v1};

fn complete_dim() -> DimensionCoverage {
    DimensionCoverage::new(
        CoverageStatus::CompleteForDeclaredBoundary,
        ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        },
    )
}

fn healthy_coverage() -> CoverageSummary {
    CoverageSummary {
        target_population: complete_dim(),
        object_discovery: complete_dim(),
        attachment: complete_dim(),
        aggregate_counts: complete_dim(),
        detailed_events: complete_dim(),
        attribution: complete_dim(),
        correlation: complete_dim(),
        completion: complete_dim(),
    }
}

#[test]
fn trailer_names_each_gap_in_kp2_order() {
    // Each dimension alone maps to its kp2 §8 token.
    let cases = [
        ("target_population", "operation"),
        ("object_discovery", "attach"),
        ("attachment", "attach"),
        ("aggregate_counts", "capture-integrity"),
        ("detailed_events", "capture-integrity"),
        ("attribution", "attribution"),
        ("correlation", "correlation"),
        ("completion", "completion"),
    ];
    for (field, token) in cases {
        let mut coverage = healthy_coverage();
        let dim = match field {
            "target_population" => &mut coverage.target_population,
            "object_discovery" => &mut coverage.object_discovery,
            "attachment" => &mut coverage.attachment,
            "aggregate_counts" => &mut coverage.aggregate_counts,
            "detailed_events" => &mut coverage.detailed_events,
            "attribution" => &mut coverage.attribution,
            "correlation" => &mut coverage.correlation,
            "completion" => &mut coverage.completion,
            _ => unreachable!("pinned field list"),
        };
        dim.status = CoverageStatus::Partial;
        assert_eq!(trailer_dims(&coverage), vec![token], "field {field}");
    }
    // Every non-complete status weakens (Unsupported/NotRun/Unknown
    // are gaps too, never COMPLETE).
    for status in [
        CoverageStatus::Partial,
        CoverageStatus::Unsupported,
        CoverageStatus::NotRun,
        CoverageStatus::Unknown,
    ] {
        let mut coverage = healthy_coverage();
        coverage.attachment.status = status;
        assert_eq!(
            trailer_dims(&coverage),
            vec!["attach"],
            "status {status:?} weakens"
        );
    }
    // Multi-gap order is the kp2 §8 order, deduped.
    let mut coverage = healthy_coverage();
    coverage.completion.status = CoverageStatus::Partial;
    coverage.attachment.status = CoverageStatus::Partial;
    coverage.aggregate_counts.status = CoverageStatus::Partial;
    coverage.correlation.status = CoverageStatus::Unknown;
    assert_eq!(
        trailer_dims(&coverage),
        vec!["attach", "capture-integrity", "completion", "correlation"]
    );
    // Contract held (incl. interval end) is COMPLETE.
    assert!(trailer_dims(&healthy_coverage()).is_empty());
}

/// Lifecycle observation with the production live payload shape
/// (`LIFECYCLE_KEYS` dispatch envelope, as the backend emits it).
fn lifecycle_obs(
    id: u64,
    terminal: &str,
    status: serde_json::Value,
    duration_ns: serde_json::Value,
) -> NativeObservation {
    let (phase, call_kind, native_result) = match terminal {
        "unknown" => (
            EvidencePhase::Entered,
            CallKind::Unknown,
            NativeResult::KCryptoUnknown,
        ),
        _ => (
            EvidencePhase::Completed,
            CallKind::Operation,
            NativeResult::KCrypto {
                status: status.as_i64().unwrap_or(0) as i32,
            },
        ),
    };
    NativeObservation {
        id: ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase,
        call_kind,
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result,
        started_ns: None,
        ended_ns: None,
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: serde_json::json!({
            "row": "lifecycle",
            "capture_profile": "request-lifecycle",
            "id": format!("lc:{id}"),
            "tfm_id": 7,
            "terminal": terminal,
            "status": status,
            "duration_ns": duration_ns,
            "evidence": terminal != "unknown",
            "count_unit": "request_lifecycle",
            "completion_coverage": if terminal == "unknown" { "unobserved" } else { "observed" },
        }),
    }
}

#[test]
fn lifecycle_projection_emits_valid_v1() {
    // Grounded + unknown rows project to exactly the six schema keys
    // and validate clean; non-lifecycle rows project to None.
    for (terminal, status, duration) in [
        ("sync", serde_json::json!(0), serde_json::json!("50")),
        ("callback", serde_json::json!(-5), serde_json::json!("70")),
        ("unknown", serde_json::json!(null), serde_json::json!(null)),
    ] {
        let obs = lifecycle_obs(1, terminal, status, duration);
        let projected = lifecycle_v1_payload(&obs)
            .expect("lifecycle row projects")
            .expect("projection validates");
        let mut keys: Vec<&str> = projected
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "duration_ns",
                "request_id",
                "schema",
                "status",
                "terminal",
                "tfm_id"
            ],
            "exactly the six schema keys"
        );
        assert_eq!(projected["schema"], "kryprobe.kcrypto.lifecycle/v1");
        assert_eq!(projected["request_id"], "lc:1");
        assert_eq!(projected["tfm_id"], "kcrypto:tfm-7");
        assert!(
            validate_lifecycle_v1(&projected).is_empty(),
            "projected payload validates"
        );
    }
    let mut agg = lifecycle_obs(2, "sync", serde_json::json!(0), serde_json::json!("50"));
    agg.backend_payload["row"] = serde_json::json!("agg");
    assert!(
        lifecycle_v1_payload(&agg).is_none(),
        "non-lifecycle rows do not project"
    );
}

#[test]
fn lifecycle_projection_fails_closed_on_drift() {
    // A forbidden combination (unknown terminal carrying a duration)
    // fails the projection — the report breaks (exit 1) rather than
    // emitting a schema-violating document.
    let obs = lifecycle_obs(
        3,
        "unknown",
        serde_json::json!(null),
        serde_json::json!("50"),
    );
    let err = lifecycle_v1_payload(&obs)
        .expect("lifecycle row projects")
        .expect_err("unknown+duration must fail");
    assert!(err.contains("payload-v1"), "names the artifact: {err}");
}

#[test]
fn lifecycle_block_renders_rows_and_exact_totals() {
    let obs = [
        lifecycle_obs(2, "sync", serde_json::json!(0), serde_json::json!("50")),
        lifecycle_obs(
            1,
            "unknown",
            serde_json::json!(null),
            serde_json::json!(null),
        ),
        lifecycle_obs(
            3,
            "callback",
            serde_json::json!(-5),
            serde_json::json!("70"),
        ),
    ];
    let text = render_lifecycle_block(&obs);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "ID TERMINAL STATUS DURATION_NS");
    // Sorted by id, unknowns render `unknown` (never zero-filled).
    assert_eq!(lines[1], "lc:1 unknown unknown unknown");
    assert_eq!(lines[2], "lc:2 sync 0 50");
    assert_eq!(lines[3], "lc:3 callback -5 70");
    assert_eq!(lines[4], "LIFECYCLE TOTAL n=3 sync=1 callback=1 unknown=1");
    assert_eq!(lines.len(), 5);
    // Empty renders nothing (agg sessions keep exact bytes).
    assert_eq!(render_lifecycle_block(&[]), "");
}

#[test]
fn watch_tables_carry_lifecycle_sessions() {
    // A lifecycle-only session no longer reports zero activity: the
    // lifecycle block follows the (empty) agg table.
    let obs = [lifecycle_obs(
        1,
        "sync",
        serde_json::json!(0),
        serde_json::json!("50"),
    )];
    let text = render_watch_tables(&obs, &healthy_coverage());
    assert!(
        text.contains("LIFECYCLE TOTAL n=1 sync=1 callback=0 unknown=0"),
        "lifecycle activity reported:\n{text}"
    );
    assert!(text.ends_with("COMPLETE\n"), "trailer intact:\n{text}");
}
