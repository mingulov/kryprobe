// SPDX-License-Identifier: GPL-3.0-or-later
//! M1: live JSONL export renders validated event-v0 streams, and the
//! scripted + live emitters share one clock cadence (`STEP_NS`).

use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegrityRef, NativeObservation, NativeResult,
    ValidityInterval,
};
use kryprobe_core::ids::{IdIssuer, ImplementationId, ObservationId, SessionId, TargetId};
use kryprobe_core::synthetic::{STEP_NS, SyntheticBackend, canonical_script};
use kryprobe_report::live_render::{LIVE_QUALIFICATION_ID, LIVE_SESSION_ID, render_live_jsonl};
use kryprobe_report::{ReportError, check_stream};

const LIVE_KINDS: &[(&str, &[&str])] = &[
    (
        "session_start",
        &[
            "target_selector",
            "capture_mode",
            "requested_backends",
            "qualification_id",
        ],
    ),
    (
        "operation_observation",
        &["observation_id", "backend", "native_operation"],
    ),
    ("session_end", &["verdict", "final_barrier"]),
];

fn kcrypto_obs(
    id: u64,
    op: Option<&str>,
    algorithm: Option<&str>,
    result: NativeResult,
) -> NativeObservation {
    let mut payload = serde_json::Map::new();
    if let Some(op) = op {
        payload.insert("op".to_owned(), serde_json::Value::String(op.to_owned()));
    }
    if let Some(algorithm) = algorithm {
        payload.insert(
            "algorithm".to_owned(),
            serde_json::Value::String(algorithm.to_owned()),
        );
    }
    NativeObservation {
        id: ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: Some(TargetId::new(7)),
        object: None,
        implementation: Some(ImplementationId::new(3)),
        phase: EvidencePhase::Completed,
        call_kind: CallKind::Operation,
        operation_class: OperationClass::Encrypt,
        native_name: None,
        native_code: None,
        native_result: result,
        started_ns: Some(1_000),
        ended_ns: Some(2_000),
        correlation: None,
        integrity: IntegrityRef::new(1),
        backend_payload: serde_json::Value::Object(payload),
    }
}

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

fn stamps(text: &str) -> Vec<u64> {
    text.lines()
        .map(|line| {
            let record: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            record
                .get("monotonic_ns")
                .and_then(serde_json::Value::as_str)
                .and_then(|text| text.parse::<u64>().ok())
                .expect("numeric monotonic_ns string")
        })
        .collect()
}

#[test]
fn live_jsonl_renders_validated_stream() {
    let observations = vec![
        kcrypto_obs(
            1,
            Some("encrypt"),
            Some("cbc(aes)"),
            NativeResult::KCrypto { status: 0 },
        ),
        // Who-shaped payloads carry no op/algorithm: the exporter must
        // report `unknown`, never invent names.
        kcrypto_obs(2, None, None, NativeResult::KCrypto { status: 0 }),
    ];
    let text = render_live_jsonl(&observations, &healthy_coverage(), false).expect("renders");
    assert_eq!(check_stream(&text, LIVE_KINDS), Vec::new());
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "start + 2 obs + end");
    assert!(lines[0].contains(LIVE_SESSION_ID));
    assert!(lines[0].contains(LIVE_QUALIFICATION_ID));
    assert!(lines[0].contains("\"kcrypto\""));
    assert!(lines[1].contains("\"encrypt\""));
    assert!(lines[1].contains("\"cbc(aes)\""));
    assert!(lines[2].contains("\"unknown\""));
    assert!(lines[3].contains("\"OBSERVED\""));
}

#[test]
fn live_jsonl_stamps_advance_by_shared_step() {
    let observations = vec![kcrypto_obs(
        1,
        Some("encrypt"),
        None,
        NativeResult::KCrypto { status: 0 },
    )];
    let text = render_live_jsonl(&observations, &healthy_coverage(), false).expect("renders");
    let stamps = stamps(&text);
    assert_eq!(stamps.len(), 3);
    for pair in stamps.windows(2) {
        assert_eq!(pair[1] - pair[0], STEP_NS);
    }
}

#[test]
fn canonical_script_stamps_advance_by_shared_step() {
    let backend = SyntheticBackend::new(canonical_script());
    let issuer = IdIssuer::default();
    let run = backend
        .run_script(SessionId::new(1), &issuer)
        .expect("script runs");
    let stamps = stamps(&run.to_jsonl());
    assert!(stamps.len() > 2, "script emits several records");
    for pair in stamps.windows(2) {
        assert_eq!(pair[1] - pair[0], STEP_NS);
    }
}

#[test]
fn live_jsonl_rejects_synthetic_result() {
    let observations = vec![kcrypto_obs(
        1,
        Some("encrypt"),
        None,
        NativeResult::Synthetic { code: 0 },
    )];
    assert_eq!(
        render_live_jsonl(&observations, &healthy_coverage(), false),
        Err(ReportError::SyntheticResult)
    );
}

#[test]
fn live_jsonl_marks_partial_verdict_when_interrupted() {
    // 4B-M5: a SIGINT-cut window forces PARTIAL even when every
    // measured dimension held.
    let text = render_live_jsonl(&[], &healthy_coverage(), true).expect("renders");
    assert_eq!(check_stream(&text, LIVE_KINDS), Vec::new());
    assert!(
        text.lines()
            .last()
            .expect("end line")
            .contains("\"PARTIAL\"")
    );
}

#[test]
fn live_jsonl_marks_partial_verdict_on_gap() {
    let mut coverage = healthy_coverage();
    coverage.attachment.status = CoverageStatus::Partial;
    let text = render_live_jsonl(&[], &coverage, false).expect("renders");
    assert_eq!(check_stream(&text, LIVE_KINDS), Vec::new());
    assert!(
        text.lines()
            .last()
            .expect("end line")
            .contains("\"PARTIAL\"")
    );
}
