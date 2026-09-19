// SPDX-License-Identifier: GPL-3.0-or-later
//! T9: writer/validator/renderer goldens, tamper cases, schema freeze.

use kryprobe_core::enums::{BackendId, CallKind, CaptureMode, EvidencePhase, OperationClass};
use kryprobe_core::enums::{CoverageStatus, TargetSelector};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegrityRef, IntegritySummary, NativeObservation,
    NativeResult, OmissionId, RelationshipConfidence, RelationshipEvidence, RelationshipKind,
    RelationshipRecord, ValidityInterval,
};
use kryprobe_core::ids::{CorrelationId, ImplementationId, ObservationId, SessionId, TargetId};
use kryprobe_report::{
    CoverageGap, FinalBarrier, JsonlWriter, ObservationExtra, ReportError, SessionEnd,
    SessionStart, SessionVerdict, SnapshotBarrier, SnapshotParams, SnapshotUnit, ValidationFinding,
    render_summary, validate_file, validate_str, write_str_atomic,
};
use kryprobe_testkit::assert_golden;
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/session-v0.jsonl")
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/goldens")
        .join(name)
}

fn observation(
    id: u64,
    backend: BackendId,
    phase: EvidencePhase,
    result: NativeResult,
    started: Option<u64>,
    ended: Option<u64>,
) -> NativeObservation {
    NativeObservation {
        id: ObservationId::new(id),
        backend,
        target: Some(TargetId::new(7)),
        object: None,
        implementation: Some(ImplementationId::new(3)),
        phase,
        call_kind: CallKind::Operation,
        operation_class: OperationClass::Sign,
        native_name: None,
        native_code: None,
        native_result: result,
        started_ns: started,
        ended_ns: ended,
        correlation: None,
        integrity: IntegrityRef::new(1),
        backend_payload: serde_json::Value::Null,
    }
}

fn scripted_stream() -> String {
    let mut writer = JsonlWriter::new("session:demo");
    writer
        .session_start(&SessionStart {
            target_selector: TargetSelector::OwnedRun,
            capture_mode: CaptureMode::Trace,
            requested_backends: vec![BackendId::P11, BackendId::OpenSsl],
            qualification_id: "qualification:synthetic-example".to_owned(),
        })
        .expect("start");
    let extra = ObservationExtra {
        boundary: "module_callback".to_owned(),
        native_operation: "C_Sign".to_owned(),
        algorithm_native: Some("CKM_RSA_PKCS_PSS".to_owned()),
        algorithm_canonical: Some("rsa-pss".to_owned()),
        algorithm_resolution: "exact".to_owned(),
    };
    writer
        .observation(
            &observation(
                11,
                BackendId::P11,
                EvidencePhase::Returned,
                NativeResult::P11 { rv: 0 },
                Some(100),
                Some(1050),
            ),
            &extra,
        )
        .expect("p11 observation");
    let ossl_extra = ObservationExtra {
        boundary: "provider_callback".to_owned(),
        native_operation: "signature_sign".to_owned(),
        algorithm_native: Some("RSA-PSS".to_owned()),
        algorithm_canonical: Some("rsa-pss".to_owned()),
        algorithm_resolution: "exact".to_owned(),
    };
    writer
        .observation(
            &observation(
                12,
                BackendId::OpenSsl,
                EvidencePhase::Entered,
                NativeResult::OpenSsl { code: 0 },
                Some(1100),
                None,
            ),
            &ossl_extra,
        )
        .expect("openssl observation");
    writer
        .coverage(&CoverageGap {
            target: Some("target:7".to_owned()),
            backend: "openssl".to_owned(),
            dimension: "attachment".to_owned(),
            reason: "callback_discovery_window".to_owned(),
            begin_ns: 0,
            end_ns: Some(50),
            impact: "partial".to_owned(),
            omitted_count: None,
        })
        .expect("gap");
    writer
        .integrity(
            &SnapshotParams {
                target: Some("target:7".to_owned()),
                backend: BackendId::P11,
                implementation: Some("implementation:3".to_owned()),
                unit: SnapshotUnit::SuccessfulOperations,
                count: 1,
                begin_ns: 50,
                end_ns: 1500,
                final_snapshot: true,
                barrier: SnapshotBarrier::Validated,
            },
            &IntegritySummary::default(),
        )
        .expect("snapshot");
    writer
        .relationship(
            &RelationshipRecord {
                id: CorrelationId::new(9),
                kind: RelationshipKind::SynchronousNestedExecution,
                parent: ObservationId::new(12),
                child: ObservationId::new(11),
                confidence: RelationshipConfidence::Qualified,
                evidence: vec![
                    RelationshipEvidence::SameProcessGeneration,
                    RelationshipEvidence::SameExecutionContext,
                    RelationshipEvidence::SharedCorrelationFrame,
                    RelationshipEvidence::ValidNestingState,
                    RelationshipEvidence::ValidPlanGenerations,
                    RelationshipEvidence::NoNonlocalExitBreak,
                    RelationshipEvidence::IndependentlyValidObservations,
                ],
                limitations: vec![],
            },
            "rule:synthetic-sync-sign",
        )
        .expect("relationship");
    writer
        .session_end(&SessionEnd {
            verdict: SessionVerdict::Partial,
            final_barrier: FinalBarrier::Validated,
            unresolved_gap_ids: vec!["record:4".to_owned()],
            child_exit_code: Some(0),
            child_signal: None,
        })
        .expect("end");
    writer.finish().to_owned()
}

#[test]
fn writer_golden_case() {
    let stream = scripted_stream();
    assert_golden(&golden_path("writer_v0.jsonl"), stream.as_bytes());
    // The writer's own output must validate with zero findings.
    let schema = include_bytes!("../../../schemas/event-v0.schema.json");
    assert!(validate_str(&stream, schema).is_empty());
}

#[test]
fn render_golden_case() {
    let stream = scripted_stream();
    let summary = render_summary(&stream);
    assert_golden(&golden_path("summary_v0.txt"), summary.as_bytes());
    assert_no_bare_zero(&summary);
}

#[test]
fn pack_fixture_validates_clean_case() {
    let path = fixture_path();
    assert!(path.is_file(), "missing pack fixture at {}", path.display());
    let findings = validate_file(&path);
    assert!(findings.is_empty(), "pack fixture findings: {findings:?}");
}

#[test]
fn schema_freeze_case() {
    // The frozen schema bytes are pinned: any edit must update this pin
    // deliberately (see `cargo xtask verify generated`).
    assert_eq!(kryprobe_report::schema_fnv1a_hex(), "497094a00e27a588");
}

#[test]
fn system_selector_session_start_validates_clean_case() {
    // The select-all scope spells `system` in session_start and the
    // report path accepts it: writer emits it, validation stays clean.
    let mut writer = JsonlWriter::new("session:system");
    writer
        .session_start(&SessionStart {
            target_selector: TargetSelector::System,
            capture_mode: CaptureMode::Profile,
            requested_backends: vec![BackendId::KCrypto],
            qualification_id: "qualification:system".to_owned(),
        })
        .expect("start");
    writer
        .session_end(&SessionEnd {
            verdict: SessionVerdict::Observed,
            final_barrier: FinalBarrier::Validated,
            unresolved_gap_ids: vec![],
            child_exit_code: None,
            child_signal: None,
        })
        .expect("end");
    let stream = writer.finish().to_owned();
    assert!(
        stream.contains("\"target_selector\":\"system\""),
        "{stream}"
    );
    let schema = include_bytes!("../../../schemas/event-v0.schema.json");
    assert!(validate_str(&stream, schema).is_empty());
}

#[test]
fn tamper_clock_case() {
    let mut lines: Vec<serde_json::Value> = scripted_stream()
        .lines()
        .map(|line| line.parse().expect("writer JSON"))
        .collect();
    let last = lines.len() - 1;
    lines[last]["monotonic_ns"] = serde_json::Value::String("5".to_owned());
    let text = lines
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let schema = include_bytes!("../../../schemas/event-v0.schema.json");
    let findings = validate_str(&text, schema);
    assert!(
        findings.iter().any(|f| matches!(
            f,
            ValidationFinding::Stream(kryprobe_testkit::StreamFinding::ClockWentBackwards { .. })
        )),
        "clock tamper must flag, got {findings:?}"
    );
}

#[test]
fn tamper_key_case() {
    let text = scripted_stream().replacen("\"payload\"", "\"dropped\"", 1);
    let schema = include_bytes!("../../../schemas/event-v0.schema.json");
    let findings = validate_str(&text, schema);
    assert!(
        findings.iter().any(|f| matches!(
            f,
            ValidationFinding::Stream(kryprobe_testkit::StreamFinding::MissingKey { .. })
        )),
        "dropped key must flag, got {findings:?}"
    );
}

#[test]
fn tamper_schema_value_case() {
    let text = scripted_stream().replacen("kryprobe.event/v0", "kryprobe.event/v9", 1);
    let schema = include_bytes!("../../../schemas/event-v0.schema.json");
    let findings = validate_str(&text, schema);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, ValidationFinding::SchemaMismatch { line: 1, .. })),
        "schema-value tamper must flag, got {findings:?}"
    );
}

#[test]
fn tamper_drift_case() {
    let stream = scripted_stream();
    let findings = validate_str(&stream, b"{\"edited\": true}");
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, ValidationFinding::SchemaDrift { .. })),
        "edited schema copy must flag drift, got {findings:?}"
    );
}

/// R-024: no standalone `0` token unless the line carries its qualifying
/// interval (`during`) and coverage (`; <dimension>: <status>`) suffix.
fn assert_no_bare_zero(text: &str) {
    for line in text.lines() {
        if has_standalone_zero(line) {
            assert!(
                line.contains("during") && line.contains(';'),
                "bare zero without interval+coverage suffix: {line}"
            );
        }
    }
}

fn has_standalone_zero(line: &str) -> bool {
    let bytes = line.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte != b'0' {
            continue;
        }
        let prev_digit = i > 0 && bytes[i - 1].is_ascii_digit();
        let next_digit = i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit();
        if !prev_digit && !next_digit {
            return true;
        }
    }
    false
}

#[test]
fn zero_wording_scan_case() {
    // Every zero-bearing branch must qualify its zeros.
    assert_no_bare_zero(&render_summary(""));
    assert_no_bare_zero(&render_summary("\n  \n"));
    // Writer stream minus observations: all phases zero, no gaps, no snapshots.
    let mut writer = JsonlWriter::new("session:empty");
    writer
        .session_start(&SessionStart {
            target_selector: TargetSelector::Pid,
            capture_mode: CaptureMode::Inventory,
            requested_backends: vec![BackendId::KCrypto],
            qualification_id: "qualification:empty".to_owned(),
        })
        .expect("start");
    writer
        .session_end(&SessionEnd {
            verdict: SessionVerdict::Observed,
            final_barrier: FinalBarrier::Validated,
            unresolved_gap_ids: vec![],
            child_exit_code: None,
            child_signal: None,
        })
        .expect("end");
    let summary = render_summary(writer.finish());
    assert_no_bare_zero(&summary);
    assert!(summary.contains("no entered-phase operations observed during"));
    // Lossy snapshot: nonzero counters still qualify.
    let lossy = IntegritySummary {
        ring_reservation_failures: 3,
        ..IntegritySummary::default()
    };
    let mut writer = JsonlWriter::new("session:lossy");
    writer
        .session_start(&SessionStart {
            target_selector: TargetSelector::OwnedRun,
            capture_mode: CaptureMode::Profile,
            requested_backends: vec![BackendId::P11],
            qualification_id: "qualification:lossy".to_owned(),
        })
        .expect("start");
    writer
        .integrity(
            &SnapshotParams {
                target: None,
                backend: BackendId::P11,
                implementation: None,
                unit: SnapshotUnit::ApiCalls,
                count: 10,
                begin_ns: 0,
                end_ns: 900,
                final_snapshot: false,
                barrier: SnapshotBarrier::NotFinal,
            },
            &lossy,
        )
        .expect("snapshot");
    assert_no_bare_zero(&render_summary(writer.finish()));
}

#[test]
fn writer_rejects_synthetic_case() {
    let mut writer = JsonlWriter::new("session:rej");
    let err = writer
        .session_start(&SessionStart {
            target_selector: TargetSelector::OwnedRun,
            capture_mode: CaptureMode::Trace,
            requested_backends: vec![BackendId::Synthetic],
            qualification_id: "q".to_owned(),
        })
        .unwrap_err();
    assert!(matches!(err, ReportError::SyntheticBackend));
    let err = writer
        .observation(
            &observation(
                1,
                BackendId::Synthetic,
                EvidencePhase::Returned,
                NativeResult::Synthetic { code: 0 },
                Some(0),
                Some(1),
            ),
            &ObservationExtra {
                boundary: "api".to_owned(),
                native_operation: "op".to_owned(),
                algorithm_native: None,
                algorithm_canonical: None,
                algorithm_resolution: "unknown".to_owned(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, ReportError::SyntheticBackend));
    // The driver test double's exact shape (P11 backend, Synthetic
    // result) refuses too: test-only `synthetic` must never reach
    // `native_namespace`.
    let err = writer
        .observation(
            &observation(
                2,
                BackendId::P11,
                EvidencePhase::Returned,
                NativeResult::Synthetic { code: 0 },
                Some(0),
                Some(1),
            ),
            &ObservationExtra {
                boundary: "api".to_owned(),
                native_operation: "op".to_owned(),
                algorithm_native: None,
                algorithm_canonical: None,
                algorithm_resolution: "unknown".to_owned(),
            },
        )
        .unwrap_err();
    assert_eq!(err, ReportError::SyntheticResult);
    assert_eq!(
        err.to_string(),
        "synthetic native result has no wire spelling"
    );
}

#[test]
fn writer_rejects_succeeded_case() {
    let mut writer = JsonlWriter::new("session:rej");
    let err = writer
        .observation(
            &observation(
                1,
                BackendId::P11,
                EvidencePhase::Succeeded,
                NativeResult::P11 { rv: 0 },
                Some(0),
                Some(1),
            ),
            &ObservationExtra {
                boundary: "api".to_owned(),
                native_operation: "op".to_owned(),
                algorithm_native: None,
                algorithm_canonical: None,
                algorithm_resolution: "unknown".to_owned(),
            },
        )
        .unwrap_err();
    assert!(matches!(err, ReportError::SucceededPhase));
}

#[test]
fn writer_rejects_bad_exit_case() {
    let mut writer = JsonlWriter::new("session:rej");
    let end = SessionEnd {
        verdict: SessionVerdict::Failed,
        final_barrier: FinalBarrier::Missing,
        unresolved_gap_ids: vec![],
        child_exit_code: Some(300),
        child_signal: None,
    };
    assert!(matches!(
        writer.session_end(&end).unwrap_err(),
        ReportError::ExitCodeOutOfRange(300)
    ));
    let end = SessionEnd {
        verdict: SessionVerdict::Failed,
        final_barrier: FinalBarrier::Missing,
        unresolved_gap_ids: vec![],
        child_exit_code: None,
        child_signal: Some(0),
    };
    assert!(matches!(
        writer.session_end(&end).unwrap_err(),
        ReportError::SignalOutOfRange(0)
    ));
}

#[test]
fn coverage_from_dimension_cases() {
    use kryprobe_report::CoverageGap as Gap;
    let interval = ValidityInterval {
        start_ns: 0,
        end_ns: Some(50),
    };
    let ctx = kryprobe_report::GapCtx {
        dimension: "attachment".to_owned(),
        target: Some("target:7".to_owned()),
        backend: "openssl".to_owned(),
        reason: "callback_discovery_window".to_owned(),
        omitted_count: None,
    };
    let complete = DimensionCoverage::new(CoverageStatus::CompleteForDeclaredBoundary, interval);
    assert!(Gap::from_dimension(&ctx, &complete).is_none());
    let partial = DimensionCoverage::new(CoverageStatus::Partial, interval);
    let gap = Gap::from_dimension(&ctx, &partial).expect("partial yields a gap");
    assert_eq!(gap.impact, "partial");
    assert_eq!(gap.begin_ns, 0);
    assert_eq!(gap.end_ns, Some(50));
    let unsupported = DimensionCoverage::new(CoverageStatus::Unsupported, interval);
    let gap = Gap::from_dimension(&ctx, &unsupported).expect("unsupported yields a gap");
    assert_eq!(gap.impact, "unsupported");
}

#[test]
fn atomic_write_roundtrip_case() {
    let dir = std::env::temp_dir().join(format!("kryprobe-report-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("out.jsonl");
    let mut writer = JsonlWriter::new("session:file");
    writer
        .session_start(&SessionStart {
            target_selector: TargetSelector::OwnedRun,
            capture_mode: CaptureMode::Trace,
            requested_backends: vec![BackendId::P11],
            qualification_id: "q".to_owned(),
        })
        .expect("start");
    writer.write_file_atomic(&path).expect("atomic write");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read back"),
        writer.finish()
    );
    // Overwrite is atomic too: second write replaces fully.
    let second = JsonlWriter::new("session:second");
    second.write_file_atomic(&path).expect("rewrite");
    assert_eq!(std::fs::read_to_string(&path).expect("read back"), "");
    assert!(validate_file(&path).is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn failed_atomic_commit_leaves_no_tmp_litter() {
    let dir = std::env::temp_dir().join(format!("kryprobe-report-fail-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    // Renaming a file onto a directory fails: the commit errors and must
    // still remove its temp file (best-effort cleanup).
    let target = dir.join("adir");
    std::fs::create_dir_all(&target).expect("target dir");
    let err = write_str_atomic(&target, "torn?\n").expect_err("rename onto dir must fail");
    assert!(
        format!("{err:?}").contains("rename to"),
        "unexpected error: {err:?}"
    );
    let litter: Vec<_> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| name.to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(litter.is_empty(), "tmp litter: {litter:?}");
    assert!(target.is_dir(), "target dir must survive");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn core_gap_types_referenced() {
    // Compile-pin the core evidence types the writer consumes.
    let summary = CoverageSummary {
        target_population: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
        object_discovery: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
        attachment: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
        aggregate_counts: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
        detailed_events: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
        attribution: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
        correlation: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
        completion: DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        ),
    };
    assert!(summary.weaker_dimensions().is_empty());
    assert_eq!(OmissionId::new(1).to_string(), "omission:1");
    assert_eq!(SessionId::new(1).to_string(), "session:1");
}
