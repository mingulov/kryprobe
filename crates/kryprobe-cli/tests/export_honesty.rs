// SPDX-License-Identifier: GPL-3.0-or-later
//! R0 repair: F01/F02 export and replay honesty (api-returns).
//!
//! Decoder → supported export → `report FILE` replay must preserve
//! the T02 qualifiers: API-return boundary/unit, no per-request
//! latency, representative (not exact) errnos, no false completion,
//! and replayed coverage that never strengthens.

use kryprobe_abi::kcrypto_agg::{KCTX_PROC, KFAM_SK, KOP_ENC, KRES_ERR, KRES_OK, KRES_QUEUED};
use kryprobe_core::backend::{Backend, DecodeContext};
use kryprobe_core::enums::CoverageStatus;
use kryprobe_core::evidence::{CoverageSummary, NativeObservation};
use kryprobe_core::ids::{IdIssuer, PlanGeneration, SessionId};
use kryprobe_testkit::kcrypto_rows::{AggSpec, agg_row_bytes, totals_row_bytes};

fn decode_agg(bytes: Vec<u8>) -> NativeObservation {
    let backend = kryprobe_privilege::kcrypto_backend::KCryptoBackend::new();
    let row = kryprobe_privilege::kcrypto_snapshot::RowBytes::new(bytes).expect("hand row");
    let issuer = IdIssuer::default();
    let integrity = kryprobe_core::evidence::IntegritySummary::default();
    let ctx = DecodeContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        integrity: &integrity,
        id_issuer: &issuer,
    };
    backend
        .decode(
            &ctx,
            kryprobe_privilege::kcrypto_snapshot::raw_event_for_agg(&row),
        )
        .expect("hand row decodes")
}

fn decode_totals(calls: u64) -> NativeObservation {
    let backend = kryprobe_privilege::kcrypto_backend::KCryptoBackend::new();
    let totals =
        kryprobe_privilege::kcrypto_snapshot::TotalsBytes::new(totals_row_bytes(calls, 0, 0))
            .expect("hand totals");
    let issuer = IdIssuer::default();
    let integrity = kryprobe_core::evidence::IntegritySummary::default();
    let ctx = DecodeContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        integrity: &integrity,
        id_issuer: &issuer,
    };
    backend
        .decode(
            &ctx,
            kryprobe_privilege::kcrypto_snapshot::raw_event_for_totals(&totals),
        )
        .expect("hand totals decode")
}

fn agg_spec(result: u8, calls: u64, ok: u64, errors: u64) -> Vec<u8> {
    agg_row_bytes(AggSpec {
        family: KFAM_SK,
        op: KOP_ENC,
        result,
        ctx: KCTX_PROC,
        name: b"cbc(aes)",
        drv: b"aesni-intel",
        calls,
        bytes: 5120,
        ok,
        errors,
        queued: 0,
    })
}

/// Spread a decoded aggregate over a wide window (the review's
/// 100..1000ns counterexample shape): duration assertions must face
/// a real nonzero width, never a zero-window fixture.
fn with_wide_window(mut obs: NativeObservation) -> NativeObservation {
    obs.started_ns = Some(100);
    obs.ended_ns = Some(1000);
    assert_eq!(
        obs.ended_ns.unwrap() - obs.started_ns.unwrap(),
        900,
        "premise: wide aggregate window"
    );
    obs
}

fn dim_unknown() -> kryprobe_core::evidence::DimensionCoverage {
    kryprobe_core::evidence::DimensionCoverage::new(
        CoverageStatus::Unknown,
        kryprobe_core::evidence::ValidityInterval {
            start_ns: 0,
            end_ns: Some(2000),
        },
    )
}

fn dim_complete() -> kryprobe_core::evidence::DimensionCoverage {
    kryprobe_core::evidence::DimensionCoverage::new(
        CoverageStatus::CompleteForDeclaredBoundary,
        kryprobe_core::evidence::ValidityInterval {
            start_ns: 0,
            end_ns: Some(2000),
        },
    )
}

/// T02-shaped live coverage: internally clean, delivery and
/// completion unmeasured.
fn live_like_coverage() -> CoverageSummary {
    CoverageSummary {
        target_population: dim_complete(),
        object_discovery: dim_complete(),
        attachment: dim_complete(),
        aggregate_counts: dim_unknown(),
        detailed_events: dim_unknown(),
        attribution: dim_complete(),
        correlation: dim_complete(),
        completion: dim_unknown(),
    }
}

fn export_records(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .map(|line| serde_json::from_str(line).expect("valid JSONL"))
        .collect()
}

fn observations_of(records: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    records
        .iter()
        .filter(|rec| rec["kind"] == "operation_observation")
        .collect()
}

/// F01: an error-class API return exports as a return at the API
/// boundary — never a completed kernel execution with a measured
/// duration and an exact errno.
#[test]
fn error_return_exports_no_completion_latency_or_exact_errno() {
    let obs = with_wide_window(decode_agg(agg_spec(KRES_ERR, 5, 0, 5)));
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
            .expect("renders");
    let records = export_records(&text);
    let exported = observations_of(&records);
    assert_eq!(exported.len(), 1);
    let payload = &exported[0]["payload"];
    assert_eq!(payload["boundary"], "api");
    assert_eq!(payload["phase"], "returned");
    assert_eq!(payload["outcome"], "failure");
    assert!(
        payload["duration_ns"].is_null(),
        "no per-request latency from an aggregate window: {payload}"
    );
    assert!(
        payload["native_result"].is_null(),
        "representative class status is not an exact errno: {payload}"
    );
}

/// F01: ok and queued rows keep their class outcome and selected
/// driver without completion or latency claims.
#[test]
fn ok_and_queued_rows_export_class_without_completion() {
    for (result, outcome) in [(KRES_OK, "success"), (KRES_QUEUED, "pending")] {
        let (ok, errors) = if result == KRES_OK { (4, 0) } else { (0, 0) };
        let obs = with_wide_window(decode_agg(agg_spec(result, 4, ok, errors)));
        let text =
            kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
                .expect("renders");
        let records = export_records(&text);
        let exported = observations_of(&records);
        assert_eq!(exported.len(), 1);
        let payload = &exported[0]["payload"];
        assert_eq!(payload["boundary"], "api", "result {result}");
        assert_eq!(payload["phase"], "returned", "result {result}");
        assert_eq!(payload["outcome"], outcome, "result {result}");
        assert!(payload["duration_ns"].is_null(), "result {result}");
    }
}

/// F01: a wide aggregate window and an error with no native errno
/// still export no duration and no errno.
#[test]
fn wide_window_error_exports_no_duration_or_errno() {
    let obs = with_wide_window(decode_agg(agg_spec(KRES_ERR, 50, 0, 50)));
    assert!(obs.native_code.is_none(), "fixture has no native errno");
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
            .expect("renders");
    let records = export_records(&text);
    let payload = &observations_of(&records)[0]["payload"];
    assert_eq!(payload["phase"], "returned");
    assert!(payload["duration_ns"].is_null());
    assert!(payload["native_result"].is_null());
}

/// F01: totals carriers export as markers — returned at the API
/// boundary with no outcome, latency, or errno. (The frozen
/// operation record has no counts/row fields, so per-class counts
/// stay in decoder JSON and human tables; the export must not invent
/// an outcome for them instead.)
#[test]
fn totals_export_carrier_without_outcome_or_latency() {
    let obs = with_wide_window(decode_totals(30));
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
            .expect("renders");
    let records = export_records(&text);
    let payload = &observations_of(&records)[0]["payload"];
    assert_eq!(payload["boundary"], "api");
    assert_eq!(payload["phase"], "returned");
    assert_eq!(payload["outcome"], "not_applicable");
    assert!(payload["duration_ns"].is_null());
    assert!(payload["native_result"].is_null());
}

/// F02: unknown delivery/completion export as gap records and the end
/// record references exactly those records by id; the stream is
/// valid event-v0.
#[test]
fn unknown_coverage_exports_gaps_and_references() {
    let obs = decode_agg(agg_spec(KRES_ERR, 5, 0, 5));
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
            .expect("renders");
    assert_stream_valid(&text);
    let records = export_records(&text);
    let gaps: Vec<&serde_json::Value> = records
        .iter()
        .filter(|rec| rec["kind"] == "coverage_gap")
        .collect();
    assert_eq!(gaps.len(), 3, "exactly the weaker dims: {text}");
    let dims: Vec<&str> = gaps
        .iter()
        .map(|gap| gap["payload"]["dimension"].as_str().expect("dim"))
        .collect();
    assert_eq!(
        dims,
        [
            "aggregate_counts",
            "event_transport",
            "observation_continuity"
        ],
        "gap dims in dimension order"
    );
    let gap_ids: Vec<&str> = gaps
        .iter()
        .map(|gap| gap["record_id"].as_str().expect("gap record id"))
        .collect();
    assert_eq!(
        gap_ids,
        ["record:3", "record:4", "record:5"],
        "start is record:1, the observation record:2"
    );
    let end = records
        .iter()
        .find(|rec| rec["kind"] == "session_end")
        .expect("end");
    assert_eq!(end["payload"]["verdict"], "PARTIAL");
    let unresolved: Vec<&str> = end["payload"]["unresolved_gap_ids"]
        .as_array()
        .expect("gap id list")
        .iter()
        .map(|id| id.as_str().expect("gap id string"))
        .collect();
    assert_eq!(
        unresolved,
        ["record:3", "record:4", "record:5"],
        "end references exactly the emitted gaps"
    );
}

fn assert_stream_valid(text: &str) {
    let schema = kryprobe_report::resolve_schema();
    let schema_bytes = schema.bytes().expect("schema resolves");
    let findings = kryprobe_report::validate_str(text, schema_bytes);
    assert!(findings.is_empty(), "export validates: {findings:?}");
}

/// F02: capture → JSONL → `report FILE` never strengthens coverage.
#[test]
fn replay_never_strengthens_coverage() {
    let obs = decode_agg(agg_spec(KRES_ERR, 5, 0, 5));
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
            .expect("renders");
    let dir = kryprobe_testkit::TempDir::named("replay-roundtrip").expect("scratch");
    let file = dir.path().join("capture.jsonl");
    std::fs::write(&file, &text).expect("write");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kryprobe"))
        .args(["report", file.to_str().expect("utf-8")])
        .output()
        .expect("spawn kryprobe");
    assert!(
        output.status.success(),
        "report exits 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = String::from_utf8(output.stdout).expect("utf-8");
    // Unknown in, unknown out: replay must reproduce the input
    // weakness exactly — partial would already strengthen it.
    for dim in [
        "aggregate_counts",
        "event_transport",
        "observation_continuity",
    ] {
        let line = summary
            .lines()
            .find(|line| line.trim_start().starts_with(dim))
            .unwrap_or_else(|| panic!("{dim} line in:\n{summary}"));
        assert!(
            line.contains("unknown;"),
            "replay keeps {dim} unknown: {line}"
        );
    }
}

/// F02: an interrupted window forces PARTIAL with a continuity gap
/// even when every measured dimension held.
#[test]
fn interrupted_window_exports_continuity_gap_and_partial() {
    let obs = decode_agg(agg_spec(KRES_OK, 4, 4, 0));
    let complete = CoverageSummary {
        target_population: dim_complete(),
        object_discovery: dim_complete(),
        attachment: dim_complete(),
        aggregate_counts: dim_complete(),
        detailed_events: dim_complete(),
        attribution: dim_complete(),
        correlation: dim_complete(),
        completion: dim_complete(),
    };
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &complete, true).expect("renders");
    assert_stream_valid(&text);
    let records = export_records(&text);
    let gaps: Vec<&serde_json::Value> = records
        .iter()
        .filter(|rec| rec["kind"] == "coverage_gap")
        .collect();
    assert_eq!(gaps.len(), 1, "only the interruption gap: {text}");
    assert_eq!(gaps[0]["payload"]["dimension"], "observation_continuity");
    assert_eq!(gaps[0]["payload"]["reason"], "observer_interrupted");
    assert_eq!(gaps[0]["record_id"], "record:3");
    let end = records
        .iter()
        .find(|rec| rec["kind"] == "session_end")
        .expect("end");
    assert_eq!(end["payload"]["verdict"], "PARTIAL");
    let unresolved: Vec<&str> = end["payload"]["unresolved_gap_ids"]
        .as_array()
        .expect("gap id list")
        .iter()
        .map(|id| id.as_str().expect("gap id string"))
        .collect();
    assert_eq!(unresolved, ["record:3"]);
}

/// F02 positive control: a genuinely complete historical stream still
/// replays complete.
#[test]
fn complete_stream_replays_complete() {
    let text = concat!(
        "{\"schema\":\"kryprobe.event/v0\",\"kind\":\"session_start\",\"session_id\":\"s:1\",\"record_id\":\"record:1\",\"monotonic_ns\":\"0\",\"payload\":{\"target_selector\":\"system\",\"capture_mode\":\"trace\",\"requested_backends\":[\"kcrypto\"],\"contract_version\":\"v0-proposed\",\"qualification_id\":\"live\"}}\n",
        "{\"schema\":\"kryprobe.event/v0\",\"kind\":\"session_end\",\"session_id\":\"s:1\",\"record_id\":\"record:2\",\"monotonic_ns\":\"1000\",\"payload\":{\"verdict\":\"OBSERVED\",\"final_barrier\":\"validated\",\"unresolved_gap_ids\":[],\"child_exit_code\":null,\"child_signal\":null}}\n",
    );
    let dir = kryprobe_testkit::TempDir::named("replay-complete").expect("scratch");
    let file = dir.path().join("complete.jsonl");
    std::fs::write(&file, text).expect("write");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kryprobe"))
        .args(["report", file.to_str().expect("utf-8")])
        .output()
        .expect("spawn kryprobe");
    assert!(output.status.success());
    let summary = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        summary.contains("aggregate_counts: complete;"),
        "complete stays complete:\n{summary}"
    );
}

/// A real base-emitted import shell (retired `import` output, kept
/// as the report fixture) still replays clean through `report FILE`:
/// exit 0, one record, unknown kind structurally accepted.
#[test]
fn base_emitted_import_shell_replays_clean() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../kryprobe-report/tests/fixtures/import-shell-v1.jsonl");
    assert!(fixture.is_file(), "base-emitted fixture exists");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kryprobe"))
        .args(["report", fixture.to_str().expect("utf-8")])
        .output()
        .expect("spawn kryprobe");
    assert!(
        output.status.success(),
        "report exits 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        summary.contains("session session:import: 1 records"),
        "one historical record replays:\n{summary}"
    );
}
