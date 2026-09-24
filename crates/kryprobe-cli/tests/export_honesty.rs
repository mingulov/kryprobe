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
    let obs = decode_agg(agg_spec(KRES_ERR, 5, 0, 5));
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
        let obs = decode_agg(agg_spec(result, 4, ok, errors));
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
    let obs = decode_agg(agg_spec(KRES_ERR, 50, 0, 50));
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

/// F01: totals carriers keep counts without completion claims.
#[test]
fn totals_export_counts_without_completion() {
    let obs = decode_totals(30);
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
            .expect("renders");
    let records = export_records(&text);
    let payload = &observations_of(&records)[0]["payload"];
    assert_eq!(payload["boundary"], "api");
    assert_eq!(payload["phase"], "returned");
    assert!(payload["duration_ns"].is_null());
}

/// F02: unknown delivery/completion export as gap records and the end
/// record references them; nothing structural is lost.
#[test]
fn unknown_coverage_exports_gaps_and_references() {
    let obs = decode_agg(agg_spec(KRES_ERR, 5, 0, 5));
    let text =
        kryprobe_report::live_render::render_live_jsonl(&[obs], &live_like_coverage(), false)
            .expect("renders");
    let records = export_records(&text);
    let gaps: Vec<&serde_json::Value> = records
        .iter()
        .filter(|rec| rec["kind"] == "coverage_gap")
        .collect();
    assert!(
        gaps.len() >= 3,
        "aggregate, transport, and continuity gaps: {text}"
    );
    let dims: Vec<&str> = gaps
        .iter()
        .map(|gap| gap["payload"]["dimension"].as_str().expect("dim"))
        .collect();
    for dim in [
        "aggregate_counts",
        "event_transport",
        "observation_continuity",
    ] {
        assert!(dims.contains(&dim), "gap for {dim}: {dims:?}");
    }
    let end = records
        .iter()
        .find(|rec| rec["kind"] == "session_end")
        .expect("end");
    assert_eq!(end["payload"]["verdict"], "PARTIAL");
    let unresolved = end["payload"]["unresolved_gap_ids"]
        .as_array()
        .expect("gap id list");
    assert_eq!(unresolved.len(), gaps.len(), "every gap referenced");
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
            !line.contains("complete;"),
            "replay must not claim {dim} complete: {line}"
        );
    }
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
