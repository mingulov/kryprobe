// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Task 01 (+ Stage 2A tightening): old frozen formats stay
//! byte-identical while the new workload-report schemas dispatch
//! alongside.

use kryprobe_report::validate::{validate_str, workload_v1, workload_v2};
use std::path::PathBuf;

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/goldens")
        .join(name)
}

/// The ctx-v1 addition must not alter one byte of the frozen v0 goldens,
/// and each new schema dispatches on its own const only.
///
/// The writer-output-vs-golden byte comparison lives in
/// `report_golden.rs::writer_golden_case` (actual `JsonlWriter` output
/// against the fixed golden). This test proves the complementary
/// direction (D13): the frozen golden still validates clean through the
/// REAL v0 validator, still carries its schema marker on every line, and
/// still refuses as v1/v2 — never silently absorbed by the new schemas.
#[test]
fn old_formats_remain_unchanged() {
    // New dispatch surfaces exist and pin their own schema ids.
    assert_eq!(workload_v1::SCHEMA_ID, "kryprobe.workload-report.v1");
    assert_eq!(
        workload_v1::schema_fnv1a_hex(),
        workload_v1::WORKLOAD_V1_SCHEMA_FNV1A
    );
    assert_eq!(workload_v2::SCHEMA_ID, "kryprobe.workload-report.v2");
    assert_eq!(
        workload_v2::schema_fnv1a_hex(),
        workload_v2::WORKLOAD_V2_SCHEMA_FNV1A
    );
    // Unknown schema values refuse typed; v0 is neither valid v1 nor v2.
    assert!(workload_v1::dispatch_schema("kryprobe.event/v0").is_err());
    assert!(workload_v1::dispatch_schema("kryprobe.workload-report.v1").is_ok());
    assert!(workload_v2::dispatch_schema("kryprobe.event/v0").is_err());
    assert!(workload_v2::dispatch_schema("kryprobe.workload-report.v2").is_ok());

    // The frozen v0 golden validates clean through the real v0 path.
    let writer_v0 = std::fs::read(golden_path("writer_v0.jsonl")).expect("v0 golden present");
    assert!(!writer_v0.is_empty());
    let stream = std::str::from_utf8(&writer_v0).expect("v0 golden is UTF-8");
    let schema = include_bytes!("../../../schemas/event-v0.schema.json");
    let v0_findings = validate_str(stream, schema);
    assert!(
        v0_findings.is_empty(),
        "v0 golden must validate clean under v0: {v0_findings:?}"
    );

    // Frozen v0 goldens are byte-identical inputs to the new dispatch
    // refusal paths: dispatching v0 bytes as v1/v2 reports schema
    // mismatch, proving the old bytes were not silently absorbed.
    let err = workload_v1::validate_bytes(&writer_v0).expect_err("v0 bytes are not v1");
    assert!(
        err.contains("schema"),
        "refusal must name the schema mismatch, got: {err}"
    );
    let err = workload_v2::validate_bytes(&writer_v0).expect_err("v0 bytes are not v2");
    assert!(
        err.contains("schema"),
        "refusal must name the schema mismatch, got: {err}"
    );

    // And every golden line still carries the v0 schema marker.
    let marker = b"\"schema\":\"kryprobe.event/v0\"";
    for line in writer_v0.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        assert!(
            line.windows(marker.len()).any(|w| w == marker),
            "v0 golden line lost its schema marker"
        );
    }
}
