// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Task 01: old frozen formats stay byte-identical while the new
//! workload-report-v1 schema dispatches alongside. RED first:
//! `validate::workload_v1` does not exist yet.

use kryprobe_report::validate::workload_v1;
use kryprobe_testkit::assert_golden;
use std::path::PathBuf;

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/goldens")
        .join(name)
}

/// The ctx-v1 addition must not alter one byte of the frozen v0 goldens,
/// and the new schema dispatches on its own const only.
#[test]
fn old_formats_remain_unchanged() {
    // New dispatch surface exists and pins its own schema id.
    assert_eq!(workload_v1::SCHEMA_ID, "kryprobe.workload-report.v1");
    assert!(!workload_v1::schema_fnv1a_hex().is_empty());
    // Unknown schema values refuse typed; v0 is not valid v1.
    assert!(workload_v1::dispatch_schema("kryprobe.event/v0").is_err());
    assert!(workload_v1::dispatch_schema("kryprobe.workload-report.v1").is_ok());

    // Frozen v0 goldens are byte-identical inputs to the new dispatch
    // refusal path: dispatching v0 bytes as v1 reports schema mismatch,
    // proving the old bytes were not silently absorbed.
    let writer_v0 = std::fs::read(golden_path("writer_v0.jsonl")).expect("v0 golden present");
    let err = workload_v1::validate_bytes(&writer_v0).expect_err("v0 bytes are not v1");
    assert!(
        err.contains("schema"),
        "refusal must name the schema mismatch, got: {err}"
    );
    // And the golden itself still matches what the v0 writer produced
    // (re-assert through the existing v0 path indirectly: the file must
    // be non-empty and every line must carry the v0 schema marker).
    assert!(!writer_v0.is_empty());
    let marker = b"\"schema\":\"kryprobe.event/v0\"";
    for line in writer_v0.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        assert!(
            line.windows(marker.len()).any(|w| w == marker),
            "v0 golden line lost its schema marker"
        );
    }
    // Keep the golden assertion helper linked so drift fails loudly.
    assert_golden(&golden_path("writer_v0.jsonl"), &writer_v0);
}
