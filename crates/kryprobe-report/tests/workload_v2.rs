// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2A frozen v2 fixtures: the eight shared examples consumed by
//! Stage 2B/2C/2D and later installed tests. Every fixture validates clean
//! under `workload_v2` and carries its scenario's exact frozen values.

use kryprobe_report::validate::workload_v2;
use std::path::PathBuf;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/workload-v2")
        .join(name)
}

fn load_fixture(name: &str) -> serde_json::Value {
    let bytes = std::fs::read(fixture_path(name)).expect("fixture present");
    workload_v2::validate_bytes(&bytes).expect("fixture validates clean");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

#[test]
fn all_frozen_fixtures_validate_clean() {
    for name in [
        "complete-raw-ids.json",
        "asserted-metadata.json",
        "unknown-context.json",
        "unknown-match.json",
        "full-map.json",
        "stale-metadata.json",
        "partial-capture.json",
        "matching-violation.json",
    ] {
        let bytes = std::fs::read(fixture_path(name)).expect("fixture present");
        assert!(
            workload_v2::validate_bytes(&bytes).is_ok(),
            "{name} must validate clean"
        );
    }
}

#[test]
fn complete_raw_ids_carry_no_workload() {
    let v = load_fixture("complete-raw-ids.json");
    assert_eq!(v["ledger"]["unknown"], "0");
    for row in v["contexts"].as_array().expect("rows") {
        assert!(row.get("workload").is_none());
        assert!(row.get("attribution").is_none());
    }
    assert_eq!(v["metadata"]["status"], "unavailable");
}

#[test]
fn asserted_metadata_freezes_two_container_bindings() {
    let v = load_fixture("asserted-metadata.json");
    let rows = v["contexts"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    let ids: Vec<&str> = rows
        .iter()
        .map(|r| r["workload"]["container"]["id"].as_str().expect("id"))
        .collect();
    assert_ne!(ids[0], ids[1]);
    for row in rows {
        assert_eq!(row["attribution"]["status"], "asserted");
    }
    assert_eq!(v["scope"]["group_by"], "container");
}

#[test]
fn unknown_context_keeps_explicit_unknown_populations() {
    let v = load_fixture("unknown-context.json");
    let rows = v["contexts"].as_array().expect("rows");
    assert!(rows.iter().any(|r| r["cgroup_id"] == "0"));
    assert!(rows.iter().any(|r| r["start_ns"] == "0"));
    assert_eq!(v["ledger"]["unknown"], "10");
    assert_eq!(v["coverage"]["capture"], "partial");
}

#[test]
fn unknown_match_stays_separate_from_match() {
    let v = load_fixture("unknown-match.json");
    assert_eq!(v["partition"]["matched"], "20");
    assert_eq!(v["partition"]["nonmatched"], "20");
    assert_eq!(v["partition"]["unknown_match"], "10");
    assert_eq!(v["selectors"]["kind"], "cgroup-id");
    assert_eq!(v["scope"]["report_scope"], "scoped");
}

#[test]
fn full_map_shows_refuse_new_loss() {
    let v = load_fixture("full-map.json");
    assert_eq!(v["ledger"]["unknown"], "60");
    assert_eq!(v["ledger"]["refused_inserts"], "60");
    assert_eq!(v["coverage"]["capture"], "partial");
}

#[test]
fn stale_metadata_keeps_identity_with_stale_status() {
    let v = load_fixture("stale-metadata.json");
    let row = &v["contexts"][0];
    assert_eq!(row["attribution"]["status"], "stale");
    assert!(row["workload"]["container"]["id"].is_string());
    assert_eq!(v["coverage"]["metadata"], "partial");
}

#[test]
fn partial_capture_exports_gap_not_unknown() {
    let v = load_fixture("partial-capture.json");
    assert_eq!(v["interval"]["consistency"], "unproven");
    assert_eq!(v["ledger"]["unknown"], "0");
    assert_eq!(v["ledger"]["gap_unreconciled"], true);
}

#[test]
fn matching_violation_binds_selector_to_forbidden_row() {
    let v = load_fixture("matching-violation.json");
    assert_eq!(v["partition"]["matched"], "20");
    assert_eq!(v["partition"]["unknown_match"], "0");
    let selector_id = v["selectors"]["container"]["id"].as_str().expect("id");
    let row = &v["contexts"][0];
    assert_eq!(row["workload"]["container"]["id"], selector_id);
    let dict_id = row["native_ref"].as_str().expect("ref");
    let entry = v["dictionary"]
        .as_array()
        .expect("dict")
        .iter()
        .find(|e| e["dict_id"] == dict_id)
        .expect("entry resolves");
    assert_eq!(entry["algorithm"], "ecb(des)");
}

#[test]
fn fixtures_use_native_context_codes_and_ordered_starts() {
    // Round-2: native context codes are proc=0, kthread=1 (softirq=2 is
    // reserved, never emitted); process starts never exceed the capture
    // end.
    for name in [
        "complete-raw-ids.json",
        "asserted-metadata.json",
        "unknown-context.json",
        "unknown-match.json",
        "full-map.json",
        "stale-metadata.json",
        "partial-capture.json",
        "matching-violation.json",
    ] {
        let v = load_fixture(name);
        let end: u64 = v["interval"]["end_ns"]
            .as_str()
            .expect("interval end")
            .parse()
            .expect("u64 end");
        let dict = v["dictionary"].as_array().expect("dictionary");
        for row in v["contexts"].as_array().expect("rows") {
            let start: u64 = row["start_ns"]
                .as_str()
                .expect("start")
                .parse()
                .expect("u64 start");
            assert!(
                start <= end,
                "{name}: process start {start} exceeds capture end {end}"
            );
            let expected = match row["execution_kind"].as_str().expect("kind") {
                "proc" => 0,
                "kthread" => 1,
                kind => panic!("{name}: unexpected execution kind {kind}"),
            };
            let code = if let Some(native) = row.get("native") {
                native["context"].as_u64().expect("inline context")
            } else {
                let id = row["native_ref"].as_str().expect("native_ref");
                dict.iter()
                    .find(|e| e["dict_id"] == id)
                    .expect("entry resolves")["context"]
                    .as_u64()
                    .expect("dict context")
            };
            assert_eq!(
                code, expected,
                "{name}: native context code must match the row kind"
            );
        }
    }
}

#[test]
fn v1_bytes_are_not_v2() {
    assert!(workload_v2::dispatch_schema("kryprobe.workload-report.v1").is_err());
    assert!(workload_v2::dispatch_schema("kryprobe.event/v0").is_err());
}
