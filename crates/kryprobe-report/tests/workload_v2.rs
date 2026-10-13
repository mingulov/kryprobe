// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2A frozen v2 fixtures: the eight shared examples consumed by
//! Stage 2B/2C/2D and later installed tests. Every fixture validates clean
//! under `workload_v2` and carries its scenario's exact frozen values.

use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, ContextIdentity, CountOperand, ExecutionKind,
    Relationship, ScopePartition, SnapshotConsistency, ValidityInterval, WorkloadIdentity,
    WorkloadOrigin,
};
use kryprobe_report::validate::workload_v2;
use kryprobe_report::workload::{
    AssemblyInput, CoverageLevel, GroupBy, MetadataAvailability, NativeIdentity, ReportCoverage,
    ReportRowInput, WorkloadSelector as ReportSelector, assemble, report_from_bytes,
};
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
fn asserted_fixture_bindings_cover_capture() {
    // Round-3: every Asserted/Verified fixture binding must cover the
    // counted capture interval it claims. Pins the asserted-metadata +
    // matching-violation window repair.
    for name in ["asserted-metadata.json", "matching-violation.json"] {
        let v = load_fixture(name);
        let start: u64 = v["interval"]["start_ns"]
            .as_str()
            .expect("interval start")
            .parse()
            .expect("u64 start");
        let end: u64 = v["interval"]["end_ns"]
            .as_str()
            .expect("interval end")
            .parse()
            .expect("u64 end");
        for row in v["contexts"].as_array().expect("rows") {
            let Some(attribution) = row.get("attribution") else {
                continue;
            };
            let status = attribution["status"].as_str().expect("status");
            assert!(
                matches!(status, "asserted" | "verified"),
                "{name}: expected an asserting status, got {status}"
            );
            let validity = attribution.get("validity").expect("validity present");
            let vs: u64 = validity["start_ns"]
                .as_str()
                .expect("validity start")
                .parse()
                .expect("u64 validity start");
            let ve: u64 = validity["end_ns"]
                .as_str()
                .expect("validity end")
                .parse()
                .expect("u64 validity end");
            assert!(
                vs <= start && end <= ve,
                "{name}: validity [{vs},{ve}] must cover capture [{start},{end}]"
            );
        }
    }
}

#[test]
fn v1_bytes_are_not_v2() {
    assert!(workload_v2::dispatch_schema("kryprobe.workload-report.v1").is_err());
    assert!(workload_v2::dispatch_schema("kryprobe.event/v0").is_err());
}

// ---------------------------------------------------------------------------
// F04 shared replay invariants (SEM01/SEM02)
// ---------------------------------------------------------------------------

const F04_SESSION: &str = "0123456789abcdef0123456789abcdef";
const F04_ID_A: &str = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
const F04_RUNTIME: &str = "docker://host-a";

fn f04_native() -> NativeIdentity {
    NativeIdentity::new(1, 2, 0, 0, "cbc(aes)", Some("cbc-aes-aesni"))
}

fn f04_row(
    cgroup: u64,
    tgid: u32,
    start_ns: u64,
    calls: u64,
    identity: WorkloadIdentity,
    evidence: AttributionEvidence,
) -> ReportRowInput {
    ReportRowInput {
        context: ContextIdentity::new(7, cgroup, tgid, 1000, start_ns, ExecutionKind::Proc),
        calls,
        native: f04_native(),
        identity,
        evidence,
    }
}

fn f04_unresolved() -> (WorkloadIdentity, AttributionEvidence) {
    (
        WorkloadIdentity::none(),
        AttributionEvidence::unresolved(Relationship::HookContext),
    )
}

fn f04_assembly_input(
    rows: Vec<ReportRowInput>,
    observed: u64,
    partition: ScopePartition,
    selector: ReportSelector,
) -> AssemblyInput {
    AssemblyInput {
        session_id: F04_SESSION.to_string(),
        kernel_identity: "7.0.0-38-generic/boot-A".to_string(),
        interval_start_ns: 100,
        interval_end_ns: 1000,
        consistency: SnapshotConsistency::Quiescent,
        profile: "api-returns".to_string(),
        system_total: CountOperand {
            value: observed,
            saturated: false,
            population: "global".to_string(),
        },
        per_context_saturated: false,
        refused_inserts: 0,
        rows,
        partition,
        selector,
        group_by: GroupBy::None,
        metadata: MetadataAvailability::Available,
        coverage: ReportCoverage {
            capture: CoverageLevel::Complete,
            attribution: CoverageLevel::Complete,
            metadata: CoverageLevel::Complete,
            correlation: CoverageLevel::Complete,
        },
    }
}

fn f04_scoped_rows() -> Vec<ReportRowInput> {
    let (id0, ev0) = f04_unresolved();
    let (id1, ev1) = f04_unresolved();
    let (id2, ev2) = f04_unresolved();
    vec![
        f04_row(43812, 1000, 555, 20, id0, ev0),
        f04_row(43813, 1001, 556, 20, id1, ev1),
        f04_row(0, 1002, 557, 10, id2, ev2),
    ]
}

fn f04_partition(matched: u64, nonmatched: u64, unknown: u64) -> ScopePartition {
    ScopePartition::from_counts(matched, nonmatched, unknown).expect("valid counts")
}

/// SEM01: conservation is not selection. Rows (43812,20),(43813,20),
/// (0,10) under selector 999 derive 0/40/10 — a stored 50/0/0 that
/// merely conserves the total refuses at validation, decode, and
/// assembly alike; the derived buckets pass. The second selector case
/// (43812) pins the same rule against the frozen fixture shape.
#[test]
fn scoped_partition_conservation_is_not_selection() {
    let hostile = |cgroup: &str, matched: &str, nonmatched: &str, unknown: &str| {
        let bytes = std::fs::read(fixture_path("unknown-match.json")).expect("fixture present");
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture parses");
        v["selectors"]["cgroup_id"] = serde_json::json!(cgroup);
        v["partition"]["matched"] = serde_json::json!(matched);
        v["partition"]["nonmatched"] = serde_json::json!(nonmatched);
        v["partition"]["unknown_match"] = serde_json::json!(unknown);
        v
    };
    // Case 1: selector 999 claims 50/0/0 although it derives 0/40/10.
    let v = hostile("999", "50", "0", "0");
    assert!(
        !workload_v2::validate_workload_v2(&v).is_empty(),
        "selector-999 50/0/0 refuses at validation"
    );
    assert!(
        report_from_bytes(&serde_json::to_vec(&v).expect("encodes")).is_err(),
        "selector-999 50/0/0 refuses at decode"
    );
    assert!(
        assemble(f04_assembly_input(
            f04_scoped_rows(),
            50,
            f04_partition(50, 0, 0),
            ReportSelector::CgroupId(999),
        ))
        .is_err(),
        "selector-999 50/0/0 refuses at assembly"
    );
    // The derived 0/40/10 passes every ingress.
    let v = hostile("999", "0", "40", "10");
    assert!(
        workload_v2::validate_workload_v2(&v).is_empty(),
        "derived 0/40/10 validates: {:?}",
        workload_v2::validate_workload_v2(&v)
    );
    let report =
        report_from_bytes(&serde_json::to_vec(&v).expect("encodes")).expect("derived decodes");
    assert_eq!(report.partition, f04_partition(0, 40, 10));
    assemble(f04_assembly_input(
        f04_scoped_rows(),
        50,
        f04_partition(0, 40, 10),
        ReportSelector::CgroupId(999),
    ))
    .expect("derived assembles");
    // Case 2: selector 43812 with stored 0/50/0 refuses; the frozen
    // 20/20/10 passes (positive control pins the fixture itself).
    let v = hostile("43812", "0", "50", "0");
    assert!(
        !workload_v2::validate_workload_v2(&v).is_empty(),
        "selector-43812 0/50/0 refuses at validation"
    );
    assert!(
        report_from_bytes(&serde_json::to_vec(&v).expect("encodes")).is_err(),
        "selector-43812 0/50/0 refuses at decode"
    );
    assert!(
        assemble(f04_assembly_input(
            f04_scoped_rows(),
            50,
            f04_partition(0, 50, 0),
            ReportSelector::CgroupId(43812),
        ))
        .is_err(),
        "selector-43812 0/50/0 refuses at assembly"
    );
    let frozen = load_fixture("unknown-match.json");
    assert!(
        workload_v2::validate_workload_v2(&frozen).is_empty(),
        "frozen 20/20/10 keeps validating"
    );
    let report = report_from_bytes(
        &std::fs::read(fixture_path("unknown-match.json")).expect("fixture present"),
    )
    .expect("frozen fixture keeps decoding");
    assert_eq!(report.partition, f04_partition(20, 20, 10));
}

/// SEM02 at the report ingress: a cgroup-zero row carrying a resolved
/// identity refuses under every usable status at validation, decode,
/// and assembly; unresolved cgroup-zero keeps working.
#[test]
fn cgroup_zero_identity_refuses_report_ingress() {
    let hostile_doc = |status: &str| {
        let bytes = std::fs::read(fixture_path("asserted-metadata.json")).expect("fixture present");
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture parses");
        v["contexts"][0]["cgroup_id"] = serde_json::json!("0");
        v["contexts"][0]["attribution"]["status"] = serde_json::json!(status);
        if status == "verified" {
            v["contexts"][0]["attribution"]["method"] = serde_json::json!("captured_cgroup");
            v["contexts"][0]["attribution"]["source"] = serde_json::json!("kernel_capture");
        }
        v
    };
    let usable_evidence = |status: AttributionStatus| match status {
        AttributionStatus::Verified => AttributionEvidence::verified_kernel_capture(
            Relationship::HookContext,
            ValidityInterval::monotonic(100, 1000),
        ),
        AttributionStatus::Asserted => AttributionEvidence::asserted_metadata(
            Relationship::HookContext,
            kryprobe_core::workload::METHOD_METADATA_FILE,
            Some(ValidityInterval::monotonic(100, 1000)),
        ),
        _ => AttributionEvidence::new(
            Relationship::HookContext,
            kryprobe_core::workload::METHOD_METADATA_FILE,
            WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Stale,
            Some(ValidityInterval::monotonic(100, 1000)),
        ),
    };
    for (wire, status) in [
        ("verified", AttributionStatus::Verified),
        ("asserted", AttributionStatus::Asserted),
        ("stale", AttributionStatus::Stale),
    ] {
        let v = hostile_doc(wire);
        assert!(
            !workload_v2::validate_workload_v2(&v).is_empty(),
            "resolved cgroup-zero refuses at validation under {wire}"
        );
        assert!(
            report_from_bytes(&serde_json::to_vec(&v).expect("encodes")).is_err(),
            "resolved cgroup-zero refuses at decode under {wire}"
        );
        let rows = vec![f04_row(
            0,
            1000,
            555,
            50,
            WorkloadIdentity::container(F04_RUNTIME, F04_ID_A, Some("lifetime-a")),
            usable_evidence(status),
        )];
        assert!(
            assemble(f04_assembly_input(
                rows,
                50,
                f04_partition(50, 0, 0),
                ReportSelector::None,
            ))
            .is_err(),
            "resolved cgroup-zero refuses at assembly under {wire}"
        );
    }
    // Positive controls: unresolved cgroup-zero assembles and decodes;
    // the frozen asserted fixture is untouched.
    let (id, ev) = f04_unresolved();
    assemble(f04_assembly_input(
        vec![f04_row(0, 1000, 555, 50, id, ev)],
        50,
        f04_partition(50, 0, 0),
        ReportSelector::None,
    ))
    .expect("unresolved cgroup-zero assembles");
    let raw = std::fs::read(fixture_path("unknown-context.json")).expect("fixture present");
    report_from_bytes(&raw).expect("unresolved cgroup-zero decodes");
    let raw = std::fs::read(fixture_path("asserted-metadata.json")).expect("fixture present");
    report_from_bytes(&raw).expect("asserted fixture keeps decoding");
}

// ---------------------------------------------------------------------------
// I05 temporal context coherence (SEM05)
//
// New invariant (defined here before enforcement): within one
// monotonic_boot clock domain, a positive-call row with an established
// (nonzero) process start refuses when that start follows the capture
// interval end. start == end is the boundary accept; start == 0 is the
// unreadable marker and stays valid; a start before the capture start
// is an ordinary long-lived process and stays valid; a zero-call row
// carries no counted context and is unaffected by this rule.
// ---------------------------------------------------------------------------

/// SEM05: a positive-call row whose established start (1001) follows
/// the capture end (1000) refuses at validation, decode, and assembly
/// alike. RED on the F04 base: all three ingresses accept it.
#[test]
fn positive_call_future_start_refuses_at_every_ingress() {
    let bytes = std::fs::read(fixture_path("asserted-metadata.json")).expect("fixture present");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture parses");
    assert_eq!(
        v["interval"]["end_ns"], "1000",
        "fixture pins the capture end"
    );
    v["contexts"][0]["start_ns"] = serde_json::json!("1001");
    assert!(
        !workload_v2::validate_workload_v2(&v).is_empty(),
        "future-start positive call refuses at validation"
    );
    assert!(
        report_from_bytes(&serde_json::to_vec(&v).expect("encodes")).is_err(),
        "future-start positive call refuses at decode"
    );
    let (id, ev) = f04_unresolved();
    assert!(
        assemble(f04_assembly_input(
            vec![f04_row(43812, 1000, 1001, 50, id, ev)],
            50,
            f04_partition(50, 0, 0),
            ReportSelector::None,
        ))
        .is_err(),
        "future-start positive call refuses at assembly"
    );
}

/// SEM05 boundary and pass cases: start == capture end accepts; a
/// pre-capture (long-lived) start accepts; start 0 (unreadable) accepts;
/// a zero-call future-start row accepts (no counted context). Frozen
/// fixtures keep validating and decoding untouched.
#[test]
fn temporal_coherence_boundary_cases_pass() {
    // Assembly: interval 100..1000; each row carries a distinct key.
    let (id0, ev0) = f04_unresolved();
    let (id1, ev1) = f04_unresolved();
    let (id2, ev2) = f04_unresolved();
    let (id3, ev3) = f04_unresolved();
    assemble(f04_assembly_input(
        vec![
            f04_row(43812, 1000, 1000, 20, id0, ev0),
            f04_row(43813, 1001, 50, 20, id1, ev1),
            f04_row(43814, 1002, 0, 20, id2, ev2),
            f04_row(43815, 1003, 1001, 0, id3, ev3),
        ],
        60,
        f04_partition(60, 0, 0),
        ReportSelector::None,
    ))
    .expect("boundary/unreadable/pre-capture/zero-call rows assemble");
    // Validation + decode: boundary and pre-capture starts validate.
    for start in ["1000", "50"] {
        let bytes = std::fs::read(fixture_path("asserted-metadata.json")).expect("fixture present");
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture parses");
        v["contexts"][0]["start_ns"] = serde_json::json!(start);
        assert!(
            workload_v2::validate_workload_v2(&v).is_empty(),
            "start {start} validates: {:?}",
            workload_v2::validate_workload_v2(&v)
        );
        report_from_bytes(&serde_json::to_vec(&v).expect("encodes"))
            .expect("boundary start decodes");
    }
    // Positive controls: the start-0 frozen fixture and every frozen
    // fixture keep validating and decoding.
    let raw = std::fs::read(fixture_path("unknown-context.json")).expect("fixture present");
    report_from_bytes(&raw).expect("start-0 fixture keeps decoding");
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
            "{name} keeps validating"
        );
    }
}
