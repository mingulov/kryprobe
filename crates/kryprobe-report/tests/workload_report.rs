// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2C: typed workload report assembly/rendering + offline replay.
//!
//! One API serves both live output and replay: [`assemble`] builds a
//! [`WorkloadReport`] from captured rows, [`report_from_bytes`] /
//! [`report_from_reader`] rebuild the identical typed report from stored
//! bytes with no host queries, and the same renderer serves both paths.

use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, ContextIdentity, CountOperand, ExecutionKind,
    MAX_REPORT_V2_BYTES, MAX_V2_CONTEXT_ROWS, METHOD_METADATA_FILE, Relationship, ScopePartition,
    SnapshotConsistency, ValidityInterval, WorkloadIdentity,
};
use kryprobe_report::workload::{
    AssemblyInput, CoverageLevel, GroupBy, GroupKey, MetadataAvailability, NativeIdentity,
    ReportCoverage, ReportRowInput, WorkloadBuildError, WorkloadDecodeError, WorkloadSelector,
    WorkloadWriteError, assemble, render_legacy_v1, report_from_bytes, report_from_reader,
};
use std::io::{Read, Write};
use std::path::PathBuf;

const SESSION: &str = "0123456789abcdef0123456789abcdef";
const KERNEL: &str = "7.0.0-38-generic/boot-A";
const CID_A: &str = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
const CID_B: &str = "9c4d2f7a8b1e4a6c9d0f3b5a7c8e1d2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b1c3d";
const RUNTIME: &str = "docker://host-a";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/workload-v2")
        .join(name)
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).expect("frozen fixture present")
}

fn native() -> NativeIdentity {
    NativeIdentity::new(1, 2, 0, 1, "cbc(aes)", Some("cbc-aes-aesni"))
}

fn context(kh: u64, cgroup: u64, tgid: u32, start_ns: u64) -> ContextIdentity {
    ContextIdentity::new(kh, cgroup, tgid, 1000, start_ns, ExecutionKind::Proc)
}

fn asserted(container_id: &str) -> (WorkloadIdentity, AttributionEvidence) {
    (
        WorkloadIdentity::container(RUNTIME, container_id, Some("lifetime-a")),
        AttributionEvidence::asserted_metadata(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            Some(ValidityInterval::monotonic(100, 200)),
        ),
    )
}

fn unresolved() -> (WorkloadIdentity, AttributionEvidence) {
    (
        WorkloadIdentity::none(),
        AttributionEvidence::unresolved(Relationship::HookContext),
    )
}

#[allow(clippy::too_many_arguments)]
fn row(
    kh: u64,
    cgroup: u64,
    tgid: u32,
    start_ns: u64,
    calls: u64,
    native: NativeIdentity,
    identity: WorkloadIdentity,
    evidence: AttributionEvidence,
) -> ReportRowInput {
    ReportRowInput {
        context: context(kh, cgroup, tgid, start_ns),
        calls,
        native,
        identity,
        evidence,
    }
}

fn coverage_complete() -> ReportCoverage {
    ReportCoverage {
        capture: CoverageLevel::Complete,
        attribution: CoverageLevel::Complete,
        metadata: CoverageLevel::Complete,
        correlation: CoverageLevel::Complete,
    }
}

fn base_input(rows: Vec<ReportRowInput>, observed: u64) -> AssemblyInput {
    AssemblyInput {
        session_id: SESSION.to_string(),
        kernel_identity: KERNEL.to_string(),
        interval_start_ns: 100,
        interval_end_ns: 200,
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
        partition: ScopePartition::from_counts(observed, 0, 0).expect("valid partition"),
        selector: WorkloadSelector::None,
        group_by: GroupBy::None,
        metadata: MetadataAvailability::Available,
        coverage: coverage_complete(),
    }
}

/// Roundtrip preserves every native-identity field, including two distinct
/// native tuples sharing one `kh` (hash collision stays qualified, never
/// merged), and re-encoding decoded bytes is byte-identical.
#[test]
fn workload_roundtrip_retains_native_identity() {
    let (no_id, no_ev) = unresolved();
    let (no_id2, no_ev2) = unresolved();
    let rows = vec![
        row(7, 43812, 1000, 555, 20, native(), no_id, no_ev),
        // Same kh, different native tuple: a collision the dictionary
        // must qualify with two entries, not merge.
        row(
            7,
            43813,
            1001,
            556,
            30,
            NativeIdentity::new(2, 4, 0, 1, "gcm(aes)", Some("gcm-aes-aesni")),
            no_id2,
            no_ev2,
        ),
    ];
    let report = assemble(base_input(rows, 50)).expect("assembles");
    let bytes = report.to_json_bytes().expect("encodes");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("is JSON");
    assert_eq!(value["dictionary"].as_array().expect("dict").len(), 2);
    let replayed = report_from_bytes(&bytes).expect("replays");
    assert_eq!(replayed.rows.len(), 2);
    assert_eq!(replayed.rows[0].native.algorithm, "cbc(aes)");
    assert_eq!(
        replayed.rows[0].native.driver.as_deref(),
        Some("cbc-aes-aesni")
    );
    assert_eq!(replayed.rows[0].context.kh, 7);
    assert_eq!(replayed.rows[1].native.algorithm, "gcm(aes)");
    assert_eq!(replayed.rows[1].context.kh, 7);
    assert_ne!(replayed.rows[0].native, replayed.rows[1].native);
    // Deterministic re-encode: decoded bytes encode byte-identically.
    assert_eq!(replayed.to_json_bytes().expect("re-encodes"), bytes);
    // And the frozen validator accepts our encoded bytes.
    kryprobe_report::validate::workload_v2::validate_bytes(&bytes).expect("valid v2");
}

/// Replay decodes captured bytes only: identities, statuses, and validity
/// intervals come from the capture, with no current host/runtime queries
/// (the decode surface takes bytes alone — no paths, no env, no clocks).
#[test]
fn replay_uses_captured_metadata_only() {
    let bytes = fixture_bytes("asserted-metadata.json");
    let first = report_from_bytes(&bytes).expect("replays frozen fixture");
    // Deterministic: no clock or host state leaks into the typed report.
    let second = report_from_bytes(&bytes).expect("replays again");
    assert_eq!(first.rows, second.rows);
    assert_eq!(first.ledger.system_total, 100);
    // Captured bindings survive even though these fixture containers do
    // not exist on this host: nothing re-resolves them.
    let ids: Vec<&str> = first
        .rows
        .iter()
        .map(|row| {
            row.workload
                .as_ref()
                .expect("asserted row keeps identity")
                .container
                .as_ref()
                .expect("container")
                .id
                .as_str()
        })
        .collect();
    assert_eq!(ids, vec![CID_A, CID_B]);
    for row in &first.rows {
        let evidence = row.evidence.as_ref().expect("asserted row keeps evidence");
        assert_eq!(evidence.status, AttributionStatus::Asserted);
        // Repaired R3 window: the captured validity covers the whole
        // counted report interval (coverage semantics, not a bare number).
        let validity = evidence
            .validity
            .as_ref()
            .expect("asserted binding carries a validity window");
        assert_eq!(*validity, ValidityInterval::monotonic(100, 1000));
        assert!(
            validity.start_ns <= first.interval.start_ns
                && first.interval.end_ns <= validity.end_ns,
            "validity {validity:?} must cover report interval {}..{}",
            first.interval.start_ns,
            first.interval.end_ns
        );
    }
    // The offline render carries the captured identities verbatim.
    let text = first.render_text();
    assert!(text.contains(CID_A), "render keeps captured id A");
    assert!(text.contains(CID_B), "render keeps captured id B");
}

/// Nested/ancestor associations are context, not second memberships: each
/// row counts exactly once, group totals sum to the per-context sum, and no
/// ancestor key appears as a group.
#[test]
fn parent_child_totals_are_not_additive() {
    let mut child_identity = WorkloadIdentity::container(RUNTIME, CID_A, Some("lifetime-a"));
    child_identity.ancestor_container = Some(kryprobe_core::workload::ContainerRef {
        runtime: RUNTIME.to_string(),
        id: CID_B.to_string(),
        lifetime: Some("lifetime-parent".to_string()),
    });
    let child_evidence = AttributionEvidence::asserted_metadata(
        Relationship::HookContext,
        METHOD_METADATA_FILE,
        Some(ValidityInterval::monotonic(100, 200)),
    );
    let (parent_id, parent_ev) = asserted(CID_B);
    let rows = vec![
        ReportRowInput {
            context: context(7, 100, 1000, 555),
            calls: 20,
            native: native(),
            identity: child_identity,
            evidence: child_evidence,
        },
        row(7, 200, 1001, 556, 30, native(), parent_id, parent_ev),
    ];
    let mut input = base_input(rows, 50);
    input.group_by = GroupBy::Container;
    let report = assemble(input).expect("assembles");
    let groups = report.grouped_totals();
    // Exactly two groups: each row under its OWN container. The ancestor
    // association contributes no group and no second count.
    assert_eq!(groups.len(), 2);
    let total: u64 = groups.iter().map(|(_, calls)| calls).sum();
    assert_eq!(total, 50);
    assert_eq!(total, report.ledger.per_context_sum);
    for (key, _) in &groups {
        assert!(
            !matches!(key, GroupKey::Unknown),
            "no unknown group expected here: {key:?}"
        );
    }
    // Group-by-cgroup likewise counts each row once under its own cgroup:
    // the "parent" cgroup total excludes the child cgroup row.
    let mut input = base_input(
        vec![
            row(
                7,
                100,
                1000,
                555,
                20,
                native(),
                {
                    let (id, _) = asserted(CID_A);
                    id
                },
                {
                    let (_, ev) = asserted(CID_A);
                    ev
                },
            ),
            row(
                7,
                200,
                1001,
                556,
                30,
                native(),
                {
                    let (id, _) = asserted(CID_B);
                    id
                },
                {
                    let (_, ev) = asserted(CID_B);
                    ev
                },
            ),
        ],
        50,
    );
    input.group_by = GroupBy::Cgroup;
    let report = assemble(input).expect("assembles");
    let groups = report.grouped_totals();
    assert_eq!(
        groups,
        vec![(GroupKey::Cgroup(100), 20), (GroupKey::Cgroup(200), 30)]
    );
}

/// Unresolved/ambiguous/unsupported rows keep explicit unknown workload
/// cells and an explicit unknown group — never a host row, never blank.
#[test]
fn unknown_rows_survive_rendering() {
    let ambiguous = AttributionEvidence::new(
        Relationship::HookContext,
        METHOD_METADATA_FILE,
        kryprobe_core::workload::WorkloadOrigin::OperatorMetadataFile,
        AttributionStatus::Ambiguous,
        None,
    );
    let unsupported = AttributionEvidence::new(
        Relationship::HookContext,
        kryprobe_core::workload::METHOD_UNRESOLVED,
        kryprobe_core::workload::WorkloadOrigin::Unknown,
        AttributionStatus::Unsupported,
        None,
    );
    let (u1, e1) = unresolved();
    let rows = vec![
        row(7, 0, 1000, 0, 10, native(), u1, e1),
        row(
            7,
            43813,
            1001,
            556,
            20,
            native(),
            WorkloadIdentity::none(),
            ambiguous,
        ),
        row(
            7,
            43814,
            1002,
            557,
            30,
            native(),
            WorkloadIdentity::none(),
            unsupported,
        ),
    ];
    let mut input = base_input(rows, 60);
    input.group_by = GroupBy::Container;
    let report = assemble(input).expect("assembles");
    assert!(report.rows.iter().all(|row| row.workload.is_none()));
    let text = report.render_text();
    // Every unknown row renders an explicit unknown workload cell.
    assert!(text.matches("unknown").count() >= 3);
    assert!(
        !text
            .lines()
            .any(|line| line.contains("WORKLOAD") && line.contains("host"))
    );
    for line in text.lines().filter(|line| line.starts_with('7')) {
        assert!(line.contains("unknown"), "row keeps unknown cell: {line}");
        assert!(!line.contains("host "), "row never becomes host: {line}");
    }
    // Grouped totals carry one explicit unknown group with every call.
    assert_eq!(report.grouped_totals(), vec![(GroupKey::Unknown, 60)]);
    // The unknown group survives a replay roundtrip too.
    let bytes = report.to_json_bytes().expect("encodes");
    let replayed = report_from_bytes(&bytes).expect("replays");
    assert_eq!(replayed.grouped_totals(), vec![(GroupKey::Unknown, 60)]);
    assert_eq!(replayed.render_text(), text);
}

/// Replay normalizes file row order to accounting-key order (so live
/// and replay renders agree), and refuses duplicate accounting keys
/// symmetric with assembly.
#[test]
fn replay_normalizes_row_order_and_refuses_duplicates() {
    let bytes = fixture_bytes("matching-violation.json");
    let straight = report_from_bytes(&bytes).expect("replays");
    // matching-violation stores kh=9 first: decode sorts kh=7 first.
    assert_eq!(straight.rows[0].context.kh, 7);
    assert_eq!(straight.rows[1].context.kh, 9);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("parses");
    value["contexts"].as_array_mut().expect("rows").reverse();
    let reversed_bytes = serde_json::to_vec(&value).expect("serializes");
    kryprobe_report::validate::workload_v2::validate_bytes(&reversed_bytes)
        .expect("reordered bytes stay valid v2");
    let reversed = report_from_bytes(&reversed_bytes).expect("replays");
    assert_eq!(reversed.rows, straight.rows);
    assert_eq!(reversed.render_text(), straight.render_text());
    // A duplicated row with otherwise consistent sums refuses typed
    // (merging would corrupt rows).
    let mut duped: serde_json::Value = serde_json::from_slice(&bytes).expect("parses");
    let first = duped["contexts"][0].clone();
    duped["contexts"].as_array_mut().expect("rows").push(first);
    duped["ledger"]["system_total"] = serde_json::json!("70");
    duped["ledger"]["per_context_sum"] = serde_json::json!("70");
    duped["partition"]["matched"] = serde_json::json!("40");
    let duped_bytes = serde_json::to_vec(&duped).expect("serializes");
    kryprobe_report::validate::workload_v2::validate_bytes(&duped_bytes)
        .expect("duped sums stay valid v2");
    assert!(matches!(
        report_from_bytes(&duped_bytes),
        Err(WorkloadDecodeError::DuplicateContext)
    ));
}

/// Malformed bytes (non-JSON, wrong schema, schema defects) refuse typed.
#[test]
fn replay_rejects_malformed_input() {
    assert!(matches!(
        report_from_bytes(b"not json at all"),
        Err(WorkloadDecodeError::Malformed)
    ));
    assert!(matches!(
        report_from_bytes(b"[1,2,3]"),
        Err(WorkloadDecodeError::SchemaDefects { .. })
    ));
    let mut value: serde_json::Value =
        serde_json::from_slice(&fixture_bytes("complete-raw-ids.json")).expect("fixture parses");
    value["schema"] = serde_json::json!("kryprobe.workload-report.v1");
    let bytes = serde_json::to_vec(&value).expect("serializes");
    assert!(matches!(
        report_from_bytes(&bytes),
        Err(WorkloadDecodeError::SchemaDefects { .. })
    ));
    // Findings never echo input bytes: the error carries a count only.
    let err = report_from_bytes(&bytes).expect_err("v1 bytes are not v2");
    assert!(!format!("{err:?}").contains("workload-report.v1"));
}

/// Truncated bytes refuse — via both the bytes and the reader entry points.
#[test]
fn replay_rejects_truncated_input() {
    let bytes = fixture_bytes("asserted-metadata.json");
    let cut = bytes.len() / 2;
    let truncated = &bytes[..cut];
    assert!(matches!(
        report_from_bytes(truncated),
        Err(WorkloadDecodeError::Malformed)
    ));
    assert!(matches!(
        report_from_reader(truncated),
        Err(WorkloadDecodeError::Malformed)
    ));
    // A truncation that stays valid JSON but drops required keys is a
    // schema defect, never a partial report.
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("parses");
    value.as_object_mut().expect("object").remove("ledger");
    let bytes = serde_json::to_vec(&value).expect("serializes");
    assert!(matches!(
        report_from_reader(bytes.as_slice()),
        Err(WorkloadDecodeError::SchemaDefects { .. })
    ));
}

/// Oversized input refuses before parsing/allocation.
#[test]
fn replay_rejects_oversized_input() {
    let big = vec![b'x'; MAX_REPORT_V2_BYTES + 1];
    assert!(matches!(
        report_from_bytes(&big),
        Err(WorkloadDecodeError::TooLarge)
    ));
    assert!(matches!(
        report_from_reader(big.as_slice()),
        Err(WorkloadDecodeError::TooLarge)
    ));
    // Exactly at the budget, the byte gate passes (JSON shape still
    // decides — here malformed, proving the size gate passed first).
    let edge = vec![b'x'; MAX_REPORT_V2_BYTES];
    assert!(matches!(
        report_from_bytes(&edge),
        Err(WorkloadDecodeError::Malformed)
    ));
}

/// Every frozen v2 fixture replays and renders identically before and
/// after a re-encode roundtrip: same fixture, identical live/offline bytes.
#[test]
fn same_fixture_renders_identically_live_and_offline() {
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
        let bytes = fixture_bytes(name);
        let live = report_from_bytes(&bytes).expect("fixture replays");
        let live_text = live.render_text();
        let re_encoded = live.to_json_bytes().expect("re-encodes");
        kryprobe_report::validate::workload_v2::validate_bytes(&re_encoded)
            .expect("re-encoded bytes stay valid v2");
        let offline = report_from_bytes(&re_encoded).expect("re-encoded replays");
        assert_eq!(
            offline.render_text(),
            live_text,
            "{name} renders identically live/offline"
        );
        assert_eq!(offline.rows, live.rows, "{name} rows survive roundtrip");
    }
}

/// A live-assembled report renders byte-identically to the same decoded
/// fixture: one renderer serves both paths.
#[test]
fn live_assembly_matches_decoded_fixture_render() {
    let bytes = fixture_bytes("complete-raw-ids.json");
    let decoded = report_from_bytes(&bytes).expect("replays");
    let (u1, e1) = unresolved();
    let (u2, e2) = unresolved();
    // Mirror the corrected fixture (R2: proc native context 0,
    // capture end 1000 past the row starts).
    let proc_native = NativeIdentity::new(1, 2, 0, 0, "cbc(aes)", Some("cbc-aes-aesni"));
    let mut input = base_input(
        vec![
            row(7, 43812, 1000, 555, 20, proc_native.clone(), u1, e1),
            row(7, 43813, 1001, 556, 30, proc_native, u2, e2),
        ],
        50,
    );
    input.interval_end_ns = 1000;
    input.metadata = MetadataAvailability::Unavailable(
        kryprobe_core::workload::MetadataUnavailable::NoPrincipal,
    );
    input.coverage = ReportCoverage {
        capture: CoverageLevel::Complete,
        attribution: CoverageLevel::Unavailable,
        metadata: CoverageLevel::Unavailable,
        correlation: CoverageLevel::Complete,
    };
    let live = assemble(input).expect("assembles");
    assert_eq!(live.render_text(), decoded.render_text());
}

/// Assembly is deterministic: shuffled input rows encode byte-identically.
#[test]
fn assembly_orders_rows_deterministically() {
    let mk = || {
        let (u1, e1) = unresolved();
        let (u2, e2) = unresolved();
        vec![
            row(9, 43813, 1001, 556, 30, native(), u1, e1),
            row(7, 43812, 1000, 555, 20, native(), u2, e2),
        ]
    };
    let mut rows = mk();
    rows.reverse();
    let a = assemble(base_input(mk(), 50)).expect("assembles");
    let b = assemble(base_input(rows, 50)).expect("assembles");
    assert_eq!(
        a.to_json_bytes().expect("encodes"),
        b.to_json_bytes().expect("encodes")
    );
    assert_eq!(a.rows[0].context.kh, 7);
}

/// Assembly enforces conservation: partition/ledger/interval/count
/// contradictions refuse typed instead of emitting a skewed report.
#[test]
fn assembly_enforces_conservation() {
    let mk = || {
        let (u1, e1) = unresolved();
        vec![row(7, 43812, 1000, 555, 50, native(), u1, e1)]
    };
    // Partition observed must equal the summed context calls.
    let mut input = base_input(mk(), 50);
    input.partition = ScopePartition::from_counts(49, 0, 0).expect("valid");
    assert!(matches!(
        assemble(input),
        Err(WorkloadBuildError::PartitionMismatch)
    ));
    // Inverted intervals refuse.
    let mut input = base_input(mk(), 50);
    input.interval_start_ns = 200;
    input.interval_end_ns = 100;
    assert!(matches!(
        assemble(input),
        Err(WorkloadBuildError::InvertedInterval)
    ));
    // Refused inserts above the unknown population refuse.
    let mut input = base_input(mk(), 50);
    input.system_total = CountOperand {
        value: 60,
        saturated: false,
        population: "global".to_string(),
    };
    input.partition = ScopePartition::from_counts(50, 0, 0).expect("valid");
    input.refused_inserts = 11;
    assert!(matches!(
        assemble(input),
        Err(WorkloadBuildError::RefusedExceedsUnknown)
    ));
    // Saturated operands cannot be quiescent.
    let mut input = base_input(mk(), 50);
    input.system_total = CountOperand {
        value: 50,
        saturated: true,
        population: "global".to_string(),
    };
    assert!(matches!(
        assemble(input),
        Err(WorkloadBuildError::LedgerRefused(_))
    ));
    // Duplicate accounting keys refuse (merging would corrupt rows).
    let (u1, e1) = unresolved();
    let (u2, e2) = unresolved();
    let dupes = vec![
        row(7, 43812, 1000, 555, 25, native(), u1, e1),
        row(7, 43812, 1000, 555, 25, native(), u2, e2),
    ];
    assert!(matches!(
        assemble(base_input(dupes, 50)),
        Err(WorkloadBuildError::DuplicateContext)
    ));
    // Row counts above the frozen budget refuse.
    let many: Vec<ReportRowInput> = (0..(MAX_V2_CONTEXT_ROWS + 1) as u64)
        .map(|c| {
            let (id, ev) = unresolved();
            row(7, 1000 + c, 1000, 555, 1, native(), id, ev)
        })
        .collect();
    assert!(matches!(
        assemble(base_input(many, 0)),
        Err(WorkloadBuildError::TooManyRows)
    ));
    // Call sums that overflow u64 refuse.
    let (u1, e1) = unresolved();
    let (u2, e2) = unresolved();
    let overflowing = vec![
        row(7, 43812, 1000, 555, u64::MAX, native(), u1, e1),
        row(7, 43813, 1001, 556, 1, native(), u2, e2),
    ];
    assert!(matches!(
        assemble(base_input(overflowing, 0)),
        Err(WorkloadBuildError::CallsOverflow)
    ));
    // Unproven exports a gap with unknown 0, never an exact unknown.
    let (u1, e1) = unresolved();
    let mut input = base_input(vec![row(7, 43812, 1000, 555, 50, native(), u1, e1)], 50);
    input.consistency = SnapshotConsistency::Unproven;
    let report = assemble(input).expect("unproven assembles");
    assert_eq!(report.ledger.unknown, 0);
    assert!(report.ledger.gap_unreconciled);
}

/// A writer that always fails short: `write` returns `Ok(0)`.
struct ShortWriter;

impl Write for ShortWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Ok(0)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer that fails flush after accepting bytes.
struct FlushFailWriter {
    accepted: Vec<u8>,
}

impl Write for FlushFailWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.accepted.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("flush failed"))
    }
}

/// A writer that fails with a fixed error kind (EPIPE / disk full).
struct KindWriter {
    kind: std::io::ErrorKind,
}

impl Write for KindWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(self.kind, "injected"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn small_report() -> kryprobe_report::workload::WorkloadReport {
    let (u1, e1) = unresolved();
    assemble(base_input(
        vec![row(7, 43812, 1000, 555, 50, native(), u1, e1)],
        50,
    ))
    .expect("assembles")
}

fn assert_io_kind(err: WorkloadWriteError, kind: std::io::ErrorKind) {
    match err {
        WorkloadWriteError::Io(io) => assert_eq!(io.kind(), kind, "io kind preserved"),
        other => panic!("expected Io error, got {other:?}"),
    }
}

/// Short writes surface as errors on both output paths — never a clean
/// terminal result after failed output.
#[test]
fn output_short_writes_propagate() {
    let report = small_report();
    let err = report
        .write_json_to(ShortWriter)
        .expect_err("short write fails");
    assert_io_kind(err, std::io::ErrorKind::WriteZero);
    let err = report
        .render_text_to(ShortWriter)
        .expect_err("short render fails");
    assert_io_kind(err, std::io::ErrorKind::WriteZero);
}

/// EPIPE surfaces with its kind intact on both output paths.
#[test]
fn output_epipe_propagates() {
    let report = small_report();
    let err = report
        .write_json_to(KindWriter {
            kind: std::io::ErrorKind::BrokenPipe,
        })
        .expect_err("EPIPE fails");
    assert_io_kind(err, std::io::ErrorKind::BrokenPipe);
    let err = report
        .render_text_to(KindWriter {
            kind: std::io::ErrorKind::BrokenPipe,
        })
        .expect_err("EPIPE render fails");
    assert_io_kind(err, std::io::ErrorKind::BrokenPipe);
}

/// Flush failures surface even after all bytes were accepted.
#[test]
fn output_flush_failure_propagates() {
    let report = small_report();
    let err = report
        .write_json_to(FlushFailWriter {
            accepted: Vec::new(),
        })
        .expect_err("flush failure fails");
    assert_io_kind(err, std::io::ErrorKind::Other);
    let err = report
        .render_text_to(FlushFailWriter {
            accepted: Vec::new(),
        })
        .expect_err("flush failure render fails");
    assert_io_kind(err, std::io::ErrorKind::Other);
}

/// Disk-full surfaces with its kind intact on both output paths.
#[test]
fn output_disk_full_propagates() {
    let report = small_report();
    let err = report
        .write_json_to(KindWriter {
            kind: std::io::ErrorKind::StorageFull,
        })
        .expect_err("disk full fails");
    assert_io_kind(err, std::io::ErrorKind::StorageFull);
    let err = report
        .render_text_to(KindWriter {
            kind: std::io::ErrorKind::StorageFull,
        })
        .expect_err("disk full render fails");
    assert_io_kind(err, std::io::ErrorKind::StorageFull);
}

/// Partial-then-failing output still fails: no clean result after bytes
/// were lost mid-stream.
#[test]
fn output_partial_then_failing_propagates() {
    struct PartialThenFail {
        remaining: usize,
    }
    impl Write for PartialThenFail {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "mid-stream",
                ));
            }
            let take = self.remaining.min(buf.len());
            self.remaining -= take;
            Ok(take)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let report = small_report();
    let err = report
        .write_json_to(PartialThenFail { remaining: 10 })
        .expect_err("mid-stream failure fails");
    assert_io_kind(err, std::io::ErrorKind::BrokenPipe);
}

/// Legacy v1 renders its stored partition with explicit limitations; any
/// scope re-evaluation refuses. Minimal behavior only.
#[test]
fn legacy_v1_renders_limitations_or_refuses() {
    let v1 = serde_json::json!({
        "schema": "kryprobe.workload-report.v1",
        "session": {"session_id": SESSION, "kernel_identity": "7.0.14"},
        "interval": {"start_ns": "100", "end_ns": "200", "consistency": "quiescent"},
        "profile": "api-returns",
        "boundary": "api_return",
        "contexts": [
            {"kh": "7", "cgroup_id": "43812", "tgid": 1000, "uid": 1000, "start_ns": "555", "execution_kind": "proc", "calls": "50",
             "workload": null, "attribution": null}
        ],
        "partition": {"matched": "50", "nonmatched": "0", "unknown_match": "0"},
        "selectors": {},
        "coverage": {"capture": "complete", "attribution": "complete", "metadata": "unavailable", "correlation": "complete"}
    });
    let text = render_legacy_v1(&v1).expect("stored v1 partition renders");
    assert!(text.contains("50"), "stored partition renders: {text}");
    assert!(text.contains("no native operation identity"), "{text}");
    assert!(text.contains("no authoritative ledger operands"), "{text}");
    assert!(
        text.contains("cannot bind re-evaluated selectors"),
        "{text}"
    );
    assert!(text.contains("untyped"), "{text}");
    // Non-empty selectors refuse: v1 cannot evaluate scopes.
    let mut scoped = v1.clone();
    scoped["selectors"] = serde_json::json!({"kind": "cgroup-id"});
    assert!(render_legacy_v1(&scoped).is_err());
    // Invalid v1 refuses.
    let mut bad = v1.clone();
    bad["partition"]["matched"] = serde_json::json!("18446744073709551615");
    bad["partition"]["nonmatched"] = serde_json::json!("1");
    assert!(render_legacy_v1(&bad).is_err());
}

/// An empty observation assembles, encodes valid v2, replays, and
/// renders an honest zero — with no fabricated unknown group.
#[test]
fn assembly_accepts_empty_observation() {
    let report = assemble(base_input(vec![], 0)).expect("empty assembles");
    assert_eq!(report.ledger.unknown, 0);
    assert!(!report.ledger.gap_unreconciled);
    let bytes = report.to_json_bytes().expect("encodes");
    kryprobe_report::validate::workload_v2::validate_bytes(&bytes).expect("valid v2");
    let replayed = report_from_bytes(&bytes).expect("replays");
    assert!(replayed.rows.is_empty());
    assert!(replayed.render_text().contains("0 calls across 0 rows"));
    let mut input = base_input(vec![], 0);
    input.group_by = GroupBy::Container;
    let grouped = assemble(input).expect("assembles");
    assert!(grouped.grouped_totals().is_empty());
}

/// A pendant cluster tag without a keyed identity rides the row through
/// a full roundtrip — preserved, never dropped — and still groups as
/// unknown (no key, no promotion).
#[test]
fn pendant_cluster_association_is_preserved() {
    let mut identity = WorkloadIdentity::none();
    identity.cluster = Some("cluster-a".to_string());
    let (_, evidence) = unresolved();
    let mk = || {
        vec![row(
            7,
            43812,
            1000,
            555,
            50,
            native(),
            identity.clone(),
            evidence.clone(),
        )]
    };
    let report = assemble(base_input(mk(), 50)).expect("assembles");
    let workload = report.rows[0].workload.as_ref().expect("workload rides");
    assert_eq!(workload.cluster.as_deref(), Some("cluster-a"));
    assert!(!workload.is_resolved());
    let bytes = report.to_json_bytes().expect("encodes");
    kryprobe_report::validate::workload_v2::validate_bytes(&bytes).expect("valid v2");
    let replayed = report_from_bytes(&bytes).expect("replays");
    assert_eq!(
        replayed.rows[0]
            .workload
            .as_ref()
            .expect("workload survives")
            .cluster
            .as_deref(),
        Some("cluster-a")
    );
    let mut input = base_input(mk(), 50);
    input.group_by = GroupBy::Container;
    let grouped = assemble(input).expect("assembles");
    assert_eq!(grouped.grouped_totals(), vec![(GroupKey::Unknown, 50)]);
}

/// Reader replay is bounded: a reader that never ends cannot OOM the
/// decoder, and an empty reader is malformed, not an empty report.
#[test]
fn replay_reader_is_bounded_and_empty_refuses() {
    struct Endless;
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            buf.fill(b'x');
            Ok(buf.len())
        }
    }
    assert!(matches!(
        report_from_reader(Endless),
        Err(WorkloadDecodeError::TooLarge)
    ));
    assert!(matches!(
        report_from_reader(b"".as_slice()),
        Err(WorkloadDecodeError::Malformed)
    ));
}

/// Driverless allocation records round-trip: the model marks the driver
/// explicitly unavailable, the encoder omits the key, the frozen
/// validator accepts the bytes, and replay restores the unavailable
/// marker (never a blank or fabricated name).
#[test]
fn driverless_allocation_record_round_trips() {
    let (no_id, no_ev) = unresolved();
    let driverless = NativeIdentity::new(1, 2, 0, 1, "cbc(aes)", None);
    driverless.validate().expect("absent driver validates");
    let report = assemble(base_input(
        vec![row(7, 43812, 1000, 555, 50, driverless, no_id, no_ev)],
        50,
    ))
    .expect("driverless assembles");
    assert!(report.rows[0].native.driver.is_none());
    let bytes = report.to_json_bytes().expect("encodes");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("is JSON");
    // The wire omits the absent driver (amended v2: absent, never empty).
    assert!(
        value["dictionary"][0]
            .as_object()
            .expect("entry")
            .get("driver")
            .is_none(),
        "absent driver encodes as omitted key"
    );
    // The frozen validator is the oracle: absent validates as unavailable.
    kryprobe_report::validate::workload_v2::validate_bytes(&bytes).expect("valid v2");
    let replayed = report_from_bytes(&bytes).expect("replays");
    assert!(replayed.rows[0].native.driver.is_none());
    assert_eq!(replayed, report);
    assert_eq!(replayed.to_json_bytes().expect("re-encodes"), bytes);
}

/// Present-but-empty drivers refuse at every owned boundary: model
/// validation, assembly, and wire decode (via the frozen validator).
#[test]
fn empty_driver_refuses() {
    let empty = NativeIdentity::new(1, 2, 0, 1, "cbc(aes)", Some(""));
    assert!(matches!(
        empty.validate(),
        Err(WorkloadBuildError::BadNativeIdentity)
    ));
    let (no_id, no_ev) = unresolved();
    let rows = vec![row(7, 43812, 1000, 555, 50, empty, no_id, no_ev)];
    assert!(matches!(
        assemble(base_input(rows, 50)),
        Err(WorkloadBuildError::BadNativeIdentity)
    ));
    // Wire bytes with a present-but-empty driver refuse decode.
    let (u_id, u_ev) = unresolved();
    let report = assemble(base_input(
        vec![row(7, 43812, 1000, 555, 50, native(), u_id, u_ev)],
        50,
    ))
    .expect("assembles");
    let mut value: serde_json::Value =
        serde_json::from_slice(&report.to_json_bytes().expect("encodes")).expect("is JSON");
    value["dictionary"][0]["driver"] = serde_json::json!("");
    let bytes = serde_json::to_vec(&value).expect("serializes");
    assert!(matches!(
        report_from_bytes(&bytes),
        Err(WorkloadDecodeError::SchemaDefects { .. })
    ));
}

/// Absent drivers render as explicit `unavailable` — never blank (which
/// would be ambiguous against a missing column) and never fabricated.
#[test]
fn absent_driver_renders_explicitly() {
    let (no_id, no_ev) = unresolved();
    let driverless = NativeIdentity::new(1, 2, 0, 1, "cbc(aes)", None);
    let report = assemble(base_input(
        vec![row(7, 43812, 1000, 555, 50, driverless, no_id, no_ev)],
        50,
    ))
    .expect("assembles");
    let text = report.render_text();
    let line = text
        .lines()
        .find(|line| line.starts_with('7'))
        .expect("detail row renders");
    assert!(
        line.contains(" unavailable "),
        "absent driver renders explicitly: {line}"
    );
    // Replay renders the identical explicit cell.
    let bytes = report.to_json_bytes().expect("encodes");
    let replayed = report_from_bytes(&bytes).expect("replays");
    assert_eq!(replayed.render_text(), text);
}

/// SEM03 helper: asserted container identity under a chosen lifetime
/// (`None` = explicitly unobserved lifetime, never a wildcard).
fn asserted_lifetime(
    container_id: &str,
    lifetime: Option<&str>,
) -> (WorkloadIdentity, AttributionEvidence) {
    (
        WorkloadIdentity::container(RUNTIME, container_id, lifetime),
        AttributionEvidence::asserted_metadata(
            Relationship::HookContext,
            METHOD_METADATA_FILE,
            Some(ValidityInterval::monotonic(100, 200)),
        ),
    )
}

/// Two rows sharing one runtime/id under one `AssemblyInput` with
/// container grouping: `lifetimes` supplies each row's lifetime.
fn two_lifetime_input(lifetimes: [Option<&str>; 2]) -> AssemblyInput {
    let (id_a, ev_a) = asserted_lifetime(CID_A, lifetimes[0]);
    let (id_b, ev_b) = asserted_lifetime(CID_A, lifetimes[1]);
    let mut input = base_input(
        vec![
            row(7, 43812, 1000, 555, 50, native(), id_a, ev_a),
            row(7, 43813, 1001, 556, 50, native(), id_b, ev_b),
        ],
        100,
    );
    input.group_by = GroupBy::Container;
    input
}

/// SEM03/I01: same runtime/id under two known lifetimes yields two
/// separately labeled container groups — human output must not merge
/// lifetime-distinct identities into one aggregate.
#[test]
fn container_groups_split_by_lifetime() {
    let report =
        assemble(two_lifetime_input([Some("lifetime-a"), Some("lifetime-b")])).expect("assembles");
    let groups = report.grouped_totals();
    assert_eq!(groups.len(), 2, "lifetimes A/B stay distinct: {groups:?}");
    assert_eq!(
        groups,
        vec![
            (
                GroupKey::Container {
                    runtime: RUNTIME.to_string(),
                    id: CID_A.to_string(),
                    lifetime: Some("lifetime-a".to_string()),
                },
                50,
            ),
            (
                GroupKey::Container {
                    runtime: RUNTIME.to_string(),
                    id: CID_A.to_string(),
                    lifetime: Some("lifetime-b".to_string()),
                },
                50,
            ),
        ],
        "groups carry lifetime-qualified identity keys"
    );
    assert_eq!(
        groups.iter().map(|(_, calls)| calls).sum::<u64>(),
        100,
        "split groups still cover every row: {groups:?}"
    );
    let text = report.render_text();
    assert!(
        text.contains("groups (group_by=container, 2):"),
        "two groups render:\n{text}"
    );
    assert!(text.contains("lifetime-a"), "lifetime-a labeled:\n{text}");
    assert!(text.contains("lifetime-b"), "lifetime-b labeled:\n{text}");
    // The two detail WORKLOAD cells must differ: identical cells erase
    // the restart distinction the stored report preserves.
    let detail: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("container:"))
        .collect();
    assert_eq!(detail.len(), 2, "two detail rows render:\n{text}");
    assert_ne!(detail[0], detail[1], "detail rows stay distinct:\n{text}");
}

/// SEM03/I01: a known lifetime and an unobserved lifetime under one
/// runtime/id stay distinct; the unobserved side renders an explicit
/// `unknown` lifetime, never blank and never merged into the known
/// group.
#[test]
fn container_known_and_unknown_lifetimes_stay_distinct() {
    let report = assemble(two_lifetime_input([Some("lifetime-a"), None])).expect("assembles");
    let groups = report.grouped_totals();
    assert_eq!(
        groups.len(),
        2,
        "known vs unknown lifetimes stay distinct: {groups:?}"
    );
    let text = report.render_text();
    assert!(
        text.contains("groups (group_by=container, 2):"),
        "two groups render:\n{text}"
    );
    assert!(text.contains("lifetime-a"), "lifetime-a labeled:\n{text}");
    assert!(
        text.contains(":unknown calls=50"),
        "unobserved lifetime renders explicitly:\n{text}"
    );
}

/// SEM03/I01 collision fix (Wave-C P2): an OBSERVED lifetime whose
/// value is `unknown` must render apart from an UNOBSERVED lifetime.
/// Grouping already buckets them separately; the regression pins the
/// labels: observed lifetimes render quoted (`"unknown"`), unobserved
/// renders bare `unknown` — never byte-identical lines.
#[test]
fn container_observed_unknown_lifetime_stays_distinct_from_unobserved() {
    let report = assemble(two_lifetime_input([Some("unknown"), None])).expect("assembles");
    let groups = report.grouped_totals();
    assert_eq!(
        groups.len(),
        2,
        "observed-unknown vs unobserved stay distinct: {groups:?}"
    );
    let text = report.render_text();
    assert!(
        text.contains("groups (group_by=container, 2):"),
        "two groups render:\n{text}"
    );
    let group_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("container "))
        .collect();
    assert_eq!(group_lines.len(), 2, "two group lines render:\n{text}");
    assert_ne!(
        group_lines[0], group_lines[1],
        "observed-unknown and unobserved group lines differ:\n{text}"
    );
    assert!(
        text.contains(":\"unknown\" calls=50"),
        "observed `unknown` lifetime renders quoted:\n{text}"
    );
    assert!(
        text.contains(":unknown calls=50"),
        "unobserved lifetime still renders bare `unknown`:\n{text}"
    );
    let detail: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("container:"))
        .collect();
    assert_eq!(detail.len(), 2, "two detail rows render:\n{text}");
    assert_ne!(detail[0], detail[1], "detail rows stay distinct:\n{text}");
    // Adversarial pin: even a lifetime spelling the quoted label
    // (`"unknown"` with literal quotes) cannot forge the unobserved
    // line — debug-escaping keeps every observed rendering quoted.
    let forged = assemble(two_lifetime_input([Some("\"unknown\""), None])).expect("assembles");
    let forged_text = forged.render_text();
    let forged_groups: Vec<&str> = forged_text
        .lines()
        .filter(|line| line.starts_with("container "))
        .collect();
    assert_eq!(
        forged_groups.len(),
        2,
        "two group lines render:\n{forged_text}"
    );
    assert_ne!(
        forged_groups[0], forged_groups[1],
        "quote-forging lifetime stays apart from unobserved:\n{forged_text}"
    );
    assert!(
        forged_text.contains(":\"\\\"unknown\\\"\" calls=50"),
        "forging lifetime renders escaped:\n{forged_text}"
    );
}

/// SEM03/I01 control: lifetime-qualified grouping changes no counts
/// and no stored bytes — totals still cover every row, the v2 JSON
/// round-trips byte-identically, and both lifetime rows survive with
/// their own calls.
#[test]
fn container_lifetime_grouping_preserves_totals_and_json() {
    let report =
        assemble(two_lifetime_input([Some("lifetime-a"), Some("lifetime-b")])).expect("assembles");
    assert_eq!(report.ledger.per_context_sum, 100);
    let text = report.render_text();
    assert!(
        text.contains("total: 100 calls across 2 rows"),
        "totals cover every row:\n{text}"
    );
    let bytes = report.to_json_bytes().expect("encodes");
    let replayed = report_from_bytes(&bytes).expect("replays");
    assert_eq!(
        replayed.to_json_bytes().expect("re-encodes"),
        bytes,
        "stored JSON round-trips byte-identically"
    );
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let contexts = value
        .get("contexts")
        .and_then(serde_json::Value::as_array)
        .expect("contexts array");
    assert_eq!(contexts.len(), 2, "both rows stored");
    let lifetimes: Vec<Option<&str>> = contexts
        .iter()
        .map(|row| {
            row.get("workload")
                .and_then(|w| w.get("container"))
                .and_then(|c| c.get("lifetime"))
                .and_then(serde_json::Value::as_str)
        })
        .collect();
    assert!(
        lifetimes.contains(&Some("lifetime-a")) && lifetimes.contains(&Some("lifetime-b")),
        "both lifetimes stored: {lifetimes:?}"
    );
}

/// SEM03/I01 control (D10): the container selector still matches both
/// lifetimes — grouping splits presentation, never selection.
#[test]
fn container_selector_matches_both_lifetimes() {
    let mut input = two_lifetime_input([Some("lifetime-a"), Some("lifetime-b")]);
    input.selector = WorkloadSelector::ContainerId {
        runtime: RUNTIME.to_string(),
        id: CID_A.to_string(),
        lifetime: None,
    };
    input.group_by = GroupBy::None;
    let report = assemble(input).expect("assembles");
    assert_eq!(report.partition.matched(), 100);
    assert_eq!(report.partition.nonmatched(), 0);
    assert_eq!(report.partition.unknown_match(), 0);
}
