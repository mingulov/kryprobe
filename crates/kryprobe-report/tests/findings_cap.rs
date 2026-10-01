// SPDX-License-Identifier: GPL-3.0-or-later
//! Findings-cap contract tests (audit X2-A): first-N + exactly one
//! truncation marker iff anything dropped; validation continues past
//! cap; batch/stream equivalence; mismatch buffer capped too.

use kryprobe_report::{
    EVENT_SCHEMA_V0, StreamChecker, StreamFinding, ValidationFinding,
    check_stream_with_max_findings, validate_reader_with_max_findings,
    validate_str_with_max_findings,
};

const KINDS: &[(&str, &[&str])] = &[("session_end", &["verdict"])];

fn record(mono: &str) -> String {
    format!(
        "{{\"schema\":\"{EVENT_SCHEMA_V0}\",\"kind\":\"session_end\",\
         \"session_id\":\"test:session\",\"record_id\":\"test:r\",\
         \"monotonic_ns\":\"{mono}\",\"payload\":{{\"verdict\":\"OBSERVED\"}}}}"
    )
}

fn schema_flood_record() -> String {
    "{\"schema\":\"WRONG\",\"kind\":\"session_end\",\
     \"session_id\":\"test:session\",\"record_id\":\"test:r\",\
     \"monotonic_ns\":\"7\",\"payload\":{\"verdict\":\"OBSERVED\"}}"
        .to_string()
}

#[test]
fn cap_appends_single_truncated_marker() {
    let text = ["not json"; 8].join("\n");
    let findings = check_stream_with_max_findings(&text, KINDS, 5);
    assert_eq!(findings.len(), 6, "first-N plus exactly one marker");
    for (i, finding) in findings[..5].iter().enumerate() {
        assert!(
            matches!(finding, StreamFinding::BadShape { line, .. } if *line == i + 1),
            "first-N retained in order: {finding:?}"
        );
    }
    assert_eq!(
        findings[5],
        StreamFinding::Truncated { dropped: 3 },
        "marker counts dropped findings"
    );
}

#[test]
fn at_cap_no_marker() {
    let text = ["not json"; 5].join("\n");
    let findings = check_stream_with_max_findings(&text, KINDS, 5);
    assert_eq!(findings.len(), 5);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, StreamFinding::Truncated { .. })),
        "no marker when nothing dropped"
    );
}

#[test]
fn limit_zero_marks_invalid_input() {
    let findings = check_stream_with_max_findings("not json", KINDS, 0);
    assert_eq!(findings, vec![StreamFinding::Truncated { dropped: 1 }]);
    let clean = check_stream_with_max_findings(&record("7"), KINDS, 0);
    assert!(clean.is_empty(), "empty still means clean");
}

#[test]
fn dropped_counts_findings_not_lines() {
    // `{}` yields 6 MissingKey findings on one line.
    let findings = check_stream_with_max_findings("{}", KINDS, 4);
    assert_eq!(findings.len(), 5);
    assert_eq!(findings[4], StreamFinding::Truncated { dropped: 2 });
}

#[test]
fn batch_stream_equivalence() {
    let text = ["not json"; 8].join("\n");
    let batch = check_stream_with_max_findings(&text, KINDS, 5);
    let mut checker = StreamChecker::with_max_findings(KINDS, 5);
    for (index, line) in text.lines().enumerate() {
        checker.push_line(index + 1, line);
    }
    assert_eq!(checker.finish(), batch);
}

#[test]
fn validation_continues_past_cap() {
    // Max 1: line 2 retained; lines 3-4 clock violations dropped but counted.
    let text = [
        record("100"),
        "not json".to_string(),
        record("50"),
        record("40"),
    ]
    .join("\n");
    let findings = check_stream_with_max_findings(&text, KINDS, 1);
    assert_eq!(findings.len(), 2);
    assert!(matches!(
        findings[0],
        StreamFinding::BadShape { line: 2, .. }
    ));
    assert_eq!(findings[1], StreamFinding::Truncated { dropped: 2 });
}

#[test]
fn long_clock_and_unicode_survive() {
    let big = "9".repeat(500);
    let text = [record("100"), record(&big), "not json ü✓".to_string()].join("\n");
    let findings = check_stream_with_max_findings(&text, KINDS, 10);
    assert_eq!(findings.len(), 1, "only the bad record flags: {findings:?}");
    assert!(
        matches!(&findings[0], StreamFinding::BadShape { value, .. } if value.contains('ü')),
        "unicode value retained: {findings:?}"
    );
}

#[test]
fn mismatch_cap_marks_dropped() {
    let text = (0..6)
        .map(|_| schema_flood_record())
        .collect::<Vec<_>>()
        .join("\n");
    let findings = validate_str_with_max_findings(&text, b"{}", 4);
    let mismatches = findings
        .iter()
        .filter(|f| matches!(f, ValidationFinding::SchemaMismatch { .. }))
        .count();
    assert_eq!(mismatches, 4, "first-N mismatches retained");
    assert!(
        findings.contains(&ValidationFinding::Truncated { dropped: 2 }),
        "mismatch overflow marked: {findings:?}"
    );
}

#[test]
fn drift_preserved_past_mismatch_cap() {
    let text = (0..6)
        .map(|_| schema_flood_record())
        .collect::<Vec<_>>()
        .join("\n");
    // b"{}" differs from the embedded schema -> drift must survive the cap.
    let findings = validate_str_with_max_findings(&text, b"{}", 2);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, ValidationFinding::SchemaDrift { .. })),
        "drift preserved: {findings:?}"
    );
    assert!(
        findings.contains(&ValidationFinding::Truncated { dropped: 4 }),
        "marker present: {findings:?}"
    );
}

#[test]
fn stream_marker_flows_through_validate_reader() {
    let text = ["not json"; 8].join("\n");
    let findings = validate_reader_with_max_findings(text.as_bytes(), b"{}", 5);
    assert!(
        findings.contains(&ValidationFinding::Stream(StreamFinding::Truncated {
            dropped: 3
        })),
        "stream marker wrapped: {findings:?}"
    );
}
