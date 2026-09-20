// SPDX-License-Identifier: GPL-3.0-or-later
//! Stream-checker tests (moved from testkit with the checker, 1B-M4).

use kryprobe_report::{StreamFinding, check_stream};

/// Caller-supplied kind table: the checker has no backend knowledge,
/// so the required payload keys per kind come from here.
const SYNTH_KINDS: &[(&str, &[&str])] = &[
    ("session_start", &["target_selector", "capture_mode"]),
    ("operation_observation", &["observation_id", "backend"]),
    ("session_end", &["verdict"]),
];

fn record(kind: &str, record_id: &str, mono: &str, payload: &str) -> String {
    format!(
        "{{\"schema\":\"kryprobe.event/v0\",\"kind\":\"{kind}\",\
         \"session_id\":\"test:session\",\"record_id\":\"{record_id}\",\
         \"monotonic_ns\":\"{mono}\",\"payload\":{payload}}}"
    )
}

/// A `session_end` record with a caller-supplied raw JSON `session_id` value
/// (e.g. `"\"Test:session\""` or `"42"`); everything else is valid.
fn record_with_session_id(session_id_json: &str) -> String {
    format!(
        "{{\"schema\":\"kryprobe.event/v0\",\"kind\":\"session_end\",\
         \"session_id\":{session_id_json},\"record_id\":\"test:r\",\
         \"monotonic_ns\":\"7\",\"payload\":{{\"verdict\":\"OBSERVED\"}}}}"
    )
}
#[test]
fn check_stream_accepts_valid_three_record_stream() {
    let text = [
        record(
            "session_start",
            "test:r1",
            "1000000",
            "{\"target_selector\":\"pid\",\"capture_mode\":\"trace\"}",
        ),
        record(
            "operation_observation",
            "test:r2",
            "1000500",
            "{\"observation_id\":\"test:o1\",\"backend\":\"p11\"}",
        ),
        record(
            "session_end",
            "test:r3",
            "1001000",
            "{\"verdict\":\"OBSERVED\"}",
        ),
    ]
    .join("\n");
    assert_eq!(check_stream(&text, SYNTH_KINDS), Vec::new());
}

#[test]
fn check_stream_reports_missing_key() {
    let text = "{\"schema\":\"kryprobe.event/v0\",\"kind\":\"session_end\",\
        \"record_id\":\"test:r\",\"monotonic_ns\":\"7\",\
        \"payload\":{\"verdict\":\"OBSERVED\"}}";
    assert_eq!(
        check_stream(text, SYNTH_KINDS),
        vec![StreamFinding::MissingKey {
            line: 1,
            key: "session_id".to_string(),
        }]
    );
}

#[test]
fn check_stream_reports_missing_payload_key() {
    let text = record("session_end", "test:r", "7", "{}");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::MissingKey {
            line: 1,
            key: "payload.verdict".to_string(),
        }]
    );
}

#[test]
fn check_stream_reports_bad_shape() {
    let text = record("session_end", "test:r", "07", "{\"verdict\":\"OBSERVED\"}");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::BadShape {
            line: 1,
            key: "monotonic_ns".to_string(),
            value: "07".to_string(),
        }]
    );
}

#[test]
fn check_stream_rejects_prefixed_id_with_uppercase_head() {
    let text = record_with_session_id("\"Test:session\"");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::BadShape {
            line: 1,
            key: "session_id".to_string(),
            value: "Test:session".to_string(),
        }]
    );
}

#[test]
fn check_stream_rejects_prefixed_id_with_digit_head() {
    let text = record_with_session_id("\"9test:session\"");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::BadShape {
            line: 1,
            key: "session_id".to_string(),
            value: "9test:session".to_string(),
        }]
    );
}

#[test]
fn check_stream_rejects_prefixed_id_without_colon() {
    let text = record_with_session_id("\"testsession\"");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::BadShape {
            line: 1,
            key: "session_id".to_string(),
            value: "testsession".to_string(),
        }]
    );
}

#[test]
fn check_stream_rejects_prefixed_id_with_empty_tail() {
    let text = record_with_session_id("\"test:\"");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::BadShape {
            line: 1,
            key: "session_id".to_string(),
            value: "test:".to_string(),
        }]
    );
}

#[test]
fn check_stream_rejects_non_string_session_id() {
    let text = record_with_session_id("42");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::BadShape {
            line: 1,
            key: "session_id".to_string(),
            value: "42".to_string(),
        }]
    );
}

#[test]
fn check_stream_accepts_equal_monotonic_ns() {
    let text = [
        record(
            "session_start",
            "test:r1",
            "100",
            "{\"target_selector\":\"pid\",\"capture_mode\":\"trace\"}",
        ),
        record(
            "session_end",
            "test:r2",
            "100",
            "{\"verdict\":\"OBSERVED\"}",
        ),
    ]
    .join("\n");
    assert_eq!(check_stream(&text, SYNTH_KINDS), Vec::new());
}

#[test]
fn check_stream_reports_clock_went_backwards() {
    let text = [
        record(
            "session_start",
            "test:r1",
            "100",
            "{\"target_selector\":\"pid\",\"capture_mode\":\"trace\"}",
        ),
        record("session_end", "test:r2", "50", "{\"verdict\":\"OBSERVED\"}"),
    ]
    .join("\n");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::ClockWentBackwards {
            line: 2,
            previous: "100".to_string(),
            current: "50".to_string(),
        }]
    );
}
