// SPDX-License-Identifier: GPL-3.0-or-later
//! Structural checks for JSONL event streams.
//!
//! No backend knowledge lives here: callers pass the per-kind required
//! payload keys as `&[(&str, &[&str])]`. Kinds absent from that table get
//! envelope, shape, and clock checks only.
//!
//! Moved here from testkit (1B-M4): stream validation is production
//! (the validator runs it on every import/report), not a test utility.

use std::fmt;

use serde_json::Value;

/// One structural defect found by [`check_stream`]; `line` is 1-based.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StreamFinding {
    /// A required key is absent: an envelope key (`"payload"`) or a
    /// per-kind payload key (`"payload.<key>"`).
    MissingKey {
        /// 1-based physical line number.
        line: usize,
        /// Missing key name.
        key: String,
    },
    /// A key is present but malformed: wrong JSON type, a digit-string or
    /// prefixed-ID shape violation, or an unparsable record (`key == "record"`).
    BadShape {
        /// 1-based physical line number.
        line: usize,
        /// Offending key name.
        key: String,
        /// Offending value, rendered and truncated.
        value: String,
    },
    /// `monotonic_ns` went backwards relative to the previous valid record.
    ClockWentBackwards {
        /// 1-based physical line number.
        line: usize,
        /// Previous valid `monotonic_ns` digit string.
        previous: String,
        /// Current (smaller) `monotonic_ns` digit string.
        current: String,
    },
}

impl fmt::Display for StreamFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamFinding::MissingKey { line, key } => {
                write!(f, "line {line}: missing key '{key}'")
            }
            StreamFinding::BadShape { line, key, value } => {
                write!(f, "line {line}: bad shape for key '{key}': {value}")
            }
            StreamFinding::ClockWentBackwards {
                line,
                previous,
                current,
            } => write!(
                f,
                "line {line}: clock went backwards: {current} < {previous}"
            ),
        }
    }
}

/// Required envelope keys of every record.
const ENVELOPE_KEYS: &[&str] = &[
    "schema",
    "kind",
    "session_id",
    "record_id",
    "monotonic_ns",
    "payload",
];

/// Envelope keys that must hold JSON strings (`payload` must hold an object).
const STRING_KEYS: &[&str] = &["schema", "kind", "session_id", "record_id", "monotonic_ns"];

/// Checks every non-blank line of a JSONL `text` stream.
///
/// Findings are in line order: envelope keys, string types, `monotonic_ns`
/// digit-string shape (`^(0|[1-9][0-9]*)$`), `session_id`/`record_id`
/// prefixed-ID shape, per-kind required payload keys from `kinds`, and
/// non-decreasing `monotonic_ns`. Blank lines are skipped.
pub fn check_stream(text: &str, kinds: &[(&str, &[&str])]) -> Vec<StreamFinding> {
    let mut checker = StreamChecker::new(kinds);
    for (index, line) in text.lines().enumerate() {
        checker.push_line(index + 1, line);
    }
    checker.finish()
}

/// Incremental [`check_stream`]: one `push_line` per physical line, then
/// [`finish`](Self::finish). Holds only the previous clock plus findings:
/// each finding is size-capped ([`shorten`]), but the COUNT is not — a
/// million-malformed-line import grows the vec (audit X2, P1: cap with a
/// truncation signal). Well-formed-heavy streams stay small.
#[derive(Debug)]
pub struct StreamChecker<'a> {
    kinds: &'a [(&'a str, &'a [&'a str])],
    previous: Option<String>,
    findings: Vec<StreamFinding>,
}

impl<'a> StreamChecker<'a> {
    /// New checker over the per-kind required-payload-key table.
    #[must_use]
    pub fn new(kinds: &'a [(&'a str, &'a [&'a str])]) -> Self {
        Self {
            kinds,
            previous: None,
            findings: Vec::new(),
        }
    }

    /// Checks physical line `line_no` (1-based); blank lines are skipped
    /// exactly as in [`check_stream`].
    pub fn push_line(&mut self, line_no: usize, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        check_record(
            line,
            line_no,
            self.kinds,
            &mut self.previous,
            &mut self.findings,
        );
    }

    /// Collected findings, in line order.
    #[must_use]
    pub fn finish(self) -> Vec<StreamFinding> {
        self.findings
    }
}

fn check_record(
    line: &str,
    line_no: usize,
    kinds: &[(&str, &[&str])],
    previous: &mut Option<String>,
    findings: &mut Vec<StreamFinding>,
) {
    let record: Value = match serde_json::from_str(line) {
        Ok(record) => record,
        Err(_) => {
            findings.push(bad_shape(line_no, "record", line));
            return;
        }
    };
    let object = match record.as_object() {
        Some(object) => object,
        None => {
            findings.push(bad_shape(line_no, "record", line));
            return;
        }
    };
    for key in ENVELOPE_KEYS {
        if !object.contains_key(*key) {
            findings.push(StreamFinding::MissingKey {
                line: line_no,
                key: (*key).to_string(),
            });
        }
    }
    check_string_shapes(object, line_no, findings);
    check_payload_keys(object, line_no, kinds, findings);
    check_clock(object, line_no, previous, findings);
}

fn check_string_shapes(
    object: &serde_json::Map<String, Value>,
    line_no: usize,
    findings: &mut Vec<StreamFinding>,
) {
    for key in STRING_KEYS {
        let Some(value) = object.get(*key) else {
            continue;
        };
        let Some(text) = value.as_str() else {
            findings.push(bad_shape(line_no, key, &render(value)));
            continue;
        };
        if !shape_ok(key, text) {
            findings.push(bad_shape(line_no, key, text));
        }
    }
}

fn shape_ok(key: &str, text: &str) -> bool {
    match key {
        "monotonic_ns" => is_digit_string(text),
        "session_id" | "record_id" => is_prefixed_id(text),
        _ => true,
    }
}

fn check_payload_keys(
    object: &serde_json::Map<String, Value>,
    line_no: usize,
    kinds: &[(&str, &[&str])],
    findings: &mut Vec<StreamFinding>,
) {
    let Some(payload) = object.get("payload") else {
        return;
    };
    let Some(payload) = payload.as_object() else {
        findings.push(bad_shape(line_no, "payload", &render(payload)));
        return;
    };
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let Some(required) = kinds.iter().find(|entry| entry.0 == kind) else {
        return;
    };
    for key in required.1 {
        if !payload.contains_key(*key) {
            findings.push(StreamFinding::MissingKey {
                line: line_no,
                key: format!("payload.{key}"),
            });
        }
    }
}

fn check_clock(
    object: &serde_json::Map<String, Value>,
    line_no: usize,
    previous: &mut Option<String>,
    findings: &mut Vec<StreamFinding>,
) {
    let Some(current) = object
        .get("monotonic_ns")
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    if !is_digit_string(current) {
        return;
    }
    if let Some(prev) = previous
        && digit_less_than(current, prev)
    {
        findings.push(StreamFinding::ClockWentBackwards {
            line: line_no,
            previous: prev.clone(),
            current: current.to_string(),
        });
    }
    *previous = Some(current.to_string());
}

fn bad_shape(line: usize, key: &str, value: &str) -> StreamFinding {
    StreamFinding::BadShape {
        line,
        key: key.to_string(),
        value: shorten(value),
    }
}

pub(crate) fn render(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unprintable>".to_string())
}

pub(crate) fn shorten(value: &str) -> String {
    const LIMIT: usize = 160;
    if value.len() <= LIMIT {
        return value.to_string();
    }
    let truncated: String = value.chars().take(LIMIT).collect();
    format!("{truncated}...")
}

/// Matches `^(0|[1-9][0-9]*)$`: all digits, no leading zero unless `"0"`.
pub(crate) fn is_digit_string(text: &str) -> bool {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    text.len() == 1 || !text.starts_with('0')
}

/// Matches `^[a-z][a-z0-9_-]*:[A-Za-z0-9_.-]+$` without a regex dependency.
pub(crate) fn is_prefixed_id(text: &str) -> bool {
    let Some(colon) = text.find(':') else {
        return false;
    };
    let (head, tail) = text.split_at(colon);
    is_id_head(head) && is_id_tail(&tail[1..])
}

fn is_id_head(head: &str) -> bool {
    let mut chars = head.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|char| {
        char.is_ascii_lowercase() || char.is_ascii_digit() || char == '_' || char == '-'
    })
}

fn is_id_tail(tail: &str) -> bool {
    if tail.is_empty() {
        return false;
    }
    tail.chars()
        .all(|char| char.is_ascii_alphanumeric() || char == '_' || char == '.' || char == '-')
}

/// Numeric order on canonical digit strings: longer means larger.
fn digit_less_than(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return a.len() < b.len();
    }
    a < b
}
