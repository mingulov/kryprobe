// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto lifecycle session-v1 stream validator.
//!
//! Enforces the T11/P6 session envelope (ADR draft under
//! `evidence/kcrypto-t11/adr-draft.md`) on a JSONL stream: every line
//! carries `schema == kryprobe.kcrypto.lifecycle-session/v1`, `session`
//! is constant, `seq` is dense 1-based, `session_start` is first, exactly
//! one `session_receipt` is last, and every embedded observation `record`
//! validates against payload-v1 BEFORE the envelope admits it.
//!
//! Fail-closed: any defect means the stream must not be evaluated as
//! clean. A stream without a receipt is TRUNCATED (never clean, never
//! partial). Findings are input-free: line numbers and closed-vocabulary
//! words only — rejected bytes could be key material or buffer contents,
//! so no property value, unknown key name, or embedded payload detail is
//! ever echoed.

use crate::KCRYPTO_LIFECYCLE_SESSION_V1;
use crate::validate::MAX_VALIDATE_LINE_BYTES;
use crate::validate::lifecycle_v1::validate_lifecycle_v1;
use serde_json::Value;

/// Closed record-kind vocabulary.
const KINDS: &[&str] = &[
    "session_start",
    "observation",
    "context",
    "coverage",
    "session_receipt",
];

/// Closed receipt-verdict vocabulary.
const VERDICTS: &[&str] = &["clean", "partial", "truncated"];

/// One session-stream defect; empty means the stream validates clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFinding {
    /// The stream holds no records at all.
    EmptyStream,
    /// A line exceeds [`MAX_VALIDATE_LINE_BYTES`] (never parsed — no OOM).
    Overlong {
        /// 1-based physical line number.
        line: usize,
    },
    /// A line is not JSON (the bytes are withheld).
    Unparseable {
        /// 1-based physical line number.
        line: usize,
    },
    /// A record's `schema` is missing or not the session-v1 const (the
    /// offered value is withheld: untrusted input).
    UnknownVersion {
        /// 1-based physical line number.
        line: usize,
    },
    /// A record's `kind` is outside the closed vocabulary.
    BadKind {
        /// 1-based physical line number.
        line: usize,
    },
    /// A required key for the record kind is absent (key names are our
    /// own vocabulary, safe to echo).
    MissingKey {
        /// 1-based physical line number.
        line: usize,
        /// Missing key name.
        key: String,
    },
    /// A key is present but malformed (wrong JSON type or shape).
    BadShape {
        /// 1-based physical line number.
        line: usize,
        /// Offending key name.
        key: String,
        /// What the key must hold (static description, no input).
        expected: String,
    },
    /// The record's `session` differs from the stream's (values withheld).
    SessionMismatch {
        /// 1-based physical line number.
        line: usize,
    },
    /// The record's `seq` breaks the dense 1-based run (numbers only).
    SeqGap {
        /// 1-based physical line number.
        line: usize,
        /// Expected sequence number.
        want: u64,
        /// Observed sequence number.
        got: u64,
    },
    /// The first record is not `session_start`.
    FirstNotStart {
        /// 1-based physical line number (always 1).
        line: usize,
    },
    /// An observation's embedded `record` fails payload-v1 (nested
    /// finding COUNT only — no payload detail).
    BadObservation {
        /// 1-based physical line number.
        line: usize,
        /// Nested payload-v1 finding count.
        nested: usize,
    },
    /// The stream carries no terminal receipt: TRUNCATED, never clean.
    MissingReceipt,
    /// A receipt exists but is not the last record.
    ReceiptNotLast {
        /// 1-based physical line number of the stray receipt.
        line: usize,
    },
    /// More than one receipt exists.
    DuplicateReceipt {
        /// 1-based physical line number of the repeat receipt.
        line: usize,
    },
    /// Individually well-shaped fields contradict each other (a clean
    /// verdict over loss, unfinished work, or a truncated flag).
    InvalidCombination {
        /// 1-based physical line number.
        line: usize,
        /// What contradicts what (closed vocabulary).
        detail: String,
    },
}

impl SessionFinding {
    /// True exactly for the missing-terminal-trailer finding.
    #[must_use]
    pub fn is_missing_receipt(&self) -> bool {
        matches!(self, Self::MissingReceipt)
    }
}

impl std::fmt::Display for SessionFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyStream => write!(f, "session stream is empty"),
            Self::Overlong { line } => write!(f, "line {line}: overlong (refused unparsed)"),
            Self::Unparseable { line } => write!(f, "line {line}: not JSON"),
            Self::UnknownVersion { line } => write!(
                f,
                "line {line}: schema is not '{KCRYPTO_LIFECYCLE_SESSION_V1}'"
            ),
            Self::BadKind { line } => write!(f, "line {line}: kind outside the closed vocabulary"),
            Self::MissingKey { line, key } => write!(f, "line {line}: missing key '{key}'"),
            Self::BadShape {
                line,
                key,
                expected,
            } => {
                write!(f, "line {line}: key '{key}' must hold {expected}")
            }
            Self::SessionMismatch { line } => {
                write!(f, "line {line}: session differs from the stream")
            }
            Self::SeqGap { line, want, got } => {
                write!(
                    f,
                    "line {line}: seq {got} breaks the dense run (want {want})"
                )
            }
            Self::FirstNotStart { line } => {
                write!(f, "line {line}: first record is not session_start")
            }
            Self::BadObservation { line, nested } => write!(
                f,
                "line {line}: embedded record fails payload-v1 ({nested} findings)"
            ),
            Self::MissingReceipt => write!(f, "stream has no terminal receipt (truncated)"),
            Self::ReceiptNotLast { line } => {
                write!(f, "line {line}: receipt is not the last record")
            }
            Self::DuplicateReceipt { line } => write!(f, "line {line}: duplicate receipt"),
            Self::InvalidCombination { line, detail } => {
                write!(f, "line {line}: invalid combination ({detail})")
            }
        }
    }
}

impl std::error::Error for SessionFinding {}

/// Required keys per record kind (beyond the universal
/// `schema`/`kind`/`session`/`seq` header, which every record carries).
fn required_for(kind: &str) -> &'static [&'static str] {
    match kind {
        "session_start" => &[
            "profile",
            "source",
            "evidence_version",
            "rule_version",
            "payload_schema",
        ],
        "observation" => &["record"],
        "context" => &["request_id", "submitter", "execution", "completion"],
        "coverage" => &[
            "admitted",
            "emitted",
            "unfinished",
            "loss",
            "unknown",
            "filtered",
        ],
        "session_receipt" => &[
            "verdict",
            "admitted",
            "emitted",
            "unfinished",
            "loss",
            "truncated",
        ],
        _ => &[],
    }
}

/// Validates one lifecycle session-v1 JSONL stream. Fail-closed: any
/// defect means the stream must not be evaluated as clean. Checks run
/// in layers per record — parse, then header (version/kind/session/seq),
/// then kind shape — plus whole-stream rules (first-is-start,
/// receipt-last-and-unique, receipt combinations).
pub fn validate_lifecycle_session(text: &str) -> Vec<SessionFinding> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        out.push(SessionFinding::EmptyStream);
        return out;
    }
    let mut session: Option<String> = None;
    let mut want_seq: u64 = 1;
    let mut receipt_line: Option<usize> = None;
    let mut receipt_count: usize = 0;
    for (index, line) in lines.iter().enumerate() {
        let no = index + 1;
        if line.len() > MAX_VALIDATE_LINE_BYTES {
            out.push(SessionFinding::Overlong { line: no });
            continue;
        }
        let parsed: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                out.push(SessionFinding::Unparseable { line: no });
                continue;
            }
        };
        let Some(obj) = parsed.as_object() else {
            out.push(SessionFinding::BadShape {
                line: no,
                key: "record".to_owned(),
                expected: "object".to_owned(),
            });
            continue;
        };
        // Header layer: version, kind, session, seq.
        match obj.get("schema") {
            Some(Value::String(found)) if found == KCRYPTO_LIFECYCLE_SESSION_V1 => {}
            _ => {
                out.push(SessionFinding::UnknownVersion { line: no });
                continue;
            }
        }
        let kind = match obj.get("kind").and_then(Value::as_str) {
            Some(kind) if KINDS.contains(&kind) => kind,
            _ => {
                out.push(SessionFinding::BadKind { line: no });
                continue;
            }
        };
        match obj.get("session").and_then(Value::as_str) {
            Some(got) => match session.as_deref() {
                None => session = Some(got.to_owned()),
                Some(first) if first == got => {}
                Some(_) => {
                    out.push(SessionFinding::SessionMismatch { line: no });
                    continue;
                }
            },
            None => {
                out.push(SessionFinding::MissingKey {
                    line: no,
                    key: "session".to_owned(),
                });
                continue;
            }
        }
        match obj.get("seq").and_then(Value::as_u64) {
            Some(got) if got == want_seq => want_seq += 1,
            Some(got) => {
                out.push(SessionFinding::SeqGap {
                    line: no,
                    want: want_seq,
                    got,
                });
                continue;
            }
            None => {
                out.push(SessionFinding::BadShape {
                    line: no,
                    key: "seq".to_owned(),
                    expected: "u64".to_owned(),
                });
                continue;
            }
        }
        if no == 1 && kind != "session_start" {
            out.push(SessionFinding::FirstNotStart { line: no });
            continue;
        }
        // Kind layer: required keys, then kind-specific shapes.
        let mut missing = false;
        for key in required_for(kind) {
            if !obj.contains_key(*key) {
                out.push(SessionFinding::MissingKey {
                    line: no,
                    key: key.to_string(),
                });
                missing = true;
            }
        }
        if missing {
            continue;
        }
        match kind {
            "session_start" => {
                // The envelope validates observations against payload-v1
                // and nothing else: a start record declaring any other
                // payload schema contradicts the envelope's own check.
                let pinned = obj
                    .get("payload_schema")
                    .and_then(Value::as_str)
                    .is_some_and(|schema| schema == crate::KCRYPTO_LIFECYCLE_V1);
                if !pinned {
                    out.push(SessionFinding::BadShape {
                        line: no,
                        key: "payload_schema".to_owned(),
                        expected: "kryprobe.kcrypto.lifecycle/v1".to_owned(),
                    });
                }
            }
            "observation" => {
                let record = &obj["record"];
                let nested = validate_lifecycle_v1(record);
                if !nested.is_empty() {
                    out.push(SessionFinding::BadObservation {
                        line: no,
                        nested: nested.len(),
                    });
                }
            }
            "session_receipt" => {
                receipt_count += 1;
                if receipt_count > 1 {
                    out.push(SessionFinding::DuplicateReceipt { line: no });
                    continue;
                }
                receipt_line = Some(no);
                check_receipt(obj, no, &mut out);
            }
            "coverage" => {
                check_counts(obj, no, &mut out);
            }
            _ => {}
        }
    }
    match receipt_line {
        None => out.push(SessionFinding::MissingReceipt),
        Some(line) if line != lines.len() => out.push(SessionFinding::ReceiptNotLast { line }),
        Some(_) => {}
    }
    out
}

/// Coverage-record counter shapes: u64 counts, `loss` a stage→u64 map.
fn check_counts(obj: &serde_json::Map<String, Value>, line: usize, out: &mut Vec<SessionFinding>) {
    for key in ["admitted", "emitted", "unfinished", "unknown", "filtered"] {
        if obj.get(key).and_then(Value::as_u64).is_none() {
            out.push(SessionFinding::BadShape {
                line,
                key: key.to_owned(),
                expected: "u64".to_owned(),
            });
        }
    }
    if check_loss_map(obj).is_none() {
        out.push(SessionFinding::BadShape {
            line,
            key: "loss".to_owned(),
            expected: "stage->u64 map".to_owned(),
        });
    }
}

/// `loss` must be an object with u64 values (stage names are producer
/// vocabulary — validated for shape, never echoed).
fn check_loss_map(obj: &serde_json::Map<String, Value>) -> Option<u64> {
    let loss = obj.get("loss")?;
    let map = loss.as_object()?;
    let mut total: u64 = 0;
    for value in map.values() {
        total = total.saturating_add(value.as_u64()?);
    }
    Some(total)
}

/// Receipt shapes + combinations: closed verdict, u64 counters, bool
/// truncated flag, and the clean-verdict rules (no truncation, zero
/// loss, no unfinished work).
fn check_receipt(obj: &serde_json::Map<String, Value>, line: usize, out: &mut Vec<SessionFinding>) {
    let verdict = match obj.get("verdict").and_then(Value::as_str) {
        Some(verdict) if VERDICTS.contains(&verdict) => verdict,
        _ => {
            out.push(SessionFinding::BadShape {
                line,
                key: "verdict".to_owned(),
                expected: "clean|partial|truncated".to_owned(),
            });
            return;
        }
    };
    for key in ["admitted", "emitted", "unfinished"] {
        if obj.get(key).and_then(Value::as_u64).is_none() {
            out.push(SessionFinding::BadShape {
                line,
                key: key.to_owned(),
                expected: "u64".to_owned(),
            });
            return;
        }
    }
    let loss_total = match check_loss_map(obj) {
        Some(total) => total,
        None => {
            out.push(SessionFinding::BadShape {
                line,
                key: "loss".to_owned(),
                expected: "stage->u64 map".to_owned(),
            });
            return;
        }
    };
    let truncated = match obj.get("truncated").and_then(Value::as_bool) {
        Some(flag) => flag,
        None => {
            out.push(SessionFinding::BadShape {
                line,
                key: "truncated".to_owned(),
                expected: "bool".to_owned(),
            });
            return;
        }
    };
    if verdict == "clean" {
        if truncated {
            out.push(SessionFinding::InvalidCombination {
                line,
                detail: "clean verdict over truncated=true".to_owned(),
            });
        }
        if loss_total > 0 {
            out.push(SessionFinding::InvalidCombination {
                line,
                detail: "clean verdict over nonzero loss".to_owned(),
            });
        }
        if obj.get("unfinished").and_then(Value::as_u64).unwrap_or(1) > 0 {
            out.push(SessionFinding::InvalidCombination {
                line,
                detail: "clean verdict over unfinished work".to_owned(),
            });
        }
    }
    if verdict == "truncated" && !truncated {
        out.push(SessionFinding::InvalidCombination {
            line,
            detail: "truncated verdict over truncated=false".to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionFinding, validate_lifecycle_session};
    use crate::SessionWriter;
    use serde_json::{Value, json};

    fn observation_record() -> Value {
        json!({
            "schema": "kryprobe.kcrypto.lifecycle/v1",
            "request_id": "fixture:req-1",
            "tfm_id": null,
            "terminal": "sync",
            "status": 0,
            "duration_ns": "120",
        })
    }

    fn clean_stream() -> String {
        let mut writer = SessionWriter::new("session:unit");
        writer
            .session_start("request-lifecycle", "evidence:v1", "rule:v1")
            .expect("start emits");
        writer
            .coverage(2, 2, 0, vec![], 0, 0)
            .expect("coverage emits");
        writer
            .observation(&observation_record())
            .expect("observation emits");
        writer.receipt(true, 2, 2, 0).expect("receipt emits");
        writer.into_string()
    }

    #[test]
    fn schema_file_pins_envelope_contract() {
        // The standalone contract doc stays parseable and keeps the
        // header keys, kind/verdict vocabularies, and version consts
        // the validator enforces (bytes freeze only after review;
        // this pins the doc against rot).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/kcrypto-lifecycle-session-v1.schema.json");
        let text = std::fs::read_to_string(&path).expect("schema file readable");
        let schema: Value = serde_json::from_str(&text).expect("schema file parses");
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("required array");
        for key in ["schema", "kind", "session", "seq"] {
            assert!(
                required.iter().any(|k| k.as_str() == Some(key)),
                "header key {key}"
            );
        }
        let properties = schema.get("properties").expect("properties");
        assert_eq!(
            properties.get("schema").and_then(|s| s.get("const")),
            Some(&json!("kryprobe.kcrypto.lifecycle-session/v1")),
            "envelope version const"
        );
        assert_eq!(
            properties
                .get("payload_schema")
                .and_then(|s| s.get("const")),
            Some(&json!("kryprobe.kcrypto.lifecycle/v1")),
            "payload version pin"
        );
        let kinds = properties
            .get("kind")
            .and_then(|k| k.get("enum"))
            .and_then(Value::as_array)
            .expect("kind enum");
        for kind in [
            "session_start",
            "observation",
            "context",
            "coverage",
            "session_receipt",
        ] {
            assert!(
                kinds.iter().any(|k| k.as_str() == Some(kind)),
                "kind {kind}"
            );
        }
        let verdicts = properties
            .get("verdict")
            .and_then(|v| v.get("enum"))
            .and_then(Value::as_array)
            .expect("verdict enum");
        for verdict in ["clean", "partial", "truncated"] {
            assert!(
                verdicts.iter().any(|v| v.as_str() == Some(verdict)),
                "verdict {verdict}"
            );
        }
    }

    #[test]
    fn writer_round_trip_validates_clean() {
        assert!(validate_lifecycle_session(&clean_stream()).is_empty());
    }

    #[test]
    fn writer_is_byte_deterministic() {
        assert_eq!(clean_stream(), clean_stream());
    }

    #[test]
    fn invalid_observation_refuses_at_writer() {
        let mut writer = SessionWriter::new("session:refuse");
        writer
            .session_start("request-lifecycle", "evidence:v1", "rule:v1")
            .expect("start emits");
        let before = writer.finish().to_owned();
        let mut bad = observation_record();
        bad.as_object_mut().expect("object").remove("status");
        let err = writer
            .observation(&bad)
            .expect_err("invalid record must refuse");
        assert!(
            matches!(
                err,
                crate::SessionWriteError::InvalidObservation { nested } if nested > 0
            ),
            "typed refusal: {err}"
        );
        assert_eq!(writer.finish(), before, "failed emit appends nothing");
    }

    #[test]
    fn seq_gap_and_session_change_refuse() {
        let gapped = clean_stream().replacen("\"seq\":2", "\"seq\":3", 1);
        assert!(
            validate_lifecycle_session(&gapped)
                .iter()
                .any(|f| matches!(f, SessionFinding::SeqGap { .. })),
            "seq gap: {gapped}"
        );
        let moved = clean_stream().replacen("session:unit", "session:other", 1);
        assert!(
            validate_lifecycle_session(&moved)
                .iter()
                .any(|f| matches!(f, SessionFinding::SessionMismatch { .. })),
            "session change must refuse"
        );
    }

    fn start_line(seq: u64) -> String {
        format!(
            "{{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"session_start\",\
             \"session\":\"session:place\",\"seq\":{seq},\"profile\":\"request-lifecycle\",\
             \"source\":\"kernel-crypto\",\"evidence_version\":\"evidence:v1\",\
             \"rule_version\":\"rule:v1\",\
             \"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\"}}"
        )
    }

    fn receipt_line(seq: u64) -> String {
        format!(
            "{{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"session_receipt\",\
             \"session\":\"session:place\",\"seq\":{seq},\"verdict\":\"clean\",\
             \"admitted\":0,\"emitted\":0,\"unfinished\":0,\"loss\":{{}},\"truncated\":false}}"
        )
    }

    fn coverage_line(seq: u64) -> String {
        format!(
            "{{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"coverage\",\
             \"session\":\"session:place\",\"seq\":{seq},\"admitted\":0,\"emitted\":0,\
             \"unfinished\":0,\"loss\":{{}},\"unknown\":0,\"filtered\":0}}"
        )
    }

    #[test]
    fn receipt_placement_is_unique_and_last() {
        // Control: start + receipt validates clean.
        let clean = format!("{}\n{}\n", start_line(1), receipt_line(2));
        assert!(validate_lifecycle_session(&clean).is_empty());
        // A record after the receipt: receipt is not last.
        let stray = format!(
            "{}\n{}\n{}\n",
            start_line(1),
            receipt_line(2),
            coverage_line(3)
        );
        assert!(
            validate_lifecycle_session(&stray)
                .iter()
                .any(|f| matches!(f, SessionFinding::ReceiptNotLast { line: 2 })),
            "receipt must be last"
        );
        // Two receipts: the repeat is named.
        let dupla = format!(
            "{}\n{}\n{}\n",
            start_line(1),
            receipt_line(2),
            receipt_line(3)
        );
        assert!(
            validate_lifecycle_session(&dupla)
                .iter()
                .any(|f| matches!(f, SessionFinding::DuplicateReceipt { line: 3 })),
            "duplicate receipt must refuse"
        );
    }

    #[test]
    fn clean_verdict_requires_zero_loss_and_no_unfinished() {
        let mut writer = SessionWriter::new("session:lossy");
        writer
            .session_start("request-lifecycle", "evidence:v1", "rule:v1")
            .expect("start emits");
        writer
            .receipt_partial(2, 1, 1, vec![("reserve", 3)])
            .expect("partial receipt emits");
        let text = writer.into_string();
        assert!(
            validate_lifecycle_session(&text).is_empty(),
            "honest partial receipt validates: {text}"
        );
        // Rewrite the verdict to clean: the validator must refuse a
        // clean claim over loss + unfinished work.
        let lied = text.replacen("\"partial\"", "\"clean\"", 1);
        let findings = validate_lifecycle_session(&lied);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, SessionFinding::InvalidCombination { .. })),
            "clean over loss/unfinished must refuse: {findings:?}"
        );
    }

    #[test]
    fn malformed_lines_refuse_input_free() {
        assert_eq!(
            validate_lifecycle_session(""),
            vec![SessionFinding::EmptyStream]
        );
        let garbage = "{not json}\n";
        assert!(
            validate_lifecycle_session(garbage)
                .iter()
                .any(|f| matches!(f, SessionFinding::Unparseable { line: 1 })),
            "unparseable line refuses"
        );
        // Findings never echo rejected bytes.
        for finding in validate_lifecycle_session(garbage) {
            assert!(
                !finding.to_string().contains("not json"),
                "input-free: {finding}"
            );
        }
    }
}
