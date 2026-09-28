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

use crate::validate::MAX_VALIDATE_LINE_BYTES;
use crate::validate::lifecycle_v1::validate_lifecycle_v1;
use crate::{KCRYPTO_CONTEXT_V1, KCRYPTO_LIFECYCLE_SESSION_V1};
use serde_json::Value;
use std::collections::BTreeMap;

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

/// Closed execution-kind vocabulary (context-v1).
const EXECUTION_KINDS: &[&str] = &["process", "worker", "softirq", "unknown"];

/// Closed stack-marker vocabulary (context-v1).
const STACK_MARKERS: &[&str] = &["missing", "sampled", "full"];

/// Closed context-v1 object key sets (extra keys refuse — the
/// shapes are closed; only the ENVELOPE stays open to extra keys).
const SUBMITTER_KEYS: &[&str] = &[
    "pid",
    "tgid",
    "start_marker",
    "comm",
    "uid",
    "cgroup",
    "ppid",
    "stack",
];
const EXECUTION_KEYS: &[&str] = &["kind", "lifetime", "handoff"];
const COMPLETION_KEYS: &[&str] = &["kind", "lifetime", "handoff", "follows_request"];
const LIFETIME_KEYS: &[&str] = &["pid", "tgid", "start_marker"];

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
    /// More than one `session_start` exists (honest producers emit
    /// exactly one — a second start is a splice/corruption marker).
    DuplicateStart {
        /// 1-based physical line number of the repeat start.
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
            Self::DuplicateStart { line } => write!(f, "line {line}: duplicate session_start"),
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
        "context" => &[
            "context_schema",
            "request_id",
            "submitter",
            "execution",
            "completion",
        ],
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
    // P6-N1 whole-stream state: start uniqueness + receipt loss vs
    // every coverage loss (monotonicity checked after the loop).
    let mut start_count: usize = 0;
    let mut coverage_losses: Vec<(usize, BTreeMap<String, u64>)> = Vec::new();
    let mut receipt_loss: Option<BTreeMap<String, u64>> = None;
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
            Some(got) => {
                // P6-N2: the header session is non-empty and matches
                // the schema pattern on EVERY record (a malformed id
                // is a stream defect even when constant).
                if !session_shape_ok(got) {
                    out.push(SessionFinding::BadShape {
                        line: no,
                        key: "session".to_owned(),
                        expected: "prefixed session id".to_owned(),
                    });
                }
                match session.as_deref() {
                    None => session = Some(got.to_owned()),
                    Some(first) if first == got => {}
                    Some(_) => {
                        out.push(SessionFinding::SessionMismatch { line: no });
                        continue;
                    }
                }
            }
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
                // P6-N1: honest producers emit exactly one start.
                start_count += 1;
                if start_count > 1 {
                    out.push(SessionFinding::DuplicateStart { line: no });
                    continue;
                }
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
                // P6-N2: start identity/config fields are typed
                // strings (never numbers, nulls, or arrays).
                for key in ["profile", "source", "evidence_version", "rule_version"] {
                    if !obj.get(key).is_some_and(Value::is_string) {
                        out.push(SessionFinding::BadShape {
                            line: no,
                            key: key.to_owned(),
                            expected: "string".to_owned(),
                        });
                    }
                }
            }
            "context" => {
                check_context(obj, no, &mut out);
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
                receipt_loss = check_receipt(obj, no, &mut out);
            }
            "coverage" => {
                check_counts(obj, no, &mut out);
                // P6-N1: keep well-shaped coverage loss maps for the
                // receipt-monotonicity check (misshapen maps already
                // reported above — never double-counted).
                if let Some(map) = loss_map_of(obj) {
                    coverage_losses.push((no, map));
                }
            }
            _ => {}
        }
    }
    match receipt_line {
        None => out.push(SessionFinding::MissingReceipt),
        Some(line) if line != lines.len() => out.push(SessionFinding::ReceiptNotLast { line }),
        Some(_) => {}
    }
    // P6-N1: receipt per-stage loss covers EVERY coverage per-stage
    // loss (the honest producer emits identical maps from the same
    // totals — a receipt below any coverage stage contradicts it).
    // Input-free: stage names and counts never echo.
    if let (Some(line), Some(receipt)) = (receipt_line, receipt_loss.as_ref()) {
        for (_, coverage) in &coverage_losses {
            let covered = coverage
                .iter()
                .all(|(stage, count)| receipt.get(stage).unwrap_or(&0) >= count);
            if !covered {
                out.push(SessionFinding::InvalidCombination {
                    line,
                    detail: "receipt loss below coverage loss".to_owned(),
                });
            }
        }
    }
    out
}

/// Header `session` shape (P6-N2): non-empty and matching the
/// schema pattern `^[a-z][a-z0-9_-]*:[A-Za-z0-9_.-]+$` (hand-rolled —
/// the report crate takes no regex dependency).
fn session_shape_ok(session: &str) -> bool {
    let Some((prefix, rest)) = session.split_once(':') else {
        return false;
    };
    let mut prefix_chars = prefix.chars();
    if !prefix_chars.next().is_some_and(|c| c.is_ascii_lowercase()) {
        return false;
    }
    if !prefix_chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
        return false;
    }
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Pushes a [`SessionFinding::BadShape`] (closed key + static
/// expectation — input-free by construction).
fn bad_shape(out: &mut Vec<SessionFinding>, line: usize, key: &str, expected: &str) {
    out.push(SessionFinding::BadShape {
        line,
        key: key.to_owned(),
        expected: expected.to_owned(),
    });
}

/// Requires the closed key set of a context-v1 object: every
/// required key present, no extras. Returns false when any defect
/// was pushed (callers skip field checks then — one defect per
/// object, never a cascade over untrusted shapes).
fn require_closed_keys(
    obj: &serde_json::Map<String, Value>,
    line: usize,
    key: &str,
    required: &[&str],
    out: &mut Vec<SessionFinding>,
) -> bool {
    let mut ok = true;
    for want in required {
        if !obj.contains_key(*want) {
            out.push(SessionFinding::MissingKey {
                line,
                key: (*want).to_owned(),
            });
            ok = false;
        }
    }
    if obj.keys().any(|got| !required.contains(&got.as_str())) {
        // Input-free: the foreign key NAME is untrusted input and
        // could smuggle key material — name our key, never theirs.
        bad_shape(out, line, key, "closed context-v1 object");
        ok = false;
    }
    ok
}

/// JSON u32 (a u64 that fits — pid/tgid/uid/ppid words).
fn as_u32(value: &Value) -> Option<u32> {
    value.as_u64().and_then(|n| u32::try_from(n).ok())
}

/// One task-lifetime shape: closed keys, u32 pid/tgid, nullable
/// u64 start marker. `key` is OUR vocabulary word for findings.
fn check_lifetime(value: &Value, line: usize, key: &str, out: &mut Vec<SessionFinding>) {
    let Some(obj) = value.as_object() else {
        bad_shape(out, line, key, "lifetime object|null");
        return;
    };
    if !require_closed_keys(obj, line, key, LIFETIME_KEYS, out) {
        return;
    }
    for word in ["pid", "tgid"] {
        if obj.get(word).and_then(as_u32).is_none() {
            bad_shape(out, line, word, "u32");
        }
    }
    if !matches!(obj.get("start_marker"), Some(Value::Null) | None)
        && obj.get("start_marker").and_then(Value::as_u64).is_none()
    {
        bad_shape(out, line, "start_marker", "u64|null");
    }
}

/// Nullable lifetime (explicit-unavailable is null, never guessed).
fn check_lifetime_or_null(value: &Value, line: usize, key: &str, out: &mut Vec<SessionFinding>) {
    if value.is_null() {
        return;
    }
    check_lifetime(value, line, key, out);
}

/// One execution/completion site shape: closed keys, closed kind,
/// nullable proving lifetimes. `completion` additionally requires
/// `follows_request: true`.
fn check_site(
    value: &Value,
    line: usize,
    key: &str,
    completion: bool,
    out: &mut Vec<SessionFinding>,
) {
    let Some(obj) = value.as_object() else {
        bad_shape(
            out,
            line,
            key,
            if completion {
                "completion object|null"
            } else {
                "execution object"
            },
        );
        return;
    };
    let required: &[&str] = if completion {
        COMPLETION_KEYS
    } else {
        EXECUTION_KEYS
    };
    if !require_closed_keys(obj, line, key, required, out) {
        return;
    }
    let kind = obj.get("kind").and_then(Value::as_str);
    if kind.is_none_or(|k| !EXECUTION_KINDS.contains(&k)) {
        bad_shape(out, line, "kind", "process|worker|softirq|unknown");
        return;
    }
    check_lifetime_or_null(&obj["lifetime"], line, "lifetime", out);
    check_lifetime_or_null(&obj["handoff"], line, "handoff", out);
    // An unknown site names NOTHING: a lifetime beside `unknown`
    // contradicts the kind (closed detail — input-free).
    if kind == Some("unknown") && (!obj["lifetime"].is_null() || !obj["handoff"].is_null()) {
        out.push(SessionFinding::InvalidCombination {
            line,
            detail: "unknown execution names a lifetime".to_owned(),
        });
    }
    if completion && obj.get("follows_request") != Some(&Value::Bool(true)) {
        bad_shape(out, line, "follows_request", "true");
    }
}

/// Context-record shapes (P6-N2, replacing the accept-all fallthrough):
/// pinned context-v1 marker, string request id, and the three closed
/// context shapes (submitter nullable, execution required, completion
/// nullable — each independently unavailable, never guessed).
fn check_context(obj: &serde_json::Map<String, Value>, line: usize, out: &mut Vec<SessionFinding>) {
    if obj
        .get("context_schema")
        .and_then(Value::as_str)
        .is_none_or(|schema| schema != KCRYPTO_CONTEXT_V1)
    {
        bad_shape(out, line, "context_schema", "kryprobe.kcrypto.context/v1");
    }
    if !obj.get("request_id").is_some_and(Value::is_string) {
        bad_shape(out, line, "request_id", "string");
    }
    if let Some(value) = obj.get("submitter") {
        check_submitter(value, line, out);
    }
    match obj.get("execution") {
        Some(value) => check_site(value, line, "execution", false, out),
        None => bad_shape(out, line, "execution", "execution object"),
    }
    // A null completion means the terminal edge has not landed
    // yet — valid, never a guess at a landing site.
    if let Some(value) = obj.get("completion")
        && !value.is_null()
    {
        check_site(value, line, "completion", true, out);
    }
}

/// One submitter shape: null (explicitly unavailable) or the closed
/// 8-key object with typed words (nullable scalars stay null, never
/// zero-filled).
fn check_submitter(value: &Value, line: usize, out: &mut Vec<SessionFinding>) {
    if value.is_null() {
        return;
    }
    let Some(sub) = value.as_object() else {
        bad_shape(out, line, "submitter", "submitter object|null");
        return;
    };
    if !require_closed_keys(sub, line, "submitter", SUBMITTER_KEYS, out) {
        return;
    }
    for word in ["pid", "tgid"] {
        if sub.get(word).and_then(as_u32).is_none() {
            bad_shape(out, line, word, "u32");
        }
    }
    if !matches!(sub.get("start_marker"), Some(Value::Null) | None)
        && sub.get("start_marker").and_then(Value::as_u64).is_none()
    {
        bad_shape(out, line, "start_marker", "u64|null");
    }
    if !matches!(sub.get("comm"), Some(Value::Null) | None)
        && !sub.get("comm").is_some_and(Value::is_string)
    {
        bad_shape(out, line, "comm", "string|null");
    }
    for word in ["uid", "ppid"] {
        if !matches!(sub.get(word), Some(Value::Null) | None)
            && sub.get(word).and_then(as_u32).is_none()
        {
            bad_shape(out, line, word, "u32|null");
        }
    }
    if !matches!(sub.get("cgroup"), Some(Value::Null) | None)
        && sub.get("cgroup").and_then(Value::as_u64).is_none()
    {
        bad_shape(out, line, "cgroup", "u64|null");
    }
    if !matches!(sub.get("stack"), Some(Value::Null) | None)
        && sub
            .get("stack")
            .and_then(Value::as_str)
            .is_none_or(|marker| !STACK_MARKERS.contains(&marker))
    {
        bad_shape(out, line, "stack", "missing|sampled|full|null");
    }
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
/// vocabulary — validated for shape, never echoed). Returns the map
/// itself (P6-N1 monotonicity compares per-stage counts).
fn loss_map_of(obj: &serde_json::Map<String, Value>) -> Option<BTreeMap<String, u64>> {
    let loss = obj.get("loss")?;
    let map = loss.as_object()?;
    let mut stages = BTreeMap::new();
    for (stage, value) in map {
        stages.insert(stage.clone(), value.as_u64()?);
    }
    Some(stages)
}

/// `loss` total (saturating — an overflowed total reads huge, never
/// wraps to a clean-looking zero).
fn check_loss_map(obj: &serde_json::Map<String, Value>) -> Option<u64> {
    loss_map_of(obj).map(|map| {
        map.values()
            .fold(0u64, |total, count| total.saturating_add(*count))
    })
}

/// Receipt shapes + combinations: closed verdict, u64 counters, bool
/// truncated flag, the reducer equation (P6-N1: post-finish
/// `admitted == emitted` exactly and `unfinished <= emitted` — the
/// reducer drains all pending at finish and the live path runs
/// `finish_stop` before `from_ledger`), and the clean-verdict rules
/// (no truncation, zero loss, no unfinished work). Returns the loss
/// map when the receipt is well-shaped (for monotonicity).
fn check_receipt(
    obj: &serde_json::Map<String, Value>,
    line: usize,
    out: &mut Vec<SessionFinding>,
) -> Option<BTreeMap<String, u64>> {
    let verdict = match obj.get("verdict").and_then(Value::as_str) {
        Some(verdict) if VERDICTS.contains(&verdict) => verdict,
        _ => {
            out.push(SessionFinding::BadShape {
                line,
                key: "verdict".to_owned(),
                expected: "clean|partial|truncated".to_owned(),
            });
            return None;
        }
    };
    for key in ["admitted", "emitted", "unfinished"] {
        if obj.get(key).and_then(Value::as_u64).is_none() {
            out.push(SessionFinding::BadShape {
                line,
                key: key.to_owned(),
                expected: "u64".to_owned(),
            });
            return None;
        }
    }
    let admitted = obj.get("admitted").and_then(Value::as_u64).unwrap_or(0);
    let emitted = obj.get("emitted").and_then(Value::as_u64).unwrap_or(0);
    let unfinished = obj.get("unfinished").and_then(Value::as_u64).unwrap_or(0);
    // The equation holds on EVERY verdict (it is reducer math, not a
    // cleanliness claim): post-finish admitted == emitted exactly,
    // and unfinished (finish-drained truthless) stays within emitted.
    if admitted != emitted {
        out.push(SessionFinding::InvalidCombination {
            line,
            detail: "receipt admitted != emitted".to_owned(),
        });
    }
    if unfinished > emitted {
        out.push(SessionFinding::InvalidCombination {
            line,
            detail: "receipt unfinished above emitted".to_owned(),
        });
    }
    let loss_map = match loss_map_of(obj) {
        Some(map) => map,
        None => {
            out.push(SessionFinding::BadShape {
                line,
                key: "loss".to_owned(),
                expected: "stage->u64 map".to_owned(),
            });
            return None;
        }
    };
    let loss_total: u64 = loss_map
        .values()
        .fold(0u64, |total, count| total.saturating_add(*count));
    let truncated = match obj.get("truncated").and_then(Value::as_bool) {
        Some(flag) => flag,
        None => {
            out.push(SessionFinding::BadShape {
                line,
                key: "truncated".to_owned(),
                expected: "bool".to_owned(),
            });
            return None;
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
    Some(loss_map)
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
        // P6-N2: the context-v1 wire pin — marker const, closed
        // submitter/execution/completion shapes (additionalProperties
        // false INSIDE the context objects; the envelope itself
        // stays open), and the lifetime def.
        assert_eq!(
            properties
                .get("context_schema")
                .and_then(|s| s.get("const")),
            Some(&json!("kryprobe.kcrypto.context/v1")),
            "context-v1 marker const"
        );
        for key in ["submitter", "execution", "completion"] {
            let shape = properties.get(key).expect("context shape");
            assert_eq!(
                shape.get("additionalProperties"),
                Some(&json!(false)),
                "{key} is closed"
            );
            assert!(
                shape
                    .get("required")
                    .and_then(Value::as_array)
                    .is_some_and(|required| !required.is_empty()),
                "{key} pins required keys"
            );
        }
        let stacks = properties
            .get("submitter")
            .and_then(|s| s.get("properties"))
            .and_then(|p| p.get("stack"))
            .and_then(|s| s.get("enum"))
            .and_then(Value::as_array)
            .expect("stack enum");
        for marker in ["missing", "sampled", "full"] {
            assert!(
                stacks.iter().any(|m| m.as_str() == Some(marker)),
                "stack marker {marker}"
            );
        }
        let kinds = properties
            .get("execution")
            .and_then(|e| e.get("properties"))
            .and_then(|p| p.get("kind"))
            .and_then(|k| k.get("enum"))
            .and_then(Value::as_array)
            .expect("execution kind enum");
        for kind in ["process", "worker", "softirq", "unknown"] {
            assert!(
                kinds.iter().any(|k| k.as_str() == Some(kind)),
                "execution kind {kind}"
            );
        }
        assert_eq!(
            properties
                .get("completion")
                .and_then(|c| c.get("properties"))
                .and_then(|p| p.get("follows_request"))
                .and_then(|f| f.get("const")),
            Some(&json!(true)),
            "completion follows its request"
        );
        assert!(
            schema
                .get("$defs")
                .and_then(|defs| defs.get("lifetime"))
                .is_some(),
            "lifetime def"
        );
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
            .receipt_partial(2, 2, 1, vec![("reserve", 3)])
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

    /// Reviewer round-1 bad-context probe, byte-exact: numeric
    /// request_id, v99 context marker, sentinel keys in submitter,
    /// string execution, array completion. Must refuse (P6-N2).
    const BAD_CONTEXT_PROBE: &str = "{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":\"10\",\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":0,\"terminal\":\"sync\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\"}\n{\"completion\":[1,2,3],\"context_schema\":\"kryprobe.kcrypto.context/v99\",\"execution\":\"unversioned-garbage\",\"kind\":\"context\",\"request_id\":42,\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\",\"submitter\":{\"arbitrary_buffer\":\"REVIEW_SENTINEL\",\"raw_kernel_pointer\":\"REVIEW_SENTINEL\"}}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":5,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";

    #[test]
    fn reviewer_bad_context_profile_refuses() {
        let findings = validate_lifecycle_session(BAD_CONTEXT_PROBE);
        assert!(
            !findings.is_empty(),
            "garbage context profile must refuse (P6-N2)"
        );
        // Input-free: the sentinel bytes never echo.
        for finding in &findings {
            assert!(
                !finding.to_string().contains("REVIEW_SENTINEL"),
                "input-free: {finding}"
            );
        }
    }

    #[test]
    fn bad_start_field_types_refuse() {
        // Reviewer probe: numeric profile, null source, array
        // evidence_version. Start fields are typed strings (P6-N2).
        let probe = "{\"evidence_version\":[],\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":42,\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":null}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":\"10\",\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":0,\"terminal\":\"sync\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";
        assert!(
            !validate_lifecycle_session(probe).is_empty(),
            "mistyped start fields must refuse (P6-N2)"
        );
    }

    #[test]
    fn empty_session_refuses() {
        // Reviewer probe: constant-but-empty session. The header
        // session is non-empty and matches the schema pattern (P6-N2).
        let probe = "{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"\",\"source\":\"kernel-crypto\"}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":\"10\",\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":0,\"terminal\":\"sync\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";
        assert!(
            !validate_lifecycle_session(probe).is_empty(),
            "empty session must refuse (P6-N2)"
        );
    }

    #[test]
    fn session_shape_matches_schema_pattern() {
        // The header session matches the schema pattern
        // `^[a-z][a-z0-9_-]*:[A-Za-z0-9_.-]+$` (P6-N2): prefixed ids
        // pass, unprefixed/empty/malformed refuse.
        let stream_with = |session: &str| {
            format!(
                "{{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"session_start\",\"session\":\"{session}\",\"seq\":1,\"profile\":\"request-lifecycle\",\"source\":\"kernel-crypto\",\"evidence_version\":\"evidence:v1\",\"rule_version\":\"rule:v1\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\"}}\n{}",
                receipt_line(2).replace("session:place", session)
            )
        };
        for good in ["session:review", "live:run", "a:b", "s9:x-y_z.0"] {
            assert!(
                validate_lifecycle_session(&stream_with(good)).is_empty(),
                "session {good} validates"
            );
        }
        for bad in [
            "",
            "nosuchcolon",
            "SESSION:x",
            "1x:y",
            "a:",
            "a:b c",
            "a:b/c",
        ] {
            assert!(
                !validate_lifecycle_session(&stream_with(bad)).is_empty(),
                "session {bad:?} must refuse"
            );
        }
    }

    #[test]
    fn unknown_extra_envelope_keys_stay_permitted() {
        // Coordinator-rejected sub-leg, pinned PERMITTED (P6-N2):
        // unknown EXTRA envelope keys refuse nothing — the schema
        // sets no additionalProperties at the envelope level.
        let probe = "{\"arbitrary_buffer\":\"REVIEW_SENTINEL\",\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":\"10\",\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":0,\"terminal\":\"sync\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";
        assert!(
            validate_lifecycle_session(probe).is_empty(),
            "extra envelope keys stay permitted (rejected sub-leg, pinned)"
        );
    }

    fn honest_context_line() -> String {
        "{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"context\",\"session\":\"session:ctx\",\"seq\":3,\"context_schema\":\"kryprobe.kcrypto.context/v1\",\"request_id\":\"req:ctx-1\",\"submitter\":{\"pid\":101,\"tgid\":100,\"start_marker\":50000,\"comm\":\"bash\",\"uid\":1000,\"cgroup\":7,\"ppid\":1,\"stack\":\"sampled\"},\"execution\":{\"kind\":\"process\",\"lifetime\":{\"pid\":101,\"tgid\":100,\"start_marker\":50000},\"handoff\":null},\"completion\":{\"kind\":\"process\",\"lifetime\":{\"pid\":101,\"tgid\":100,\"start_marker\":50000},\"handoff\":null,\"follows_request\":true}}".to_owned()
    }

    #[test]
    fn honest_context_record_validates() {
        // Positive control (P6-N2): a fully-shaped context-v1 record
        // rides a clean stream.
        let stream = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            start_line(1).replace("session:place", "session:ctx"),
            "{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"observation\",\"session\":\"session:ctx\",\"seq\":2,\"record\":{\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"request_id\":\"req:ctx-1\",\"tfm_id\":null,\"terminal\":\"sync\",\"status\":0,\"duration_ns\":\"10\"}}",
            honest_context_line(),
            coverage_line(4).replace("session:place", "session:ctx"),
            receipt_line(5).replace("session:place", "session:ctx"),
        );
        assert!(
            validate_lifecycle_session(&stream).is_empty(),
            "honest context validates: {}",
            validate_lifecycle_session(&stream)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    fn unobserved_context_line() -> String {
        "{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"context\",\"session\":\"session:ctx\",\"seq\":3,\"context_schema\":\"kryprobe.kcrypto.context/v1\",\"request_id\":\"req:ctx-9\",\"submitter\":null,\"execution\":{\"kind\":\"unknown\",\"lifetime\":null,\"handoff\":null},\"completion\":null}".to_owned()
    }

    #[test]
    fn unobserved_contexts_validate_explicitly() {
        // Positive control (P6-N2): null submitter, unknown
        // execution, null completion — the explicit-unavailable
        // wire shape validates.
        let stream = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            start_line(1).replace("session:place", "session:ctx"),
            "{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"observation\",\"session\":\"session:ctx\",\"seq\":2,\"record\":{\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"request_id\":\"req:ctx-9\",\"tfm_id\":null,\"terminal\":\"unknown\",\"status\":null,\"duration_ns\":null}}",
            unobserved_context_line(),
            coverage_line(4).replace("session:place", "session:ctx"),
            receipt_line(5).replace("session:place", "session:ctx"),
        );
        assert!(
            validate_lifecycle_session(&stream).is_empty(),
            "unobserved context validates"
        );
    }

    #[test]
    fn unknown_execution_naming_a_lifetime_refuses() {
        // An `unknown` site beside a non-null lifetime contradicts
        // the kind (P6-N2).
        let line = unobserved_context_line().replace(
            "\"execution\":{\"kind\":\"unknown\",\"lifetime\":null,\"handoff\":null}",
            "\"execution\":{\"kind\":\"unknown\",\"lifetime\":{\"pid\":1,\"tgid\":1,\"start_marker\":null},\"handoff\":null}",
        );
        let stream = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            start_line(1).replace("session:place", "session:ctx"),
            "{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"observation\",\"session\":\"session:ctx\",\"seq\":2,\"record\":{\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"request_id\":\"req:ctx-9\",\"tfm_id\":null,\"terminal\":\"unknown\",\"status\":null,\"duration_ns\":null}}",
            line,
            coverage_line(4).replace("session:place", "session:ctx"),
            receipt_line(5).replace("session:place", "session:ctx"),
        );
        assert!(
            validate_lifecycle_session(&stream)
                .iter()
                .any(|f| matches!(f, SessionFinding::InvalidCombination { .. })),
            "unknown site naming a lifetime must refuse"
        );
    }

    /// Reviewer round-1 broken-equation probe, byte-exact: receipt
    /// admitted/emitted 500/0 over a clean claim. Must refuse (P6-N1).
    const BROKEN_EQUATION_PROBE: &str = "{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":\"10\",\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":0,\"terminal\":\"sync\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":500,\"emitted\":0,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";

    #[test]
    fn broken_receipt_equation_refuses() {
        let findings = validate_lifecycle_session(BROKEN_EQUATION_PROBE);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, SessionFinding::InvalidCombination { .. })),
            "500/0 receipt must refuse the equation (P6-N1): {findings:?}"
        );
    }

    #[test]
    fn duplicate_session_start_refuses() {
        // Reviewer probe: honest producers emit exactly one start —
        // a second start is a splice/corruption marker (P6-N1).
        let probe = "{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":\"10\",\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":0,\"terminal\":\"sync\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":5,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";
        assert!(
            !validate_lifecycle_session(probe).is_empty(),
            "duplicate session_start must refuse (P6-N1)"
        );
    }

    #[test]
    fn receipt_loss_below_coverage_refuses() {
        // Reviewer probe: coverage counts kernel.reserve=9 while the
        // receipt claims empty loss — the receipt per-stage loss must
        // cover every coverage per-stage loss (P6-N1).
        let probe = "{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":\"10\",\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":0,\"terminal\":\"sync\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{\"kernel.reserve\":9},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";
        let findings = validate_lifecycle_session(probe);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, SessionFinding::InvalidCombination { .. })),
            "loss below coverage must refuse (P6-N1): {findings:?}"
        );
        for finding in &findings {
            assert!(
                !finding.to_string().contains("kernel.reserve"),
                "stage names never echo: {finding}"
            );
        }
    }

    #[test]
    fn unfinished_above_emitted_refuses() {
        // `unfinished` is a subset of `emitted` (drained truthless by
        // finish): unfinished > emitted contradicts the equation.
        let stream = format!(
            "{}\n{}\n",
            start_line(1),
            receipt_line(2)
                .replacen("\"emitted\":0", "\"emitted\":1", 1)
                .replacen("\"unfinished\":0", "\"unfinished\":2", 1)
                .replacen("\"clean\"", "\"partial\"", 1),
        );
        assert!(
            validate_lifecycle_session(&stream)
                .iter()
                .any(|f| matches!(f, SessionFinding::InvalidCombination { .. })),
            "unfinished above emitted must refuse (P6-N1)"
        );
    }

    #[test]
    fn honest_partial_receipt_with_loss_superset_validates() {
        // Positive control (P6-N1): honest 4/4/0 guest-shaped receipt
        // over a coverage record with a per-stage loss the receipt
        // covers validates.
        let stream = format!(
            "{}\n{}\n{}\n",
            start_line(1),
            "{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"coverage\",\"session\":\"session:place\",\"seq\":2,\"admitted\":4,\"emitted\":4,\"unfinished\":0,\"loss\":{\"decode.bad_records\":2},\"unknown\":0,\"filtered\":0}",
            "{\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"kind\":\"session_receipt\",\"session\":\"session:place\",\"seq\":3,\"verdict\":\"partial\",\"admitted\":4,\"emitted\":4,\"unfinished\":0,\"loss\":{\"decode.bad_records\":2},\"truncated\":false}",
        );
        assert!(
            validate_lifecycle_session(&stream).is_empty(),
            "honest loss-carrying partial validates"
        );
    }

    #[test]
    fn removed_observation_stays_permitted() {
        // Coordinator-REJECTED leg, pinned PERMITTED (P6-N1): the
        // equation is receipt-side (admitted == emitted); the
        // observation COUNT is not reconciled against emitted (the
        // pinned clean control itself emits 2 with one observation,
        // and the omitted-counter design counts driver-side drops).
        let probe = "{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":0}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";
        assert!(
            validate_lifecycle_session(probe).is_empty(),
            "observation-count reconciliation stays out (rejected leg, pinned)"
        );
    }

    #[test]
    fn unknown_terminal_clean_receipt_stays_permitted() {
        // Coordinator-REJECTED leg, pinned PERMITTED (P6-N1): the ADR
        // clean rule omits unknown — Unknown terminals are honest
        // P4/P5 accounting and the receipt carries no unknown field.
        let probe = "{\"evidence_version\":\"evidence:v1\",\"kind\":\"session_start\",\"payload_schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"profile\":\"request-lifecycle\",\"rule_version\":\"rule:v1\",\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":1,\"session\":\"session:review\",\"source\":\"kernel-crypto\"}\n{\"kind\":\"observation\",\"record\":{\"duration_ns\":null,\"request_id\":\"req:1\",\"schema\":\"kryprobe.kcrypto.lifecycle/v1\",\"status\":null,\"terminal\":\"unknown\",\"tfm_id\":null},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":2,\"session\":\"session:review\"}\n{\"admitted\":1,\"emitted\":1,\"filtered\":0,\"kind\":\"coverage\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":3,\"session\":\"session:review\",\"unfinished\":0,\"unknown\":1}\n{\"admitted\":1,\"emitted\":1,\"kind\":\"session_receipt\",\"loss\":{},\"schema\":\"kryprobe.kcrypto.lifecycle-session/v1\",\"seq\":4,\"session\":\"session:review\",\"truncated\":false,\"unfinished\":0,\"verdict\":\"clean\"}\n";
        assert!(
            validate_lifecycle_session(probe).is_empty(),
            "unknown-terminal clean stays permitted (rejected leg, pinned)"
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
