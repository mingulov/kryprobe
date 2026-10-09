// SPDX-License-Identifier: GPL-3.0-or-later
//! workload-report-v1 validator + schema dispatch (ADR-0008 §(i), as
//! tightened by the Stage 2A contract ADR).
//!
//! Enforces `schemas/workload-report-v1.schema.json` on a standalone
//! report value: required keys, wire shapes (including every nested
//! object), the version const, and the matched/nonmatched/unknown
//! partition invariant. Unknown schema values fail closed. The schema
//! bytes are freeze-pinned to a FIXED digest (E01) with drift detection,
//! mirroring event-v0. Findings never echo untrusted input bytes.
//!
//! Tightening notes (G05.1/G05.2): the v1 SCHEMA BYTES are frozen and
//! untouched — only the validator changed, to reject what the stated
//! schema already forbids (non-hex session ids, missing nested keys,
//! mistyped members, extra nested keys). V1's stated schema still
//! permits arbitrary `workload`/`attribution` members (D10) and omits
//! the lifetime discriminator (D03): those gaps are closed in v2, and
//! v1 scoped evaluation is limited by [`v1_scope_support`], never
//! silently extended.

use serde_json::Value;

/// The workload-report-v1 schema id: the dispatch const.
pub const SCHEMA_ID: &str = "kryprobe.workload-report.v1";

/// The frozen schema bytes compiled into this crate.
const EMBEDDED_SCHEMA: &str = include_str!("../../../../schemas/workload-report-v1.schema.json");

/// Fixed freeze pin (FNV-1a 64 hex) over the v1 schema bytes (E01): the
/// schema file is frozen, so this digest never changes.
pub const WORKLOAD_V1_SCHEMA_FNV1A: &str = "6d5cf345969d3ff7";

/// Required top-level keys, in schema order.
const REQUIRED: &[&str] = &[
    "schema",
    "session",
    "interval",
    "profile",
    "boundary",
    "contexts",
    "partition",
    "selectors",
    "coverage",
];

/// One workload-v1 defect; empty means the report validates clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadFinding {
    /// The value is not a JSON object.
    NotAnObject,
    /// A required key is absent.
    MissingKey {
        /// Missing key name.
        key: String,
    },
    /// A key outside the schema is present (name withheld: untrusted).
    UnknownKey,
    /// `schema` is present but not [`SCHEMA_ID`] (value withheld).
    UnknownVersion,
    /// A key is present but malformed (static description, no input).
    BadShape {
        /// Offending key name.
        key: String,
        /// What the key must hold.
        expected: String,
    },
    /// Well-shaped fields contradict each other (e.g. partition sums).
    InvalidCombination {
        /// What contradicts what.
        detail: String,
    },
    /// On-disk schema bytes differ from the frozen pin (drift).
    SchemaDrift {
        /// Frozen pin (hex).
        expected: String,
        /// On-disk hash (hex).
        actual: String,
    },
}

/// FNV-1a 64 over bytes (drift detection, not security).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Hex hash of the compiled-in frozen schema (the freeze pin).
#[must_use]
pub fn schema_fnv1a_hex() -> String {
    format!("{:016x}", fnv1a64(EMBEDDED_SCHEMA.as_bytes()))
}

/// Drift check of on-disk schema bytes against the fixed freeze pin:
/// `None` when the bytes match, a [`WorkloadFinding::SchemaDrift`]
/// otherwise. Callers pass the dev-tree copy when present (installed
/// binaries validate embed-only); see the event-v0 pattern.
#[must_use]
pub fn check_schema_drift(schema_disk_bytes: &[u8]) -> Option<WorkloadFinding> {
    let actual = format!("{:016x}", fnv1a64(schema_disk_bytes));
    if actual == WORKLOAD_V1_SCHEMA_FNV1A {
        None
    } else {
        Some(WorkloadFinding::SchemaDrift {
            expected: WORKLOAD_V1_SCHEMA_FNV1A.to_string(),
            actual,
        })
    }
}

/// Dispatch on a schema value: only [`SCHEMA_ID`] routes to this
/// validator; every other value (including event-v0) refuses typed.
pub fn dispatch_schema(schema: &str) -> Result<(), String> {
    if schema == SCHEMA_ID {
        Ok(())
    } else {
        Err(format!(
            "schema mismatch: not '{SCHEMA_ID}' (offered value withheld)"
        ))
    }
}

/// Validate raw report bytes: parse, then [`validate_workload_v1`].
/// Returns `Ok(())` only when the report validates clean.
pub fn validate_bytes(bytes: &[u8]) -> Result<(), String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| format!("report is not valid JSON for schema '{SCHEMA_ID}'"))?;
    let findings = validate_workload_v1(&value);
    if findings.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "workload-report-v1 schema defects: {}",
            findings.len()
        ))
    }
}

/// Digit-string (`u64` without JSON precision loss) shape check.
fn is_digit_string(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}

/// Lowercase-hex string of exactly `len` chars.
fn is_hex_string(value: &Value, len: usize) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == len
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// JSON integer `>= 0` (stated v1 `tgid`/`uid` shape: no upper bound in
/// the frozen schema).
fn is_nonnegative_int(value: &Value) -> bool {
    value.as_u64().is_some()
}

/// Push a shape defect.
fn bad(findings: &mut Vec<WorkloadFinding>, key: String, expected: &str) {
    findings.push(WorkloadFinding::BadShape {
        key,
        expected: expected.to_string(),
    });
}

/// Check `obj` carries no keys outside `allowed`.
fn check_no_extra_keys(obj: &serde_json::Map<String, Value>, allowed: &[&str]) -> bool {
    obj.keys().all(|k| allowed.contains(&k.as_str()))
}

/// Validates one workload-report-v1 value. Fail-closed: any defect means
/// the report must not be evaluated as clean. Layers: object shape,
/// then presence (missing + extra together), then version, then shapes
/// (every nested object per the stated schema), then combinations — one
/// defect class never cascades into another.
#[must_use]
pub fn validate_workload_v1(payload: &Value) -> Vec<WorkloadFinding> {
    let Some(obj) = payload.as_object() else {
        return vec![WorkloadFinding::NotAnObject];
    };
    let mut findings = Vec::new();
    for key in REQUIRED {
        if !obj.contains_key(*key) {
            findings.push(WorkloadFinding::MissingKey {
                key: (*key).to_string(),
            });
        }
    }
    for _ in obj.keys().filter(|k| !REQUIRED.contains(&k.as_str())) {
        findings.push(WorkloadFinding::UnknownKey);
    }
    if !findings.is_empty() {
        return findings;
    }
    if obj.get("schema").and_then(Value::as_str) != Some(SCHEMA_ID) {
        return vec![WorkloadFinding::UnknownVersion];
    }
    validate_session(obj, &mut findings);
    validate_interval(obj, &mut findings);
    for key in ["profile", "boundary"] {
        if !obj.get(key).is_some_and(Value::is_string) {
            bad(&mut findings, key.to_string(), "string");
        }
    }
    validate_contexts(obj, &mut findings);
    validate_partition_shape(obj, &mut findings);
    if !obj.get("selectors").is_some_and(Value::is_object) {
        bad(&mut findings, "selectors".to_string(), "object");
    }
    validate_coverage(obj, &mut findings);
    if !findings.is_empty() {
        return findings;
    }
    // Combinations: the partition invariant parses (u64) — overflow or
    // unparseable magnitudes contradict the report.
    let partition = obj
        .get("partition")
        .and_then(Value::as_object)
        .expect("shapes checked");
    let parse = |key: &str| {
        partition
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
    };
    match (
        parse("matched"),
        parse("nonmatched"),
        parse("unknown_match"),
    ) {
        (Some(m), Some(n), Some(u)) => {
            if m.checked_add(n)
                .and_then(|base| base.checked_add(u))
                .is_none()
            {
                findings.push(WorkloadFinding::InvalidCombination {
                    detail: "partition counts overflow u64".to_string(),
                });
            }
        }
        _ => findings.push(WorkloadFinding::InvalidCombination {
            detail: "partition magnitudes do not parse as u64".to_string(),
        }),
    }
    findings
}

/// Session shape: 32-char lowercase-hex session id (G05.1) plus a
/// bounded kernel identity; no extra keys.
fn validate_session(obj: &serde_json::Map<String, Value>, findings: &mut Vec<WorkloadFinding>) {
    let Some(session) = obj.get("session").and_then(Value::as_object) else {
        bad(findings, "session".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(session, &["session_id", "kernel_identity"]) {
        findings.push(WorkloadFinding::UnknownKey);
    }
    if !session
        .get("session_id")
        .is_some_and(|v| is_hex_string(v, 32))
    {
        bad(
            findings,
            "session.session_id".to_string(),
            "32 lowercase hex chars",
        );
    }
    if !session
        .get("kernel_identity")
        .is_some_and(|v| v.as_str().is_some_and(|s| s.chars().count() <= 128))
    {
        bad(
            findings,
            "session.kernel_identity".to_string(),
            "string <= 128 chars",
        );
    }
}

/// Interval shape: digit bounds + consistency enum; no extra keys.
/// (The stated v1 schema has no order rule: inversion is a v2 refusal.)
fn validate_interval(obj: &serde_json::Map<String, Value>, findings: &mut Vec<WorkloadFinding>) {
    let Some(interval) = obj.get("interval").and_then(Value::as_object) else {
        bad(findings, "interval".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(interval, &["start_ns", "end_ns", "consistency"]) {
        findings.push(WorkloadFinding::UnknownKey);
    }
    for key in ["start_ns", "end_ns"] {
        if !interval.get(key).is_some_and(is_digit_string) {
            bad(findings, format!("interval.{key}"), "digit string");
        }
    }
    if !interval
        .get("consistency")
        .and_then(Value::as_str)
        .is_some_and(|c| c == "quiescent" || c == "unproven")
    {
        bad(
            findings,
            "interval.consistency".to_string(),
            "quiescent | unproven",
        );
    }
}

/// Context rows: every stated member shape, including required keys,
/// enums, integer bounds, the object-or-null metadata members, and the
/// closed key set (G05.2).
fn validate_contexts(obj: &serde_json::Map<String, Value>, findings: &mut Vec<WorkloadFinding>) {
    let Some(contexts) = obj.get("contexts").and_then(Value::as_array) else {
        bad(findings, "contexts".to_string(), "array");
        return;
    };
    for (i, context) in contexts.iter().enumerate() {
        let path = format!("contexts[{i}]");
        let Some(row) = context.as_object() else {
            bad(findings, path, "object");
            continue;
        };
        if !check_no_extra_keys(
            row,
            &[
                "kh",
                "cgroup_id",
                "tgid",
                "uid",
                "start_ns",
                "execution_kind",
                "calls",
                "workload",
                "attribution",
            ],
        ) {
            findings.push(WorkloadFinding::UnknownKey);
        }
        for key in ["kh", "cgroup_id", "calls"] {
            if !row.get(key).is_some_and(is_digit_string) {
                bad(findings, format!("{path}.{key}"), "digit string");
            }
        }
        if let Some(start) = row.get("start_ns")
            && !is_digit_string(start)
        {
            bad(findings, format!("{path}.start_ns"), "digit string");
        }
        for key in ["tgid", "uid"] {
            if !row.get(key).is_some_and(is_nonnegative_int) {
                bad(findings, format!("{path}.{key}"), "integer >= 0");
            }
        }
        if !row
            .get("execution_kind")
            .and_then(Value::as_str)
            .is_some_and(|k| matches!(k, "proc" | "kthread" | "softirq" | "unknown"))
        {
            bad(
                findings,
                format!("{path}.execution_kind"),
                "proc | kthread | softirq | unknown",
            );
        }
        // Stated v1 shape only (D10): object or null. The validator
        // checks the TYPE, never the arbitrary nested content — and
        // legacy handling must not retain/render that content (see
        // `v1_scope_support`: static limitations only).
        for key in ["workload", "attribution"] {
            if let Some(member) = row.get(key)
                && !member.is_object()
                && !member.is_null()
            {
                bad(findings, format!("{path}.{key}"), "object | null");
            }
        }
    }
}

/// Partition shape: three digit strings, closed key set.
fn validate_partition_shape(
    obj: &serde_json::Map<String, Value>,
    findings: &mut Vec<WorkloadFinding>,
) {
    let Some(partition) = obj.get("partition").and_then(Value::as_object) else {
        bad(findings, "partition".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(partition, &["matched", "nonmatched", "unknown_match"]) {
        findings.push(WorkloadFinding::UnknownKey);
    }
    for key in ["matched", "nonmatched", "unknown_match"] {
        if !partition.get(key).is_some_and(is_digit_string) {
            bad(findings, format!("partition.{key}"), "digit string");
        }
    }
}

/// Coverage shape: four required string members, closed key set.
fn validate_coverage(obj: &serde_json::Map<String, Value>, findings: &mut Vec<WorkloadFinding>) {
    let Some(coverage) = obj.get("coverage").and_then(Value::as_object) else {
        bad(findings, "coverage".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(
        coverage,
        &["capture", "attribution", "metadata", "correlation"],
    ) {
        findings.push(WorkloadFinding::UnknownKey);
    }
    for key in ["capture", "attribution", "metadata", "correlation"] {
        if !coverage.get(key).is_some_and(Value::is_string) {
            bad(findings, format!("coverage.{key}"), "string");
        }
    }
}

/// One documented v1 limitation (static vocabulary, no input echo).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V1Limitation {
    /// Contexts carry only the `kh` hash: operations, algorithms,
    /// drivers, and results cannot be reconstructed or replayed.
    NoNativeIdentity,
    /// No authoritative system/per-context/unknown operands: conservation
    /// cannot be checked and scoped conclusions cannot be established.
    NoLedgerOperands,
    /// Selectors are an untyped object: the report cannot bind a
    /// re-evaluated scope to its stored partition.
    NoSelectorBinding,
    /// Workload/attribution members are untyped: arbitrary nested
    /// metadata must not be retained or rendered as typed evidence.
    UntypedMetadata,
}

impl std::fmt::Display for V1Limitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoNativeIdentity => write!(f, "v1 carries no native operation identity"),
            Self::NoLedgerOperands => write!(f, "v1 carries no authoritative ledger operands"),
            Self::NoSelectorBinding => write!(f, "v1 cannot bind re-evaluated selectors"),
            Self::UntypedMetadata => write!(f, "v1 metadata members are untyped"),
        }
    }
}

/// Refusal of unsupported scoped evaluation over a v1 report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1ScopeRefusal {
    /// Static reason (no input echo).
    pub reason: &'static str,
}

/// Legacy v1 scoped-evaluation support (G05.3): a v1 report renders its
/// STORED partition with explicit limitations, but any request to
/// evaluate a (new) scope refuses — v1 did not record what scoped
/// evaluation needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1ScopeSupport {
    /// Render the stored partition alongside every limitation.
    RenderWithLimitations(Vec<V1Limitation>),
    /// The scope cannot be evaluated from v1: refuse.
    Refused(V1ScopeRefusal),
}

/// Every v1 limitation, in stable order.
#[must_use]
pub fn v1_limitations() -> Vec<V1Limitation> {
    vec![
        V1Limitation::NoNativeIdentity,
        V1Limitation::NoLedgerOperands,
        V1Limitation::NoSelectorBinding,
        V1Limitation::UntypedMetadata,
    ]
}

/// Decide scoped-evaluation support for the report's `selectors` value:
/// an empty selector object renders with limitations; anything else —
/// including a missing or mistyped value — refuses.
#[must_use]
pub fn v1_scope_support(selectors: &Value) -> V1ScopeSupport {
    match selectors.as_object() {
        Some(selectors) if selectors.is_empty() => {
            V1ScopeSupport::RenderWithLimitations(v1_limitations())
        }
        _ => V1ScopeSupport::Refused(V1ScopeRefusal {
            reason: "v1 cannot evaluate selectors it did not record",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal_valid() -> Value {
        json!({
            "schema": SCHEMA_ID,
            "session": {"session_id": "0123456789abcdef0123456789abcdef", "kernel_identity": "7.0.14"},
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
        })
    }

    #[test]
    fn valid_report_passes() {
        assert!(validate_workload_v1(&minimal_valid()).is_empty());
    }

    #[test]
    fn wrong_schema_refuses_without_echo() {
        let mut v = minimal_valid();
        v["schema"] = json!("kryprobe.event/v0");
        let findings = validate_workload_v1(&v);
        assert_eq!(findings, vec![WorkloadFinding::UnknownVersion]);
        assert!(dispatch_schema("kryprobe.event/v0").is_err());
    }

    #[test]
    fn overflow_partition_contradicts() {
        let mut v = minimal_valid();
        v["partition"]["matched"] = json!("18446744073709551615");
        v["partition"]["nonmatched"] = json!("1");
        let findings = validate_workload_v1(&v);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, WorkloadFinding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn freeze_pin_is_fixed_and_drift_detects() {
        assert_eq!(schema_fnv1a_hex(), WORKLOAD_V1_SCHEMA_FNV1A);
        assert_eq!(WORKLOAD_V1_SCHEMA_FNV1A, "6d5cf345969d3ff7");
        assert!(check_schema_drift(EMBEDDED_SCHEMA.as_bytes()).is_none());
        assert!(check_schema_drift(b"{tampered}").is_some());
    }

    #[test]
    fn non_hex_session_refuses() {
        let mut v = minimal_valid();
        v["session"]["session_id"] = json!("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(validate_workload_v1(&v).iter().any(
            |f| matches!(f, WorkloadFinding::BadShape { key, .. } if key == "session.session_id")
        ));
    }

    #[test]
    fn invalid_input_trace_rejects_every_defect() {
        // The exact Codex B1 trace: rejected by the stated schema, and
        // now rejected by the validator on every defect class.
        let trace = json!({
            "schema": "kryprobe.workload-report.v1",
            "session": {"session_id": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
            "interval": {"consistency": "quiescent"},
            "profile": null,
            "boundary": [],
            "contexts": [false],
            "partition": {"matched": "1", "nonmatched": "0", "unknown_match": "0"},
            "selectors": false,
            "coverage": null
        });
        let findings = validate_workload_v1(&trace);
        assert!(!findings.is_empty());
        for key in [
            "session.session_id",
            "session.kernel_identity",
            "interval.start_ns",
            "interval.end_ns",
            "profile",
            "boundary",
            "contexts[0]",
            "selectors",
            "coverage",
        ] {
            assert!(
                findings.iter().any(|f| matches!(
                    f,
                    WorkloadFinding::BadShape { key: bad, .. } if bad == key
                )),
                "trace defect {key} escaped validation: {findings:?}"
            );
        }
    }

    #[test]
    fn nested_extra_keys_refuse() {
        let mut v = minimal_valid();
        v["session"]["extra"] = json!(1);
        assert!(validate_workload_v1(&v).contains(&WorkloadFinding::UnknownKey));
        let mut v = minimal_valid();
        v["contexts"][0]["extra"] = json!(1);
        assert!(validate_workload_v1(&v).contains(&WorkloadFinding::UnknownKey));
        let mut v = minimal_valid();
        v["coverage"]["extra"] = json!(1);
        assert!(validate_workload_v1(&v).contains(&WorkloadFinding::UnknownKey));
    }

    #[test]
    fn mistyped_context_members_refuse() {
        let mut v = minimal_valid();
        v["contexts"][0]["tgid"] = json!(-1);
        assert!(
            validate_workload_v1(&v)
                .iter()
                .any(|f| matches!(f, WorkloadFinding::BadShape { .. }))
        );
        let mut v = minimal_valid();
        v["contexts"][0]["execution_kind"] = json!("irq");
        assert!(
            validate_workload_v1(&v)
                .iter()
                .any(|f| matches!(f, WorkloadFinding::BadShape { .. }))
        );
        let mut v = minimal_valid();
        v["contexts"][0]["workload"] = json!(42);
        assert!(
            validate_workload_v1(&v)
                .iter()
                .any(|f| matches!(f, WorkloadFinding::BadShape { .. }))
        );
    }

    #[test]
    fn scoped_evaluation_renders_limitations_or_refuses() {
        match v1_scope_support(&json!({})) {
            V1ScopeSupport::RenderWithLimitations(limitations) => {
                assert_eq!(limitations, v1_limitations());
                assert_eq!(limitations.len(), 4);
            }
            V1ScopeSupport::Refused(_) => panic!("empty selectors must render with limitations"),
        }
        match v1_scope_support(&json!({"kind": "cgroup-id"})) {
            V1ScopeSupport::Refused(refusal) => assert!(!refusal.reason.is_empty()),
            V1ScopeSupport::RenderWithLimitations(_) => {
                panic!("non-empty selectors must refuse")
            }
        }
        assert!(matches!(
            v1_scope_support(&json!(null)),
            V1ScopeSupport::Refused(_)
        ));
        // Limitations render without touching report bytes.
        for limitation in v1_limitations() {
            assert!(!limitation.to_string().is_empty());
        }
    }
}
