// SPDX-License-Identifier: GPL-3.0-or-later
//! workload-report-v1 validator + schema dispatch (ADR-0008 §(i)).
//!
//! Enforces `schemas/workload-report-v1.schema.json` on a standalone
//! report value: required keys, wire shapes, the version const, and
//! the matched/nonmatched/unknown partition invariant. Unknown schema
//! values fail closed. The schema bytes are freeze-pinned (FNV over
//! the compiled-in copy) with dev-tree drift detection, mirroring
//! event-v0. Findings never echo untrusted input bytes.

use serde_json::Value;

/// The workload-report-v1 schema id: the dispatch const.
pub const SCHEMA_ID: &str = "kryprobe.workload-report.v1";

/// The frozen schema bytes compiled into this crate.
const EMBEDDED_SCHEMA: &str = include_str!("../../../../schemas/workload-report-v1.schema.json");

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

/// Validates one workload-report-v1 value. Fail-closed: any defect means
/// the report must not be evaluated as clean. Layers: object shape,
/// then presence (missing + extra together), then version, then shapes,
/// then combinations — one defect class never cascades into another.
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
    // Shapes: partition digit-strings, session id shape, interval enum.
    let partition = obj.get("partition").and_then(Value::as_object);
    let mut part_ok = true;
    if let Some(part) = partition {
        for key in ["matched", "nonmatched", "unknown_match"] {
            if !part.get(key).is_some_and(is_digit_string) {
                findings.push(WorkloadFinding::BadShape {
                    key: format!("partition.{key}"),
                    expected: "digit string".to_string(),
                });
                part_ok = false;
            }
        }
    } else {
        findings.push(WorkloadFinding::BadShape {
            key: "partition".to_string(),
            expected: "object".to_string(),
        });
        part_ok = false;
    }
    let session_ok = obj
        .get("session")
        .and_then(Value::as_object)
        .is_some_and(|s| {
            s.get("session_id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.len() == 32)
        });
    if !session_ok {
        findings.push(WorkloadFinding::BadShape {
            key: "session.session_id".to_string(),
            expected: "32 lowercase hex chars".to_string(),
        });
    }
    let consistency_ok = obj
        .get("interval")
        .and_then(Value::as_object)
        .and_then(|i| i.get("consistency"))
        .and_then(Value::as_str)
        .is_some_and(|c| c == "quiescent" || c == "unproven");
    if !consistency_ok {
        findings.push(WorkloadFinding::BadShape {
            key: "interval.consistency".to_string(),
            expected: "quiescent | unproven".to_string(),
        });
    }
    if !obj.get("contexts").is_some_and(Value::is_array) {
        findings.push(WorkloadFinding::BadShape {
            key: "contexts".to_string(),
            expected: "array".to_string(),
        });
    }
    if !findings.is_empty() {
        return findings;
    }
    // Combinations: the partition invariant parses (u64) — overflow or
    // unparseable magnitudes contradict the report.
    if part_ok {
        let part = partition.expect("checked above");
        let parse = |key: &str| {
            part.get(key)
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
    }
    findings
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
            "contexts": [],
            "partition": {"matched": "70", "nonmatched": "20", "unknown_match": "10"},
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
    fn freeze_pin_is_stable_hex() {
        let pin = schema_fnv1a_hex();
        assert_eq!(pin.len(), 16);
        assert!(pin.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
