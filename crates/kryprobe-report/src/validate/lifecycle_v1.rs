// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto lifecycle payload-v1 validator.
//!
//! Enforces `schemas/kcrypto-lifecycle-v1.schema.json` on a single
//! `backend_payload` value: required keys, wire shapes, the version
//! const, and terminal/status/duration consistency. Unknown versions
//! fail closed. Schema bytes freeze only after review (no
//! compiled-in pin yet).

use crate::KCRYPTO_LIFECYCLE_V1;
use crate::checker::{is_digit_string, is_prefixed_id, render, shorten};
use serde_json::Value;

/// Required top-level keys, in schema order.
const REQUIRED: &[&str] = &[
    "schema",
    "request_id",
    "tfm_id",
    "terminal",
    "status",
    "duration_ns",
];

/// Maximum ID string length, per the schema.
const MAX_ID_LEN: usize = 96;

/// One payload-v1 defect; empty means the payload validates clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleFinding {
    /// A required key is absent.
    MissingKey {
        /// Missing key name.
        key: String,
    },
    /// A key is present but malformed: wrong JSON type, a digit-string
    /// or prefixed-ID shape violation, or an out-of-range integer.
    BadShape {
        /// Offending key name.
        key: String,
        /// Offending value, rendered and truncated.
        value: String,
    },
    /// `schema` is present but not `kryprobe.kcrypto.lifecycle/v1`.
    UnknownVersion {
        /// Offending schema value.
        found: String,
    },
    /// Individually well-shaped fields contradict each other (terminal
    /// truth without status, status/duration without terminal truth).
    InvalidCombination {
        /// What contradicts what.
        detail: String,
    },
}

/// Validates one lifecycle payload-v1 object. Fail-closed: any defect
/// means the payload must not be evaluated as clean. Checks run in
/// layers — presence, then version, then shapes, then combinations —
/// so one defect class never cascades into another.
pub fn validate_lifecycle_v1(payload: &Value) -> Vec<LifecycleFinding> {
    let Some(obj) = payload.as_object() else {
        return vec![LifecycleFinding::BadShape {
            key: "record".to_string(),
            value: shorten(&render(payload)),
        }];
    };
    let mut missing = Vec::new();
    for key in REQUIRED {
        if !obj.contains_key(*key) {
            missing.push(LifecycleFinding::MissingKey {
                key: key.to_string(),
            });
        }
    }
    if !missing.is_empty() {
        return missing;
    }
    let mut out = Vec::new();
    match obj.get("schema") {
        Some(Value::String(found)) if found == KCRYPTO_LIFECYCLE_V1 => {}
        Some(Value::String(found)) => {
            out.push(LifecycleFinding::UnknownVersion {
                found: found.clone(),
            });
        }
        other => out.push(LifecycleFinding::BadShape {
            key: "schema".to_string(),
            value: shorten(&render(other.unwrap_or(&Value::Null))),
        }),
    }
    check_id(obj, "request_id", false, &mut out);
    check_id(obj, "tfm_id", true, &mut out);
    let terminal_ok = check_terminal(obj, &mut out);
    let status = check_status(obj, &mut out);
    let duration = check_duration(obj, &mut out);
    if terminal_ok && status.is_some() && duration.is_some() {
        check_combination(obj, &mut out);
    }
    out
}

/// Validates a prefixed-ID key; `nullable` allows explicit null.
fn check_id(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    nullable: bool,
    out: &mut Vec<LifecycleFinding>,
) {
    match obj.get(key) {
        Some(Value::String(text)) if text.len() <= MAX_ID_LEN && is_prefixed_id(text) => {}
        Some(value) if nullable && value.is_null() => {}
        Some(value) => out.push(LifecycleFinding::BadShape {
            key: key.to_string(),
            value: shorten(&render(value)),
        }),
        // Unreachable: presence was checked above; fail closed anyway.
        None => out.push(LifecycleFinding::MissingKey {
            key: key.to_string(),
        }),
    }
}

/// Validates the terminal enum; returns whether it is usable.
fn check_terminal(obj: &serde_json::Map<String, Value>, out: &mut Vec<LifecycleFinding>) -> bool {
    match obj.get("terminal") {
        Some(Value::String(word)) if matches!(word.as_str(), "sync" | "callback" | "unknown") => {
            true
        }
        Some(value) => {
            out.push(LifecycleFinding::BadShape {
                key: "terminal".to_string(),
                value: shorten(&render(value)),
            });
            false
        }
        None => {
            out.push(LifecycleFinding::MissingKey {
                key: "terminal".to_string(),
            });
            false
        }
    }
}

/// Validates the native status: JSON integer in i32 range, or null.
/// Returns `Some(is_null)` when well-shaped, `None` otherwise.
fn check_status(
    obj: &serde_json::Map<String, Value>,
    out: &mut Vec<LifecycleFinding>,
) -> Option<bool> {
    match obj.get("status") {
        Some(Value::Null) => Some(true),
        Some(Value::Number(number)) => match number.as_i64() {
            Some(raw) if i32::try_from(raw).is_ok() => Some(false),
            _ => {
                out.push(LifecycleFinding::BadShape {
                    key: "status".to_string(),
                    value: shorten(&number.to_string()),
                });
                None
            }
        },
        Some(value) => {
            out.push(LifecycleFinding::BadShape {
                key: "status".to_string(),
                value: shorten(&render(value)),
            });
            None
        }
        None => {
            out.push(LifecycleFinding::MissingKey {
                key: "status".to_string(),
            });
            None
        }
    }
}

/// Validates the duration: decimal u64 string, or null.
/// Returns `Some(is_null)` when well-shaped, `None` otherwise.
fn check_duration(
    obj: &serde_json::Map<String, Value>,
    out: &mut Vec<LifecycleFinding>,
) -> Option<bool> {
    match obj.get("duration_ns") {
        Some(Value::Null) => Some(true),
        Some(Value::String(text)) => {
            if text.len() <= 24 && is_digit_string(text) && text.parse::<u64>().is_ok() {
                Some(false)
            } else {
                out.push(LifecycleFinding::BadShape {
                    key: "duration_ns".to_string(),
                    value: shorten(text),
                });
                None
            }
        }
        Some(value) => {
            out.push(LifecycleFinding::BadShape {
                key: "duration_ns".to_string(),
                value: shorten(&render(value)),
            });
            None
        }
        None => {
            out.push(LifecycleFinding::MissingKey {
                key: "duration_ns".to_string(),
            });
            None
        }
    }
}

/// Cross-field rules over well-shaped values: terminal truth requires
/// an exact native status; unknown terminals carry neither status
/// nor duration.
fn check_combination(obj: &serde_json::Map<String, Value>, out: &mut Vec<LifecycleFinding>) {
    let terminal = obj
        .get("terminal")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let status_null = obj.get("status").is_none_or(Value::is_null);
    let duration_null = obj.get("duration_ns").is_none_or(Value::is_null);
    match terminal {
        "sync" | "callback" => {
            if status_null {
                out.push(LifecycleFinding::InvalidCombination {
                    detail: format!("terminal '{terminal}' requires an exact native status"),
                });
            }
        }
        "unknown" => {
            if !status_null {
                out.push(LifecycleFinding::InvalidCombination {
                    detail: "terminal 'unknown' must not carry a status".to_string(),
                });
            }
            if !duration_null {
                out.push(LifecycleFinding::InvalidCombination {
                    detail: "terminal 'unknown' must not carry a duration".to_string(),
                });
            }
        }
        // Unreachable: terminal shape was checked above.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{LifecycleFinding, validate_lifecycle_v1};
    use serde_json::{Value, json};

    fn base() -> Value {
        json!({
            "schema": "kryprobe.kcrypto.lifecycle/v1",
            "request_id": "kcrypto:req-1",
            "tfm_id": "kcrypto:tfm-7",
            "terminal": "sync",
            "status": 0,
            "duration_ns": "20",
        })
    }

    #[test]
    fn accepts_valid_payloads() {
        let sync = json!({
            "schema": "kryprobe.kcrypto.lifecycle/v1",
            "request_id": "kcrypto:req-1",
            "tfm_id": "kcrypto:tfm-7",
            "terminal": "sync",
            "status": 0,
            "duration_ns": "20",
        });
        let callback = json!({
            "schema": "kryprobe.kcrypto.lifecycle/v1",
            "request_id": "kcrypto:req-2",
            "tfm_id": null,
            "terminal": "callback",
            "status": -5,
            "duration_ns": "140",
        });
        let unknown = json!({
            "schema": "kryprobe.kcrypto.lifecycle/v1",
            "request_id": "kcrypto:req-3",
            "tfm_id": null,
            "terminal": "unknown",
            "status": null,
            "duration_ns": null,
        });
        for payload in [&sync, &callback, &unknown] {
            assert!(validate_lifecycle_v1(payload).is_empty());
        }
    }

    #[test]
    fn rejects_absent_terminal_data() {
        let mut missing_terminal = base();
        missing_terminal
            .as_object_mut()
            .expect("object")
            .remove("terminal");
        assert_eq!(
            validate_lifecycle_v1(&missing_terminal),
            vec![LifecycleFinding::MissingKey {
                key: "terminal".to_string()
            }]
        );
        let mut missing_status = base();
        missing_status
            .as_object_mut()
            .expect("object")
            .remove("status");
        assert_eq!(
            validate_lifecycle_v1(&missing_status),
            vec![LifecycleFinding::MissingKey {
                key: "status".to_string()
            }]
        );
    }

    #[test]
    fn rejects_integer_overflow() {
        let mut big_status = base();
        big_status
            .as_object_mut()
            .expect("object")
            .insert("status".to_string(), serde_json::json!(1099511627776u64));
        assert!(matches!(
            validate_lifecycle_v1(&big_status)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
        let mut big_duration = base();
        big_duration.as_object_mut().expect("object").insert(
            "duration_ns".to_string(),
            serde_json::json!("99999999999999999999999"),
        );
        assert!(matches!(
            validate_lifecycle_v1(&big_duration)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }

    #[test]
    fn rejects_malformed_ids() {
        let mut bad_request = base();
        bad_request
            .as_object_mut()
            .expect("object")
            .insert("request_id".to_string(), serde_json::json!("no-colon-here"));
        assert!(matches!(
            validate_lifecycle_v1(&bad_request)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
        let mut bad_tfm = base();
        bad_tfm
            .as_object_mut()
            .expect("object")
            .insert("tfm_id".to_string(), serde_json::json!("TFM:x"));
        assert!(matches!(
            validate_lifecycle_v1(&bad_tfm)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut wrong = base();
        wrong.as_object_mut().expect("object").insert(
            "schema".to_string(),
            serde_json::json!("kryprobe.kcrypto.lifecycle/v9"),
        );
        assert_eq!(
            validate_lifecycle_v1(&wrong),
            vec![LifecycleFinding::UnknownVersion {
                found: "kryprobe.kcrypto.lifecycle/v9".to_string()
            }]
        );
        let mut untyped = base();
        untyped
            .as_object_mut()
            .expect("object")
            .insert("schema".to_string(), serde_json::json!(5));
        assert!(matches!(
            validate_lifecycle_v1(&untyped)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }

    #[test]
    fn rejects_invalid_combinations() {
        // Terminal truth without a status.
        let mut sync_null = base();
        sync_null
            .as_object_mut()
            .expect("object")
            .insert("status".to_string(), Value::Null);
        assert!(matches!(
            validate_lifecycle_v1(&sync_null)[..],
            [LifecycleFinding::InvalidCombination { .. }]
        ));
        // Status without terminal truth.
        let mut unknown_status = base();
        let unknown_status_obj = unknown_status.as_object_mut().expect("object");
        unknown_status_obj.insert("terminal".to_string(), serde_json::json!("unknown"));
        unknown_status_obj.insert("status".to_string(), serde_json::json!(0));
        unknown_status_obj.insert("duration_ns".to_string(), Value::Null);
        assert!(matches!(
            validate_lifecycle_v1(&unknown_status)[..],
            [LifecycleFinding::InvalidCombination { .. }]
        ));
        // Duration without terminal truth.
        let mut unknown_duration = base();
        let unknown_duration_obj = unknown_duration.as_object_mut().expect("object");
        unknown_duration_obj.insert("terminal".to_string(), serde_json::json!("unknown"));
        unknown_duration_obj.insert("status".to_string(), Value::Null);
        assert!(matches!(
            validate_lifecycle_v1(&unknown_duration)[..],
            [LifecycleFinding::InvalidCombination { .. }]
        ));
    }

    #[test]
    fn rejects_non_object_payload() {
        let array = serde_json::json!([1, 2, 3]);
        assert!(matches!(
            validate_lifecycle_v1(&array)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }

    #[test]
    fn rejects_unknown_terminal_word() {
        let mut bogus = base();
        bogus
            .as_object_mut()
            .expect("object")
            .insert("terminal".to_string(), serde_json::json!("completed"));
        assert!(matches!(
            validate_lifecycle_v1(&bogus)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }

    #[test]
    fn rejects_overlong_id() {
        let mut long = base();
        long.as_object_mut().expect("object").insert(
            "request_id".to_string(),
            serde_json::json!(format!("kcrypto:req-{}", "9".repeat(200))),
        );
        assert!(matches!(
            validate_lifecycle_v1(&long)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }

    #[test]
    fn keeps_exact_native_errno() {
        // Negative native errnos are exact JSON integers, never strings.
        let mut neg = base();
        neg.as_object_mut()
            .expect("object")
            .insert("status".to_string(), serde_json::json!(-115));
        assert!(validate_lifecycle_v1(&neg).is_empty());
        for bound in [i32::MIN, i32::MAX] {
            let mut payload = base();
            payload
                .as_object_mut()
                .expect("object")
                .insert("status".to_string(), serde_json::json!(bound));
            assert!(validate_lifecycle_v1(&payload).is_empty());
        }
        let mut stringified = base();
        stringified
            .as_object_mut()
            .expect("object")
            .insert("status".to_string(), serde_json::json!("-115"));
        assert!(matches!(
            validate_lifecycle_v1(&stringified)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }
}
