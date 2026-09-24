// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto lifecycle payload-v1 validator.
//!
//! Enforces `schemas/kcrypto-lifecycle-v1.schema.json` on a single
//! standalone report-JSON value: required keys, wire shapes, the
//! version const, and terminal/status/duration consistency. Unknown
//! versions fail closed. Schema bytes freeze only after review (no
//! compiled-in pin yet). Not carried in the v0 event envelope (no
//! `backend_payload` there); envelope carriage awaits an envelope
//! ADR.

use crate::KCRYPTO_LIFECYCLE_V1;
use crate::checker::{is_digit_string, is_prefixed_id};
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
/// Findings are input-free by construction: they name keys and
/// expected shapes, never rejected values (which could be key
/// material or buffer contents).
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
        /// What the key must hold (static description, no input).
        expected: String,
    },
    /// `schema` is present but not `kryprobe.kcrypto.lifecycle/v1`
    /// (the offered value is withheld: it is untrusted input).
    UnknownVersion,
    /// A key outside the schema is present. Names the key only:
    /// unknown values (which could be key material or buffer
    /// contents) must never leak into diagnostics.
    UnknownKey {
        /// Offending key name.
        key: String,
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
/// layers — presence (missing and extra keys together), then
/// version, then shapes, then combinations — so one defect class
/// never cascades into another.
pub fn validate_lifecycle_v1(payload: &Value) -> Vec<LifecycleFinding> {
    let Some(obj) = payload.as_object() else {
        return vec![LifecycleFinding::BadShape {
            key: "record".to_string(),
            expected: "object".to_string(),
        }];
    };
    let mut out = Vec::new();
    for key in REQUIRED {
        if !obj.contains_key(*key) {
            out.push(LifecycleFinding::MissingKey {
                key: key.to_string(),
            });
        }
    }
    let mut unknown: Vec<&str> = obj
        .keys()
        .filter(|key| !REQUIRED.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    unknown.sort_unstable();
    for key in unknown {
        out.push(LifecycleFinding::UnknownKey {
            key: key.to_string(),
        });
    }
    if !out.is_empty() {
        return out;
    }
    match obj.get("schema") {
        Some(Value::String(found)) if found == KCRYPTO_LIFECYCLE_V1 => {}
        Some(Value::String(_)) => {
            out.push(LifecycleFinding::UnknownVersion);
        }
        _ => out.push(LifecycleFinding::BadShape {
            key: "schema".to_string(),
            expected: "version string".to_string(),
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
    let expected = if nullable {
        "scope:name id (≤96 chars) or null"
    } else {
        "scope:name id (≤96 chars)"
    };
    match obj.get(key) {
        Some(Value::String(text)) if text.len() <= MAX_ID_LEN && is_prefixed_id(text) => {}
        Some(value) if nullable && value.is_null() => {}
        Some(_) => out.push(LifecycleFinding::BadShape {
            key: key.to_string(),
            expected: expected.to_string(),
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
        Some(_) => {
            out.push(LifecycleFinding::BadShape {
                key: "terminal".to_string(),
                expected: "`sync`, `callback` or `unknown`".to_string(),
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
/// JSON Schema `integer` admits zero-fraction floats (`-5.0`), so the
/// validator accepts them too; exactness is preserved (f64 holds
/// every i32). Returns `Some(is_null)` when well-shaped, `None`
/// otherwise.
fn check_status(
    obj: &serde_json::Map<String, Value>,
    out: &mut Vec<LifecycleFinding>,
) -> Option<bool> {
    match obj.get("status") {
        Some(Value::Null) => Some(true),
        Some(Value::Number(number)) => match number.as_i64() {
            Some(raw) if i32::try_from(raw).is_ok() => Some(false),
            _ => match number.as_f64() {
                Some(face) if is_integral_i32(face) => Some(false),
                _ => {
                    out.push(LifecycleFinding::BadShape {
                        key: "status".to_string(),
                        expected: "JSON integer in i32 range or null".to_string(),
                    });
                    None
                }
            },
        },
        Some(_) => {
            out.push(LifecycleFinding::BadShape {
                key: "status".to_string(),
                expected: "JSON integer in i32 range or null".to_string(),
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

/// A float the schema's `integer` type admits: zero fraction and
/// inside the i32 range (f64 represents every i32 exactly).
fn is_integral_i32(face: f64) -> bool {
    face.fract() == 0.0 && face >= f64::from(i32::MIN) && face <= f64::from(i32::MAX)
}

/// Maximum duration-string length, per the schema: u64 needs at most
/// 20 decimal digits; the `u64` parse enforces the exact range.
const MAX_DURATION_LEN: usize = 20;

/// Validates the duration: decimal u64 string, or null.
/// Returns `Some(is_null)` when well-shaped, `None` otherwise.
fn check_duration(
    obj: &serde_json::Map<String, Value>,
    out: &mut Vec<LifecycleFinding>,
) -> Option<bool> {
    match obj.get("duration_ns") {
        Some(Value::Null) => Some(true),
        Some(Value::String(text)) => {
            if text.len() <= MAX_DURATION_LEN
                && is_digit_string(text)
                && text.parse::<u64>().is_ok()
            {
                Some(false)
            } else {
                out.push(LifecycleFinding::BadShape {
                    key: "duration_ns".to_string(),
                    expected: "canonical decimal u64 string or null".to_string(),
                });
                None
            }
        }
        Some(_) => {
            out.push(LifecycleFinding::BadShape {
                key: "duration_ns".to_string(),
                expected: "canonical decimal u64 string or null".to_string(),
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

    /// Prefixed-id pattern the schema must carry (portable strict
    /// end: `(?![\s\S])`, since `$` alone matches before a trailing
    /// newline in some engines).
    const EXPECTED_ID_PATTERN: &str = "^[a-z][a-z0-9_-]*:[A-Za-z0-9_.-]+(?![\\s\\S])";

    /// Exact canonical-decimal u64 range pattern the schema must
    /// carry (generated + verified by an exact range script; any
    /// schema-side weakening breaks this pin).
    const EXPECTED_DURATION_PATTERN: &str = "^(0|[1-9][0-9]{0,18}|1(?:0[0-9]{18}|[1-7][0-9]{18}|8(?:(?:0[0-9]{17}|[1-3][0-9]{17}|4(?:(?:0[0-9]{16}|[1-3][0-9]{16}|4(?:(?:0[0-9]{15}|[1-5][0-9]{15}|6(?:(?:0[0-9]{14}|[1-6][0-9]{14}|7(?:(?:0[0-9]{13}|[1-3][0-9]{13}|4(?:(?:0[0-9]{12}|[1-3][0-9]{12}|4(?:0(?:0[0-9]{10}|[1-6][0-9]{10}|7(?:(?:0[0-9]{9}|[1-2][0-9]{9}|3(?:(?:0[0-9]{8}|[1-6][0-9]{8}|7(?:0(?:0[0-9]{6}|[1-8][0-9]{6}|9(?:(?:0[0-9]{5}|[1-4][0-9]{5}|5(?:(?:0[0-9]{4}|[1-4][0-9]{4}|5(?:(?:0[0-9]{3}|1(?:(?:0[0-9]{2}|[1-5][0-9]{2}|6(?:(?:0[0-9]|1(?:(?:0|[1-4]|5))))))))))))))))))))))))))))))))))(?![\\s\\S])";

    #[test]
    fn schema_file_matches_validator() {
        // The standalone contract doc stays parseable and keeps the
        // keys + version const the validator enforces (bytes freeze
        // only after review; this pins the doc against rot).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/kcrypto-lifecycle-v1.schema.json");
        let text = std::fs::read_to_string(&path).expect("schema file readable");
        let schema: Value = serde_json::from_str(&text).expect("schema file parses");
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("required array");
        for key in [
            "schema",
            "request_id",
            "tfm_id",
            "terminal",
            "status",
            "duration_ns",
        ] {
            assert!(
                required.iter().any(|k| k.as_str() == Some(key)),
                "key {key}"
            );
        }
        assert_eq!(
            schema
                .get("properties")
                .and_then(|p| p.get("schema"))
                .and_then(|s| s.get("const")),
            Some(&serde_json::json!("kryprobe.kcrypto.lifecycle/v1")),
        );
        // Numeric bounds the validator enforces exactly: i32 status
        // range, canonical-decimal duration capped at 20 digits (u64
        // needs no more; the validator enforces the exact range).
        let status_number = schema
            .get("properties")
            .and_then(|p| p.get("status"))
            .and_then(|s| s.get("anyOf"))
            .and_then(Value::as_array)
            .and_then(|branches| branches.first())
            .expect("status number branch");
        assert_eq!(
            status_number.get("minimum"),
            Some(&serde_json::json!(-2147483648i64)),
        );
        assert_eq!(
            status_number.get("maximum"),
            Some(&serde_json::json!(2147483647i64)),
        );
        let duration_string = schema
            .get("properties")
            .and_then(|p| p.get("duration_ns"))
            .and_then(|s| s.get("anyOf"))
            .and_then(Value::as_array)
            .and_then(|branches| branches.first())
            .expect("duration string branch");
        assert_eq!(
            duration_string.get("maxLength"),
            Some(&serde_json::json!(20u64)),
        );
        assert_eq!(
            duration_string.get("pattern"),
            Some(&serde_json::json!(EXPECTED_DURATION_PATTERN)),
        );
        // ID patterns use the same portable strict end assertion
        // (`$` alone matches before a trailing newline in some
        // engines).
        for key in ["request_id", "tfm_id"] {
            let branch = schema
                .get("properties")
                .and_then(|p| p.get(key))
                .and_then(|s| {
                    s.get("anyOf")
                        .and_then(Value::as_array)
                        .and_then(|branches| branches.first())
                        .or(Some(s))
                })
                .expect("id string branch");
            assert_eq!(
                branch.get("pattern"),
                Some(&serde_json::json!(EXPECTED_ID_PATTERN)),
                "{key}"
            );
        }
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
            vec![LifecycleFinding::UnknownVersion]
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
    fn rejects_unknown_keys_without_echoing_values() {
        let mut extra = base();
        extra
            .as_object_mut()
            .expect("object")
            .insert("key_material".to_string(), serde_json::json!("secret"));
        let findings = validate_lifecycle_v1(&extra);
        assert_eq!(
            findings,
            vec![LifecycleFinding::UnknownKey {
                key: "key_material".to_string()
            }]
        );
        // Forbidden contents must not leak into diagnostics: the
        // finding names the key, never its value.
        let rendered = format!("{findings:?}");
        assert!(rendered.contains("key_material"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn reports_unknown_keys_alongside_missing_keys() {
        // Presence-layer defects are complete: a missing required
        // key must not hide an extra key.
        let mut payload = base();
        let obj = payload.as_object_mut().expect("object");
        obj.remove("terminal");
        obj.insert("key_material".to_string(), json!("secret"));
        assert_eq!(
            validate_lifecycle_v1(&payload),
            vec![
                LifecycleFinding::MissingKey {
                    key: "terminal".to_string()
                },
                LifecycleFinding::UnknownKey {
                    key: "key_material".to_string()
                },
            ]
        );
    }

    #[test]
    fn rejects_trailing_newlines() {
        // The schema patterns use a portable strict end assertion;
        // the validator agrees byte-for-byte (no `$`-before-newline
        // leniency on either side).
        for (key, value) in [
            ("request_id", "kcrypto:req-1\n"),
            ("tfm_id", "kcrypto:tfm-7\n"),
            ("duration_ns", "20\n"),
        ] {
            let mut payload = base();
            payload
                .as_object_mut()
                .expect("object")
                .insert(key.to_string(), serde_json::json!(value));
            assert!(
                matches!(
                    validate_lifecycle_v1(&payload)[..],
                    [LifecycleFinding::BadShape { .. }]
                ),
                "{key}"
            );
        }
    }

    #[test]
    fn redacts_rejected_values_on_every_path() {
        // Every rejection path must leak no input bytes: findings
        // name the key and the expected shape, never the offending
        // value.
        const SECRET: &str = "sekrit-redaction-probe";
        let mut cases: Vec<Value> = Vec::new();
        cases.push(json!([SECRET]));
        for (key, value) in [
            ("schema", json!(SECRET)),
            ("request_id", json!(SECRET)),
            ("tfm_id", json!(SECRET)),
            ("terminal", json!(SECRET)),
            ("status", json!({"nested": SECRET})),
            ("duration_ns", json!(SECRET)),
        ] {
            let mut payload = base();
            payload
                .as_object_mut()
                .expect("object")
                .insert(key.to_string(), value);
            cases.push(payload);
        }
        let mut extra = base();
        extra
            .as_object_mut()
            .expect("object")
            .insert("key_material".to_string(), json!(SECRET));
        cases.push(extra);
        for case in &cases {
            let findings = validate_lifecycle_v1(case);
            assert!(!findings.is_empty(), "{case}");
            let rendered = format!("{findings:?}");
            assert!(!rendered.contains(SECRET), "{case} -> {rendered}");
        }
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
    fn accepts_integral_float_status() {
        // JSON Schema "integer" admits zero-fraction numbers; the
        // validator matches the schema exactly on this axis.
        for text in ["-5.0", "0.0", "1e3"] {
            let mut payload = base();
            let status: Value = serde_json::from_str(text).expect("number parses");
            payload
                .as_object_mut()
                .expect("object")
                .insert("status".to_string(), status);
            assert!(validate_lifecycle_v1(&payload).is_empty(), "status {text}");
        }
        let mut frac = base();
        let status: Value = serde_json::from_str("5.5").expect("number parses");
        frac.as_object_mut()
            .expect("object")
            .insert("status".to_string(), status);
        assert!(matches!(
            validate_lifecycle_v1(&frac)[..],
            [LifecycleFinding::BadShape { .. }]
        ));
    }

    #[test]
    fn pins_u64_duration_boundary() {
        // Canonical zero, u64::MAX - 1 and u64::MAX are the boundary
        // accepts; u64::MAX + 1 (the round-1 counterexample) and a
        // 20-digit overflow are rejected — exactly like the schema
        // pattern.
        for text in ["0", "18446744073709551614", &u64::MAX.to_string()] {
            let mut payload = base();
            payload
                .as_object_mut()
                .expect("object")
                .insert("duration_ns".to_string(), serde_json::json!(text));
            assert!(validate_lifecycle_v1(&payload).is_empty(), "{text}");
        }
        for text in ["18446744073709551616", "99999999999999999999"] {
            let mut payload = base();
            payload
                .as_object_mut()
                .expect("object")
                .insert("duration_ns".to_string(), serde_json::json!(text));
            assert!(
                matches!(
                    validate_lifecycle_v1(&payload)[..],
                    [LifecycleFinding::BadShape { .. }]
                ),
                "{text}"
            );
        }
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
