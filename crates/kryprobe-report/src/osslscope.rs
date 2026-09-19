// SPDX-License-Identifier: GPL-3.0-or-later
//! osslscope report adapter (reads output docs only; no ported code).
//!
//! Matches `schema_version: observed-crypto-v1[.minor]` (major-1 gate
//! per the osslscope schema: minors add optional keys only). Maps
//! `target`/`provider`/`window`/`completeness` verbatim where small,
//! counts `executions`, and labels `check` when the `policy` key is
//! present — everything else rides `native` verbatim.

use super::{SHELL_SCHEMA_V1, Shell};
use serde_json::Value;

/// Base marker; `observed-crypto-v1.N` minors share major 1.
pub const MARKER_BASE: &str = "observed-crypto-v1";

/// True when the doc carries the major-1 report marker (exact base or
/// base + `.` + digits — `v10`/`v2` never match a prefix guess).
#[must_use]
pub fn matches_doc(doc: &Value) -> bool {
    let Some(marker) = doc.get("schema_version").and_then(Value::as_str) else {
        return false;
    };
    if marker == MARKER_BASE {
        return true;
    }
    let Some(rest) = marker.strip_prefix("observed-crypto-v1.") else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit())
}

/// Copies `key` verbatim, or null when the doc lacks it.
fn cell(doc: &Value, key: &str) -> Value {
    doc.get(key).cloned().unwrap_or(Value::Null)
}

/// Maps one report doc onto a shell (callers check [`matches_doc`]).
#[must_use]
pub fn adapt(doc: &Value) -> Shell {
    let executions = doc.get("executions").and_then(Value::as_array);
    let total_calls: u64 = executions
        .map(|rows| {
            rows.iter()
                .map(|row| row.get("count").and_then(Value::as_u64).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);
    Shell {
        schema: SHELL_SCHEMA_V1.to_owned(),
        source: "osslscope".to_owned(),
        scope: cell(doc, "target"),
        context: doc
            .get("completeness")
            .and_then(|completeness| completeness.get("status"))
            .cloned()
            .unwrap_or(Value::Null),
        operation: Value::String(
            if doc.get("policy").is_some() {
                "check"
            } else {
                "report"
            }
            .to_owned(),
        ),
        implementation: cell(doc, "provider"),
        metrics: serde_json::json!({
            "executions": executions.map_or(0, Vec::len),
            "total_calls": total_calls,
        }),
        window: cell(doc, "window"),
        evidence: cell(doc, "completeness"),
        native: doc.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{SHELL_SCHEMA_V1, validate_shell};

    #[test]
    fn adapters_osslscope_marker_versions() {
        assert!(matches_doc(
            &serde_json::json!({"schema_version": "observed-crypto-v1"})
        ));
        assert!(matches_doc(
            &serde_json::json!({"schema_version": "observed-crypto-v1.0"})
        ));
        assert!(matches_doc(
            &serde_json::json!({"schema_version": "observed-crypto-v1.12"})
        ));
        // Near-misses never match: major-only gating, no prefix guess.
        for bad in [
            "observed-crypto-v10",
            "observed-crypto-v2",
            "observed-crypto-v1.",
            "observed-crypto-v1.x",
            "observed-crypto-v1.0.1",
            "",
        ] {
            assert!(
                !matches_doc(&serde_json::json!({"schema_version": bad})),
                "{bad:?} must not match"
            );
        }
        assert!(!matches_doc(&serde_json::json!({})));
        assert!(!matches_doc(&serde_json::json!({"schema_version": 1})));
    }

    #[test]
    fn adapters_osslscope_operation_report_vs_check() {
        // The schema reserves a `policy` key for `check` output; its
        // presence selects the operation label, nothing else.
        let report = adapt(&serde_json::json!({"schema_version": "observed-crypto-v1"}));
        let json: serde_json::Value = serde_json::to_value(&report).expect("serializes");
        assert_eq!(json["operation"], "report");
        let check =
            adapt(&serde_json::json!({"schema_version": "observed-crypto-v1", "policy": {}}));
        let json: serde_json::Value = serde_json::to_value(&check).expect("serializes");
        assert_eq!(json["operation"], "check");
        assert_eq!(json["schema"], SHELL_SCHEMA_V1);
        assert!(validate_shell(&json).is_empty());
    }
}
