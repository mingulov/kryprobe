// SPDX-License-Identifier: GPL-3.0-or-later
//! p11scope profile adapter (reads output docs only; no ported code).
//!
//! Matches exactly `schema: p11scope/observed-profile/v3` (the stale
//! pre-rename marker and the `v3-metrics` sibling are unknown, never
//! guessed). Maps small salient summaries — full detail rides `native`
//! verbatim, so mapped fields stay lean sub-objects, never copies of
//! hundred-key sections.

use super::{SHELL_SCHEMA_V1, Shell};
use serde_json::Value;

/// The current profile marker (exact match only).
pub const MARKER: &str = "p11scope/observed-profile/v3";

/// True only for the exact current profile marker.
#[must_use]
pub fn matches_doc(doc: &Value) -> bool {
    doc.get("schema").and_then(Value::as_str) == Some(MARKER)
}

/// Copies `section.key` verbatim, or null when absent.
fn section(doc: &Value, section: &str, key: &str) -> Value {
    doc.get(section)
        .and_then(|value| value.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

/// Maps one profile doc onto a shell (callers check [`matches_doc`]).
#[must_use]
pub fn adapt(doc: &Value) -> Shell {
    let mode = doc
        .get("capture")
        .and_then(|capture| capture.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("profile");
    Shell {
        schema: SHELL_SCHEMA_V1.to_owned(),
        source: "p11scope".to_owned(),
        scope: doc.get("capture").cloned().unwrap_or(Value::Null),
        context: section(doc, "evidence", "completeness"),
        operation: Value::String(mode.to_owned()),
        implementation: serde_json::json!({
            "mechanisms": doc.get("mechanisms").and_then(Value::as_array).map_or(0, Vec::len),
            "functions": doc.get("functions").and_then(Value::as_array).map_or(0, Vec::len),
            "sessions": doc.get("sessions").cloned().unwrap_or(Value::Null),
        }),
        metrics: serde_json::json!({
            "attached_probes": section(doc, "evidence", "attached_probes"),
            "event_loss": section(doc, "evidence", "event_loss"),
            "slots": section(doc, "evidence", "slots"),
        }),
        window: serde_json::json!({
            "start": section(doc, "capture", "start"),
            "end": section(doc, "capture", "end"),
        }),
        evidence: serde_json::json!({
            "completeness": section(doc, "evidence", "completeness"),
            "authority": section(doc, "evidence", "authority"),
        }),
        native: doc.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{SHELL_SCHEMA_V1, validate_shell};

    #[test]
    fn adapters_p11scope_marker_exact() {
        assert!(matches_doc(
            &serde_json::json!({"schema": "p11scope/observed-profile/v3"})
        ));
        // The stale pre-rename marker, the metrics sibling doc, and
        // future versions are all unknown — never guessed.
        for bad in [
            "pkcs11-scope/observed-profile/v3",
            "p11scope/observed-profile/v3-metrics",
            "p11scope/observed-profile/v2",
            "p11scope/observed-profile/v4",
            "",
        ] {
            assert!(
                !matches_doc(&serde_json::json!({"schema": bad})),
                "{bad:?} must not match"
            );
        }
        assert!(!matches_doc(&serde_json::json!({})));
        assert!(!matches_doc(&serde_json::json!({"schema": 3})));
    }

    #[test]
    fn adapters_p11scope_operation_follows_capture_mode() {
        let doc = serde_json::json!({
            "schema": "p11scope/observed-profile/v3",
            "capture": {"mode": "profile"},
        });
        let shell = adapt(&doc);
        let json: serde_json::Value = serde_json::to_value(&shell).expect("serializes");
        assert_eq!(json["operation"], "profile");
        assert_eq!(json["schema"], SHELL_SCHEMA_V1);
        assert!(validate_shell(&json).is_empty());
        let bare = adapt(&serde_json::json!({"schema": "p11scope/observed-profile/v3"}));
        let json: serde_json::Value = serde_json::to_value(&bare).expect("serializes");
        assert_eq!(json["operation"], "profile");
    }
}
