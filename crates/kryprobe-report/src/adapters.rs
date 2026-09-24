// SPDX-License-Identifier: GPL-3.0-or-later
//! Retired `import` shell: historical structural compatibility only.
//!
//! KryProbe is a kernel-crypto-only observer (ADR-0004): no command
//! ingests third-party docs, and the osslscope/p11scope mapping
//! implementations are removed. What remains is the frozen reader
//! contract for old output: an `import_shell` payload keeps exactly
//! the D6 keys with schema [`SHELL_SCHEMA_V1`], and old
//! `kryprobe.event/v0` envelopes carrying kind [`IMPORT_SHELL_KIND`]
//! still validate structurally (`report FILE` accepts unknown kinds).
//!
//! The legacy input docs under `tests/fixtures/` are preserved
//! byte-for-byte as provenance (hash-pinned below); nothing adapts
//! them. The frozen `import-shell-v1.jsonl` record is old emitted
//! output kept so the structural reader stays honest.

use serde_json::Value;

/// Shell envelope const: every imported record carries exactly this.
pub const SHELL_SCHEMA_V1: &str = "kryprobe/shell/v1";

/// Stream kind stamped when a shell rides a `JsonlWriter` envelope.
/// Unknown to the frozen `KIND_TABLE` by design (that table is frozen):
/// the stream checker structurally accepts unknown kinds, so `report
/// FILE` validates old import output clean.
pub const IMPORT_SHELL_KIND: &str = "import_shell";

/// D6 shell keys in D6 order.
pub const SHELL_KEYS: &[&str] = &[
    "schema",
    "source",
    "scope",
    "context",
    "operation",
    "implementation",
    "metrics",
    "window",
    "evidence",
    "native",
];

/// Shell kind check: every D6 key present and `schema` exact. Empty
/// means the shell validates; the caller needs no other acceptance.
#[must_use]
pub fn validate_shell(shell: &Value) -> Vec<String> {
    let Some(object) = shell.as_object() else {
        return vec!["shell is not a JSON object".to_owned()];
    };
    let mut findings = Vec::new();
    for key in SHELL_KEYS {
        if !object.contains_key(*key) {
            findings.push(format!("missing shell key '{key}'"));
        }
    }
    if let Some(schema) = object.get("schema")
        && schema.as_str() != Some(SHELL_SCHEMA_V1)
    {
        findings.push(format!("schema is {schema}, want '{SHELL_SCHEMA_V1}'"));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{resolve_schema, validate_str};

    /// Retired osslscope input doc: preserved bytes, never adapted.
    const OSSL_FIXTURE_HASH: &str = "e9b71732cbd5e8c5";
    /// Retired p11scope input doc: preserved bytes, never adapted.
    const P11_FIXTURE_HASH: &str = "2581491704fd0c1a";

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read(&path).expect("fixture readable")
    }

    fn fnv1a_hex(bytes: &[u8]) -> String {
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }

    #[test]
    fn legacy_input_fixtures_preserved() {
        // Provenance only: the retired adapter inputs stay byte-identical.
        // Nothing in the tree adapts them (no `adapt_*` exists anymore).
        assert_eq!(
            fnv1a_hex(&fixture_bytes("osslscope-report.json")),
            OSSL_FIXTURE_HASH
        );
        assert_eq!(
            fnv1a_hex(&fixture_bytes("p11scope-profile.json")),
            P11_FIXTURE_HASH
        );
    }

    #[test]
    fn historical_import_shell_record_validates() {
        // Old `import` output still reads: the frozen `import_shell`
        // event-v0 record validates clean under the real validator and
        // its payload validates under the D6 shell check.
        let raw = fixture_bytes("import-shell-v1.jsonl");
        let text = String::from_utf8(raw).expect("fixture utf-8");
        assert_eq!(text.lines().count(), 1, "one frozen record");
        let schema = resolve_schema();
        let schema_bytes = schema.bytes().expect("schema resolves");
        let findings = validate_str(&text, schema_bytes);
        assert!(findings.is_empty(), "findings {findings:?}");
        let record: Value = serde_json::from_str(text.trim_end()).expect("record parses");
        assert_eq!(record["schema"], "kryprobe.event/v0");
        assert_eq!(record["kind"], IMPORT_SHELL_KIND);
        assert!(
            validate_shell(&record["payload"]).is_empty(),
            "shell findings {:?}",
            validate_shell(&record["payload"])
        );
    }

    #[test]
    fn shell_schema_still_requires_shell_keys() {
        // 3B-M7 (kept): `schemas/shell-v1.schema.json` requires exactly
        // the emitted shell keys — schema and reader cannot drift.
        let schema = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/shell-v1.schema.json");
        let text = std::fs::read_to_string(&schema).expect("shell schema reads");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("schema parses");
        let mut required: Vec<&str> = doc["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|key| key.as_str().expect("string key"))
            .collect();
        required.sort_unstable();
        let mut want = SHELL_KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(required, want);
        assert_eq!(doc["properties"]["schema"]["const"], SHELL_SCHEMA_V1);
    }
}
