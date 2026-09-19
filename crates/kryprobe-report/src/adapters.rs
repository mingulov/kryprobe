// SPDX-License-Identifier: GPL-3.0-or-later
//! `import` adapters: detect an osslscope report or p11scope profile doc
//! by its own versioned schema marker and map it onto the kryprobe
//! shell (D6) with the FULL original doc verbatim under `native`.
//!
//! The adapters only READ the sibling tools' output docs; no code is
//! ported from osslscope/p11scope. Unknown markers are an honest
//! [`ImportError::UnknownMarker`] naming what was found, never a
//! guessed mapping.

#[path = "osslscope.rs"]
pub mod osslscope;
#[path = "p11scope.rs"]
pub mod p11scope;

use crate::{JsonlWriter, ReportError};
use serde::Serialize;
use serde_json::Value;

/// Shell envelope const: every imported record carries exactly this.
pub const SHELL_SCHEMA_V1: &str = "kryprobe/shell/v1";

/// Stream kind stamped when a shell rides a [`JsonlWriter`] envelope.
/// Unknown to the frozen `KIND_TABLE` by design (that table is frozen):
/// the stream checker structurally accepts unknown kinds, so `report
/// FILE` validates import output clean.
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

/// One imported shell: D6 keys in D6 order (struct order, not sorted —
/// the envelope idiom), `native` carrying the FULL original doc.
#[derive(Debug, Clone, Serialize)]
pub struct Shell {
    /// Always [`SHELL_SCHEMA_V1`].
    pub schema: String,
    /// `osslscope` or `p11scope`.
    pub source: String,
    /// Best-effort scope (`target` / `capture` verbatim, else null).
    pub scope: Value,
    /// Best-effort status (`completeness` string, else null).
    pub context: Value,
    /// Best-effort operation (`report`/`check`, `capture.mode`).
    pub operation: Value,
    /// Best-effort implementation summary.
    pub implementation: Value,
    /// Best-effort counters.
    pub metrics: Value,
    /// Best-effort window.
    pub window: Value,
    /// Best-effort evidence summary.
    pub evidence: Value,
    /// FULL original parsed doc, verbatim.
    pub native: Value,
}

/// Import defects: unparseable input or an unknown schema marker.
/// Unknown markers name what was found (D6 honesty), never a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The file is not JSON.
    NotJson(String),
    /// The JSON doc is not an object.
    NotObject,
    /// Neither adapter recognized the versioned marker; carries the
    /// marker description (found values, or "no marker").
    UnknownMarker(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson(detail) => write!(f, "invalid JSON: {detail}"),
            Self::NotObject => write!(f, "import doc must be a JSON object"),
            Self::UnknownMarker(found) => write!(f, "unknown schema marker ({found})"),
        }
    }
}

impl std::error::Error for ImportError {}

/// Parses one doc and adapts it onto a shell.
pub fn adapt_bytes(bytes: &[u8]) -> Result<Shell, ImportError> {
    let doc: Value =
        serde_json::from_slice(bytes).map_err(|err| ImportError::NotJson(err.to_string()))?;
    adapt_doc(&doc)
}

/// Adapts one parsed doc: osslscope report vs p11scope profile by the
/// doc's own versioned marker; anything else is [`ImportError::UnknownMarker`].
pub fn adapt_doc(doc: &Value) -> Result<Shell, ImportError> {
    if !doc.is_object() {
        return Err(ImportError::NotObject);
    }
    if osslscope::matches_doc(doc) {
        return Ok(osslscope::adapt(doc));
    }
    if p11scope::matches_doc(doc) {
        return Ok(p11scope::adapt(doc));
    }
    Err(ImportError::UnknownMarker(describe_markers(doc)))
}

/// Names the marker values found (for the unknown-marker error).
fn describe_markers(doc: &Value) -> String {
    let mut parts = Vec::new();
    for key in ["schema_version", "schema"] {
        if let Some(found) = doc.get(key) {
            parts.push(format!("{key}={found}"));
        }
    }
    if parts.is_empty() {
        "no schema_version/schema marker".to_owned()
    } else {
        parts.join(", ")
    }
}

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

/// Emits one shell through the writer (envelope kind
/// [`IMPORT_SHELL_KIND`]).
pub fn emit_shell(writer: &mut JsonlWriter, shell: &Shell) -> Result<(), ReportError> {
    writer.emit(IMPORT_SHELL_KIND, shell)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JsonlWriter, resolve_schema, validate_str};

    /// osslscope report fixture: REAL sample, byte-copy of
    /// `osslscope/tests/goldens/report-complete.json`.
    const OSSL_FIXTURE_HASH: &str = "e9b71732cbd5e8c5";
    /// p11scope profile fixture: HAND-AUTHORED minimal versioned doc —
    /// no real emitted sample carries the current
    /// `p11scope/observed-profile/v3` marker (see the task-4 report).
    const P11_FIXTURE_HASH: &str = "2581491704fd0c1a";

    /// Golden: exact wire bytes of the osslscope fixture shell.
    const EXPECTED_OSSL_SCOPE_SHELL: &str = r#"{"schema":"kryprobe/shell/v1","source":"osslscope","scope":{"cmdline":"t","comm":"t","container_id":"","image_digest":"","pid":7},"context":"COMPLETE","operation":"report","implementation":{"build_id":"unknown","path":"/p/provider.so"},"metrics":{"executions":4,"total_calls":1204549},"window":{"actual_s":1.0,"end_epoch":1700000001.0,"planned_s":1.0,"start_epoch":1700000000.0},"evidence":{"counters":{"cold_gap_calls":0,"drain_shortfall":0,"dropped_events":0,"dropped_events_bpf":0,"dropped_events_userspace":0,"engine_fallback_uninstrumented":0,"fork_exec_ignored":0,"missed_attaches":0,"over_budget":0,"provider_changed":0,"scan_budget_exhaustions":0,"table_staleness_events":0,"uninstrumented_ops":0,"unresolved_offsets":0},"reasons":[],"status":"COMPLETE"},"native":{"child_exit":0,"completeness":{"counters":{"cold_gap_calls":0,"drain_shortfall":0,"dropped_events":0,"dropped_events_bpf":0,"dropped_events_userspace":0,"engine_fallback_uninstrumented":0,"fork_exec_ignored":0,"missed_attaches":0,"over_budget":0,"provider_changed":0,"scan_budget_exhaustions":0,"table_staleness_events":0,"uninstrumented_ops":0,"unresolved_offsets":0},"reasons":[],"status":"COMPLETE"},"drain_wall_us":0,"executions":[{"alg_class":"SHA-256","aliases":[],"cookie":1,"count":1204033,"first_ns":0,"funcid":11,"last_ns":0,"offset":0,"op":1,"provider":"default"},{"alg_class":"DES","aliases":[],"cookie":2,"count":500,"first_ns":0,"funcid":21,"last_ns":0,"offset":0,"op":2,"provider":"default"},{"alg_class":"other","aliases":[],"cookie":2,"count":9,"first_ns":0,"funcid":22,"last_ns":0,"offset":0,"op":2,"provider":"default"},{"alg_class":"ML-DSA-65","aliases":[],"cookie":13,"count":7,"first_ns":0,"funcid":31,"last_ns":0,"offset":0,"op":13,"provider":"default"}],"kernel":"test-kernel","legacy":{"capability":{"syms_present":10,"tripwires_attached":8,"tripwires_missed":2},"engine":{"calls_by_entrypoint":{"ENGINE_init":5},"engine_id_class":{"builtin":0,"dynamic":1,"other":0}},"entries":[{"class":"engine","name":"ENGINE_init","probed":true,"state":"observed"},{"class":"meth","name":"RSA_meth_new","probed":false,"state":"uninstrumented"},{"class":"lowlevel","name":"SHA256_Update","probed":true,"state":"absent"}],"flags":["engine-api-absent"],"legacy_provider":{"algs":["MD4"],"executed_calls":4,"loads":{"legacy":1}},"weak":{"executed_algs":["DES"],"executed_calls":500,"legacy_algs":["MD4"],"unknown_calls":9}},"provider":{"build_id":"unknown","path":"/p/provider.so"},"schema_version":"observed-crypto-v1.0","stale":[{"detail":[],"events":450,"generation":0,"keys":2}],"target":{"cmdline":"t","comm":"t","container_id":"","image_digest":"","pid":7},"window":{"actual_s":1.0,"end_epoch":1700000001.0,"planned_s":1.0,"start_epoch":1700000000.0}}}"#;
    /// Golden: exact wire bytes of the p11scope fixture shell.
    const EXPECTED_P11SCOPE_SHELL: &str = r#"{"schema":"kryprobe/shell/v1","source":"p11scope","scope":{"drain_interval_ms":1000,"end":"2026-09-17T05:19:56Z","kernel":"test-kernel","mode":"profile","modules":[],"privacy_mode":"allowlisted","ring_bytes":262144,"start":"2026-09-17T05:19:50Z"},"context":"COMPLETE","operation":"profile","implementation":{"functions":1,"mechanisms":1,"sessions":{"async_opened":0,"balance":0,"closed":1,"inherited":0,"opened":1,"peak_concurrent":1}},"metrics":{"attached_probes":12,"event_loss":0,"slots":2},"window":{"end":"2026-09-17T05:19:56Z","start":"2026-09-17T05:19:50Z"},"evidence":{"authority":"hash-pinned","completeness":"COMPLETE"},"native":{"capture":{"drain_interval_ms":1000,"end":"2026-09-17T05:19:56Z","kernel":"test-kernel","mode":"profile","modules":[],"privacy_mode":"allowlisted","ring_bytes":262144,"start":"2026-09-17T05:19:50Z"},"cgroups":[],"evidence":{"attached_probes":12,"authority":"hash-pinned","completeness":"COMPLETE","event_loss":0,"slots":2},"functions":[{"calls":25,"errors":3,"name":"C_OpenSession","pending_returns":0}],"logins":{},"mechanisms":[{"mechanism":1,"mechanism_hex":"0x0000000000000001","note":"test mechanism","params":null}],"schema":"p11scope/observed-profile/v3","sessions":{"async_opened":0,"balance":0,"closed":1,"inherited":0,"opened":1,"peak_concurrent":1},"templates":{"note":"test note","operations":[]}}}"#;

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

    fn canonical(value: &serde_json::Value) -> String {
        serde_json::to_string(value).expect("shell serializes")
    }

    #[test]
    fn adapters_fixture_hashes_pinned() {
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
    fn adapters_detect_both_fixtures() {
        let ossl = adapt_bytes(&fixture_bytes("osslscope-report.json")).expect("osslscope adapts");
        assert_eq!(ossl.source, "osslscope");
        let p11 = adapt_bytes(&fixture_bytes("p11scope-profile.json")).expect("p11scope adapts");
        assert_eq!(p11.source, "p11scope");
    }

    #[test]
    fn adapters_shell_keys_exact_d6() {
        // `serde_json::Map` sorts keys (no `preserve_order`), so the key
        // SET is asserted on the `Value` while the D6 ORDER is asserted
        // on the serialized struct (field order, like the envelope).
        let mut want = [
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
        want.sort_unstable();
        for name in ["osslscope-report.json", "p11scope-profile.json"] {
            let shell = adapt_bytes(&fixture_bytes(name)).expect("adapts");
            let json: serde_json::Value = serde_json::to_value(&shell).expect("shell serializes");
            let object = json.as_object().expect("shell is an object");
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, want, "{name}: D6 key set exact");
            assert_eq!(json["schema"], SHELL_SCHEMA_V1);
            // Order from the struct serialization (`Value` re-sorts).
            let text = serde_json::to_string(&shell).expect("shell serializes");
            let mut cursor = 0;
            for key in [
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
            ] {
                let needle = format!("\"{key}\":");
                let at = text[cursor..]
                    .find(&needle)
                    .unwrap_or_else(|| panic!("{name}: shell misses {key}"));
                cursor += at + needle.len();
            }
        }
    }

    #[test]
    fn adapters_native_verbatim_canonical_bytes() {
        // MANDATORY losslessness proof: canonical JSON of `native` is
        // byte-identical to canonical JSON of the original parsed doc.
        for name in ["osslscope-report.json", "p11scope-profile.json"] {
            let raw = fixture_bytes(name);
            let original: serde_json::Value = serde_json::from_slice(&raw).expect("fixture parses");
            let shell = adapt_bytes(&raw).expect("adapts");
            let json: serde_json::Value = serde_json::to_value(&shell).expect("shell serializes");
            assert_eq!(
                canonical(&json["native"]),
                canonical(&original),
                "{name}: native must equal the original doc"
            );
        }
    }

    #[test]
    fn adapters_shell_validates_under_kind_validator() {
        for name in ["osslscope-report.json", "p11scope-profile.json"] {
            let shell = adapt_bytes(&fixture_bytes(name)).expect("adapts");
            let json: serde_json::Value = serde_json::to_value(&shell).expect("shell serializes");
            assert!(
                validate_shell(&json).is_empty(),
                "{name}: findings {:?}",
                validate_shell(&json)
            );
        }
        // The validator bites: a shell missing D6 keys is rejected.
        let thin = serde_json::json!({"schema": SHELL_SCHEMA_V1});
        assert!(!validate_shell(&thin).is_empty());
    }

    #[test]
    fn adapters_emitted_stream_validates() {
        // Shells ride `JsonlWriter` envelopes, so `report FILE` on
        // import output validates clean under the real validator.
        let schema = resolve_schema();
        let schema_bytes = schema.bytes().expect("schema resolves");
        for name in ["osslscope-report.json", "p11scope-profile.json"] {
            let shell = adapt_bytes(&fixture_bytes(name)).expect("adapts");
            let mut writer = JsonlWriter::new("session:import");
            emit_shell(&mut writer, &shell).expect("shell emits");
            let findings = validate_str(writer.finish(), schema_bytes);
            assert!(
                findings.is_empty(),
                "{name}: emitted stream findings {findings:?}"
            );
        }
    }

    #[test]
    fn adapters_unknown_marker_names_it() {
        let doc = serde_json::json!({"schema": "p11scope/observed-profile/v9"});
        let err = adapt_doc(&doc).expect_err("v9 must not adapt");
        assert!(
            err.to_string().contains("p11scope/observed-profile/v9"),
            "error names the marker: {err}"
        );
        let stale = serde_json::json!({"schema": "pkcs11-scope/observed-profile/v3"});
        let err = adapt_doc(&stale).expect_err("stale rename must not adapt");
        assert!(
            err.to_string().contains("pkcs11-scope/observed-profile/v3"),
            "error names the marker: {err}"
        );
        let bare = serde_json::json!({"hello": "world"});
        assert!(matches!(
            adapt_doc(&bare),
            Err(ImportError::UnknownMarker(_))
        ));
    }

    #[test]
    fn adapters_reject_invalid_docs() {
        assert!(matches!(
            adapt_bytes(b"not json"),
            Err(ImportError::NotJson(_))
        ));
        assert!(matches!(
            adapt_bytes(b"[1, 2]"),
            Err(ImportError::NotObject)
        ));
    }

    #[test]
    fn adapters_golden_shells_pinned() {
        // Goldens pin the exact wire bytes (struct serialization: D6
        // key order top-level, sorted nested maps).
        let ossl = adapt_bytes(&fixture_bytes("osslscope-report.json")).expect("adapts");
        assert_eq!(
            serde_json::to_string(&ossl).expect("shell serializes"),
            EXPECTED_OSSL_SCOPE_SHELL
        );
        let p11 = adapt_bytes(&fixture_bytes("p11scope-profile.json")).expect("adapts");
        assert_eq!(
            serde_json::to_string(&p11).expect("shell serializes"),
            EXPECTED_P11SCOPE_SHELL
        );
    }
}
