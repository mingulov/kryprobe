// SPDX-License-Identifier: GPL-3.0-or-later
//! workload-report-v2 validator + schema dispatch (Stage 2A contract).
//!
//! Enforces `schemas/workload-report-v2.schema.json` on a standalone
//! report value: required keys, wire shapes, the version const, native
//! identity (inline or collision-qualified dictionary), the authoritative
//! ledger, the partition/ledger link, selector/metadata/coverage typing,
//! and count budgets. Unknown schema values fail closed. The schema bytes
//! are freeze-pinned (FNV over the compiled-in copy) with dev-tree drift
//! detection, mirroring event-v0. Findings never echo untrusted input
//! bytes (positions such as `contexts[3]` are safe and included).

use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, MAX_REPORT_V2_BYTES, MAX_STRING_FIELD_BYTES,
    MAX_V2_CONTEXT_ROWS, MAX_V2_DICTIONARY_ENTRIES, Relationship, ValidityInterval, WorkloadOrigin,
};
use serde_json::Value;

/// The workload-report-v2 schema id: the dispatch const.
pub const SCHEMA_ID: &str = "kryprobe.workload-report.v2";

/// The frozen schema bytes compiled into this crate.
const EMBEDDED_SCHEMA: &str = include_str!("../../../../schemas/workload-report-v2.schema.json");

/// Fixed freeze pin (FNV-1a 64 hex) over the v2 schema bytes: any schema
/// edit must update this pin deliberately (E01).
pub const WORKLOAD_V2_SCHEMA_FNV1A: &str = "92e9d634369c605c";

/// Required top-level keys, in schema order.
const REQUIRED: &[&str] = &[
    "schema",
    "session",
    "interval",
    "profile",
    "boundary",
    "dictionary",
    "contexts",
    "ledger",
    "partition",
    "selectors",
    "scope",
    "metadata",
    "coverage",
];

/// One workload-v2 defect; empty means the report validates clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Finding {
    /// The value is not a JSON object.
    NotAnObject,
    /// A required top-level key is absent.
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
        /// Offending key path.
        key: String,
        /// What the key must hold.
        expected: String,
    },
    /// Well-shaped fields contradict each other (e.g. ledger sums).
    InvalidCombination {
        /// What contradicts what.
        detail: String,
    },
    /// Two dictionary entries share one id with different content, or
    /// one id repeats at all (fail-closed: ids are unique).
    DictionaryCollision {
        /// Static description (no input echo).
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
/// `None` when the bytes match, a [`V2Finding::SchemaDrift`] otherwise.
/// Callers pass the dev-tree copy when present (installed binaries
/// validate embed-only); see the event-v0 pattern.
#[must_use]
pub fn check_schema_drift(schema_disk_bytes: &[u8]) -> Option<V2Finding> {
    let actual = format!("{:016x}", fnv1a64(schema_disk_bytes));
    if actual == WORKLOAD_V2_SCHEMA_FNV1A {
        None
    } else {
        Some(V2Finding::SchemaDrift {
            expected: WORKLOAD_V2_SCHEMA_FNV1A.to_string(),
            actual,
        })
    }
}

/// Dispatch on a schema value: only [`SCHEMA_ID`] routes to this
/// validator; every other value (including v1) refuses typed.
pub fn dispatch_schema(schema: &str) -> Result<(), String> {
    if schema == SCHEMA_ID {
        Ok(())
    } else {
        Err(format!(
            "schema mismatch: not '{SCHEMA_ID}' (offered value withheld)"
        ))
    }
}

/// Validate raw report bytes: budget, then parse, then
/// [`validate_workload_v2`]. Returns `Ok(())` only when the report
/// validates clean.
pub fn validate_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_REPORT_V2_BYTES {
        return Err(format!("report exceeds {MAX_REPORT_V2_BYTES} bytes"));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| format!("report is not valid JSON for schema '{SCHEMA_ID}'"))?;
    let findings = validate_workload_v2(&value);
    if findings.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "workload-report-v2 schema defects: {}",
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

/// Parse a digit string as `u64` (overflow refuses).
fn parse_digit(value: &Value) -> Option<u64> {
    value.as_str()?.parse::<u64>().ok()
}

/// Lowercase-hex string of exactly `len` chars.
fn is_hex_string(value: &Value, len: usize) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == len
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// Bounded non-empty string (byte bound).
fn is_bounded_string(value: &Value, max_bytes: usize) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= max_bytes)
}

/// Bounded string, possibly empty (display fields).
fn is_bounded_string_or_empty(value: &Value, max_bytes: usize) -> bool {
    value.as_str().is_some_and(|s| s.len() <= max_bytes)
}

/// Integer in `0..=max`.
fn is_bounded_int(value: &Value, max: u64) -> bool {
    value.as_u64().is_some_and(|n| n <= max)
}

/// Push a shape defect.
fn bad(findings: &mut Vec<V2Finding>, key: String, expected: &str) {
    findings.push(V2Finding::BadShape {
        key,
        expected: expected.to_string(),
    });
}

/// Check `obj` carries no keys outside `allowed`.
fn check_no_extra_keys(obj: &serde_json::Map<String, Value>, allowed: &[&str]) -> bool {
    obj.keys().all(|k| allowed.contains(&k.as_str()))
}

/// Validates one workload-report-v2 value. Fail-closed: any defect means
/// the report must not be evaluated as clean. Layers: object shape, then
/// presence (missing + extra together), then version, then shapes, then
/// counts, then combinations — one defect class never cascades into
/// another.
#[must_use]
pub fn validate_workload_v2(payload: &Value) -> Vec<V2Finding> {
    let Some(obj) = payload.as_object() else {
        return vec![V2Finding::NotAnObject];
    };
    let mut findings = Vec::new();
    for key in REQUIRED {
        if !obj.contains_key(*key) {
            findings.push(V2Finding::MissingKey {
                key: (*key).to_string(),
            });
        }
    }
    for _ in obj.keys().filter(|k| !REQUIRED.contains(&k.as_str())) {
        findings.push(V2Finding::UnknownKey);
    }
    if !findings.is_empty() {
        return findings;
    }
    if obj.get("schema").and_then(Value::as_str) != Some(SCHEMA_ID) {
        return vec![V2Finding::UnknownVersion];
    }
    validate_session(obj, &mut findings);
    validate_interval_shape(obj, &mut findings);
    for key in ["profile", "boundary"] {
        if !obj
            .get(key)
            .is_some_and(|v| is_bounded_string(v, MAX_STRING_FIELD_BYTES))
        {
            bad(
                &mut findings,
                key.to_string(),
                "non-empty string <= 256 bytes",
            );
        }
    }
    validate_dictionary_shape(obj, &mut findings);
    validate_contexts_shape(obj, &mut findings);
    validate_ledger_shape(obj, &mut findings);
    validate_partition_shape(obj, &mut findings);
    validate_selectors(obj, &mut findings);
    validate_scope(obj, &mut findings);
    validate_metadata(obj, &mut findings);
    validate_coverage(obj, &mut findings);
    if !findings.is_empty() {
        return findings;
    }
    // Counts: contexts/dictionary budgets.
    let contexts_len = obj
        .get("contexts")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if contexts_len > MAX_V2_CONTEXT_ROWS {
        bad(&mut findings, "contexts".to_string(), "at most 1024 rows");
    }
    let dictionary_len = obj
        .get("dictionary")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if dictionary_len > MAX_V2_DICTIONARY_ENTRIES {
        bad(
            &mut findings,
            "dictionary".to_string(),
            "at most 1024 entries",
        );
    }
    if !findings.is_empty() {
        return findings;
    }
    validate_combinations(obj, &mut findings);
    findings
}

/// Session shape: 32-char lowercase-hex session id, non-empty
/// kernel identity within 128 bytes.
fn validate_session(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(session) = obj.get("session").and_then(Value::as_object) else {
        bad(findings, "session".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(session, &["session_id", "kernel_identity"]) {
        findings.push(V2Finding::UnknownKey);
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
        .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 128))
    {
        bad(
            findings,
            "session.kernel_identity".to_string(),
            "non-empty string <= 128 bytes",
        );
    }
}

/// Interval shape: digit strings + consistency enum (order and inversion
/// are combination checks).
fn validate_interval_shape(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(interval) = obj.get("interval").and_then(Value::as_object) else {
        bad(findings, "interval".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(interval, &["start_ns", "end_ns", "consistency", "clock"]) {
        findings.push(V2Finding::UnknownKey);
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
    if interval.get("clock").and_then(Value::as_str) != Some("monotonic_boot") {
        bad(findings, "interval.clock".to_string(), "monotonic_boot");
    }
}

/// One native-identity tuple shape (dictionary entries and inline
/// `native` objects share it). Dictionary entries additionally carry a
/// `dict_id` (checked by the caller) and a `kh` digit string.
fn validate_native_shape(
    value: Option<&Value>,
    path: &str,
    dictionary_entry: bool,
    findings: &mut Vec<V2Finding>,
) {
    let Some(native) = value.and_then(Value::as_object) else {
        bad(findings, path.to_string(), "object");
        return;
    };
    let mut allowed = vec!["family", "op", "result", "context", "algorithm", "driver"];
    if dictionary_entry {
        allowed.push("dict_id");
        allowed.push("kh");
    }
    if !check_no_extra_keys(native, &allowed) {
        findings.push(V2Finding::UnknownKey);
    }
    for key in ["family", "op", "result", "context"] {
        if !native.get(key).is_some_and(|v| is_bounded_int(v, 255)) {
            bad(findings, format!("{path}.{key}"), "integer 0..=255");
        }
    }
    if !native
        .get("algorithm")
        .is_some_and(|v| is_bounded_string(v, MAX_STRING_FIELD_BYTES))
    {
        bad(
            findings,
            format!("{path}.algorithm"),
            "non-empty string <= 256 bytes",
        );
    }
    // The driver is absent exactly when unavailable: allocation captures
    // carry zero driver bytes, so absence validates (explicitly
    // unavailable) while present-but-empty refuses.
    if let Some(driver) = native.get("driver")
        && !is_bounded_string(driver, MAX_STRING_FIELD_BYTES)
    {
        bad(
            findings,
            format!("{path}.driver"),
            "non-empty string <= 256 bytes (absent when unavailable)",
        );
    }
    if dictionary_entry && !native.get("kh").is_some_and(is_digit_string) {
        bad(findings, format!("{path}.kh"), "digit string");
    }
}

/// Dictionary shape: every entry well-formed with a non-empty id.
fn validate_dictionary_shape(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(entries) = obj.get("dictionary").and_then(Value::as_array) else {
        bad(findings, "dictionary".to_string(), "array");
        return;
    };
    for (i, entry) in entries.iter().enumerate() {
        let path = format!("dictionary[{i}]");
        let Some(item) = entry.as_object() else {
            bad(findings, path, "object");
            continue;
        };
        if !item
            .get("dict_id")
            .is_some_and(|v| is_bounded_string(v, MAX_STRING_FIELD_BYTES))
        {
            bad(
                findings,
                format!("{path}.dict_id"),
                "non-empty string <= 256 bytes",
            );
        }
        validate_native_shape(Some(entry), &path, true, findings);
    }
}

/// Context row shape, including the native-identity XOR, workload, and
/// attribution sub-objects.
fn validate_contexts_shape(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
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
                "native",
                "native_ref",
                "workload",
                "attribution",
            ],
        ) {
            findings.push(V2Finding::UnknownKey);
        }
        // Lifetime is REQUIRED (D03): a value or explicit unreadable
        // "0" — reused TGIDs across lifetimes must never export
        // indistinguishable rows.
        for key in ["kh", "cgroup_id", "calls", "start_ns"] {
            if !row.get(key).is_some_and(is_digit_string) {
                bad(findings, format!("{path}.{key}"), "digit string");
            }
        }
        for key in ["tgid", "uid"] {
            if !row
                .get(key)
                .is_some_and(|v| is_bounded_int(v, 4_294_967_295))
            {
                bad(findings, format!("{path}.{key}"), "integer 0..=4294967295");
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
        match (row.contains_key("native"), row.contains_key("native_ref")) {
            (true, false) => {
                validate_native_shape(
                    row.get("native"),
                    &format!("{path}.native"),
                    false,
                    findings,
                );
            }
            (false, true) => {
                if !row
                    .get("native_ref")
                    .is_some_and(|v| is_bounded_string(v, MAX_STRING_FIELD_BYTES))
                {
                    bad(
                        findings,
                        format!("{path}.native_ref"),
                        "non-empty string <= 256 bytes",
                    );
                }
            }
            _ => bad(findings, path.clone(), "exactly one of native | native_ref"),
        }
        if let Some(workload) = row.get("workload") {
            validate_workload_shape(workload, &format!("{path}.workload"), findings);
        }
        if let Some(attribution) = row.get("attribution") {
            validate_attribution_shape(attribution, &format!("{path}.attribution"), findings);
        }
    }
}

/// Workload sub-object shape: typed container/pod/cluster/node/ancestor
/// associations with full-ID rules.
fn validate_workload_shape(value: &Value, path: &str, findings: &mut Vec<V2Finding>) {
    let Some(workload) = value.as_object() else {
        bad(findings, path.to_string(), "object");
        return;
    };
    if !check_no_extra_keys(
        workload,
        &["container", "pod", "cluster", "node", "ancestor_container"],
    ) {
        findings.push(V2Finding::UnknownKey);
    }
    if workload.is_empty() {
        bad(
            findings,
            path.to_string(),
            "at least one association when present",
        );
    }
    for key in ["container", "ancestor_container"] {
        if let Some(container) = workload.get(key) {
            validate_container_shape(container, &format!("{path}.{key}"), findings);
        }
    }
    if let Some(pod) = workload.get("pod") {
        let pod_path = format!("{path}.pod");
        let Some(pod) = pod.as_object() else {
            bad(findings, pod_path, "object");
            return;
        };
        if !check_no_extra_keys(pod, &["cluster", "uid", "name", "namespace"]) {
            findings.push(V2Finding::UnknownKey);
        }
        for key in ["cluster", "uid"] {
            if !pod
                .get(key)
                .is_some_and(|v| is_bounded_string(v, MAX_STRING_FIELD_BYTES))
            {
                bad(
                    findings,
                    format!("{pod_path}.{key}"),
                    "non-empty string <= 256 bytes",
                );
            }
        }
        for key in ["name", "namespace"] {
            if !pod
                .get(key)
                .is_some_and(|v| is_bounded_string_or_empty(v, MAX_STRING_FIELD_BYTES))
            {
                bad(findings, format!("{pod_path}.{key}"), "string <= 256 bytes");
            }
        }
    }
    for key in ["cluster", "node"] {
        if let Some(v) = workload.get(key)
            && !is_bounded_string_or_empty(v, MAX_STRING_FIELD_BYTES)
        {
            bad(findings, format!("{path}.{key}"), "string <= 256 bytes");
        }
    }
}

/// Container sub-object shape: non-empty runtime, FULL 64-char
/// lowercase-hex id, optional bounded lifetime.
fn validate_container_shape(value: &Value, path: &str, findings: &mut Vec<V2Finding>) {
    let Some(container) = value.as_object() else {
        bad(findings, path.to_string(), "object");
        return;
    };
    if !check_no_extra_keys(container, &["runtime", "id", "lifetime"]) {
        findings.push(V2Finding::UnknownKey);
    }
    if !container
        .get("runtime")
        .is_some_and(|v| is_bounded_string(v, MAX_STRING_FIELD_BYTES))
    {
        bad(
            findings,
            format!("{path}.runtime"),
            "non-empty string <= 256 bytes",
        );
    }
    if !container.get("id").is_some_and(|v| is_hex_string(v, 64)) {
        bad(findings, format!("{path}.id"), "64 lowercase hex chars");
    }
    if let Some(lifetime) = container.get("lifetime")
        && !is_bounded_string_or_empty(lifetime, MAX_STRING_FIELD_BYTES)
    {
        bad(findings, format!("{path}.lifetime"), "string <= 256 bytes");
    }
}

/// Attribution sub-object shape: frozen method/source/status vocabulary
/// plus an optional digit-string validity pair.
fn validate_attribution_shape(value: &Value, path: &str, findings: &mut Vec<V2Finding>) {
    let Some(attribution) = value.as_object() else {
        bad(findings, path.to_string(), "object");
        return;
    };
    if !check_no_extra_keys(
        attribution,
        &["relationship", "method", "source", "status", "validity"],
    ) {
        findings.push(V2Finding::UnknownKey);
    }
    if !attribution
        .get("relationship")
        .and_then(Value::as_str)
        .is_some_and(|r| {
            matches!(
                r,
                "hook_context"
                    | "submitter"
                    | "completion_context"
                    | "workload_origin"
                    | "consumer"
            )
        })
    {
        bad(
            findings,
            format!("{path}.relationship"),
            "frozen relationship vocabulary",
        );
    }
    if !attribution
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|m| {
            matches!(
                m,
                "captured_cgroup"
                    | "cgroup_inode_bind"
                    | "metadata_file"
                    | "metadata_label"
                    | "runtime_adapter"
                    | "unresolved"
            )
        })
    {
        bad(
            findings,
            format!("{path}.method"),
            "frozen method vocabulary",
        );
    }
    if !attribution
        .get("source")
        .and_then(Value::as_str)
        .is_some_and(|s| {
            matches!(
                s,
                "kernel_capture"
                    | "operator_metadata_file"
                    | "runtime_adapter"
                    | "host_proc"
                    | "unknown"
            )
        })
    {
        bad(
            findings,
            format!("{path}.source"),
            "frozen source vocabulary",
        );
    }
    if !attribution
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|s| {
            matches!(
                s,
                "verified" | "asserted" | "unresolved" | "ambiguous" | "stale" | "unsupported"
            )
        })
    {
        bad(
            findings,
            format!("{path}.status"),
            "frozen status vocabulary",
        );
    }
    if let Some(validity) = attribution.get("validity") {
        let valid = validity.as_object().is_some_and(|window| {
            check_no_extra_keys(window, &["start_ns", "end_ns", "clock"])
                && window.get("start_ns").is_some_and(is_digit_string)
                && window.get("end_ns").is_some_and(is_digit_string)
                && window.get("clock").and_then(Value::as_str) == Some("monotonic_boot")
        });
        if !valid {
            bad(
                findings,
                format!("{path}.validity"),
                "{start_ns, end_ns, clock} validity window",
            );
        }
    }
}

/// Ledger shape: digit operands + consistency + gap flag.
fn validate_ledger_shape(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(ledger) = obj.get("ledger").and_then(Value::as_object) else {
        bad(findings, "ledger".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(
        ledger,
        &[
            "system_total",
            "per_context_sum",
            "unknown",
            "consistency",
            "gap_unreconciled",
            "system_saturated",
            "per_context_saturated",
            "refused_inserts",
        ],
    ) {
        findings.push(V2Finding::UnknownKey);
    }
    for key in [
        "system_total",
        "per_context_sum",
        "unknown",
        "refused_inserts",
    ] {
        if !ledger.get(key).is_some_and(is_digit_string) {
            bad(findings, format!("ledger.{key}"), "digit string");
        }
    }
    if !ledger
        .get("consistency")
        .and_then(Value::as_str)
        .is_some_and(|c| c == "quiescent" || c == "unproven")
    {
        bad(
            findings,
            "ledger.consistency".to_string(),
            "quiescent | unproven",
        );
    }
    if !ledger
        .get("gap_unreconciled")
        .is_some_and(Value::is_boolean)
    {
        bad(findings, "ledger.gap_unreconciled".to_string(), "boolean");
    }
    for key in ["system_saturated", "per_context_saturated"] {
        if !ledger.get(key).is_some_and(Value::is_boolean) {
            bad(findings, format!("ledger.{key}"), "boolean");
        }
    }
}

/// Partition shape: three digit strings.
fn validate_partition_shape(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(partition) = obj.get("partition").and_then(Value::as_object) else {
        bad(findings, "partition".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(partition, &["matched", "nonmatched", "unknown_match"]) {
        findings.push(V2Finding::UnknownKey);
    }
    for key in ["matched", "nonmatched", "unknown_match"] {
        if !partition.get(key).is_some_and(is_digit_string) {
            bad(findings, format!("partition.{key}"), "digit string");
        }
    }
}

/// Selector shape: known kinds only, with kind-matched extras. Pod and
/// runtime selectors refuse until M2: only `none`, `cgroup-id`, and
/// `container-id` exist.
fn validate_selectors(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(selectors) = obj.get("selectors").and_then(Value::as_object) else {
        bad(findings, "selectors".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(selectors, &["kind", "cgroup_id", "container"]) {
        findings.push(V2Finding::UnknownKey);
    }
    let kind = selectors.get("kind").and_then(Value::as_str);
    match kind {
        Some("none") => {
            if selectors.contains_key("cgroup_id") || selectors.contains_key("container") {
                bad(
                    findings,
                    "selectors".to_string(),
                    "kind none carries no extras",
                );
            }
        }
        Some("cgroup-id") => {
            if !selectors.get("cgroup_id").is_some_and(is_digit_string) {
                bad(
                    findings,
                    "selectors.cgroup_id".to_string(),
                    "digit string (required for cgroup-id)",
                );
            }
            if selectors.contains_key("container") {
                bad(
                    findings,
                    "selectors".to_string(),
                    "kind cgroup-id carries no container",
                );
            }
        }
        Some("container-id") => {
            if selectors.contains_key("cgroup_id") {
                bad(
                    findings,
                    "selectors".to_string(),
                    "kind container-id carries no cgroup_id",
                );
            }
            match selectors.get("container") {
                Some(container) => {
                    validate_selector_container_shape(container, findings);
                }
                None => bad(
                    findings,
                    "selectors.container".to_string(),
                    "container object (required for container-id)",
                ),
            }
        }
        _ => bad(
            findings,
            "selectors.kind".to_string(),
            "none | cgroup-id | container-id",
        ),
    }
}

/// Selector container shape: runtime + FULL id ONLY, matching the
/// frozen schema — unlike workload containers, selectors carry no
/// lifetime, so any extra key (including `lifetime`) refuses.
fn validate_selector_container_shape(value: &Value, findings: &mut Vec<V2Finding>) {
    const PATH: &str = "selectors.container";
    let Some(container) = value.as_object() else {
        bad(findings, PATH.to_string(), "object");
        return;
    };
    if !check_no_extra_keys(container, &["runtime", "id"]) {
        findings.push(V2Finding::UnknownKey);
    }
    if !container
        .get("runtime")
        .is_some_and(|v| is_bounded_string(v, MAX_STRING_FIELD_BYTES))
    {
        bad(
            findings,
            format!("{PATH}.runtime"),
            "non-empty string <= 256 bytes",
        );
    }
    if !container.get("id").is_some_and(|v| is_hex_string(v, 64)) {
        bad(findings, format!("{PATH}.id"), "64 lowercase hex chars");
    }
}

/// Scope shape: capture scope is always `system` in M1 (workload
/// selectors are post-ingestion views, never confinement); the report
/// scope and grouping are explicit.
fn validate_scope(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(scope) = obj.get("scope").and_then(Value::as_object) else {
        bad(findings, "scope".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(scope, &["capture_scope", "report_scope", "group_by"]) {
        findings.push(V2Finding::UnknownKey);
    }
    if scope.get("capture_scope").and_then(Value::as_str) != Some("system") {
        bad(findings, "scope.capture_scope".to_string(), "system");
    }
    if !scope
        .get("report_scope")
        .and_then(Value::as_str)
        .is_some_and(|s| matches!(s, "unscoped" | "scoped"))
    {
        bad(
            findings,
            "scope.report_scope".to_string(),
            "unscoped | scoped",
        );
    }
    if !scope
        .get("group_by")
        .and_then(Value::as_str)
        .is_some_and(|g| matches!(g, "none" | "cgroup" | "container"))
    {
        bad(
            findings,
            "scope.group_by".to_string(),
            "none | cgroup | container",
        );
    }
}

/// Metadata availability shape: typed status with a reason required
/// exactly when unavailable.
fn validate_metadata(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(metadata) = obj.get("metadata").and_then(Value::as_object) else {
        bad(findings, "metadata".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(metadata, &["status", "reason"]) {
        findings.push(V2Finding::UnknownKey);
    }
    match metadata.get("status").and_then(Value::as_str) {
        Some("available") => {
            if metadata.contains_key("reason") {
                bad(
                    findings,
                    "metadata".to_string(),
                    "reason must be absent when available",
                );
            }
        }
        Some("unavailable") => {
            if !metadata
                .get("reason")
                .and_then(Value::as_str)
                .is_some_and(|r| {
                    matches!(
                        r,
                        "no_principal"
                            | "helper_refused"
                            | "budget_exceeded"
                            | "unsupported_environment"
                            | "parse_failed"
                    )
                })
            {
                bad(
                    findings,
                    "metadata.reason".to_string(),
                    "typed unavailability reason (required when unavailable)",
                );
            }
        }
        _ => bad(
            findings,
            "metadata.status".to_string(),
            "available | unavailable",
        ),
    }
}

/// Coverage shape: four independent completeness values.
fn validate_coverage(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let Some(coverage) = obj.get("coverage").and_then(Value::as_object) else {
        bad(findings, "coverage".to_string(), "object");
        return;
    };
    if !check_no_extra_keys(
        coverage,
        &["capture", "attribution", "metadata", "correlation"],
    ) {
        findings.push(V2Finding::UnknownKey);
    }
    for key in ["capture", "attribution", "metadata", "correlation"] {
        if !coverage
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|c| matches!(c, "complete" | "partial" | "unavailable"))
        {
            bad(
                findings,
                format!("coverage.{key}"),
                "complete | partial | unavailable",
            );
        }
    }
}

/// Combination checks over well-shaped reports: dictionary uniqueness,
/// reference resolution, ledger arithmetic, partition/ledger links,
/// context sums, interval order, and evidence rules.
fn validate_combinations(obj: &serde_json::Map<String, Value>, findings: &mut Vec<V2Finding>) {
    let interval = obj
        .get("interval")
        .and_then(Value::as_object)
        .expect("shapes checked");
    let start = parse_digit(interval.get("start_ns").expect("shapes checked"));
    let end = parse_digit(interval.get("end_ns").expect("shapes checked"));
    match (start, end) {
        (Some(start), Some(end)) if start <= end => {}
        (Some(_), Some(_)) => findings.push(V2Finding::InvalidCombination {
            detail: "interval is inverted".to_string(),
        }),
        _ => findings.push(V2Finding::InvalidCombination {
            detail: "interval bounds do not parse as u64".to_string(),
        }),
    }
    let interval_consistency = interval
        .get("consistency")
        .and_then(Value::as_str)
        .expect("shapes checked");
    // The counted capture/report window for attribution coverage (R3):
    // usable only when ordered and representable — otherwise the
    // interval finding above already refuses and attribution checks must
    // not cascade.
    let capture_window: Option<(u64, u64)> = match (start, end) {
        (Some(start), Some(end)) if start <= end => Some((start, end)),
        _ => None,
    };

    // Dictionary: ids unique (distinct natives sharing one kh stay
    // representable — refs disambiguate by id); every key parses as u64.
    let entries = obj
        .get("dictionary")
        .and_then(Value::as_array)
        .expect("shapes checked");
    let mut dict_ids: Vec<&str> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let id = entry
            .get("dict_id")
            .and_then(Value::as_str)
            .expect("shapes checked");
        if dict_ids.contains(&id) {
            findings.push(V2Finding::DictionaryCollision {
                detail: "dictionary id repeats (ids are unique)".to_string(),
            });
        } else {
            dict_ids.push(id);
        }
        if parse_digit(entry.get("kh").expect("shapes checked")).is_none() {
            findings.push(V2Finding::InvalidCombination {
                detail: format!("dictionary[{i}].kh does not parse as u64"),
            });
        }
    }

    // Contexts: ref resolution + kh agreement + evidence rules + sum.
    let contexts = obj
        .get("contexts")
        .and_then(Value::as_array)
        .expect("shapes checked");
    let mut calls_sum: u64 = 0;
    let mut calls_overflow = false;
    for (i, context) in contexts.iter().enumerate() {
        let row = context.as_object().expect("shapes checked");
        let Some(calls) = parse_digit(row.get("calls").expect("shapes checked")) else {
            findings.push(V2Finding::InvalidCombination {
                detail: format!("contexts[{i}].calls does not parse as u64"),
            });
            continue;
        };
        match calls_sum.checked_add(calls) {
            Some(sum) => calls_sum = sum,
            None => calls_overflow = true,
        }
        if parse_digit(row.get("kh").expect("shapes checked")).is_none() {
            findings.push(V2Finding::InvalidCombination {
                detail: format!("contexts[{i}].kh does not parse as u64"),
            });
        }
        if parse_digit(row.get("cgroup_id").expect("shapes checked")).is_none() {
            findings.push(V2Finding::InvalidCombination {
                detail: format!("contexts[{i}].cgroup_id does not parse as u64"),
            });
        }
        if parse_digit(row.get("start_ns").expect("shapes checked")).is_none() {
            findings.push(V2Finding::InvalidCombination {
                detail: format!("contexts[{i}].start_ns does not parse as u64"),
            });
        }
        // Report-level cluster agreement: workload.cluster must equal
        // workload.pod.cluster when both are present, mirroring core
        // check_consistency (D02).
        if let Some(workload) = row.get("workload").and_then(Value::as_object)
            && let (Some(top), Some(pod)) = (
                workload.get("cluster").and_then(Value::as_str),
                workload
                    .get("pod")
                    .and_then(Value::as_object)
                    .and_then(|pod| pod.get("cluster").and_then(Value::as_str)),
            )
            && top != pod
        {
            findings.push(V2Finding::InvalidCombination {
                detail: format!("contexts[{i}].workload cluster contradicts pod cluster"),
            });
        }
        if let Some(native_ref) = row.get("native_ref").and_then(Value::as_str) {
            match entries
                .iter()
                .find(|e| e.get("dict_id").and_then(Value::as_str) == Some(native_ref))
            {
                None => findings.push(V2Finding::InvalidCombination {
                    detail: format!("contexts[{i}] references an unknown dictionary id"),
                }),
                Some(entry) => {
                    let entry_kh = parse_digit(entry.get("kh").expect("shapes checked"));
                    let row_kh = parse_digit(row.get("kh").expect("shapes checked"));
                    if entry_kh.is_none() || row_kh.is_none() || entry_kh != row_kh {
                        findings.push(V2Finding::InvalidCombination {
                            detail: format!("contexts[{i}] kh disagrees with its dictionary entry"),
                        });
                    }
                }
            }
        }
        if let Some(attribution) = row.get("attribution") {
            validate_attribution_rules(attribution, i, capture_window, findings);
        }
    }
    if calls_overflow {
        findings.push(V2Finding::InvalidCombination {
            detail: "context calls overflow u64".to_string(),
        });
    }

    // Ledger: consistency agreement + quiescent/unproven rules.
    let ledger = obj
        .get("ledger")
        .and_then(Value::as_object)
        .expect("shapes checked");
    let ledger_consistency = ledger
        .get("consistency")
        .and_then(Value::as_str)
        .expect("shapes checked");
    if ledger_consistency != interval_consistency {
        findings.push(V2Finding::InvalidCombination {
            detail: "ledger consistency disagrees with interval consistency".to_string(),
        });
    }
    let system = parse_digit(ledger.get("system_total").expect("shapes checked"));
    let per_context = parse_digit(ledger.get("per_context_sum").expect("shapes checked"));
    let unknown = parse_digit(ledger.get("unknown").expect("shapes checked"));
    let refused = parse_digit(ledger.get("refused_inserts").expect("shapes checked"));
    let gap = ledger
        .get("gap_unreconciled")
        .and_then(Value::as_bool)
        .expect("shapes checked");
    let system_saturated = ledger
        .get("system_saturated")
        .and_then(Value::as_bool)
        .expect("shapes checked");
    let per_context_saturated = ledger
        .get("per_context_saturated")
        .and_then(Value::as_bool)
        .expect("shapes checked");
    // Report scope agrees with the applied selector: `scoped` iff a
    // workload selector is present.
    let selectors = obj
        .get("selectors")
        .and_then(Value::as_object)
        .expect("shapes checked");
    let scope = obj
        .get("scope")
        .and_then(Value::as_object)
        .expect("shapes checked");
    let kind_is_none = selectors.get("kind").and_then(Value::as_str) == Some("none");
    let scope_is_scoped = scope.get("report_scope").and_then(Value::as_str) == Some("scoped");
    if kind_is_none == scope_is_scoped {
        findings.push(V2Finding::InvalidCombination {
            detail: "report scope disagrees with applied selectors".to_string(),
        });
    }
    if let Some(cgroup) = selectors.get("cgroup_id")
        && parse_digit(cgroup).is_none()
    {
        findings.push(V2Finding::InvalidCombination {
            detail: "selectors.cgroup_id does not parse as u64".to_string(),
        });
    }
    match (system, per_context, unknown, refused) {
        (Some(system), Some(per_context), Some(unknown), Some(refused)) => {
            if per_context != calls_sum {
                findings.push(V2Finding::InvalidCombination {
                    detail: "per-context sum disagrees with summed context calls".to_string(),
                });
            }
            match ledger_consistency {
                "quiescent" => {
                    if gap {
                        findings.push(V2Finding::InvalidCombination {
                            detail: "quiescent ledger must not flag gap_unreconciled".to_string(),
                        });
                    }
                    if system_saturated || per_context_saturated {
                        findings.push(V2Finding::InvalidCombination {
                            detail: "saturated ledger cannot be quiescent".to_string(),
                        });
                    }
                    match system.checked_sub(per_context) {
                        Some(diff) if diff == unknown => {}
                        _ => findings.push(V2Finding::InvalidCombination {
                            detail: "ledger unknown contradicts system minus per-context"
                                .to_string(),
                        }),
                    }
                    // Refused inserts land in the unknown population, never
                    // double-counted: refused is bounded above by unknown.
                    if refused > unknown {
                        findings.push(V2Finding::InvalidCombination {
                            detail: "refused inserts exceed ledger unknown".to_string(),
                        });
                    }
                }
                _ => {
                    if !gap {
                        findings.push(V2Finding::InvalidCombination {
                            detail: "unproven ledger must flag gap_unreconciled".to_string(),
                        });
                    }
                    if unknown != 0 {
                        findings.push(V2Finding::InvalidCombination {
                            detail: "unproven ledger must not export an exact unknown".to_string(),
                        });
                    }
                }
            }
            // Partition: checked sum + the partition/ledger link.
            let partition = obj
                .get("partition")
                .and_then(Value::as_object)
                .expect("shapes checked");
            let matched = parse_digit(partition.get("matched").expect("shapes checked"));
            let nonmatched = parse_digit(partition.get("nonmatched").expect("shapes checked"));
            let unknown_match =
                parse_digit(partition.get("unknown_match").expect("shapes checked"));
            match (matched, nonmatched, unknown_match) {
                (Some(matched), Some(nonmatched), Some(unknown_match)) => {
                    match matched
                        .checked_add(nonmatched)
                        .and_then(|base| base.checked_add(unknown_match))
                    {
                        Some(observed) if observed == per_context => {
                            // An unscoped report matches its WHOLE observed
                            // population: matched = observed, others zero.
                            if !scope_is_scoped
                                && (matched != per_context || nonmatched != 0 || unknown_match != 0)
                            {
                                findings.push(V2Finding::InvalidCombination {
                                    detail: "unscoped partition must match its whole observed population"
                                        .to_string(),
                                });
                            }
                        }
                        Some(_) => findings.push(V2Finding::InvalidCombination {
                            detail: "partition observed contradicts ledger per-context sum"
                                .to_string(),
                        }),
                        None => findings.push(V2Finding::InvalidCombination {
                            detail: "partition counts overflow u64".to_string(),
                        }),
                    }
                }
                _ => findings.push(V2Finding::InvalidCombination {
                    detail: "partition magnitudes do not parse as u64".to_string(),
                }),
            }
        }
        _ => findings.push(V2Finding::InvalidCombination {
            detail: "ledger magnitudes do not parse as u64".to_string(),
        }),
    }
}

/// Evidence cross-rules for one context attribution: reuse the frozen
/// [`AttributionEvidence`] validation, then enforce evidence-vs-capture
/// agreement for asserting statuses, mapping every refusal to a static
/// positional finding (never echoing input bytes).
fn validate_attribution_rules(
    attribution: &Value,
    index: usize,
    capture_window: Option<(u64, u64)>,
    findings: &mut Vec<V2Finding>,
) {
    let item = attribution.as_object().expect("shapes checked");
    let relationship = match item.get("relationship").and_then(Value::as_str) {
        Some("hook_context") => Relationship::HookContext,
        Some("submitter") => Relationship::Submitter,
        Some("completion_context") => Relationship::CompletionContext,
        Some("workload_origin") => Relationship::WorkloadOrigin,
        _ => Relationship::Consumer,
    };
    let source = match item.get("source").and_then(Value::as_str) {
        Some("kernel_capture") => WorkloadOrigin::KernelCapture,
        Some("operator_metadata_file") => WorkloadOrigin::OperatorMetadataFile,
        Some("runtime_adapter") => WorkloadOrigin::RuntimeAdapter,
        Some("host_proc") => WorkloadOrigin::HostProc,
        _ => WorkloadOrigin::Unknown,
    };
    let status = match item.get("status").and_then(Value::as_str) {
        Some("verified") => AttributionStatus::Verified,
        Some("asserted") => AttributionStatus::Asserted,
        Some("unresolved") => AttributionStatus::Unresolved,
        Some("ambiguous") => AttributionStatus::Ambiguous,
        Some("stale") => AttributionStatus::Stale,
        _ => AttributionStatus::Unsupported,
    };
    let validity = item.get("validity").and_then(|v| {
        let window = v.as_object()?;
        Some(ValidityInterval::monotonic(
            parse_digit(window.get("start_ns")?)?,
            parse_digit(window.get("end_ns")?)?,
        ))
    });
    if item.contains_key("validity") && validity.is_none() {
        findings.push(V2Finding::InvalidCombination {
            detail: format!("contexts[{index}].attribution validity does not parse as u64"),
        });
        return;
    }
    let evidence = AttributionEvidence::new(
        relationship,
        item.get("method")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        source,
        status,
        validity,
    );
    if evidence.validate().is_err() {
        findings.push(V2Finding::InvalidCombination {
            detail: format!("contexts[{index}].attribution contradicts evidence rules"),
        });
        return;
    }
    // Receiving-boundary temporal validation (R3): asserted/verified
    // attribution applies its row counts only when its validity window
    // covers the whole counted capture/report interval — the same
    // conservative coverage rule as D01, applied here where the evidence
    // meets the parsed interval. Stale and weaker statuses assert
    // nothing about the counted interval. A defective interval refuses
    // on its own finding; without a usable window no cascade follows.
    if matches!(
        status,
        AttributionStatus::Asserted | AttributionStatus::Verified
    ) {
        // A defective interval already refuses on its own finding; without a
        // usable window the coverage check must not cascade (R4).
        let Some((start, end)) = capture_window else {
            return;
        };
        let covers = match &validity {
            Some(window) => window.start_ns <= start && end <= window.end_ns,
            None => false,
        };
        if !covers {
            findings.push(V2Finding::InvalidCombination {
                detail: format!(
                    "contexts[{index}].attribution validity does not cover the report interval"
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const CONTAINER_ID: &str = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";

    fn minimal_valid() -> Value {
        json!({
            "schema": SCHEMA_ID,
            "session": {"session_id": SESSION, "kernel_identity": "7.0.0-38-generic/boot-A"},
            "interval": {"start_ns": "100", "end_ns": "200", "consistency": "quiescent", "clock": "monotonic_boot"},
            "profile": "api-returns",
            "boundary": "api_return",
            "dictionary": [
                {"dict_id": "n0", "kh": "7", "family": 1, "op": 2, "result": 0, "context": 0, "algorithm": "cbc(aes)", "driver": "cbc-aes-aesni"}
            ],
            "contexts": [
                {"kh": "7", "cgroup_id": "43812", "tgid": 1000, "uid": 1000, "start_ns": "555", "execution_kind": "proc", "calls": "50", "native_ref": "n0",
                 "workload": {"container": {"runtime": "docker://host-a", "id": CONTAINER_ID, "lifetime": "lifetime-a"}},
                 "attribution": {"relationship": "hook_context", "method": "metadata_file", "source": "operator_metadata_file", "status": "asserted",
                                 "validity": {"start_ns": "100", "end_ns": "200", "clock": "monotonic_boot"}}},
                {"kh": "7", "cgroup_id": "43813", "tgid": 1001, "uid": 1000, "start_ns": "556", "execution_kind": "proc", "calls": "50",
                 "native": {"family": 1, "op": 2, "result": 0, "context": 0, "algorithm": "cbc(aes)", "driver": "cbc-aes-aesni"}}
            ],
            "ledger": {"system_total": "100", "per_context_sum": "100", "unknown": "0", "consistency": "quiescent", "gap_unreconciled": false, "system_saturated": false, "per_context_saturated": false, "refused_inserts": "0"},
            "partition": {"matched": "100", "nonmatched": "0", "unknown_match": "0"},
            "selectors": {"kind": "none"},
            "scope": {"capture_scope": "system", "report_scope": "unscoped", "group_by": "none"},
            "metadata": {"status": "available"},
            "coverage": {"capture": "complete", "attribution": "complete", "metadata": "complete", "correlation": "complete"}
        })
    }

    #[test]
    fn valid_report_passes() {
        assert!(validate_workload_v2(&minimal_valid()).is_empty());
    }

    #[test]
    fn wrong_schema_refuses_without_echo() {
        let mut v = minimal_valid();
        v["schema"] = json!("kryprobe.workload-report.v1");
        assert_eq!(validate_workload_v2(&v), vec![V2Finding::UnknownVersion]);
        assert!(dispatch_schema("kryprobe.workload-report.v1").is_err());
        assert!(dispatch_schema(SCHEMA_ID).is_ok());
    }

    #[test]
    fn unknown_top_level_key_refuses() {
        let mut v = minimal_valid();
        v["sneaky"] = json!(true);
        assert!(validate_workload_v2(&v).contains(&V2Finding::UnknownKey));
    }

    #[test]
    fn non_hex_session_refuses() {
        let mut v = minimal_valid();
        v["session"]["session_id"] = json!("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(
            validate_workload_v2(&v).iter().any(
                |f| matches!(f, V2Finding::BadShape { key, .. } if key == "session.session_id")
            )
        );
    }

    #[test]
    fn missing_kernel_identity_refuses() {
        let mut v = minimal_valid();
        v["session"]["kernel_identity"] = json!("");
        assert!(validate_workload_v2(&v).iter().any(
            |f| matches!(f, V2Finding::BadShape { key, .. } if key == "session.kernel_identity")
        ));
    }

    #[test]
    fn inverted_interval_refuses() {
        let mut v = minimal_valid();
        v["interval"]["start_ns"] = json!("200");
        v["interval"]["end_ns"] = json!("100");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn missing_lifetime_refuses() {
        let mut v = minimal_valid();
        v["contexts"][0]
            .as_object_mut()
            .expect("row")
            .remove("start_ns");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { key, .. } if key.contains("start_ns")))
        );
    }

    #[test]
    fn abbreviated_container_id_refuses() {
        let mut v = minimal_valid();
        v["contexts"][0]["workload"]["container"]["id"] = json!("70f16eb35cd4");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { key, .. } if key.ends_with(".id")))
        );
    }

    #[test]
    fn dictionary_collision_refuses() {
        let mut v = minimal_valid();
        let entry = v["dictionary"][0].clone();
        v["dictionary"].as_array_mut().expect("array").push(entry);
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::DictionaryCollision { .. }))
        );
    }

    #[test]
    fn unresolvable_native_ref_refuses() {
        let mut v = minimal_valid();
        v["contexts"][0]["native_ref"] = json!("missing");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn kh_disagreement_with_dictionary_refuses() {
        let mut v = minimal_valid();
        v["contexts"][0]["kh"] = json!("8");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn native_and_ref_together_refuse() {
        let mut v = minimal_valid();
        v["contexts"][1]["native_ref"] = json!("n0");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { .. }))
        );
        let mut v = minimal_valid();
        v["contexts"][1]
            .as_object_mut()
            .expect("row")
            .remove("native");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { .. }))
        );
    }

    #[test]
    fn ledger_contradiction_refuses() {
        let mut v = minimal_valid();
        v["ledger"]["unknown"] = json!("5");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn partition_ledger_contradiction_refuses() {
        // G05.3's trace shape: rows sum to 100 but the partition claims 1.
        let mut v = minimal_valid();
        v["partition"]["matched"] = json!("1");
        v["partition"]["nonmatched"] = json!("0");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn partition_overflow_refuses() {
        let mut v = minimal_valid();
        v["partition"]["matched"] = json!("18446744073709551615");
        v["partition"]["nonmatched"] = json!("1");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn unproven_with_exact_unknown_refuses() {
        let mut v = minimal_valid();
        v["interval"]["consistency"] = json!("unproven");
        v["ledger"]["consistency"] = json!("unproven");
        v["ledger"]["gap_unreconciled"] = json!(true);
        v["ledger"]["unknown"] = json!("5");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
        // Honest unproven validates.
        let mut v = minimal_valid();
        v["interval"]["consistency"] = json!("unproven");
        v["ledger"]["consistency"] = json!("unproven");
        v["ledger"]["gap_unreconciled"] = json!(true);
        assert!(validate_workload_v2(&v).is_empty());
    }

    #[test]
    fn refused_inserts_above_unknown_refuse() {
        let mut v = minimal_valid();
        v["ledger"]["unknown"] = json!("5");
        v["ledger"]["system_total"] = json!("105");
        v["ledger"]["refused_inserts"] = json!("6");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
        let mut v = minimal_valid();
        v["ledger"]["unknown"] = json!("5");
        v["ledger"]["system_total"] = json!("105");
        v["ledger"]["refused_inserts"] = json!("5");
        assert!(validate_workload_v2(&v).is_empty());
    }

    #[test]
    fn saturated_quiescent_refuses() {
        let mut v = minimal_valid();
        v["ledger"]["system_saturated"] = json!(true);
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn scope_selector_disagreement_refuses() {
        let mut v = minimal_valid();
        v["scope"]["report_scope"] = json!("scoped");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn origin_relationship_with_asserted_refuses() {
        let mut v = minimal_valid();
        v["contexts"][0]["attribution"]["relationship"] = json!("workload_origin");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn inverted_validity_refuses() {
        let mut v = minimal_valid();
        v["contexts"][0]["attribution"]["validity"]["start_ns"] = json!("300");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. }))
        );
    }

    #[test]
    fn over_cap_contexts_refuse() {
        let row = minimal_valid()["contexts"][0].clone();
        let mut v = minimal_valid();
        let contexts = v["contexts"].as_array_mut().expect("array");
        contexts.clear();
        contexts.resize(MAX_V2_CONTEXT_ROWS + 1, row);
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { key, .. } if key == "contexts"))
        );
    }

    #[test]
    fn metadata_reason_rules_hold() {
        let mut v = minimal_valid();
        v["metadata"] = json!({"status": "unavailable"});
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { key, .. } if key == "metadata.reason"))
        );
        let mut v = minimal_valid();
        v["metadata"] = json!({"status": "available", "reason": "no_principal"});
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { .. }))
        );
        let mut v = minimal_valid();
        v["metadata"] = json!({"status": "unavailable", "reason": "no_principal"});
        assert!(validate_workload_v2(&v).is_empty());
    }

    #[test]
    fn freeze_pin_matches_fixed_digest() {
        assert_eq!(schema_fnv1a_hex(), WORKLOAD_V2_SCHEMA_FNV1A);
        assert!(check_schema_drift(EMBEDDED_SCHEMA.as_bytes()).is_none());
        assert!(check_schema_drift(b"{tampered}").is_some());
    }

    #[test]
    fn unscoped_split_partition_refuses() {
        // ADR-0012: an unscoped report matches its WHOLE observed
        // population — matched = observed, other buckets zero.
        // (Round-2 G05.3 oracle.)
        let mut v = minimal_valid();
        v["partition"]["matched"] = json!("50");
        v["partition"]["nonmatched"] = json!("50");
        v["partition"]["unknown_match"] = json!("0");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. })),
            "unscoped split partition must refuse"
        );
        let mut v = minimal_valid();
        v["partition"]["matched"] = json!("90");
        v["partition"]["nonmatched"] = json!("0");
        v["partition"]["unknown_match"] = json!("10");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. })),
            "unscoped unknown_match must refuse"
        );
    }

    #[test]
    fn absent_driver_validates_as_unavailable() {
        // Allocation captures carry zero driver bytes: an absent driver is
        // explicitly unavailable, never a defect. (Round-2 G05.4 oracle.)
        let mut v = minimal_valid();
        v["dictionary"][0]
            .as_object_mut()
            .expect("entry")
            .remove("driver");
        v["contexts"][1]["native"]
            .as_object_mut()
            .expect("native")
            .remove("driver");
        assert!(
            validate_workload_v2(&v).is_empty(),
            "absent driver must validate: {:?}",
            validate_workload_v2(&v)
        );
    }

    #[test]
    fn empty_driver_refuses() {
        // Absent means unavailable; present-but-empty is malformed.
        let mut v = minimal_valid();
        v["dictionary"][0]["driver"] = json!("");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { .. })),
            "empty dictionary driver must refuse"
        );
        let mut v = minimal_valid();
        v["contexts"][1]["native"]["driver"] = json!("");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::BadShape { .. })),
            "empty inline driver must refuse"
        );
    }

    #[test]
    fn distinct_natives_sharing_kh_are_representable() {
        // kh is an index, not proof: two distinct native tuples sharing one
        // kh stay disambiguated by their dict_id refs. (Round-2 G05.4
        // kh-collision oracle.)
        let mut v = minimal_valid();
        v["dictionary"].as_array_mut().expect("array").push(json!(
            {"dict_id": "n1", "kh": "7", "family": 1, "op": 3, "result": 0, "context": 0, "algorithm": "cbc(aes)", "driver": "cbc-aes-aesni"}
        ));
        v["contexts"][1]
            .as_object_mut()
            .expect("row")
            .remove("native");
        v["contexts"][1]["native_ref"] = json!("n1");
        assert!(
            validate_workload_v2(&v).is_empty(),
            "kh collision must stay representable: {:?}",
            validate_workload_v2(&v)
        );
    }

    #[test]
    fn unrepresentable_digit_strings_refuse() {
        // Every digit string must parse as u64 — including lifetime,
        // unreferenced dictionary keys, and selector ids. (Round-2 D03
        // oracle.)
        let overflow = json!("18446744073709551616");
        let mut v = minimal_valid();
        v["contexts"][0]["start_ns"] = overflow.clone();
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. })),
            "overflow start_ns must refuse"
        );
        let mut v = minimal_valid();
        v["dictionary"].as_array_mut().expect("array").push(json!(
            {"dict_id": "nx", "kh": "18446744073709551616", "family": 1, "op": 2, "result": 0, "context": 0, "algorithm": "cbc(aes)", "driver": "cbc-aes-aesni"}
        ));
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. })),
            "overflow unreferenced dictionary kh must refuse"
        );
        let mut v = minimal_valid();
        v["selectors"] = json!({"kind": "cgroup-id", "cgroup_id": "18446744073709551616"});
        v["scope"]["report_scope"] = json!("scoped");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. })),
            "overflow selector cgroup_id must refuse"
        );
    }

    #[test]
    fn conflicting_workload_cluster_refuses() {
        // Report-level D02: workload.cluster must agree with
        // workload.pod.cluster, mirroring core check_consistency.
        // (Round-2 D02 oracle.)
        let mut v = minimal_valid();
        v["contexts"][0]["workload"]["cluster"] = json!("cluster-a");
        v["contexts"][0]["workload"]["pod"] = json!(
            {"cluster": "cluster-b", "uid": "uid-1", "name": "api", "namespace": "production"}
        );
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. })),
            "conflicting workload/pod cluster must refuse"
        );
        let mut v = minimal_valid();
        v["contexts"][0]["workload"]["cluster"] = json!("cluster-a");
        v["contexts"][0]["workload"]["pod"] = json!(
            {"cluster": "cluster-a", "uid": "uid-1", "name": "api", "namespace": "production"}
        );
        assert!(
            validate_workload_v2(&v).is_empty(),
            "agreeing workload/pod cluster must validate: {:?}",
            validate_workload_v2(&v)
        );
    }

    #[test]
    fn expired_binding_asserted_refuses() {
        // Receiving-boundary temporal validation: an Asserted binding
        // whose validity expired before the counted interval cannot
        // support asserted/matched claims — the same conservative
        // coverage rule as D01, applied where the evidence meets the
        // report interval. (Round-3 oracle.)
        let mut v = minimal_valid();
        v["interval"]["end_ns"] = json!("1000");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { .. })),
            "expired Asserted binding must refuse"
        );
        // Positive control: covering validity validates.
        let mut v = minimal_valid();
        v["interval"]["end_ns"] = json!("1000");
        v["contexts"][0]["attribution"]["validity"]["end_ns"] = json!("1000");
        assert!(
            validate_workload_v2(&v).is_empty(),
            "covering Asserted binding must validate: {:?}",
            validate_workload_v2(&v)
        );
        // Stale keeps its honest expired window: it asserts nothing about
        // the counted interval.
        let mut v = minimal_valid();
        v["interval"]["end_ns"] = json!("1000");
        v["contexts"][0]["attribution"]["status"] = json!("stale");
        assert!(
            validate_workload_v2(&v).is_empty(),
            "expired Stale binding must validate: {:?}",
            validate_workload_v2(&v)
        );
    }

    #[test]
    fn defective_interval_refuses_without_cascading_coverage() {
        // Round-4: a defective report interval refuses on its own finding;
        // attribution-coverage findings must not cascade from asserting rows
        // (ADR-0012 "without cascading").
        let mut v = minimal_valid();
        v["interval"]["start_ns"] = json!("200");
        v["interval"]["end_ns"] = json!("100");
        assert_eq!(
            validate_workload_v2(&v),
            vec![V2Finding::InvalidCombination {
                detail: "interval is inverted".to_string(),
            }],
            "inverted interval must refuse once, without coverage cascade"
        );
        let mut v = minimal_valid();
        v["interval"]["start_ns"] = json!("18446744073709551616");
        assert_eq!(
            validate_workload_v2(&v),
            vec![V2Finding::InvalidCombination {
                detail: "interval bounds do not parse as u64".to_string(),
            }],
            "unparseable interval must refuse once, without coverage cascade"
        );
        // Control: a valid interval with non-covering validity still refuses
        // on the coverage finding itself.
        let mut v = minimal_valid();
        v["interval"]["end_ns"] = json!("1000");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::InvalidCombination { detail }
                    if detail.contains("does not cover the report interval"))),
            "expired Asserted binding on a valid interval must still refuse on coverage"
        );
    }

    #[test]
    fn selector_container_lifetime_refuses() {
        // The frozen schema permits only runtime/id under
        // selectors.container: a lifetime there refuses. (Round-2 D10
        // oracle.)
        let mut v = minimal_valid();
        v["selectors"] = json!(
            {"kind": "container-id", "container": {"runtime": "docker://host-a", "id": CONTAINER_ID, "lifetime": "lifetime-a"}}
        );
        v["scope"]["report_scope"] = json!("scoped");
        assert!(
            validate_workload_v2(&v)
                .iter()
                .any(|f| matches!(f, V2Finding::UnknownKey | V2Finding::BadShape { .. })),
            "selector container lifetime must refuse"
        );
    }
}
