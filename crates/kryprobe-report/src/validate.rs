// SPDX-License-Identifier: GPL-3.0-or-later
//! Stream validation: structural checks + schema const + schema freeze.
//!
//! Testkit [`check_stream`](kryprobe_testkit::check_stream) checks envelope
//! presence only (T4 ruling); this module additionally requires every
//! record's `schema` to equal [`EVENT_SCHEMA_V0`](crate::EVENT_SCHEMA_V0)
//! and the on-disk schema file to hash identically to the compiled-in
//! copy, else [`ValidationFinding::SchemaDrift`].

mod kinds;

use self::kinds::KIND_TABLE;
use crate::EVENT_SCHEMA_V0;
use kryprobe_testkit::{StreamFinding, check_stream};
use serde_json::Value;
use std::path::Path;

/// One validation defect; empty means the stream validates clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFinding {
    /// Structural defect from testkit checks.
    Stream(StreamFinding),
    /// Record `schema` is present but not the frozen const.
    SchemaMismatch {
        /// 1-based physical line number.
        line: usize,
        /// Offending schema value.
        found: String,
    },
    /// On-disk schema file hash differs from the compiled-in copy.
    SchemaDrift {
        /// Compiled-in hash (hex).
        expected: String,
        /// On-disk hash (hex), or `"unreadable"`.
        actual: String,
    },
    /// The stream file itself could not be read (fail-closed, never clean).
    Unreadable {
        /// I/O detail.
        detail: String,
    },
}

impl std::fmt::Display for ValidationFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(finding) => write!(f, "{finding}"),
            Self::SchemaMismatch { line, found } => {
                write!(
                    f,
                    "line {line}: schema is '{found}', want '{EVENT_SCHEMA_V0}'"
                )
            }
            Self::SchemaDrift { expected, actual } => {
                write!(f, "schema drift: disk {actual} != frozen {expected}")
            }
            Self::Unreadable { detail } => write!(f, "unreadable stream: {detail}"),
        }
    }
}

/// The frozen schema bytes compiled into this crate.
const EMBEDDED_SCHEMA: &str = include_str!("../../../schemas/event-v0.schema.json");

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

/// Validates the stream at `path`; empty means clean.
pub fn validate_file(path: &Path) -> Vec<ValidationFinding> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return vec![ValidationFinding::Unreadable {
                detail: err.to_string(),
            }];
        }
    };
    // Manifest-dir relative: one fewer `..` than the `include_str!` above,
    // which resolves from `src/`.
    let schema_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/event-v0.schema.json");
    let disk = std::fs::read(&schema_path);
    let mut findings = validate_str(&text, disk.as_deref().unwrap_or(EMBEDDED_SCHEMA.as_bytes()));
    if disk.is_err() {
        // Fail-closed: an unreadable schema file cannot prove no drift.
        findings.push(ValidationFinding::SchemaDrift {
            expected: schema_fnv1a_hex(),
            actual: "unreadable".to_owned(),
        });
    }
    findings
}

/// Validates stream `text` against caller-supplied on-disk schema bytes.
/// Pure core of [`validate_file`]; tamper tests drive this directly.
pub fn validate_str(text: &str, schema_disk_bytes: &[u8]) -> Vec<ValidationFinding> {
    let mut findings: Vec<ValidationFinding> = check_stream(text, KIND_TABLE)
        .into_iter()
        .map(ValidationFinding::Stream)
        .collect();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<Value>(line)
            && let Some(found) = record.get("schema").and_then(Value::as_str)
            && found != EVENT_SCHEMA_V0
        {
            findings.push(ValidationFinding::SchemaMismatch {
                line: index + 1,
                found: found.to_owned(),
            });
        }
    }
    if fnv1a64(schema_disk_bytes) != fnv1a64(EMBEDDED_SCHEMA.as_bytes()) {
        findings.push(ValidationFinding::SchemaDrift {
            expected: schema_fnv1a_hex(),
            actual: format!("{:016x}", fnv1a64(schema_disk_bytes)),
        });
    }
    findings
}
