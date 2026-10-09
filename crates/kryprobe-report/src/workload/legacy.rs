// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal legacy-v1 behavior (M1 Stage 2C): validate a v1 report value
//! and render its STORED partition alongside the frozen v1 limitations,
//! or refuse scoped re-evaluation it did not record.
//!
//! Deliberately minimal: v1's bytes are frozen (ADR-0008) and its gaps
//! (no native identity, no ledger, untyped selectors/metadata) stay as
//! documented limitations. No prototype presentation work lives here.

use crate::validate::workload_v1::{V1ScopeSupport, v1_scope_support, validate_workload_v1};
use serde_json::Value;

/// Typed legacy-v1 refusal. Static diagnostics only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyV1Error {
    /// The value fails v1 validation (finding count only).
    InvalidReport {
        /// Number of validator findings.
        findings: usize,
    },
    /// The requested scope cannot be evaluated from v1.
    UnsupportedScope {
        /// Static refusal reason (from the frozen scope support).
        reason: &'static str,
    },
}

impl std::fmt::Display for LegacyV1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidReport { findings } => {
                write!(f, "workload-report-v1 schema defects: {findings}")
            }
            Self::UnsupportedScope { reason } => {
                write!(f, "v1 scope unsupported: {reason}")
            }
        }
    }
}

impl std::error::Error for LegacyV1Error {}

/// Render a legacy v1 report value: its stored partition plus every
/// frozen limitation — or refuse when the value is invalid or carries a
/// scope v1 cannot evaluate.
pub fn render_legacy_v1(value: &Value) -> Result<String, LegacyV1Error> {
    let findings = validate_workload_v1(value);
    if !findings.is_empty() {
        return Err(LegacyV1Error::InvalidReport {
            findings: findings.len(),
        });
    }
    let obj = value.as_object().expect("validated reports are objects");
    let selectors = obj
        .get("selectors")
        .expect("validated reports carry selectors");
    match v1_scope_support(selectors) {
        V1ScopeSupport::RenderWithLimitations(limitations) => {
            let partition = obj
                .get("partition")
                .and_then(Value::as_object)
                .expect("validated reports carry partitions");
            let magnitude = |key: &str| {
                partition
                    .get(key)
                    .and_then(Value::as_str)
                    .expect("validated partitions carry digit strings")
            };
            let mut text = format!(
                "workload-report v1 (legacy) stored partition: matched={} nonmatched={} unknown_match={}\n",
                magnitude("matched"),
                magnitude("nonmatched"),
                magnitude("unknown_match"),
            );
            text.push_str("limitations:\n");
            for limitation in &limitations {
                text.push_str(&format!("- {limitation}\n"));
            }
            Ok(text)
        }
        V1ScopeSupport::Refused(refusal) => Err(LegacyV1Error::UnsupportedScope {
            reason: refusal.reason,
        }),
    }
}
