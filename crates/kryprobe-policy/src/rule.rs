// SPDX-License-Identifier: GPL-3.0-or-later
//! Policy shapes: YAML `version: 1` + `rules` (kp2 §10), parsed with
//! unknown-key rejection — unknown keys or versions are errors (exit 2
//! at the CLI), never silently ignored.

use serde::Deserialize;

/// Exact YAML shape: `version: 1`, `rules: [{id, source, match, decision}]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Policy schema version; only 1 exists (anything else is rejected).
    pub version: u32,
    /// Rules in evaluation order (first matching `deny` wins).
    pub rules: Vec<Rule>,
}

/// One explicit rule: source-scoped match with a deny/report decision.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable rule identity (named in the violation verdict).
    pub id: String,
    /// Capture source this rule applies to (`kernel-crypto` in v0.1;
    /// any other spelling parses but never matches kcrypto data).
    pub source: String,
    /// Conjunction of present keys (all must match; `{}` matches all).
    #[serde(rename = "match")]
    pub match_spec: MatchSpec,
    /// `deny` raises violations; `report` never does (v0.1 records
    /// nothing — the verdict only distinguishes deny-vs-report).
    pub decision: Decision,
}

/// Rule decision: violation-raising or record-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// A match is a policy violation (exit 10 at the CLI).
    Deny,
    /// A match is not a violation (no verdict effect in v0.1).
    Report,
}

/// Execution stage (D3): created vs actually executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// Transform/selection observed (`phase == Selected` on agg rows).
    Selected,
    /// Real execution (agg row in Entered/Returned/Completed).
    Executed,
}

/// Match conjunction: every present key must hold (absent keys are
/// wildcards). String keys are glob patterns (D5: `*`/`?` only);
/// `operation` reads the payload `op` spelling (the one key-name
/// mapping — payload names are grounded in the K2 D8 tables).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    /// Execution stage (D3).
    #[serde(default)]
    pub stage: Option<Stage>,
    /// Kernel algorithm name (exact or glob).
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Kernel driver name (exact or glob).
    #[serde(default)]
    pub driver: Option<String>,
    /// Matches when the driver glob does NOT match.
    #[serde(default)]
    pub driver_not: Option<String>,
    /// Kernel module (D4: never matches kcrypto v0.1 data).
    #[serde(default)]
    pub module: Option<String>,
    /// Crypto family (`skcipher`/`aead`/`ahash`/`shash`/…).
    #[serde(default)]
    pub family: Option<String>,
    /// Operation (`alloc`/`encrypt`/`decrypt`/`digest`/`finup`/…).
    #[serde(default)]
    pub operation: Option<String>,
    /// Immediate result class (`ok`/`error`/`queued`/…).
    #[serde(default)]
    pub result: Option<String>,
    /// Context kind (`process`/`kthread`/`softirq`/…).
    #[serde(default)]
    pub context: Option<String>,
}

impl MatchSpec {
    /// True when no key constrains the match (matches everything in
    /// the rule's source — the vacuous AND).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stage.is_none()
            && self.algorithm.is_none()
            && self.driver.is_none()
            && self.driver_not.is_none()
            && self.module.is_none()
            && self.family.is_none()
            && self.operation.is_none()
            && self.result.is_none()
            && self.context.is_none()
    }
}

/// Policy rejection: malformed YAML, unknown keys, or a version
/// other than 1 (the CLI exits 2 with this message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    message: String,
}

impl PolicyError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for PolicyError {}

/// Parses policy YAML: exact shape, unknown keys rejected, only
/// `version: 1` accepted.
pub fn parse_policy(text: &str) -> Result<Policy, PolicyError> {
    let policy: Policy = serde_yaml::from_str(text)
        .map_err(|err| PolicyError::new(format!("invalid policy: {err}")))?;
    if policy.version != 1 {
        return Err(PolicyError::new(format!(
            "unsupported policy version: {} (only 1)",
            policy.version
        )));
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_spec_empty_tracks_keys() {
        assert!(MatchSpec::default().is_empty());
        assert!(
            !MatchSpec {
                algorithm: Some("md5".to_owned()),
                ..MatchSpec::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn version_error_names_version() {
        let err = parse_policy("version: 2\nrules: []\n").expect_err("version 2 rejected");
        assert!(err.to_string().contains('2'), "{err}");
    }
}
