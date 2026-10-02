// SPDX-License-Identifier: GPL-3.0-or-later
//! Scope decisions and the matched/nonmatched/unknown partition
//! (ADR-0008 §(g), spec F05): `observed = matched + nonmatched +
//! unknown_match` with checked arithmetic.

use serde::{Deserialize, Serialize};

/// Selector outcome for one observation: `Unknown` is neither match nor
/// non-match and never collapses into either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDecision {
    /// Definitely matches the selector.
    Match,
    /// Definitely does not match.
    NonMatch,
    /// Match-ness cannot be established (unknown context or gap).
    Unknown,
}

/// A fixed observed population partitioned by one selector. The
/// invariant `observed = matched + nonmatched + unknown_match` is
/// established at construction with checked addition; overflow refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopePartition {
    matched: u64,
    nonmatched: u64,
    unknown_match: u64,
}

impl ScopePartition {
    /// Build the partition, refusing on arithmetic overflow. For
    /// lifecycle records the population is admitted requests, not edges.
    pub fn from_counts(matched: u64, nonmatched: u64, unknown_match: u64) -> Result<Self, String> {
        matched
            .checked_add(nonmatched)
            .and_then(|base| base.checked_add(unknown_match))
            .map(|_| Self {
                matched,
                nonmatched,
                unknown_match,
            })
            .ok_or_else(|| "scope partition counts overflow u64".to_string())
    }

    /// Confirmed matches.
    #[must_use]
    pub fn matched(&self) -> u64 {
        self.matched
    }

    /// Confirmed non-matches.
    #[must_use]
    pub fn nonmatched(&self) -> u64 {
        self.nonmatched
    }

    /// Unknown matches: separately labeled, never hidden, never counted
    /// as confirmed matches.
    #[must_use]
    pub fn unknown_match(&self) -> u64 {
        self.unknown_match
    }

    /// The full observed population (cannot overflow: checked at build).
    #[must_use]
    pub fn observed(&self) -> u64 {
        self.matched + self.nonmatched + self.unknown_match
    }

    /// Decision for a resolvable observation.
    #[must_use]
    pub fn decision_for_known(&self, matches: bool) -> ScopeDecision {
        if matches {
            ScopeDecision::Match
        } else {
            ScopeDecision::NonMatch
        }
    }

    /// Decision for an unresolvable observation: always `Unknown`.
    #[must_use]
    pub fn decision_for_unknown(&self) -> ScopeDecision {
        ScopeDecision::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_invariant_holds() {
        let p = ScopePartition::from_counts(70, 20, 10).expect("valid");
        assert_eq!(p.observed(), 100);
    }

    #[test]
    fn zero_population_is_valid() {
        let p = ScopePartition::from_counts(0, 0, 0).expect("empty is valid");
        assert_eq!(p.observed(), 0);
    }
}
