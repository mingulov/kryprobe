// SPDX-License-Identifier: GPL-3.0-or-later
//! Helper snapshot DTOs, typed metadata unavailability, and the
//! unknown-by-difference constructor (ADR-0008 §§(e),(h)).
//!
//! Unknown context, unknown selector match, hook context, and workload
//! origin are four distinct concepts: this module owns the unknown
//! *context* magnitude. Selector unknowns live in [`super::ScopePartition`].

use super::{MAX_SNAPSHOT_ASSOCIATIONS, MAX_SNAPSHOT_REQUEST_BYTES, MAX_SNAPSHOT_RESPONSE_BYTES};
use serde::{Deserialize, Serialize};

/// Snapshot consistency: only a proved writer fence yields `Quiescent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotConsistency {
    /// Writers fenced before the terminal reads (M1 control ABI v1).
    Quiescent,
    /// No fence proof: magnitudes are samples, not exact unknowns.
    Unproven,
}

/// Bounded helper snapshot request (Task 03 implements the helper; the
/// bytes on the wire never exceed [`MAX_SNAPSHOT_REQUEST_BYTES`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Session id (32 lowercase hex chars).
    pub session_id: String,
    /// Captured context keys to resolve (bounded count).
    pub keys: Vec<SnapshotKey>,
}

/// One resolvable captured key: kernel/session scope + cgroup + process
/// lifetime discriminator. No names, no paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotKey {
    /// Kernel/boot scope tag.
    pub kernel_scope: String,
    /// Captured cgroup id (0 = unreadable; resolvable as unknown).
    pub cgroup: u64,
    /// Host TGID.
    pub tgid: u32,
    /// Observed process lifetime discriminator (0 = unreadable).
    pub start_ns: u64,
}

/// Typed metadata unavailability: the resolver never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataUnavailable {
    /// Root invocation with no trustworthy non-root principal.
    NoPrincipal,
    /// The helper refused the request.
    HelperRefused,
    /// A hard budget was exceeded.
    BudgetExceeded,
    /// The environment cannot support resolution.
    UnsupportedEnvironment,
    /// The metadata file failed validation.
    ParseFailed,
}

/// Unknown-by-difference magnitude (ADR-0008 §(e)):
/// `unknown = system_total − Σ per-context`, computed from one
/// consistent stop snapshot over the same counted population.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownByDifference {
    /// The system total operand (`KTOT`).
    pub system_total: u64,
    /// The summed per-context operand (`ΣKCTX`).
    pub per_context_sum: u64,
    /// The resulting unknown magnitude.
    pub unknown: u64,
}

impl UnknownByDifference {
    /// Compute the unknown magnitude. Requires a `Quiescent` snapshot;
    /// an `Unproven` snapshot, a negative difference, or a population
    /// mismatch refuses typed — impossible values surface, never
    /// saturate to zero.
    pub fn compute(
        consistency: SnapshotConsistency,
        system_total: u64,
        per_context_sum: u64,
    ) -> Result<Self, String> {
        if consistency != SnapshotConsistency::Quiescent {
            return Err("unknown-by-difference requires a quiescent snapshot".to_string());
        }
        let unknown = system_total.checked_sub(per_context_sum).ok_or_else(|| {
            format!("contradictory snapshot: per-context sum {per_context_sum} exceeds system total {system_total}")
        })?;
        Ok(Self {
            system_total,
            per_context_sum,
            unknown,
        })
    }
}

/// Wire-size guard for snapshot DTOs: requests beyond
/// [`MAX_SNAPSHOT_REQUEST_BYTES`] and responses beyond
/// [`MAX_SNAPSHOT_RESPONSE_BYTES`] / [`MAX_SNAPSHOT_ASSOCIATIONS`]
/// refuse before parsing.
pub fn check_request_budget(json_bytes: usize, keys: usize) -> Result<(), MetadataUnavailable> {
    if json_bytes > MAX_SNAPSHOT_REQUEST_BYTES || keys > MAX_SNAPSHOT_ASSOCIATIONS {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    Ok(())
}

/// Response budget guard (same refusal discipline as requests).
pub fn check_response_budget(
    json_bytes: usize,
    associations: usize,
) -> Result<(), MetadataUnavailable> {
    if json_bytes > MAX_SNAPSHOT_RESPONSE_BYTES || associations > MAX_SNAPSHOT_ASSOCIATIONS {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unproven_snapshot_cannot_yield_exact_unknown() {
        assert!(UnknownByDifference::compute(SnapshotConsistency::Unproven, 100, 60).is_err());
    }

    #[test]
    fn negative_difference_surfaces_instead_of_saturating() {
        let err = UnknownByDifference::compute(SnapshotConsistency::Quiescent, 50, 60)
            .expect_err("ΣKCTX > KTOT must surface");
        assert!(err.contains("contradictory snapshot"), "got: {err}");
    }

    #[test]
    fn exact_unknown_computes() {
        let u = UnknownByDifference::compute(SnapshotConsistency::Quiescent, 100, 60)
            .expect("valid difference");
        assert_eq!(u.unknown, 40);
    }

    #[test]
    fn budgets_refuse_overlarge_dtos() {
        assert!(check_request_budget(MAX_SNAPSHOT_REQUEST_BYTES + 1, 1).is_err());
        assert!(check_request_budget(100, MAX_SNAPSHOT_ASSOCIATIONS + 1).is_err());
        assert!(check_response_budget(MAX_SNAPSHOT_RESPONSE_BYTES + 1, 1).is_err());
        assert!(check_request_budget(100, 10).is_ok());
    }
}
