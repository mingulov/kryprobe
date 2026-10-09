// SPDX-License-Identifier: GPL-3.0-or-later
//! Helper snapshot DTOs, typed metadata unavailability, the
//! unknown-by-difference constructor, and the snapshot wire codec
//! (ADR-0008 §§(e),(h), as corrected by the Stage 2A contract ADR).
//!
//! Unknown context, unknown selector match, hook context, and workload
//! origin are four distinct concepts: this module owns the unknown
//! *context* magnitude. Selector unknowns live in [`super::ScopePartition`].
//!
//! Codec discipline: byte limits apply BEFORE allocation/parsing (on the
//! raw byte length), count limits AFTER parsing (on the decoded value).

use super::{AttributionEvidence, KernelIdentity, MetadataSnapshot, WorkloadIdentity};
use super::{
    AttributionStatus, MAX_HELPER_RETRIES, MAX_KERNEL_IDENTITY_BYTES, MAX_METADATA_BYTES,
    MAX_METADATA_NESTING_DEPTH, MAX_RESOLVER_CACHE_ENTRIES, MAX_RESOLVER_TOMBSTONES,
    MAX_SNAPSHOT_ASSOCIATIONS, MAX_SNAPSHOT_REQUEST_BYTES, MAX_SNAPSHOT_RESPONSE_BYTES,
    MAX_STRING_FIELD_BYTES, SESSION_ID_HEX_CHARS,
};
use serde::{Deserialize, Deserializer, Serialize};

/// The frozen snapshot-IPC schema bytes compiled into this crate.
const EMBEDDED_SNAPSHOT_SCHEMA: &str =
    include_str!("../../../../schemas/workload-snapshot-v1.schema.json");

/// Fixed freeze pin (FNV-1a 64 hex) over the snapshot schema bytes: any
/// schema edit must update this pin deliberately.
pub const WORKLOAD_SNAPSHOT_SCHEMA_FNV1A: &str = "38832964ea2d9f7e";

/// FNV-1a 64 over bytes (drift detection, not security).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Hex hash of the compiled-in frozen snapshot schema.
#[must_use]
pub fn snapshot_schema_fnv1a_hex() -> String {
    format!("{:016x}", fnv1a64(EMBEDDED_SNAPSHOT_SCHEMA.as_bytes()))
}

/// Whether on-disk snapshot-schema bytes drifted from the freeze pin.
#[must_use]
pub fn snapshot_schema_drifted(schema_disk_bytes: &[u8]) -> bool {
    format!("{:016x}", fnv1a64(schema_disk_bytes)) != WORKLOAD_SNAPSHOT_SCHEMA_FNV1A
}

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

impl SnapshotRequest {
    /// Request rules: well-formed session, non-empty deduplicated keys
    /// within the count budget, every key valid.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        validate_session_id(&self.session_id)?;
        if self.keys.is_empty() {
            return Err(MetadataUnavailable::ParseFailed);
        }
        if self.keys.len() > MAX_SNAPSHOT_ASSOCIATIONS {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        for key in &self.keys {
            key.validate()?;
        }
        for (i, key) in self.keys.iter().enumerate() {
            if self.keys[..i].contains(key) {
                return Err(MetadataUnavailable::ParseFailed);
            }
        }
        Ok(())
    }
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

impl SnapshotKey {
    /// Key rules: the scope tag is non-empty and within the kernel
    /// identity bound; all numeric fields are representable (including
    /// the unreadable zeros).
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        if self.kernel_scope.is_empty() || self.kernel_scope.len() > MAX_KERNEL_IDENTITY_BYTES {
            return Err(MetadataUnavailable::ParseFailed);
        }
        Ok(())
    }
}

/// Session-id shape: exactly 32 lowercase hex chars (128-bit random).
pub fn validate_session_id(session_id: &str) -> Result<(), MetadataUnavailable> {
    if session_id.len() != SESSION_ID_HEX_CHARS
        || !session_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(MetadataUnavailable::ParseFailed);
    }
    Ok(())
}

/// One resolved association: the request key echoed back, the workload
/// identity established for it (possibly none), and the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedAssociation {
    /// The request key this association answers.
    pub key: SnapshotKey,
    /// Established workload identity (empty when unresolved/ambiguous).
    pub identity: WorkloadIdentity,
    /// Evidence for the association.
    pub evidence: AttributionEvidence,
}

/// Typed per-key refusal code (bounded vocabulary, no free text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotErrorCode {
    /// The snapshot kernel differs from the key's kernel scope.
    KernelMismatch,
    /// The snapshot cannot establish its kernel: no key is servable.
    UnknownKernel,
    /// The key was dropped to fit the response byte budget.
    BudgetExceeded,
    /// The key cannot be resolved in this environment (Stage 2B use;
    /// the pure resolver never emits this).
    Unsupported,
}

/// One refused key: the request key echoed back plus a typed code and a
/// short static detail (details never echo untrusted input bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotKeyError {
    /// The request key this error answers.
    pub key: SnapshotKey,
    /// Typed refusal code.
    pub code: SnapshotErrorCode,
    /// Short static detail (bounded, no input echo).
    pub detail: String,
}

/// Response completeness: `Complete` covers every request key with an
/// association or a refusal; `Truncated` additionally dropped tail keys
/// into [`SnapshotErrorCode::BudgetExceeded`] errors to fit the byte
/// budget. Truncation drops from the request-order tail only, so a
/// truncated response is always a prefix of the complete one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    /// Every key answered, nothing dropped for budget.
    Complete,
    /// Tail keys dropped into budget errors to fit the byte budget.
    Truncated,
}

/// Chunk position for multi-part responses: `index` (0-based) of `total`.
/// Single responses always carry `{index: 0, total: 1}`.
/// Deserialization routes through [`ChunkInfo::validate`] (D05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ChunkInfo {
    /// This chunk's 0-based index.
    pub index: u32,
    /// Total chunks in the sequence (>= 1).
    pub total: u32,
}

impl ChunkInfo {
    /// Single-chunk position.
    #[must_use]
    pub fn single() -> Self {
        Self { index: 0, total: 1 }
    }

    /// Chunk rules: `total >= 1` and `index < total`.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        if self.total == 0 || self.index >= self.total {
            return Err(MetadataUnavailable::ParseFailed);
        }
        Ok(())
    }
}

/// Wire shape for [`ChunkInfo`]: identical fields, checked on conversion.
#[derive(Debug, Clone, Copy, Deserialize)]
struct ChunkInfoWire {
    index: u32,
    total: u32,
}

impl<'de> Deserialize<'de> for ChunkInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ChunkInfoWire::deserialize(deserializer)?;
        let info = Self {
            index: wire.index,
            total: wire.total,
        };
        info.validate()
            .map_err(|_| serde::de::Error::custom("chunk requires total >= 1 and index < total"))?;
        Ok(info)
    }
}

/// Bounded response counters: exact, never saturating. `resolved` counts
/// verified/asserted associations; `unresolved` counts
/// unresolved/ambiguous/stale/unsupported associations (present but not
/// usable as resolved); `refused` counts errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotCounters {
    /// Verified/asserted associations.
    pub resolved: u64,
    /// Present-but-unusable associations.
    pub unresolved: u64,
    /// Refused keys.
    pub refused: u64,
}

/// The frozen snapshot response: session-bound, chunked, counted, and
/// byte-budgeted. Field names are frozen by the Stage 2A contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResponse {
    /// Echo of the request session id (binding).
    pub session_id: String,
    /// The snapshot kernel this response was resolved against (audit).
    pub kernel_identity: KernelIdentity,
    /// Per-key associations (request order, bounded count).
    pub associations: Vec<ResolvedAssociation>,
    /// Per-key refusals.
    pub errors: Vec<SnapshotKeyError>,
    /// Completeness flag.
    pub status: ResponseStatus,
    /// Chunk position.
    pub chunk: ChunkInfo,
    /// Exact counters over associations/errors.
    pub counters: SnapshotCounters,
}

impl SnapshotResponse {
    /// Response rules: well-formed session, bounded associations/errors,
    /// valid chunk, exact counters, status consistent with budget
    /// errors, every association key/identity/evidence valid, every
    /// error key/detail valid, and the encoded bytes within budget.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        validate_session_id(&self.session_id)?;
        if self.associations.len() > MAX_SNAPSHOT_ASSOCIATIONS {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        if self.errors.len() > MAX_SNAPSHOT_ASSOCIATIONS {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        self.chunk.validate()?;
        let mut resolved: u64 = 0;
        let mut unresolved: u64 = 0;
        for assoc in &self.associations {
            assoc.key.validate()?;
            if !assoc.identity.check_bounds(MAX_STRING_FIELD_BYTES) {
                return Err(MetadataUnavailable::BudgetExceeded);
            }
            if !assoc.identity.check_consistency() {
                return Err(MetadataUnavailable::ParseFailed);
            }
            assoc
                .evidence
                .validate()
                .map_err(|_| MetadataUnavailable::ParseFailed)?;
            match assoc.evidence.status {
                AttributionStatus::Verified | AttributionStatus::Asserted => {
                    resolved += 1;
                }
                AttributionStatus::Unresolved
                | AttributionStatus::Ambiguous
                | AttributionStatus::Stale
                | AttributionStatus::Unsupported => {
                    unresolved += 1;
                }
            }
        }
        for error in &self.errors {
            error.key.validate()?;
            if error.detail.len() > MAX_STRING_FIELD_BYTES {
                return Err(MetadataUnavailable::BudgetExceeded);
            }
        }
        let refused = self.errors.len() as u64;
        if self.counters.resolved != resolved
            || self.counters.unresolved != unresolved
            || self.counters.refused != refused
        {
            return Err(MetadataUnavailable::ParseFailed);
        }
        let has_budget_errors = self
            .errors
            .iter()
            .any(|e| e.code == SnapshotErrorCode::BudgetExceeded);
        match self.status {
            ResponseStatus::Complete if has_budget_errors => {
                return Err(MetadataUnavailable::ParseFailed);
            }
            ResponseStatus::Truncated if !has_budget_errors => {
                return Err(MetadataUnavailable::ParseFailed);
            }
            ResponseStatus::Complete | ResponseStatus::Truncated => {}
        }
        if self.encoded_len()? > MAX_SNAPSHOT_RESPONSE_BYTES {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        Ok(())
    }

    /// Encoded byte length of this response (JSON).
    pub fn encoded_len(&self) -> Result<usize, MetadataUnavailable> {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .map_err(|_| MetadataUnavailable::ParseFailed)
    }
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
/// Deserialization recomputes and verifies `unknown` (D05): a stored
/// magnitude that disagrees with its operands refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UnknownByDifference {
    /// The system total operand (`KTOT`).
    pub system_total: u64,
    /// The summed per-context operand (`ΣKCTX`).
    pub per_context_sum: u64,
    /// The resulting unknown magnitude.
    pub unknown: u64,
}

/// Wire shape for [`UnknownByDifference`]: identical fields, recomputed
/// on conversion.
#[derive(Debug, Clone, Copy, Deserialize)]
struct UnknownByDifferenceWire {
    system_total: u64,
    per_context_sum: u64,
    unknown: u64,
}

impl<'de> Deserialize<'de> for UnknownByDifference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UnknownByDifferenceWire::deserialize(deserializer)?;
        let expected = wire
            .system_total
            .checked_sub(wire.per_context_sum)
            .ok_or_else(|| {
                serde::de::Error::custom("stored difference contradicts its operands")
            })?;
        if expected != wire.unknown {
            return Err(serde::de::Error::custom(
                "stored difference contradicts its operands",
            ));
        }
        Ok(Self {
            system_total: wire.system_total,
            per_context_sum: wire.per_context_sum,
            unknown: wire.unknown,
        })
    }
}

impl UnknownByDifference {
    /// Compute the unknown magnitude. Requires a `Quiescent` snapshot;
    /// an `Unproven` snapshot or a negative difference refuses typed —
    /// impossible values surface, never saturate to zero.
    ///
    /// Precondition: both operands were established unsaturated by the
    /// caller (Stage 1 checked folding refuses saturated lanes before
    /// this point). Callers whose saturation state travels with the
    /// data must use [`compute_qualified`] instead (D06).
    pub fn compute(
        consistency: SnapshotConsistency,
        system_total: u64,
        per_context_sum: u64,
    ) -> Result<Self, String> {
        if consistency != SnapshotConsistency::Quiescent {
            return Err("unknown-by-difference requires a quiescent snapshot".to_string());
        }
        let unknown = system_total.checked_sub(per_context_sum).ok_or_else(|| {
            "contradictory snapshot: per-context sum exceeds system total".to_string()
        })?;
        Ok(Self {
            system_total,
            per_context_sum,
            unknown,
        })
    }
}

/// One difference operand with its saturation qualification: a saturated
/// counter no longer measures its population, so exactness refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CountOperand {
    /// The counter value.
    pub value: u64,
    /// Whether the counter saturated while measuring.
    pub saturated: bool,
}

/// Typed unknown-by-difference refusal (static diagnostics, no
/// operand echo).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DifferenceError {
    /// No fence proof: magnitudes are samples, not exact unknowns.
    Unproven,
    /// A saturated operand cannot establish exactness.
    SaturatedOperand,
    /// Per-context sum exceeds the system total.
    Contradictory,
    /// The population tag is empty or over budget.
    BadPopulation,
}

impl std::fmt::Display for DifferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unproven => write!(f, "unknown-by-difference requires a quiescent snapshot"),
            Self::SaturatedOperand => write!(f, "saturated operand cannot establish exactness"),
            Self::Contradictory => {
                write!(
                    f,
                    "contradictory snapshot: per-context sum exceeds system total"
                )
            }
            Self::BadPopulation => write!(f, "difference population tag is malformed"),
        }
    }
}

/// A population- and fence-qualified unknown-by-difference (D06): the
/// magnitude plus the scope it was computed over and the fence receipt
/// qualifying its exactness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualifiedDifference {
    /// The recomputed magnitude.
    pub difference: UnknownByDifference,
    /// The counted population both operands cover (`global` or
    /// `kh:<digits>`).
    pub population: String,
    /// The fence receipt qualifying this exactness.
    pub consistency: SnapshotConsistency,
}

/// Compute a qualified unknown magnitude: both operands must cover the
/// same named population, prove a `Quiescent` fence, and arrive
/// unsaturated — anything else refuses typed (D06).
pub fn compute_qualified(
    consistency: SnapshotConsistency,
    population: &str,
    system: CountOperand,
    per_context: CountOperand,
) -> Result<QualifiedDifference, DifferenceError> {
    if consistency != SnapshotConsistency::Quiescent {
        return Err(DifferenceError::Unproven);
    }
    if population.is_empty() || population.len() > MAX_STRING_FIELD_BYTES {
        return Err(DifferenceError::BadPopulation);
    }
    if system.saturated || per_context.saturated {
        return Err(DifferenceError::SaturatedOperand);
    }
    let unknown = system
        .value
        .checked_sub(per_context.value)
        .ok_or(DifferenceError::Contradictory)?;
    Ok(QualifiedDifference {
        difference: UnknownByDifference {
            system_total: system.value,
            per_context_sum: per_context.value,
            unknown,
        },
        population: population.to_string(),
        consistency,
    })
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

/// Resolver cache-entry budget guard.
pub fn check_cache_budget(entries: usize) -> Result<(), MetadataUnavailable> {
    if entries > MAX_RESOLVER_CACHE_ENTRIES {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    Ok(())
}

/// Ended-workload tombstone budget guard.
pub fn check_tombstone_budget(tombstones: usize) -> Result<(), MetadataUnavailable> {
    if tombstones > MAX_RESOLVER_TOMBSTONES {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    Ok(())
}

/// JSON nesting depth of a parsed value: scalars are depth 0, each
/// array/object level adds one.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Nesting guard for untrusted JSON documents (metadata files): deeper
/// than `max` refuses before conversion into typed DTOs.
pub fn check_json_nesting_depth(
    value: &serde_json::Value,
    max: usize,
) -> Result<(), MetadataUnavailable> {
    if json_depth(value) > max {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    Ok(())
}

/// Whether retry attempt `index` (0-based: 0 is the initial attempt) is
/// allowed: at most [`MAX_HELPER_RETRIES`] retries follow the initial
/// attempt, so indexes `0..=MAX_HELPER_RETRIES` are allowed.
#[must_use]
pub fn attempt_allowed(index: u32) -> bool {
    index <= MAX_HELPER_RETRIES
}

/// Whether a monotonic-nanosecond deadline has passed: `now - start >
/// timeout`. A backwards clock (`now < start`) fails closed as expired.
#[must_use]
pub fn deadline_exceeded(start_ns: u64, now_ns: u64, timeout_ns: u64) -> bool {
    if now_ns < start_ns {
        return true;
    }
    now_ns - start_ns > timeout_ns
}

/// Whether a cache entry observed at `observed_ns` is expired at `now_ns`
/// under `ttl_ns`: expired iff age exceeds the TTL. A backwards clock
/// fails closed as expired.
#[must_use]
pub fn cache_entry_expired(observed_ns: u64, now_ns: u64, ttl_ns: u64) -> bool {
    if now_ns < observed_ns {
        return true;
    }
    now_ns - observed_ns > ttl_ns
}

/// Encode a request: validate first, then serialize, then enforce the
/// byte budget on the encoded bytes.
pub fn encode_request(request: &SnapshotRequest) -> Result<Vec<u8>, MetadataUnavailable> {
    request.validate()?;
    let bytes = serde_json::to_vec(request).map_err(|_| MetadataUnavailable::ParseFailed)?;
    check_request_budget(bytes.len(), request.keys.len())?;
    Ok(bytes)
}

/// Decode a request: enforce the byte budget on the raw bytes BEFORE
/// parsing, count limits after.
pub fn decode_request(bytes: &[u8]) -> Result<SnapshotRequest, MetadataUnavailable> {
    if bytes.len() > MAX_SNAPSHOT_REQUEST_BYTES {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    let request: SnapshotRequest =
        serde_json::from_slice(bytes).map_err(|_| MetadataUnavailable::ParseFailed)?;
    request.validate()?;
    Ok(request)
}

/// Encode a response: validate first (including the byte budget), then
/// serialize.
pub fn encode_response(response: &SnapshotResponse) -> Result<Vec<u8>, MetadataUnavailable> {
    response.validate()?;
    serde_json::to_vec(response).map_err(|_| MetadataUnavailable::ParseFailed)
}

/// Decode a response: enforce the byte budget on the raw bytes BEFORE
/// parsing, count limits after.
pub fn decode_response(bytes: &[u8]) -> Result<SnapshotResponse, MetadataUnavailable> {
    if bytes.len() > MAX_SNAPSHOT_RESPONSE_BYTES {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    let response: SnapshotResponse =
        serde_json::from_slice(bytes).map_err(|_| MetadataUnavailable::ParseFailed)?;
    response.validate()?;
    Ok(response)
}

/// Decode a metadata file: byte budget first, then parse, then the
/// nesting guard, then typed conversion and validation.
pub fn decode_metadata(bytes: &[u8]) -> Result<MetadataSnapshot, MetadataUnavailable> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(MetadataUnavailable::BudgetExceeded);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| MetadataUnavailable::ParseFailed)?;
    check_json_nesting_depth(&value, MAX_METADATA_NESTING_DEPTH)?;
    let snapshot: MetadataSnapshot =
        serde_json::from_value(value).map_err(|_| MetadataUnavailable::ParseFailed)?;
    snapshot.validate()?;
    Ok(snapshot)
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
    fn stored_difference_is_recomputed_on_decode() {
        let ok: UnknownByDifference =
            serde_json::from_str(r#"{"system_total":100,"per_context_sum":60,"unknown":40}"#)
                .expect("consistent decodes");
        assert_eq!(ok.unknown, 40);
        let tampered = r#"{"system_total":100,"per_context_sum":60,"unknown":41}"#;
        assert!(serde_json::from_str::<UnknownByDifference>(tampered).is_err());
        let negative = r#"{"system_total":50,"per_context_sum":60,"unknown":0}"#;
        assert!(serde_json::from_str::<UnknownByDifference>(negative).is_err());
    }

    #[test]
    fn qualified_difference_refuses_saturation_and_contradiction() {
        let unsaturated = CountOperand {
            value: 100,
            saturated: false,
        };
        let per_context = CountOperand {
            value: 60,
            saturated: false,
        };
        let qualified = compute_qualified(
            SnapshotConsistency::Quiescent,
            "global",
            unsaturated,
            per_context,
        )
        .expect("qualified computes");
        assert_eq!(qualified.difference.unknown, 40);
        assert_eq!(qualified.population, "global");
        // Saturated operands refuse even when the arithmetic looks fine.
        let saturated = CountOperand {
            value: u64::MAX,
            saturated: true,
        };
        assert_eq!(
            compute_qualified(
                SnapshotConsistency::Quiescent,
                "global",
                saturated,
                saturated
            ),
            Err(DifferenceError::SaturatedOperand)
        );
        assert_eq!(
            compute_qualified(
                SnapshotConsistency::Unproven,
                "global",
                unsaturated,
                per_context
            ),
            Err(DifferenceError::Unproven)
        );
        assert_eq!(
            compute_qualified(
                SnapshotConsistency::Quiescent,
                "global",
                per_context,
                unsaturated
            ),
            Err(DifferenceError::Contradictory)
        );
        assert_eq!(
            compute_qualified(SnapshotConsistency::Quiescent, "", unsaturated, per_context),
            Err(DifferenceError::BadPopulation)
        );
    }

    #[test]
    fn chunk_decode_routes_through_validation() {
        let ok: ChunkInfo = serde_json::from_str(r#"{"index":0,"total":1}"#).expect("decodes");
        assert_eq!(ok, ChunkInfo::single());
        assert!(serde_json::from_str::<ChunkInfo>(r#"{"index":1,"total":1}"#).is_err());
        assert!(serde_json::from_str::<ChunkInfo>(r#"{"index":0,"total":0}"#).is_err());
    }

    #[test]
    fn budgets_refuse_overlarge_dtos() {
        assert!(check_request_budget(MAX_SNAPSHOT_REQUEST_BYTES + 1, 1).is_err());
        assert!(check_request_budget(100, MAX_SNAPSHOT_ASSOCIATIONS + 1).is_err());
        assert!(check_response_budget(MAX_SNAPSHOT_RESPONSE_BYTES + 1, 1).is_err());
        assert!(check_request_budget(100, 10).is_ok());
    }

    #[test]
    fn session_id_shape_is_exact() {
        assert!(validate_session_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_session_id("0123456789ABCDEF0123456789ABCDEF").is_err());
        assert!(validate_session_id("0123456789abcdef0123456789abcde").is_err());
        assert!(validate_session_id("0123456789abcdef0123456789abcdefX").is_err());
        assert!(validate_session_id("").is_err());
    }

    #[test]
    fn request_boundaries_are_exact() {
        let key = SnapshotKey {
            kernel_scope: "k".to_string(),
            cgroup: 1,
            tgid: 1,
            start_ns: 1,
        };
        let exact = SnapshotRequest {
            session_id: "0123456789abcdef0123456789abcdef".to_string(),
            keys: vec![key.clone(); MAX_SNAPSHOT_ASSOCIATIONS],
        };
        // Duplicates refuse even at the boundary count.
        assert!(exact.validate().is_err());
        let distinct: Vec<SnapshotKey> = (0..MAX_SNAPSHOT_ASSOCIATIONS as u64)
            .map(|c| SnapshotKey {
                kernel_scope: "k".to_string(),
                cgroup: c,
                tgid: 1,
                start_ns: 1,
            })
            .collect();
        let ok = SnapshotRequest {
            session_id: "0123456789abcdef0123456789abcdef".to_string(),
            keys: distinct,
        };
        assert!(ok.validate().is_ok());
        let _ = key;
    }

    #[test]
    fn nesting_guard_counts_containers() {
        let scalar = serde_json::json!("x");
        assert!(check_json_nesting_depth(&scalar, 0).is_ok());
        let mut deep = serde_json::json!({"leaf": true});
        for _ in 0..15 {
            deep = serde_json::json!({"nest": deep});
        }
        // 16 object levels: exactly at the pin.
        assert!(check_json_nesting_depth(&deep, MAX_METADATA_NESTING_DEPTH).is_ok());
        let deeper = serde_json::json!({"nest": deep});
        assert!(check_json_nesting_depth(&deeper, MAX_METADATA_NESTING_DEPTH).is_err());
    }

    #[test]
    fn cache_and_tombstone_budgets_are_exact() {
        assert!(check_cache_budget(MAX_RESOLVER_CACHE_ENTRIES).is_ok());
        assert!(check_cache_budget(MAX_RESOLVER_CACHE_ENTRIES + 1).is_err());
        assert!(check_tombstone_budget(MAX_RESOLVER_TOMBSTONES).is_ok());
        assert!(check_tombstone_budget(MAX_RESOLVER_TOMBSTONES + 1).is_err());
    }

    #[test]
    fn retry_attempts_allow_initial_plus_max_retries() {
        assert!(attempt_allowed(0));
        assert!(attempt_allowed(MAX_HELPER_RETRIES));
        assert!(!attempt_allowed(MAX_HELPER_RETRIES + 1));
    }

    #[test]
    fn snapshot_schema_freeze_pin_is_fixed() {
        assert_eq!(snapshot_schema_fnv1a_hex(), WORKLOAD_SNAPSHOT_SCHEMA_FNV1A);
        assert!(!snapshot_schema_drifted(
            EMBEDDED_SNAPSHOT_SCHEMA.as_bytes()
        ));
        assert!(snapshot_schema_drifted(b"{tampered}"));
    }

    #[test]
    fn deadlines_and_ttls_fail_closed_on_backwards_clocks() {
        assert!(!deadline_exceeded(100, 100 + 50, 50));
        assert!(deadline_exceeded(100, 100 + 51, 50));
        assert!(deadline_exceeded(200, 100, 50));
        assert!(!cache_entry_expired(100, 100 + 50, 50));
        assert!(cache_entry_expired(100, 100 + 51, 50));
        assert!(cache_entry_expired(200, 100, 50));
    }
}
