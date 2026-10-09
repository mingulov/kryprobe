// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 workload-context model (ADR-0008, ctx-v1): pure captured-context,
//! identity, evidence, scope, and snapshot types.
//!
//! Pure by construction: no OS reads, no I/O, no ambient clocks. All
//! budgets are hard caps from ADR-0008 §(h); exceeding input refuses
//! typed instead of truncating silently.

mod context;
mod evidence;
mod identity;
mod metadata;
mod observation;
mod resolve;
mod scope;
mod snapshot;

pub use context::{ContextIdentity, ContextQualification, ExecutionKind, ObservationBoundary};
pub use evidence::{
    AttributionEvidence, AttributionStatus, ClockDomain, METHOD_CAPTURED_CGROUP,
    METHOD_CGROUP_INODE_BIND, METHOD_METADATA_FILE, METHOD_METADATA_LABEL, METHOD_RUNTIME_ADAPTER,
    METHOD_UNRESOLVED, Relationship, ValidityInterval, WorkloadOrigin,
};
pub use identity::{
    ContainerRef, IdentityKey, JoinQualification, PodRef, WorkloadIdentity, qualify_join,
};
pub use metadata::{
    BindingProvenance, KernelIdentity, MetadataEntry, MetadataSnapshot, SnapshotInterval,
    WORKLOAD_METADATA_SCHEMA_FNV1A, metadata_schema_drifted, metadata_schema_fnv1a_hex,
};
pub use observation::WorkloadObservation;
pub use resolve::{bind_response_to_request, chunk_sequence_complete, resolve};
pub use scope::{ScopeDecision, ScopePartition};
pub use snapshot::{
    ChunkInfo, CountOperand, DifferenceError, MetadataUnavailable, QualifiedDifference,
    ResolvedAssociation, ResponseStatus, SnapshotConsistency, SnapshotCounters, SnapshotErrorCode,
    SnapshotKey, SnapshotKeyDetail, SnapshotKeyError, SnapshotRequest, SnapshotResponse,
    UnknownByDifference, WORKLOAD_SNAPSHOT_SCHEMA_FNV1A, attempt_allowed, cache_entry_expired,
    check_cache_budget, check_json_nesting_depth, check_request_budget, check_response_budget,
    check_tombstone_budget, compute_qualified, deadline_exceeded, decode_metadata, decode_request,
    decode_response, encode_request, encode_response, snapshot_schema_drifted,
    snapshot_schema_fnv1a_hex, validate_session_id,
};

/// Maximum metadata-file bytes accepted (ADR-0008 §(h)).
pub const MAX_METADATA_BYTES: usize = 1_048_576;
/// Maximum metadata entries accepted.
pub const MAX_METADATA_ENTRIES: usize = 1024;
/// Maximum bytes of one id/name/label string field.
pub const MAX_STRING_FIELD_BYTES: usize = 256;
/// Maximum snapshot-request bytes.
pub const MAX_SNAPSHOT_REQUEST_BYTES: usize = 4096;
/// Maximum snapshot-response bytes.
pub const MAX_SNAPSHOT_RESPONSE_BYTES: usize = 65_536;
/// Maximum associations per snapshot response.
pub const MAX_SNAPSHOT_ASSOCIATIONS: usize = 256;
/// Kernel identity string bound.
pub const MAX_KERNEL_IDENTITY_BYTES: usize = 128;
/// Session id: 128-bit random, lowercase hex.
pub const SESSION_ID_HEX_CHARS: usize = 32;
/// Maximum JSON nesting depth accepted in metadata files (Stage 2A pin).
pub const MAX_METADATA_NESTING_DEPTH: usize = 16;
/// Maximum resolver cache entries (Stage 2A pin).
pub const MAX_RESOLVER_CACHE_ENTRIES: usize = 256;
/// Maximum tombstones for ended workloads (Stage 2A pin).
pub const MAX_RESOLVER_TOMBSTONES: usize = 256;
/// Maximum cache entry lifetime in monotonic nanoseconds: 5 minutes.
pub const RESOLVER_CACHE_TTL_NS: u64 = 300_000_000_000;
/// Negative-cache entry lifetime in monotonic nanoseconds: 5 seconds.
pub const RESOLVER_NEGATIVE_CACHE_TTL_NS: u64 = 5_000_000_000;
/// Minimum interval between resolver refresh scans: 1 second.
pub const RESOLVER_MIN_REFRESH_INTERVAL_NS: u64 = 1_000_000_000;
/// Maximum helper retries after the initial attempt (Stage 2A pin).
pub const MAX_HELPER_RETRIES: u32 = 2;
/// Helper request timeout in monotonic nanoseconds: 2 seconds.
pub const HELPER_REQUEST_TIMEOUT_NS: u64 = 2_000_000_000;
/// Maximum workload-report-v2 file bytes (Stage 2A pin).
pub const MAX_REPORT_V2_BYTES: usize = 1_048_576;
/// Maximum context rows in a workload-report-v2 file (mirrors KCTX).
pub const MAX_V2_CONTEXT_ROWS: usize = 1024;
/// Maximum dictionary entries in a workload-report-v2 file.
pub const MAX_V2_DICTIONARY_ENTRIES: usize = 1024;
