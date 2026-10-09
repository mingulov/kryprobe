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
mod scope;
mod snapshot;

pub use context::{ContextIdentity, ContextQualification, ExecutionKind};
pub use evidence::{
    AttributionEvidence, AttributionStatus, WorkloadOrigin, METHOD_CAPTURED_CGROUP,
    METHOD_CGROUP_INODE_BIND, METHOD_METADATA_FILE, METHOD_METADATA_LABEL, METHOD_RUNTIME_ADAPTER,
    METHOD_UNRESOLVED,
};
pub use identity::{ContainerRef, IdentityKey, JoinQualification, PodRef, WorkloadIdentity, qualify_join};
pub use scope::{ScopeDecision, ScopePartition};
pub use snapshot::{
    MetadataUnavailable, SnapshotConsistency, SnapshotKey, SnapshotRequest, UnknownByDifference,
    check_request_budget, check_response_budget,
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
