// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-report: JSONL writer, validator, and summary renderer (T9).
//!
//! The writer maps core evidence types onto the frozen `event-v0` wire
//! records; the validator checks streams structurally and pins the schema
//! bytes; the renderer prints counts that always qualify zeros (R-024).

pub mod adapters;
pub mod checker;
pub mod cover;
pub mod live_render;
pub mod observe;
pub mod rel;
pub mod render;
pub mod session;
pub mod snapshot;
pub mod validate;
pub mod writer;

pub use checker::{StreamChecker, StreamFinding, check_stream};
pub use cover::{CoverageGap, GapCtx};
pub use observe::ObservationExtra;
pub use render::{render_summary, render_summary_reader, sanitize_cell};
pub use session::{FinalBarrier, SessionEnd, SessionStart, SessionVerdict};
pub use snapshot::{SnapshotBarrier, SnapshotParams, SnapshotUnit};
pub use validate::{
    LifecycleFinding, MAX_VALIDATE_LINE_BYTES, ResolvedSchema, SessionFinding, ValidationFinding,
    lifecycle_v1_payload, resolve_schema, resolve_schema_at, schema_fnv1a_hex,
    validate_and_render_file, validate_and_render_reader, validate_file,
    validate_lifecycle_session, validate_lifecycle_v1, validate_reader, validate_str,
};
pub use writer::{JsonlWriter, ReportError, SessionWriteError, SessionWriter, write_str_atomic};

/// Frozen event-envelope schema const; every record must carry exactly this.
pub const EVENT_SCHEMA_V0: &str = "kryprobe.event/v0";

/// Frozen contract version carried in `session_start` payloads (1B-M5:
/// one shared const, not a literal per emitter; see `docs/versioning.md`
/// for what each version marker versions and the reader-tolerance rules).
pub const CONTRACT_VERSION_V0: &str = "v0-proposed";

/// kcrypto lifecycle payload version for the standalone payload-v1
/// `schema` field (no v0 envelope carriage; see ADR-0005).
/// Draft: bytes freeze only after review (see T05).
pub const KCRYPTO_LIFECYCLE_V1: &str = "kryprobe.kcrypto.lifecycle/v1";

/// kcrypto lifecycle session-envelope version (T11/P6 ADR: the distinct
/// versioned envelope carrying start/config, validated observations,
/// coverage updates, and the terminal receipt — never event-v0).
/// Draft: bytes freeze only after review (no compiled-in pin yet).
pub const KCRYPTO_LIFECYCLE_SESSION_V1: &str = "kryprobe.kcrypto.lifecycle-session/v1";

/// kcrypto context record-profile version (P6r2/N2 ADR amendment:
/// the closed wire shapes of one request's submitter, execution,
/// and completion contexts — every `context` record pins this).
/// Draft: bytes freeze only after review (no compiled-in pin yet).
pub const KCRYPTO_CONTEXT_V1: &str = "kryprobe.kcrypto.context/v1";
