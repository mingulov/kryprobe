// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-report: JSONL writer, validator, and summary renderer (T9).
//!
//! The writer maps core evidence types onto the frozen `event-v0` wire
//! records; the validator checks streams structurally and pins the schema
//! bytes; the renderer prints counts that always qualify zeros (R-024).

pub mod cover;
pub mod observe;
pub mod rel;
pub mod render;
pub mod session;
pub mod snapshot;
pub mod validate;
pub mod writer;

pub use cover::{CoverageGap, GapCtx};
pub use observe::ObservationExtra;
pub use render::{render_summary, render_summary_reader};
pub use session::{FinalBarrier, SessionEnd, SessionStart, SessionVerdict};
pub use snapshot::{SnapshotBarrier, SnapshotParams, SnapshotUnit};
pub use validate::{
    ResolvedSchema, ValidationFinding, resolve_schema, resolve_schema_at, schema_fnv1a_hex,
    validate_and_render_file, validate_and_render_reader, validate_file, validate_reader,
    validate_str,
};
pub use writer::{JsonlWriter, ReportError, write_str_atomic};

/// Frozen event-envelope schema const; every record must carry exactly this.
pub const EVENT_SCHEMA_V0: &str = "kryprobe.event/v0";
