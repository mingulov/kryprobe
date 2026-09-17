// SPDX-License-Identifier: GPL-3.0-or-later
//! Aggregate records: `aggregate_snapshot` qualified by integrity receipts.
//!
//! Snapshots count operations, never loss: the integrity summary qualifies
//! them instead. Spotless receipts read `qualified`/`qualified`; any
//! recorded loss downgrades counts to `lower_bound` and events to `partial`.

use crate::writer::{JsonlWriter, ReportError};
use kryprobe_core::enums::BackendId;
use kryprobe_core::evidence::IntegritySummary;
use serde::Serialize;

/// Snapshot unit (schema `unit` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotUnit {
    /// Raw API calls observed.
    ApiCalls,
    /// Callback entries observed.
    CallbackEntries,
    /// Size-query calls observed.
    SizeQueries,
    /// Operation attempts observed.
    OperationAttempts,
    /// Successful operations observed.
    SuccessfulOperations,
    /// Backend-level logical operations.
    LogicalOperations,
}

/// Snapshot barrier state (schema `barrier_status` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotBarrier {
    /// Closing barrier observed and checked.
    Validated,
    /// Snapshot is not the final one.
    NotFinal,
    /// Closing barrier missing (truncated interval).
    Missing,
}

/// `aggregate_snapshot` parameters; integrity bindings derive from receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotParams {
    /// Attributed target, or `None` for null.
    pub target: Option<String>,
    /// Backend counted (never `Synthetic`: no wire spelling).
    pub backend: BackendId,
    /// Attributed implementation, or `None` for null.
    pub implementation: Option<String>,
    /// What the count counts.
    pub unit: SnapshotUnit,
    /// Aggregate count over the interval.
    pub count: u64,
    /// Interval begin, monotonic nanoseconds.
    pub begin_ns: u64,
    /// Interval end, monotonic nanoseconds.
    pub end_ns: u64,
    /// Whether this snapshot closes the interval.
    pub final_snapshot: bool,
    /// Closing barrier state.
    pub barrier: SnapshotBarrier,
}

#[derive(Serialize)]
struct SnapPayload<'a> {
    target_id: Option<&'a str>,
    backend: &'a str,
    implementation_id: Option<&'a str>,
    unit: SnapshotUnit,
    count: String,
    count_integrity: &'static str,
    begin_ns: String,
    end_ns: String,
    #[serde(rename = "final")]
    final_snapshot: bool,
    barrier_status: SnapshotBarrier,
    event_integrity: &'static str,
}

fn spotless(summary: &IntegritySummary) -> bool {
    summary.ring_reservation_failures == 0
        && summary.user_queue_drops == 0
        && summary.state_insert_failures == 0
        && summary.state_evictions == 0
        && summary.unmatched_entries == 0
        && summary.unmatched_returns == 0
        && summary.correlation_overflows == 0
        && summary.unknown_generation_events == 0
        && summary.budget_omissions == 0
}

impl JsonlWriter {
    /// Appends `aggregate_snapshot`, qualified by integrity receipts.
    pub fn integrity(
        &mut self,
        snap: &SnapshotParams,
        summary: &IntegritySummary,
    ) -> Result<(), ReportError> {
        let Some(backend) = snap.backend.as_wire_str() else {
            return Err(ReportError::SyntheticBackend);
        };
        let (count_integrity, event_integrity) = if spotless(summary) {
            ("qualified", "qualified")
        } else {
            ("lower_bound", "partial")
        };
        self.emit(
            "aggregate_snapshot",
            SnapPayload {
                target_id: snap.target.as_deref(),
                backend,
                implementation_id: snap.implementation.as_deref(),
                unit: snap.unit,
                count: snap.count.to_string(),
                count_integrity,
                begin_ns: snap.begin_ns.to_string(),
                end_ns: snap.end_ns.to_string(),
                final_snapshot: snap.final_snapshot,
                barrier_status: snap.barrier,
                event_integrity,
            },
        );
        Ok(())
    }
}
