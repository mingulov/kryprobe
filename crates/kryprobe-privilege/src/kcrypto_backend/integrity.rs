// SPDX-License-Identifier: GPL-3.0-or-later
//! Measured aggregate integrity; non-atomic sample differences are not loss.

use crate::kcrypto_snapshot::{ParsedRow, SnapshotRows, parse_snapshot_row};
use kryprobe_core::error::{BackendError, InternalError};
use kryprobe_core::evidence::IntegritySummary;

// ---------------------------------------------------------------------------
// One owner for each measured counter.
// ---------------------------------------------------------------------------

/// Validate snapshot row kinds and map measured ring/who indicators. The
/// independently read KTOT and KAGG values cannot establish insertion loss.
pub(crate) fn integrity_for_snapshot(
    snap: &SnapshotRows,
    drops: u8,
    who_drops: u64,
) -> Result<IntegritySummary, BackendError> {
    let reparse = |err: BackendError| {
        BackendError::Internal(InternalError::with_detail(
            "kcrypto_finalize_read",
            &format!("row reparse: {err}"),
        ))
    };
    let mut agg_calls = 0u64;
    for row in &snap.rows {
        match parse_snapshot_row(row.as_bytes()).map_err(reparse)? {
            ParsedRow::Agg { vagg, .. } => {
                agg_calls = agg_calls.saturating_add(vagg.calls);
            }
            _ => {
                return Err(BackendError::Internal(InternalError::new(
                    "kcrypto_finalize_row_kind",
                )));
            }
        }
    }
    let totals_calls = match &snap.totals {
        // Array map: live-impossible; with no baseline, claim no gap.
        None => None,
        Some(totals) => match parse_snapshot_row(totals.as_bytes()).map_err(reparse)? {
            ParsedRow::Totals { vagg } => Some(vagg.calls),
            _ => {
                return Err(BackendError::Internal(InternalError::new(
                    "kcrypto_finalize_row_kind",
                )));
            }
        },
    };
    integrity_for_counts(agg_calls, totals_calls, drops, who_drops)
}

/// Only independently measured loss indicators enter integrity. Call operands
/// remain unreconciled diagnostics: no writer fence exists in this profile.
pub(crate) fn integrity_for_counts(
    _agg_calls: u64,
    _totals_calls: Option<u64>,
    drops: u8,
    who_drops: u64,
) -> Result<IntegritySummary, BackendError> {
    Ok(IntegritySummary {
        ring_reservation_failures: u64::from(drops),
        state_insert_failures: who_drops,
        // Queue refusal belongs to the shared transport feed.
        user_queue_drops: 0,
        // N/A: these maps never evict. Map-full volume is not separately measured.
        state_evictions: 0,
        // N/A: single-edge fexit sensor (no entry/return pairing).
        unmatched_entries: 0,
        // N/A: single-edge fexit sensor (no entry/return pairing).
        unmatched_returns: 0,
        // N/A: no correlation state (C10-unattributed observations).
        correlation_overflows: 0,
        // N/A: single-generation sensor (generation guards configure, not events).
        unknown_generation_events: 0,
        // N/A: decode charges no budget (budgets gate configure only).
        budget_omissions: 0,
    })
}
