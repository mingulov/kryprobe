// SPDX-License-Identifier: GPL-3.0-or-later
//! D10 integrity mapping (1A-M10).

use crate::kcrypto_snapshot::{ParsedRow, SnapshotRows, parse_snapshot_row};
use kryprobe_core::error::{BackendError, InternalError};
use kryprobe_core::evidence::IntegritySummary;

// ---------------------------------------------------------------------------
// D10 integrity mapping (exact).
// ---------------------------------------------------------------------------

/// D10 over snapshot data: `ring_reservation_failures ← drops`,
/// `state_insert_failures ← KTOT − ΣKAGG` calls gap `+ who_drops`
/// (saturating; the KAGG/KIDN-full volume plus the KWHO-family
/// attribution-insert loss — chase-failures skip KTOT so are excluded),
/// other 7 counters zero with N/A reasons. Pure over rows so the PARTIAL
/// path pins unprivileged; `finalize` wires it to a live snapshot.
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

/// D10 over call counts (M5 core): `ring_reservation_failures ←
/// drops`, `state_insert_failures ← KTOT − ΣKAGG calls gap `+`
/// who_drops` (saturating). No baseline (missing totals) claims no
/// gap. Infallible in practice (`Result` keeps the wrapper's error
/// channel shape).
pub(crate) fn integrity_for_counts(
    agg_calls: u64,
    totals_calls: Option<u64>,
    drops: u8,
    who_drops: u64,
) -> Result<IntegritySummary, BackendError> {
    let gap = totals_calls.map_or(0, |totals| totals.saturating_sub(agg_calls));
    Ok(IntegritySummary {
        ring_reservation_failures: u64::from(drops),
        state_insert_failures: gap.saturating_add(who_drops),
        // N/A: v0.1 short-lived drain keeps no queue accounting (queue pins 0 via the shared feed).
        user_queue_drops: 0,
        // N/A: BPF maps never evict; full-map loss accrues above via the KTOT gap.
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
