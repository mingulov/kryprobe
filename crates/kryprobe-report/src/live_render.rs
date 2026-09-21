// SPDX-License-Identifier: GPL-3.0-or-later
//! Live human rendering (moved from the CLI, 1B-H2/1B-M8).
//!
//! The aggregated watch tables, the K5 attribution block, and the kp2
//! §8 trailer over session coverage. `watch --system` and human
//! `report --system` render these same tables; only the exit code
//! differs. Pure over core evidence types — no CLI types here (the
//! callers pass observations + coverage, never the outcome struct).

use crate::observe::ObservationExtra;
use crate::session::{FinalBarrier, SessionEnd, SessionStart, SessionVerdict};
use crate::writer::{JsonlWriter, ReportError};
use kryprobe_core::enums::{BackendId, CaptureMode, CoverageStatus, TargetSelector};
use kryprobe_core::evidence::payload_keys as K;
use kryprobe_core::evidence::{CoverageSummary, NativeObservation};
use std::collections::BTreeMap;

/// Every payload key watch reads, top-level and nested under `counts`
/// (1B-H3: keep in sync with the readers below — the
/// `payload_contract` test proves the producer emits all of these).
pub const WATCH_READ_KEYS: &[&str] = &[
    K::ROW,
    K::FAMILY,
    K::OP,
    K::RESULT,
    K::ALGORITHM,
    K::DRIVER,
    K::CONTEXT,
    K::COUNTS,
    K::CALLS,
    K::OK,
    K::QUEUED,
    K::ERRORS,
    K::BYTES,
    K::KEY_HASH,
    K::TGID,
    K::COMM,
    K::UID,
];

/// Exact table header (brief-exact column set).
const HEADER: &str = "FAMILY OP ALGORITHM DRIVER CALLS BYTES OK QUEUED ERRORS";

/// WHO block column header (spec §2.3: `KH TGID COMM UID CALLS`).
pub const WHO_HEADER: &str = "KH TGID COMM UID CALLS";

/// Max WHO rows rendered; the rest collapse into the `+N more` trailer.
pub const WHO_MAX_ROWS: usize = 32;

/// Accumulated counters for one rendered row.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Acc {
    calls: u64,
    bytes: u64,
    ok: u64,
    queued: u64,
    errors: u64,
}

impl Acc {
    /// Field-wise saturating sum (counters never wrap, never panic).
    fn add(&mut self, other: Acc) {
        self.calls = self.calls.saturating_add(other.calls);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.ok = self.ok.saturating_add(other.ok);
        self.queued = self.queued.saturating_add(other.queued);
        self.errors = self.errors.saturating_add(other.errors);
    }
}

/// Raw payload string (empty when missing or not a string).
fn raw<'a>(payload: &'a serde_json::Value, key: &str) -> &'a str {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

/// Rendered cell: missing or empty renders `unknown` (C10 — zeros and
/// unknowns render as unknown, never fabricated).
/// Rendered cell (shared with `check`; C10 rule in one place).
pub fn show(cell: &str) -> String {
    if cell.is_empty() {
        String::from("unknown")
    } else {
        crate::sanitize_cell(cell)
    }
}

/// One `counts` sub-counter (0 when the shape is absent — real decodes
/// always carry it; only hand-fed shapes can miss it).
fn count(payload: &serde_json::Value, key: &str) -> u64 {
    payload
        .get(K::COUNTS)
        .and_then(|counts| counts.get(key))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn acc_of(obs: &NativeObservation) -> Acc {
    let payload = &obs.backend_payload;
    Acc {
        calls: count(payload, K::CALLS),
        bytes: payload
            .get(K::BYTES)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        ok: count(payload, K::OK),
        queued: count(payload, K::QUEUED),
        errors: count(payload, K::ERRORS),
    }
}

/// Full row key (1A-L14): the KAGG identity the payload mirrors.
/// Field order IS the `BTreeMap` order (family, op, result,
/// algorithm, driver, context) — the derived `Ord` compares top to
/// bottom exactly like the old 6-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RowKey<'a> {
    family: &'a str,
    op: &'a str,
    result: &'a str,
    algorithm: &'a str,
    driver: &'a str,
    context: &'a str,
}

/// Table class key: the row key minus result/context (the GROUP BY
/// of the rendered table). Same field-order rule as [`RowKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ClassKey<'a> {
    family: &'a str,
    op: &'a str,
    algorithm: &'a str,
    driver: &'a str,
}

fn row_key(obs: &NativeObservation) -> RowKey<'_> {
    let payload = &obs.backend_payload;
    RowKey {
        family: raw(payload, K::FAMILY),
        op: raw(payload, K::OP),
        result: raw(payload, K::RESULT),
        algorithm: raw(payload, K::ALGORITHM),
        driver: raw(payload, K::DRIVER),
        context: raw(payload, K::CONTEXT),
    }
}

/// kp2 §8 trailer order over the canonical dimensions (1B-M3):
/// merged pairs stay adjacent so the shared token emits once.
const KP2_ORDER: [kryprobe_core::evidence::CoverageDimension; 8] = {
    use kryprobe_core::evidence::CoverageDimension as D;
    [
        D::Attachment,
        D::ObjectDiscovery,
        D::TargetPopulation,
        D::AggregateCounts,
        D::DetailedEvents,
        D::Completion,
        D::Attribution,
        D::Correlation,
    ]
};

/// kp2 §8 trailer dimensions in kp2 order: `attach` (attachment,
/// object_discovery), `operation` (target_population — the observed op
/// surface), `capture-integrity` (aggregate_counts, detailed_events),
/// `completion` (completion — the closed window attests temporal
/// coverage, so `temporal` is never emitted alone), `attribution`
/// (attribution), `correlation` (passthrough — no kp2 §8 counterpart).
/// Empty ⟺ every dimension complete (interval end with the contract held
/// is COMPLETE, never PARTIAL).
#[must_use]
pub fn trailer_dims(coverage: &CoverageSummary) -> Vec<&'static str> {
    let weak = |status: CoverageStatus| status != CoverageStatus::CompleteForDeclaredBoundary;
    let mut dims = Vec::new();
    for dim in KP2_ORDER {
        if weak(coverage.dimension(dim).status) {
            // Adjacent merged pairs share one token — emit once.
            let token = dim.as_kp2_str();
            if dims.last() != Some(&token) {
                dims.push(token);
            }
        }
    }
    dims
}

/// One who-row `calls` tally (0 when the shape is absent — real
/// decodes always carry it; only hand-fed shapes can miss it).
fn who_calls(obs: &NativeObservation) -> u64 {
    obs.backend_payload
        .get(K::CALLS)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// Who-row dedup key (1A-L14): (key_hash, tgid), 0 when absent
/// (real decodes always carry both; only hand-fed shapes can miss
/// them). Derived order matches the old pair order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct WhoKey {
    kh: u64,
    tgid: u64,
}

impl WhoKey {
    /// Absent tgid sorts as 0, NOT as `None`-first.
    fn of(kh: u64, tgid: Option<u64>) -> Self {
        WhoKey {
            kh,
            tgid: tgid.unwrap_or(0),
        }
    }
}

fn who_key(obs: &NativeObservation) -> WhoKey {
    let payload = &obs.backend_payload;
    WhoKey {
        kh: payload
            .get(K::KEY_HASH)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        tgid: payload
            .get(K::TGID)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    }
}

/// Projected who row (M4): every JSON walk for the row happens once,
/// at projection time — dedup/sort/render below never touch JSON.
#[derive(Debug, Clone, Copy)]
struct WhoProj<'a> {
    kh: u64,
    tgid: Option<u64>,
    comm: &'a str,
    uid: Option<u64>,
    calls: u64,
}

/// Projects one who observation (same defaults as the direct
/// readers: 0 key parts, `None` cells, 0 calls when absent).
fn project_who(obs: &NativeObservation) -> WhoProj<'_> {
    let payload = &obs.backend_payload;
    let kh = who_key(obs).kh;
    WhoProj {
        kh,
        tgid: payload.get(K::TGID).and_then(serde_json::Value::as_u64),
        comm: raw(payload, K::COMM),
        uid: payload.get(K::UID).and_then(serde_json::Value::as_u64),
        calls: who_calls(obs),
    }
}

/// Renders the K5 attribution block over `obs`: only `row="who"`
/// observations feed it; latest wins per (key_hash, tgid) (cumulative
/// per-tick snapshots, the agg-table idiom); rows sort by calls desc
/// (ties by (kh, tgid) asc, deterministic); the top 32 render as
/// `KH TGID COMM UID CALLS` (`KH` is 16-digit lowercase hex) and the
/// rest collapse into a `+N more` trailer. Empty renders `WHO: none`.
#[must_use]
pub fn render_who_block(obs: &[NativeObservation]) -> String {
    // M4: one projection pass (each row's JSON walks once), then
    // plain-struct dedup/sort/render — no per-comparison walks.
    let mut latest: BTreeMap<WhoKey, WhoProj<'_>> = BTreeMap::new();
    for ob in obs {
        if ob
            .backend_payload
            .get(K::ROW)
            .and_then(serde_json::Value::as_str)
            != Some("who")
        {
            continue;
        }
        let proj = project_who(ob);
        latest.insert(WhoKey::of(proj.kh, proj.tgid), proj);
    }
    if latest.is_empty() {
        return String::from("WHO: none\n");
    }
    let mut rows: Vec<WhoProj<'_>> = latest.into_values().collect();
    rows.sort_by(|a, b| {
        // Tie-break matches `who_key` exactly (absent tgid sorts as
        // 0, NOT as `None`-first).
        b.calls
            .cmp(&a.calls)
            .then_with(|| WhoKey::of(a.kh, a.tgid).cmp(&WhoKey::of(b.kh, b.tgid)))
    });
    let mut text = String::from(WHO_HEADER);
    text.push('\n');
    for row in rows.iter().take(WHO_MAX_ROWS) {
        text.push_str(&format!(
            "{kh:016x} {tgid} {comm} {uid} {calls}\n",
            kh = row.kh,
            tgid = row
                .tgid
                .map(|value| value.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            comm = show(row.comm),
            uid = row
                .uid
                .map(|value| value.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            calls = row.calls
        ));
    }
    if rows.len() > WHO_MAX_ROWS {
        text.push_str(&format!("+{} more\n", rows.len() - WHO_MAX_ROWS));
    }
    text
}

/// Renders observations + coverage: header + one row per
/// (family, op, algorithm, driver) + `TOTAL` + the WHO attribution
/// block + the `COMPLETE` / `PARTIAL: <dims>` trailer. Latest wins
/// per full row key (cumulative snapshots), then classes/contexts
/// sum; idents never render as rows;
/// `TOTAL` comes from the latest totals carrier (column sums when totals
/// are absent — the coverage trailer separately attests the gap).
#[must_use]
pub fn render_watch_tables(
    observations: &[NativeObservation],
    coverage: &CoverageSummary,
) -> String {
    // M4: one projection pass builds the agg latest-map AND the
    // totals slot (last totals in vec order wins — the `rev().find`
    // idiom, without the second iteration).
    let mut latest: BTreeMap<RowKey<'_>, Acc> = BTreeMap::new();
    let mut totals_slot: Option<Acc> = None;
    for obs in observations {
        let kind = obs
            .backend_payload
            .get(K::ROW)
            .and_then(serde_json::Value::as_str);
        if kind == Some("agg") {
            latest.insert(row_key(obs), acc_of(obs));
        } else if kind == Some("totals") {
            totals_slot = Some(acc_of(obs));
        }
    }
    let mut rows: BTreeMap<ClassKey<'_>, Acc> = BTreeMap::new();
    for (key, acc) in latest {
        rows.entry(ClassKey {
            family: key.family,
            op: key.op,
            algorithm: key.algorithm,
            driver: key.driver,
        })
        .or_default()
        .add(acc);
    }
    let mut text = String::from(HEADER);
    text.push('\n');
    for (key, acc) in &rows {
        text.push_str(&format!(
            "{} {} {} {} {} {} {} {} {}\n",
            show(key.family),
            show(key.op),
            show(key.algorithm),
            show(key.driver),
            acc.calls,
            acc.bytes,
            acc.ok,
            acc.queued,
            acc.errors
        ));
    }
    let totals = totals_slot.unwrap_or_else(|| {
        rows.values().fold(Acc::default(), |mut total, acc| {
            total.add(*acc);
            total
        })
    });
    text.push_str(&format!(
        "TOTAL - - - {} {} {} {} {}\n",
        totals.calls, totals.bytes, totals.ok, totals.queued, totals.errors
    ));
    text.push_str(&render_who_block(observations));
    let dims = trailer_dims(coverage);
    if dims.is_empty() {
        text.push_str("COMPLETE\n");
    } else {
        text.push_str(&format!("PARTIAL: {}\n", dims.join(",")));
    }
    text
}

/// Fixed session label for live JSONL export: a live capture is a
/// single unqualified run with no session identity of its own. The
/// `live:run` spelling satisfies the checker's prefixed-id shape.
pub const LIVE_SESSION_ID: &str = "live:run";

/// Fixed qualification label for live JSONL export: a live capture
/// carries no qualification stamp — a qualification harness stamps
/// its own id when it adopts the stream.
pub const LIVE_QUALIFICATION_ID: &str = "live";

/// Renders a finished live session as event-v0 JSONL (M1):
/// `session_start`, one `operation_observation` per aggregated
/// observation, `session_end`. Same single source as the human
/// tables — observations + coverage, never the CLI outcome struct.
///
/// Every record is validated-shape: the verdict mirrors the human
/// `COMPLETE`/`PARTIAL` trailer (`trailer_dims` empty ⟺
/// `OBSERVED`), and each observation passes through the same
/// fail-closed [`JsonlWriter::observation`] gate as scripted
/// sessions (test-only `Synthetic` results refuse, never stamp).
/// Native op/algorithm names come from the payload (`op` /
/// `algorithm` keys); shapes without them (totals, who) report
/// `unknown` rather than inventing names. `interrupted` (4B-M5: a
/// SIGINT-cut window) forces `PARTIAL` even when every measured
/// dimension held.
pub fn render_live_jsonl(
    observations: &[NativeObservation],
    coverage: &CoverageSummary,
    interrupted: bool,
) -> Result<String, ReportError> {
    let mut writer = JsonlWriter::new(LIVE_SESSION_ID);
    writer.session_start(&SessionStart {
        target_selector: TargetSelector::System,
        capture_mode: CaptureMode::Trace,
        requested_backends: vec![BackendId::KCrypto],
        qualification_id: LIVE_QUALIFICATION_ID.to_owned(),
    })?;
    for obs in observations {
        let payload = &obs.backend_payload;
        writer.observation(
            obs,
            &ObservationExtra {
                boundary: "kernel_completion".to_owned(),
                native_operation: payload
                    .get(K::OP)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                algorithm_native: payload
                    .get(K::ALGORITHM)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                algorithm_canonical: None,
                algorithm_resolution: "unknown".to_owned(),
            },
        )?;
    }
    let verdict = if !interrupted && trailer_dims(coverage).is_empty() {
        SessionVerdict::Observed
    } else {
        SessionVerdict::Partial
    };
    writer.session_end(&SessionEnd {
        verdict,
        final_barrier: FinalBarrier::Validated,
        unresolved_gap_ids: Vec::new(),
        child_exit_code: None,
        child_signal: None,
    })?;
    Ok(writer.into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1A-L14: derived field order must match the old tuple order —
    /// `result` sorts before `algorithm` (tuple positions 3 < 4),
    /// `kh` before `tgid`.
    #[test]
    fn key_order_matches_tuple_order() {
        let base = RowKey {
            family: "f",
            op: "o",
            result: "r",
            algorithm: "a",
            driver: "d",
            context: "c",
        };
        let earlier_result = RowKey {
            result: "0",
            algorithm: "zzz",
            ..base
        };
        assert!(earlier_result < base);
        let earlier_family = RowKey {
            family: "0",
            ..base
        };
        assert!(earlier_family < earlier_result);
        assert_eq!(base, base);
        assert!(WhoKey { kh: 1, tgid: 9 } < WhoKey { kh: 2, tgid: 0 });
        assert!(WhoKey { kh: 1, tgid: 1 } < WhoKey { kh: 1, tgid: 2 });
    }
}
