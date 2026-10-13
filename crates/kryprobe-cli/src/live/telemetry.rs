// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure live-telemetry leaf formatters (ARCH02/I04).
//!
//! Explicit-input string builders only: no clock reads, no
//! emission, no outcome state, no capture/stop control, no profile
//! state machines (all retained in [`super`]). Every function here
//! is reexported through `live` with an unchanged signature, so
//! `live::telemetry_*` paths and output bytes are stable.

use super::SessionStop;
use kryprobe_privilege::kcrypto_backend::MissTerminal;
use kryprobe_privilege::kcrypto_lifecycle::sensor::EnrichmentStatus;
use kryprobe_privilege::kcrypto_snapshot::{AggOccupancy, CtxTerminal};

/// Render one count for the occupancy line (`None` → `null`).
fn count_json(count: Option<u64>) -> String {
    count.map_or("null".to_owned(), |n| n.to_string())
}

/// JSON-mode audit line for the privileged object load (4B-M4): the
/// staged object path plus its sha256. Pure over inputs for tests;
/// the shape is documented in `docs/json.md`.
pub(crate) fn audit_object_line(path: &str, sha256: &str) -> String {
    serde_json::json!({"audit": "object-load", "path": path, "sha256": sha256}).to_string()
}

/// JSON-mode audit line for the attach outcome (4B-M4): attached vs
/// expected probe points. Pure over inputs for tests.
pub(crate) fn audit_attach_line(attached: usize, expected: usize) -> String {
    serde_json::json!({"audit": "attach", "attached": attached, "expected": expected}).to_string()
}

/// R1 machine-readable telemetry line bodies (stderr
/// `kryprobe: telemetry {...}`). The harness folds these into
/// per-leg observer metrics (drain lag, stop spans, occupancy).
/// SEPARATE from the human-only progress line (which stays
/// unscripted by contract). Shapes twinned with
/// `scripts/kcrypto_perf/parsers.py::parse_telemetry` (v1).
pub fn telemetry_tick_line(tick: u64, lagmax_us: Option<u64>) -> String {
    match lagmax_us {
        Some(us) => format!("kryprobe: telemetry {{\"v\":1,\"tick\":{tick},\"lagmax_us\":{us}}}"),
        None => format!("kryprobe: telemetry {{\"v\":1,\"tick\":{tick},\"lagmax_us\":null}}"),
    }
}

/// R1 occupancy telemetry line (agg profile). Shape twinned with
/// the Python `parse_telemetry` consumer (v1).
pub fn telemetry_occupancy_line(occ: &AggOccupancy) -> String {
    format!(
        "kryprobe: telemetry {{\"v\":1,\"occupancy\":{{\"kagg\":{},\"ktot\":{},\"kidn\":{},\"kring_pending\":{},\"kwho\":{},\"kstack\":{},\"kerr\":{},\"kparams\":{},\"kdrops_slots\":{},\"kctx\":{}}}}}",
        count_json(occ.kagg),
        count_json(occ.ktot),
        count_json(occ.kidn),
        count_json(occ.kring_pending),
        count_json(occ.kwho),
        count_json(occ.kstack),
        count_json(occ.kerr),
        count_json(occ.kparams),
        count_json(occ.kdrops_slots),
        count_json(occ.kctx),
    )
}

/// M1 terminal ctx telemetry line (agg profile): the unknown-
/// by-difference operands from one consistent post-fence read (rows,
/// present/system/unknown calls, exact drops). The frozen
/// `parse_telemetry` consumer ignores the `ctx` object (no lag/stop/
/// occupancy keys — counted as a line, never malformed); the M1 judge
/// parses it fail-closed (absence invalidates the leg).
pub fn telemetry_ctx_line(ctx: &CtxTerminal) -> String {
    format!(
        "kryprobe: telemetry {{\"v\":1,\"ctx\":{{\"rows\":{},\"present_calls\":{},\"system_calls\":{},\"unknown_calls\":{},\"drops\":{}}}}}",
        count_json(ctx.rows),
        count_json(ctx.present_calls),
        count_json(ctx.system_calls),
        count_json(ctx.unknown_calls),
        count_json(ctx.drops),
    )
}

/// M1 terminal miss telemetry line (finding C4): aggregate guard
/// skips across attached programs. `run_delta` sums only when EVERY
/// program qualified (statistics at both endpoints) — any
/// stats-gated program nulls the aggregate rather than zero-filling
/// it. Per-program detail (stable section/program-ID join,
/// per-operation qualification, unavailable reasons) rides the
/// workload report section, never this line; global misses are never
/// assigned to individual contexts. Shape twinned with the Python
/// `parse_telemetry` consumer (v1): the `misses` object is
/// counted-as-a-line, never malformed.
pub fn telemetry_miss_line(misses: &MissTerminal) -> String {
    match misses {
        MissTerminal::Available(deltas) => {
            let miss_delta: u64 = deltas
                .iter()
                .fold(0u64, |acc, delta| acc.saturating_add(delta.miss_delta));
            let mut run_delta: Option<u64> = Some(0);
            for delta in deltas {
                match (run_delta, delta.run_delta) {
                    (Some(acc), Some(run)) => run_delta = Some(acc.saturating_add(run)),
                    _ => {
                        run_delta = None;
                        break;
                    }
                }
            }
            format!(
                "kryprobe: telemetry {{\"v\":1,\"misses\":{{\"programs\":{},\"miss_delta\":{},\"run_delta\":{}}}}}",
                deltas.len(),
                miss_delta,
                count_json(run_delta),
            )
        }
        MissTerminal::Unavailable { .. } => {
            "kryprobe: telemetry {\"v\":1,\"misses\":{\"unavailable\":true}}".to_owned()
        }
    }
}

/// R1 occupancy telemetry line (lifecycle profile). Cumulative
/// ledger equation + close backlog bytes (the ring drained at
/// close, so close-state record counts would read zero — the
/// ledger carries the state evidence instead). Shape twinned with
/// the Python `parse_telemetry` consumer (v1).
/// R1 detail occupancy line. Reducer equation: `admitted ==
/// emitted + live` with `live ≈ 0` at close (`finish` drains
/// pending truthless stop-the-world); `unfinished ⊆ emitted`
/// (truthless-drained subset, never double-counted against
/// `admitted`). `backlog_bytes` is the close backpressure residue.
pub fn telemetry_detail_occupancy_line(
    admitted: u64,
    emitted: u64,
    unfinished: u64,
    backlog_bytes: u64,
) -> String {
    format!(
        "kryprobe: telemetry {{\"v\":1,\"occupancy\":{{\"admitted\":{admitted},\"emitted\":{emitted},\"unfinished\":{unfinished},\"backlog_bytes\":{backlog_bytes}}}}}"
    )
}

/// R1 stop telemetry line. `session` carries the in-session spans
/// (finish/finalize/assemble); `render_us` covers render + write;
/// `total_us` spans session end → report written. Shape twinned
/// with the Python `parse_telemetry` consumer (v1).
pub fn telemetry_stop_line(total_us: u64, session: Option<&SessionStop>, render_us: u64) -> String {
    let (finish, finalize, assemble) = session.map_or(
        ("null".to_owned(), "null".to_owned(), "null".to_owned()),
        |spans| {
            (
                spans.finish_us.to_string(),
                spans.finalize_us.to_string(),
                spans.assemble_us.to_string(),
            )
        },
    );
    format!(
        "kryprobe: telemetry {{\"v\":1,\"stop\":{{\"total_us\":{total_us},\"finish_us\":{finish},\"finalize_us\":{finalize},\"assemble_us\":{assemble},\"render_us\":{render_us}}}}}"
    )
}

/// One human-report trailer line for the enrichment verdict
/// (T07-R2-09: shared by `watch` and `report --system` human —
/// the ledger's available/unavailable verdict is user-visible;
/// profiles that never snapshot say so, never stay silent).
#[must_use]
pub fn render_enrichment_line(enrichment: &Option<EnrichmentStatus>) -> String {
    match enrichment {
        Some(EnrichmentStatus::Available { entries, truncated }) => {
            format!("enrichment: available (entries={entries}, truncated={truncated})\n")
        }
        Some(EnrichmentStatus::Unavailable { reason }) => {
            format!("enrichment: unavailable (reason: {reason})\n")
        }
        None => "enrichment: not attempted (profile snapshots no registry)\n".to_owned(),
    }
}
