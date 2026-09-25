// SPDX-License-Identifier: GPL-3.0-or-later
//! VM canary oracle (T06): strict fixture-transcript parse + exact
//! verdict rules (pure — the `lifecycle_canary` bin is the IO shell
//! that brings up the sensor, drives the fixture, and writes files).
//!
//! The oracle joins INDEPENDENT evidence: the fixture ledger (what the
//! kernel module did, per sequence number) against the sensor ledger
//! (what the BPF sensor observed). Every refusal names its reason;
//! nothing parses leniently, nothing compares loosely:
//!
//! - Transcript rows are strict: unknown phases/ops, duplicate
//!   sequence numbers, and malformed fields FAIL the run (a skipped
//!   row could hide the exact traffic the verdict must see).
//! - Terminals join PAIRWISE by index (fixture sequential ⇒ return
//!   order == op order): each sensor terminal status must EQUAL the
//!   fixture errno. `Unknown` terminals fail sync scenarios.
//! - `async-once` expects the pending shape T06 can actually observe
//!   (submit + queued return, completion invisible until T09): one
//!   post-finish `Unknown` record + `unfinished == 1`.
//! - The reconciliation equation must hold exactly over deltas:
//!   `agg == hits + reserve + noslot` (post-quiet, empty close ring).
//! - Every loss counter must read zero; any close backlog fails.

use crate::kcrypto_lifecycle::decode::DecodeStats;
use kryprobe_core::kcrypto::{ReducerStats, RequestRecord, Terminal};

/// One fixture op (sequence order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureOp {
    /// Sequence number (unique per run among submits).
    pub seq: u64,
    /// `encrypt` or `decrypt`.
    pub op: String,
}

/// Fixture ground truth: parsed transcript (strict — see
/// [`parse_transcript`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureTruth {
    /// Submits in sequence order.
    pub ops: Vec<FixtureOp>,
    /// `(seq, errno)` return rows in row order.
    pub returns: Vec<(u64, i32)>,
    /// `(seq, errno)` terminal (callback) rows in row order.
    pub terminals: Vec<(u64, i32)>,
    /// Fixture self-check result (must be 0).
    pub fixture_result: i32,
    /// Fixture self-check overflow (must be 0).
    pub fixture_overflow: u64,
}

/// Strict transcript failure: line number + static reason (no
/// untrusted bytes interpolated — validator idiom).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptError {
    /// 1-based line number (0 = whole-file shape).
    pub line: usize,
    /// Static reason (never echoes the offending bytes).
    pub reason: &'static str,
}

impl std::fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transcript line {}: {}", self.line, self.reason)
    }
}

/// Extract `"key":value` (number) following a marker, or `None`
/// (the fixture JSON shapes are fixed by the fixture C source —
/// marker scans, never a JSON parser dependency in the oracle).
fn num_after(row: &str, marker: &str) -> Option<i64> {
    let at = row.find(marker)? + marker.len();
    let rest = &row[at..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse::<i64>().ok()
}

/// Extract `"key":"str"` following a marker, or `None`.
fn str_after(row: &str, marker: &str) -> Option<String> {
    let at = row.find(marker)? + marker.len();
    let rest = &row[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Parse a fixture transcript STRICTLY: JSON lines with
/// `"run":"{run_id}"`, phases `alloc`/`submit`/`return`/`terminal`/
/// `free`/`done`. Rows for other runs are out of scope (skipped);
/// a row FOR this run with an unknown phase/op, a malformed field,
/// a duplicate submit seq, a return/terminal for an unknown seq, a
/// duplicate `done`, a missing `done`, or zero submits is a
/// [`TranscriptError`] (fail the run — never skip-and-pass).
pub fn parse_transcript(text: &str, run_id: &str) -> Result<FixtureTruth, TranscriptError> {
    let run_mark = format!("\"run\":\"{run_id}\"");
    let mut ops: Vec<FixtureOp> = Vec::new();
    let mut returns: Vec<(u64, i32)> = Vec::new();
    let mut terminals: Vec<(u64, i32)> = Vec::new();
    let mut done: Option<(i32, u64)> = None;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || !line.contains(&run_mark) {
            continue;
        }
        let phase = str_after(line, "\"phase\":\"").ok_or(TranscriptError {
            line: line_no,
            reason: "row has no phase field",
        })?;
        match phase.as_str() {
            // Lifecycle rows: known, not oracle evidence.
            "alloc" | "free" => {}
            "submit" => {
                let seq = num_after(line, "\"seq\":")
                    .and_then(|n| u64::try_from(n).ok())
                    .ok_or(TranscriptError {
                        line: line_no,
                        reason: "submit row lacks a sequence",
                    })?;
                let op = str_after(line, "\"op\":\"").ok_or(TranscriptError {
                    line: line_no,
                    reason: "submit row lacks an op",
                })?;
                if op != "encrypt" && op != "decrypt" {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "unknown op name",
                    });
                }
                if ops.iter().any(|o: &FixtureOp| o.seq == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "duplicate submit sequence",
                    });
                }
                ops.push(FixtureOp { seq, op });
            }
            "return" => {
                let (seq, errno) = seq_errno(line, line_no, "return")?;
                if !ops.iter().any(|o: &FixtureOp| o.seq == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "return for an unknown sequence",
                    });
                }
                returns.push((seq, errno));
            }
            "terminal" => {
                let (seq, errno) = seq_errno(line, line_no, "terminal")?;
                if !ops.iter().any(|o: &FixtureOp| o.seq == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "terminal for an unknown sequence",
                    });
                }
                terminals.push((seq, errno));
            }
            "done" => {
                if done.is_some() {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "duplicate done row",
                    });
                }
                let result = num_after(line, "\"fixture_result\":")
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or(TranscriptError {
                        line: line_no,
                        reason: "done row lacks a result",
                    })?;
                let overflow = num_after(line, "\"overflow\":")
                    .and_then(|n| u64::try_from(n).ok())
                    .ok_or(TranscriptError {
                        line: line_no,
                        reason: "done row lacks an overflow",
                    })?;
                done = Some((result, overflow));
            }
            _ => {
                return Err(TranscriptError {
                    line: line_no,
                    reason: "unknown phase",
                });
            }
        }
    }
    let (fixture_result, fixture_overflow) = done.ok_or(TranscriptError {
        line: 0,
        reason: "transcript has no done row",
    })?;
    if ops.is_empty() {
        return Err(TranscriptError {
            line: 0,
            reason: "transcript ran zero ops (no positive control)",
        });
    }
    ops.sort_by_key(|op| op.seq);
    Ok(FixtureTruth {
        ops,
        returns,
        terminals,
        fixture_result,
        fixture_overflow,
    })
}

/// `seq` + `errno` from a return/terminal row (strict pair).
fn seq_errno(line: &str, line_no: usize, what: &str) -> Result<(u64, i32), TranscriptError> {
    let seq = num_after(line, "\"seq\":")
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(TranscriptError {
            line: line_no,
            reason: if what == "return" {
                "return row lacks a sequence"
            } else {
                "terminal row lacks a sequence"
            },
        })?;
    let errno = num_after(line, "\"errno\":")
        .and_then(|n| i32::try_from(n).ok())
        .ok_or(TranscriptError {
            line: line_no,
            reason: if what == "return" {
                "return row lacks an errno"
            } else {
                "terminal row lacks an errno"
            },
        })?;
    Ok((seq, errno))
}

/// Sensor counters at one instant (baselines + final read share it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SensorBaseline {
    /// Per-hook consumed edges `[enc-sub, enc-ret, dec-sub, dec-ret]`.
    pub edge_hits: [u64; 4],
    /// `LLOSS` per-class totals (5 classes).
    pub kernel_loss: [u64; 5],
    /// `LAGG` per-hook accepted totals.
    pub agg_accepted: [u64; 4],
    /// Retained completions surfaced so far.
    pub completed_len: u64,
    /// Decoder counters (quiescence + delta verdict; robust to
    /// pre-clear traffic between bring-up and baseline).
    pub decode: DecodeStats,
    /// Reducer counters (same rationale).
    pub reducer: ReducerStats,
    /// Retention drops past the ledger bound.
    pub retained_dropped: u64,
}

/// Sensor evidence for one scenario (post-finish: completions include
/// the `finish` reconciliation; counters are the final ledger).
#[derive(Debug)]
pub struct SensorView<'a> {
    /// Post-finish completions (every pending request reconciled).
    pub completed: &'a [RequestRecord],
    /// Final per-hook consumed edges.
    pub edge_hits: [u64; 4],
    /// Final decode counters.
    pub decode: DecodeStats,
    /// Final reducer counters.
    pub reducer: ReducerStats,
    /// Final kernel loss.
    pub kernel_loss: [u64; 5],
    /// Final accepted aggregate.
    pub agg_accepted: [u64; 4],
    /// Retention drops past the ledger bound.
    pub retained_dropped: u64,
    /// Quiescence-proven pre-GO baseline (deltas measure from here).
    pub baseline: SensorBaseline,
    /// Quiet-verdict close backlog in ring bytes (must be 0).
    pub quiet_backlog_bytes: u64,
}

/// Exact verdict over one scenario: `Ok(())` passes, `Err(reason)`
/// fails with the named mismatch. Counter deltas use checked
/// subtraction — a counter that ran BACKWARDS fails (reset images
/// are not silently absorbed).
pub fn verdict(scenario: &str, truth: &FixtureTruth, view: &SensorView<'_>) -> Result<(), String> {
    if truth.fixture_result != 0 {
        return Err(format!(
            "fixture self-check failed (result {})",
            truth.fixture_result
        ));
    }
    if truth.fixture_overflow != 0 {
        return Err(format!(
            "fixture overflowed (overflow {})",
            truth.fixture_overflow
        ));
    }
    if view.quiet_backlog_bytes != 0 {
        return Err(format!(
            "close backlog {} bytes (teardown loss)",
            view.quiet_backlog_bytes
        ));
    }
    let sub = |a: u64, b: u64, what: &str| -> Result<u64, String> {
        a.checked_sub(b)
            .ok_or_else(|| format!("counter {what} ran backwards"))
    };
    let mut hits_d = [0u64; 4];
    let mut loss_d = [0u64; 5];
    let mut agg_d = [0u64; 4];
    for i in 0..4 {
        hits_d[i] = sub(view.edge_hits[i], view.baseline.edge_hits[i], "edge_hits")?;
        agg_d[i] = sub(
            view.agg_accepted[i],
            view.baseline.agg_accepted[i],
            "agg_accepted",
        )?;
    }
    for (i, slot) in loss_d.iter_mut().enumerate() {
        *slot = sub(
            view.kernel_loss[i],
            view.baseline.kernel_loss[i],
            "kernel_loss",
        )?;
    }
    // Reconciliation equation over deltas (post-quiet, empty close
    // ring): accepted == consumed + reserve-dropped + noslot-dropped.
    let (agg_sum, hits_sum): (u64, u64) = (
        agg_d.iter().fold(0, |s, a| s.saturating_add(*a)),
        hits_d.iter().fold(0, |s, h| s.saturating_add(*h)),
    );
    if agg_sum != hits_sum + loss_d[0] + loss_d[4] {
        return Err(format!(
            "reconciliation broke (agg {agg_sum} != hits {hits_sum} + reserve {} + noslot {})",
            loss_d[0], loss_d[4]
        ));
    }
    // Every loss counter delta reads zero (checked deltas —
    // pre-clear traffic between bring-up and baseline cannot fake
    // a pass or a fail).
    let losses = [
        (
            "submit_refused",
            sub(
                view.decode.submit_refused,
                view.baseline.decode.submit_refused,
                "submit_refused",
            )?,
        ),
        (
            "unknown_key_returns",
            sub(
                view.decode.unknown_key_returns,
                view.baseline.decode.unknown_key_returns,
                "unknown_key_returns",
            )?,
        ),
        (
            "bad_records",
            sub(
                view.decode.bad_records,
                view.baseline.decode.bad_records,
                "bad_records",
            )?,
        ),
        (
            "gaps_synthesized",
            sub(
                view.decode.gaps_synthesized,
                view.baseline.decode.gaps_synthesized,
                "gaps_synthesized",
            )?,
        ),
        (
            "stale_returns",
            sub(
                view.decode.stale_returns,
                view.baseline.decode.stale_returns,
                "stale_returns",
            )?,
        ),
        (
            "orphan",
            sub(view.reducer.orphan, view.baseline.reducer.orphan, "orphan")?,
        ),
        (
            "duplicate",
            sub(
                view.reducer.duplicate,
                view.baseline.reducer.duplicate,
                "duplicate",
            )?,
        ),
        (
            "ambiguous",
            sub(
                view.reducer.ambiguous,
                view.baseline.reducer.ambiguous,
                "ambiguous",
            )?,
        ),
        (
            "admission_failed",
            sub(
                view.reducer.admission_failed,
                view.baseline.reducer.admission_failed,
                "admission_failed",
            )?,
        ),
        (
            "retained_dropped",
            sub(
                view.retained_dropped,
                view.baseline.retained_dropped,
                "retained_dropped",
            )?,
        ),
    ];
    for (name, value) in losses {
        if value != 0 {
            return Err(format!("loss counter {name} delta reads {value}"));
        }
    }
    for (i, loss) in loss_d.iter().enumerate() {
        if *loss != 0 {
            return Err(format!("kernel_loss[{i}] reads {loss}"));
        }
    }
    // Per-hook expectations + terminal join per scenario.
    let expected_hits: [u64; 4] = match scenario {
        "sync-once" => [1, 1, 1, 1],
        "async-once" => [1, 1, 0, 0],
        _ => return Err(format!("unknown scenario {scenario}")),
    };
    if hits_d != expected_hits {
        return Err(format!(
            "edge hits {hits_d:?} != expected {expected_hits:?}"
        ));
    }
    let admitted_d = sub(
        view.decode.admitted,
        view.baseline.decode.admitted,
        "decode.admitted",
    )?;
    if admitted_d != truth.ops.len() as u64 {
        return Err(format!(
            "admitted delta {admitted_d} != {} ops",
            truth.ops.len()
        ));
    }
    // Admission lockstep: one reducer id per decoded submit, and
    // post-finish every admitted id emitted (`admitted == emitted +
    // live` with live drained by `finish`).
    let reducer_admitted_d = sub(
        view.reducer.admitted,
        view.baseline.reducer.admitted,
        "reducer.admitted",
    )?;
    if reducer_admitted_d != admitted_d {
        return Err(format!(
            "reducer admitted delta {reducer_admitted_d} != decode admitted delta {admitted_d}"
        ));
    }
    let emitted_d = sub(
        view.reducer.emitted,
        view.baseline.reducer.emitted,
        "reducer.emitted",
    )?;
    if emitted_d != admitted_d {
        return Err(format!(
            "emitted delta {emitted_d} != admitted delta {admitted_d}"
        ));
    }
    let unfinished_d = sub(
        view.reducer.unfinished,
        view.baseline.reducer.unfinished,
        "reducer.unfinished",
    )?;
    match scenario {
        "sync-once" => {
            if view.completed.len() != truth.ops.len() {
                return Err(format!(
                    "completed {} != {} ops",
                    view.completed.len(),
                    truth.ops.len()
                ));
            }
            if unfinished_d != 0 {
                return Err(format!("unfinished delta {unfinished_d}"));
            }
            // Exact return join: one return row per op, in submit
            // order (the fixture is sequential — any reorder fails).
            let op_seqs: Vec<u64> = truth.ops.iter().map(|op| op.seq).collect();
            let ret_seqs: Vec<u64> = truth.returns.iter().map(|(seq, _)| *seq).collect();
            if ret_seqs != op_seqs {
                return Err(format!(
                    "fixture return seqs {ret_seqs:?} != submit seqs {op_seqs:?}"
                ));
            }
            // Pairwise terminal join by index: grounded kind + EXACT
            // errno + observed duration per completion.
            for (i, record) in view.completed.iter().enumerate() {
                let (seq, errno) = truth.returns[i];
                let status = match record.terminal {
                    Terminal::Sync(status) | Terminal::Callback(status) => status,
                    Terminal::Unknown => {
                        return Err(format!("completion {i} (seq {seq}) has Unknown terminal"));
                    }
                };
                if status != errno {
                    return Err(format!(
                        "completion {i} (seq {seq}) status {status} != fixture errno {errno}"
                    ));
                }
                if record.duration_ns.is_none() {
                    return Err(format!("completion {i} (seq {seq}) lacks a duration"));
                }
            }
        }
        "async-once" => {
            // The pending shape T06 can observe: submit + queued
            // return, completion invisible until T09 — post-finish
            // the request truthless-drains as one `Unknown` record.
            if truth.ops.len() != 1 {
                return Err(format!(
                    "async-once runs 1 op, fixture ran {}",
                    truth.ops.len()
                ));
            }
            // Positive controls: the fixture queued exactly once
            // (`-EINPROGRESS`, kernel UAPI) AND observed async
            // completion (errno 0) — the sensor legitimately sees
            // neither the queue code's meaning nor the callback.
            if truth.returns.as_slice() != [(truth.ops[0].seq, -115)] {
                return Err(format!(
                    "async fixture returns {:?} != [(seq, -EINPROGRESS)]",
                    truth.returns
                ));
            }
            if truth.terminals.len() != 1 || truth.terminals[0].1 != 0 {
                return Err(
                    "async fixture shows no clean terminal row (scenario did not complete)"
                        .to_owned(),
                );
            }
            if view.completed.len() != 1 {
                return Err(format!(
                    "async post-finish completed {} != 1",
                    view.completed.len()
                ));
            }
            if view.completed[0].terminal != Terminal::Unknown {
                return Err(format!(
                    "async post-finish terminal {:?} != Unknown (unexpected sync completion)",
                    view.completed[0].terminal
                ));
            }
            if unfinished_d != 1 {
                return Err(format!(
                    "async unfinished delta {unfinished_d} != 1 (expected-pending)"
                ));
            }
        }
        _ => unreachable!("scenario matched above"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real sync transcript shape (alloc/submit/return/terminal/free/done).
    fn sync_text() -> String {
        let run = "run-sync-once";
        [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"decrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free"}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n")
    }

    fn sync_truth() -> FixtureTruth {
        parse_transcript(&sync_text(), "run-sync-once").expect("valid sync transcript")
    }

    fn sync_view(completed: &[RequestRecord]) -> SensorView<'_> {
        SensorView {
            completed,
            edge_hits: [1, 1, 1, 1],
            decode: DecodeStats {
                admitted: 2,
                ..DecodeStats::default()
            },
            reducer: ReducerStats {
                admitted: 2,
                emitted: 2,
                ..ReducerStats::default()
            },
            kernel_loss: [0; 5],
            agg_accepted: [1, 1, 1, 1],
            retained_dropped: 0,
            baseline: SensorBaseline::default(),
            quiet_backlog_bytes: 0,
        }
    }

    fn record(id: u64, terminal: Terminal) -> RequestRecord {
        RequestRecord {
            id,
            tfm_id: None,
            terminal,
            duration_ns: Some(100),
        }
    }

    #[test]
    fn parse_accepts_valid_transcript() {
        let truth = sync_truth();
        assert_eq!(truth.ops.len(), 2);
        assert_eq!(truth.returns, vec![(2, 0), (3, 0)]);
        assert_eq!(truth.terminals, vec![(2, 0), (3, 0)]);
        assert_eq!(truth.fixture_result, 0);
    }

    #[test]
    fn parse_ignores_foreign_runs_but_fails_own_malformed_rows() {
        // Foreign rows are out of scope; own malformed rows fail.
        let mut text = String::from("{\"v\":1,\"run\":\"other\",\"seq\":9,\"phase\":\"bogus\"}\n");
        text.push_str(&sync_text());
        parse_transcript(&text, "run-sync-once").expect("foreign rows skipped");
        let bad_shapes = [
            // Unknown phase on an own row.
            sync_text().replace("\"phase\":\"free\"", "\"phase\":\"frobnicate\""),
            // Unknown op.
            sync_text().replacen("\"op\":\"encrypt\"", "\"op\":\"hash\"", 1),
            // Duplicate submit seq.
            sync_text().replacen("\"seq\":3,\"phase\":\"submit\"", "\"seq\":2,\"phase\":\"submit\"", 1),
            // Return for an unknown seq.
            sync_text().replacen("\"seq\":2,\"phase\":\"return\"", "\"seq\":7,\"phase\":\"return\"", 1),
            // Malformed errno.
            sync_text().replacen("\"errno\":0", "\"errno\":\"NaN\"", 1),
            // Missing done.
            sync_text().replace("{\"v\":1,\"run\":\"run-sync-once\",\"phase\":\"done\",\"fixture_result\":0,\"overflow\":0}", ""),
        ];
        for (i, bad) in bad_shapes.iter().enumerate() {
            assert!(
                parse_transcript(bad, "run-sync-once").is_err(),
                "shape {i} must reject"
            );
        }
        // Zero submits: done-only transcript.
        let done_only =
            "{\"v\":1,\"run\":\"r\",\"phase\":\"done\",\"fixture_result\":0,\"overflow\":0}\n";
        assert!(parse_transcript(done_only, "r").is_err());
    }

    #[test]
    fn verdict_sync_green() {
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        verdict("sync-once", &truth, &sync_view(&completed)).expect("sync green");
    }

    #[test]
    fn verdict_sync_status_mismatch_fails() {
        // The independence gap round-2 closed: a wrong errno fails
        // even when every count matches.
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(-5)), record(2, Terminal::Sync(0))];
        let err =
            verdict("sync-once", &truth, &sync_view(&completed)).expect_err("status must join");
        assert!(err.contains("status -5"), "names the mismatch: {err}");
    }

    #[test]
    fn verdict_sync_unknown_terminal_fails() {
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Unknown)];
        verdict("sync-once", &truth, &sync_view(&completed)).expect_err("Unknown must fail sync");
    }

    #[test]
    fn verdict_async_expects_pending() {
        let run = "run-async-once";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free"}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("valid async transcript");
        let completed = [record(1, Terminal::Unknown)];
        let mut view = sync_view(&completed);
        view.edge_hits = [1, 1, 0, 0];
        view.agg_accepted = [1, 1, 0, 0];
        view.decode.admitted = 1;
        view.reducer.admitted = 1;
        view.reducer.emitted = 1;
        view.reducer.unfinished = 1;
        verdict("async-once", &truth, &view).expect("async pending green");
        // A grounded async completion fails: the scenario did not
        // produce the async shape it exists to prove.
        let completed = [record(1, Terminal::Sync(0))];
        let mut view = sync_view(&completed);
        view.edge_hits = [1, 1, 0, 0];
        view.agg_accepted = [1, 1, 0, 0];
        view.decode.admitted = 1;
        view.reducer.admitted = 1;
        view.reducer.emitted = 1;
        view.reducer.unfinished = 0;
        verdict("async-once", &truth, &view).expect_err("grounded async must fail");
    }

    #[test]
    fn verdict_equation_and_loss_fail_loud() {
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        // Equation: agg 5 != hits 4 + reserve 0 + noslot 0.
        let mut view = sync_view(&completed);
        view.agg_accepted = [2, 1, 1, 1];
        let err = verdict("sync-once", &truth, &view).expect_err("equation must hold");
        assert!(err.contains("reconciliation"), "names it: {err}");
        // Any loss counter fails.
        let mut view = sync_view(&completed);
        view.decode.stale_returns = 1;
        verdict("sync-once", &truth, &view).expect_err("stale must fail");
        let mut view = sync_view(&completed);
        view.kernel_loss[2] = 1;
        verdict("sync-once", &truth, &view).expect_err("badkey must fail");
        // Close backlog fails.
        let mut view = sync_view(&completed);
        view.quiet_backlog_bytes = 40;
        verdict("sync-once", &truth, &view).expect_err("backlog must fail");
        // Backwards counters fail (no silent reset absorb).
        let mut view = sync_view(&completed);
        view.baseline.edge_hits = [9, 9, 9, 9];
        verdict("sync-once", &truth, &view).expect_err("backwards must fail");
        // Fixture self-check failure fails.
        let mut truth = sync_truth();
        truth.fixture_result = -1;
        verdict("sync-once", &truth, &sync_view(&completed)).expect_err("fixture fail must fail");
    }

    #[test]
    fn verdict_tolerates_preclear_traffic_but_not_scenario_loss() {
        // Bring-up traffic between sensor creation and baseline
        // (clear-drained, counted in lifetime stats) must neither
        // fake a pass nor a fail: the verdict joins deltas.
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let mut view = sync_view(&completed);
        view.baseline.edge_hits = [5, 5, 5, 5];
        view.baseline.agg_accepted = [5, 5, 5, 5];
        view.baseline.decode.admitted = 7;
        view.baseline.reducer.admitted = 7;
        view.baseline.reducer.emitted = 7;
        view.edge_hits = [6, 6, 6, 6];
        view.agg_accepted = [6, 6, 6, 6];
        view.decode.admitted = 9;
        view.reducer.admitted = 9;
        view.reducer.emitted = 9;
        verdict("sync-once", &truth, &view).expect("pre-clear traffic tolerated");
        // ...but a loss inside the scenario window still fails even
        // with a dirty baseline.
        let mut view = sync_view(&completed);
        view.baseline.decode.stale_returns = 3;
        view.decode.stale_returns = 4;
        let err = verdict("sync-once", &truth, &view).expect_err("scenario loss must fail");
        assert!(err.contains("stale_returns"), "names it: {err}");
    }
}
