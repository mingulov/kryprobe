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
use crate::kcrypto_lifecycle::view::ProgMisses;
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

impl FixtureTruth {
    /// Fixture-derived per-hook expectations
    /// `[enc_sub, enc_ret, dec_sub, dec_ret]` : submits counted from
    /// submit rows by op, returns counted from return rows joined to
    /// their submit's op. The verdict compares sensor deltas against
    /// THIS (ledger data), never scenario-name constants — a fixture
    /// running two encrypts must fail against a 1+1 sensor view.
    #[must_use]
    pub fn expected_hooks(&self) -> [u64; 4] {
        let mut hooks = [0u64; 4];
        for op in &self.ops {
            let (submit_lane, return_lane) = if op.op == "encrypt" { (0, 1) } else { (2, 3) };
            hooks[submit_lane] = hooks[submit_lane].saturating_add(1);
            let returns = self
                .returns
                .iter()
                .filter(|(seq, _)| *seq == op.seq)
                .count() as u64;
            hooks[return_lane] = hooks[return_lane].saturating_add(returns);
        }
        hooks
    }
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

/// Strict field readers over a parsed row: exact JSON types only
/// (a float `0.5` is not an errno; a numeric prefix scan would
/// misread it as `0`). Reasons are input-free (key + expectation,
/// never the offered value).
fn get_u64(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    line_no: usize,
    what: &'static str,
) -> Result<u64, TranscriptError> {
    obj.get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or(TranscriptError {
            line: line_no,
            reason: what,
        })
}

fn get_i32(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    line_no: usize,
    what: &'static str,
) -> Result<i32, TranscriptError> {
    obj.get(key)
        .and_then(|v| v.as_i64())
        .and_then(|n| i32::try_from(n).ok())
        .ok_or(TranscriptError {
            line: line_no,
            reason: what,
        })
}

fn get_str<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    line_no: usize,
    what: &'static str,
) -> Result<&'a str, TranscriptError> {
    obj.get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or(TranscriptError {
            line: line_no,
            reason: what,
        })
}

fn get_bool(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    line_no: usize,
    what: &'static str,
) -> Result<bool, TranscriptError> {
    obj.get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or(TranscriptError {
            line: line_no,
            reason: what,
        })
}

/// Parse a fixture transcript STRICTLY, as real JSON (fixture.h
/// contract, `"v":1`): every non-empty line must be a JSON object
/// with a string `run`; rows for other runs are out of scope
/// (skipped by EXACT run equality, never substring); rows for this
/// run need known phases, exact-typed required fields (INCLUDING
/// the alloc/free/progress markers — a malformed marker is a broken
/// transcript, not ignorable noise), unique submit/return/terminal
/// seqs (a duplicate evidence row could shadow the verdict's
/// first-match lookup), return/terminal only for submitted seqs,
/// exactly one `done` with nothing after it, and at least one
/// submit with its return AND terminal rows. Anything else is a
/// [`TranscriptError`] (fail the run — never skip-and-pass).
/// Extra keys on own rows are ignored per the fixture contract
/// (every row shape ends `,...}` — extensibility reserved); the
/// `v == 1` pin still fails a format revision loudly.
pub fn parse_transcript(text: &str, run_id: &str) -> Result<FixtureTruth, TranscriptError> {
    let mut ops: Vec<FixtureOp> = Vec::new();
    let mut returns: Vec<(u64, i32)> = Vec::new();
    let mut terminals: Vec<(u64, i32)> = Vec::new();
    let mut done: Option<(i32, u64)> = None;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(line).map_err(|_| TranscriptError {
            line: line_no,
            reason: "line is not a JSON object",
        })?;
        let obj = row.as_object().ok_or(TranscriptError {
            line: line_no,
            reason: "line is not a JSON object",
        })?;
        let run = get_str(obj, "run", line_no, "row lacks a run id")?;
        if run != run_id {
            continue;
        }
        if done.is_some() {
            return Err(TranscriptError {
                line: line_no,
                reason: "row follows done",
            });
        }
        let version = get_u64(obj, "v", line_no, "row lacks a format version")?;
        if version != 1 {
            return Err(TranscriptError {
                line: line_no,
                reason: "unsupported transcript version",
            });
        }
        let phase = get_str(obj, "phase", line_no, "row has no phase field")?;
        match phase {
            // Lifecycle + waiter markers: not oracle evidence, but
            // their REQUIRED fields validate (fixture.h: a malformed
            // marker is a broken transcript — round-4 minor).
            "alloc" => {
                get_u64(obj, "seq", line_no, "alloc row lacks a sequence")?;
                let req = get_str(obj, "req", line_no, "alloc row lacks a req")?;
                let drv = get_str(obj, "drv", line_no, "alloc row lacks a drv")?;
                if req.is_empty() || drv.is_empty() {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "alloc row has an empty req or drv",
                    });
                }
            }
            "free" => {
                get_u64(obj, "seq", line_no, "free row lacks a sequence")?;
                get_bool(obj, "final", line_no, "free row lacks a bool final")?;
            }
            "progress" => {
                get_u64(obj, "seq", line_no, "progress row lacks a sequence")?;
                get_i32(obj, "errno", line_no, "progress row lacks an errno")?;
            }
            "submit" => {
                let seq = get_u64(obj, "seq", line_no, "submit row lacks a sequence")?;
                let op = get_str(obj, "op", line_no, "submit row lacks an op")?;
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
                ops.push(FixtureOp {
                    seq,
                    op: op.to_owned(),
                });
            }
            "return" => {
                let seq = get_u64(obj, "seq", line_no, "return row lacks a sequence")?;
                let errno = get_i32(obj, "errno", line_no, "return row lacks an errno")?;
                if !ops.iter().any(|o: &FixtureOp| o.seq == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "return for an unknown sequence",
                    });
                }
                if returns.iter().any(|(s, _)| *s == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "duplicate return sequence",
                    });
                }
                returns.push((seq, errno));
            }
            "terminal" => {
                let seq = get_u64(obj, "seq", line_no, "terminal row lacks a sequence")?;
                let errno = get_i32(obj, "errno", line_no, "terminal row lacks an errno")?;
                if !ops.iter().any(|o: &FixtureOp| o.seq == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "terminal for an unknown sequence",
                    });
                }
                if terminals.iter().any(|(s, _)| *s == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "duplicate terminal sequence",
                    });
                }
                terminals.push((seq, errno));
            }
            "done" => {
                let result = get_i32(obj, "fixture_result", line_no, "done row lacks a result")?;
                let overflow = get_u64(obj, "overflow", line_no, "done row lacks an overflow")?;
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
    // Fixture.h structural rule: every request needs its return AND
    // terminal rows (a submit without either is a broken scenario,
    // not oracle evidence).
    for op in &ops {
        if !returns.iter().any(|(seq, _)| *seq == op.seq) {
            return Err(TranscriptError {
                line: 0,
                reason: "submit seq lacks a return row",
            });
        }
        if !terminals.iter().any(|(seq, _)| *seq == op.seq) {
            return Err(TranscriptError {
                line: 0,
                reason: "submit seq lacks a terminal row",
            });
        }
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

/// Sensor counters at one instant (baselines + final read share it).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
    /// Per-program recursion-miss absolutes (H2 quiescence + delta
    /// verdict: pre-GO misses are baseline, post-GO misses fail).
    pub prog_misses: Vec<ProgMisses>,
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
    /// M2 sticky identity verdict (must be true: a void identity
    /// voids every exact count in the run).
    pub view_valid: bool,
    /// Attach count while armed (must be exactly 2 — the two
    /// fsession session links, W8; captured pre-close since detach
    /// drops the links before the verdict runs).
    pub attached_links: usize,
    /// Foreign tracing links on our attach targets (must be 0 — H4
    /// retirement exclusion: any foreign link may have retired ours).
    pub foreign_links: u64,
    /// Final per-program recursion-miss absolutes (H2: every
    /// post-baseline delta must read zero — strict all-zero).
    pub prog_misses: Vec<ProgMisses>,
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
    if !view.view_valid {
        return Err("sensor identity unverified (M2 sticky validity void)".to_owned());
    }
    if view.attached_links != 2 {
        return Err(format!(
            "want exactly 2 session links, have {}",
            view.attached_links
        ));
    }
    if view.foreign_links != 0 {
        return Err(format!(
            "foreign tracing links on our targets: {} (H4 retirement exclusion)",
            view.foreign_links
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
    // Reserve/noslot drops are global classes (no per-lane
    // attribution exists), so the lossless case demands EXACT
    // per-lane equality (a permuted aggregate vector must fail) and
    // the lossy case falls back to the totals equation.
    let drops = loss_d[0].saturating_add(loss_d[4]);
    if drops == 0 {
        if agg_d != hits_d {
            return Err(format!(
                "per-lane reconciliation broke (agg {agg_d:?} != hits {hits_d:?})"
            ));
        }
    } else {
        let (agg_sum, hits_sum): (u64, u64) = (
            agg_d.iter().fold(0, |s, a| s.saturating_add(*a)),
            hits_d.iter().fold(0, |s, h| s.saturating_add(*h)),
        );
        if agg_sum != hits_sum.saturating_add(drops) {
            return Err(format!(
                "reconciliation broke (agg {agg_sum} != hits {hits_sum} + reserve {} + noslot {})",
                loss_d[0], loss_d[4]
            ));
        }
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
            "unknown_invoc_returns",
            sub(
                view.decode.unknown_invoc_returns,
                view.baseline.decode.unknown_invoc_returns,
                "unknown_invoc_returns",
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
    // Strict all-zero recursion misses (H2/M2 miss gate): every
    // post-baseline per-program delta must read zero — a wholly
    // skipped call leaves no edge and no LLOSS, so a nonzero miss
    // delta voids the run. Joined by section; a final program with
    // no baseline entry fails closed (unattributed program).
    for got in &view.prog_misses {
        let base = view
            .baseline
            .prog_misses
            .iter()
            .find(|want| want.section == got.section)
            .ok_or_else(|| format!("prog_misses[{}] has no baseline", got.section))?;
        let delta = sub(
            got.misses,
            base.misses,
            &format!("prog_misses[{}]", got.section),
        )?;
        if delta != 0 {
            return Err(format!("prog_misses[{}] delta reads {delta}", got.section));
        }
    }
    // Per-hook expectations come from the LEDGER (fixture-derived),
    // never scenario-name constants: the scenario selects only the
    // oracle SHAPE below (grounding rules vs pending rules). A
    // fixture running two encrypts must fail against a 1+1 view.
    if !matches!(scenario, "sync-once" | "async-once") {
        return Err(format!("unknown scenario {scenario}"));
    }
    let expected_hits = truth.expected_hooks();
    if hits_d != expected_hits {
        return Err(format!(
            "edge hits {hits_d:?} != fixture-derived {expected_hits:?}"
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
            // Terminal reconciliation: every op's callback row must
            // exist with errno EQUAL to its return errno (a missing
            // or conflicting terminal row means the fixture did not
            // run the scenario the sensor is graded against).
            for op in &truth.ops {
                let ret_errno = truth
                    .returns
                    .iter()
                    .find(|(seq, _)| *seq == op.seq)
                    .map(|(_, errno)| *errno);
                let term_errno = truth
                    .terminals
                    .iter()
                    .find(|(seq, _)| *seq == op.seq)
                    .map(|(_, errno)| *errno);
                match (ret_errno, term_errno) {
                    (Some(ret), Some(term)) if ret == term => {}
                    _ => {
                        return Err(format!(
                            "op seq {} return/terminal mismatch (ret {ret_errno:?}, term {term_errno:?})",
                            op.seq
                        ));
                    }
                }
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
            // The callback row must belong to THE op (seq match) and
            // show clean completion (errno 0): the sensor
            // legitimately sees neither, but the scenario must have
            // run to grade the pending shape against.
            if truth.terminals.as_slice() != [(truth.ops[0].seq, 0)] {
                return Err(format!(
                    "async fixture terminals {:?} != [(op seq, 0)]",
                    truth.terminals
                ));
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

/// H4 foreign-link classifier (pure — the privileged enumeration
/// in the canary shell feeds it): a link is foreign when it is a
/// `TRACING` link on one of OUR attach targets with a program id
/// outside OUR program set. Anything else (own links, other link
/// types, other targets) is not ours to exclude.
#[must_use]
pub fn is_foreign_link(
    link_type: u32,
    prog_id: u32,
    target_btf_id: u32,
    own_prog_ids: &[u32],
    target_btf_ids: &[u32],
) -> bool {
    link_type == crate::probe::bpf_sys::BPF_LINK_TYPE_TRACING
        && target_btf_ids.contains(&target_btf_id)
        && !own_prog_ids.contains(&prog_id)
}

/// Count foreign tracing links on our attach targets by root
/// enumeration (`BPF_LINK_GET_NEXT_ID` + `GET_FD_BY_ID` + GET_INFO per
/// link, classified by [`is_foreign_link`]). Bounded (refuses past
/// the cap instead of looping forever); permission refusals surface
/// typed (the canary shell maps them to its environment exit).
pub fn count_foreign_links(
    own_prog_ids: &[u32],
    target_btf_ids: &[u32],
) -> Result<u64, ForeignLinksError> {
    use crate::probe::bpf_sys::{link_get_fd_by_id, link_get_next_id, obj_get_info};
    const CAP: u32 = 65_536;
    const PREFIX: u32 = 24;
    let mut foreign = 0u64;
    let mut id = 0u32;
    let mut seen = 0u32;
    loop {
        let Some(next) = link_get_next_id(id).map_err(|errno| ForeignLinksError::Enumerate {
            stage: "link_get_next_id",
            errno,
        })?
        else {
            return Ok(foreign);
        };
        id = next;
        seen += 1;
        if seen > CAP {
            return Err(ForeignLinksError::TooMany { cap: CAP });
        }
        let fd = match link_get_fd_by_id(next) {
            Ok(fd) => fd,
            // Raced with detach (the link vanished between id and
            // open) — not evidence either way, skip it.
            Err(libc::ENOENT) => continue,
            Err(errno) => {
                return Err(ForeignLinksError::Enumerate {
                    stage: "link_get_fd_by_id",
                    errno,
                });
            }
        };
        let mut buf = [0u8; 512];
        let got = obj_get_info(fd.as_raw_fd(), &mut buf).map_err(|errno| {
            ForeignLinksError::Enumerate {
                stage: "link_get_info",
                errno,
            }
        })?;
        if got < PREFIX {
            return Err(ForeignLinksError::InfoShort { got, want: PREFIX });
        }
        let u32le =
            |off: usize| u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        if is_foreign_link(u32le(0), u32le(8), u32le(20), own_prog_ids, target_btf_ids) {
            foreign += 1;
        }
    }
}

/// H4 enumeration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignLinksError {
    /// Syscall refused (stage + errno; EPERM/EACCES = not root).
    Enumerate {
        /// Failing stage (static).
        stage: &'static str,
        /// Kernel errno.
        errno: i32,
    },
    /// Link table past the sanity cap (refuse, never loop).
    TooMany {
        /// Cap that tripped.
        cap: u32,
    },
    /// Kernel link-info shorter than the consumed prefix.
    InfoShort {
        /// Reported length.
        got: u32,
        /// Required prefix.
        want: u32,
    },
}

impl std::fmt::Display for ForeignLinksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enumerate { stage, errno } => {
                write!(
                    f,
                    "foreign-link enumeration failed at {stage}: errno {errno}"
                )
            }
            Self::TooMany { cap } => write!(f, "link table past cap {cap}"),
            Self::InfoShort { got, want } => {
                write!(f, "link info length {got} below prefix {want}")
            }
        }
    }
}

impl std::error::Error for ForeignLinksError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real sync transcript shape (alloc/submit/return/terminal/free/done).
    fn sync_text() -> String {
        let run = "run-sync-once";
        [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-sync-t06a","drv":"kxcipher-sync-t06a"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"decrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n")
    }

    fn sync_truth() -> FixtureTruth {
        parse_transcript(&sync_text(), "run-sync-once").expect("valid sync transcript")
    }

    fn miss_abs(section: &str, id: u32, misses: u64) -> ProgMisses {
        ProgMisses {
            section: section.to_owned(),
            id,
            misses,
        }
    }

    fn sync_view(completed: &[RequestRecord]) -> SensorView<'_> {
        // Pre-GO misses (equal baseline/final absolutes) pass: the
        // gate owns post-baseline deltas only.
        let misses = vec![miss_abs("fsession/a", 11, 3), miss_abs("fsession/b", 12, 0)];
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
            baseline: SensorBaseline {
                prog_misses: misses.clone(),
                ..SensorBaseline::default()
            },
            quiet_backlog_bytes: 0,
            view_valid: true,
            attached_links: 2,
            foreign_links: 0,
            prog_misses: misses,
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
    fn verdict_prog_miss_delta_fails() {
        // H2/M2 miss gate: a post-baseline recursion-miss delta
        // voids the run (a wholly skipped call leaves no edge and
        // no LLOSS — the gate is the only witness).
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let mut view = sync_view(&completed);
        view.prog_misses[0].misses += 1;
        let err = verdict("sync-once", &truth, &view).expect_err("miss delta must fail");
        assert!(
            err.contains("prog_misses[fsession/a] delta reads 1"),
            "{err}"
        );
    }

    #[test]
    fn verdict_prog_miss_backwards_fails() {
        // A miss counter that ran backwards fails (reset images are
        // not silently absorbed — same rule as every verdict delta).
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let mut view = sync_view(&completed);
        view.prog_misses[0].misses = 2;
        let err = verdict("sync-once", &truth, &view).expect_err("backwards must fail");
        assert!(err.contains("ran backwards"), "{err}");
    }

    #[test]
    fn verdict_prog_miss_without_baseline_fails_closed() {
        // A final program with no baseline entry fails closed (an
        // unattributed program must never read as zero misses).
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let mut view = sync_view(&completed);
        view.baseline.prog_misses.clear();
        let err = verdict("sync-once", &truth, &view).expect_err("missing baseline must fail");
        assert!(err.contains("has no baseline"), "{err}");
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
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t06a","drv":"kxcipher-async-t06a"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
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
    fn verdict_void_identity_or_links_fail() {
        // W8/H4: a void M2 identity, a non-2 link count, or any
        // foreign link on our targets fails the run — exact counts
        // are void without identity + retirement exclusion.
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let mut view = sync_view(&completed);
        view.view_valid = false;
        let err = verdict("sync-once", &truth, &view).expect_err("void identity must fail");
        assert!(err.contains("identity"), "names it: {err}");
        let mut view = sync_view(&completed);
        view.attached_links = 1;
        let err = verdict("sync-once", &truth, &view).expect_err("1 link must fail");
        assert!(err.contains("2 session links"), "names it: {err}");
        let mut view = sync_view(&completed);
        view.foreign_links = 1;
        let err = verdict("sync-once", &truth, &view).expect_err("foreign link must fail");
        assert!(err.contains("foreign"), "names it: {err}");
    }

    #[test]
    fn foreign_link_classification() {
        // Pure classifier behind the H4 root enumeration: only a
        // TRACING link on OUR target with a prog id OUTSIDE our set
        // counts as foreign (own links, other link types, and other
        // targets never count).
        let own = [11u32, 12];
        let targets = [700u32, 701];
        assert!(is_foreign_link(2, 99, 700, &own, &targets));
        assert!(!is_foreign_link(2, 11, 700, &own, &targets));
        assert!(!is_foreign_link(2, 99, 702, &own, &targets));
        assert!(!is_foreign_link(1, 99, 700, &own, &targets));
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

    #[test]
    fn parse_rejects_json_type_confusion() {
        // A float errno is not errno 0 (numeric-prefix scans
        // misread `"errno":0.5` as `0`); exact JSON types only.
        let float_errno = sync_text().replacen("\"errno\":0", "\"errno\":0.5", 1);
        let err =
            parse_transcript(&float_errno, "run-sync-once").expect_err("float errno must reject");
        assert!(err.reason.contains("errno"), "names it: {err}");
        // Non-object lines and runless rows fail (unattributable).
        for bad in [
            sync_text().replace(
                "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":1,\"phase\":\"alloc\",\"req\":\"kxcipher-sync-t06a\",\"drv\":\"kxcipher-sync-t06a\"}",
                "not json at all",
            ),
            sync_text().replace(
                "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":1,\"phase\":\"alloc\",\"req\":\"kxcipher-sync-t06a\",\"drv\":\"kxcipher-sync-t06a\"}",
                "{\"v\":1,\"seq\":1,\"phase\":\"alloc\"}",
            ),
        ] {
            assert!(parse_transcript(&bad, "run-sync-once").is_err());
        }
        // Substring spoof: the run mark inside another field's value
        // does not scope the row (exact run equality only).
        let spoof = "{\"v\":1,\"run\":\"other\",\"seq\":1,\"phase\":\"alloc\",\"req\":\"x run-sync-once y\"}\n"
            .to_owned()
            + &sync_text();
        parse_transcript(&spoof, "run-sync-once").expect("spoof row ignored");
    }

    #[test]
    fn parse_enforces_version_order_and_completeness() {
        // Wrong format version fails loudly (drift, not compat).
        let v2 = sync_text().replace("\"v\":1", "\"v\":2");
        assert!(parse_transcript(&v2, "run-sync-once").is_err());
        // A row after done fails (fixture contract: nothing follows).
        let mut after_done = sync_text();
        after_done.push_str("\n{\"v\":1,\"run\":\"run-sync-once\",\"seq\":9,\"phase\":\"alloc\"}");
        assert!(parse_transcript(&after_done, "run-sync-once").is_err());
        // Every submit needs its return AND terminal rows.
        let no_terminal = sync_text().replace(
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":3,\"phase\":\"terminal\",\"errno\":0}",
            "",
        );
        let err = parse_transcript(&no_terminal, "run-sync-once")
            .expect_err("missing terminal must fail");
        assert!(err.reason.contains("terminal"), "names it: {err}");
        // Known-ignored phases (progress/free) validate shape, not values.
        let with_progress = sync_text().replace(
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"terminal\",\"errno\":0}",
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"terminal\",\"errno\":0}\n{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"progress\",\"errno\":-115}",
        );
        parse_transcript(&with_progress, "run-sync-once").expect("progress ignored");
    }

    #[test]
    fn parse_rejects_duplicate_evidence_rows() {
        // Round-4 (sol-M2/astra-M2): the verdict looks up the FIRST
        // return/terminal per seq, so a conflicting duplicate row
        // would be silently shadowed — duplicates reject at parse.
        let dup_terminal = sync_text().replace(
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"terminal\",\"errno\":0}",
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"terminal\",\"errno\":0}\n{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"terminal\",\"errno\":-5}",
        );
        let err = parse_transcript(&dup_terminal, "run-sync-once")
            .expect_err("duplicate terminal must fail");
        assert!(err.reason.contains("duplicate terminal"), "names it: {err}");
        let dup_return = sync_text().replace(
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":3,\"phase\":\"return\",\"errno\":0}",
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":3,\"phase\":\"return\",\"errno\":0}\n{\"v\":1,\"run\":\"run-sync-once\",\"seq\":3,\"phase\":\"return\",\"errno\":-5}",
        );
        let err =
            parse_transcript(&dup_return, "run-sync-once").expect_err("duplicate return must fail");
        assert!(err.reason.contains("duplicate return"), "names it: {err}");
    }

    #[test]
    fn parse_validates_marker_rows() {
        // Round-4 minor: alloc/free/progress are not oracle evidence,
        // but their required fields validate — a malformed marker is
        // a broken transcript (fixture.h contract).
        let no_req = sync_text().replace("\"req\":\"kxcipher-sync-t06a\",", "");
        assert!(parse_transcript(&no_req, "run-sync-once").is_err());
        let empty_drv = sync_text().replace("\"drv\":\"kxcipher-sync-t06a\"", "\"drv\":\"\"");
        assert!(parse_transcript(&empty_drv, "run-sync-once").is_err());
        let no_final = sync_text().replace(",\"final\":true", "");
        assert!(parse_transcript(&no_final, "run-sync-once").is_err());
        let bad_final = sync_text().replace("\"final\":true", "\"final\":\"yes\"");
        let err =
            parse_transcript(&bad_final, "run-sync-once").expect_err("mistyped final must fail");
        assert!(err.reason.contains("final"), "names it: {err}");
        let no_errno = sync_text().replace(
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"terminal\",\"errno\":0}",
            "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"terminal\",\"errno\":0}\n{\"v\":1,\"run\":\"run-sync-once\",\"seq\":2,\"phase\":\"progress\"}",
        );
        assert!(parse_transcript(&no_errno, "run-sync-once").is_err());
    }

    #[test]
    fn verdict_hooks_come_from_the_ledger() {
        // Round-3 counterexample: a two-encrypt fixture must FAIL
        // against a 1+1 sensor view (scenario constants passed it).
        let run = "run-sync-once";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("valid transcript");
        assert_eq!(truth.expected_hooks(), [2, 2, 0, 0]);
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let err = verdict("sync-once", &truth, &sync_view(&completed))
            .expect_err("2-enc fixture vs 1+1 view must fail");
        assert!(err.contains("fixture-derived"), "names it: {err}");
    }

    #[test]
    fn verdict_reconciles_terminals_and_lanes() {
        // Terminal errno must equal return errno per op.
        let truth = sync_truth();
        let mut conflict = truth.clone();
        conflict.terminals[0].1 = -5;
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let err = verdict("sync-once", &conflict, &sync_view(&completed))
            .expect_err("terminal conflict must fail");
        assert!(err.contains("return/terminal mismatch"), "names it: {err}");
        // Per-lane reconciliation: permuted aggregates fail even
        // when totals match ([4,0,0,0] vs [1,1,1,1]).
        let mut view = sync_view(&completed);
        view.agg_accepted = [4, 0, 0, 0];
        let err = verdict("sync-once", &truth, &view).expect_err("permuted agg must fail");
        assert!(err.contains("per-lane"), "names it: {err}");
    }

    #[test]
    fn verdict_async_terminal_belongs_to_the_op() {
        // The async terminal row must match THE op's seq (errno-only
        // checks pass a foreign terminal row).
        let run = "run-async-once";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":7,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        // Parser rejects first (terminal for unknown seq) — the
        // verdict seq check below covers a parser-passing shape.
        assert!(parse_transcript(&text, run).is_err());
        let mut truth = parse_transcript(
            &text.replace(
                "\"seq\":7,\"phase\":\"terminal\"",
                "\"seq\":2,\"phase\":\"terminal\"",
            ),
            run,
        )
        .expect("valid async transcript");
        truth.terminals = vec![(7, 0)];
        let completed = [RequestRecord {
            id: 1,
            tfm_id: None,
            terminal: Terminal::Unknown,
            duration_ns: None,
        }];
        let view = SensorView {
            completed: &completed,
            edge_hits: [1, 1, 0, 0],
            agg_accepted: [1, 1, 0, 0],
            kernel_loss: [0; 5],
            decode: DecodeStats {
                admitted: 1,
                ..DecodeStats::default()
            },
            reducer: ReducerStats {
                admitted: 1,
                emitted: 1,
                unfinished: 1,
                ..ReducerStats::default()
            },
            retained_dropped: 0,
            baseline: SensorBaseline::default(),
            quiet_backlog_bytes: 0,
            view_valid: true,
            attached_links: 2,
            foreign_links: 0,
            prog_misses: Vec::new(),
        };
        let err = verdict("async-once", &truth, &view).expect_err("foreign terminal must fail");
        assert!(err.contains("terminals"), "names it: {err}");
    }
}
