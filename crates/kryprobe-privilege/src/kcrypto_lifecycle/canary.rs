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
//! - Every loss counter must read zero — except `cryptd-async`'s
//!   `duplicate`, which pins one nested re-join per op (P4: the
//!   cryptd completion synchronously invokes the nested owner
//!   completion); any close backlog fails.

use crate::kcrypto_lifecycle::async_adapter::AdapterStats;
use crate::kcrypto_lifecycle::decode::DecodeStats;
use crate::kcrypto_lifecycle::profile::{LANE_COUNT, LifecycleProfile, manifest};
use crate::kcrypto_lifecycle::tfm::{GenerationInfo, TfmStats};
use crate::kcrypto_lifecycle::view::ProgMisses;
use kryprobe_abi::kcrypto_lifecycle::{
    LTFM_SITE_SETAUTHSIZE, LTFM_SITE_SETKEY_AEAD, LTFM_SITE_SETKEY_SK,
};
use kryprobe_core::kcrypto::{ReducerStats, RequestRecord, Terminal};

/// One fixture op (sequence order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureOp {
    /// Sequence number (unique per run among submits).
    pub seq: u64,
    /// `encrypt` or `decrypt`.
    pub op: String,
}

/// One fixture allocation (T07-R2-04: retained transform truth —
/// the oracle pairs these with sensor generations by index).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureAlloc {
    /// Alloc sequence (unique per run; shares the run's seq
    /// counter with submits — never collides with an op seq).
    pub seq: u64,
    /// Requested name (`req`).
    pub req: String,
    /// Resolved driver (`drv`).
    pub drv: String,
    /// Type (`type`).
    pub alg_type: u32,
    /// Mask (`mask`).
    pub alg_mask: u32,
}

/// One fixture release (row order — a shared lifetime frees more
/// than once, so seqs repeat here by design).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureFree {
    /// Alloc sequence being released.
    pub seq: u64,
    /// Whether this release freed the transform.
    pub final_free: bool,
}

/// One fixture configuration (row order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureConfig {
    /// Alloc sequence being configured.
    pub seq: u64,
    /// `setkey` or `setauthsize` (sk-vs-aead disambiguated by the
    /// scenario arm — the row carries no family).
    pub op: String,
    /// Native errno (0 on success).
    pub errno: i32,
    /// Length scalar (key length or authsize).
    pub len: u32,
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
    /// `(seq, errno)` progress rows in row order (P4: waiter-side
    /// markers AND kernel backlog-progress callbacks — the
    /// scenario arm decides which shape each scenario runs).
    pub progresses: Vec<(u64, i32)>,
    /// Notification order (P4): `(seq, is_terminal)` for every
    /// progress (`false`) and terminal (`true`) row, in row order —
    /// the deterministic drain order the burst arm pins
    /// (`P1,T0,P2,T1,P3,T2,T3`).
    pub notify_order: Vec<(u64, bool)>,
    /// Row-order evidence (P4r2): `(seq, row_index)` for every
    /// submit row in row order — the race arms pin forced
    /// orderings (terminal-before-return, reuse-before-unwind)
    /// against THESE, never timestamps (coarse-clock ties) or
    /// cross-phase vec positions (lost at parse).
    pub submit_lines: Vec<(u64, usize)>,
    /// Row-order evidence (P4r2): `(seq, row_index)` for every
    /// return row in row order.
    pub return_lines: Vec<(u64, usize)>,
    /// Row-order evidence (P4r2): `(seq, row_index)` for every
    /// terminal row in row order.
    pub terminal_lines: Vec<(u64, usize)>,
    /// Allocation rows in sequence order (T07-R2-04).
    pub allocs: Vec<FixtureAlloc>,
    /// Release rows in row order (T07-R2-04).
    pub frees: Vec<FixtureFree>,
    /// Configuration rows in row order (T07-R2-04).
    pub configs: Vec<FixtureConfig>,
    /// `alloc-probe` submit seqs (failed-alloc/init scenarios —
    /// probes, not ops: no hooks, no generations).
    pub probes: Vec<u64>,
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
            // Family classification over the parser's closed
            // label set (suffixed labels are encrypt flavors —
            // `encrypt-cryptd` hooks the encrypt site like every
            // other flavor; only its COMPLETION lane differs).
            let (submit_lane, return_lane) = match op.op.as_str() {
                "encrypt" | "encrypt-exact" | "encrypt-delayed" | "encrypt-burst"
                | "encrypt-early" | "encrypt-cryptd" | "encrypt-reuse" | "encrypt-reuse-cb" => {
                    (0, 1)
                }
                "decrypt" => (2, 3),
                _ => unreachable!("parser admits only the closed label set"),
            };
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

fn get_u32(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    line_no: usize,
    what: &'static str,
) -> Result<u32, TranscriptError> {
    obj.get(key)
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
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
/// the alloc/free/config/progress rows — a malformed row is a
/// broken transcript, not ignorable noise), unique
/// submit/probe/alloc/return/terminal seqs (a duplicate evidence
/// row could shadow the verdict's first-match lookup),
/// return/terminal only for submitted/probed seqs, frees/configs
/// only for allocated seqs, exactly one `done` with nothing after
/// it, and a positive control (≥1 submit with its return AND
/// terminal rows, ≥1 alloc, or ≥1 probe). Anything else is a
/// [`TranscriptError`] (fail the run — never skip-and-pass).
/// Extra keys on own rows are ignored per the fixture contract
/// (every row shape ends `,...}` — extensibility reserved); the
/// `v == 1` pin still fails a format revision loudly.
pub fn parse_transcript(text: &str, run_id: &str) -> Result<FixtureTruth, TranscriptError> {
    let mut ops: Vec<FixtureOp> = Vec::new();
    let mut returns: Vec<(u64, i32)> = Vec::new();
    let mut terminals: Vec<(u64, i32)> = Vec::new();
    let mut progresses: Vec<(u64, i32)> = Vec::new();
    let mut notify_order: Vec<(u64, bool)> = Vec::new();
    let mut submit_lines: Vec<(u64, usize)> = Vec::new();
    let mut return_lines: Vec<(u64, usize)> = Vec::new();
    let mut terminal_lines: Vec<(u64, usize)> = Vec::new();
    let mut allocs: Vec<FixtureAlloc> = Vec::new();
    let mut frees: Vec<FixtureFree> = Vec::new();
    let mut configs: Vec<FixtureConfig> = Vec::new();
    let mut probes: Vec<u64> = Vec::new();
    // T07-R3-11 lifetime order state (row order — the testkit
    // ledger's R5 equivalent: a free/config before its alloc, or
    // any row after the final free, is an impossible history).
    let mut alloc_seen: Vec<u64> = Vec::new();
    let mut final_seen: Vec<u64> = Vec::new();
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
            // Lifecycle rows: RETAINED oracle evidence (T07-R2-04 —
            // the transform verdict pairs these with sensor
            // generations); waiter markers validate only.
            "alloc" => {
                let seq = get_u64(obj, "seq", line_no, "alloc row lacks a sequence")?;
                let req = get_str(obj, "req", line_no, "alloc row lacks a req")?;
                let drv = get_str(obj, "drv", line_no, "alloc row lacks a drv")?;
                if req.is_empty() || drv.is_empty() {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "alloc row has an empty req or drv",
                    });
                }
                if allocs.iter().any(|a: &FixtureAlloc| a.seq == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "duplicate alloc sequence",
                    });
                }
                allocs.push(FixtureAlloc {
                    seq,
                    req: req.to_owned(),
                    drv: drv.to_owned(),
                    alg_type: get_u32(obj, "type", line_no, "alloc row lacks a type")?,
                    alg_mask: get_u32(obj, "mask", line_no, "alloc row lacks a mask")?,
                });
                alloc_seen.push(seq);
            }
            "free" => {
                let seq = get_u64(obj, "seq", line_no, "free row lacks a sequence")?;
                let final_free = get_bool(obj, "final", line_no, "free row lacks a bool final")?;
                // Seqs repeat by design (shared lifetimes free more
                // than once) — row order retained, no dup check —
                // but every free follows its alloc and precedes any
                // final (T07-R3-11: a final free ends the lifetime).
                if !alloc_seen.contains(&seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "free row arrived before its alloc",
                    });
                }
                if final_seen.contains(&seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "free row arrived after final free",
                    });
                }
                if final_free {
                    final_seen.push(seq);
                }
                frees.push(FixtureFree { seq, final_free });
            }
            "config" => {
                let seq = get_u64(obj, "seq", line_no, "config row lacks a sequence")?;
                let op = get_str(obj, "op", line_no, "config row lacks an op")?;
                if op != "setkey" && op != "setauthsize" {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "unknown config op",
                    });
                }
                // A config follows its alloc and precedes any final
                // free (T07-R3-11: configuring a dead transform is
                // an impossible history).
                if !alloc_seen.contains(&seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "config row arrived before its alloc",
                    });
                }
                if final_seen.contains(&seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "config row arrived after final free",
                    });
                }
                configs.push(FixtureConfig {
                    seq,
                    op: op.to_owned(),
                    errno: get_i32(obj, "errno", line_no, "config row lacks an errno")?,
                    len: get_u32(obj, "len", line_no, "config row lacks a len")?,
                });
            }
            "progress" => {
                let seq = get_u64(obj, "seq", line_no, "progress row lacks a sequence")?;
                let errno = get_i32(obj, "errno", line_no, "progress row lacks an errno")?;
                if !ops.iter().any(|o: &FixtureOp| o.seq == seq) && !probes.contains(&seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "progress for an unknown sequence",
                    });
                }
                if progresses.iter().any(|(s, _)| *s == seq) {
                    return Err(TranscriptError {
                        line: line_no,
                        reason: "duplicate progress sequence",
                    });
                }
                progresses.push((seq, errno));
                notify_order.push((seq, false));
            }
            "submit" => {
                let seq = get_u64(obj, "seq", line_no, "submit row lacks a sequence")?;
                let op = get_str(obj, "op", line_no, "submit row lacks an op")?;
                // `alloc-probe` submits are failure-path probes
                // (F03), not invocations: retained separately, no
                // hook expectations, no generations.
                if op == "alloc-probe" {
                    if probes.contains(&seq) {
                        return Err(TranscriptError {
                            line: line_no,
                            reason: "duplicate probe sequence",
                        });
                    }
                    probes.push(seq);
                    continue;
                }
                // Closed fixture label set (T07-R2-04: the suffixed
                // labels are per-scenario encrypt flavors hooked at
                // the encrypt site — `exact-driver` runs
                // `encrypt-exact`, never plain `encrypt`;
                // `cryptd-async` runs `encrypt-cryptd`; an unknown
                // label is still drift, never a default family).
                if !matches!(
                    op,
                    "encrypt"
                        | "decrypt"
                        | "encrypt-exact"
                        | "encrypt-delayed"
                        | "encrypt-burst"
                        | "encrypt-early"
                        | "encrypt-cryptd"
                        | "encrypt-reuse"
                        | "encrypt-reuse-cb"
                ) {
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
                submit_lines.push((seq, idx));
            }
            "return" => {
                let seq = get_u64(obj, "seq", line_no, "return row lacks a sequence")?;
                let errno = get_i32(obj, "errno", line_no, "return row lacks an errno")?;
                if !ops.iter().any(|o: &FixtureOp| o.seq == seq) && !probes.contains(&seq) {
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
                return_lines.push((seq, idx));
            }
            "terminal" => {
                let seq = get_u64(obj, "seq", line_no, "terminal row lacks a sequence")?;
                let errno = get_i32(obj, "errno", line_no, "terminal row lacks an errno")?;
                if !ops.iter().any(|o: &FixtureOp| o.seq == seq) && !probes.contains(&seq) {
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
                notify_order.push((seq, true));
                terminal_lines.push((seq, idx));
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
    // Positive control: transform-only scenarios run zero ops
    // (allocs are their evidence); failure probes likewise.
    if ops.is_empty() && allocs.is_empty() && probes.is_empty() {
        return Err(TranscriptError {
            line: 0,
            reason: "transcript ran zero ops and zero allocs (no positive control)",
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
    for probe in &probes {
        if !returns.iter().any(|(seq, _)| seq == probe) {
            return Err(TranscriptError {
                line: 0,
                reason: "probe seq lacks a return row",
            });
        }
        if !terminals.iter().any(|(seq, _)| seq == probe) {
            return Err(TranscriptError {
                line: 0,
                reason: "probe seq lacks a terminal row",
            });
        }
    }
    // One run-wide seq counter: submit, probe, and alloc seqs must
    // never collide (a collision shadows the verdict's lookups).
    {
        let mut seen: Vec<u64> = ops.iter().map(|op| op.seq).collect();
        for probe in &probes {
            if seen.contains(probe) {
                return Err(TranscriptError {
                    line: 0,
                    reason: "probe sequence collides with a submit",
                });
            }
            seen.push(*probe);
        }
        for alloc in &allocs {
            if seen.contains(&alloc.seq) {
                return Err(TranscriptError {
                    line: 0,
                    reason: "alloc sequence collides with a submit",
                });
            }
            seen.push(alloc.seq);
        }
    }
    // Frees and configs reference allocated seqs (a release for an
    // unrecorded alloc is a broken transcript, not evidence).
    // (T07-R3-11: the row-order checks above subsume these — they
    // stay as the `FixtureTruth`-level invariant.)
    for free in &frees {
        if !allocs.iter().any(|a| a.seq == free.seq) {
            return Err(TranscriptError {
                line: 0,
                reason: "free row references an unrecorded alloc",
            });
        }
    }
    for config in &configs {
        if !allocs.iter().any(|a| a.seq == config.seq) {
            return Err(TranscriptError {
                line: 0,
                reason: "config row references an unrecorded alloc",
            });
        }
    }
    ops.sort_by_key(|op| op.seq);
    allocs.sort_by_key(|alloc| alloc.seq);
    Ok(FixtureTruth {
        ops,
        returns,
        terminals,
        progresses,
        notify_order,
        submit_lines,
        return_lines,
        terminal_lines,
        allocs,
        frees,
        configs,
        probes,
        fixture_result,
        fixture_overflow,
    })
}

/// Sensor counters at one instant (baselines + final read share it).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SensorBaseline {
    /// Per-hook consumed edges in `LAGG_*` lane order (lanes 0–3 are
    /// the op hooks `[enc-sub, enc-ret, dec-sub, dec-ret]`; lanes
    /// 16/17 are the P4 callback hooks).
    pub edge_hits: [u64; 18],
    /// `LLOSS` per-class totals (5 classes).
    pub kernel_loss: [u64; 5],
    /// `LAGG` per-hook accepted totals.
    pub agg_accepted: [u64; 18],
    /// Retained completions surfaced so far.
    pub completed_len: u64,
    /// Decoder counters (quiescence + delta verdict; robust to
    /// pre-clear traffic between bring-up and baseline).
    pub decode: DecodeStats,
    /// Reducer counters (same rationale).
    pub reducer: ReducerStats,
    /// Callback-adapter counters (P4: same rationale — loss deltas
    /// join the strict all-zero gate).
    pub adapter: AdapterStats,
    /// Retention drops past the ledger bound.
    pub retained_dropped: u64,
    /// Per-program recursion-miss absolutes (H2 quiescence + delta
    /// verdict: pre-GO misses are baseline, post-GO misses fail).
    pub prog_misses: Vec<ProgMisses>,
    /// Transform-lifetime counters (T07-05/R3: loss deltas join
    /// the strict all-zero gate — normal transform accounting is
    /// truth, never gated).
    pub tfm: TfmStats,
    /// Generation count at this instant (T07-R2-04: fixture
    /// allocs pair with generations ABOVE this baseline — the
    /// fixture runs sequentially, so alloc[i] joins
    /// generations[baseline + i]).
    pub generations_len: u64,
}

/// Sensor evidence for one scenario (post-finish: completions include
/// the `finish` reconciliation; counters are the final ledger).
#[derive(Debug)]
pub struct SensorView<'a> {
    /// Post-finish completions (every pending request reconciled).
    pub completed: &'a [RequestRecord],
    /// Final per-hook consumed edges (18 `LAGG_*` lanes).
    pub edge_hits: [u64; 18],
    /// Final decode counters.
    pub decode: DecodeStats,
    /// Final reducer counters.
    pub reducer: ReducerStats,
    /// Final callback-adapter counters (loss deltas join the
    /// strict all-zero gate below).
    pub adapter: AdapterStats,
    /// Final kernel loss.
    pub kernel_loss: [u64; 5],
    /// Final accepted aggregate (18 `LAGG_*` lanes).
    pub agg_accepted: [u64; 18],
    /// Retention drops past the ledger bound.
    pub retained_dropped: u64,
    /// Quiescence-proven pre-GO baseline (deltas measure from here).
    pub baseline: SensorBaseline,
    /// Quiet-verdict close backlog in ring bytes (must be 0).
    pub quiet_backlog_bytes: u64,
    /// M2 sticky identity verdict (must be true: a void identity
    /// voids every exact count in the run).
    pub view_valid: bool,
    /// Attach count while armed (must be exactly 3 — the three
    /// fsession session links, W8 grown by the T07.2 alloc site;
    /// captured pre-close since detach drops the links before the
    /// verdict runs).
    pub attached_links: usize,
    /// Foreign tracing links on our attach targets (must be 0 — H4
    /// retirement exclusion: any foreign link may have retired ours).
    pub foreign_links: u64,
    /// Final per-program recursion-miss absolutes (H2: every
    /// post-baseline delta must read zero — strict all-zero).
    pub prog_misses: Vec<ProgMisses>,
    /// Final transform-lifetime counters (loss deltas join the
    /// strict all-zero gate below).
    pub tfm: TfmStats,
    /// Final generations (T07-R2-04: paired against fixture
    /// allocs above `baseline.generations_len` — provenance,
    /// retirement, epochs, and config scalars compared
    /// per-lifetime, never just counted).
    pub generations: &'a [GenerationInfo],
    /// Session exact-reuse predicate at verdict time (T07-R2-04:
    /// read off the live tracker — reuse-burst asserts it true,
    /// proving 1,000 observed boundaries chained exactly).
    pub reuse_exact: bool,
}

/// Checked counter delta (a counter that ran BACKWARDS fails —
/// reset images are not silently absorbed).
fn delta(a: u64, b: u64, what: &str) -> Result<u64, String> {
    a.checked_sub(b)
        .ok_or_else(|| format!("counter {what} ran backwards"))
}

/// Unbound-destroy inventory delta (T07-R3-12): digest/shash
/// background pairs reconcile into the destroy lanes and the
/// admitted/releases equations with their complete production
/// baggage (one attempt, one release, one edge pair each — a
/// counter-only view is not real inventory). Sound because the
/// loss gates above already passed: zero loss means every fixture
/// alloc was observed, zero forced/evicted means fixture
/// generations stay bindable, and fixture destroys then always
/// bind at entry — never unknown. So this delta counts exactly
/// non-fixture pairs, and the exact-equality equations (no
/// tolerance) cross-check the baggage both ways: edges without
/// the counter fail, and the counter without edges fails. (A null
/// background destroy still fails loudly — it bumps lanes and
/// releases without inventory standing behind them — same as any
/// unattributed edge; nothing absorbs silently.)
fn unknown_inventory_d(view: &SensorView<'_>) -> Result<u64, String> {
    delta(
        view.tfm.unknown_releases,
        view.baseline.tfm.unknown_releases,
        "tfm_unknown_releases",
    )
}

/// Fresh sensor generations for this scenario (T07-R2-04): the
/// fixture runs sequentially, so fixture alloc[i] pairs with
/// generations[baseline + i] — the count must match EXACTLY (a
/// civilian background allocation fails the run, never hides in
/// the join). Generation IDs must be nonzero and STRICTLY
/// INCREASING across the whole visible slice (T07-R3-03 / astra
/// R3-05): the tracker mints monotonically in assignment order and
/// never reuses (eviction preserves order), so one strict-increase
/// check pins fresh distinctness, fresh order, AND separation from
/// baseline identities — a regression emitting 1,000 correct rows
/// under one ID fails here, never certifies.
fn fresh_generations<'v>(
    truth: &FixtureTruth,
    view: &'v SensorView<'v>,
) -> Result<&'v [GenerationInfo], String> {
    let base = view.baseline.generations_len as usize;
    if view.generations.len() < base {
        return Err(format!(
            "generations {} < baseline {base} (went backwards)",
            view.generations.len()
        ));
    }
    let fresh = &view.generations[base..];
    if fresh.len() != truth.allocs.len() {
        return Err(format!(
            "fresh generations {} != {} fixture allocs",
            fresh.len(),
            truth.allocs.len()
        ));
    }
    let mut prev = 0u64;
    for (i, g) in view.generations.iter().enumerate() {
        if g.id == 0 {
            return Err(format!("generation id at index {i} is zero (never issued)"));
        }
        if g.id <= prev {
            return Err(format!(
                "generation id {} at index {i} is not above previous id {prev} (duplicate, unordered, or baseline-reusing)",
                g.id
            ));
        }
        prev = g.id;
    }
    Ok(fresh)
}

/// One alloc-observed (sk) lifetime vs its generation (T07-R2-04):
/// provenance, retirement, ambiguity, and config scalars compared
/// per-lifetime. `expect_ambiguous` is true only for the
/// shared-release intermediate (a retained release that a later
/// final destroy retires — the flag truthfully survives).
fn verdict_lifetime_sk(
    truth: &FixtureTruth,
    alloc: &FixtureAlloc,
    generation: &GenerationInfo,
    expect_ambiguous: bool,
) -> Result<(), String> {
    let tag = format!("alloc seq {}", alloc.seq);
    if generation.req_name != alloc.req {
        return Err(format!(
            "{tag}: req {:?} != fixture {:?}",
            generation.req_name, alloc.req
        ));
    }
    if generation.drv_name != alloc.drv {
        return Err(format!(
            "{tag}: drv {:?} != fixture {:?}",
            generation.drv_name, alloc.drv
        ));
    }
    if generation.alg_type != alloc.alg_type || generation.alg_mask != alloc.alg_mask {
        return Err(format!(
            "{tag}: type/mask {}/{} != fixture {}/{}",
            generation.alg_type, generation.alg_mask, alloc.alg_type, alloc.alg_mask
        ));
    }
    if generation.name_truncated || generation.drv_truncated {
        return Err(format!(
            "{tag}: fixture names are short — truncation is drift"
        ));
    }
    if generation.first_seen {
        return Err(format!(
            "{tag}: alloc-observed lifetime must not be first-seen"
        ));
    }
    let frees: Vec<&FixtureFree> = truth.frees.iter().filter(|f| f.seq == alloc.seq).collect();
    match frees.last() {
        Some(last) if generation.retired != last.final_free => {
            return Err(format!(
                "{tag}: retired {} != fixture final {}",
                generation.retired, last.final_free
            ));
        }
        None if generation.retired => {
            return Err(format!("{tag}: unreleased lifetime retired"));
        }
        _ => {}
    }
    if generation.ambiguous != expect_ambiguous {
        return Err(format!(
            "{tag}: ambiguous {} != expected {expect_ambiguous}",
            generation.ambiguous
        ));
    }
    let configs: Vec<&FixtureConfig> = truth
        .configs
        .iter()
        .filter(|c| c.seq == alloc.seq)
        .collect();
    if generation.configs != configs.len() as u64 {
        return Err(format!(
            "{tag}: configs {} != {} fixture rows",
            generation.configs,
            configs.len()
        ));
    }
    let ok = configs.iter().filter(|c| c.errno == 0).count() as u64;
    if generation.epoch != ok {
        return Err(format!(
            "{tag}: epoch {} != {ok} successful configs",
            generation.epoch
        ));
    }
    if let Some(last) = configs.last() {
        if generation.last_config_len != last.len {
            return Err(format!(
                "{tag}: last config len {} != fixture {}",
                generation.last_config_len, last.len
            ));
        }
        if generation.last_config_errno != last.errno {
            return Err(format!(
                "{tag}: last config errno {} != fixture {}",
                generation.last_config_errno, last.errno
            ));
        }
        let want_site = if last.op == "setauthsize" {
            LTFM_SITE_SETAUTHSIZE
        } else {
            LTFM_SITE_SETKEY_SK
        };
        if generation.last_config_site != want_site {
            return Err(format!(
                "{tag}: last config site {} != {want_site} for {:?}",
                generation.last_config_site, last.op
            ));
        }
    }
    Ok(())
}

/// One config-admitted (AEAD) lifetime vs its generation
/// (T07-R2-04): the narrowed contract — allocation unhooked, so
/// the generation is first-seen with EMPTY provenance (honest
/// unknown, never a fabricated name), while retirement, epochs,
/// and config scalars still compare exactly.
fn verdict_lifetime_aead(
    truth: &FixtureTruth,
    alloc: &FixtureAlloc,
    generation: &GenerationInfo,
) -> Result<(), String> {
    let tag = format!("aead alloc seq {}", alloc.seq);
    if !generation.first_seen {
        return Err(format!(
            "{tag}: AEAD lifetime must be first-seen (alloc unhooked)"
        ));
    }
    if !generation.req_name.is_empty() || !generation.drv_name.is_empty() {
        return Err(format!(
            "{tag}: AEAD provenance must be empty (got {:?}/{:?})",
            generation.req_name, generation.drv_name
        ));
    }
    // T07-R3-07: unknown creation provenance pins the WHOLE
    // creation record — a fabricated nonzero type/mask, or a
    // truncation claim on names that were never read, fails the
    // verdict exactly like a fabricated name.
    if generation.alg_type != 0 || generation.alg_mask != 0 {
        return Err(format!(
            "{tag}: AEAD type/mask {}/{} must stay unknown (0/0 — alloc unhooked)",
            generation.alg_type, generation.alg_mask
        ));
    }
    if generation.name_truncated || generation.drv_truncated {
        return Err(format!(
            "{tag}: AEAD truncation flags must be clear (no names were read)"
        ));
    }
    let frees: Vec<&FixtureFree> = truth.frees.iter().filter(|f| f.seq == alloc.seq).collect();
    match frees.last() {
        Some(last) if generation.retired != last.final_free => {
            return Err(format!(
                "{tag}: retired {} != fixture final {}",
                generation.retired, last.final_free
            ));
        }
        None if generation.retired => {
            return Err(format!("{tag}: unreleased lifetime retired"));
        }
        _ => {}
    }
    if generation.ambiguous {
        return Err(format!("{tag}: clean AEAD release must not flag ambiguous"));
    }
    let configs: Vec<&FixtureConfig> = truth
        .configs
        .iter()
        .filter(|c| c.seq == alloc.seq)
        .collect();
    if generation.configs != configs.len() as u64 {
        return Err(format!(
            "{tag}: configs {} != {} fixture rows",
            generation.configs,
            configs.len()
        ));
    }
    let ok = configs.iter().filter(|c| c.errno == 0).count() as u64;
    if generation.epoch != ok {
        return Err(format!(
            "{tag}: epoch {} != {ok} successful configs",
            generation.epoch
        ));
    }
    if let Some(last) = configs.last() {
        if generation.last_config_len != last.len {
            return Err(format!(
                "{tag}: last config len {} != fixture {}",
                generation.last_config_len, last.len
            ));
        }
        if generation.last_config_errno != last.errno {
            return Err(format!(
                "{tag}: last config errno {} != fixture {}",
                generation.last_config_errno, last.errno
            ));
        }
        let want_site = if last.op == "setauthsize" {
            LTFM_SITE_SETAUTHSIZE
        } else {
            LTFM_SITE_SETKEY_AEAD
        };
        if generation.last_config_site != want_site {
            return Err(format!(
                "{tag}: last config site {} != {want_site} for {:?}",
                generation.last_config_site, last.op
            ));
        }
    }
    Ok(())
}

/// Exact verdict over one scenario: `Ok(())` passes, `Err(reason)`
/// fails with the named mismatch. Counter deltas use checked
/// subtraction — a counter that ran BACKWARDS fails (reset images
/// are not silently absorbed). This is the SESSION-level exactness
/// verdict (astra R3-04): ingest-level exactness (the tracker's
/// `reuse_exact`, required true-or-false per scenario arm) AND
/// transport validity (zero kernel-loss deltas, zero program-miss
/// deltas, zero close backlog) must both hold — transport that
/// erases both halves of a boundary pair leaves no tracker trace,
/// so the loss/miss gates below are part of the release claim,
/// not defense in depth.
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
    let want_links = manifest(LifecycleProfile::RequestLifecycle).required.len();
    if view.attached_links != want_links {
        return Err(format!(
            "want exactly {want_links} session links, have {}",
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
    let mut hits_d = [0u64; 18];
    let mut loss_d = [0u64; 5];
    let mut agg_d = [0u64; 18];
    for i in 0..LANE_COUNT as usize {
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
        // Transform-lifetime loss (T07-05/R3: same loss/truth
        // split as the backend buckets — refused, unadmitted,
        // unjoined, and uncertain-identity evidence gates the
        // run; admissions, completions, classified failures,
        // proved retires, no-op releases, and joined configs
        // incl. errno verdicts are truth, never gated; unbound
        // destroys are inventory, never gated either — T07-R2-05:
        // a missed fixture identity still fails via its op
        // admission or the edge-hit equation).
        (
            "tfm_submit_refused",
            sub(
                view.tfm.submit_refused,
                view.baseline.tfm.submit_refused,
                "tfm_submit_refused",
            )?,
        ),
        (
            "tfm_tainted_refused",
            sub(
                view.tfm.tainted_refused,
                view.baseline.tfm.tainted_refused,
                "tfm_tainted_refused",
            )?,
        ),
        (
            "tfm_table_full",
            sub(
                view.tfm.table_full,
                view.baseline.tfm.table_full,
                "tfm_table_full",
            )?,
        ),
        (
            "tfm_live_full",
            sub(
                view.tfm.live_full,
                view.baseline.tfm.live_full,
                "tfm_live_full",
            )?,
        ),
        (
            "tfm_stale_returns",
            sub(
                view.tfm.stale_returns,
                view.baseline.tfm.stale_returns,
                "tfm_stale_returns",
            )?,
        ),
        (
            "tfm_bad_records",
            sub(
                view.tfm.bad_records,
                view.baseline.tfm.bad_records,
                "tfm_bad_records",
            )?,
        ),
        (
            "tfm_unlinked_ops",
            sub(
                view.tfm.unlinked_ops,
                view.baseline.tfm.unlinked_ops,
                "tfm_unlinked_ops",
            )?,
        ),
        (
            "tfm_unknown_returns",
            sub(
                view.tfm.unknown_returns,
                view.baseline.tfm.unknown_returns,
                "tfm_unknown_returns",
            )?,
        ),
        (
            "tfm_mismatched_returns",
            sub(
                view.tfm.mismatched_returns,
                view.baseline.tfm.mismatched_returns,
                "tfm_mismatched_returns",
            )?,
        ),
        (
            "tfm_unfinished",
            sub(
                view.tfm.unfinished,
                view.baseline.tfm.unfinished,
                "tfm_unfinished",
            )?,
        ),
        // (T07-R2-04: `tfm_ambiguous_releases` is ledger-derived
        // below — retained fixture releases EXPECT it.)
        (
            "tfm_forced_retires",
            sub(
                view.tfm.forced_retires,
                view.baseline.tfm.forced_retires,
                "tfm_forced_retires",
            )?,
        ),
        // (T07-R2-05, narrowed T07-R3-02: `tfm_unknown_releases`
        // deliberately NOT gated — expected digest/shash releases
        // at unoccupied bases share the counter; a missed fixture
        // identity fails via `tfm_unobserved_boundary` or the
        // edge-hit equation. `tfm_colliding_releases` IS gated
        // below — a live occupant makes it indeterminate.)
        (
            "tfm_stale_releases",
            sub(
                view.tfm.stale_releases,
                view.baseline.tfm.stale_releases,
                "tfm_stale_releases",
            )?,
        ),
        (
            "tfm_colliding_releases",
            sub(
                view.tfm.colliding_releases,
                view.baseline.tfm.colliding_releases,
                "tfm_colliding_releases",
            )?,
        ),
        (
            "tfm_config_unlinked",
            sub(
                view.tfm.config_unlinked,
                view.baseline.tfm.config_unlinked,
                "tfm_config_unlinked",
            )?,
        ),
        // (T07-R2-04: `tfm_unobserved_boundary` is ledger-derived
        // below — AEAD config admission EXPECTS it.)
        (
            "tfm_tombstone_evictions",
            sub(
                view.tfm.tombstone_evictions,
                view.baseline.tfm.tombstone_evictions,
                "tfm_tombstone_evictions",
            )?,
        ),
        // Callback-adapter loss (P4: same strict all-zero gate —
        // refused cover, orphans, ambiguity gaps, tombstone
        // evictions, and stale callbacks all void exact counts).
        (
            "adapter_cover_refused",
            sub(
                view.adapter.cover_refused,
                view.baseline.adapter.cover_refused,
                "adapter_cover_refused",
            )?,
        ),
        (
            "adapter_callback_orphans",
            sub(
                view.adapter.callback_orphans,
                view.baseline.adapter.callback_orphans,
                "adapter_callback_orphans",
            )?,
        ),
        (
            "adapter_ambiguous_keys",
            sub(
                view.adapter.ambiguous_keys,
                view.baseline.adapter.ambiguous_keys,
                "adapter_ambiguous_keys",
            )?,
        ),
        (
            "adapter_tombstone_evictions",
            sub(
                view.adapter.tombstone_evictions,
                view.baseline.adapter.tombstone_evictions,
                "adapter_tombstone_evictions",
            )?,
        ),
        (
            "adapter_stale_callbacks",
            sub(
                view.adapter.stale_callbacks,
                view.baseline.adapter.stale_callbacks,
                "adapter_stale_callbacks",
            )?,
        ),
    ];
    // P4 nested completions: real-cryptd traffic observes each
    // outer op's completion TWICE (cryptd completion entry, then
    // the nested owner completion it synchronously invokes —
    // call-nesting guarantees cryptd-first). The first observation
    // wins; each nested re-join counts exactly one `duplicate`
    // (redundant terminal evidence dropped — the counter's
    // documented meaning). Every other scenario pins zero: a
    // duplicate outside nesting is corruption, and a missing
    // nested duplicate means the owner completion never arrived.
    let want_dup = if scenario == "cryptd-async" {
        truth.ops.len() as u64
    } else {
        0
    };
    for (name, value) in losses {
        let want = if name == "duplicate" { want_dup } else { 0 };
        if value != want {
            return Err(format!(
                "loss counter {name} delta reads {value} (want {want})"
            ));
        }
    }
    // Ledger-derived ambiguity/admission (T07-R2-04): retained
    // fixture releases expect exactly that many ambiguous
    // releases, and the AEAD scenario expects one first-seen
    // admission per alloc — every other expectation is zero, so
    // unexpected ambiguity still fails here, never hides. P4:
    // `cryptd-async` grades no transform shape (see its arm's
    // contract note), so both tfm pins exempt it.
    if scenario != "cryptd-async" {
        let ambiguous_d = sub(
            view.tfm.ambiguous_releases,
            view.baseline.tfm.ambiguous_releases,
            "tfm_ambiguous_releases",
        )?;
        let want_ambiguous = truth.frees.iter().filter(|f| !f.final_free).count() as u64;
        if ambiguous_d != want_ambiguous {
            return Err(format!(
                "tfm ambiguous_releases delta {ambiguous_d} != {want_ambiguous} retained fixture releases"
            ));
        }
        let unobserved_d = sub(
            view.tfm.unobserved_boundary,
            view.baseline.tfm.unobserved_boundary,
            "tfm_unobserved_boundary",
        )?;
        let want_unobserved = if scenario == "authsize" {
            truth.allocs.len() as u64
        } else {
            0
        };
        if unobserved_d != want_unobserved {
            return Err(format!(
                "tfm unobserved_boundary delta {unobserved_d} != {want_unobserved} (AEAD config admissions)"
            ));
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
    if !matches!(
        scenario,
        "sync-once"
            | "async-once"
            | "reuse-burst"
            | "refheld-release"
            | "shared-release"
            | "rekey"
            | "authsize"
            | "typed-sync"
            | "exact-driver"
            | "failed-alloc"
            | "failed-init"
            | "backlog-accepted"
            | "no-backlog-burst"
            | "cryptd-async"
            | "early-callback"
            | "reuse-in-callback"
    ) {
        return Err(format!("unknown scenario {scenario}"));
    }
    // Op lanes: ledger-derived — EXCEPT `authsize`, whose op is an
    // AEAD encrypt (unhooked by design): the sensor must observe
    // NOTHING there (negative control — a phantom AEAD op fails).
    let expected_hits = if scenario == "authsize" {
        [0, 0, 0, 0]
    } else {
        truth.expected_hooks()
    };
    // P4: `cryptd-async` carries transcript-invisible kernel
    // traffic (one inner sync child submit per op — the audited
    // single-child-call shape), so its op lanes pin in its own arm
    // (2× the transcript ops), never here.
    if scenario != "cryptd-async" {
        let op_hits = [hits_d[0], hits_d[1], hits_d[2], hits_d[3]];
        if op_hits != expected_hits {
            return Err(format!(
                "edge hits {op_hits:?} != fixture-derived {expected_hits:?}"
            ));
        }
    }
    // Callback lanes (P4): ledger-derived per op — an op whose
    // return queued (`-EINPROGRESS`/`-EBUSY`, kernel UAPI) fired
    // one kernel callback per progress + terminal row; a
    // sync-completed op fired none (its terminal row is
    // waiter-side). `encrypt-cryptd` completions land on lane 16
    // (cryptd site), every other flavor on lane 17 (fixture
    // site). No scenario switch: the return errnos decide.
    let mut want_cb = [0u64, 0u64];
    for op in &truth.ops {
        let ret = truth
            .returns
            .iter()
            .find(|(seq, _)| *seq == op.seq)
            .map(|(_, errno)| *errno);
        if !matches!(ret, Some(-115) | Some(-16)) {
            continue;
        }
        let notes = truth
            .progresses
            .iter()
            .filter(|(seq, _)| *seq == op.seq)
            .count() as u64
            + truth
                .terminals
                .iter()
                .filter(|(seq, _)| *seq == op.seq)
                .count() as u64;
        let lane = usize::from(op.op != "encrypt-cryptd");
        want_cb[lane] = want_cb[lane].saturating_add(notes);
    }
    // P4: `cryptd-async` observes each completion twice (nested
    // owner completion on lane 17), so its callback lanes pin in
    // its own arm ([N, N]), never here.
    if scenario != "cryptd-async" {
        let got_cb = [hits_d[16], hits_d[17]];
        if got_cb != want_cb {
            return Err(format!(
                "callback lanes {got_cb:?} != fixture-derived {want_cb:?}"
            ));
        }
    }
    // Transform lanes (T07-R2-04): ledger-derived per-lane
    // expectations — alloc/destroy/config halves counted from
    // fixture rows (the scenario selects only the FAMILY shape:
    // sk scenarios observe alloc halves, the AEAD scenario must
    // not, failed probes observe the attempt but admit nothing).
    let alloc_halves = if scenario == "authsize" {
        0
    } else {
        truth.allocs.len() as u64
    };
    let setkey_rows = truth.configs.iter().filter(|c| c.op == "setkey").count() as u64;
    let authsize_rows = truth
        .configs
        .iter()
        .filter(|c| c.op == "setauthsize")
        .count() as u64;
    let (sk_setkey, aead_setkey) = if scenario == "authsize" {
        (0, setkey_rows)
    } else {
        (setkey_rows, 0)
    };
    let probe_halves = truth.probes.len() as u64;
    let frees = truth.frees.len() as u64;
    // T07-R3-12: permitted digest inventory rides the destroy
    // lanes exactly (see `unknown_inventory_d`).
    let unknown_d = unknown_inventory_d(view)?;
    let want_tfm = [
        alloc_halves + probe_halves, // 4 alloc-sk sub
        alloc_halves + probe_halves, // 5 alloc-sk ret
        frees + unknown_d,           // 6 destroy sub
        frees + unknown_d,           // 7 destroy ret
        sk_setkey,                   // 8 setkey-sk sub
        sk_setkey,                   // 9 setkey-sk ret
        authsize_rows,               // 10 setauthsize sub
        authsize_rows,               // 11 setauthsize ret
        0,                           // 12 alloc-aead sub (unhooked)
        0,                           // 13 alloc-aead ret (unhooked)
        aead_setkey,                 // 14 setkey-aead sub
        aead_setkey,                 // 15 setkey-aead ret
    ];
    // P4: `cryptd-async` grades no transform shape (see its
    // arm's contract note), so its tfm lanes pin nowhere.
    let cryptd = scenario == "cryptd-async";
    if !cryptd {
        let got_tfm: Vec<u64> = hits_d[4..16].to_vec();
        if got_tfm.as_slice() != want_tfm {
            return Err(format!(
                "transform lanes {got_tfm:?} != fixture-derived {want_tfm:?}"
            ));
        }
    }
    let admitted_d = sub(
        view.decode.admitted,
        view.baseline.decode.admitted,
        "decode.admitted",
    )?;
    // Decode admission: one per hooked op submit (`authsize` admits
    // nothing — its op never reaches the decoder; `cryptd-async`
    // admits 2× — the arm pins its own lockstep).
    let expect_admitted = if scenario == "authsize" {
        0
    } else {
        truth.ops.len() as u64
    };
    if !cryptd && admitted_d != expect_admitted {
        return Err(format!(
            "admitted delta {admitted_d} != {expect_admitted} hooked ops",
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
            verdict_op_sync(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "async-once" => {
            verdict_op_async(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "backlog-accepted" => {
            verdict_op_backlog(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "no-backlog-burst" => {
            verdict_op_no_backlog(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "early-callback" => {
            verdict_op_early(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "reuse-in-callback" => {
            verdict_op_reuse(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "cryptd-async" => {
            // Adapter-shape-strict only (no tfm grading — see the
            // arm's contract note).
            verdict_op_cryptd(scenario, truth, view, unfinished_d)?;
        }
        "rekey" => {
            verdict_op_sync(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "exact-driver" => {
            verdict_op_async(scenario, truth, view, unfinished_d)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "authsize" => {
            verdict_op_negative(scenario, truth, view)?;
            verdict_tfm_aead(truth, view)?;
        }
        "reuse-burst" | "refheld-release" | "typed-sync" => {
            verdict_op_negative(scenario, truth, view)?;
            verdict_tfm_sk(truth, view, false)?;
        }
        "shared-release" => {
            verdict_op_negative(scenario, truth, view)?;
            verdict_tfm_sk(truth, view, true)?;
            // The retained release voids exactness BY DESIGN (an
            // ambiguous release happened — the predicate must say
            // so, and the assertion pins that it does).
            if view.reuse_exact {
                return Err("shared-release: ambiguous release must void exactness".to_owned());
            }
        }
        "failed-alloc" | "failed-init" => {
            verdict_op_negative(scenario, truth, view)?;
            verdict_tfm_failed(truth, view)?;
        }
        _ => unreachable!("scenario matched above"),
    }
    Ok(())
}

/// Sync op shape: grounded completions pairwise-joined to fixture
/// errnos (shared by every scenario with synchronous sk ops).
fn verdict_op_sync(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    unfinished_d: u64,
) -> Result<(), String> {
    // Exact submit labels per scenario (T07-R2-04: the labels pin
    // WHICH fixture path ran — a mislabeled transcript never
    // grades against the wrong shape).
    let want_ops: &[&str] = match scenario {
        "sync-once" => &["encrypt", "decrypt"],
        "rekey" => &["encrypt"],
        _ => unreachable!("sync shape covers sync-once + rekey"),
    };
    let got_ops: Vec<&str> = truth.ops.iter().map(|op| op.op.as_str()).collect();
    if got_ops.as_slice() != want_ops {
        return Err(format!(
            "{scenario} runs {want_ops:?}, fixture ran {got_ops:?}"
        ));
    }
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
    Ok(())
}

/// Async op shape (P4: callback-grounded — T06 graded the pending
/// shape because completion was invisible; the qualified adapter
/// completes it now): one queued submit, one terminal callback,
/// post-finish one `Callback(0)` record with a submit→callback
/// span, nothing unfinished. Shared by every scenario with one
/// async fixture-completed sk op.
fn verdict_op_async(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    unfinished_d: u64,
) -> Result<(), String> {
    if truth.ops.len() != 1 {
        return Err(format!(
            "{scenario} runs 1 op, fixture ran {}",
            truth.ops.len()
        ));
    }
    // Exact submit label per scenario (T07-R2-04: the label pins
    // WHICH fixture path ran — a mislabeled transcript never
    // grades against the wrong shape).
    let want_op = match scenario {
        "async-once" => "encrypt",
        "exact-driver" => "encrypt-exact",
        _ => unreachable!("async shape covers async-once + exact-driver"),
    };
    if truth.ops[0].op != want_op {
        return Err(format!(
            "{scenario} runs `{want_op}`, fixture ran `{}`",
            truth.ops[0].op
        ));
    }
    // Positive controls: the fixture queued exactly once
    // (`-EINPROGRESS`, kernel UAPI) AND observed async
    // completion (errno 0) with NO progress row (single
    // in-flight op — no backlog engages).
    if truth.returns.as_slice() != [(truth.ops[0].seq, -115)] {
        return Err(format!(
            "async fixture returns {:?} != [(seq, -EINPROGRESS)]",
            truth.returns
        ));
    }
    if truth.terminals.as_slice() != [(truth.ops[0].seq, 0)] {
        return Err(format!(
            "async fixture terminals {:?} != [(op seq, 0)]",
            truth.terminals
        ));
    }
    if !truth.progresses.is_empty() {
        return Err(format!(
            "async fixture progresses {:?} != [] (no backlog on one op)",
            truth.progresses
        ));
    }
    if view.completed.len() != 1 {
        return Err(format!(
            "async post-finish completed {} != 1",
            view.completed.len()
        ));
    }
    // The adapter joined the terminal callback: exact status,
    // observed callback span, nothing truthless.
    if view.completed[0].terminal != Terminal::Callback(0) {
        return Err(format!(
            "async post-finish terminal {:?} != Callback(0) (callback unjoined)",
            view.completed[0].terminal
        ));
    }
    if view.completed[0].duration_ns.is_none() {
        return Err("async post-finish completion lacks a callback span".to_owned());
    }
    if unfinished_d != 0 {
        return Err(format!(
            "async unfinished delta {unfinished_d} != 0 (expected-complete)"
        ));
    }
    Ok(())
}

/// Backlog-burst op shape (P4): four `encrypt-burst` ops, returns
/// `-EINPROGRESS, -EBUSY × 3`, kernel progress rows on reqs 1..3
/// (`-EINPROGRESS`, always before their terminal), terminal 0
/// everywhere, notification order exactly `P1,T0,P2,T1,P3,T2,T3`
/// (the cryptd-worker drain shape), post-finish four `Callback(0)`
/// records with spans, nothing unfinished.
fn verdict_op_backlog(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    unfinished_d: u64,
) -> Result<(), String> {
    if truth.ops.len() != 4 {
        return Err(format!(
            "{scenario} runs 4 ops, fixture ran {}",
            truth.ops.len()
        ));
    }
    for op in &truth.ops {
        if op.op != "encrypt-burst" {
            return Err(format!(
                "{scenario} runs `encrypt-burst`, fixture ran `{}`",
                op.op
            ));
        }
    }
    let seqs: Vec<u64> = truth.ops.iter().map(|op| op.seq).collect();
    let want_returns: Vec<(u64, i32)> = vec![
        (seqs[0], -115),
        (seqs[1], -16),
        (seqs[2], -16),
        (seqs[3], -16),
    ];
    if truth.returns != want_returns {
        return Err(format!(
            "backlog fixture returns {:?} != [-EINPROGRESS, -EBUSY × 3]",
            truth.returns
        ));
    }
    let want_terminals: Vec<(u64, i32)> = seqs.iter().map(|seq| (*seq, 0)).collect();
    for (seq, errno) in &want_terminals {
        if !truth.terminals.contains(&(*seq, *errno)) {
            return Err(format!(
                "backlog fixture terminals {:?} lack ({seq}, 0)",
                truth.terminals
            ));
        }
    }
    let want_progress: Vec<(u64, i32)> = seqs[1..].iter().map(|seq| (*seq, -115)).collect();
    if truth.progresses != want_progress {
        return Err(format!(
            "backlog fixture progresses {:?} != [(reqs 1..3, -EINPROGRESS)]",
            truth.progresses
        ));
    }
    // Deterministic drain order (derived from the op seqs, never
    // positional constants): P1,T0,P2,T1,P3,T2,T3.
    let want_notify = vec![
        (seqs[1], false),
        (seqs[0], true),
        (seqs[2], false),
        (seqs[1], true),
        (seqs[3], false),
        (seqs[2], true),
        (seqs[3], true),
    ];
    if truth.notify_order != want_notify {
        return Err(format!(
            "backlog notify order {:?} != P1,T0,P2,T1,P3,T2,T3",
            truth.notify_order
        ));
    }
    if view.completed.len() != 4 {
        return Err(format!(
            "backlog post-finish completed {} != 4",
            view.completed.len()
        ));
    }
    for (i, record) in view.completed.iter().enumerate() {
        if record.terminal != Terminal::Callback(0) {
            return Err(format!(
                "backlog completion {i} terminal {:?} != Callback(0)",
                record.terminal
            ));
        }
        if record.duration_ns.is_none() {
            return Err(format!("backlog completion {i} lacks a callback span"));
        }
    }
    if unfinished_d != 0 {
        return Err(format!(
            "backlog unfinished delta {unfinished_d} != 0 (expected-complete)"
        ));
    }
    Ok(())
}

/// No-backlog-burst op shape (P4): two `encrypt-burst` ops without
/// backlog consent — submit 0 queues (`-EINPROGRESS`, terminal via
/// callback), submit 1 answers `-ENOSPC` immediately (waiter-side
/// terminal row, no kernel callback). Post-finish: one
/// `Callback(0)` + one `Sync(-ENOSPC)` (exact errno, never
/// rewritten), both with spans, nothing unfinished. Completion
/// ORDER is arrival order (the sync record may precede the
/// callback): joined as a set, never positionally.
fn verdict_op_no_backlog(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    unfinished_d: u64,
) -> Result<(), String> {
    if truth.ops.len() != 2 {
        return Err(format!(
            "{scenario} runs 2 ops, fixture ran {}",
            truth.ops.len()
        ));
    }
    for op in &truth.ops {
        if op.op != "encrypt-burst" {
            return Err(format!(
                "{scenario} runs `encrypt-burst`, fixture ran `{}`",
                op.op
            ));
        }
    }
    let seqs: Vec<u64> = truth.ops.iter().map(|op| op.seq).collect();
    if truth.returns != vec![(seqs[0], -115), (seqs[1], -28)] {
        return Err(format!(
            "no-backlog fixture returns {:?} != [(seq0, -EINPROGRESS), (seq1, -ENOSPC)]",
            truth.returns
        ));
    }
    // Waiter-side terminal FIRST (submit 1's ENOSPC records
    // synchronously in the submit loop), callback terminal SECOND
    // (op 0 completes after the kick) — deterministic by
    // construction, pinned in row order.
    if truth.terminals != vec![(seqs[1], -28), (seqs[0], 0)] {
        return Err(format!(
            "no-backlog fixture terminals {:?} != [(seq1, -ENOSPC), (seq0, 0)]",
            truth.terminals
        ));
    }
    if !truth.progresses.is_empty() {
        return Err(format!(
            "no-backlog fixture progresses {:?} != [] (no backlog engages)",
            truth.progresses
        ));
    }
    if view.completed.len() != 2 {
        return Err(format!(
            "no-backlog post-finish completed {} != 2",
            view.completed.len()
        ));
    }
    let mut terms: Vec<Terminal> = view.completed.iter().map(|r| r.terminal).collect();
    terms.sort_by_key(|t| match t {
        Terminal::Sync(_) => 0,
        Terminal::Callback(_) => 1,
        Terminal::Unknown => 2,
    });
    if terms.as_slice() != [Terminal::Sync(-28), Terminal::Callback(0)] {
        return Err(format!(
            "no-backlog terminals {terms:?} != [Sync(-ENOSPC), Callback(0)]"
        ));
    }
    for (i, record) in view.completed.iter().enumerate() {
        if record.duration_ns.is_none() {
            return Err(format!("no-backlog completion {i} lacks a span"));
        }
    }
    if unfinished_d != 0 {
        return Err(format!(
            "no-backlog unfinished delta {unfinished_d} != 0 (expected-complete)"
        ));
    }
    Ok(())
}

/// Row-order lookup (P4r2): the row index of `seq`'s row in a
/// phase's line vec — `None` when the row is absent (the arm
/// fails naming the phase).
fn row_line(lines: &[(u64, usize)], seq: u64) -> Option<usize> {
    lines.iter().find(|(s, _)| *s == seq).map(|(_, idx)| *idx)
}

/// Early-callback op shape (P4r2): one `encrypt-early` op whose
/// terminal callback fires INLINE — before the submitter's return
/// row lands (forced terminal-before-return row order: submit,
/// terminal, return). The return still reads `-EINPROGRESS`
/// (queued — the callback carries terminal truth, never the
/// return), no progress row exists (single in-flight op: no
/// backlog, no waiter-side marker), and the sensor joins exactly
/// one `Callback(0)` with a span, nothing unfinished, zero loss.
fn verdict_op_early(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    unfinished_d: u64,
) -> Result<(), String> {
    if truth.ops.len() != 1 || truth.ops[0].op != "encrypt-early" {
        let got: Vec<&str> = truth.ops.iter().map(|op| op.op.as_str()).collect();
        return Err(format!(
            "{scenario} runs [`encrypt-early`], fixture ran {got:?}"
        ));
    }
    let seq = truth.ops[0].seq;
    if truth.returns.as_slice() != [(seq, -115)] {
        return Err(format!(
            "early fixture returns {:?} != [(seq, -EINPROGRESS)]",
            truth.returns
        ));
    }
    if truth.terminals.as_slice() != [(seq, 0)] {
        return Err(format!(
            "early fixture terminals {:?} != [(op seq, 0)]",
            truth.terminals
        ));
    }
    if !truth.progresses.is_empty() {
        return Err(format!(
            "early fixture progresses {:?} != [] (no backlog on one op)",
            truth.progresses
        ));
    }
    // The forced race: the terminal ROW precedes the return ROW
    // (inline completion — a sequential transcript proves no race).
    let submit = row_line(&truth.submit_lines, seq)
        .ok_or_else(|| format!("early op seq {seq} lacks a submit row for the order check"))?;
    let terminal = row_line(&truth.terminal_lines, seq)
        .ok_or_else(|| format!("early op seq {seq} lacks a terminal row for the order check"))?;
    let ret = row_line(&truth.return_lines, seq)
        .ok_or_else(|| format!("early op seq {seq} lacks a return row for the order check"))?;
    if !(submit < terminal && terminal < ret) {
        return Err(format!(
            "early row order (submit {submit}, terminal {terminal}, return {ret}) is not terminal-before-return"
        ));
    }
    if view.completed.len() != 1 {
        return Err(format!(
            "early post-finish completed {} != 1",
            view.completed.len()
        ));
    }
    if view.completed[0].terminal != Terminal::Callback(0) {
        return Err(format!(
            "early post-finish terminal {:?} != Callback(0) (callback unjoined)",
            view.completed[0].terminal
        ));
    }
    if view.completed[0].duration_ns.is_none() {
        return Err("early post-finish completion lacks a callback span".to_owned());
    }
    if unfinished_d != 0 {
        return Err(format!(
            "early unfinished delta {unfinished_d} != 0 (expected-complete)"
        ));
    }
    Ok(())
}

/// Reuse-in-callback op shape (P4r2): the outer `encrypt-reuse`
/// op completes inline (terminal before its return) and the SAME
/// callback resubmits the request storage — the inner
/// `encrypt-reuse-cb` submit lands before the outer return
/// (nested reuse before unwind). Forced row order: submit_outer,
/// terminal_outer, submit_inner, return_inner, return_outer,
/// terminal_inner (the held drain releases only after the outer
/// return row, so the inner terminal cannot land early). Both
/// records join `Callback(0)` with spans — joined as a SET
/// (completion order is cross-CPU arrival order, never
/// positional) — nothing unfinished, zero loss, zero ambiguity
/// (the all-zero gate above pins distinct pairing under
/// same-key reuse: a misjoin would gap or orphan loudly).
fn verdict_op_reuse(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    unfinished_d: u64,
) -> Result<(), String> {
    let got_ops: Vec<&str> = truth.ops.iter().map(|op| op.op.as_str()).collect();
    if got_ops.as_slice() != ["encrypt-reuse", "encrypt-reuse-cb"] {
        return Err(format!(
            "{scenario} runs [`encrypt-reuse`, `encrypt-reuse-cb`], fixture ran {got_ops:?}"
        ));
    }
    let outer = truth.ops[0].seq;
    let inner = truth.ops[1].seq;
    let mut rets: Vec<(u64, i32)> = truth.returns.clone();
    rets.sort_unstable();
    if rets != [(outer, -115), (inner, -115)] {
        return Err(format!(
            "reuse fixture returns {:?} != [(outer, -EINPROGRESS), (inner, -EINPROGRESS)]",
            truth.returns
        ));
    }
    let mut terms: Vec<(u64, i32)> = truth.terminals.clone();
    terms.sort_unstable();
    if terms != [(outer, 0), (inner, 0)] {
        return Err(format!(
            "reuse fixture terminals {:?} != [(outer, 0), (inner, 0)]",
            truth.terminals
        ));
    }
    if !truth.progresses.is_empty() {
        return Err(format!(
            "reuse fixture progresses {:?} != [] (no backlog engages)",
            truth.progresses
        ));
    }
    // The forced race: nested reuse before unwind, pinned in full
    // row order (a sequential transcript proves no race).
    let so = row_line(&truth.submit_lines, outer);
    let to = row_line(&truth.terminal_lines, outer);
    let si = row_line(&truth.submit_lines, inner);
    let ri = row_line(&truth.return_lines, inner);
    let ro = row_line(&truth.return_lines, outer);
    let ti = row_line(&truth.terminal_lines, inner);
    match (so, to, si, ri, ro, ti) {
        (Some(so), Some(to), Some(si), Some(ri), Some(ro), Some(ti))
            if so < to && to < si && si < ri && ri < ro && ro < ti => {}
        _ => {
            return Err(format!(
                "reuse row order (submit {so:?}, terminal {to:?}, inner-submit {si:?}, inner-return {ri:?}, outer-return {ro:?}, inner-terminal {ti:?}) is not nested-reuse-before-unwind"
            ));
        }
    }
    if view.completed.len() != 2 {
        return Err(format!(
            "reuse post-finish completed {} != 2",
            view.completed.len()
        ));
    }
    for (i, record) in view.completed.iter().enumerate() {
        if record.terminal != Terminal::Callback(0) {
            return Err(format!(
                "reuse completion {i} terminal {:?} != Callback(0)",
                record.terminal
            ));
        }
        if record.duration_ns.is_none() {
            return Err(format!("reuse completion {i} lacks a callback span"));
        }
    }
    if unfinished_d != 0 {
        return Err(format!(
            "reuse unfinished delta {unfinished_d} != 0 (expected-complete)"
        ));
    }
    Ok(())
}

/// Real-cryptd op shape (P4 adapter-shape-strict): every traffic
/// op is an `encrypt-cryptd` that queued (`-EINPROGRESS`) and
/// completed clean (terminal 0, no progress — single in-flight, and
/// the quiescence gate refuses a guest whose shared cryptd queue
/// carries foreign backlog). At least one op ran (a refusal-only
/// run proves no real path and must not pass vacuously).
///
/// Real cryptd wraps each op in transcript-invisible kernel
/// traffic (audited `crypto/cryptd.c`, identical 7.0.14/7.2.6):
/// one inner sync child submit per op (the single-child-call
/// shape — op lanes pin 2× the transcript ops), and one NESTED
/// owner completion per op (the cryptd completion synchronously
/// invokes the owner's — callback lanes pin [N, N], cryptd-first
/// by call nesting, and the loss gate pins `duplicate == N`).
/// Post-finish: N `Callback(0)` (outer ids) + N `Sync(0)` (inner
/// child ids), every record with a span, joined as a SET (arrival
/// order across ids is not positional), nothing unfinished.
///
/// Transform lifetimes are NOT graded here: cryptd-instance
/// internals (child/spawn allocs, free cascades) are invisible to
/// the transcript, T07-sealed, and version-sensitive — the other
/// canary cells gate tfm strictly, and this cell receipts the tfm
/// counters for the record.
fn verdict_op_cryptd(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    unfinished_d: u64,
) -> Result<(), String> {
    if truth.ops.is_empty() {
        return Err(format!(
            "{scenario} ran no traffic ops (refusal-only proves no real path)"
        ));
    }
    for op in &truth.ops {
        if op.op != "encrypt-cryptd" {
            return Err(format!(
                "{scenario} runs `encrypt-cryptd`, fixture ran `{}`",
                op.op
            ));
        }
        let ret = truth
            .returns
            .iter()
            .find(|(seq, _)| *seq == op.seq)
            .map(|(_, errno)| *errno);
        if ret != Some(-115) {
            return Err(format!(
                "cryptd op seq {} return {ret:?} != -EINPROGRESS",
                op.seq
            ));
        }
        let term = truth
            .terminals
            .iter()
            .find(|(seq, _)| *seq == op.seq)
            .map(|(_, errno)| *errno);
        if term != Some(0) {
            return Err(format!("cryptd op seq {} terminal {term:?} != 0", op.seq));
        }
    }
    if !truth.progresses.is_empty() {
        return Err(format!(
            "cryptd fixture progresses {:?} != [] (foreign backlog voids the run)",
            truth.progresses
        ));
    }
    // Admission lockstep (arm-local — the generic pin counts
    // transcript ops only): 2N decoded submits (outer + inner),
    // one reducer id per decoded submit, all emitted post-finish.
    let n = truth.ops.len() as u64;
    let sub = |a: u64, b: u64| {
        a.checked_sub(b)
            .ok_or_else(|| "counter ran backwards".to_owned())
    };
    let admitted_d = sub(view.decode.admitted, view.baseline.decode.admitted)?;
    if admitted_d != 2 * n {
        return Err(format!("cryptd admitted delta {admitted_d} != 2× {n} ops"));
    }
    let reducer_admitted_d = sub(view.reducer.admitted, view.baseline.reducer.admitted)?;
    if reducer_admitted_d != admitted_d {
        return Err(format!(
            "cryptd reducer admitted {reducer_admitted_d} != decode admitted {admitted_d}"
        ));
    }
    let emitted_d = sub(view.reducer.emitted, view.baseline.reducer.emitted)?;
    if emitted_d != admitted_d {
        return Err(format!(
            "cryptd emitted {emitted_d} != admitted {admitted_d}"
        ));
    }
    // Op lanes: outer + inner-sync-child submits per op (the
    // transcript counts outers only — the 2× is the audited
    // kernel shape, and any drift (extra child calls, an async
    // child queuing instead) breaks it loud).
    let enc_sub = sub(view.edge_hits[0], view.baseline.edge_hits[0])?;
    let enc_ret = sub(view.edge_hits[1], view.baseline.edge_hits[1])?;
    if (enc_sub, enc_ret) != (2 * n, 2 * n) {
        return Err(format!(
            "cryptd op lanes ({enc_sub}, {enc_ret}) != (2N, 2N) for {n} ops"
        ));
    }
    // Callback lanes: cryptd-first + nested-owner per op.
    let cb_cryptd = sub(view.edge_hits[16], view.baseline.edge_hits[16])?;
    let cb_kxc = sub(view.edge_hits[17], view.baseline.edge_hits[17])?;
    if (cb_cryptd, cb_kxc) != (n, n) {
        return Err(format!(
            "cryptd callback lanes ({cb_cryptd}, {cb_kxc}) != ({n}, {n})"
        ));
    }
    // Completions: outer callbacks + inner syncs, as a set.
    if view.completed.len() != 2 * truth.ops.len() {
        return Err(format!(
            "cryptd post-finish completed {} != 2× {} ops",
            view.completed.len(),
            truth.ops.len()
        ));
    }
    let mut terms: Vec<Terminal> = view.completed.iter().map(|r| r.terminal).collect();
    terms.sort_by_key(|t| match t {
        Terminal::Sync(_) => 0,
        Terminal::Callback(_) => 1,
        Terminal::Unknown => 2,
    });
    let mut want: Vec<Terminal> = Vec::with_capacity(2 * truth.ops.len());
    want.extend(std::iter::repeat_n(Terminal::Sync(0), truth.ops.len()));
    want.extend(std::iter::repeat_n(Terminal::Callback(0), truth.ops.len()));
    if terms != want {
        return Err(format!(
            "cryptd terminals {terms:?} != [Sync(0)×{n}, Callback(0)×{n}]"
        ));
    }
    for (i, record) in view.completed.iter().enumerate() {
        if record.duration_ns.is_none() {
            return Err(format!("cryptd completion {i} lacks a span"));
        }
    }
    if unfinished_d != 0 {
        return Err(format!(
            "cryptd unfinished delta {unfinished_d} != 0 (expected-complete)"
        ));
    }
    Ok(())
}

/// Op-negative shape: the sensor completes NOTHING here —
/// transform-only scenarios run zero ops, and `authsize`'s op is
/// an unhooked AEAD encrypt (any completion would be a phantom).
fn verdict_op_negative(
    scenario: &str,
    truth: &FixtureTruth,
    view: &SensorView<'_>,
) -> Result<(), String> {
    if scenario == "authsize" {
        if truth.ops.len() != 1 {
            return Err(format!(
                "authsize runs 1 (unhooked) op, fixture ran {}",
                truth.ops.len()
            ));
        }
        // Exact label (T07-R2-04: the AEAD leg encrypts — a
        // mislabeled transcript never grades the negative
        // control).
        if truth.ops[0].op != "encrypt" {
            return Err(format!(
                "authsize runs `encrypt`, fixture ran `{}`",
                truth.ops[0].op
            ));
        }
    } else if scenario == "failed-alloc" || scenario == "failed-init" {
        if !truth.ops.is_empty() {
            return Err(format!("{scenario}: failed scenario ran ops"));
        }
        // Probes are expected here — counted in `verdict_tfm_failed`.
    } else if !truth.ops.is_empty() || !truth.probes.is_empty() {
        return Err(format!(
            "{scenario}: transform-only scenario ran ops/probes"
        ));
    }
    if !view.completed.is_empty() {
        return Err(format!(
            "{scenario}: {} phantom completions observed",
            view.completed.len()
        ));
    }
    Ok(())
}

/// Sk transform shape (T07-R2-04): per-lifetime correlation
/// (provenance, retirement, ambiguity, config scalars) plus
/// ledger-derived stat deltas. `expect_ambiguous` is true only
/// for shared-release's retained-then-final lifetime.
/// Shared lifetime pairing: each fixture alloc joins one fresh
/// sensor generation, checked pairwise (T07-R3).
fn verdict_tfm_lifetimes(
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    expect_ambiguous: bool,
) -> Result<(), String> {
    let fresh = fresh_generations(truth, view)?;
    for (alloc, generation) in truth.allocs.iter().zip(fresh.iter()) {
        verdict_lifetime_sk(truth, alloc, generation, expect_ambiguous)?;
    }
    Ok(())
}

fn verdict_tfm_sk(
    truth: &FixtureTruth,
    view: &SensorView<'_>,
    expect_ambiguous: bool,
) -> Result<(), String> {
    verdict_tfm_lifetimes(truth, view, expect_ambiguous)?;
    let frees = truth.frees.len() as u64;
    let finals = truth.frees.iter().filter(|f| f.final_free).count() as u64;
    let configs = truth.configs.len() as u64;
    let failed_configs = truth.configs.iter().filter(|c| c.errno != 0).count() as u64;
    let allocs = truth.allocs.len() as u64;
    let tfm = &view.tfm;
    let base = &view.baseline.tfm;
    // T07-R3-12: permitted digest inventory carries one admitted
    // attempt + one release per pair (never completed/retired).
    let unknown_d = unknown_inventory_d(view)?;
    let expect = [
        (
            "admitted",
            allocs + frees + configs + unknown_d,
            tfm.admitted,
            base.admitted,
        ),
        ("completed", allocs, tfm.completed, base.completed),
        ("releases", frees + unknown_d, tfm.releases, base.releases),
        ("retired", finals, tfm.retired, base.retired),
        (
            "configs_joined",
            configs,
            tfm.configs_joined,
            base.configs_joined,
        ),
        (
            "configs_failed",
            failed_configs,
            tfm.configs_failed,
            base.configs_failed,
        ),
        ("failed_allocs", 0, tfm.failed_allocs, base.failed_allocs),
        (
            "ambiguous_releases",
            frees - finals,
            tfm.ambiguous_releases,
            base.ambiguous_releases,
        ),
        (
            "unobserved_boundary",
            0,
            tfm.unobserved_boundary,
            base.unobserved_boundary,
        ),
    ];
    for (name, want, got, got_base) in expect {
        let d = delta(got, got_base, name)?;
        if d != want {
            return Err(format!("tfm {name} delta {d} != {want} (fixture-derived)"));
        }
    }
    // Clean sk lifetimes chain exactly (every boundary observed);
    // the shared intermediate voids BY DESIGN (asserted false by
    // its arm — the predicate must say so).
    if !expect_ambiguous && !view.reuse_exact {
        return Err("clean sk lifetimes must chain exactly".to_owned());
    }
    Ok(())
}

/// AEAD transform shape (T07-R2-04): the narrowed contract —
/// allocation unhooked (no alloc halves, config admission shapes
/// the generations), everything else ledger-derived. The
/// first-seen admission is EXPECTED truth here (asserted
/// exactly), never gated loss.
fn verdict_tfm_aead(truth: &FixtureTruth, view: &SensorView<'_>) -> Result<(), String> {
    let fresh = fresh_generations(truth, view)?;
    for (alloc, generation) in truth.allocs.iter().zip(fresh.iter()) {
        verdict_lifetime_aead(truth, alloc, generation)?;
    }
    let frees = truth.frees.len() as u64;
    let finals = truth.frees.iter().filter(|f| f.final_free).count() as u64;
    let configs = truth.configs.len() as u64;
    let failed_configs = truth.configs.iter().filter(|c| c.errno != 0).count() as u64;
    let allocs = truth.allocs.len() as u64;
    let tfm = &view.tfm;
    let base = &view.baseline.tfm;
    // T07-R3-12: permitted digest inventory (see the sk arm).
    let unknown_d = unknown_inventory_d(view)?;
    let expect = [
        (
            "admitted",
            frees + configs + unknown_d,
            tfm.admitted,
            base.admitted,
        ),
        ("completed", 0, tfm.completed, base.completed),
        ("releases", frees + unknown_d, tfm.releases, base.releases),
        ("retired", finals, tfm.retired, base.retired),
        (
            "configs_joined",
            configs,
            tfm.configs_joined,
            base.configs_joined,
        ),
        (
            "configs_failed",
            failed_configs,
            tfm.configs_failed,
            base.configs_failed,
        ),
        ("failed_allocs", 0, tfm.failed_allocs, base.failed_allocs),
        (
            "ambiguous_releases",
            0,
            tfm.ambiguous_releases,
            base.ambiguous_releases,
        ),
        (
            "unobserved_boundary",
            allocs,
            tfm.unobserved_boundary,
            base.unobserved_boundary,
        ),
    ];
    for (name, want, got, got_base) in expect {
        let d = delta(got, got_base, name)?;
        if d != want {
            return Err(format!("tfm {name} delta {d} != {want} (fixture-derived)"));
        }
    }
    if view.reuse_exact {
        return Err("authsize: first-seen admission must void exactness".to_owned());
    }
    Ok(())
}

/// Failed-allocation shape (T07-R2-04/F03): the attempt observed
/// and classified, zero generations (no phantom from an ERR
/// return), exactness intact (a classified failure is truth, not
/// boundary uncertainty).
fn verdict_tfm_failed(truth: &FixtureTruth, view: &SensorView<'_>) -> Result<(), String> {
    if !truth.allocs.is_empty() || !truth.frees.is_empty() || !truth.configs.is_empty() {
        return Err("failed scenario recorded alloc/free/config rows".to_owned());
    }
    if truth.probes.len() != 1 {
        return Err(format!(
            "failed scenario ran {} probes, want 1",
            truth.probes.len()
        ));
    }
    // Zero allocs ⇒ zero fresh generations (any generation here
    // is a phantom from the ERR return — the count check names
    // it).
    let _fresh = fresh_generations(truth, view)?;
    let tfm = &view.tfm;
    let base = &view.baseline.tfm;
    let failed_d = delta(tfm.failed_allocs, base.failed_allocs, "failed_allocs")?;
    if failed_d != 1 {
        return Err(format!("tfm failed_allocs delta {failed_d} != 1 probe"));
    }
    // T07-R3-12: permitted digest inventory (one admitted attempt +
    // one release per pair — the probe attempt itself stays exact).
    let unknown_d = unknown_inventory_d(view)?;
    let admitted_d = delta(tfm.admitted, base.admitted, "admitted")?;
    if admitted_d != 1 + unknown_d {
        return Err(format!(
            "tfm admitted delta {admitted_d} != 1 attempt + {unknown_d} inventory"
        ));
    }
    let completed_d = delta(tfm.completed, base.completed, "completed")?;
    if completed_d != 1 {
        return Err(format!("tfm completed delta {completed_d} != 1 attempt"));
    }
    // Nothing else may account: no retires, no joined configs from
    // an allocation that never happened; releases carry exactly
    // the permitted inventory.
    for (name, want, got, got_base) in [
        ("releases", unknown_d, tfm.releases, base.releases),
        ("retired", 0, tfm.retired, base.retired),
        ("configs_joined", 0, tfm.configs_joined, base.configs_joined),
        ("configs_failed", 0, tfm.configs_failed, base.configs_failed),
    ] {
        let d = delta(got, got_base, name)?;
        if d != want {
            return Err(format!("tfm {name} delta {d} != {want} (failed alloc)"));
        }
    }
    if !view.reuse_exact {
        return Err("failed alloc must not void exactness (classified truth)".to_owned());
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
    use kryprobe_core::kcrypto::{LifecycleFamily, OpDirection, RequestMeta};

    /// P3 submit metadata for synthetic canary records (entry-side
    /// scalars; the canary reconciles identity/counts, not metadata).
    fn test_meta() -> RequestMeta {
        RequestMeta {
            family: LifecycleFamily::Skcipher,
            direction: OpDirection::Encrypt,
            cryptlen: Some(16),
            req_flags: Some(0),
            epoch: Some(0),
        }
    }

    /// Real sync transcript shape (alloc/config/submit/return/
    /// terminal/free/done — the setup setkey rides its own config
    /// row since T07-R2-04).
    fn sync_text() -> String {
        let run = "run-sync-once";
        [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-sync-t06a","drv":"kxcipher-sync-t06a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
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

    /// The sync fixture's one lifetime as the sensor observes
    /// it: alloc-observed provenance, one setup setkey (epoch 1),
    /// proved final retire.
    /// Three sync-shaped generations with explicit IDs (T07-R3-03:
    /// the verdict must see distinct ordered IDs — three copies of
    /// `sync_gen()`'s shared `id: 1` no longer pass a multi-lifetime
    /// pairing).
    fn sync_gens3(a: u64, b: u64, c: u64) -> [GenerationInfo; 3] {
        let mut gens = [sync_gen(), sync_gen(), sync_gen()];
        gens[0].id = a;
        gens[1].id = b;
        gens[2].id = c;
        gens
    }

    fn sync_gen() -> GenerationInfo {
        GenerationInfo {
            id: 1,
            req_name: "kxcipher-sync-t06a".to_owned(),
            alg_type: 0,
            alg_mask: 0,
            drv_name: "kxcipher-sync-t06a".to_owned(),
            name_truncated: false,
            drv_truncated: false,
            first_seen: false,
            retired: true,
            ambiguous: false,
            epoch: 1,
            configs: 1,
            last_config_site: LTFM_SITE_SETKEY_SK,
            last_config_len: 16,
            last_config_errno: 0,
        }
    }

    fn sync_view<'a>(
        completed: &'a [RequestRecord],
        generations: &'a [GenerationInfo],
    ) -> SensorView<'a> {
        // Pre-GO misses (equal baseline/final absolutes) pass: the
        // gate owns post-baseline deltas only.
        let misses = vec![miss_abs("fsession/a", 11, 3), miss_abs("fsession/b", 12, 0)];
        SensorView {
            completed,
            edge_hits: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            decode: DecodeStats {
                admitted: 2,
                ..DecodeStats::default()
            },
            reducer: ReducerStats {
                admitted: 2,
                emitted: 2,
                ..ReducerStats::default()
            },
            adapter: AdapterStats::default(),
            kernel_loss: [0; 5],
            agg_accepted: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            retained_dropped: 0,
            baseline: SensorBaseline {
                prog_misses: misses.clone(),
                ..SensorBaseline::default()
            },
            quiet_backlog_bytes: 0,
            view_valid: true,
            attached_links: 7,
            foreign_links: 0,
            prog_misses: misses,
            tfm: TfmStats {
                admitted: 3,
                completed: 1,
                releases: 1,
                retired: 1,
                configs_joined: 1,
                ..TfmStats::default()
            },
            generations,
            reuse_exact: true,
        }
    }

    fn record(id: u64, terminal: Terminal) -> RequestRecord {
        RequestRecord {
            id,
            tfm_id: None,
            terminal,
            duration_ns: Some(100),
            meta: test_meta(),
        }
    }

    /// One burst lifetime transcript row-set (alloc + setup config +
    /// proved free) at `seq`.
    fn burst_rows(run: &str, seq: u64) -> Vec<String> {
        vec![
            format!(
                r#"{{"v":1,"run":"{run}","seq":{seq},"phase":"alloc","req":"kxcipher-sync-t06a","drv":"kxcipher-sync-t06a","type":0,"mask":0}}"#
            ),
            format!(
                r#"{{"v":1,"run":"{run}","seq":{seq},"phase":"config","op":"setkey","errno":0,"len":16}}"#
            ),
            format!(r#"{{"v":1,"run":"{run}","seq":{seq},"phase":"free","final":true}}"#),
        ]
    }

    #[test]
    fn verdict_reuse_burst_pairs_many_lifetimes() {
        // T07-R2-04: three sequential lifetimes pair by index
        // (provenance, retirement, epochs each) and chain exactly
        // (unit-scale stand-in — the guest proves 1,000).
        let run = "run-reuse-burst";
        let mut rows = Vec::new();
        for seq in [1u64, 2, 3] {
            rows.extend(burst_rows(run, seq));
        }
        rows.push(format!(
            r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#
        ));
        let truth = parse_transcript(&rows.join("\n"), run).expect("burst parses");
        assert_eq!(truth.allocs.len(), 3);
        // T07-R3-03: the positive fixture carries distinct ordered
        // IDs — the verdict must pin the tracker's monotonic mint.
        let gens = sync_gens3(1, 2, 3);
        let completed: [RequestRecord; 0] = [];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 9;
        view.tfm.completed = 3;
        view.tfm.releases = 3;
        view.tfm.retired = 3;
        view.tfm.configs_joined = 3;
        verdict("reuse-burst", &truth, &view).expect("burst pairs green");
        // A provenance lie on lifetime 3 fails, naming it.
        let mut bad_gens = sync_gens3(1, 2, 3);
        bad_gens[2].drv_name = "wrong-driver".to_owned();
        let mut view = sync_view(&completed, &bad_gens);
        view.edge_hits = [0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 9;
        view.tfm.completed = 3;
        view.tfm.releases = 3;
        view.tfm.retired = 3;
        view.tfm.configs_joined = 3;
        let err = verdict("reuse-burst", &truth, &view).expect_err("drv lie must fail");
        assert!(err.contains("alloc seq 3"), "names the lifetime: {err}");
        // T07-R3-03: duplicate, unordered, and zero generation IDs
        // fail — the verdict pins nonzero, distinct, ordered IDs,
        // not just row count and metadata.
        for (ids, why) in [
            ((1, 1, 1), "duplicate"),
            ((1, 3, 2), "unordered"),
            ((0, 1, 2), "zero"),
        ] {
            let gens = sync_gens3(ids.0, ids.1, ids.2);
            let mut view = sync_view(&completed, &gens);
            view.edge_hits = [0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
            view.agg_accepted = [0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0];
            view.decode.admitted = 0;
            view.reducer.admitted = 0;
            view.reducer.emitted = 0;
            view.tfm.admitted = 9;
            view.tfm.completed = 3;
            view.tfm.releases = 3;
            view.tfm.retired = 3;
            view.tfm.configs_joined = 3;
            let err =
                verdict("reuse-burst", &truth, &view).expect_err(&format!("{why} IDs must fail"));
            assert!(err.contains("generation id"), "names it: {err}");
        }
    }

    #[test]
    fn verdict_generation_ids_must_not_reuse_baseline() {
        // T07-R3-03 / astra R3-05: a fresh generation reusing a
        // baseline ID fails (no separation); a fresh ID above the
        // baseline passes. The sync fixture carries one lifetime.
        let truth = sync_truth();
        assert_eq!(truth.allocs.len(), 1);
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let mut fresh = sync_gen();
        fresh.id = 1;
        let gens = [sync_gen(), fresh];
        let mut view = sync_view(&completed, &gens);
        view.baseline.generations_len = 1;
        let err = verdict("sync-once", &truth, &view).expect_err("baseline reuse must fail");
        assert!(err.contains("generation id"), "names it: {err}");
        // Positive control: the same shape with a separated fresh
        // ID passes.
        let mut fresh = sync_gen();
        fresh.id = 2;
        let gens = [sync_gen(), fresh];
        let mut view = sync_view(&completed, &gens);
        view.baseline.generations_len = 1;
        verdict("sync-once", &truth, &view).expect("separated fresh ID passes");
    }

    #[test]
    fn verdict_shared_release_expects_ambiguous_retire() {
        // T07-R2-04: retained release then proved final — the
        // generation retires WITH the ambiguity flag surviving
        // (truthful history, asserted exactly).
        let run = "run-shared-release";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-sync-t06a","drv":"kxcipher-sync-t06a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":false}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("shared parses");
        let mut shared = sync_gen();
        shared.ambiguous = true;
        let gens = [shared];
        let completed: [RequestRecord; 0] = [];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 1, 1, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 1, 1, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 1;
        view.tfm.releases = 2;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 1;
        view.tfm.ambiguous_releases = 1;
        view.reuse_exact = false;
        verdict("shared-release", &truth, &view).expect("shared green");
        // A non-ambiguous flag on the shared lifetime fails.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 1, 1, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 1, 1, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 1;
        view.tfm.releases = 2;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 1;
        view.tfm.ambiguous_releases = 1;
        view.reuse_exact = false;
        let err = verdict("shared-release", &truth, &view).expect_err("clean flag must fail");
        assert!(err.contains("ambiguous"), "names it: {err}");
    }

    #[test]
    fn verdict_authsize_pins_narrowed_contract() {
        // T07-R2-04: the AEAD lifetime is first-seen with EMPTY
        // provenance (alloc unhooked — honest unknown), the op
        // unobserved (negative control), epochs/configs exact, and
        // exactness void (the admission says so).
        let run = "run-authsize";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxc-aead-t07a","drv":"kxc-aead-t07a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setauthsize","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setauthsize","errno":-22,"len":64}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("authsize parses");
        let gens = [GenerationInfo {
            req_name: String::new(),
            drv_name: String::new(),
            first_seen: true,
            epoch: 2,
            configs: 3,
            last_config_site: LTFM_SITE_SETAUTHSIZE,
            last_config_len: 64,
            last_config_errno: -22,
            ..sync_gen()
        }];
        let completed: [RequestRecord; 0] = [];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 0;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 3;
        view.tfm.configs_failed = 1;
        view.tfm.unobserved_boundary = 1;
        view.reuse_exact = false;
        verdict("authsize", &truth, &view).expect("authsize green");
        // Claimed exactness on a first-seen admission fails.
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 0;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 3;
        view.tfm.configs_failed = 1;
        view.tfm.unobserved_boundary = 1;
        view.reuse_exact = true;
        verdict("authsize", &truth, &view).expect_err("false exactness must fail");
        // T07-R3-07: fabricated creation metadata on a first-seen
        // AEAD generation fails — unknown provenance means the
        // type/mask stay zero and neither truncation bit is set.
        let mut fb = gens.clone();
        fb[0].alg_type = 5;
        let mut view = sync_view(&completed, &fb);
        view.edge_hits = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 0;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 3;
        view.tfm.configs_failed = 1;
        view.tfm.unobserved_boundary = 1;
        view.reuse_exact = false;
        let err = verdict("authsize", &truth, &view).expect_err("fabricated type must fail");
        assert!(err.contains("type/mask"), "names it: {err}");
        let mut fb = gens.clone();
        fb[0].alg_mask = 0x8f;
        let mut view = sync_view(&completed, &fb);
        view.edge_hits = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 0;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 3;
        view.tfm.configs_failed = 1;
        view.tfm.unobserved_boundary = 1;
        view.reuse_exact = false;
        verdict("authsize", &truth, &view).expect_err("fabricated mask must fail");
        let mut fb = gens.clone();
        fb[0].name_truncated = true;
        let mut view = sync_view(&completed, &fb);
        view.edge_hits = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 0;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 3;
        view.tfm.configs_failed = 1;
        view.tfm.unobserved_boundary = 1;
        view.reuse_exact = false;
        verdict("authsize", &truth, &view).expect_err("truncation claim must fail");
        let mut fb = gens.clone();
        fb[0].drv_truncated = true;
        let mut view = sync_view(&completed, &fb);
        view.edge_hits = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 2, 0, 0, 1, 1, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 4;
        view.tfm.completed = 0;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 3;
        view.tfm.configs_failed = 1;
        view.tfm.unobserved_boundary = 1;
        view.reuse_exact = false;
        verdict("authsize", &truth, &view).expect_err("drv truncation claim must fail");
    }

    #[test]
    fn verdict_failed_alloc_classifies_without_phantoms() {
        // T07-R2-04/F03: the failed attempt observed and classified
        // (lanes + failed_allocs), zero generations, exactness
        // intact — a phantom gen or a missed classification fails.
        let run = "run-failed-alloc";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"submit","op":"alloc-probe"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"return","errno":-2}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"terminal","errno":-2}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("probe parses");
        assert_eq!(truth.probes, vec![1]);
        assert!(truth.ops.is_empty() && truth.allocs.is_empty());
        let gens: [GenerationInfo; 0] = [];
        let completed: [RequestRecord; 0] = [];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 1;
        view.tfm.completed = 1;
        view.tfm.failed_allocs = 1;
        view.tfm.releases = 0;
        view.tfm.retired = 0;
        view.tfm.configs_joined = 0;
        verdict("failed-alloc", &truth, &view).expect("failed probe green");
        // A phantom generation from the ERR return fails.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 1;
        view.tfm.completed = 1;
        view.tfm.failed_allocs = 1;
        view.tfm.releases = 0;
        view.tfm.retired = 0;
        view.tfm.configs_joined = 0;
        let err = verdict("failed-alloc", &truth, &view).expect_err("phantom must fail");
        assert!(
            err.contains("fresh generations 1 != 0 fixture allocs"),
            "names it: {err}"
        );
    }

    #[test]
    fn verdict_rekey_epochs_and_errno() {
        // T07-R2-04: two setkeys (one ok, one short-key EINVAL)
        // epoch once, record the failing tail exactly.
        let run = "run-rekey";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-sync-t06a","drv":"kxcipher-sync-t06a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":-22,"len":7}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("rekey parses");
        let gens = [GenerationInfo {
            epoch: 1,
            configs: 2,
            last_config_site: LTFM_SITE_SETKEY_SK,
            last_config_len: 7,
            last_config_errno: -22,
            ..sync_gen()
        }];
        let completed = [record(1, Terminal::Sync(0))];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [1, 1, 0, 0, 1, 1, 1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [1, 1, 0, 0, 1, 1, 1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 1;
        view.reducer.admitted = 1;
        view.reducer.emitted = 1;
        view.tfm.admitted = 4;
        view.tfm.completed = 1;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 2;
        view.tfm.configs_failed = 1;
        verdict("rekey", &truth, &view).expect("rekey green");
    }

    #[test]
    fn parse_rejects_transform_inconsistencies() {
        // T07-R2-04: frees/configs must reference recorded allocs,
        // alloc seqs must not collide with submits, config ops are
        // closed, and a rowless transcript has no positive control.
        let run = "run-sync-once";
        let dangling_free =
            sync_text().replace(r#""seq":1,"phase":"free""#, r#""seq":9,"phase":"free""#);
        assert!(parse_transcript(&dangling_free, run).is_err());
        let dangling_config =
            sync_text().replace(r#""seq":1,"phase":"config""#, r#""seq":9,"phase":"config""#);
        assert!(parse_transcript(&dangling_config, run).is_err());
        let colliding_alloc =
            sync_text().replace(r#""seq":1,"phase":"alloc""#, r#""seq":2,"phase":"alloc""#);
        assert!(parse_transcript(&colliding_alloc, run).is_err());
        let bad_op = sync_text().replace(r#""op":"setkey""#, r#""op":"rekey""#);
        assert!(parse_transcript(&bad_op, run).is_err());
        let rowless =
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#);
        let err = parse_transcript(&rowless, run).expect_err("rowless must fail");
        assert!(err.reason.contains("positive control"), "names it: {err}");
    }

    #[test]
    fn parse_rejects_impossible_lifetime_order() {
        // T07-R3-11 / astra R3-06: the canary entry point enforces
        // the testkit-equivalent lifetime order statefully, in row
        // order — a config after the final free, a free before its
        // alloc, or a repeated final free is an impossible history,
        // rejected before any `FixtureTruth` is produced (sharing
        // the testkit parser itself would invert the dev-dependency
        // direction — the canary binary cannot depend on testkit).
        let run = "run-sync-once";
        let text = sync_text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 10, "sync fixture shape");
        // Config-after-final: move the setup config (line 1) to
        // just after the final free (line 8), before done.
        let mut moved = lines.clone();
        let config = moved.remove(1);
        moved.insert(8, config);
        let err =
            parse_transcript(&moved.join("\n"), run).expect_err("config-after-final must fail");
        assert!(err.reason.contains("after final free"), "names it: {err}");
        // Free-before-alloc: move the final free (line 8) ahead of
        // the alloc (line 0).
        let mut moved = lines.clone();
        let free = moved.remove(8);
        moved.insert(0, free);
        let err =
            parse_transcript(&moved.join("\n"), run).expect_err("free-before-alloc must fail");
        assert!(err.reason.contains("before its alloc"), "names it: {err}");
        // Repeated final: a second final free after the first.
        let mut moved = lines.clone();
        moved.insert(9, lines[8]);
        let err = parse_transcript(&moved.join("\n"), run).expect_err("repeated final must fail");
        assert!(err.reason.contains("after final free"), "names it: {err}");
        // Positive control: a retained (non-final) free ahead of
        // the final free is a legal shared release, still parses.
        let shared = sync_text().replace(
            r#""seq":1,"phase":"free","final":true"#,
            r#""seq":1,"phase":"free","final":false"#,
        );
        let mut moved: Vec<&str> = shared.lines().collect();
        moved.insert(9, lines[8]);
        parse_transcript(&moved.join("\n"), run).expect("retained-then-final parses");
    }

    #[test]
    fn parse_accepts_valid_transcript() {
        let truth = sync_truth();
        assert_eq!(truth.ops.len(), 2);
        assert_eq!(truth.returns, vec![(2, 0), (3, 0)]);
        assert_eq!(truth.terminals, vec![(2, 0), (3, 0)]);
        // T07-R2-04: transform truth retained (one lifetime, one
        // setup setkey, one proved final release).
        assert_eq!(truth.allocs.len(), 1);
        assert_eq!(truth.allocs[0].req, "kxcipher-sync-t06a");
        assert_eq!(truth.allocs[0].drv, "kxcipher-sync-t06a");
        assert_eq!(truth.configs.len(), 1);
        assert_eq!(truth.configs[0].op, "setkey");
        assert_eq!(truth.configs[0].len, 16);
        assert_eq!(
            truth.frees,
            vec![FixtureFree {
                seq: 1,
                final_free: true
            }]
        );
        assert!(truth.probes.is_empty());
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
        verdict("sync-once", &truth, &sync_view(&completed, &[sync_gen()])).expect("sync green");
    }

    #[test]
    fn verdict_prog_miss_delta_fails() {
        // H2/M2 miss gate: a post-baseline recursion-miss delta
        // voids the run (a wholly skipped call leaves no edge and
        // no LLOSS — the gate is the only witness).
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
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
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
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
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
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
        let err = verdict("sync-once", &truth, &sync_view(&completed, &[sync_gen()]))
            .expect_err("status must join");
        assert!(err.contains("status -5"), "names the mismatch: {err}");
    }

    #[test]
    fn verdict_sync_unknown_terminal_fails() {
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Unknown)];
        verdict("sync-once", &truth, &sync_view(&completed, &[sync_gen()]))
            .expect_err("Unknown must fail sync");
    }

    #[test]
    fn verdict_async_expects_pending() {
        // P4: the async shape is callback-grounded now (T06 graded
        // the pending shape because completion was invisible).
        let run = "run-async-once";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t06a","drv":"kxcipher-async-t06a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("valid async transcript");
        let gens = [GenerationInfo {
            req_name: "kxcipher-async-t06a".to_owned(),
            drv_name: "kxcipher-async-t06a".to_owned(),
            ..sync_gen()
        }];
        let completed = [record(1, Terminal::Callback(0))];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.agg_accepted = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.decode.admitted = 1;
        view.reducer.admitted = 1;
        view.reducer.emitted = 1;
        view.reducer.unfinished = 0;
        verdict("async-once", &truth, &view).expect("async callback green");
        // An UNJOINED callback fails: the old pending shape no
        // longer grades — the scenario exists to prove the
        // adapter completes it.
        let completed = [record(1, Terminal::Unknown)];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 1;
        view.reducer.admitted = 1;
        view.reducer.emitted = 1;
        view.reducer.unfinished = 1;
        verdict("async-once", &truth, &view).expect_err("unjoined async must fail");
    }

    #[test]
    fn verdict_backlog_burst_pins_progress_and_order() {
        // P4: four encrypt-burst ops, EINPROGRESS + EBUSY × 3,
        // kernel progress on reqs 1..3, drain order
        // P1,T0,P2,T1,P3,T2,T3, four Callback(0) records.
        let run = "run-backlog-accepted";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t06a","drv":"kxcipher-async-t06a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt-burst"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"encrypt-burst"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"submit","op":"encrypt-burst"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":5,"phase":"submit","op":"encrypt-burst"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":-16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"return","errno":-16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":5,"phase":"return","errno":-16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"progress","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"progress","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":5,"phase":"progress","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":5,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("valid backlog transcript");
        let gens = [GenerationInfo {
            req_name: "kxcipher-async-t06a".to_owned(),
            drv_name: "kxcipher-async-t06a".to_owned(),
            ..sync_gen()
        }];
        let completed = [
            record(1, Terminal::Callback(0)),
            record(2, Terminal::Callback(0)),
            record(3, Terminal::Callback(0)),
            record(4, Terminal::Callback(0)),
        ];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [4, 4, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 7];
        view.agg_accepted = [4, 4, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 7];
        view.decode.admitted = 4;
        view.reducer.admitted = 4;
        view.reducer.emitted = 4;
        view.reducer.unfinished = 0;
        verdict("backlog-accepted", &truth, &view).expect("backlog green");
        // A reordered drain fails: swap the T0/T1 terminal rows
        // (progresses/terminals-as-sets still pass — only the
        // notify order breaks).
        let mut rows: Vec<&str> = text.lines().collect();
        rows.swap(11, 13);
        let text = rows.join("\n");
        let truth = parse_transcript(&text, run).expect("reordered parses");
        let err = verdict("backlog-accepted", &truth, &view).expect_err("reorder must fail");
        assert!(err.contains("notify order"), "names it: {err}");
    }

    #[test]
    fn verdict_no_backlog_burst_pins_exact_enospc() {
        // P4: submit 0 queues (callback terminal), submit 1
        // answers -ENOSPC immediately (sync terminal, exact).
        let run = "run-no-backlog-burst";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t06a","drv":"kxcipher-async-t06a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt-burst"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"encrypt-burst"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":-28}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":-28}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("valid no-backlog transcript");
        let gens = [GenerationInfo {
            req_name: "kxcipher-async-t06a".to_owned(),
            drv_name: "kxcipher-async-t06a".to_owned(),
            ..sync_gen()
        }];
        // Arrival order is NOT positional: the sync record may
        // precede the callback — the join is a set. Prove both
        // orders pass.
        for completed in [
            [
                record(1, Terminal::Sync(-28)),
                record(2, Terminal::Callback(0)),
            ],
            [
                record(1, Terminal::Callback(0)),
                record(2, Terminal::Sync(-28)),
            ],
        ] {
            let mut view = sync_view(&completed, &gens);
            view.edge_hits = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
            view.agg_accepted = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
            view.decode.admitted = 2;
            view.reducer.admitted = 2;
            view.reducer.emitted = 2;
            view.reducer.unfinished = 0;
            verdict("no-backlog-burst", &truth, &view).expect("no-backlog green");
        }
        // A rewritten errno fails: ENOSPC is exact, never EBUSY.
        let completed = [
            record(1, Terminal::Sync(-16)),
            record(2, Terminal::Callback(0)),
        ];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.agg_accepted = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.decode.admitted = 2;
        view.reducer.admitted = 2;
        view.reducer.emitted = 2;
        view.reducer.unfinished = 0;
        verdict("no-backlog-burst", &truth, &view).expect_err("rewrite must fail");
    }

    #[test]
    fn verdict_cryptd_async_pins_real_completions() {
        // P4: the A3 live shape — control alloc (untrafficked),
        // full-name cryptd alloc + op, async-masked alloc + op.
        let run = "run-cryptd-async";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"ecb(aes)","drv":"ecb-aes-aesni","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"alloc","req":"cryptd(ecb(aes-lib))","drv":"cryptd(ecb(aes-lib))","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"encrypt-cryptd"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"alloc","req":"ecb(aes)","drv":"cryptd(ecb(aes-lib))","type":133,"mask":143}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":5,"phase":"submit","op":"encrypt-cryptd"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":5,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":5,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("valid cryptd transcript");
        // Generations ungraded for cryptd (instance internals are
        // transcript-invisible) — the empty slice documents that.
        let gens: [GenerationInfo; 0] = [];
        // Live arrival order (7.2.6 cell): inner Sync, then outer
        // Callback, per op — the arm joins as a set, never
        // positionally.
        let completed = [
            record(1, Terminal::Sync(0)),
            record(2, Terminal::Callback(0)),
            record(3, Terminal::Sync(0)),
            record(4, Terminal::Callback(0)),
        ];
        let mut view = sync_view(&completed, &gens);
        // Live lane vector (7.2.6 cell): 2× op lanes (inner child),
        // [2, 2] callback lanes (nested), tfm lanes carry hidden
        // instance traffic (ungraded — receipted for the record).
        view.edge_hits = [4, 4, 0, 0, 3, 3, 9, 9, 4, 4, 0, 0, 0, 0, 0, 0, 2, 2];
        view.agg_accepted = [4, 4, 0, 0, 3, 3, 9, 9, 4, 4, 0, 0, 0, 0, 0, 0, 2, 2];
        view.decode.admitted = 4;
        view.reducer.admitted = 4;
        view.reducer.emitted = 4;
        view.reducer.duplicate = 2;
        view.reducer.unfinished = 0;
        verdict("cryptd-async", &truth, &view).expect("cryptd green");
        // A missing nested duplicate fails: the owner completion
        // never arrived (or never joined) — the carve-out pins
        // exactly N, never ≤N.
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [4, 4, 0, 0, 3, 3, 9, 9, 4, 4, 0, 0, 0, 0, 0, 0, 2, 2];
        view.agg_accepted = [4, 4, 0, 0, 3, 3, 9, 9, 4, 4, 0, 0, 0, 0, 0, 0, 2, 2];
        view.decode.admitted = 4;
        view.reducer.admitted = 4;
        view.reducer.emitted = 4;
        view.reducer.duplicate = 0;
        view.reducer.unfinished = 0;
        let err = verdict("cryptd-async", &truth, &view).expect_err("dup 0 must fail");
        assert!(err.contains("duplicate"), "names it: {err}");
        // Mixed bind + refusal (the 7.0 shape if the masked avenue
        // refuses): one traffic op + one alloc probe — probes ride
        // no op checks (parser-separated), the op pins 2×/dup 1.
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"ecb(aes)","drv":"ecb-aes-aesni","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"alloc","req":"cryptd(ecb(aes-lib))","drv":"cryptd(ecb(aes-lib))","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"encrypt-cryptd"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"submit","op":"alloc-probe"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"return","errno":-17}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":4,"phase":"terminal","errno":-17}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("mixed parses");
        let gens: [GenerationInfo; 0] = [];
        let completed = [
            record(1, Terminal::Sync(0)),
            record(2, Terminal::Callback(0)),
        ];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [2, 2, 0, 0, 3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1];
        view.agg_accepted = [2, 2, 0, 0, 3, 3, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1];
        view.decode.admitted = 2;
        view.reducer.admitted = 2;
        view.reducer.emitted = 2;
        view.reducer.duplicate = 1;
        view.reducer.unfinished = 0;
        verdict("cryptd-async", &truth, &view).expect("mixed cryptd green");
        // Refusal-only proves no real path: zero ops must fail,
        // never pass vacuously.
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"ecb(aes)","drv":"ecb-aes-aesni","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("refusal-only parses");
        let gens = [GenerationInfo {
            id: 1,
            req_name: "ecb(aes)".to_owned(),
            drv_name: "ecb-aes-aesni".to_owned(),
            epoch: 0,
            configs: 0,
            ..sync_gen()
        }];
        let completed: [RequestRecord; 0] = [];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 0;
        view.reducer.admitted = 0;
        view.reducer.emitted = 0;
        view.tfm.admitted = 2;
        view.tfm.completed = 1;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 0;
        verdict("cryptd-async", &truth, &view).expect_err("refusal-only must fail");
    }

    #[test]
    fn verdict_equation_and_loss_fail_loud() {
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        // Equation: agg 5 != hits 4 + reserve 0 + noslot 0.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.agg_accepted = [2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = verdict("sync-once", &truth, &view).expect_err("equation must hold");
        assert!(err.contains("reconciliation"), "names it: {err}");
        // Any loss counter fails.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.decode.stale_returns = 1;
        verdict("sync-once", &truth, &view).expect_err("stale must fail");
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.kernel_loss[2] = 1;
        verdict("sync-once", &truth, &view).expect_err("badkey must fail");
        // Close backlog fails.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.quiet_backlog_bytes = 40;
        verdict("sync-once", &truth, &view).expect_err("backlog must fail");
        // Backwards counters fail (no silent reset absorb).
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.baseline.edge_hits = [9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        verdict("sync-once", &truth, &view).expect_err("backwards must fail");
        // Fixture self-check failure fails.
        let mut truth = sync_truth();
        truth.fixture_result = -1;
        verdict("sync-once", &truth, &sync_view(&completed, &[sync_gen()]))
            .expect_err("fixture fail must fail");
    }

    #[test]
    fn verdict_transform_loss_fails_but_truth_passes() {
        // T07-05/R3: transform-lifetime loss deltas gate the run
        // (D4 refusal, dangling close, uncertain identity) while
        // truth-only transform traffic (proved retires, joined
        // configs incl. errno verdicts, classified failures) gates
        // nothing.
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.live_full = 1;
        let err = verdict("sync-once", &truth, &view).expect_err("D4 refusal must fail");
        assert!(err.contains("tfm_live_full"), "names it: {err}");
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.unfinished = 1;
        verdict("sync-once", &truth, &view).expect_err("dangling close must fail");
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.ambiguous_releases = 1;
        verdict("sync-once", &truth, &view).expect_err("ambiguity must fail");
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.unobserved_boundary = 1;
        verdict("sync-once", &truth, &view).expect_err("uncertain identity must fail");
        // T07-R3-02: a colliding destroy (unbound at a live base)
        // gates the run — indeterminate identity, never inventory.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.colliding_releases = 1;
        let err = verdict("sync-once", &truth, &view).expect_err("colliding must fail");
        assert!(err.contains("tfm_colliding_releases"), "names it: {err}");
        // Truth-only: the fixture's own lifetime (admitted 3 =
        // alloc + free + setup config, proved retire, one joined
        // config) + a classified no-op release pass the gate AND
        // the ledger-derived arms. (Classified failed allocs pass
        // via the failed scenarios — `verdict_tfm_failed`.)
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.admitted = 3;
        view.tfm.completed = 1;
        view.tfm.releases = 1;
        view.tfm.retired = 1;
        view.tfm.configs_joined = 1;
        view.tfm.configs_failed = 0;
        view.tfm.failed_allocs = 0;
        view.tfm.noop_releases = 1;
        verdict("sync-once", &truth, &view).expect("truth-only transform traffic green");
        // T07-R2-05, reconciled T07-R3-12: routine unbound
        // destroys (digest/shash background in the guest) gate
        // nothing — WITH their complete production baggage (one
        // admitted attempt, one release, one destroy submit/return
        // edge pair each: a counter-only view is not real
        // inventory). A missed identity that was USED still fails
        // via its admission.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.unknown_releases = 5;
        view.tfm.admitted += 5;
        view.tfm.releases += 5;
        view.edge_hits[6] += 5;
        view.edge_hits[7] += 5;
        view.agg_accepted[6] += 5;
        view.agg_accepted[7] += 5;
        verdict("sync-once", &truth, &view).expect("unbound destroys are inventory");
        // Partial baggage is NOT inventory: destroy edges without
        // the matching admitted attempts fail the equations (no
        // laundering through the reconciled counter).
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.unknown_releases = 5;
        view.edge_hits[6] += 5;
        view.edge_hits[7] += 5;
        view.agg_accepted[6] += 5;
        view.agg_accepted[7] += 5;
        verdict("sync-once", &truth, &view).expect_err("partial baggage must fail");
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.tfm.unknown_releases = 5;
        view.tfm.unobserved_boundary = 1;
        verdict("sync-once", &truth, &view).expect_err("used missed identity must fail");
    }

    #[test]
    fn verdict_equation_covers_transform_lanes() {
        // T07.2: the per-lane equation binds lanes 4+ exactly like
        // op lanes (fixture truth pins them since T07-R2-04 — and
        // every accepted transform edge must still be consumed
        // once).
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits[4] = 1;
        view.edge_hits[5] = 1;
        view.agg_accepted[4] = 1;
        view.agg_accepted[5] = 1;
        verdict("sync-once", &truth, &view).expect("matched transform lanes green");
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits[4] = 1;
        view.edge_hits[5] = 1;
        view.agg_accepted[4] = 2;
        view.agg_accepted[5] = 1;
        let err = verdict("sync-once", &truth, &view).expect_err("alloc-lane skew must fail");
        assert!(err.contains("reconciliation"), "names it: {err}");
    }

    #[test]
    fn verdict_void_identity_or_links_fail() {
        // W8/H4: a void M2 identity, a short link count, or any
        // foreign link on our targets fails the run — exact counts
        // are void without identity + retirement exclusion.
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.view_valid = false;
        let err = verdict("sync-once", &truth, &view).expect_err("void identity must fail");
        assert!(err.contains("identity"), "names it: {err}");
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.attached_links = 1;
        let err = verdict("sync-once", &truth, &view).expect_err("1 link must fail");
        assert!(err.contains("7 session links"), "names it: {err}");
        // Every earlier count is no longer a full attach: all 7
        // sites must be linked.
        for short in [2, 3, 4, 6] {
            let gens = [sync_gen()];
            let mut view = sync_view(&completed, &gens);
            view.attached_links = short;
            let err = verdict("sync-once", &truth, &view).expect_err("short attach must fail");
            assert!(err.contains("7 session links"), "names it: {err}");
        }
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
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
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.baseline.edge_hits = [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0];
        view.baseline.agg_accepted = [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0];
        view.baseline.decode.admitted = 7;
        view.baseline.reducer.admitted = 7;
        view.baseline.reducer.emitted = 7;
        view.edge_hits = [6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0];
        view.decode.admitted = 9;
        view.reducer.admitted = 9;
        view.reducer.emitted = 9;
        verdict("sync-once", &truth, &view).expect("pre-clear traffic tolerated");
        // ...but a loss inside the scenario window still fails even
        // with a dirty baseline.
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
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
                "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":1,\"phase\":\"alloc\",\"req\":\"kxcipher-sync-t06a\",\"drv\":\"kxcipher-sync-t06a\",\"type\":0,\"mask\":0}",
                "not json at all",
            ),
            sync_text().replace(
                "{\"v\":1,\"run\":\"run-sync-once\",\"seq\":1,\"phase\":\"alloc\",\"req\":\"kxcipher-sync-t06a\",\"drv\":\"kxcipher-sync-t06a\",\"type\":0,\"mask\":0}",
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
        // Round-4 minor (+T07-R2-04: alloc/free/config are oracle
        // evidence now): required fields validate either way — a
        // malformed row is a broken transcript (fixture.h contract).
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
        let err = verdict("sync-once", &truth, &sync_view(&completed, &[sync_gen()]))
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
        let err = verdict(
            "sync-once",
            &conflict,
            &sync_view(&completed, &[sync_gen()]),
        )
        .expect_err("terminal conflict must fail");
        assert!(err.contains("return/terminal mismatch"), "names it: {err}");
        // Per-lane reconciliation: permuted aggregates fail even
        // when totals match ([4,0,0,0] vs [1,1,1,1]).
        let gens = [sync_gen()];
        let mut view = sync_view(&completed, &gens);
        view.agg_accepted = [4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
            meta: test_meta(),
        }];
        let view = SensorView {
            completed: &completed,
            edge_hits: [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            agg_accepted: [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            kernel_loss: [0; 5],
            decode: DecodeStats {
                admitted: 1,
                ..DecodeStats::default()
            },
            adapter: AdapterStats::default(),
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
            attached_links: 7,
            foreign_links: 0,
            prog_misses: Vec::new(),
            tfm: TfmStats::default(),
            generations: &[],
            reuse_exact: true,
        };
        let err = verdict("async-once", &truth, &view).expect_err("foreign terminal must fail");
        assert!(err.contains("terminals"), "names it: {err}");
    }

    #[test]
    fn transcript_accepts_closed_fixture_label_set() {
        // T07-R2-04: every submit label the fixture emits parses
        // (the suffixed labels are encrypt flavors) while an
        // unknown label still refuses as drift.
        let run = "run-labels";
        let mut rows = Vec::new();
        for (i, op) in [
            "encrypt",
            "decrypt",
            "encrypt-exact",
            "encrypt-delayed",
            "encrypt-burst",
            "encrypt-early",
            "encrypt-reuse",
            "encrypt-reuse-cb",
        ]
        .iter()
        .enumerate()
        {
            let seq = i as u64 + 1;
            rows.push(format!(
                r#"{{"v":1,"run":"{run}","seq":{seq},"phase":"submit","op":"{op}"}}"#
            ));
            rows.push(format!(
                r#"{{"v":1,"run":"{run}","seq":{seq},"phase":"return","errno":0}}"#
            ));
            rows.push(format!(
                r#"{{"v":1,"run":"{run}","seq":{seq},"phase":"terminal","errno":0}}"#
            ));
        }
        rows.push(format!(
            r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#
        ));
        let truth = parse_transcript(&rows.join("\n"), run).expect("labels parse");
        let got: Vec<&str> = truth.ops.iter().map(|o| o.op.as_str()).collect();
        assert_eq!(
            got,
            [
                "encrypt",
                "decrypt",
                "encrypt-exact",
                "encrypt-delayed",
                "encrypt-burst",
                "encrypt-early",
                "encrypt-reuse",
                "encrypt-reuse-cb"
            ]
        );
        // Family classification: seven encrypt flavors hit lanes
        // 0/1, the decrypt hits 2/3.
        assert_eq!(truth.expected_hooks(), [7, 7, 1, 1]);
        // An unknown label refuses (never a default family).
        let bad = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"submit","op":"splice"}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let err = parse_transcript(&bad, run).expect_err("unknown label must fail");
        assert_eq!(err.reason, "unknown op name");
        assert_eq!(err.line, 1);
    }

    #[test]
    fn verdict_exact_driver_pins_encrypt_exact() {
        // T07-R2-04: `exact-driver` runs ONE `encrypt-exact` op on
        // the generically requested transform (the sensor sees the
        // async-pending shape + the resolved async provenance); a
        // transcript carrying plain `encrypt` grades against the
        // wrong shape and must fail naming the label.
        let run = "run-exact-driver";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher","drv":"kxcipher-async-t06a","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt-exact"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("exact transcript parses");
        let gens = [GenerationInfo {
            req_name: "kxcipher".to_owned(),
            drv_name: "kxcipher-async-t06a".to_owned(),
            ..sync_gen()
        }];
        let completed = [record(1, Terminal::Callback(0))];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.agg_accepted = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.decode.admitted = 1;
        view.reducer.admitted = 1;
        view.reducer.emitted = 1;
        view.reducer.unfinished = 0;
        verdict("exact-driver", &truth, &view).expect("exact-driver green");
        // Plain `encrypt` on this scenario is the wrong shape.
        let text = text.replace("encrypt-exact", "encrypt");
        let truth = parse_transcript(&text, run).expect("relabeled parses");
        let err = verdict("exact-driver", &truth, &view).expect_err("label lie must fail");
        assert!(err.contains("encrypt-exact"), "names the label: {err}");
    }

    #[test]
    fn verdict_sync_pins_submit_labels() {
        // T07-R2-04: `sync-once` runs exactly encrypt-then-decrypt;
        // a transcript with both submits relabeled still joins
        // seqs/errnos but grades the wrong path and must fail.
        let truth = sync_truth();
        let completed = [record(1, Terminal::Sync(0)), record(2, Terminal::Sync(0))];
        let gens = [sync_gen()];
        let view = sync_view(&completed, &gens);
        verdict("sync-once", &truth, &view).expect("sync labels green");
        let text = sync_text().replace(r#""op":"decrypt""#, r#""op":"encrypt""#);
        let truth = parse_transcript(&text, "run-sync-once").expect("relabeled parses");
        let gens = [sync_gen()];
        // A sensor view matching the RELABELED lanes sails the
        // edge-hits gate — the label pin must still catch it.
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        view.agg_accepted = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = verdict("sync-once", &truth, &view).expect_err("label lie must fail");
        assert!(err.contains("decrypt"), "names the label: {err}");
    }

    /// Async-flavored generation (fixture async driver, one setup
    /// setkey, proved final retire) for the P4r2 race arms.
    fn race_gen() -> GenerationInfo {
        GenerationInfo {
            req_name: "kxcipher-async-t09r".to_owned(),
            drv_name: "kxcipher-async-t09r".to_owned(),
            ..sync_gen()
        }
    }

    #[test]
    fn verdict_early_callback_forces_terminal_before_return() {
        // P4-N4: `early-callback` is ACCEPTED, and its fixture
        // FORCES terminal-before-return row order (inline
        // completion): the terminal row precedes the return row.
        // The sensor still joins exactly one Callback(0) with a
        // span, zero loss. A sequential transcript (return row
        // first) proves no race and must fail the arm.
        let run = "run-early-callback";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t09r","drv":"kxcipher-async-t09r","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt-early"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("early transcript parses");
        let gens = [race_gen()];
        let completed = [record(1, Terminal::Callback(0))];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.agg_accepted = [1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        view.decode.admitted = 1;
        view.reducer.admitted = 1;
        view.reducer.emitted = 1;
        view.reducer.unfinished = 0;
        verdict("early-callback", &truth, &view).expect("early-callback green");
        // Sequential row order (return before terminal) is the
        // unforced shape — the race arm must reject it.
        let seq_text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t09r","drv":"kxcipher-async-t09r","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt-early"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&seq_text, run).expect("sequential parses");
        let err = verdict("early-callback", &truth, &view).expect_err("unforced order must fail");
        assert!(err.contains("order"), "names the ordering: {err}");
    }

    #[test]
    fn verdict_reuse_in_callback_pins_nested_reuse() {
        // P4-N4: `reuse-in-callback` is ACCEPTED — the outer op's
        // terminal lands inline (before its return) and the SAME
        // callback resubmits the request storage (inner submit
        // before the outer return): nested reuse before unwind,
        // forced in row order. Both records join Callback(0) with
        // spans, zero loss, zero ambiguity. An inner submit AFTER
        // the outer return is sequential reuse, not the race.
        let run = "run-reuse-in-callback";
        let text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t09r","drv":"kxcipher-async-t09r","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt-reuse"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"encrypt-reuse-cb"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&text, run).expect("reuse transcript parses");
        let gens = [race_gen()];
        let completed = [
            record(1, Terminal::Callback(0)),
            record(2, Terminal::Callback(0)),
        ];
        let mut view = sync_view(&completed, &gens);
        view.edge_hits = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 2];
        view.agg_accepted = [2, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 2];
        view.decode.admitted = 2;
        view.reducer.admitted = 2;
        view.reducer.emitted = 2;
        view.reducer.unfinished = 0;
        verdict("reuse-in-callback", &truth, &view).expect("reuse-in-callback green");
        // Sequential reuse (inner submit after the outer return)
        // is not the race — the arm must reject it.
        let seq_text = [
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher-async-t09r","drv":"kxcipher-async-t09r","type":0,"mask":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"submit","op":"encrypt-reuse"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":2,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"submit","op":"encrypt-reuse-cb"}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"return","errno":-115}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":3,"phase":"terminal","errno":0}}"#),
            format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
            format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
        ]
        .join("\n");
        let truth = parse_transcript(&seq_text, run).expect("sequential parses");
        let err =
            verdict("reuse-in-callback", &truth, &view).expect_err("unforced order must fail");
        assert!(err.contains("order"), "names the ordering: {err}");
    }
}
