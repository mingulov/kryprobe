// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent fixture-ledger oracle (T04).
//!
//! Parses the kernel truth fixture's JSONL rows — written directly
//! by the provider/consumer, never derived from KryProbe aggregates,
//! decoder or counters — into per-request records for exact
//! per-invocation comparison.

use std::collections::HashSet;

/// One parsed request: its fixture sequence, terminal native errno
/// and callback notification count (progress + terminal rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRequest {
    /// Fixture invocation sequence.
    pub seq: u64,
    /// Native errno of the terminal row.
    pub terminal_errno: i32,
    /// Progress + terminal rows observed for this sequence.
    pub callbacks: u32,
}

/// One transform lifetime: allocation sequence, whether a free
/// row closed it, and the fixture's final-free flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerAlloc {
    /// Fixture sequence shared by the alloc/free pair.
    pub seq: u64,
    /// Whether the free row arrived.
    pub freed: bool,
    /// Fixture-reported final free (vs release at refcount > 1).
    pub final_free: bool,
}

/// A fully parsed run ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLedger {
    /// Run ID every row was checked against.
    pub run_id: String,
    /// Per-request records, in first-seen sequence order.
    pub requests: Vec<LedgerRequest>,
    /// Transform lifetimes, in first-seen sequence order.
    pub allocs: Vec<LedgerAlloc>,
    /// Whether a DONE row closed the run.
    pub done: bool,
}

/// Ledger rejection reasons. Any of these means the run's truth is
/// unusable — never a partial silent accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// A row is not valid JSON or lacks required fields.
    Malformed(String),
    /// A row belongs to a different run than `expected_run`.
    ForeignRunId {
        /// Run the caller asked to parse.
        expected: String,
        /// Run the offending row claims.
        found: String,
    },
    /// The same (sequence, phase) row appeared twice.
    DuplicateRow {
        /// Fixture invocation sequence.
        seq: u64,
        /// Repeated phase name.
        phase: String,
    },
    /// No DONE row closed the run.
    MissingDone,
    /// Phase order/content contradicts the fixture protocol
    /// (details in the message).
    PhaseInconsistency(String),
    /// A row reports a nonzero fixture overflow counter: truth was
    /// lost, the run is unusable.
    Overflow {
        /// Fixture invocation sequence (`u64::MAX` for run-level).
        seq: u64,
    },
    /// The fixture's own result is nonzero: truth from a failed
    /// fixture is rejected.
    NonzeroFixtureResult(i32),
}

/// In-progress per-sequence record while scanning rows.
struct Build {
    /// Fixture invocation sequence.
    seq: u64,
    /// Whether the submit row arrived (later phases require it).
    submitted: bool,
    /// Terminal errno once the terminal row arrives.
    terminal_errno: Option<i32>,
    /// Progress + terminal rows seen so far.
    callbacks: u32,
}

/// Sequence key for run-level rows (DONE), which carry no `seq`.
const RUN_LEVEL_SEQ: u64 = u64::MAX;

/// In-progress transform lifetime while scanning rows.
struct AllocBuild {
    /// Fixture sequence shared by the alloc/free pair.
    seq: u64,
    /// Whether the free row arrived.
    freed: bool,
    /// Fixture-reported final free.
    final_free: bool,
}

fn malformed(lineno: usize, msg: &str) -> LedgerError {
    LedgerError::Malformed(format!("line {}: {msg}", lineno + 1))
}

/// Parses `text` as the JSONL ledger of run `expected_run`.
///
/// Row schema (all objects, unknown fields ignored so the fixture
/// can grow): `v` (must be 1), `run` (must match), `phase` (one of
/// submit/return/progress/terminal/alloc/free/done), `seq` on every
/// phase but `done`, `errno` on terminal rows, optional `overflow`
/// counter (nonzero rejects), required `fixture_result` on the DONE
/// row (nonzero rejects), `final` flag on free rows.
///
/// Strictness is load-bearing: (sequence, phase) rows are unique
/// (a future multi-progress fixture relaxes this with its own
/// test), later request phases require a prior submit, free
/// requires a prior alloc, every alloc must close before DONE, and
/// the run must close with DONE.
pub fn parse_ledger(expected_run: &str, text: &str) -> Result<ParsedLedger, LedgerError> {
    let mut reqs: Vec<Build> = Vec::new();
    let mut alloc_builds: Vec<AllocBuild> = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();
    let mut done = false;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| malformed(lineno, &format!("invalid json: {e}")))?;
        if row.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
            return Err(malformed(lineno, "unsupported ledger version (want v:1)"));
        }
        let run = row
            .get("run")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| malformed(lineno, "missing run"))?;
        if run != expected_run {
            return Err(LedgerError::ForeignRunId {
                expected: expected_run.to_owned(),
                found: run.to_owned(),
            });
        }
        let phase = row
            .get("phase")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| malformed(lineno, "missing phase"))?;
        let seq = match phase {
            "done" => RUN_LEVEL_SEQ,
            "submit" | "return" | "progress" | "terminal" | "alloc" | "free" => row
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| malformed(lineno, "missing seq"))?,
            other => return Err(malformed(lineno, &format!("unknown phase {other:?}"))),
        };
        if let Some(overflow) = row.get("overflow") {
            let overflow = overflow
                .as_u64()
                .ok_or_else(|| malformed(lineno, "overflow is not a u64"))?;
            if overflow != 0 {
                return Err(LedgerError::Overflow { seq });
            }
        }
        if !seen.insert((seq, phase.to_owned())) {
            return Err(LedgerError::DuplicateRow {
                seq,
                phase: phase.to_owned(),
            });
        }
        match phase {
            "done" => {
                let result = row
                    .get("fixture_result")
                    .and_then(serde_json::Value::as_i64)
                    .ok_or_else(|| malformed(lineno, "done row missing fixture_result"))?;
                let result = i32::try_from(result)
                    .map_err(|_| malformed(lineno, "fixture_result out of i32 range"))?;
                if result != 0 {
                    return Err(LedgerError::NonzeroFixtureResult(result));
                }
                done = true;
            }
            "alloc" => {
                // Duplicate allocs are rejected by the seen-set
                // above, so no entry exists here.
                alloc_builds.push(AllocBuild {
                    seq,
                    freed: false,
                    final_free: false,
                });
            }
            "free" => {
                let entry = alloc_builds.iter_mut().find(|a| a.seq == seq);
                match entry {
                    Some(entry) => {
                        entry.freed = true;
                        entry.final_free =
                            row.get("final").and_then(serde_json::Value::as_bool) == Some(true);
                    }
                    None => {
                        return Err(LedgerError::PhaseInconsistency(format!(
                            "seq {seq} free arrived without alloc"
                        )));
                    }
                }
            }
            "submit" | "return" | "progress" | "terminal" => {
                let idx = match reqs.iter().position(|r| r.seq == seq) {
                    Some(i) => i,
                    None => {
                        reqs.push(Build {
                            seq,
                            submitted: false,
                            terminal_errno: None,
                            callbacks: 0,
                        });
                        reqs.len() - 1
                    }
                };
                if phase == "submit" {
                    reqs[idx].submitted = true;
                } else if !reqs[idx].submitted {
                    return Err(LedgerError::PhaseInconsistency(format!(
                        "seq {seq} {phase} arrived before submit"
                    )));
                }
                if phase == "progress" || phase == "terminal" {
                    reqs[idx].callbacks += 1;
                }
                if phase == "terminal" {
                    let errno = row
                        .get("errno")
                        .and_then(serde_json::Value::as_i64)
                        .ok_or_else(|| malformed(lineno, "terminal row missing errno"))?;
                    let errno = i32::try_from(errno)
                        .map_err(|_| malformed(lineno, "terminal errno out of i32 range"))?;
                    reqs[idx].terminal_errno = Some(errno);
                }
            }
            // Reachable only if the phase list above drifts from the
            // seq-extraction match: fail loudly, never silent accept.
            other => return Err(malformed(lineno, &format!("unhandled phase {other:?}"))),
        }
    }
    if !done {
        return Err(LedgerError::MissingDone);
    }
    let mut allocs = Vec::with_capacity(alloc_builds.len());
    for a in alloc_builds {
        if !a.freed {
            return Err(LedgerError::PhaseInconsistency(format!(
                "seq {} allocated but never freed",
                a.seq
            )));
        }
        allocs.push(LedgerAlloc {
            seq: a.seq,
            freed: true,
            final_free: a.final_free,
        });
    }
    let mut requests = Vec::with_capacity(reqs.len());
    for r in reqs {
        match r.terminal_errno {
            Some(errno) => requests.push(LedgerRequest {
                seq: r.seq,
                terminal_errno: errno,
                callbacks: r.callbacks,
            }),
            None => {
                return Err(LedgerError::PhaseInconsistency(format!(
                    "seq {} never reached terminal",
                    r.seq
                )));
            }
        }
    }
    Ok(ParsedLedger {
        run_id: expected_run.to_owned(),
        requests,
        allocs,
        done,
    })
}
