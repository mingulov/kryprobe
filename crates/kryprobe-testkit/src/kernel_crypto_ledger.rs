// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent fixture-ledger oracle (T04).
//!
//! Parses the kernel truth fixture's JSONL rows — written directly
//! by the provider/consumer, never derived from KryProbe aggregates,
//! decoder or counters — into per-request records for exact
//! per-invocation comparison.

use std::collections::HashSet;

/// One parsed request: its fixture sequence, submitted operation
/// label, recorded errnos and progress/terminal notification count.
///
/// A progress row is a waiter-side in-flight marker, never a kernel
/// callback; only the terminal row is the completion notification.
/// Every recorded errno is surfaced: altering any of them changes
/// the parsed result, so corrupted truth cannot validate unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRequest {
    /// Fixture invocation sequence.
    pub seq: u64,
    /// Operation label from the submit row (scenario tag).
    pub submit_op: String,
    /// Native errno of the submit-return row.
    pub return_errno: i32,
    /// Native errno of the progress row, if one was recorded.
    pub progress_errno: Option<i32>,
    /// Native errno of the terminal row.
    pub terminal_errno: i32,
    /// Progress + terminal rows observed for this sequence.
    pub notifications: u32,
}

/// One transform lifetime: allocation sequence, requested and
/// resolved driver names, whether a free row closed it, and the
/// fixture's final-free flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerAlloc {
    /// Fixture sequence shared by the alloc/free rows.
    pub seq: u64,
    /// Name the consumer requested (generic or exact driver).
    pub req_name: String,
    /// Driver the crypto API resolved.
    pub drv_name: String,
    /// Requested algorithm type mask (F02 provenance; `None`
    /// when the fixture row predates it — unknown, never zero).
    pub alg_type: Option<u32>,
    /// Requested algorithm mask (F02 provenance; `None` when
    /// the fixture row predates it — unknown, never zero).
    pub alg_mask: Option<u32>,
    /// Whether a free row arrived.
    pub freed: bool,
    /// Fixture-reported final free (last free row's flag: a
    /// refcount-retained release lands `false`, the proved final
    /// free lands `true`).
    pub final_free: bool,
    /// Free rows observed for this sequence (each put counts;
    /// a shared transform legitimately lands several).
    pub releases: u32,
}

/// One transform configuration: metadata-only truth (operation,
/// native result, length) — never key/tag/IV bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerConfig {
    /// Fixture sequence of the owning alloc row.
    pub seq: u64,
    /// Configuration operation (`setkey`, `setauthsize`).
    pub op: String,
    /// Native errno of the operation (0 on success; a failure
    /// is truth, never a dropped row).
    pub result_errno: i32,
    /// Metadata length the operation carried (key/authsize
    /// bytes offered — lengths only, never content).
    pub len: u32,
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
    /// Transform configurations, in row order.
    pub configs: Vec<LedgerConfig>,
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
    /// Operation label from the submit row.
    submit_op: Option<String>,
    /// Submit-return errno once the return row arrives.
    return_errno: Option<i32>,
    /// Progress errno once the progress row arrives, if ever.
    progress_errno: Option<i32>,
    /// Terminal errno once the terminal row arrives.
    terminal_errno: Option<i32>,
    /// Progress + terminal rows seen so far.
    notifications: u32,
}

/// Sequence key for run-level rows (DONE), which carry no `seq`.
const RUN_LEVEL_SEQ: u64 = u64::MAX;

/// In-progress transform lifetime while scanning rows.
struct AllocBuild {
    /// Fixture sequence shared by the alloc/free rows.
    seq: u64,
    /// Requested name from the alloc row.
    req_name: String,
    /// Resolved driver from the alloc row.
    drv_name: String,
    /// Requested algorithm type mask, when the row carries it.
    alg_type: Option<u32>,
    /// Requested algorithm mask, when the row carries it.
    alg_mask: Option<u32>,
    /// Whether a free row arrived.
    freed: bool,
    /// Last free row's final flag.
    final_free: bool,
    /// Free rows observed so far.
    releases: u32,
}

fn malformed(lineno: usize, msg: &str) -> LedgerError {
    LedgerError::Malformed(format!("line {}: {msg}", lineno + 1))
}

/// Required non-empty string field (`op` on submit, `req`/`drv` on
/// alloc). Empty values carry no identity and are rejected.
fn nonempty_str<'a>(
    row: &'a serde_json::Value,
    lineno: usize,
    phase: &str,
    field: &str,
) -> Result<&'a str, LedgerError> {
    let value = row
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| malformed(lineno, &format!("{phase} row missing {field}")))?;
    if value.is_empty() {
        return Err(malformed(lineno, &format!("{phase} row has empty {field}")));
    }
    Ok(value)
}

/// Required native errno (`return`, `progress`, `terminal` rows).
/// Presence and type are structural; values are truth data the
/// per-scenario validator interprets.
fn row_errno(row: &serde_json::Value, lineno: usize, phase: &str) -> Result<i32, LedgerError> {
    let errno = row
        .get("errno")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| malformed(lineno, &format!("{phase} row missing errno")))?;
    i32::try_from(errno).map_err(|_| malformed(lineno, &format!("{phase} errno out of i32 range")))
}

/// Required u32 metadata (`len` on `config` rows).
fn row_u32(
    row: &serde_json::Value,
    lineno: usize,
    phase: &str,
    field: &str,
) -> Result<u32, LedgerError> {
    let value = row
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed(lineno, &format!("{phase} row missing {field}")))?;
    u32::try_from(value)
        .map_err(|_| malformed(lineno, &format!("{phase} {field} out of u32 range")))
}

/// Optional u32 provenance (`type`/`mask` on `alloc` rows):
/// absent stays unknown, present-but-not-u32 is malformed
/// (a lying provenance field must not parse as truth).
fn row_opt_u32(
    row: &serde_json::Value,
    lineno: usize,
    phase: &str,
    field: &str,
) -> Result<Option<u32>, LedgerError> {
    match row.get(field) {
        None => Ok(None),
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| malformed(lineno, &format!("{phase} {field} is not a u32")))?;
            u32::try_from(raw)
                .map(Some)
                .map_err(|_| malformed(lineno, &format!("{phase} {field} out of u32 range")))
        }
    }
}

/// Parses `text` as the JSONL ledger of run `expected_run`.
///
/// Row schema (all objects, unknown fields ignored so the fixture
/// can grow): `v` (must be 1), `run` (must match), `phase` (one of
/// submit/return/progress/terminal/alloc/free/config/done), `seq`
/// on every phase but `done`, non-empty `op` on submit rows,
/// non-empty `req`/`drv` on alloc rows (plus optional u32
/// `type`/`mask` provenance), `errno` on
/// return/progress/terminal rows, `overflow` counter on every row
/// that carries it (nonzero rejects) and required on DONE,
/// required `fixture_result` on the DONE row (nonzero rejects),
/// required `final` flag on free rows, and on `config` rows a
/// non-empty `op`, an `errno` result and a u32 `len`.
///
/// Strictness is load-bearing: (sequence, phase) rows are unique
/// except `free` (each put counts; a shared transform lands
/// several, last `final` wins) and `config` (each configuration
/// counts; a transform is configured repeatedly) — both
/// exemptions carry their own tests. Every request needs submit,
/// return and terminal rows (submit first; return existence
/// required but unordered vs terminal — a genuine terminal may
/// land first under preemption, matrix Q04), free and config
/// require a prior alloc, every alloc must close before DONE, no
/// row may follow DONE, and the run must close with DONE.
pub fn parse_ledger(expected_run: &str, text: &str) -> Result<ParsedLedger, LedgerError> {
    let mut reqs: Vec<Build> = Vec::new();
    let mut alloc_builds: Vec<AllocBuild> = Vec::new();
    let mut configs: Vec<LedgerConfig> = Vec::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();
    let mut done = false;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if done {
            return Err(LedgerError::PhaseInconsistency(format!(
                "row after done at line {}",
                lineno + 1
            )));
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
            "submit" | "return" | "progress" | "terminal" | "alloc" | "free" | "config" => row
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
        // `free` and `config` rows repeat per sequence by design
        // (each put / each configuration counts); every other
        // phase stays (sequence, phase) unique.
        if phase != "free" && phase != "config" && !seen.insert((seq, phase.to_owned())) {
            return Err(LedgerError::DuplicateRow {
                seq,
                phase: phase.to_owned(),
            });
        }
        match phase {
            "done" => {
                if row.get("overflow").is_none() {
                    return Err(malformed(lineno, "done row missing overflow"));
                }
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
                let req_name = nonempty_str(&row, lineno, "alloc", "req")?;
                let drv_name = nonempty_str(&row, lineno, "alloc", "drv")?;
                let alg_type = row_opt_u32(&row, lineno, "alloc", "type")?;
                let alg_mask = row_opt_u32(&row, lineno, "alloc", "mask")?;
                alloc_builds.push(AllocBuild {
                    seq,
                    req_name: req_name.to_owned(),
                    drv_name: drv_name.to_owned(),
                    alg_type,
                    alg_mask,
                    freed: false,
                    final_free: false,
                    releases: 0,
                });
            }
            "free" => {
                let entry = alloc_builds.iter_mut().find(|a| a.seq == seq);
                match entry {
                    Some(entry) => {
                        // R5: release history is ordered — a final
                        // free ends the lifetime, so any further
                        // release is an impossible history (a
                        // duplicate final is not a shared release).
                        if entry.final_free {
                            return Err(LedgerError::PhaseInconsistency(format!(
                                "seq {seq} free arrived after final free"
                            )));
                        }
                        entry.freed = true;
                        entry.final_free = row
                            .get("final")
                            .and_then(serde_json::Value::as_bool)
                            .ok_or_else(|| malformed(lineno, "free row missing final"))?;
                        entry.releases = entry.releases.saturating_add(1);
                    }
                    None => {
                        return Err(LedgerError::PhaseInconsistency(format!(
                            "seq {seq} free arrived without alloc"
                        )));
                    }
                }
            }
            "config" => {
                let entry = alloc_builds.iter().find(|a| a.seq == seq);
                let Some(entry) = entry else {
                    return Err(LedgerError::PhaseInconsistency(format!(
                        "seq {seq} config arrived without alloc"
                    )));
                };
                // R5: configuration after the final free configures
                // a dead transform — impossible history.
                if entry.final_free {
                    return Err(LedgerError::PhaseInconsistency(format!(
                        "seq {seq} config arrived after final free"
                    )));
                }
                let op = nonempty_str(&row, lineno, "config", "op")?;
                let result_errno = row_errno(&row, lineno, "config")?;
                let len = row_u32(&row, lineno, "config", "len")?;
                configs.push(LedgerConfig {
                    seq,
                    op: op.to_owned(),
                    result_errno,
                    len,
                });
            }
            "submit" | "return" | "progress" | "terminal" => {
                let idx = match reqs.iter().position(|r| r.seq == seq) {
                    Some(i) => i,
                    None => {
                        reqs.push(Build {
                            seq,
                            submitted: false,
                            submit_op: None,
                            return_errno: None,
                            progress_errno: None,
                            terminal_errno: None,
                            notifications: 0,
                        });
                        reqs.len() - 1
                    }
                };
                if phase == "submit" {
                    let op = nonempty_str(&row, lineno, "submit", "op")?;
                    reqs[idx].submit_op = Some(op.to_owned());
                    reqs[idx].submitted = true;
                } else if !reqs[idx].submitted {
                    return Err(LedgerError::PhaseInconsistency(format!(
                        "seq {seq} {phase} arrived before submit"
                    )));
                }
                if phase == "return" {
                    reqs[idx].return_errno = Some(row_errno(&row, lineno, "return")?);
                }
                if phase == "progress" {
                    let marker = row_errno(&row, lineno, "progress")?;
                    // R2-05: the marker is atomic against the
                    // terminal row under the fixture's mark lock
                    // (`marker = completed ? 0 : -EINPROGRESS`,
                    // and the terminal row lands BEFORE
                    // `completed` flips) — so a 0 marker arrives
                    // iff a terminal already landed in the stream
                    // for this sequence. Either crossed
                    // combination is fixture-impossible history.
                    let terminal_seen = reqs[idx].terminal_errno.is_some();
                    let want = if terminal_seen { 0 } else { -libc::EINPROGRESS };
                    if marker != want {
                        return Err(LedgerError::PhaseInconsistency(format!(
                            "seq {seq} progress marker {marker} with terminal {}",
                            if terminal_seen {
                                "already recorded"
                            } else {
                                "not yet recorded"
                            }
                        )));
                    }
                    reqs[idx].progress_errno = Some(marker);
                    reqs[idx].notifications += 1;
                }
                if phase == "terminal" {
                    // No order requirement vs return: a genuine
                    // terminal may land first under preemption
                    // (matrix Q04). Existence of the return row
                    // is still required at finalize.
                    reqs[idx].terminal_errno = Some(row_errno(&row, lineno, "terminal")?);
                    reqs[idx].notifications += 1;
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
            req_name: a.req_name,
            drv_name: a.drv_name,
            alg_type: a.alg_type,
            alg_mask: a.alg_mask,
            freed: true,
            final_free: a.final_free,
            releases: a.releases,
        });
    }
    let mut requests = Vec::with_capacity(reqs.len());
    for r in reqs {
        match (r.submit_op, r.return_errno, r.terminal_errno) {
            (Some(op), Some(returned), Some(errno)) => requests.push(LedgerRequest {
                seq: r.seq,
                submit_op: op,
                return_errno: returned,
                progress_errno: r.progress_errno,
                terminal_errno: errno,
                notifications: r.notifications,
            }),
            (None, _, _) => {
                return Err(LedgerError::PhaseInconsistency(format!(
                    "seq {} submit carried no op",
                    r.seq
                )));
            }
            (_, None, _) => {
                return Err(LedgerError::PhaseInconsistency(format!(
                    "seq {} never returned",
                    r.seq
                )));
            }
            (_, _, None) => {
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
        configs,
        done,
    })
}
