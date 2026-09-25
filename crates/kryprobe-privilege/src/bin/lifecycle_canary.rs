// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 VM canary: attach the lifecycle sensor in a vng guest, drive one
//! fixture scenario, and cross-check sensor edges against the fixture's
//! own ledger rows (independent oracle).
//!
//! Flow: bring up the sensor (4 required links) → clear-drain pre-GO
//! traffic → `PREPARE <id> <scenario> <seed>` + `GO` on the fixture
//! control file → read the fixture ledger → drain until the sensor
//! matches the fixture's submit/return counts (or the deadline) →
//! write the receipt. Exit 0 on PASS, 1 on totals mismatch, 2 on
//! usage/bring-up/fixture failure.
//!
//! Expectations derive from the FIXTURE ledger (per-op submit/return/
//! terminal rows joined by seq), never from hardcoded counts: the
//! canary fails loudly on drift instead of pinning observations.

use kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleSensor;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Fixture rows for one run id, joined by seq.
#[derive(Debug, Default)]
struct FixtureTruth {
    /// seq → op ("encrypt"/"decrypt") from submit rows.
    ops: HashMap<u64, String>,
    /// (op, errno) per return row, in ledger order.
    returns: Vec<(String, i64)>,
    /// Terminal-row errnos, in ledger order.
    terminals: Vec<i64>,
    /// Done-row result + ledger overflow.
    fixture_result: i64,
    /// Done-row overflow count.
    overflow: u64,
    /// Done row present.
    done: bool,
}

/// Extract `"key":value` (number) following a marker, or `None`.
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

/// Parse fixture ledger rows for `run_id` (JSON lines; manual scan —
/// the formats are fixed by the fixture C source).
fn parse_fixture_ledger(text: &str, run_id: &str) -> FixtureTruth {
    let mut truth = FixtureTruth::default();
    let run_mark = format!("\"run\":\"{run_id}\"");
    for row in text.lines() {
        if !row.contains(&run_mark) {
            continue;
        }
        let Some(phase) = str_after(row, "\"phase\":\"") else {
            continue;
        };
        match phase.as_str() {
            "submit" => {
                if let (Some(seq), Some(op)) = (
                    num_after(row, "\"seq\":").and_then(|n| u64::try_from(n).ok()),
                    str_after(row, "\"op\":\""),
                ) {
                    truth.ops.insert(seq, op);
                }
            }
            "return" => {
                if let (Some(seq), Some(errno)) = (
                    num_after(row, "\"seq\":").and_then(|n| u64::try_from(n).ok()),
                    num_after(row, "\"errno\":"),
                ) {
                    let op = truth.ops.get(&seq).cloned().unwrap_or_default();
                    truth.returns.push((op, errno));
                }
            }
            "terminal" => {
                if let Some(errno) = num_after(row, "\"errno\":") {
                    truth.terminals.push(errno);
                }
            }
            "done" => {
                truth.done = true;
                truth.fixture_result = num_after(row, "\"fixture_result\":").unwrap_or(-9999);
                truth.overflow = num_after(row, "\"overflow\":")
                    .and_then(|n| u64::try_from(n).ok())
                    .unwrap_or(u64::MAX);
            }
            _ => {}
        }
    }
    truth
}

fn usage() -> ! {
    eprintln!(
        "usage: lifecycle_canary --object PATH --fixture-dir PATH --scenario NAME \
         --run-id ID --seed N --receipt PATH [--timeout-ms MS]"
    );
    std::process::exit(2);
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(object), Some(fixture_dir), Some(scenario), Some(run_id), Some(seed), Some(receipt)) = (
        arg_value(&args, "--object"),
        arg_value(&args, "--fixture-dir"),
        arg_value(&args, "--scenario"),
        arg_value(&args, "--run-id"),
        arg_value(&args, "--seed"),
        arg_value(&args, "--receipt"),
    ) else {
        usage()
    };
    let timeout_ms: u64 = arg_value(&args, "--timeout-ms")
        .map(|v| v.parse().unwrap_or_else(|_| usage()))
        .unwrap_or(5000);

    let mut out: Vec<(String, String)> = Vec::new();
    let put = |out: &mut Vec<(String, String)>, k: &str, v: String| {
        out.push((k.to_owned(), v));
    };
    put(&mut out, "run", run_id.clone());
    put(&mut out, "scenario", scenario.clone());
    let kernel = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    put(&mut out, "kernel", kernel);

    let fail = |out: &[(String, String)], receipt: &str, reason: &str| -> ! {
        let mut text = String::new();
        for (k, v) in out {
            text.push_str(&format!("{k}={v}\n"));
        }
        text.push_str(&format!("verdict=FAIL\nreason={reason}\n"));
        let _ = std::fs::write(receipt, &text);
        eprintln!("canary FAIL: {reason}");
        std::process::exit(1);
    };

    // 1. Bring up the sensor (all 4 required links or nothing).
    let object_bytes = std::fs::read(&object).unwrap_or_else(|err| {
        eprintln!("canary error: cannot read object {object}: {err}");
        std::process::exit(2);
    });
    let (mut sensor, points) =
        LifecycleSensor::bring_up(&object_bytes, None).unwrap_or_else(|err| {
            eprintln!("canary error: bring-up failed: {err}");
            std::process::exit(2);
        });
    put(&mut out, "links", points.len().to_string());
    if points.len() != 4 {
        fail(
            &out,
            &receipt,
            &format!("want 4 links, have {}", points.len()),
        );
    }

    // 2. Clear-drain pre-GO traffic (discarded; deltas measured after).
    if let Err(err) = sensor.drain_once(4096) {
        eprintln!("canary error: clear drain failed: {err}");
        std::process::exit(2);
    }
    let baseline = sensor.ledger().unwrap_or_else(|err| {
        eprintln!("canary error: baseline ledger failed: {err}");
        std::process::exit(2);
    });

    // 3. Drive the fixture (GO blocks until the scenario completes).
    let control = PathBuf::from(&fixture_dir).join("control");
    let cmd = format!("PREPARE {run_id} {scenario} {seed}");
    if let Err(err) = std::fs::write(&control, &cmd) {
        eprintln!("canary error: PREPARE failed: {err}");
        std::process::exit(2);
    }
    if let Err(err) = std::fs::write(&control, "GO") {
        eprintln!("canary error: GO failed: {err}");
        std::process::exit(2);
    }
    let ledger_text = std::fs::read_to_string(PathBuf::from(&fixture_dir).join("ledger"))
        .unwrap_or_else(|err| {
            eprintln!("canary error: cannot read fixture ledger: {err}");
            std::process::exit(2);
        });
    let truth = parse_fixture_ledger(&ledger_text, &run_id);
    put(&mut out, "fixture_result", truth.fixture_result.to_string());
    put(&mut out, "fixture_overflow", truth.overflow.to_string());
    if !truth.done {
        fail(&out, &receipt, "fixture ledger has no done row");
    }
    if truth.fixture_result != 0 {
        fail(
            &out,
            &receipt,
            &format!("fixture failed: result {}", truth.fixture_result),
        );
    }
    if truth.overflow != 0 {
        fail(&out, &receipt, "fixture ledger overflowed");
    }

    // 4. Expected sensor totals from the fixture rows (independent oracle).
    let mut exp = [0u64; 4];
    for op in truth.ops.values() {
        match op.as_str() {
            "encrypt" => exp[0] += 1,
            "decrypt" => exp[2] += 1,
            _ => {}
        }
    }
    let mut exp_completed = 0u64;
    for (op, errno) in &truth.returns {
        match op.as_str() {
            "encrypt" => exp[1] += 1,
            "decrypt" => exp[3] += 1,
            _ => {}
        }
        if *errno != -115 && *errno != -16 {
            exp_completed += 1;
        }
    }
    put(&mut out, "fx_enc_sub", exp[0].to_string());
    put(&mut out, "fx_enc_ret", exp[1].to_string());
    put(&mut out, "fx_dec_sub", exp[2].to_string());
    put(&mut out, "fx_dec_ret", exp[3].to_string());
    put(&mut out, "fx_completed", exp_completed.to_string());

    // 5. Drain until the sensor matches (or the deadline).
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let ledger = loop {
        if sensor.drain_once(1024).is_err() {
            break sensor.ledger().unwrap_or_else(|_| baseline.clone());
        }
        let ledger = sensor.ledger().unwrap_or_else(|_| baseline.clone());
        let hits = [
            ledger.edge_hits[0] - baseline.edge_hits[0],
            ledger.edge_hits[1] - baseline.edge_hits[1],
            ledger.edge_hits[2] - baseline.edge_hits[2],
            ledger.edge_hits[3] - baseline.edge_hits[3],
        ];
        let done = ledger.completed.len() as u64 - baseline.completed.len() as u64;
        if hits == exp && done == exp_completed {
            break ledger;
        }
        if Instant::now() >= deadline {
            break ledger;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    // 6. Receipt + verdict (deltas vs the fixture oracle).
    let hits = [
        ledger.edge_hits[0] - baseline.edge_hits[0],
        ledger.edge_hits[1] - baseline.edge_hits[1],
        ledger.edge_hits[2] - baseline.edge_hits[2],
        ledger.edge_hits[3] - baseline.edge_hits[3],
    ];
    let done = ledger.completed.len() as u64 - baseline.completed.len() as u64;
    put(&mut out, "se_enc_sub", hits[0].to_string());
    put(&mut out, "se_enc_ret", hits[1].to_string());
    put(&mut out, "se_dec_sub", hits[2].to_string());
    put(&mut out, "se_dec_ret", hits[3].to_string());
    put(&mut out, "se_completed", done.to_string());
    let terms: Vec<String> = ledger.completed[baseline.completed.len()..]
        .iter()
        .map(|r| format!("{:?}", r.terminal))
        .collect();
    put(&mut out, "se_terminals", terms.join(","));
    put(
        &mut out,
        "decode",
        format!(
            "admitted={} refused={} unknown={} bad={} gaps={}",
            ledger.decode.admitted - baseline.decode.admitted,
            ledger.decode.submit_refused - baseline.decode.submit_refused,
            ledger.decode.unknown_key_returns - baseline.decode.unknown_key_returns,
            ledger.decode.bad_records - baseline.decode.bad_records,
            ledger.decode.gaps_synthesized - baseline.decode.gaps_synthesized,
        ),
    );
    put(
        &mut out,
        "reducer",
        format!(
            "admitted={} emitted={} unfinished={}",
            ledger.reducer.admitted - baseline.reducer.admitted,
            ledger.reducer.emitted - baseline.reducer.emitted,
            ledger.reducer.unfinished - baseline.reducer.unfinished,
        ),
    );
    put(
        &mut out,
        "kernel_loss",
        format!(
            "{},{},{},{}",
            ledger.kernel_loss[0] - baseline.kernel_loss[0],
            ledger.kernel_loss[1] - baseline.kernel_loss[1],
            ledger.kernel_loss[2] - baseline.kernel_loss[2],
            ledger.kernel_loss[3] - baseline.kernel_loss[3],
        ),
    );

    let mut reasons: Vec<String> = Vec::new();
    if hits != exp {
        reasons.push(format!("edge_hits {hits:?} != fixture {exp:?}"));
    }
    if done != exp_completed {
        reasons.push(format!("completed {done} != fixture {exp_completed}"));
    }
    for (i, term) in ledger.completed[baseline.completed.len()..]
        .iter()
        .enumerate()
    {
        if !term.evidence_valid() {
            reasons.push(format!(
                "completion {i} not evidence-valid: {:?}",
                term.terminal
            ));
        }
    }
    if ledger.decode.submit_refused != baseline.decode.submit_refused
        || ledger.decode.unknown_key_returns != baseline.decode.unknown_key_returns
        || ledger.decode.bad_records != baseline.decode.bad_records
        || ledger.decode.gaps_synthesized != baseline.decode.gaps_synthesized
    {
        reasons.push("decode loss nonzero".to_owned());
    }
    if ledger.kernel_loss != baseline.kernel_loss {
        reasons.push(format!(
            "kernel loss nonzero: {:?} -> {:?}",
            baseline.kernel_loss, ledger.kernel_loss
        ));
    }
    if ledger.reducer.unfinished != baseline.reducer.unfinished {
        reasons.push("reducer unfinished nonzero".to_owned());
    }
    if reasons.is_empty() {
        let mut text = String::new();
        for (k, v) in &out {
            text.push_str(&format!("{k}={v}\n"));
        }
        text.push_str("verdict=PASS\n");
        if let Err(err) = std::fs::write(&receipt, &text) {
            eprintln!("canary error: cannot write receipt: {err}");
            std::process::exit(2);
        }
        let _ = std::io::stdout().write_all(text.as_bytes());
    } else {
        fail(&out, &receipt, &reasons.join("; "));
    }
}
