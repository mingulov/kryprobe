// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 VM canary: attach the lifecycle sensor in a vng guest, drive one
//! fixture scenario, and verdict the sensor ledger against the
//! fixture's own ledger rows (independent oracle — the exact rules
//! live in [`canary`](kryprobe_privilege::kcrypto_lifecycle::canary),
//! this bin is the IO shell).
//!
//! Flow: bring up the sensor (4 required links) → PREPARE →
//! clear-drain → two quiescence baselines (the guest must be idle:
//! equal baselines prove no background crypto brackets the run) →
//! GO (blocks until the scenario completes) → drain until quiet →
//! detach + quiet-drain → `finish` reconciliation → verdict. Exit 0
//! on PASS, 1 on verdict/parse/drain mismatch, 2 on
//! usage/bring-up/fixture failure.
//!
//! Expectations derive from the FIXTURE ledger plus the scenario's
//! exact shape (see the oracle): the canary fails loudly on drift
//! instead of pinning observations.

use kryprobe_core::kcrypto::Terminal;
use kryprobe_privilege::host::monotonic_ns;
use kryprobe_privilege::kcrypto_lifecycle::canary::{
    SensorBaseline, SensorView, parse_transcript, verdict,
};
use kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleSensor;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn usage() -> ! {
    eprintln!(
        "usage: lifecycle_canary --object PATH --fixture-dir PATH --scenario NAME \
         --run-id ID --seed N --receipt PATH [--sensor-ledger PATH] [--timeout-ms MS]"
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
    if scenario != "sync-once" && scenario != "async-once" {
        eprintln!("canary error: unknown scenario {scenario}");
        std::process::exit(2);
    }
    let sensor_ledger_path = arg_value(&args, "--sensor-ledger");
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

    // 2. PREPARE, then clear-drain (discarded) + two quiescence
    // baselines: equal baselines 200ms apart prove the guest emits
    // no background crypto around the scenario (the oracle joins
    // deltas, so foreign traffic would corrupt the join).
    let control = PathBuf::from(&fixture_dir).join("control");
    let cmd = format!("PREPARE {run_id} {scenario} {seed}");
    if let Err(err) = std::fs::write(&control, &cmd) {
        eprintln!("canary error: PREPARE failed: {err}");
        std::process::exit(2);
    }
    for _ in 0..8 {
        match sensor.drain_once(8192) {
            Ok(drained) => {
                let _ = sensor.take_completed();
                if drained.records == 0 && !drained.busy {
                    break;
                }
            }
            Err(err) => {
                eprintln!("canary error: clear drain failed: {err}");
                std::process::exit(2);
            }
        }
    }
    let snapshot = |sensor: &LifecycleSensor, taken: u64| -> SensorBaseline {
        let ledger = sensor.ledger().unwrap_or_else(|err| {
            eprintln!("canary error: ledger read failed: {err}");
            std::process::exit(2);
        });
        SensorBaseline {
            edge_hits: ledger.edge_hits,
            kernel_loss: ledger.kernel_loss,
            agg_accepted: ledger.agg_accepted,
            completed_len: taken,
            decode: ledger.decode,
            reducer: ledger.reducer,
            retained_dropped: ledger.retained_dropped,
        }
    };
    // Quiescence gates RUN validity (a noisy guest refuses the
    // run); traffic ORIGIN during GO is proven by the verdict's
    // exact join (hook counts + errno + status + deltas), not by
    // these baselines — background traffic breaks the join and fails.
    let baseline1 = snapshot(&sensor, 0);
    std::thread::sleep(Duration::from_millis(200));
    let baseline2 = snapshot(&sensor, 0);
    if baseline1 != baseline2 {
        fail(&out, &receipt, "guest not quiet (baselines differ)");
    }
    put(&mut out, "quiescence", "ok".to_owned());

    // 3. GO (blocks until the scenario completes), then parse the
    // fixture transcript STRICTLY (any malformed own-row fails).
    if let Err(err) = std::fs::write(&control, "GO") {
        eprintln!("canary error: GO failed: {err}");
        std::process::exit(2);
    }
    let ledger_text = std::fs::read_to_string(PathBuf::from(&fixture_dir).join("ledger"))
        .unwrap_or_else(|err| {
            eprintln!("canary error: cannot read fixture ledger: {err}");
            std::process::exit(2);
        });
    let truth = parse_transcript(&ledger_text, &run_id).unwrap_or_else(|err| {
        fail(&out, &receipt, &format!("fixture transcript: {err}"));
    });
    put(&mut out, "fixture_result", truth.fixture_result.to_string());
    put(
        &mut out,
        "fixture_overflow",
        truth.fixture_overflow.to_string(),
    );

    // Fixture-derived hook EXPECTATIONS (the verdict's oracle
    // input — same `expected_hooks` the verdict compares deltas
    // against, so the receipt shows both sides of the join).
    let fx = truth.expected_hooks();
    let mut fx_completed = 0u64;
    for (_, errno) in &truth.returns {
        if *errno != -115 && *errno != -16 {
            fx_completed += 1;
        }
    }
    put(&mut out, "fx_enc_sub", fx[0].to_string());
    put(&mut out, "fx_enc_ret", fx[1].to_string());
    put(&mut out, "fx_dec_sub", fx[2].to_string());
    put(&mut out, "fx_dec_ret", fx[3].to_string());
    put(&mut out, "fx_completed", fx_completed.to_string());

    // 4. Drain until a quiet round (records==0, no busy writer) or
    // the deadline — the poll owns NO count expectations (the oracle
    // does); drain errors fail loudly, never fall back.
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut completed = Vec::new();
    loop {
        let drained = sensor.drain_once(8192).unwrap_or_else(|err| {
            fail(&out, &receipt, &format!("sensor drain failed: {err}"));
        });
        completed.extend(sensor.take_completed());
        if drained.records == 0 && !drained.busy {
            break;
        }
        if Instant::now() >= deadline {
            fail(&out, &receipt, "drain deadline (sensor never quiet)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // 5. Detach + quiet-drain + finish reconciliation (post-finish
    // completions join the take: every pending request reconciled).
    sensor.close_input();
    let quiet = sensor.drain_quiet().unwrap_or_else(|err| {
        fail(&out, &receipt, &format!("quiet drain failed: {err}"));
    });
    completed.extend(sensor.take_completed());
    let stop_ns = monotonic_ns().unwrap_or_else(|err| {
        eprintln!("canary error: clock read failed: {err}");
        std::process::exit(2);
    });
    // `finish` reconciles into retention; the take is the ONE read
    // path (finish returns nothing by design — a returning finish
    // double-surfaced every reconciled record).
    sensor.finish(stop_ns);
    completed.extend(sensor.take_completed());
    let ledger = sensor.ledger().unwrap_or_else(|err| {
        eprintln!("canary error: final ledger failed: {err}");
        std::process::exit(2);
    });

    // Sensor-ledger evidence file (exact join inputs for reviewers).
    if let Some(path) = sensor_ledger_path {
        let mut text = String::new();
        for record in &completed {
            let (terminal, status) = match record.terminal {
                Terminal::Sync(status) => ("sync", Some(status)),
                Terminal::Callback(status) => ("callback", Some(status)),
                Terminal::Unknown => ("unknown", None),
            };
            text.push_str(&format!(
                "{{\"id\":{},\"terminal\":\"{}\",\"status\":{},\"duration_ns\":{}}}\n",
                record.id,
                terminal,
                status.map_or("null".to_owned(), |s| s.to_string()),
                record
                    .duration_ns
                    .map_or("null".to_owned(), |d| d.to_string()),
            ));
        }
        if let Err(err) = std::fs::write(&path, &text) {
            eprintln!("canary error: cannot write sensor ledger: {err}");
            std::process::exit(2);
        }
    }

    // 6. Receipt sensor lines (post-finish deltas) + oracle verdict.
    let delta = |a: u64, b: u64| a.saturating_sub(b);
    let hits = [
        delta(ledger.edge_hits[0], baseline2.edge_hits[0]),
        delta(ledger.edge_hits[1], baseline2.edge_hits[1]),
        delta(ledger.edge_hits[2], baseline2.edge_hits[2]),
        delta(ledger.edge_hits[3], baseline2.edge_hits[3]),
    ];
    put(&mut out, "se_enc_sub", hits[0].to_string());
    put(&mut out, "se_enc_ret", hits[1].to_string());
    put(&mut out, "se_dec_sub", hits[2].to_string());
    put(&mut out, "se_dec_ret", hits[3].to_string());
    put(&mut out, "se_completed", completed.len().to_string());
    let terms: Vec<String> = completed
        .iter()
        .map(|r| format!("{:?}", r.terminal))
        .collect();
    put(&mut out, "se_terminals", terms.join(","));
    put(
        &mut out,
        "decode",
        format!(
            "admitted={} refused={} unknown={} bad={} gaps={} stale={}",
            delta(ledger.decode.admitted, baseline2.decode.admitted),
            delta(
                ledger.decode.submit_refused,
                baseline2.decode.submit_refused
            ),
            delta(
                ledger.decode.unknown_key_returns,
                baseline2.decode.unknown_key_returns
            ),
            delta(ledger.decode.bad_records, baseline2.decode.bad_records),
            delta(
                ledger.decode.gaps_synthesized,
                baseline2.decode.gaps_synthesized
            ),
            delta(ledger.decode.stale_returns, baseline2.decode.stale_returns),
        ),
    );
    put(
        &mut out,
        "reducer",
        format!(
            "admitted={} emitted={} unfinished={} orphan={} dup={} ambiguous={} admission_failed={}",
            delta(ledger.reducer.admitted, baseline2.reducer.admitted),
            delta(ledger.reducer.emitted, baseline2.reducer.emitted),
            delta(ledger.reducer.unfinished, baseline2.reducer.unfinished),
            delta(ledger.reducer.orphan, baseline2.reducer.orphan),
            delta(ledger.reducer.duplicate, baseline2.reducer.duplicate),
            delta(ledger.reducer.ambiguous, baseline2.reducer.ambiguous),
            delta(
                ledger.reducer.admission_failed,
                baseline2.reducer.admission_failed
            ),
        ),
    );
    put(
        &mut out,
        "kernel_loss",
        format!(
            "{},{},{},{},{}",
            delta(ledger.kernel_loss[0], baseline2.kernel_loss[0]),
            delta(ledger.kernel_loss[1], baseline2.kernel_loss[1]),
            delta(ledger.kernel_loss[2], baseline2.kernel_loss[2]),
            delta(ledger.kernel_loss[3], baseline2.kernel_loss[3]),
            delta(ledger.kernel_loss[4], baseline2.kernel_loss[4]),
        ),
    );
    put(
        &mut out,
        "agg",
        format!(
            "{},{},{},{}",
            delta(ledger.agg_accepted[0], baseline2.agg_accepted[0]),
            delta(ledger.agg_accepted[1], baseline2.agg_accepted[1]),
            delta(ledger.agg_accepted[2], baseline2.agg_accepted[2]),
            delta(ledger.agg_accepted[3], baseline2.agg_accepted[3]),
        ),
    );
    put(
        &mut out,
        "close",
        format!(
            "quiet={} rounds={} records={} backlog_bytes={}",
            quiet.quiet, quiet.rounds, quiet.records, quiet.backlog_bytes,
        ),
    );

    let view = SensorView {
        completed: &completed,
        edge_hits: ledger.edge_hits,
        decode: ledger.decode,
        reducer: ledger.reducer,
        kernel_loss: ledger.kernel_loss,
        agg_accepted: ledger.agg_accepted,
        retained_dropped: ledger.retained_dropped,
        baseline: baseline2,
        quiet_backlog_bytes: quiet.backlog_bytes,
    };
    if let Err(reason) = verdict(&scenario, &truth, &view) {
        fail(&out, &receipt, &reason);
    }
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
}
