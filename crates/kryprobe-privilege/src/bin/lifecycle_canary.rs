// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 VM canary: attach the lifecycle sensor in a vng guest, drive one
//! fixture scenario, and verdict the sensor ledger against the
//! fixture's own ledger rows (independent oracle — the exact rules
//! live in [`canary`](kryprobe_privilege::kcrypto_lifecycle::canary),
//! this bin is the IO shell).
//!
//! Flow: bring up the sensor (3 required session links) → PREPARE →
//! clear-drain → two quiescence baselines (the guest must be idle:
//! equal baselines prove no background crypto brackets the run) →
//! GO (blocks until the scenario completes) → drain until quiet →
//! disarm + detach + quiet-drain → `finish` reconciliation → H4
//! foreign-link exclusion → verdict. Exit 0 on PASS, 1 on
//! verdict/parse/drain mismatch, 2 on usage/bring-up/fixture failure.
//!
//! Expectations derive from the FIXTURE ledger plus the scenario's
//! exact shape (see the oracle): the canary fails loudly on drift
//! instead of pinning observations.

use kryprobe_core::kcrypto::Terminal;
use kryprobe_privilege::btf_resolve::{AttachOutcome, resolve_kfunc_ids, resolve_lifecycle_ids};
use kryprobe_privilege::host::monotonic_ns;
use kryprobe_privilege::kcrypto_lifecycle::canary::{
    SensorBaseline, SensorView, count_foreign_links, parse_transcript, verdict,
};
use kryprobe_privilege::kcrypto_lifecycle::profile::{LifecycleProfile, manifest};
use kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleSensor;
use kryprobe_privilege::kcrypto_lifecycle::view::ProgMisses;
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
    if !matches!(
        scenario.as_str(),
        "sync-once"
            | "async-once"
            | "backlog-accepted"
            | "no-backlog-burst"
            | "cryptd-async"
            | "reuse-burst"
            | "refheld-release"
            | "shared-release"
            | "rekey"
            | "authsize"
            | "typed-sync"
            | "exact-driver"
            | "failed-alloc"
            | "failed-init"
            | "early-callback"
            | "reuse-in-callback"
    ) {
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
    // A4 guest preempt evidence: the `preempt=` cmdline token plus the
    // kernel's `Dynamic Preempt:` dmesg line (preempt model brackets
    // the run's scheduling behavior).
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let preempt_cmd = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("preempt="))
        .unwrap_or("absent");
    put(&mut out, "preempt_cmdline", preempt_cmd.to_owned());
    let dmesg = std::process::Command::new("dmesg").output();
    let preempt_dmesg = dmesg
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find(|line| line.contains("Dynamic Preempt"))
                .map(|line| line.trim().to_owned())
        })
        .unwrap_or_else(|| "unavailable".to_owned());
    put(&mut out, "preempt_dmesg", preempt_dmesg);

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

    // 1. Bring up the sensor (all required session links or nothing).
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
    // P4: required session links all attached (all-or-nothing) +
    // callback points RECORDED; the scenario class decides which
    // callback must be ATTACHED (the verdict would grade
    // callback-grounded shapes against a submit/return-only
    // sensor otherwise — a vacuous mismatch, failed here with
    // the cause named).
    let table = manifest(LifecycleProfile::RequestLifecycle);
    if points.len() != table.required.len() + table.callbacks.len() {
        fail(
            &out,
            &receipt,
            &format!(
                "want {} required + {} callback points, have {}",
                table.required.len(),
                table.callbacks.len(),
                points.len()
            ),
        );
    }
    let attached = |section: &str| {
        points
            .iter()
            .any(|p| p.name == section && p.attach == Some(AttachOutcome::Attached))
    };
    for site in table.required {
        let section = format!("fsession/{}", site.symbol);
        if !attached(&section) {
            fail(&out, &receipt, &format!("required {section} not attached"));
        }
    }
    let want_callback: Option<&str> = match scenario.as_str() {
        "async-once" | "exact-driver" | "backlog-accepted" | "no-backlog-burst"
        | "early-callback" | "reuse-in-callback" => Some("fentry/kxc_complete"),
        "cryptd-async" => Some("fentry/cryptd_skcipher_complete"),
        _ => None,
    };
    if let Some(section) = want_callback
        && !attached(section)
    {
        fail(
            &out,
            &receipt,
            &format!("{scenario} needs {section} attached (have: {points:?})"),
        );
    }
    // P4: the verdict's link gate counts REQUIRED session links
    // only (callback links attach optionally and are proven by
    // the per-scenario attach check above + the lane-16/17
    // expectations — never by this count).
    let attached_links = points
        .iter()
        .filter(|p| p.name.starts_with("fsession/") && p.attach == Some(AttachOutcome::Attached))
        .count();
    put(
        &mut out,
        "attached_total",
        sensor.attached_points().to_string(),
    );
    // M2 receipts: the session-kfunc BTF ids the loader rewrote, the
    // kernel prog/map/link ids from the pre-arm identity baseline,
    // and the ring positions at arm (abs snapshots; deltas below).
    let kfunc_ids = resolve_kfunc_ids().unwrap_or_else(|err| {
        eprintln!("canary error: kfunc ids unreadable: {err}");
        std::process::exit(2);
    });
    put(
        &mut out,
        "kfunc_ids",
        format!(
            "is_return={} cookie={}",
            kfunc_ids.get("bpf_session_is_return").copied().unwrap_or(0),
            kfunc_ids.get("bpf_session_cookie").copied().unwrap_or(0),
        ),
    );
    let identity = sensor.baseline_identity();
    let join_ids = |ids: Vec<u32>| {
        ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    put(
        &mut out,
        "prog_ids",
        join_ids(identity.progs.iter().map(|p| p.id).collect()),
    );
    put(
        &mut out,
        "map_ids",
        join_ids(identity.maps.iter().map(|m| m.id).collect()),
    );
    put(
        &mut out,
        "link_ids",
        join_ids(identity.links.iter().map(|l| l.id).collect()),
    );
    let (arm_cons, arm_prod) = sensor.ring_positions();
    put(&mut out, "ring_arm", format!("{arm_cons},{arm_prod}"));

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
            adapter: ledger.adapter,
            retained_dropped: ledger.retained_dropped,
            prog_misses: ledger.miss_current.clone(),
            tfm: ledger.tfm_stats,
            generations_len: sensor.tfm().generations().len() as u64,
        }
    };
    // Quiescence gates RUN validity (a noisy guest refuses the
    // run); the verdict then checks POSITIONAL agreement between
    // the fixture ledger and the sensor ledger (per-hook counts,
    // per-index errno/status, deltas — background traffic breaks
    // the exact join and fails), not these baselines. That is
    // count/order/status agreement under quiescence — NOT
    // per-call origin proof: records carry no shared fixture
    // identity (no seq/invocation survives into RequestRecord), so
    // a same-shape foreign call replacing a missed fixture call is
    // indistinguishable to the positional join. The archived
    // sensor rows support independent count/order/status
    // reconciliation, not individual call attribution.
    let baseline1 = snapshot(&sensor, 0);
    std::thread::sleep(Duration::from_millis(200));
    let baseline2 = snapshot(&sensor, 0);
    if baseline1 != baseline2 {
        fail(&out, &receipt, "guest not quiet (baselines differ)");
    }
    put(&mut out, "quiescence", "ok".to_owned());

    // 3. GO in a writer thread (the write BLOCKS until the
    // scenario completes) while the main thread drains: a
    // 1,000-lifetime burst emits ~6,000 records, past the ring —
    // drain-during-GO keeps the ring from dropping (T07-R2-04).
    // The sensor stays on the main thread (no sharing); the GO
    // thread only signals completion. Then parse the fixture
    // transcript STRICTLY (any malformed own-row fails).
    let mut completed = Vec::new();
    let control_go = control.clone();
    let go = std::thread::spawn(move || std::fs::write(&control_go, "GO"));
    loop {
        match sensor.drain_once(8192) {
            Ok(drained) => {
                completed.extend(sensor.take_completed());
                // Wake on the owned ring after a quiet drain: even
                // a fixed 1 ms idle sleep can miss a short fixture
                // burst. Reserved-but-uncommitted records need the
                // same bounded retry yield as production collection.
                // The timeout also services a GO that ends quietly.
                if drained.records == 0
                    && let Err(err) =
                        sensor.wait_for_activity(Duration::from_millis(1), drained.busy)
                {
                    fail(
                        &out,
                        &receipt,
                        &format!("sensor wait during GO failed: {err}"),
                    );
                }
            }
            Err(err) => {
                fail(
                    &out,
                    &receipt,
                    &format!("sensor drain during GO failed: {err}"),
                );
            }
        }
        if go.is_finished() {
            break;
        }
    }
    match go.join() {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            eprintln!("canary error: GO failed: {err}");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("canary error: GO thread panicked");
            std::process::exit(2);
        }
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
    // T07-R2-04: fixture transform truth (the lifetime oracle's
    // input — counts here, per-lifetime rows in the fixture
    // ledger the receipt archives beside).
    put(&mut out, "fx_allocs", truth.allocs.len().to_string());
    put(&mut out, "fx_frees", truth.frees.len().to_string());
    put(
        &mut out,
        "fx_final_frees",
        truth
            .frees
            .iter()
            .filter(|f| f.final_free)
            .count()
            .to_string(),
    );
    put(&mut out, "fx_configs", truth.configs.len().to_string());
    put(&mut out, "fx_probes", truth.probes.len().to_string());

    // 4. Drain until a quiet round (records==0, no busy writer) or
    // the deadline — the poll owns NO count expectations (the oracle
    // does); drain errors fail loudly, never fall back. (Continues
    // the `completed` take from the drain-during-GO loop above —
    // one take stream, no reset between GO and quiet.)
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
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

    // 5. Disarm + detach + quiet-drain + finish reconciliation
    // (post-finish completions join the take: every pending request
    // reconciled). Ring positions bracket the ingest (arm → ingest →
    // disarm); the H4 exclusion enumerates AFTER detach (our links
    // are gone — any tracing link left on our targets is foreign).
    let (ingest_cons, ingest_prod) = sensor.ring_positions();
    put(
        &mut out,
        "ring_ingest",
        format!("{ingest_cons},{ingest_prod}"),
    );
    // M2 read-after-ingest: full identity re-verification while
    // attached (the ledger re-verifies post-detach; both feed the
    // same sticky bit, and the verdict consults it).
    match sensor.verify_identity() {
        Ok(()) => put(&mut out, "verify_preclose", "ok".to_owned()),
        Err(err) => put(&mut out, "verify_preclose", format!("VOID: {err}")),
    }
    sensor.close_input().unwrap_or_else(|err| {
        fail(
            &out,
            &receipt,
            &format!("sensor disarm/detach failed: {err}"),
        );
    });
    let (disarm_cons, disarm_prod) = sensor.ring_positions();
    put(
        &mut out,
        "ring_disarm",
        format!("{disarm_cons},{disarm_prod}"),
    );
    let attach_ids = resolve_lifecycle_ids().unwrap_or_else(|err| {
        eprintln!("canary error: attach ids unreadable: {err}");
        std::process::exit(2);
    });
    let own_prog_ids: Vec<u32> = sensor
        .baseline_identity()
        .progs
        .iter()
        .map(|p| p.id)
        .collect();
    let target_btf_ids: Vec<u32> = attach_ids.values().copied().collect();
    let foreign_links = count_foreign_links(&own_prog_ids, &target_btf_ids).unwrap_or_else(|err| {
        use kryprobe_privilege::kcrypto_lifecycle::canary::ForeignLinksError;
        match err {
            // Not root (or LSM): environment failure, not evidence.
            ForeignLinksError::Enumerate { errno, .. }
                if errno == libc::EPERM || errno == libc::EACCES =>
            {
                eprintln!("canary error: H4 enumeration refused: {err}");
                std::process::exit(2);
            }
            // Exclusion unverifiable: the run's evidence is void.
            _ => fail(&out, &receipt, &format!("H4 exclusion failed: {err}")),
        }
    });
    put(&mut out, "foreign_links", foreign_links.to_string());
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
        // T07-R2-04: per-lifetime generation rows (fixture alloc[i]
        // joins generations[baseline + i] — both sides archived).
        for generation in sensor.tfm().generations() {
            text.push_str(&format!(
                "{{\"kind\":\"gen\",\"id\":{},\"req\":{:?},\"drv\":{:?},\"type\":{},\"mask\":{},\"first_seen\":{},\"retired\":{},\"ambiguous\":{},\"epoch\":{},\"configs\":{},\"site\":{},\"len\":{},\"errno\":{}}}\n",
                generation.id,
                generation.req_name,
                generation.drv_name,
                generation.alg_type,
                generation.alg_mask,
                generation.first_seen,
                generation.retired,
                generation.ambiguous,
                generation.epoch,
                generation.configs,
                generation.last_config_site,
                generation.last_config_len,
                generation.last_config_errno,
            ));
        }
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
    let hits: Vec<u64> = ledger
        .edge_hits
        .iter()
        .zip(baseline2.edge_hits.iter())
        .map(|(a, b)| delta(*a, *b))
        .collect();
    put(&mut out, "se_enc_sub", hits[0].to_string());
    put(&mut out, "se_enc_ret", hits[1].to_string());
    put(&mut out, "se_dec_sub", hits[2].to_string());
    put(&mut out, "se_dec_ret", hits[3].to_string());
    put(&mut out, "se_allocsk_sub", hits[4].to_string());
    put(&mut out, "se_allocsk_ret", hits[5].to_string());
    // T07-R2-04: sensor transform evidence (both sides of the
    // lifetime join — per-lifetime rows ride the sensor ledger).
    put(&mut out, "se_destroy_sub", hits[6].to_string());
    put(&mut out, "se_destroy_ret", hits[7].to_string());
    put(&mut out, "se_setkeysk_sub", hits[8].to_string());
    put(&mut out, "se_setkeysk_ret", hits[9].to_string());
    put(&mut out, "se_setauthsize_sub", hits[10].to_string());
    put(&mut out, "se_setauthsize_ret", hits[11].to_string());
    put(&mut out, "se_allocaead_sub", hits[12].to_string());
    put(&mut out, "se_allocaead_ret", hits[13].to_string());
    put(&mut out, "se_setkeyaead_sub", hits[14].to_string());
    put(&mut out, "se_setkeyaead_ret", hits[15].to_string());
    let tfm_delta = |got: u64, base: u64| delta(got, base).to_string();
    put(
        &mut out,
        "se_tfm",
        format!(
            "admitted={} completed={} releases={} retired={} joined={} failed_cfg={} failed_alloc={} ambiguous={} unobserved={}",
            tfm_delta(ledger.tfm_stats.admitted, baseline2.tfm.admitted),
            tfm_delta(ledger.tfm_stats.completed, baseline2.tfm.completed),
            tfm_delta(ledger.tfm_stats.releases, baseline2.tfm.releases),
            tfm_delta(ledger.tfm_stats.retired, baseline2.tfm.retired),
            tfm_delta(
                ledger.tfm_stats.configs_joined,
                baseline2.tfm.configs_joined
            ),
            tfm_delta(
                ledger.tfm_stats.configs_failed,
                baseline2.tfm.configs_failed
            ),
            tfm_delta(ledger.tfm_stats.failed_allocs, baseline2.tfm.failed_allocs),
            tfm_delta(
                ledger.tfm_stats.ambiguous_releases,
                baseline2.tfm.ambiguous_releases
            ),
            tfm_delta(
                ledger.tfm_stats.unobserved_boundary,
                baseline2.tfm.unobserved_boundary
            ),
        ),
    );
    put(
        &mut out,
        "se_gens",
        format!(
            "baseline={} final={}",
            baseline2.generations_len,
            sensor.tfm().generations().len()
        ),
    );
    put(
        &mut out,
        "se_reuse_exact",
        sensor.tfm().reuse_exact().to_string(),
    );
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
                ledger.decode.unknown_invoc_returns,
                baseline2.decode.unknown_invoc_returns
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
        ledger
            .agg_accepted
            .iter()
            .zip(baseline2.agg_accepted.iter())
            .map(|(a, b)| delta(*a, *b).to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    put(
        &mut out,
        "close",
        format!(
            "quiet={} rounds={} records={} backlog_bytes={}",
            quiet.quiet, quiet.rounds, quiet.records, quiet.backlog_bytes,
        ),
    );
    // M2 abs snapshots: pre-arm baselines + final absolutes (deltas
    // above are GO-relative; these bracket the whole session).
    put(
        &mut out,
        "arm_loss_abs",
        format!(
            "{},{},{},{},{}",
            ledger.loss_baseline[0],
            ledger.loss_baseline[1],
            ledger.loss_baseline[2],
            ledger.loss_baseline[3],
            ledger.loss_baseline[4],
        ),
    );
    put(
        &mut out,
        "arm_agg_abs",
        ledger
            .agg_baseline
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
    put(
        &mut out,
        "loss_abs",
        format!(
            "{},{},{},{},{}",
            ledger.kernel_loss[0],
            ledger.kernel_loss[1],
            ledger.kernel_loss[2],
            ledger.kernel_loss[3],
            ledger.kernel_loss[4],
        ),
    );
    put(
        &mut out,
        "agg_abs",
        ledger
            .agg_accepted
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
    put(&mut out, "view_valid", ledger.view_valid.to_string());
    // H2 per-program misses abs+delta (GO-relative join against the
    // quiescence baseline + pre-arm session absolutes): the verdict
    // owns the all-zero gate; the receipt shows both sides.
    let miss_line = |base: &[ProgMisses], cur: &[ProgMisses]| -> String {
        cur.iter()
            .map(|got| {
                let b = base
                    .iter()
                    .find(|want| want.section == got.section)
                    .map_or(0, |want| want.misses);
                format!(
                    "{} base={b} cur={} delta={}",
                    got.section,
                    got.misses,
                    got.misses.saturating_sub(b)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    put(
        &mut out,
        "prog_misses",
        miss_line(&baseline2.prog_misses, &ledger.miss_current),
    );
    put(
        &mut out,
        "arm_miss_abs",
        ledger
            .prog_misses
            .iter()
            .map(|d| format!("{}={}", d.section, d.baseline))
            .collect::<Vec<_>>()
            .join(","),
    );

    let generations = sensor.tfm().generations();
    let view = SensorView {
        completed: &completed,
        edge_hits: ledger.edge_hits,
        decode: ledger.decode,
        reducer: ledger.reducer,
        adapter: ledger.adapter,
        kernel_loss: ledger.kernel_loss,
        agg_accepted: ledger.agg_accepted,
        retained_dropped: ledger.retained_dropped,
        baseline: baseline2,
        quiet_backlog_bytes: quiet.backlog_bytes,
        view_valid: ledger.view_valid,
        attached_links,
        foreign_links,
        prog_misses: ledger.miss_current.clone(),
        tfm: ledger.tfm_stats,
        generations: &generations,
        reuse_exact: sensor.tfm().reuse_exact(),
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
