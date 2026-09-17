// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixture roundtrip: spawn, attach, drain, count (see `super`).

use super::{
    BpfSelftestConfig, BpfSelftestError, BpfSelftestOutcome, await_line, is_denied, kill_quietly,
    pump_lines, view_spine_event,
};
use crate::attach::{AttachError, attach_group};
use crate::bpfloader::LoadedSpine;
use crate::drain::{DrainEvent, DrainStats, DrainThread};
use crate::elfread::goblin_parser;
use crate::mapops::{MapOpsError, map_lookup_percpu_sum, map_update};
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{DrainConfig, GenerationGuard, LinkGroup, LossLedger, ProgramId};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Test generation pinned into cookies + CONFIG.
const GENERATION: u32 = 1;
/// Ring size for the drain thread (matches the T7 lane).
const RING_BYTES: u32 = 262_144;

fn map_denied(stage: &'static str, err: MapOpsError) -> BpfSelftestError {
    match err {
        MapOpsError::UpdateFailed { errno, .. } | MapOpsError::LookupFailed { errno, .. }
            if is_denied(errno) =>
        {
            BpfSelftestError::Denied {
                stage: stage.to_owned(),
                errno,
            }
        }
        other => BpfSelftestError::Map(other.to_string()),
    }
}

pub(super) fn roundtrip(
    config: &BpfSelftestConfig,
    loaded: &LoadedSpine,
) -> Result<BpfSelftestOutcome, BpfSelftestError> {
    let fixture_bytes =
        std::fs::read(&config.fixture).map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    let offset = goblin_parser::static_symbol_file_offset(&fixture_bytes, "spine_target_fn")
        .map_err(|err| BpfSelftestError::Fixture(format!("{err:?}")))?
        .ok_or(BpfSelftestError::BadEvent("spine_target_fn unresolved"))?;
    let mut child = Command::new(&config.fixture)
        .arg(config.calls.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    let outcome = drive(config, loaded, offset, &mut child);
    if outcome.is_err() {
        kill_quietly(&mut child);
    }
    outcome
}

fn drive(
    config: &BpfSelftestConfig,
    loaded: &LoadedSpine,
    offset: u64,
    child: &mut Child,
) -> Result<BpfSelftestOutcome, BpfSelftestError> {
    let lines = pump_lines(child.stdout.take().expect("piped stdout"));
    if await_line(&lines, "READY", Duration::from_secs(10))? != "READY" {
        return Err(BpfSelftestError::BadEvent("READY line malformed"));
    }
    let pid = child.id();
    let generation = PlanGeneration::new(GENERATION);
    for (map, key, value, stage) in [
        (&loaded.maps.config, 0, u64::from(GENERATION), "config/gen"),
        (&loaded.maps.config, 1, u64::from(pid), "config/tgid"),
        (&loaded.maps.start, 0, 1, "start/arm"),
    ] {
        map_update(map, key, value, stage).map_err(|err| map_denied(stage, err))?;
    }
    let meta = std::fs::symlink_metadata(&config.fixture)
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
    let group = |entry: bool| LinkGroup {
        object: ObjectRef {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: mtime_ns,
            role: ObjectRole::Executable,
        },
        program: ProgramId::UprobeMultiSelfProbe,
        scope: TargetScope::Pid { pid },
        entry,
        generation,
    };
    let guard = GenerationGuard { generation };
    // Links stay bound until the drain below finishes (drop = detach).
    let mut links = Vec::new();
    for (prog, entry, stage) in [
        (&loaded.progs.entry, true, "entry attach"),
        (&loaded.progs.ret, false, "return attach"),
    ] {
        let link = attach_group(&group(entry), &guard, prog, &config.fixture, &[offset]).map_err(
            |err| match err {
                AttachError::LinkFailed { errno, .. } if is_denied(errno) => {
                    BpfSelftestError::Denied {
                        stage: stage.to_owned(),
                        errno,
                    }
                }
                other => BpfSelftestError::Fixture(format!("attach failed: {other:?}")),
            },
        )?;
        links.push(link);
    }
    let drain_config = DrainConfig {
        // A full ring per wakeup (256 KiB / 72 B ≈ 3.6k records).
        max_events_per_iter: 4096,
        // Absorbs whole wakeup bursts (try_send never blocks, so a
        // shallow queue would drop under burst production even with a
        // concurrent receiver); production backends size their own.
        queue_depth: 65536,
        poll_timeout_ms: 50,
    };
    let drain = DrainThread::spawn(&loaded.maps.events, RING_BYTES, &drain_config)
        .map_err(|err| BpfSelftestError::Drain(format!("{err:?}")))?;
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(b"GO\n")
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    let done_secs = 30 + config.calls / 500;
    // DONE watcher owns the line pump: it waits for DONE, lets the ring
    // settle, then releases the collector below. Records are collected
    // CONCURRENTLY with the fixture run, so bursts larger than the
    // queue survive; the flag is set on every path (including fixture
    // errors) so the collector always terminates.
    let settled = Arc::new(AtomicBool::new(false));
    let settled_w = settled.clone();
    let watcher = thread::spawn(move || {
        let outcome: Result<(), BpfSelftestError> = (|| {
            let done = await_line(&lines, "DONE", Duration::from_secs(done_secs))?;
            if !done.starts_with("DONE ") {
                return Err(BpfSelftestError::BadEvent("DONE line malformed"));
            }
            thread::sleep(Duration::from_secs(2));
            Ok(())
        })();
        settled_w.store(true, Ordering::Release);
        outcome
    });
    let mut records: Vec<Vec<u8>> = Vec::new();
    while !settled.load(Ordering::Acquire) {
        match drain.receiver().recv_timeout(Duration::from_millis(100)) {
            Ok(DrainEvent::Record(bytes)) => records.push(bytes),
            Ok(DrainEvent::Barrier(_)) => {}
            Err(_) => {}
        }
    }
    while let Ok(DrainEvent::Record(bytes)) = drain.receiver().try_recv() {
        records.push(bytes);
    }
    watcher
        .join()
        .map_err(|_| BpfSelftestError::Fixture("DONE watcher panicked".to_owned()))??;
    let stats: DrainStats = drain.stop();
    drop(links);
    let status = child
        .wait()
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    if !status.success() {
        return Err(BpfSelftestError::FixtureExit(status.code().unwrap_or(-1)));
    }
    use std::os::unix::process::ExitStatusExt as _;
    let (exit_code, signal) = (status.code(), status.signal());
    let mut entries = 0u64;
    let mut returns = 0u64;
    for bytes in &records {
        let view = view_spine_event(bytes)?;
        if view.cookie >> 32 != u64::from(GENERATION) {
            return Err(BpfSelftestError::BadEvent("stale generation leaked"));
        }
        match view.flags {
            0 => entries += 1,
            1 => returns += 1,
            _ => return Err(BpfSelftestError::BadEvent("bad flags")),
        }
    }
    let ring = map_lookup_percpu_sum(&loaded.maps.loss, 0, "loss/ring")
        .map_err(|err| map_denied("loss/ring", err))?;
    let dropped = map_lookup_percpu_sum(&loaded.maps.loss, 1, "loss/drop")
        .map_err(|err| map_denied("loss/drop", err))?;
    let ledger = LossLedger {
        exact: 2 * config.calls,
        received: records.len() as u64,
        drops: ring + dropped,
    };
    Ok(BpfSelftestOutcome {
        entries,
        returns,
        received: records.len() as u64,
        ring,
        dropped,
        queue_drops: stats.queue_drops,
        exit_code,
        signal,
        verdict: ledger.reconcile(),
    })
}
