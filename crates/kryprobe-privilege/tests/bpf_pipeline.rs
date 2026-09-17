// SPDX-License-Identifier: GPL-3.0-or-later
//! BPF spine pipeline: object presence + attach/drain/loss roundtrip.
//!
//! The presence test fails naming `cargo xtask build --bpf` until T7b
//! builds the object. The roundtrip test is `#[ignore]`d (needs privilege
//! or honest-Denied paths) and is filled in by T7c.

use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{
    DrainConfig, GenerationGuard, LinkGroup, LossLedger, ProgramId, ReconcileVerdict,
};
use kryprobe_privilege::attach::{AttachError, attach_group};
use kryprobe_privilege::bpfloader::{LoaderError, load_spine_object};
use kryprobe_privilege::bpfselftest::{SpineEventView, view_spine_event};
use kryprobe_privilege::drain::{DrainEvent, DrainThread};
use kryprobe_privilege::elfread::goblin_parser;
use kryprobe_privilege::mapops::{MapOpsError, map_lookup_percpu_sum, map_update};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// Workspace-relative path of the built spine object.
fn spine_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("spine.bpf.o")
}

#[test]
fn spine_object_present() {
    let path = spine_object_path();
    assert!(
        path.is_file(),
        "missing BPF spine object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
}

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixture call count: 200 calls → 400 spine records.
const CALLS: u64 = 200;
/// Test generation pinned into cookies + CONFIG.
const GENERATION: u32 = 1;

/// Spawn a line pump: stdout lines flow to a channel for deadline reads.
fn pump_lines<R: std::io::Read + Send + 'static>(reader: R) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

fn await_line(rx: &std::sync::mpsc::Receiver<String>, what: &str, timeout: Duration) -> String {
    rx.recv_timeout(timeout)
        .unwrap_or_else(|_| panic!("timed out waiting for fixture {what}"))
}

/// Best-effort child cleanup on honest-skip paths.
fn kill_quietly(child: &mut Child) {
    child.kill().ok();
    child.wait().ok();
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("debug")
        .join("spine_fixture")
}

/// Honest-skip adapter: EPERM/EACCES at any privileged step passes the
/// lane (partial caps); anything else fails loudly. Returns `None` to skip.
fn or_skip<T, E: std::fmt::Display>(
    result: Result<T, E>,
    denied: impl Fn(&E) -> bool,
    stage: &str,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) if denied(&err) => {
            eprintln!("pipeline: {stage} honestly denied ({err}); skipping");
            None
        }
        Err(err) => panic!("pipeline: {stage} failed dishonestly: {err}"),
    }
}

/// Lane-local parse: lib validates shape, lane asserts generation + flags.
fn view_event(bytes: &[u8]) -> SpineEventView {
    view_spine_event(bytes).expect("spine record must parse")
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn bpf_pipeline_clean_or_denied() {
    let object = spine_object_path();
    assert!(
        object.is_file(),
        "missing BPF spine object at {} — run `cargo xtask test bpf`",
        object.display()
    );
    // Load first: unprivileged runs prove the Denied path without a fixture.
    let loaded = match load_spine_object(&object) {
        Ok(loaded) => loaded,
        Err(LoaderError::MapFailed { errno, .. }) | Err(LoaderError::LoadFailed { errno, .. })
            if errno == libc::EPERM || errno == libc::EACCES =>
        {
            eprintln!("pipeline: unprivileged, loader honestly denied (errno {errno})");
            return;
        }
        Err(other) => panic!("loader failed dishonestly: {other}"),
    };
    privileged_roundtrip(&loaded);
}

/// Full attach/drain/loss roundtrip. Only runs with BPF privilege.
fn privileged_roundtrip(loaded: &kryprobe_privilege::bpfloader::LoadedSpine) {
    let fixture = fixture_path();
    assert!(
        fixture.is_file(),
        "missing fixture at {} — run `cargo xtask test bpf`",
        fixture.display()
    );
    let fixture_bytes = std::fs::read(&fixture).unwrap();
    let offset = goblin_parser::static_symbol_file_offset(&fixture_bytes, "spine_target_fn")
        .unwrap()
        .expect("spine_target_fn must resolve in the fixture");
    let mut child: Child = Command::new(&fixture)
        .arg(CALLS.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("fixture must spawn");
    let lines = pump_lines(child.stdout.take().unwrap());
    assert_eq!(
        await_line(&lines, "READY", Duration::from_secs(10)),
        "READY"
    );
    let pid = child.id();
    let generation = PlanGeneration::new(GENERATION);
    let map_denied = |err: &MapOpsError| {
        matches!(
            err,
            MapOpsError::UpdateFailed { errno, .. }
                if *errno == libc::EPERM || *errno == libc::EACCES
        )
    };
    let updates = [
        (&loaded.maps.config, 0, u64::from(GENERATION), "config/gen"),
        (&loaded.maps.config, 1, u64::from(pid), "config/tgid"),
        (&loaded.maps.start, 0, 1, "start/arm"),
    ];
    for (map, key, value, stage) in updates {
        if or_skip(map_update(map, key, value, stage), map_denied, stage).is_none() {
            kill_quietly(&mut child);
            return;
        }
    }
    let meta = std::fs::symlink_metadata(&fixture).unwrap();
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
    let link_denied = |err: &AttachError| {
        matches!(
            err,
            AttachError::LinkFailed { errno, .. }
                if *errno == libc::EPERM || *errno == libc::EACCES
        )
    };
    let entry = attach_group(
        &group(true),
        &guard,
        &loaded.progs.entry,
        &fixture,
        &[offset],
    );
    let _entry_link = match or_skip(entry, link_denied, "entry attach") {
        Some(link) => link,
        None => {
            kill_quietly(&mut child);
            return;
        }
    };
    let ret = attach_group(
        &group(false),
        &guard,
        &loaded.progs.ret,
        &fixture,
        &[offset],
    );
    let _ret_link = match or_skip(ret, link_denied, "return attach") {
        Some(link) => link,
        None => {
            kill_quietly(&mut child);
            return;
        }
    };
    let config = DrainConfig {
        max_events_per_iter: 128,
        queue_depth: 1024,
        poll_timeout_ms: 50,
    };
    let drain =
        DrainThread::spawn(&loaded.maps.events, 262_144, &config).expect("drain must spawn");
    child.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
    let done = await_line(&lines, "DONE", Duration::from_secs(30));
    assert!(done.starts_with("DONE "), "fixture misbehaved: {done}");
    // DONE+2s grace drain, then stop.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut records: Vec<Vec<u8>> = Vec::new();
    while Instant::now() < deadline {
        match drain.receiver().recv_timeout(Duration::from_millis(100)) {
            Ok(DrainEvent::Record(bytes)) => records.push(bytes),
            Ok(DrainEvent::Barrier(_)) => {}
            Err(_) => {}
        }
    }
    // Drain anything left queued before stopping.
    while let Ok(DrainEvent::Record(bytes)) = drain.receiver().try_recv() {
        records.push(bytes);
    }
    let stats = drain.stop();
    let status = child.wait().expect("fixture must exit");
    assert!(status.success(), "fixture failed: {status}");

    let mut entries = 0u64;
    let mut returns = 0u64;
    let mut seqs: Vec<u64> = Vec::with_capacity(records.len());
    for bytes in &records {
        let view = view_event(bytes);
        assert_eq!(view.cookie >> 32, u64::from(GENERATION), "stale gen leaked");
        assert_eq!(view.cookie & 0xffff_ffff, 0, "bad offset index");
        match view.flags {
            0 => entries += 1,
            1 => returns += 1,
            other => panic!("bad flags {other}"),
        }
        seqs.push(view.seq);
    }
    seqs.sort_unstable();
    let want: Vec<u64> = (1..=2 * CALLS).collect();
    // COUNT cross-check: per-idx counter includes ring-failed hits.
    let count_sum = map_lookup_percpu_sum(&loaded.maps.count, 0, "count/sum").unwrap();
    let ring = map_lookup_percpu_sum(&loaded.maps.loss, 0, "loss/ring").unwrap();
    let dropped = map_lookup_percpu_sum(&loaded.maps.loss, 1, "loss/drop").unwrap();
    assert_eq!(
        count_sum,
        records.len() as u64 + ring,
        "COUNT must cover received+ring"
    );
    assert_eq!(entries, CALLS, "entry count drifted");
    assert_eq!(returns, CALLS, "return count drifted");
    assert_eq!(seqs, want, "seqs must cover 1..=2N exactly once");
    assert_eq!(stats.queue_drops, 0, "userspace queue must not drop");
    let ledger = LossLedger {
        exact: 2 * CALLS,
        received: records.len() as u64,
        drops: ring + dropped,
    };
    assert_eq!(
        ledger.reconcile(),
        ReconcileVerdict::Clean,
        "reconcile must be Clean (entries={entries} returns={returns} ring={ring} drop={dropped})"
    );
}
