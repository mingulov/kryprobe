// SPDX-License-Identifier: GPL-3.0-or-later
//! BPF spine pipeline: object presence + attach/drain/loss roundtrip.
//!
//! The presence test names `cargo xtask build --bpf` when the object is
//! missing. The roundtrip test is `#[ignore]`d (needs privilege or
//! honest-Denied paths); run it with `cargo xtask test bpf`.

use kryprobe_core::authority::{AttachAuthority, BpfLoadAuthority};
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{
    CookieAllocator, CookieRange, DrainConfig, GenerationGuard, LinkGroup, LossLedger, ProgramId,
    ReconcileVerdict,
};
use kryprobe_privilege::LocalPrivilegedAuthority;
use kryprobe_privilege::attach::AttachError;
use kryprobe_privilege::bpfloader::{LoadedSpine, LoaderError};
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
/// Fixture call count for the wide-CONFIG lane (10 calls → 20 refused hits).
const WIDE_CALLS: u64 = 10;

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

/// Load the spine object, or honestly skip when unprivileged.
/// Returns `None` to skip; panics on dishonest failure.
fn load_spine_or_skip() -> Option<LoadedSpine> {
    let object = spine_object_path();
    assert!(
        object.is_file(),
        "missing BPF spine object at {} — run `cargo xtask test bpf`",
        object.display()
    );
    // Load first: unprivileged runs prove the Denied path without a fixture.
    let bytes = std::fs::read(&object).expect("spine object must be readable");
    match LocalPrivilegedAuthority.load_program(ProgramId::UprobeMultiSelfProbe, &bytes) {
        Ok(loaded) => Some(loaded),
        Err(LoaderError::MapFailed { errno, .. }) | Err(LoaderError::LoadFailed { errno, .. })
            if errno == libc::EPERM || errno == libc::EACCES =>
        {
            eprintln!("pipeline: unprivileged, loader honestly denied (errno {errno})");
            None
        }
        Err(other) => panic!("loader failed dishonestly: {other}"),
    }
}

/// TGID value pinned into CONFIG[1]: the fixture pid, or a wide
/// out-of-u32 value whose low 32 bits equal the pid (so a truncating
/// gate would pass it — the regression oracle for borrow (a)).
#[derive(Debug, Clone, Copy)]
enum ConfigTgid {
    Pid,
    Wide,
}

/// Roundtrip knobs: the clean lane pins narrow CONFIG values; the
/// wide-CONFIG lane injects one out-of-u32 CONFIG value.
struct RoundtripSpec {
    calls: u64,
    gen_value: u64,
    tgid: ConfigTgid,
}

/// Everything a roundtrip observes: drained records, COUNT slots, all
/// three LOSS buckets, and the userspace queue drops.
struct RoundtripObserved {
    records: Vec<Vec<u8>>,
    entry_base: u32,
    ret_base: u32,
    count_entry: u64,
    count_ret: u64,
    ring: u64,
    dropped: u64,
    truncated: u64,
    queue_drops: u64,
}

#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn bpf_pipeline_clean_or_denied() {
    let Some(loaded) = load_spine_or_skip() else {
        return;
    };
    let Some(obs) = privileged_roundtrip(
        &loaded,
        &RoundtripSpec {
            calls: CALLS,
            gen_value: u64::from(GENERATION),
            tgid: ConfigTgid::Pid,
        },
    ) else {
        return;
    };
    let mut entries = 0u64;
    let mut returns = 0u64;
    let mut entry_seqs: Vec<u64> = Vec::with_capacity(obs.records.len());
    let mut ret_seqs: Vec<u64> = Vec::with_capacity(obs.records.len());
    for bytes in &obs.records {
        let view = view_event(bytes);
        assert_eq!(view.cookie >> 32, u64::from(GENERATION), "stale gen leaked");
        match view.flags {
            0 => {
                assert_eq!(
                    view.cookie & 0xffff_ffff,
                    u64::from(obs.entry_base),
                    "entry index drifted"
                );
                entries += 1;
                entry_seqs.push(view.seq);
            }
            1 => {
                assert_eq!(
                    view.cookie & 0xffff_ffff,
                    u64::from(obs.ret_base),
                    "return index drifted"
                );
                returns += 1;
                ret_seqs.push(view.seq);
            }
            other => panic!("bad flags {other}"),
        }
    }
    entry_seqs.sort_unstable();
    ret_seqs.sort_unstable();
    let want: Vec<u64> = (1..=CALLS).collect();
    // COUNT cross-check: each group's slot covers its received hits plus
    // its ring-failed share (ring loss itself is unattributable, so only
    // the sum is exact).
    let count_sum = obs.count_entry.saturating_add(obs.count_ret);
    assert_eq!(
        count_sum,
        obs.records.len() as u64 + obs.ring,
        "COUNT must cover received+ring"
    );
    assert_eq!(entries, CALLS, "entry count drifted");
    assert_eq!(returns, CALLS, "return count drifted");
    assert_eq!(entry_seqs, want, "entry seqs must cover 1..=N exactly once");
    assert_eq!(ret_seqs, want, "return seqs must cover 1..=N exactly once");
    assert_eq!(obs.queue_drops, 0, "userspace queue must not drop");
    assert_eq!(
        obs.truncated, 0,
        "narrow CONFIG must never touch the truncation bucket"
    );
    let ledger = LossLedger {
        exact: 2 * CALLS,
        received: obs.records.len() as u64,
        drops: obs
            .ring
            .saturating_add(obs.dropped)
            .saturating_add(obs.truncated),
    };
    assert_eq!(
        ledger.reconcile(),
        ReconcileVerdict::Clean,
        "reconcile must be Clean (entries={entries} returns={returns} ring={} drop={} trunc={})",
        obs.ring,
        obs.dropped,
        obs.truncated,
    );
}

/// Wide CONFIG values are refused into LOSS[2], never silently
/// truncated (T10 borrow (a) from osslscope `count.rs`: a u64 value
/// wider than its u32 domain lands in a distinct counted bucket).
/// Each sub-case pins a CONFIG value whose low 32 bits are *correct*,
/// so a truncating gate would fire the probe instead of refusing it.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn bpf_pipeline_wide_config_refused() {
    let Some(loaded) = load_spine_or_skip() else {
        return;
    };
    let wide_gen = (1u64 << 32) | u64::from(GENERATION);
    for (what, spec) in [
        (
            "gen",
            RoundtripSpec {
                calls: WIDE_CALLS,
                gen_value: wide_gen,
                tgid: ConfigTgid::Pid,
            },
        ),
        (
            "tgid",
            RoundtripSpec {
                calls: WIDE_CALLS,
                gen_value: u64::from(GENERATION),
                tgid: ConfigTgid::Wide,
            },
        ),
    ] {
        let Some(obs) = privileged_roundtrip(&loaded, &spec) else {
            return;
        };
        assert!(
            obs.records.is_empty(),
            "wide {what}: probe must not fire ({} records leaked)",
            obs.records.len()
        );
        assert_eq!(obs.count_entry, 0, "wide {what}: COUNT must stay zero");
        assert_eq!(obs.count_ret, 0, "wide {what}: COUNT must stay zero");
        assert_eq!(obs.ring, 0, "wide {what}: no ring loss expected");
        assert_eq!(obs.dropped, 0, "wide {what}: no guard-drop expected");
        assert_eq!(
            obs.truncated,
            2 * WIDE_CALLS,
            "wide {what}: every hit (entry+return) must land in LOSS[2]"
        );
    }
}

/// Full attach/drain/loss roundtrip. Only runs with BPF privilege.
/// Returns `None` on honest-skip paths (partial caps mid-lane).
fn privileged_roundtrip(loaded: &LoadedSpine, spec: &RoundtripSpec) -> Option<RoundtripObserved> {
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
        .arg(spec.calls.to_string())
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
    let tgid_value = match spec.tgid {
        ConfigTgid::Pid => u64::from(pid),
        ConfigTgid::Wide => (1u64 << 32) | u64::from(pid),
    };
    let generation = PlanGeneration::new(GENERATION);
    let map_denied = |err: &MapOpsError| {
        matches!(
            err,
            MapOpsError::UpdateFailed { errno, .. }
                if *errno == libc::EPERM || *errno == libc::EACCES
        )
    };
    let updates = [
        (&loaded.maps.config, 0, spec.gen_value, "config/gen"),
        (&loaded.maps.config, 1, tgid_value, "config/tgid"),
        (&loaded.maps.start, 0, 1, "start/arm"),
    ];
    for (map, key, value, stage) in updates {
        if or_skip(map_update(map, key, value, stage), map_denied, stage).is_none() {
            kill_quietly(&mut child);
            return None;
        }
    }
    let meta = std::fs::symlink_metadata(&fixture).unwrap();
    let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
    let mut cookies = CookieAllocator::new(generation);
    let entry_range = cookies.allocate(1).expect("lane needs 2 of 64 slots");
    let ret_range = cookies.allocate(1).expect("lane needs 2 of 64 slots");
    let entry_base = entry_range.base();
    let ret_base = ret_range.base();
    let group = |entry: bool, range: CookieRange| {
        LinkGroup::from_range(
            ObjectRef {
                dev: meta.dev(),
                ino: meta.ino(),
                size: meta.size(),
                mtime: mtime_ns,
                role: ObjectRole::Executable,
            },
            ProgramId::UprobeMultiSelfProbe,
            TargetScope::Pid { pid },
            entry,
            range,
        )
    };
    let guard = GenerationGuard { generation };
    let link_denied = |err: &AttachError| {
        matches!(
            err,
            AttachError::LinkFailed { errno, .. }
                if *errno == libc::EPERM || *errno == libc::EACCES
        )
    };
    let entry = LocalPrivilegedAuthority.attach_group(
        &group(true, entry_range),
        &guard,
        &loaded.progs.entry,
        &fixture,
        &[offset],
    );
    let _entry_link = match or_skip(entry, link_denied, "entry attach") {
        Some(link) => link,
        None => {
            kill_quietly(&mut child);
            return None;
        }
    };
    let ret = LocalPrivilegedAuthority.attach_group(
        &group(false, ret_range),
        &guard,
        &loaded.progs.ret,
        &fixture,
        &[offset],
    );
    let _ret_link = match or_skip(ret, link_denied, "return attach") {
        Some(link) => link,
        None => {
            kill_quietly(&mut child);
            return None;
        }
    };
    let config = DrainConfig {
        max_events_per_iter: 128,
        queue_depth: 1024,
        poll_timeout_ms: 50,
    };
    let drain =
        DrainThread::spawn(&loaded.maps.events, 262_144, &config).expect("drain must spawn");
    // Baselines: lanes may share one load (the wide lane runs two
    // sub-cases), so counters are reported as deltas. The fixture
    // blocks on stdin until GO, so nothing can advance them first.
    let base_entry = map_lookup_percpu_sum(&loaded.maps.count, entry_base, "count/entry").unwrap();
    let base_ret = map_lookup_percpu_sum(&loaded.maps.count, ret_base, "count/ret").unwrap();
    let base_ring = map_lookup_percpu_sum(&loaded.maps.loss, 0, "loss/ring").unwrap();
    let base_dropped = map_lookup_percpu_sum(&loaded.maps.loss, 1, "loss/drop").unwrap();
    let base_trunc = map_lookup_percpu_sum(&loaded.maps.loss, 2, "loss/trunc").unwrap();
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

    // Observation only: callers own the assertions. Counters are
    // deltas over the pre-GO baselines (lanes may share one load).
    let count_entry = map_lookup_percpu_sum(&loaded.maps.count, entry_base, "count/entry")
        .unwrap()
        .saturating_sub(base_entry);
    let count_ret = map_lookup_percpu_sum(&loaded.maps.count, ret_base, "count/ret")
        .unwrap()
        .saturating_sub(base_ret);
    let ring = map_lookup_percpu_sum(&loaded.maps.loss, 0, "loss/ring")
        .unwrap()
        .saturating_sub(base_ring);
    let dropped = map_lookup_percpu_sum(&loaded.maps.loss, 1, "loss/drop")
        .unwrap()
        .saturating_sub(base_dropped);
    let truncated = map_lookup_percpu_sum(&loaded.maps.loss, 2, "loss/trunc")
        .unwrap()
        .saturating_sub(base_trunc);
    Some(RoundtripObserved {
        records,
        entry_base,
        ret_base,
        count_entry,
        count_ret,
        ring,
        dropped,
        truncated,
        queue_drops: stats.queue_drops,
    })
}
