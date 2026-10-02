// SPDX-License-Identifier: GPL-3.0-or-later
//! Decoy-pid harness driver (FU6): BPF TGID/generation guard negatives.
//!
//! Two privileged cells share one load → spawn → attach → drain shape
//! (borrowed from the T7 lane). Observation only: callers own the
//! strict asserts. Denials surface as [`BpfSelftestError::Denied`] for
//! honest-degraded skips; everything else is a hard error.

use crate::attach::{AttachError, OwnedLink, UPROBE_MULTI_RETURN};
use crate::bpfloader::{LoadedSpine, LoaderError};
use crate::bpfselftest::{
    BpfSelftestError, await_line, is_denied, kill_quietly, loader_outcome, pump_lines,
};
use crate::drain::{DrainEvent, DrainThread};
use crate::elfread::{ElfBytes, MmapGuard};
use crate::fd::OwnedFd;
use crate::local::LocalPrivilegedAuthority;
use crate::mapops::{MapOpsError, map_lookup_percpu_sum, map_update};
use crate::probe::bpf_sys::{
    BPF_LINK_CREATE, BPF_TRACE_UPROBE_MULTI, LinkUprobeMulti, bpf, fd_or_errno,
};
use core::ffi::c_void;
use kryprobe_core::attach::{COUNT_SLOTS, cookie_for};
use kryprobe_core::authority::{AttachAuthority, BpfLoadAuthority};
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{
    CookieAllocator, CookieRange, DrainConfig, GenerationGuard, LinkGroup, LossLedger, ProgramId,
};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Test generation pinned into cookies.
const GENERATION: u32 = 1;
/// Ring size for the drain thread (matches the T7 lane).
const RING_BYTES: u32 = 262_144;

/// Serializes the privileged cells within this process.
///
/// The TGID cell attaches path-wide (pid 0): its link fires for EVERY
/// process executing the fixture path, including a sibling cell's
/// fixture running concurrently in another test thread. Those foreign
/// hits land in the TGID cell's LOSS[1] and break its exact-count
/// assert (150 = 100 decoy + 50 stale-gen). Both cells hold this lock
/// for their full load → attach → drain → read-counters span, so the
/// wide link can never observe a sibling fixture. Runner flags
/// (`--test-threads=1`) cannot be relied on; the serialization lives
/// here, at the shared-resource boundary.
static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire the cell lock, tolerating poisoning: each cell loads fresh
/// BPF state, so a prior cell's panic leaves no shared state to
/// distrust — failing open on poison keeps one failure from
/// cascading into a lock panic in the next cell.
fn lock_cell() -> std::sync::MutexGuard<'static, ()> {
    CELL_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// TGID cell inputs: target + decoy call counts plus artifact paths.
#[derive(Debug)]
pub struct DecoyConfig {
    /// Target fixture calls (2 clean records per call).
    pub target_calls: u64,
    /// Decoy fixture calls (2 guard drops per call).
    pub decoy_calls: u64,
    /// Built spine object path.
    pub object: PathBuf,
    /// `spine_fixture` binary path.
    pub fixture: PathBuf,
}

/// Stale-generation cell inputs: call count plus artifact paths.
#[derive(Debug)]
pub struct StaleGenConfig {
    /// Fixture calls (2 guard drops per call, zero records).
    pub calls: u64,
    /// Built spine object path.
    pub object: PathBuf,
    /// `spine_fixture` binary path.
    pub fixture: PathBuf,
}

/// Everything a cell observes: drained records, COUNT slots, all three
/// LOSS buckets, queue drops, and both processes' exits.
#[derive(Debug)]
pub struct DecoyOutcome {
    /// Target fixture pid (pinned into CONFIG[1]).
    pub target_pid: u32,
    /// Decoy fixture pid (`None` when the cell spawns no decoy).
    pub decoy_pid: Option<u32>,
    /// Drained spine records.
    pub records: Vec<Vec<u8>>,
    /// Entry group's COUNT index base.
    pub entry_base: u32,
    /// Return group's COUNT index base.
    pub ret_base: u32,
    /// Entry COUNT slot.
    pub count_entry: u64,
    /// Return COUNT slot.
    pub count_ret: u64,
    /// Ringbuf reservation failures (LOSS[0]).
    pub ring: u64,
    /// BPF-side guard drops (LOSS[1]).
    pub dropped: u64,
    /// Wide-CONFIG refusals (LOSS[2]).
    pub truncated: u64,
    /// Userspace queue drops.
    pub queue_drops: u64,
    /// Target exit code (`None` when killed by signal).
    pub target_exit: Option<i32>,
    /// Decoy exit code (`None` when the cell spawns no decoy).
    pub decoy_exit: Option<i32>,
}

/// Loss ledger for a decoy run: both processes' hits are exact
/// (2 per call), target hits are received, decoy hits are drops.
pub fn decoy_ledger(target_calls: u64, decoy_calls: u64, received: u64, drops: u64) -> LossLedger {
    LossLedger {
        exact: target_calls.saturating_add(decoy_calls).saturating_mul(2),
        received,
        drops,
    }
}

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

fn load_or_denied(object: &Path) -> Result<LoadedSpine, BpfSelftestError> {
    if !object.is_file() {
        return Err(BpfSelftestError::MissingArtifact {
            what: "object",
            path: object.to_path_buf(),
        });
    }
    let guard = MmapGuard::open(object).map_err(|err| {
        BpfSelftestError::Loader(LoaderError::Io {
            stage: "open",
            detail: format!("{}: {err:#}", object.display()),
        })
    })?;
    LocalPrivilegedAuthority
        .load_program(ProgramId::UprobeMultiSelfProbe, guard.bytes())
        .map_err(loader_outcome)
}

fn spawn_fixture(
    fixture: &Path,
    calls: u64,
) -> Result<(Child, std::sync::mpsc::Receiver<String>), BpfSelftestError> {
    let mut child = Command::new(fixture)
        .arg(calls.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    let lines = pump_lines(child.stdout.take().expect("piped stdout"));
    if await_line(&lines, "READY", Duration::from_secs(10))? != "READY" {
        kill_quietly(&mut child);
        return Err(BpfSelftestError::BadEvent("READY line malformed"));
    }
    Ok((child, lines))
}

fn go(child: &mut Child) -> Result<(), BpfSelftestError> {
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(b"GO\n")
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))
}

fn await_done(lines: &std::sync::mpsc::Receiver<String>) -> Result<(), BpfSelftestError> {
    let done = await_line(lines, "DONE", Duration::from_secs(30))?;
    if !done.starts_with("DONE ") {
        return Err(BpfSelftestError::BadEvent("DONE line malformed"));
    }
    Ok(())
}

/// Attached entry+return pair; links stay bound until dropped.
struct AttachedPair {
    _entry: crate::attach::OwnedLink,
    _ret: crate::attach::OwnedLink,
    entry_base: u32,
    ret_base: u32,
}

fn attach_pair(
    loaded: &LoadedSpine,
    fixture: &Path,
    link_pid: u32,
    generation: PlanGeneration,
    offset: u64,
) -> Result<AttachedPair, BpfSelftestError> {
    let meta = std::fs::symlink_metadata(fixture)
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
    let mut cookies = CookieAllocator::new(generation);
    let alloc = |cookies: &mut CookieAllocator, stage: &'static str| {
        cookies.allocate(1).map_err(|err| {
            BpfSelftestError::Fixture(format!("{stage}: cookie allocation failed: {err}"))
        })
    };
    let entry_range = alloc(&mut cookies, "entry attach")?;
    let ret_range = alloc(&mut cookies, "return attach")?;
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
            TargetScope::Pid { pid: link_pid },
            entry,
            range,
        )
    };
    let guard = GenerationGuard { generation };
    let attach = |prog: &OwnedFd, entry: bool, range: CookieRange, stage: &'static str| {
        if link_pid == 0 {
            // TGID cell only: the facet refuses pid 0 for every caller
            // (B10), so the harness issues its path-wide link itself —
            // see `attach_wide_raw`. No production path reaches this.
            return attach_wide_raw(&guard, prog, entry, range, fixture, offset, stage);
        }
        LocalPrivilegedAuthority
            .attach_group(&group(entry, range), &guard, prog, fixture, &[offset])
            .map_err(|err| match err {
                AttachError::LinkFailed { errno, .. } if is_denied(errno) => {
                    BpfSelftestError::Denied {
                        stage: stage.to_owned(),
                        errno,
                    }
                }
                other => BpfSelftestError::Fixture(format!("attach failed: {other:?}")),
            })
    };
    let entry = attach(&loaded.progs.entry, true, entry_range, "entry attach")?;
    let ret = attach(&loaded.progs.ret, false, ret_range, "return attach")?;
    Ok(AttachedPair {
        _entry: entry,
        _ret: ret,
        entry_base: entry_range.base(),
        ret_base: ret_range.base(),
    })
}

/// Test-local path-wide link-create for the TGID cell ONLY.
///
/// Why this bypass exists: the cell proves the BPF TGID guard
/// discriminates target hits (kept) from foreign hits (dropped plus
/// exactly counted). That proof requires a path-wide (pid 0)
/// uprobe-multi link — the guard must actually SEE foreign hits to
/// drop them, and a pid-scoped link can never deliver any. The
/// production facet refuses pid 0 for every caller (T16 B10: a zero
/// pid would widen a single-target scope system-wide), and it keeps
/// doing so: this helper never routes through the facet, and no
/// production path calls this helper (its only caller is
/// `drive_tgid`, itself reachable only from the `decoy_pid`
/// integration test). A test-only exemption inside the facet was
/// rejected for the same reason — the refusal must hold for all
/// production paths, unconditionally.
///
/// The helper mirrors the facet's checks (stale guard, saturating
/// index-range validation, raw-byte UTF-8/NUL path handling,
/// [`cookie_for`] stamps) minus the pid-0 refusal, over a single
/// offset (nonempty by construction). It issues the syscall through
/// the shared `bpf()` wrapper, so the privilege-seam gate (no new
/// raw entry point) still holds, and it maps EPERM/EACCES to
/// [`BpfSelftestError::Denied`] so unprivileged runs keep skipping
/// honestly at the link stage if load ever passes without link.
fn attach_wide_raw(
    guard: &GenerationGuard,
    prog_fd: &OwnedFd,
    entry: bool,
    range: CookieRange,
    object: &Path,
    offset: u64,
    stage: &'static str,
) -> Result<OwnedLink, BpfSelftestError> {
    if guard.is_stale(range.generation()) {
        return Err(BpfSelftestError::Fixture(format!(
            "wide attach: stale plan generation: range {}, guard {}",
            range.generation(),
            guard.generation
        )));
    }
    let offsets = [offset];
    if u64::from(range.base()).saturating_add(offsets.len() as u64) > u64::from(COUNT_SLOTS) {
        return Err(BpfSelftestError::Fixture(format!(
            "wide attach: cookie index range overflows {} slots: base {} + {} offsets",
            COUNT_SLOTS,
            range.base(),
            offsets.len()
        )));
    }
    // Raw bytes, never lossy — same discipline as the facet.
    let raw = object.as_os_str().as_bytes();
    if std::str::from_utf8(raw).is_err() {
        return Err(BpfSelftestError::Fixture(
            "wide attach: object path is not valid UTF-8".to_owned(),
        ));
    }
    let path_c = CString::new(raw).map_err(|_| {
        BpfSelftestError::Fixture("wide attach: object path is not NUL-safe".to_owned())
    })?;
    let cookies: Vec<u64> = (0..offsets.len() as u32)
        .map(|i| cookie_for(range.generation(), range.base() + i))
        .collect();
    let mut attr = LinkUprobeMulti {
        prog_fd: prog_fd.as_raw_fd() as u32,
        target: 0,
        attach_type: BPF_TRACE_UPROBE_MULTI,
        link_flags: 0,
        path: path_c.as_ptr() as u64,
        offsets: offsets.as_ptr() as u64,
        ref_ctr_offsets: 0,
        cookies: cookies.as_ptr() as u64,
        cnt: offsets.len() as u32,
        um_flags: if entry { 0 } else { UPROBE_MULTI_RETURN },
        pid: 0,
        pad: 0,
    };
    // SAFETY: attr + pointees (path, offsets, cookies) outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_LINK_CREATE,
            (&raw mut attr).cast::<c_void>(),
            size_of::<LinkUprobeMulti>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(fd) => Ok(OwnedLink::from_fd(fd)),
        Err(errno) if is_denied(errno) => Err(BpfSelftestError::Denied {
            stage: stage.to_owned(),
            errno,
        }),
        Err(errno) => Err(BpfSelftestError::Fixture(format!(
            "wide attach failed at {stage}: errno {errno}"
        ))),
    }
}

fn arm_maps(loaded: &LoadedSpine, gen_value: u64, tgid_value: u64) -> Result<(), BpfSelftestError> {
    for (map, key, value, stage) in [
        (&loaded.maps.config, 0, gen_value, "config/gen"),
        (&loaded.maps.config, 1, tgid_value, "config/tgid"),
        (&loaded.maps.start, 0, 1, "start/arm"),
    ] {
        map_update(map, key, value, stage).map_err(|err| map_denied(stage, err))?;
    }
    Ok(())
}

fn drain_config() -> DrainConfig {
    DrainConfig {
        max_events_per_iter: 4096,
        queue_depth: 65536,
        poll_timeout_ms: 50,
    }
}

/// DONE+2s grace drain: collects records until the deadline, then
/// join-then-sweeps the drain thread (P7/T12): the worker is joined
/// BEFORE the final channel sweep, so records forwarded after the
/// collector's last receive are collected, never dropped with the
/// channel.
fn grace_drain(drain: DrainThread) -> (Vec<Vec<u8>>, u64) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut records: Vec<Vec<u8>> = Vec::new();
    while Instant::now() < deadline {
        match drain.receiver().recv_timeout(Duration::from_millis(100)) {
            Ok(DrainEvent::Record(bytes)) => records.push(bytes),
            Ok(DrainEvent::Barrier(_)) => {}
            Err(_) => {}
        }
    }
    let (stats, tail) = drain.stop_and_drain();
    for event in tail {
        if let DrainEvent::Record(bytes) = event {
            records.push(bytes);
        }
    }
    (records, stats.queue_drops)
}

fn read_counters(
    loaded: &LoadedSpine,
    entry_base: u32,
    ret_base: u32,
) -> Result<(u64, u64, u64, u64, u64), BpfSelftestError> {
    let count_entry = map_lookup_percpu_sum(&loaded.maps.count, entry_base, "count/entry")
        .map_err(|err| map_denied("count/entry", err))?;
    let count_ret = map_lookup_percpu_sum(&loaded.maps.count, ret_base, "count/ret")
        .map_err(|err| map_denied("count/ret", err))?;
    let ring = map_lookup_percpu_sum(&loaded.maps.loss, 0, "loss/ring")
        .map_err(|err| map_denied("loss/ring", err))?;
    let dropped = map_lookup_percpu_sum(&loaded.maps.loss, 1, "loss/drop")
        .map_err(|err| map_denied("loss/drop", err))?;
    let truncated = map_lookup_percpu_sum(&loaded.maps.loss, 2, "loss/trunc")
        .map_err(|err| map_denied("loss/trunc", err))?;
    Ok((count_entry, count_ret, ring, dropped, truncated))
}

fn resolve_offset(fixture: &Path) -> Result<u64, BpfSelftestError> {
    let bytes = std::fs::read(fixture).map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    crate::elfread::goblin_parser::static_symbol_file_offset(&bytes, "spine_target_fn")
        .map_err(|err| BpfSelftestError::Fixture(format!("{err:?}")))?
        .ok_or(BpfSelftestError::BadEvent("spine_target_fn unresolved"))
}

fn wait_exit(child: &mut Child) -> Result<Option<i32>, BpfSelftestError> {
    let status = child
        .wait()
        .map_err(|err| BpfSelftestError::Fixture(err.to_string()))?;
    if !status.success() {
        return Err(BpfSelftestError::FixtureExit(status.code().unwrap_or(-1)));
    }
    Ok(status.code())
}

/// TGID cell: path-wide link (pid 0 fans out to every process
/// executing the fixture path), CONFIG pinned to the target pid.
/// The decoy emits concurrently; the BPF TGID guard is the only
/// confinement, so its drops are exactly the decoy's hits. The wide
/// link is issued by the harness's test-local raw path
/// ([`attach_wide_raw`]), never through the facet — the facet's
/// pid-0 refusal (T16 B10) stays unconditional for all callers that
/// route through it.
pub fn run_tgid_cell(config: &DecoyConfig) -> Result<DecoyOutcome, BpfSelftestError> {
    // Held for the whole cell: the wide link must not observe a sibling
    // fixture. See CELL_LOCK.
    let _cell = lock_cell();
    if !config.fixture.is_file() {
        return Err(BpfSelftestError::MissingArtifact {
            what: "fixture",
            path: config.fixture.clone(),
        });
    }
    let loaded = load_or_denied(&config.object)?;
    let offset = resolve_offset(&config.fixture)?;
    let (mut target, target_lines) = spawn_fixture(&config.fixture, config.target_calls)?;
    let (mut decoy, decoy_lines) = match spawn_fixture(&config.fixture, config.decoy_calls) {
        Ok(pair) => pair,
        Err(err) => {
            kill_quietly(&mut target);
            return Err(err);
        }
    };
    let outcome = drive_tgid(
        config,
        &loaded,
        offset,
        &mut target,
        &target_lines,
        &mut decoy,
        &decoy_lines,
    );
    if outcome.is_err() {
        kill_quietly(&mut target);
        kill_quietly(&mut decoy);
    }
    outcome
}

fn drive_tgid(
    config: &DecoyConfig,
    loaded: &LoadedSpine,
    offset: u64,
    target: &mut Child,
    target_lines: &std::sync::mpsc::Receiver<String>,
    decoy: &mut Child,
    decoy_lines: &std::sync::mpsc::Receiver<String>,
) -> Result<DecoyOutcome, BpfSelftestError> {
    let target_pid = target.id();
    let decoy_pid = decoy.id();
    arm_maps(loaded, u64::from(GENERATION), u64::from(target_pid))?;
    let generation = PlanGeneration::new(GENERATION);
    let pair = attach_pair(loaded, &config.fixture, 0, generation, offset)?;
    let drain = DrainThread::spawn(&loaded.maps.events, RING_BYTES, &drain_config())
        .map_err(|err| BpfSelftestError::Drain(format!("{err:?}")))?;
    go(target)?;
    go(decoy)?;
    await_done(target_lines)?;
    await_done(decoy_lines)?;
    let (records, queue_drops) = grace_drain(drain);
    let (entry_base, ret_base) = (pair.entry_base, pair.ret_base);
    drop(pair);
    let target_exit = wait_exit(target)?;
    let decoy_exit = wait_exit(decoy)?;
    let (count_entry, count_ret, ring, dropped, truncated) =
        read_counters(loaded, entry_base, ret_base)?;
    Ok(DecoyOutcome {
        target_pid,
        decoy_pid: Some(decoy_pid),
        records,
        entry_base,
        ret_base,
        count_entry,
        count_ret,
        ring,
        dropped,
        truncated,
        queue_drops,
        target_exit,
        decoy_exit,
    })
}

/// Stale-generation cell: attach with generation-1 cookies, then rotate
/// CONFIG[0] to generation 2 before GO. Every hit carries a stale
/// cookie, so the BPF generation guard drops all of them.
pub fn run_stale_gen_cell(config: &StaleGenConfig) -> Result<DecoyOutcome, BpfSelftestError> {
    // Held for the whole cell: this cell's fixture must not run while a
    // sibling holds the wide link. See CELL_LOCK.
    let _cell = lock_cell();
    if !config.fixture.is_file() {
        return Err(BpfSelftestError::MissingArtifact {
            what: "fixture",
            path: config.fixture.clone(),
        });
    }
    let loaded = load_or_denied(&config.object)?;
    let offset = resolve_offset(&config.fixture)?;
    let (mut target, lines) = spawn_fixture(&config.fixture, config.calls)?;
    let outcome = drive_stale_gen(config, &loaded, offset, &mut target, &lines);
    if outcome.is_err() {
        kill_quietly(&mut target);
    }
    outcome
}

fn drive_stale_gen(
    config: &StaleGenConfig,
    loaded: &LoadedSpine,
    offset: u64,
    target: &mut Child,
    lines: &std::sync::mpsc::Receiver<String>,
) -> Result<DecoyOutcome, BpfSelftestError> {
    let target_pid = target.id();
    let generation = PlanGeneration::new(GENERATION);
    // Attach first (guard agrees with the cookie generation), then
    // rotate CONFIG stale: the plan moved on, the cookies did not.
    let pair = attach_pair(loaded, &config.fixture, target_pid, generation, offset)?;
    arm_maps(loaded, u64::from(GENERATION + 1), u64::from(target_pid))?;
    let drain = DrainThread::spawn(&loaded.maps.events, RING_BYTES, &drain_config())
        .map_err(|err| BpfSelftestError::Drain(format!("{err:?}")))?;
    go(target)?;
    await_done(lines)?;
    let (records, queue_drops) = grace_drain(drain);
    let (entry_base, ret_base) = (pair.entry_base, pair.ret_base);
    drop(pair);
    let target_exit = wait_exit(target)?;
    let (count_entry, count_ret, ring, dropped, truncated) =
        read_counters(loaded, entry_base, ret_base)?;
    Ok(DecoyOutcome {
        target_pid,
        decoy_pid: None,
        records,
        entry_base,
        ret_base,
        count_entry,
        count_ret,
        ring,
        dropped,
        truncated,
        queue_drops,
        target_exit,
        decoy_exit: None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn unavailable_topology_refuses_decoy_counters_before_bpf() {
        use crate::mapops::topology_tests::{spine, with_topology};
        let (result, calls) = with_topology(None, || super::read_counters(&spine(), 0, 1));
        assert!(
            matches!(result, Err(super::BpfSelftestError::Map(_))),
            "{result:?}"
        );
        assert_eq!(calls, 0, "topology refusal must precede the first lookup");
    }

    use super::*;
    use kryprobe_core::ReconcileVerdict;

    #[test]
    fn decoy_ledger_counts_both_processes_exact() {
        let ledger = decoy_ledger(200, 50, 400, 100);
        assert_eq!(ledger.exact, 500);
        assert_eq!(ledger.received, 400);
        assert_eq!(ledger.drops, 100);
        assert_eq!(ledger.reconcile(), ReconcileVerdict::Clean);
    }

    #[test]
    fn decoy_ledger_saturates_hostile_counts() {
        let ledger = decoy_ledger(u64::MAX, u64::MAX, 0, 0);
        assert_eq!(ledger.exact, u64::MAX);
        assert_eq!(
            ledger.reconcile(),
            ReconcileVerdict::Partial { missing: u64::MAX }
        );
    }
}
