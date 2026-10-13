// SPDX-License-Identifier: GPL-3.0-or-later
//! I02 (PRIV03) report-wide helper-economics measurement: one cgroup
//! with enough distinct TGID keys to exceed a single 4096-byte
//! request, served chunk-by-chunk through FRESH helper processes —
//! exactly the production one-shot shape (`finish_workload_report`
//! loops chunks, `serve_once` spawns per chunk, `run_serve` builds a
//! fresh `ResolverCache` per process).
//!
//! Measurement only: these tests pin the CURRENT economics (launches,
//! scans, cache hits, useful-output delta) so the coordinator can
//! select omit-vs-bounded-scheduling. The follow-up implementation
//! track replaces these baseline pins with the selected budget. No
//! product behavior is changed by this file.

use kryprobe_core::workload::{
    AttributionStatus, MetadataSnapshot, SnapshotInterval, SnapshotKey, SnapshotRequest,
    SnapshotResponse, decode_response, encode_request, resolve,
};
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SESSION: &str = "0123456789abcdef0123456789abcdef";
const OS_RELEASE: &str = "7.0.0-test";
const BOOT_ID: &str = "test-boot-id-001";
const KERNEL_A: &str = "7.0.0-test/test-boot-id-001";
/// Distinct TGIDs on ONE cgroup: under the 256-count cap, over the
/// 4096-byte budget as one request (asserted, never assumed).
const KEY_COUNT: u64 = 120;
const FIRST_TGID: u32 = 2000;

fn helper_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kryprobe-workload-helper"))
}

fn scratch_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kwh-i02-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock")
            .as_nanos()
    ))
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent");
    }
    fs::write(path, bytes).expect("fixture write");
}

/// Fixture host view: proc root (kernel identity + uptime + optional
/// pids) and cgroup root. Removed on drop; only paths created here.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn create(tag: &str) -> Self {
        let dir = scratch_dir(tag);
        write_file(
            &dir.join("proc/sys/kernel/osrelease"),
            format!("{OS_RELEASE}\n").as_bytes(),
        );
        write_file(
            &dir.join("proc/sys/kernel/random/boot_id"),
            format!("{BOOT_ID}\n").as_bytes(),
        );
        write_file(&dir.join("proc/uptime"), b"100.00 200.00\n");
        fs::create_dir_all(dir.join("cgroup")).expect("cgroup root");
        Self { dir }
    }

    fn proc_root(&self) -> PathBuf {
        self.dir.join("proc")
    }

    fn cgroup_root(&self) -> PathBuf {
        self.dir.join("cgroup")
    }

    /// Create `<cgroup-root>/<rel>`; return its inode (the simulated
    /// kernel cgroup id for keys built against this fixture).
    fn cgroup_dir(&self, rel: &str) -> u64 {
        let path = self.cgroup_root().join(rel);
        fs::create_dir_all(&path).expect("cgroup dir");
        fs::metadata(&path).expect("cgroup stat").ino()
    }

    /// Create a fake `<proc>/<tgid>/` with cgroup hint + stat starttime.
    fn pid(&self, tgid: u32, cgroup_hint: &str, start_ticks: u64) {
        let base = self.proc_root().join(tgid.to_string());
        write_file(
            &base.join("cgroup"),
            format!("0::{cgroup_hint}\n").as_bytes(),
        );
        write_file(
            &base.join("stat"),
            format!(
                "{tgid} (fixture-proc) R 1 1 1 0 -1 4194304 10 0 0 0 5 5 0 0 20 0 2 0 {start_ticks} 0 0\n"
            )
            .as_bytes(),
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn key(cgroup: u64, tgid: u32) -> SnapshotKey {
    SnapshotKey {
        kernel_scope: KERNEL_A.to_string(),
        cgroup,
        tgid,
        start_ns: 555,
    }
}

fn interval() -> SnapshotInterval {
    SnapshotInterval {
        start_ns: 100,
        end_ns: 1000,
    }
}

/// Production-faithful greedy byte-budget split: same algorithm as the
/// CLI `split_request_batches` (accumulate, probe with the frozen
/// `encode_request`, cut on overflow). The CLI-level I02 test covers
/// the real splitter; this mirror lets the helper harness serve the
/// same chunk shapes one process per chunk.
fn split_like_production(keys: Vec<SnapshotKey>) -> Vec<SnapshotRequest> {
    let mut batches = Vec::new();
    let mut current: Vec<SnapshotKey> = Vec::new();
    for k in keys {
        current.push(k);
        let probe = SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: current.clone(),
            capture_interval: Some(interval()),
        };
        if encode_request(&probe).is_err() {
            let overflow = current.pop().expect("probed non-empty");
            if current.is_empty() {
                batches.push(SnapshotRequest {
                    session_id: SESSION.to_string(),
                    keys: vec![overflow],
                    capture_interval: Some(interval()),
                });
            } else {
                batches.push(SnapshotRequest {
                    session_id: SESSION.to_string(),
                    keys: std::mem::take(&mut current),
                    capture_interval: Some(interval()),
                });
                current.push(overflow);
            }
        }
    }
    if !current.is_empty() {
        batches.push(SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: current,
            capture_interval: Some(interval()),
        });
    }
    batches
}

struct Run {
    status: i32,
    stdout: Vec<u8>,
    stderr: String,
}

fn run_chunk(
    fixture: &Fixture,
    request: &SnapshotRequest,
) -> (SnapshotResponse, serde_json::Map<String, serde_json::Value>) {
    let stdin_bytes = serde_json::to_vec(request).expect("request encodes");
    let mut child = Command::new(helper_bin())
        .arg("--proc-root")
        .arg(fixture.proc_root())
        .arg("--cgroup-root")
        .arg(fixture.cgroup_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("helper spawns as ordinary user");
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(&stdin_bytes)
        .expect("stdin write lands (serve reads stdin)");
    let output = child.wait_with_output().expect("helper reaped");
    let run = Run {
        status: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    assert_eq!(run.status, 0, "chunk serves, stderr: {}", run.stderr);
    let response = decode_response(&run.stdout).expect("valid SnapshotResponse");
    let counters = run
        .stderr
        .lines()
        .find_map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()?
                .get("helper_counters")?
                .as_object()
                .cloned()
        })
        .unwrap_or_else(|| panic!("no helper_counters line in stderr: {}", run.stderr));
    (response, counters)
}

fn counter(counters: &serde_json::Map<String, serde_json::Value>, name: &str) -> u64 {
    counters
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// One merged report measurement: per-key outcomes plus summed
/// per-launch counters across all chunks.
struct ReportMeasurement {
    merged: Vec<(SnapshotKey, AttributionStatus, bool)>,
    hits: u64,
    neg_hits: u64,
    throttled: u64,
    inserts: u64,
    trips: u64,
}

/// Serve every chunk in its own fresh helper process; return merged
/// associations plus summed per-launch counters.
fn serve_report(fixture: &Fixture, chunks: &[SnapshotRequest]) -> ReportMeasurement {
    let mut merged = Vec::new();
    let (mut hits, mut neg_hits, mut throttled, mut inserts, mut trips) = (0u64, 0, 0, 0, 0);
    for (index, chunk) in chunks.iter().enumerate() {
        let (response, counters) = run_chunk(fixture, chunk);
        // Every chunk binds its own session/request (production merges
        // per-chunk answers the same way).
        assert_eq!(
            response.associations.len(),
            chunk.keys.len(),
            "chunk {index} answers every key"
        );
        hits += counter(&counters, "positive_hits");
        neg_hits += counter(&counters, "negative_hits");
        throttled += counter(&counters, "refresh_throttled");
        inserts += counter(&counters, "inserts");
        trips += counter(&counters, "deadline_trips");
        // Fresh cache per launch: no hits, no throttle, and the SAME
        // single binding re-learned once per key in this chunk.
        assert_eq!(
            counter(&counters, "positive_hits"),
            0,
            "chunk {index}: fresh cache, no positive hits"
        );
        assert_eq!(
            counter(&counters, "negative_hits"),
            0,
            "chunk {index}: fresh cache, no negative hits"
        );
        assert_eq!(
            counter(&counters, "refresh_throttled"),
            0,
            "chunk {index}: 1s refresh gate cannot throttle a fresh cache"
        );
        assert_eq!(
            counter(&counters, "deadline_trips"),
            0,
            "chunk {index}: no deadline trip"
        );
        assert_eq!(
            counter(&counters, "inserts"),
            chunk.keys.len() as u64,
            "chunk {index}: one batched scan re-inserts the same binding per key"
        );
        for assoc in &response.associations {
            merged.push((
                assoc.key.clone(),
                assoc.evidence.status,
                assoc.identity.is_resolved(),
            ));
        }
    }
    merged.sort_by_key(|(k, _, _)| (k.cgroup, k.tgid, k.start_ns));
    ReportMeasurement {
        merged,
        hits,
        neg_hits,
        throttled,
        inserts,
        trips,
    }
}

/// Pure frozen baseline over the FULL key set (no liveness): what the
/// report would carry if no helper scan ever ran. The helper mirrors
/// this snapshot when `--metadata` is absent (host kernel, no entries).
fn pure_baseline(keys: &[SnapshotKey]) -> Vec<(SnapshotKey, AttributionStatus, bool)> {
    let full = SnapshotRequest {
        session_id: SESSION.to_string(),
        keys: keys.to_vec(),
        capture_interval: Some(interval()),
    };
    let empty = MetadataSnapshot {
        collector: "i02-baseline".to_string(),
        snapshot_interval: interval(),
        kernel_identity: kryprobe_core::workload::KernelIdentity::Known(KERNEL_A.to_string()),
        entries: Vec::new(),
    };
    let response = resolve(&full, &empty).expect("pure resolve answers");
    let mut base: Vec<_> = response
        .associations
        .iter()
        .map(|assoc| {
            (
                assoc.key.clone(),
                assoc.evidence.status,
                assoc.identity.is_resolved(),
            )
        })
        .collect();
    base.sort_by_key(|(k, _, _)| (k.cgroup, k.tgid, k.start_ns));
    base
}

/// I02 primary: 120 live pids on ONE live cgroup. Every chunk's scans
/// succeed (pid checks pass, the object is found and cached) — yet no
/// chunk changes any usable output: R3 coherence keeps identity-less
/// liveness `Unresolved`, exactly as the pure baseline.
#[test]
fn one_cgroup_many_tgids_live_pids_rescan_per_chunk_without_useful_change() {
    let fixture = Fixture::create("live-pids");
    let live = fixture.cgroup_dir("live");
    for i in 0..KEY_COUNT {
        fixture.pid(FIRST_TGID + i as u32, "/live", 777);
    }
    let keys: Vec<SnapshotKey> = (0..KEY_COUNT)
        .map(|i| key(live, FIRST_TGID + i as u32))
        .collect();

    // Premise: one request cannot carry this report (the old code
    // refused the whole batch here).
    let single = SnapshotRequest {
        session_id: SESSION.to_string(),
        keys: keys.clone(),
        capture_interval: Some(interval()),
    };
    assert_eq!(
        encode_request(&single),
        Err(kryprobe_core::workload::MetadataUnavailable::BudgetExceeded),
        "120 same-cgroup keys exceed one 4096-byte request"
    );
    let chunks = split_like_production(keys.clone());
    assert!(chunks.len() > 1, "report spans several chunks");

    let measured = serve_report(&fixture, &chunks);

    // Useful-output delta: merged chunked answers vs pure no-liveness
    // baseline — identical per key (all Unresolved, no identity).
    let base = pure_baseline(&keys);
    assert_eq!(measured.merged.len(), KEY_COUNT as usize);
    assert_eq!(
        measured.merged, base,
        "successful scans change no usable output"
    );
    assert!(
        measured
            .merged
            .iter()
            .all(|(_, status, resolved)| *status == AttributionStatus::Unresolved && !resolved)
    );

    eprintln!(
        "I02_MEASUREMENT {}",
        serde_json::json!({
            "variant": "live_pids",
            "keys": KEY_COUNT,
            "cgroups": 1,
            "chunks": chunks.len(),
            "launches": chunks.len(),
            "scans": chunks.len(),
            "positive_hits": measured.hits,
            "negative_hits": measured.neg_hits,
            "refresh_throttled": measured.throttled,
            "inserts_same_binding": measured.inserts,
            "deadline_trips": measured.trips,
            "useful_output_delta_vs_pure": 0,
        })
    );
}

/// I02 secondary: same shape, captured TGIDs already gone (the common
/// post-interval case). Gone pids still allow cgroup liveness, so
/// every chunk still scans the same tree — and still changes nothing.
#[test]
fn one_cgroup_many_tgids_gone_pids_rescan_per_chunk_without_useful_change() {
    let fixture = Fixture::create("gone-pids");
    let live = fixture.cgroup_dir("live");
    // No pid dirs: every captured TGID is gone.
    let keys: Vec<SnapshotKey> = (0..KEY_COUNT)
        .map(|i| key(live, FIRST_TGID + i as u32))
        .collect();

    let single = SnapshotRequest {
        session_id: SESSION.to_string(),
        keys: keys.clone(),
        capture_interval: Some(interval()),
    };
    assert_eq!(
        encode_request(&single),
        Err(kryprobe_core::workload::MetadataUnavailable::BudgetExceeded),
        "120 same-cgroup keys exceed one 4096-byte request"
    );
    let chunks = split_like_production(keys.clone());
    assert!(chunks.len() > 1, "report spans several chunks");

    let measured = serve_report(&fixture, &chunks);

    let base = pure_baseline(&keys);
    assert_eq!(measured.merged.len(), KEY_COUNT as usize);
    assert_eq!(measured.merged, base, "scans change no usable output");
    assert!(
        measured
            .merged
            .iter()
            .all(|(_, status, resolved)| *status == AttributionStatus::Unresolved && !resolved)
    );

    eprintln!(
        "I02_MEASUREMENT {}",
        serde_json::json!({
            "variant": "gone_pids",
            "keys": KEY_COUNT,
            "cgroups": 1,
            "chunks": chunks.len(),
            "launches": chunks.len(),
            "scans": chunks.len(),
            "positive_hits": measured.hits,
            "negative_hits": measured.neg_hits,
            "refresh_throttled": measured.throttled,
            "inserts_same_binding": measured.inserts,
            "deadline_trips": measured.trips,
            "useful_output_delta_vs_pure": 0,
        })
    );
}
