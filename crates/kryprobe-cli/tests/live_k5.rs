// SPDX-License-Identifier: GPL-3.0-or-later
//! K5 Task 6: privileged live tests — setcap roundtrip + attribution goldens.
//!
//! Lane tests 1–3 are `#[ignore]` (run under sudo with the k5-bpf-lane
//! lock); they skip with a printed reason when not root or when BTF is
//! absent (the `live_session.rs` harness convention — `lane_ready`).
//! Test 4 refuses pre-load, never attaches, and runs everywhere: as root
//! it drops to `nobody` via `setpriv`, unprivileged it runs directly.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Traffic generator (hash-only mode default; proven lane fixture).
const GEN: &str = "/tmp/kcrypto_gen.py";

/// Decoded agg identity: family/op/result/algorithm/driver/context.
type DecodedIdentity = (String, String, String, String, String, String);

/// Test-2 golden maps: latest calls per (identity, `key_hash`) +
/// distinct hashes per alloc identity (split-key robustness, G-I1).
type DigestAgg = BTreeMap<(DecodedIdentity, u64), u64>;
type AllocKh = BTreeMap<DecodedIdentity, BTreeSet<u64>>;

/// Fully attached live session: 9 fexit symbols on the single sensor
/// (H1(b); was x 2 twins). K4 graded gate, mirrored from `live_session.rs`.
const ATTACHED_LINKS: usize = 9;

/// Built CLI under test (cargo builds the binary for integration tests).
fn kryprobe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kryprobe"))
}

/// Workspace-relative path of the built kcrypto object.
fn kcrypto_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/kryprobe-bpf/kcrypto.bpf.o")
}

fn is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

fn btf_available() -> bool {
    std::fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

/// Privileged-gate: true when this test must run (root + BTF).
/// Callers `return` early on false (honest skip, prints why).
fn lane_ready(name: &str) -> bool {
    if !is_root() {
        println!("SKIP: {name} requires root (euid != 0)");
        return false;
    }
    if !btf_available() {
        println!("SKIP: {name} requires /sys/kernel/btf/vmlinux");
        return false;
    }
    true
}

/// Suite serialization lock: live sensors are system-wide. Tests 1–3
/// hold this across their whole body (attach→detach). Poison-tolerant.
static SUITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn suite_guard() -> std::sync::MutexGuard<'static, ()> {
    SUITE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Unique scratch dir per test (no shared state). Removed on drop —
/// a gate failure must not leave temp copies behind either.
struct ScratchGuard(PathBuf);

fn scratch(name: &str) -> ScratchGuard {
    let dir = std::env::temp_dir().join(format!("kryprobe-k5-t6-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    ScratchGuard(dir)
}

impl ScratchGuard {
    fn path(&self) -> &std::path::Path {
        &self.0
    }

    /// Remove now (success path) and prove it is gone.
    fn remove_and_check(&self, test: &str) {
        std::fs::remove_dir_all(&self.0).ok();
        assert!(!self.0.exists(), "{test}: scratch removed");
    }
}

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Owns a live child; SIGKILLs + reaps on drop unless released. Lane
/// tests must never orphan a sensor when a gate fails (a wedged child
/// holds its fexit links until its window closes).
struct ChildGuard {
    child: Option<Child>,
    test: &'static str,
}

impl ChildGuard {
    fn new(test: &'static str, child: Child) -> Self {
        Self {
            child: Some(child),
            test,
        }
    }

    fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("guard holds the child")
    }

    fn release(mut self) -> Child {
        self.child.take().expect("guard holds the child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("{}: child reaped by guard", self.test);
        }
    }
}

/// A `bpftool link show` block header: `<id>:` followed by the link kind
/// (mirrored from `live_session.rs`).
fn is_link_header(line: &str) -> bool {
    let mut parts = line.splitn(2, ':');
    matches!(parts.next(), Some(id) if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_some()
}

/// Count TRUE `trace_fexit` links in `bpftool link show` output
/// (mirrored from `live_session.rs`: per-block, foreign links ignored).
fn count_trace_fexit_links(output: &str) -> usize {
    let mut count = 0;
    let mut in_block = false;
    let mut block_has_fexit = false;
    for line in output.lines() {
        if is_link_header(line) {
            in_block = true;
            block_has_fexit = false;
        } else if in_block && !block_has_fexit && line.contains("attach_type trace_fexit") {
            block_has_fexit = true;
            count += 1;
        }
    }
    count
}

/// Tracing-link count via bpftool. `None` when bpftool itself errors
/// (transient during attach storms — the caller retries).
fn link_count_or_none() -> Option<usize> {
    let output = Command::new("bpftool")
        .args(["link", "show"])
        .output()
        .or_else(|_| {
            Command::new("/usr/sbin/bpftool")
                .args(["link", "show"])
                .output()
        })
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(count_trace_fexit_links(&text))
}

/// Block until the session sensor is fully attached (deterministic
/// gate — no sleep-guessing against BPF load times), then settle.
/// Fails loudly when the lane starts dirty or attach never completes;
/// fails FAST with the child's output when the child dies first. The
/// guard returns to the caller on success (still owning the child).
fn gate_attach_and_settle(test: &'static str, guard: ChildGuard) -> ChildGuard {
    assert_eq!(
        link_count_or_none(),
        Some(0),
        "{test}: lane must start clean (no kryprobe-owned trace_fexit links)"
    );
    gate_wait(test, guard)
}

/// Same gate when an oracle already holds links (test 2: bpftrace's 2
/// fexit links are up before kryprobe starts, so the lane is not
/// clean — only the completion side applies).
fn gate_attach_only(test: &'static str, guard: ChildGuard) -> ChildGuard {
    gate_wait(test, guard)
}

fn gate_wait(test: &'static str, mut guard: ChildGuard) -> ChildGuard {
    // Generous ceiling: verifier + BTF resolve + 9 links run ~9s on a
    // quiet host but past 60s under heavy load (observed at loadavg
    // ~20); the child-liveness check keeps a real failure fast.
    const GATE_SECS: u64 = 180;
    let start = Instant::now();
    // Log the first poll immediately (evidence progress trail).
    let mut last_log = Instant::now() - Duration::from_secs(10);
    loop {
        if let Some(status) = guard.child().try_wait().expect("try_wait") {
            let output = guard.release().wait_with_output().expect("child output");
            panic!(
                "{test}: child exited {status} before attach\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if link_count_or_none().is_some_and(|n| n >= ATTACHED_LINKS) {
            break;
        }
        if last_log.elapsed() >= Duration::from_secs(5) {
            println!(
                "{test}: waiting for attach (links: {:?}, {:?} elapsed)",
                link_count_or_none(),
                start.elapsed()
            );
            last_log = Instant::now();
        }
        assert!(
            start.elapsed() < Duration::from_secs(GATE_SECS),
            "{test}: sensors attach within {GATE_SECS}s (links: {:?})",
            link_count_or_none()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("{test}: attach gate passed after {:?}", start.elapsed());
    // Controller note: settle before generating (the gate already
    // avoids the instant-burst-at-t0 wart; this is margin).
    std::thread::sleep(Duration::from_secs(2));
    guard
}

/// One hash-traffic round through the proven generator (default mode is
/// hash-only: 50 sha256 digests).
fn hash_traffic(test: &str) {
    let output = Command::new("python3")
        .args([GEN, "1"])
        .output()
        .expect("spawn kcrypto_gen.py");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{test}: generator must exit 0\nstdout: {stdout}\nstderr: {stderr}"
    );
    println!("{test}: traffic done:\n{stdout}");
}

/// `TOTAL` calls cell from `watch`/`report` human tables
/// (`TOTAL - - - CALLS BYTES OK QUEUED ERRORS`).
fn parse_total_calls(stdout: &str) -> Option<u64> {
    stdout
        .lines()
        .find(|line| line.starts_with("TOTAL "))
        .and_then(|line| line.split_whitespace().nth(4)?.parse().ok())
}

/// Drain a piped stream into a shared line buffer (reader thread).
fn drain_lines<R: Read + Send + 'static>(
    reader: R,
) -> (Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let out = Arc::clone(&lines);
    let handle = std::thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => out.lock().expect("drain lock").push(line),
                Err(_) => break,
            }
        }
    });
    (lines, handle)
}

/// Wait for a child with a hard timeout; SIGKILLs and panics past it
/// (lane tests are supervised, but a wedged child must stay loud).
fn wait_timeout(test: &str, child: &mut Child, secs: u64) {
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                assert!(
                    status.success(),
                    "{test}: child must exit 0, got {status:?}"
                );
                return;
            }
            None => {
                assert!(
                    start.elapsed() < Duration::from_secs(secs),
                    "{test}: child wedged past {secs}s"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// True when `setpriv` runs and the `nobody` user resolves.
fn setpriv_nobody_ready() -> bool {
    let setpriv = Command::new("setpriv").arg("--version").output().is_ok();
    let nobody = Command::new("id")
        .arg("nobody")
        .output()
        .is_ok_and(|out| out.status.success());
    setpriv && nobody
}

/// Spawn `args` on `binary` as `nobody` (root-only path): options
/// first, then the program — `setpriv` passes our explicit env through
/// (the dir-or-file `bpf_dir` tier + no token, hermetic either way).
fn spawn_as_nobody(binary: &std::path::Path, args: &[&str], bpf_dir: &std::path::Path) -> Child {
    let mut cmd = Command::new("setpriv");
    cmd.args(["--reuid", "nobody", "--regid", "nogroup", "--clear-groups"]);
    cmd.arg(binary);
    cmd.args(args);
    cmd.env("KRYPROBE_BPF_DIR", bpf_dir);
    cmd.env_remove("KRYPROBE_TOKEN");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().expect("spawn setpriv")
}

/// `chmod 755` one path (fresh copies inherit the source mode, but the
/// nobody legs must not depend on the building umask).
fn chmod_755(path: &std::path::Path) {
    let mut perms = std::fs::metadata(path).expect("copy meta").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(path, perms).expect("chmod copy");
}

// ---------------------------------------------------------------------------
// Test 1: setcap roundtrip — mint (root, temp copy) → setpriv nobody
// `watch --system --duration` + traffic → exit 0 + TOTAL>0.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BPF lane: run under sudo with the k5-bpf-lane lock"]
fn setcap_roundtrip_unpriv() {
    const TEST: &str = "setcap_roundtrip_unpriv";
    let _suite = suite_guard();
    if !lane_ready(TEST) {
        return;
    }
    if !setpriv_nobody_ready() {
        println!("SKIP: {TEST} requires setpriv + the nobody user");
        return;
    }
    if !std::path::Path::new(GEN).is_file() {
        println!("SKIP: {TEST} requires {GEN}");
        return;
    }
    let object = kcrypto_object_path();
    assert!(
        object.is_file(),
        "BPF object must be prebuilt: {}",
        object.display()
    );
    // Brief-exact: KRYPROBE_BPF_DIR points at the worktree's object DIR
    // (tier-1 dir join); the dir must be world-readable (evidence
    // records the `namei -l` proof).
    let object_dir = object.parent().expect("object parent").to_owned();

    // Hermetic mint target: a pid-scoped copy — never the worktree
    // binary itself (mutating build output other tasks use is forbidden).
    let dir = scratch("roundtrip");
    let copy = dir.path().join("kryprobe-setcap");
    std::fs::copy(kryprobe(), &copy).expect("copy binary");
    chmod_755(&copy);
    let receipt = dir.path().join("receipt.json");

    // Mint as root.
    let output = Command::new(kryprobe())
        .args(["token", "mint", "--bin"])
        .arg(&copy)
        .args(["--receipt"])
        .arg(&receipt)
        .output()
        .expect("spawn mint");
    let mint_out = String::from_utf8(output.stdout).expect("mint stdout utf-8");
    let mint_err = String::from_utf8(output.stderr).expect("mint stderr utf-8");
    assert_eq!(output.status.code(), Some(0), "mint exits 0: {mint_err}");
    assert_eq!(
        mint_out.lines().count(),
        1,
        "one receipt object: {mint_out:?}"
    );
    let doc: serde_json::Value = serde_json::from_str(mint_out.trim_end()).expect("receipt parses");
    assert_eq!(doc["mechanism"], "setcap");
    assert_eq!(doc["effective"], true);
    println!(
        "{TEST}: receipt: {mint_outtrim}",
        mint_outtrim = mint_out.trim_end()
    );

    // getcap oracle on the minted copy (handoff (a): the live
    // re-confirmation that our 0x02-magic bytes grant `=ep`).
    let output = Command::new("getcap")
        .arg(&copy)
        .output()
        .expect("spawn getcap");
    let getcap = String::from_utf8(output.stdout).expect("getcap utf-8");
    assert!(
        getcap.contains("cap_bpf") && getcap.contains("cap_perfmon") && getcap.contains("=ep"),
        "getcap sees the grant: {getcap:?}"
    );
    println!("{TEST}: getcap oracle: {}", getcap.trim_end());
    let raw = kryprobe_privilege::filecaps::get_capability_xattr(&copy).expect("read xattr");
    println!("{TEST}: security.capability raw: {}", hex_bytes(&raw));

    // `token status` csv agrees with getcap (handoff (b)).
    let output = Command::new(kryprobe())
        .args(["token", "status", "--bin"])
        .arg(&copy)
        .output()
        .expect("spawn status");
    let status = String::from_utf8(output.stdout).expect("status utf-8");
    assert!(
        status.contains("caps: cap_perfmon,cap_bpf effective"),
        "status csv agrees: {status:?}"
    );
    println!("{TEST}: status: {}", status.trim_end().replace('\n', " | "));

    // Unprivileged consume: setpriv nobody `watch --system --duration`.
    // The attach gate runs against the nobody-owned sensor (bpftool
    // reads system-wide as root); traffic only after attach + settle.
    let guard = ChildGuard::new(
        TEST,
        spawn_as_nobody(
            &copy,
            &["watch", "--system", "--duration", "20"],
            &object_dir,
        ),
    );
    let mut guard = gate_attach_and_settle(TEST, guard);
    // Nobody attestation (fix wave, G-M1): prove the watch leg runs as
    // nobody — `/proc/<child>/status` read pre-wait (the child must
    // still be alive).
    attest_nobody(TEST, guard.child());
    hash_traffic(TEST);
    let output = guard.release().wait_with_output().expect("watch output");
    let stdout = String::from_utf8(output.stdout).expect("watch stdout utf-8");
    let stderr = String::from_utf8(output.stderr).expect("watch stderr utf-8");
    println!("{TEST}: watch stdout:\n{stdout}\n{TEST}: watch stderr:\n{stderr}");
    assert_eq!(output.status.code(), Some(0), "unpriv watch exits 0");
    let total = parse_total_calls(&stdout).expect("TOTAL line parses");
    assert!(total > 0, "TOTAL calls > 0, got {total}");

    dir.remove_and_check(TEST);
}

/// Nobody attestation (fix wave, G-M1): `/proc/<child>/status` read
/// pre-wait — prints + pins `Uid: 65534` (all four) and the effective
/// set carrying the minted `cap_bpf`+`cap_perfmon` (bits 39+38).
fn attest_nobody(test: &str, child: &mut Child) {
    let pid = child.id();
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).expect("child status reads");
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .expect("Uid line present");
    let capeff = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .expect("CapEff line present");
    println!("{test}: nobody leg pid={pid} | {uid} | {capeff}");
    assert_eq!(
        uid.split_whitespace().skip(1).collect::<Vec<_>>(),
        ["65534", "65534", "65534", "65534"],
        "{test}: watch leg runs as nobody"
    );
    let hex = capeff
        .split_whitespace()
        .nth(1)
        .expect("CapEff hex present");
    let bits = u64::from_str_radix(hex, 16).expect("CapEff hex parses");
    assert_eq!(
        bits & ((1 << 38) | (1 << 39)),
        (1 << 38) | (1 << 39),
        "{test}: CapEff carries the minted cap_perfmon+cap_bpf"
    );
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Test 2: attribution golden — bounded capture + `kcrypto_gen.py 1` →
// who rows contain comm=python3 with calls>=50; filtered agg counts ==
// the live bpftrace oracle on the same window (EXACT — a mismatch is a
// real bug, never weakened to approximate).
// ---------------------------------------------------------------------------

/// bpftrace oracle: count returns of the two digest entry points over
/// the same window (read-only observer alongside kryprobe).
const ORACLE_PROGRAM: &str =
    "fexit:crypto_ahash_digest { @c = count(); }\nfexit:crypto_shash_digest { @c = count(); }";

#[test]
#[ignore = "BPF lane: run under sudo with the k5-bpf-lane lock"]
fn attribution_golden_python() {
    const TEST: &str = "attribution_golden_python";
    let _suite = suite_guard();
    if !lane_ready(TEST) {
        return;
    }
    if !std::path::Path::new(GEN).is_file() {
        println!("SKIP: {TEST} requires {GEN}");
        return;
    }
    if Command::new("bpftrace").arg("--version").output().is_err() {
        println!("SKIP: {TEST} requires bpftrace");
        return;
    }
    let object = kcrypto_object_path();
    assert!(
        object.is_file(),
        "BPF object must be prebuilt: {}",
        object.display()
    );
    assert_eq!(
        link_count_or_none(),
        Some(0),
        "{TEST}: lane must start clean"
    );

    // Oracle first (its window covers kryprobe's; the lane is otherwise
    // quiet so the margins hold zero events).
    let mut oracle = ChildGuard::new(
        TEST,
        Command::new("bpftrace")
            .args(["-e", ORACLE_PROGRAM])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bpftrace"),
    );
    let (oracle_out, oracle_out_handle) =
        drain_lines(oracle.child().stdout.take().expect("oracle stdout"));
    let (oracle_err, oracle_err_handle) =
        drain_lines(oracle.child().stderr.take().expect("oracle stderr"));
    let start = Instant::now();
    loop {
        let attached = oracle_err
            .lock()
            .expect("oracle err lock")
            .iter()
            .any(|line| line.contains("Attached"));
        if attached {
            break;
        }
        assert!(
            oracle
                .child()
                .try_wait()
                .expect("oracle try_wait")
                .is_none(),
            "{TEST}: bpftrace died before attaching: {:?}",
            oracle_err.lock().expect("oracle err lock").join("\n")
        );
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "{TEST}: bpftrace attaches within 60s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("{TEST}: oracle attached after {:?}", start.elapsed());

    // Bounded capture (JSON carries the who rows via live decode).
    let guard = ChildGuard::new(
        TEST,
        Command::new(kryprobe())
            .args(["report", "--system", "--duration", "20", "--format", "json"])
            .env("KRYPROBE_BPF_DIR", &object)
            .env_remove("KRYPROBE_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn report"),
    );
    let guard = gate_attach_only(TEST, guard);
    hash_traffic(TEST);
    let output = guard.release().wait_with_output().expect("report output");
    let stdout = String::from_utf8(output.stdout).expect("report stdout utf-8");
    let stderr = String::from_utf8(output.stderr).expect("report stderr utf-8");
    assert_eq!(output.status.code(), Some(0), "report exits 0: {stderr}");

    // Stop the oracle the moment the window closes (SIGINT prints the
    // map; SIGKILL would not). Shells out to `kill` so the test needs
    // no signal syscall of its own (ADR-0002 Rule B).
    let pid = oracle.child().id();
    let status = Command::new("kill")
        .args(["-s", "INT"])
        .arg(pid.to_string())
        .status()
        .expect("spawn kill");
    assert!(status.success(), "SIGINT oracle");
    wait_timeout(TEST, oracle.child(), 30);
    // Defuse the guard: the oracle already exited (wait_timeout reaped
    // it); the second wait only satisfies clippy's zombie lint.
    let mut oracle_done = oracle.release();
    let _ = oracle_done.wait();
    oracle_out_handle.join().expect("oracle stdout joins");
    oracle_err_handle.join().expect("oracle stderr joins");
    let oracle_lines = oracle_out.lock().expect("oracle out lock").clone();
    println!("{TEST}: oracle output:\n{}", oracle_lines.join("\n"));
    let oracle_count = parse_oracle_count(&oracle_lines).expect("oracle @c parses");

    // Golden decode: per-tick rows carry CUMULATIVE counters, so both
    // goldens take the latest value per row key (the WHO-block idiom).
    let doc: serde_json::Value =
        serde_json::from_str(stdout.trim_end()).expect("report json parses");
    let observations = doc["observations"].as_array().expect("observations array");

    let mut python_who: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    // Split-key robustness (fix wave, G-I1): max per
    // (decoded-identity, `key_hash`), then sum — the old
    // max-per-decoded-identity idiom undercounts phantom splits.
    let mut digest_agg: DigestAgg = BTreeMap::new();
    let mut alloc_kh: AllocKh = BTreeMap::new();
    let mut totals_latest: u64 = 0;
    for obs in observations {
        let payload = &obs["backend_payload"];
        match payload.get("row").and_then(serde_json::Value::as_str) {
            Some("who")
                if payload.get("comm").and_then(serde_json::Value::as_str) == Some("python3") =>
            {
                let key = (
                    payload["key_hash"].as_u64().expect("who key_hash"),
                    payload["tgid"].as_u64().expect("who tgid"),
                );
                let calls = payload["calls"].as_u64().expect("who calls");
                python_who
                    .entry(key)
                    .and_modify(|latest| *latest = (*latest).max(calls))
                    .or_insert(calls);
            }
            Some("agg")
                if matches!(
                    payload.get("family").and_then(serde_json::Value::as_str),
                    Some("ahash") | Some("shash")
                ) && payload.get("op").and_then(serde_json::Value::as_str) == Some("digest") =>
            {
                let identity = (
                    str_cell(payload, "family"),
                    str_cell(payload, "op"),
                    str_cell(payload, "result"),
                    str_cell(payload, "algorithm"),
                    str_cell(payload, "driver"),
                    str_cell(payload, "context"),
                );
                let key = (
                    identity,
                    payload["key_hash"].as_u64().expect("agg key_hash"),
                );
                let calls = payload["counts"]["calls"].as_u64().expect("agg calls");
                digest_agg
                    .entry(key)
                    .and_modify(|latest| *latest = (*latest).max(calls))
                    .or_insert(calls);
            }
            Some("agg")
                if payload.get("op").and_then(serde_json::Value::as_str) == Some("alloc") =>
            {
                let key = (
                    str_cell(payload, "family"),
                    str_cell(payload, "op"),
                    str_cell(payload, "result"),
                    str_cell(payload, "algorithm"),
                    str_cell(payload, "driver"),
                    str_cell(payload, "context"),
                );
                let kh = payload["key_hash"].as_u64().expect("alloc key_hash");
                alloc_kh.entry(key).or_default().insert(kh);
            }
            Some("totals") => {
                let calls = payload["counts"]["calls"].as_u64().expect("totals calls");
                totals_latest = totals_latest.max(calls);
            }
            _ => {}
        }
    }
    let python_calls: u64 = python_who.values().sum();
    let kryprobe_digest: u64 = digest_agg.values().sum();
    println!(
        "{TEST}: python3 who rows={} calls={python_calls}; kryprobe digest agg={kryprobe_digest}; oracle={oracle_count}; totals_latest={totals_latest}",
        python_who.len()
    );
    assert!(
        !python_who.is_empty(),
        "{TEST}: who rows contain comm=python3"
    );
    assert!(
        python_calls >= 50,
        "{TEST}: python3 who calls >= 50, got {python_calls}"
    );
    assert_eq!(
        kryprobe_digest, oracle_count,
        "{TEST}: EXACT oracle equality (kryprobe filtered agg == bpftrace @c); totals_latest={totals_latest}"
    );
    // Single-kh-per-alloc-identity pin (fix wave, G-I1): post-NUL
    // canonicalization makes this deterministic (pre-fix it was
    // probabilistic — L4 alloc showed 8 key_hashes × 500).
    for (identity, hashes) in &alloc_kh {
        println!("{TEST}: alloc {identity:?} key_hashes={hashes:?}");
        assert_eq!(
            hashes.len(),
            1,
            "{TEST}: one key_hash per alloc identity, got {hashes:?} for {identity:?}"
        );
    }
}

fn str_cell(payload: &serde_json::Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Final `@c: N` line of the oracle map dump.
fn parse_oracle_count(lines: &[String]) -> Option<u64> {
    lines.iter().find_map(|line| {
        let rest = line.strip_prefix("@c:")?;
        rest.trim().parse().ok()
    })
}

// ---------------------------------------------------------------------------
// Test 3: stack-shape smoke — who rows carry stack.frames with >=1 sym
// non-null when kallsyms is readable (root), else sym null + ip present
// (shape, not content).
// ---------------------------------------------------------------------------

/// True when `/proc/kallsyms` exposes real (non-zero) addresses.
fn kallsyms_readable() -> bool {
    std::fs::read_to_string("/proc/kallsyms").is_ok_and(|text| {
        text.lines().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|addr| addr.chars().any(|digit| digit != '0'))
        })
    })
}

#[test]
#[ignore = "BPF lane: run under sudo with the k5-bpf-lane lock"]
fn stack_symbol_smoke() {
    const TEST: &str = "stack_symbol_smoke";
    let _suite = suite_guard();
    if !lane_ready(TEST) {
        return;
    }
    if !std::path::Path::new(GEN).is_file() {
        println!("SKIP: {TEST} requires {GEN}");
        return;
    }
    let object = kcrypto_object_path();
    assert!(
        object.is_file(),
        "BPF object must be prebuilt: {}",
        object.display()
    );
    let readable = kallsyms_readable();
    println!("{TEST}: kallsyms readable = {readable}");

    let guard = ChildGuard::new(
        TEST,
        Command::new(kryprobe())
            .args(["report", "--system", "--duration", "20", "--format", "json"])
            .env("KRYPROBE_BPF_DIR", &object)
            .env_remove("KRYPROBE_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn report"),
    );
    let guard = gate_attach_and_settle(TEST, guard);
    hash_traffic(TEST);
    let output = guard.release().wait_with_output().expect("report output");
    let stdout = String::from_utf8(output.stdout).expect("report stdout utf-8");
    let stderr = String::from_utf8(output.stderr).expect("report stderr utf-8");
    assert_eq!(output.status.code(), Some(0), "report exits 0: {stderr}");

    let doc: serde_json::Value =
        serde_json::from_str(stdout.trim_end()).expect("report json parses");
    let observations = doc["observations"].as_array().expect("observations array");
    let whos: Vec<&serde_json::Value> = observations
        .iter()
        .filter(|obs| {
            obs["backend_payload"]
                .get("row")
                .and_then(serde_json::Value::as_str)
                == Some("who")
        })
        .collect();
    assert!(!whos.is_empty(), "{TEST}: traffic yields who rows");

    // Shape on every row: stack.frames array; ip numeric; sym null|string.
    let mut rows_with_frames = 0usize;
    let mut named_frames = 0usize;
    let mut total_frames = 0usize;
    for who in &whos {
        let frames = who["backend_payload"]["stack"]["frames"]
            .as_array()
            .unwrap_or_else(|| panic!("{TEST}: frames array: {}", who["backend_payload"]));
        if !frames.is_empty() {
            rows_with_frames += 1;
        }
        for frame in frames {
            total_frames += 1;
            assert!(
                frame
                    .get("ip")
                    .and_then(serde_json::Value::as_u64)
                    .is_some(),
                "{TEST}: ip present: {frame}"
            );
            match frame.get("sym") {
                Some(serde_json::Value::Null) | None => {}
                Some(sym) if sym.is_string() => named_frames += 1,
                Some(other) => panic!("{TEST}: sym null|string: {other}"),
            }
        }
    }
    println!(
        "{TEST}: who_rows={} rows_with_frames={rows_with_frames} total_frames={total_frames} named_frames={named_frames}",
        whos.len()
    );
    if readable {
        assert!(
            rows_with_frames >= 1,
            "{TEST}: >=1 who row carries frames when kallsyms is readable"
        );
        assert!(
            named_frames >= 1,
            "{TEST}: >=1 sym non-null when kallsyms is readable"
        );
    } else {
        assert_eq!(
            named_frames, 0,
            "{TEST}: sym all null when kallsyms is restricted"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 4: honest negative — no caps + no token anywhere → exit 4 naming
// `token mint`. Refuses pre-load (never attaches): runs in every lane,
// as `nobody` under root, directly when already unprivileged.
// ---------------------------------------------------------------------------

#[test]
fn no_mechanism_honest() {
    const TEST: &str = "no_mechanism_honest";
    let object = kcrypto_object_path();
    if !object.is_file() {
        println!("SKIP: {TEST} requires the prebuilt BPF object");
        return;
    }
    // Un-capped copy (fresh copies carry no xattr grant).
    let dir = scratch("nomech");
    let copy = dir.path().join("kryprobe-plain");
    std::fs::copy(kryprobe(), &copy).expect("copy binary");
    chmod_755(&copy);
    assert_eq!(
        kryprobe_privilege::filecaps::get_capability_xattr(&copy),
        Err(libc::ENODATA),
        "fresh copy carries no caps"
    );

    // Real object in env (so the refusal is at the authority stage, not
    // the artifact stage), token nowhere.
    let args = [
        "watch",
        "--system",
        "--duration",
        "3",
        "--token",
        "/nonexistent",
    ];
    let output = if is_root() {
        if !setpriv_nobody_ready() {
            println!("SKIP: {TEST} requires setpriv + the nobody user");
            return;
        }
        spawn_as_nobody(&copy, &args, &object)
            .wait_with_output()
            .expect("run nobody watch")
    } else {
        Command::new(&copy)
            .args(args)
            .env("KRYPROBE_BPF_DIR", &object)
            .env_remove("KRYPROBE_TOKEN")
            .output()
            .expect("run unpriv watch")
    };
    let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    println!(
        "{TEST}: exit={:?} stdout={stdout:?} stderr={stderr:?}",
        output.status.code()
    );
    assert_eq!(output.status.code(), Some(4), "no mechanism exits 4");
    assert!(stderr.contains("token mint"), "stderr names `token mint`");

    dir.remove_and_check(TEST);
}
