// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2B helper acceptance: the eight spec §11.5 named tests plus
//! binary-level follow-ups, all driving the real helper subprocess as an
//! ordinary user. Fixture /proc + cgroup trees are built per test under
//! the system temp dir (unique names, removed afterwards); nothing here
//! needs root, runtime services, or network.

use kryprobe_core::workload::{
    AttributionStatus, MAX_METADATA_BYTES, SnapshotErrorCode, SnapshotKey, SnapshotRequest,
    SnapshotResponse, decode_response,
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
const KERNEL_B: &str = "7.0.0-test/test-boot-id-002";

fn helper_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kryprobe-workload-helper"))
}

/// Unique scratch dir for one test (removed by [`Fixture`] on drop).
fn scratch_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kwh-{}-{}-{}",
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

/// Fixture host view: proc root (kernel identity + uptime + optional pids)
/// and cgroup root. Removed on drop; only paths this fixture created.
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

    /// Create `<cgroup-root>/<rel>` and return its inode (the simulated
    /// kernel cgroup id for keys/metadata built against this fixture).
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

    fn metadata_file(&self, name: &str, body: &str) -> PathBuf {
        let path = self.dir.join(name);
        write_file(&path, body.as_bytes());
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn key(kernel: &str, cgroup: u64, tgid: u32) -> SnapshotKey {
    SnapshotKey {
        kernel_scope: kernel.to_string(),
        cgroup,
        tgid,
        start_ns: 555,
    }
}

fn request_json(keys: &[SnapshotKey]) -> Vec<u8> {
    let request = SnapshotRequest {
        session_id: SESSION.to_string(),
        keys: keys.to_vec(),
        // No counted interval established (wire-omitted): matches stay
        // unknown/stale, never asserted — honest for tests whose intent
        // is not coverage.
        capture_interval: None,
    };
    serde_json::to_vec(&request).expect("request encodes")
}

/// A request with an established counted interval: only this form can
/// reach covered `Asserted` bindings (R2 coverage gate). Tests whose
/// intent needs asserted metadata use this.
fn request_json_with_capture(keys: &[SnapshotKey], start_ns: u64, end_ns: u64) -> Vec<u8> {
    let request = SnapshotRequest {
        session_id: SESSION.to_string(),
        keys: keys.to_vec(),
        capture_interval: Some(kryprobe_core::workload::SnapshotInterval { start_ns, end_ns }),
    };
    serde_json::to_vec(&request).expect("request encodes")
}

fn metadata_json(kernel_tag: Option<&str>, entries_json: &str, window: (u64, u64)) -> String {
    let kernel = match kernel_tag {
        Some(tag) => format!(r#"{{"known":{tag:?}}}"#),
        None => r#"{"unknown":null}"#.to_string(),
    };
    format!(
        r#"{{"collector":"fixture-v1","snapshot_interval":{{"start_ns":{},"end_ns":{}}},"kernel_identity":{kernel},"entries":[{entries_json}]}}"#,
        window.0, window.1,
    )
}

fn entry_json(cgroup: u64, validity_json: Option<&str>) -> String {
    let validity = validity_json.unwrap_or("null");
    format!(
        r#"{{"container":{{"runtime":"docker://host-a","id":"70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57","lifetime":"life-a"}},"display_name":"web-0","cgroup_id":{cgroup},"binding":{{"method":"metadata_file","source":"operator_metadata_file","status":"asserted","validity":{validity}}}}}"#
    )
}

struct Run {
    status: i32,
    stdout: Vec<u8>,
    stderr: String,
}

fn run_helper(args: &[&str], stdin_bytes: &[u8]) -> Run {
    let mut child = Command::new(helper_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("helper spawns as ordinary user");
    let write_result = child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(stdin_bytes);
    if let Err(err) = write_result {
        // The helper validates metadata BEFORE reading stdin (run_serve
        // steps 2-3), so on refusal paths it can exit before this write
        // lands; under full-suite load it wins that race and the write
        // gets EPIPE. That means "helper already exited", never a pass:
        // reap and require the typed refusal via the shared oracle, so a
        // crash (nonzero without a JSON error line, or exit 0) still
        // fails loudly here instead of masking as EPIPE.
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::BrokenPipe,
            "unexpected stdin write error (only EPIPE is a raced refusal)"
        );
        let output = child.wait_with_output().expect("helper reaped");
        let run = Run {
            status: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        let _ = stderr_error(&run);
        return run;
    }
    let output = child.wait_with_output().expect("helper reaped");
    Run {
        status: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_serve(fixture: &Fixture, metadata: Option<&Path>, stdin_bytes: &[u8]) -> Run {
    let proc_root = fixture.proc_root();
    let cgroup_root = fixture.cgroup_root();
    let proc_arg = proc_root.to_string_lossy().into_owned();
    let cgroup_arg = cgroup_root.to_string_lossy().into_owned();
    let mut owned: Vec<String> = vec![
        "--proc-root".to_string(),
        proc_arg,
        "--cgroup-root".to_string(),
        cgroup_arg,
    ];
    if let Some(path) = metadata {
        owned.push("--metadata".to_string());
        owned.push(path.to_string_lossy().into_owned());
    }
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
    run_helper(&args, stdin_bytes)
}

fn decode_stdout(run: &Run) -> SnapshotResponse {
    assert_eq!(run.status, 0, "expected success, stderr: {}", run.stderr);
    decode_response(&run.stdout).expect("stdout is a valid SnapshotResponse")
}

/// stderr JSON error line `{"error":"<name>"}` on refusal paths.
fn stderr_error(run: &Run) -> String {
    assert_ne!(run.status, 0, "expected refusal");
    assert!(
        run.stdout.is_empty(),
        "refusal must not emit a partial response"
    );
    for line in run.stderr.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(name) = value.get("error").and_then(|e| e.as_str())
        {
            return name.to_string();
        }
    }
    panic!("no JSON error line in stderr: {}", run.stderr);
}

// ---------------------------------------------------------------------------
// The eight spec §11.5 named tests.
// ---------------------------------------------------------------------------

#[test]
fn metadata_budget_is_enforced() {
    let fixture = Fixture::create("budget");
    // Over-byte file refuses before parsing.
    let big = vec![b'x'; MAX_METADATA_BYTES + 1];
    let big_path = fixture.dir.join("big.json");
    write_file(&big_path, &big);
    let run = run_serve(
        &fixture,
        Some(&big_path),
        &request_json(&[key(KERNEL_A, 1, 1)]),
    );
    assert_eq!(stderr_error(&run), "budget_exceeded");

    // Over-count entries refuse after parsing.
    let mut entries = String::new();
    for i in 0..1025u64 {
        if i > 0 {
            entries.push(',');
        }
        entries.push_str(&entry_json(1000 + i, None));
    }
    let many_path = fixture.metadata_file(
        "many.json",
        &metadata_json(Some(KERNEL_A), &entries, (1000, 2000)),
    );
    let run = run_serve(
        &fixture,
        Some(&many_path),
        &request_json(&[key(KERNEL_A, 1000, 1)]),
    );
    assert_eq!(stderr_error(&run), "budget_exceeded");

    // Over-deep nesting refuses.
    let mut deep = String::from("true");
    for _ in 0..17 {
        deep = format!(r#"{{"nest":{deep}}}"#);
    }
    let deep_doc = format!(
        r#"{{"collector":"x","snapshot_interval":{{"start_ns":1,"end_ns":2}},"kernel_identity":{{"known":"k"}},"entries":[],"pad":{deep}}}"#
    );
    let deep_path = fixture.metadata_file("deep.json", &deep_doc);
    let run = run_serve(
        &fixture,
        Some(&deep_path),
        &request_json(&[key(KERNEL_A, 1, 1)]),
    );
    assert_eq!(stderr_error(&run), "budget_exceeded");

    // Over-byte stdin request refuses before parsing.
    let run = run_serve(&fixture, None, &vec![b'y'; 4096 + 1]);
    assert_eq!(stderr_error(&run), "budget_exceeded");
}

#[test]
fn malformed_metadata_is_rejected() {
    let fixture = Fixture::create("malformed");
    let request = request_json(&[key(KERNEL_A, 1, 1)]);
    // Not JSON at all.
    let bad = fixture.metadata_file("bad.json", "{not json");
    assert_eq!(
        stderr_error(&run_serve(&fixture, Some(&bad), &request)),
        "parse_failed"
    );
    // A file claiming verified status overreaches: files assert.
    let evil_validity =
        entry_json(1, None).replace(r#""status":"asserted""#, r#""status":"verified""#);
    let verified = fixture.metadata_file(
        "verified.json",
        &metadata_json(Some(KERNEL_A), &evil_validity, (1000, 2000)),
    );
    assert_eq!(
        stderr_error(&run_serve(&fixture, Some(&verified), &request)),
        "parse_failed"
    );
    // Inverted snapshot interval.
    let inverted = fixture.metadata_file(
        "inverted.json",
        &metadata_json(Some(KERNEL_A), &entry_json(1, None), (2000, 1000)),
    );
    assert_eq!(
        stderr_error(&run_serve(&fixture, Some(&inverted), &request)),
        "parse_failed"
    );
    // Empty collector.
    let mut doc: serde_json::Value = serde_json::from_str(&metadata_json(
        Some(KERNEL_A),
        &entry_json(1, None),
        (1000, 2000),
    ))
    .expect("valid");
    doc["collector"] = serde_json::Value::String(String::new());
    let empty_collector = fixture.metadata_file(
        "collector.json",
        &serde_json::to_string(&doc).expect("json"),
    );
    assert_eq!(
        stderr_error(&run_serve(&fixture, Some(&empty_collector), &request)),
        "parse_failed"
    );
}

#[test]
fn wrong_kernel_metadata_is_rejected() {
    let fixture = Fixture::create("wrong-kernel");
    // Metadata from kernel/boot B must refuse a captured key from A: the
    // helper compares kernel scopes, it never assumes same-kernel.
    let meta_b = fixture.metadata_file(
        "b.json",
        &metadata_json(Some(KERNEL_B), &entry_json(43812, None), (1000, 2000)),
    );
    let response = decode_stdout(&run_serve(
        &fixture,
        Some(&meta_b),
        &request_json(&[key(KERNEL_A, 43812, 4242)]),
    ));
    assert_eq!(response.associations.len(), 0);
    assert_eq!(response.errors.len(), 1);
    assert_eq!(response.errors[0].code, SnapshotErrorCode::KernelMismatch);
    assert_eq!(response.errors[0].key.cgroup, 43812);

    // Positive control: the same bytes under kernel A resolve. The
    // R2 coverage gate requires a validity window covering the counted
    // interval, so the control carries both (the kernel comparison is
    // the intent under test, not coverage).
    let covered_a = entry_json(
        43812,
        Some(r#"{"start_ns":500,"end_ns":2500,"clock":"monotonic_boot"}"#),
    );
    let meta_a = fixture.metadata_file(
        "a.json",
        &metadata_json(Some(KERNEL_A), &covered_a, (1000, 2000)),
    );
    let response = decode_stdout(&run_serve(
        &fixture,
        Some(&meta_a),
        &request_json_with_capture(&[key(KERNEL_A, 43812, 4242)], 1000, 2000),
    ));
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Asserted
    );
}

#[test]
fn expired_binding_stays_stale() {
    let fixture = Fixture::create("stale");
    // The cgroup object is LIVE in the fixture tree, but the metadata
    // binding validity [100,200] does not cover the counted capture
    // interval [1000,2000] (R2 coverage gate): the association must stay
    // stale, never refresh.
    let live = fixture.cgroup_dir("live-group");
    let stale_entry = entry_json(
        live,
        Some(r#"{"start_ns":100,"end_ns":200,"clock":"monotonic_boot"}"#),
    );
    let meta = fixture.metadata_file(
        "stale.json",
        &metadata_json(Some(KERNEL_A), &stale_entry, (1000, 2000)),
    );
    let response = decode_stdout(&run_serve(
        &fixture,
        Some(&meta),
        &request_json_with_capture(&[key(KERNEL_A, live, 4242)], 1000, 2000),
    ));
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Stale,
        "live object + expired binding must stay stale"
    );
    assert!(
        response.associations[0].identity.container.is_some(),
        "stale keeps its asserted identity"
    );

    // Positive control: covering validity asserts (overlap alone
    // never asserts under the R2 coverage gate).
    let fresh_entry = entry_json(
        live,
        Some(r#"{"start_ns":500,"end_ns":2500,"clock":"monotonic_boot"}"#),
    );
    let fresh = fixture.metadata_file(
        "fresh.json",
        &metadata_json(Some(KERNEL_A), &fresh_entry, (1000, 2000)),
    );
    let response = decode_stdout(&run_serve(
        &fixture,
        Some(&fresh),
        &request_json_with_capture(&[key(KERNEL_A, live, 4242)], 1000, 2000),
    ));
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Asserted
    );
}

#[test]
fn gone_process_retains_captured_cgroup() {
    let fixture = Fixture::create("gone");
    // TGID 4242 never existed in the fixture proc tree: the captured
    // cgroup id is retained verbatim, never dropped or remapped.
    let response = decode_stdout(&run_serve(
        &fixture,
        None,
        &request_json(&[key(KERNEL_A, 43812, 4242)]),
    ));
    assert_eq!(response.associations.len(), 1);
    let assoc = &response.associations[0];
    assert_eq!(assoc.key.cgroup, 43812);
    assert_eq!(assoc.key.tgid, 4242);
    assert_eq!(assoc.key.start_ns, 555);
    assert_eq!(assoc.evidence.status, AttributionStatus::Unresolved);
    assert!(
        !assoc.identity.is_resolved(),
        "gone process must not gain an identity"
    );
}

#[test]
fn namespace_relative_path_is_not_host_path() {
    let fixture = Fixture::create("ns-relative");
    // A cgroup namespace rewrites the task's view: a relative path (or a
    // `..` escape) is never joined onto the host cgroup root.
    let live = fixture.cgroup_dir("real-group");
    for (tgid, hint) in [(5001u32, "relative/path"), (5002u32, "/../escape")] {
        fixture.pid(tgid, hint, 777);
        let response = decode_stdout(&run_serve(
            &fixture,
            None,
            &request_json(&[key(KERNEL_A, live, tgid)]),
        ));
        assert_eq!(response.associations.len(), 1);
        assert_ne!(
            response.associations[0].evidence.status,
            AttributionStatus::Verified,
            "namespace-relative hint {hint:?} must never verify"
        );
        assert!(
            !response.associations[0].identity.is_resolved(),
            "namespace-relative hint {hint:?} must not resolve"
        );
    }
}

#[test]
fn symlink_escape_is_refused() {
    let fixture = Fixture::create("symlink");
    let live = fixture.cgroup_dir("inner/live");
    // Outside tree the walk must never enter (deep enough that entry
    // would be observable via the scan budget/counters).
    let outside = fixture.dir.join("outside");
    let mut deep = outside.clone();
    for i in 0..32 {
        deep = deep.join(format!("level{i}"));
    }
    fs::create_dir_all(&deep).expect("outside tree");
    std::os::unix::fs::symlink(&outside, fixture.cgroup_root().join("escape-link"))
        .expect("escape symlink");
    std::os::unix::fs::symlink(
        fixture.dir.join("no-such-target"),
        fixture.cgroup_root().join("dangling-link"),
    )
    .expect("dangling symlink");

    let run = run_serve(&fixture, None, &request_json(&[key(KERNEL_A, live, 4242)]));
    let response = decode_stdout(&run);
    assert_eq!(response.associations.len(), 1);
    // The scan completes honestly (missing tgid: unresolved, retained).
    assert_eq!(response.associations[0].key.cgroup, live);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Unresolved,
        "R3 coherence withholds Verified without an established identity"
    );
    // ...and the escape attempts were refused, visibly.
    let counters = stderr_counters(&run.stderr);
    assert!(
        counter_value(&counters, "symlink_refused") >= 2,
        "expected symlink refusals, stderr: {}",
        run.stderr
    );
}

#[test]
fn metadata_cannot_choose_helper_executable() {
    let fixture = Fixture::create("exec-choice");
    // Canary: if the helper ever shells out to a metadata-named path,
    // this marker appears. It must not.
    let marker = fixture.dir.join("EVIL_RAN_MARKER");
    let evil = fixture.dir.join("evil-helper.sh");
    write_file(
        &evil,
        format!("#!/bin/sh\ntouch {}\n", marker.to_string_lossy()).as_bytes(),
    );
    for (name, doc) in [
        (
            "top",
            metadata_json(Some(KERNEL_A), &entry_json(1, None), (1000, 2000)).replace(
                r#""collector":"fixture-v1""#,
                &format!(
                    r#""collector":"fixture-v1","helper_executable":{0:?},"executable":{0:?}"#,
                    evil.to_string_lossy()
                ),
            ),
        ),
        (
            "nested",
            metadata_json(
                Some(KERNEL_A),
                &entry_json(1, None).replace(
                    r#""display_name":"web-0""#,
                    &format!(
                        r#""display_name":"web-0","executable":{0:?}"#,
                        evil.to_string_lossy()
                    ),
                ),
                (1000, 2000),
            ),
        ),
    ] {
        let path = fixture.metadata_file(&format!("{name}.json"), &doc);
        let run = run_serve(&fixture, Some(&path), &request_json(&[key(KERNEL_A, 1, 1)]));
        assert_eq!(stderr_error(&run), "parse_failed", "case {name}");
    }
    assert!(!marker.exists(), "metadata-named executable must never run");
}

#[test]
fn resolver_runs_unprivileged() {
    // Real subprocess, ordinary user: empty capability sets, honest
    // no-new-privs report, stdio-only FDs, and a valid response.
    let attest = run_helper(&["--attest"], &[]);
    assert_eq!(attest.status, 0, "stderr: {}", attest.stderr);
    let doc: serde_json::Value =
        serde_json::from_slice(&attest.stdout).expect("attestation is JSON");
    let att = doc.get("attestation").expect("attestation object");
    assert_ne!(
        att.get("uid").and_then(serde_json::Value::as_u64),
        Some(0),
        "tests run as an ordinary user"
    );
    assert_ne!(
        att.get("euid").and_then(serde_json::Value::as_u64),
        Some(0),
        "tests run as an ordinary user"
    );
    for cap in ["eff", "prm", "inh", "amb"] {
        assert_eq!(
            att.get("caps")
                .and_then(|c| c.get(cap))
                .and_then(serde_json::Value::as_str),
            Some("0"),
            "capability set {cap} must be empty"
        );
    }
    assert!(
        att.get("no_new_privs")
            .and_then(serde_json::Value::as_bool)
            .is_some(),
        "no_new_privs must be honestly reported"
    );
    assert_eq!(
        att.get("fds"),
        Some(&serde_json::json!([0, 1, 2])),
        "only stdio FDs may be inherited"
    );

    // --require-no-new-privs enforces the installed-launcher invariant:
    // exit matches the actual flag, read independently from /proc.
    let self_status = fs::read_to_string("/proc/self/status").expect("own status readable");
    let own_nnp = self_status.lines().any(|l| l.trim() == "NoNewPrivs:\t1");
    let required = run_helper(&["--attest", "--require-no-new-privs"], &[]);
    assert_eq!(required.status == 0, own_nnp);

    // The same invariants hold on the serve path (attestation line on
    // stderr) alongside a valid empty-metadata response.
    let fixture = Fixture::create("unprivileged");
    let run = run_serve(&fixture, None, &request_json(&[key(KERNEL_A, 43812, 4242)]));
    let response = decode_stdout(&run);
    assert_eq!(response.associations.len(), 1);
    assert!(
        run.stderr.lines().any(|l| l.contains("\"attestation\"")),
        "serve path must attest on stderr: {}",
        run.stderr
    );

    // Statically: the helper implements no privilege acquisition or
    // escape hatch. Asserted here, not by inspection.
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = String::new();
    for entry in fs::read_dir(&src_dir).expect("src dir") {
        let entry = entry.expect("src entry");
        if entry.path().extension().and_then(|e| e.to_str()) == Some("rs") {
            sources.push_str(&fs::read_to_string(entry.path()).expect("src read"));
            sources.push('\n');
        }
    }
    for forbidden in [
        "open_by_handle_at",
        "std::process::Command",
        "Command::new",
        "TcpListener",
        "TcpStream",
        "UdpSocket",
        "UnixStream",
        "UnixListener",
        "setuid",
        "setgid",
        "CAP_DAC",
        "prctl",
        "env::var",
        "docker",
        "socketpair",
    ] {
        assert!(
            !sources.contains(forbidden),
            "helper source must not contain {forbidden:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Binary-level follow-ups.
// ---------------------------------------------------------------------------

/// One numeric counter from the stderr counters object (0 when absent).
fn counter_value(counters: &serde_json::Map<String, serde_json::Value>, key: &str) -> u64 {
    counters
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// Parse the `{"helper_counters":{...}}` stderr line.
fn stderr_counters(stderr: &str) -> serde_json::Map<String, serde_json::Value> {
    for line in stderr.lines() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(counters) = value.get("helper_counters")
        {
            return counters.as_object().cloned().unwrap_or_default();
        }
    }
    panic!("no helper_counters line in stderr: {stderr}");
}

#[test]
fn error_and_ipc_output_carry_ids_only() {
    let fixture = Fixture::create("no-leak");
    // Distinctive names everywhere untrusted bytes could flow; none may
    // surface through IPC, diagnostics, or errors.
    let marker = "LEAK_MARKER_ZZ9Q";
    let live = fixture.cgroup_dir(&format!("group-{marker}"));
    fixture.pid(6001, &format!("/{marker}-hint"), 999);
    let mut doc: serde_json::Value = serde_json::from_str(&metadata_json(
        Some(KERNEL_A),
        &entry_json(live, None),
        (1000, 2000),
    ))
    .expect("valid");
    doc["entries"][0]["display_name"] = serde_json::Value::String(format!("name-{marker}"));
    let meta = fixture.metadata_file("m.json", &serde_json::to_string(&doc).expect("json"));
    let run = run_serve(
        &fixture,
        Some(&meta),
        &request_json(&[key(KERNEL_A, live, 6001)]),
    );
    assert_eq!(run.status, 0, "stderr: {}", run.stderr);
    // stdout carries asserted display metadata by contract (bounded
    // allowlisted field), so the leak check targets stderr/errors: paths
    // and untrusted bytes must never appear there.
    assert!(
        !run.stderr.contains(marker),
        "stderr leaked untrusted bytes: {}",
        run.stderr
    );
    // Malformed input errors likewise carry no input bytes.
    let bad = fixture.metadata_file("bad.json", &format!("{{not json {marker}"));
    let run = run_serve(&fixture, Some(&bad), &request_json(&[key(KERNEL_A, 1, 1)]));
    assert_eq!(stderr_error(&run), "parse_failed");
    assert!(
        !run.stderr.contains(marker),
        "error leaked input bytes: {}",
        run.stderr
    );
}

#[test]
fn permission_denial_is_typed_unavailability() {
    let fixture = Fixture::create("denied");
    // Unreadable cgroup subtree: typed unavailability, raw IDs kept.
    let blocked = fixture.cgroup_root().join("blocked");
    fs::create_dir_all(&blocked).expect("blocked dir");
    let target = blocked.join("target");
    fs::create_dir_all(&target).expect("target dir");
    let _ino = fs::metadata(&target).expect("target stat").ino();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).expect("chmod");
    }
    let run = run_serve(
        &fixture,
        None,
        &request_json(&[key(KERNEL_A, 123_456_789, 4242)]),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).expect("chmod back");
    }
    let response = decode_stdout(&run);
    assert_eq!(response.associations[0].key.cgroup, 123_456_789);
    let counters = stderr_counters(&run.stderr);
    assert!(
        counter_value(&counters, "denied") > 0
            || response.associations[0].evidence.status == AttributionStatus::Unresolved,
        "denial must surface typed or stay honestly unresolved: {}",
        run.stderr
    );
}

#[test]
fn rebooted_host_skips_verification() {
    // Captured key from boot A, metadata from boot A, but the live host
    // view is boot B: metadata still asserts (frozen pure path), while
    // live verification refuses to compare across boots.
    let fixture = Fixture::create("reboot");
    write_file(
        &fixture.proc_root().join("sys/kernel/random/boot_id"),
        b"test-boot-id-002\n",
    );
    let live = fixture.cgroup_dir("live");
    // Covered validity + counted capture so the frozen path asserts
    // (R2 coverage gate); the cross-boot live view must still refuse
    // to upgrade it.
    let covered = entry_json(
        live,
        Some(r#"{"start_ns":500,"end_ns":2500,"clock":"monotonic_boot"}"#),
    );
    let meta = fixture.metadata_file(
        "a.json",
        &metadata_json(Some(KERNEL_A), &covered, (1000, 2000)),
    );
    let response = decode_stdout(&run_serve(
        &fixture,
        Some(&meta),
        &request_json_with_capture(&[key(KERNEL_A, live, 4242)], 1000, 2000),
    ));
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Asserted,
        "cross-boot live verification must not upgrade"
    );
}

#[test]
fn wide_tree_scan_stays_bounded() {
    // PRIV01 end to end over the real subprocess: 5000 readable child
    // directories with a missing target refuse as a TYPED partial
    // response (the key converts to `Unsupported`, the budget trip is
    // counted exactly once), never a hang, a crash, or a silent sweep —
    // and no directory name reaches stderr.
    let fixture = Fixture::create("wide-tree");
    let marker = "WIDE_MARKER_K7Q2";
    for i in 0..5000 {
        fixture.cgroup_dir(&format!("child-{marker}-{i:05}"));
    }
    let run = run_serve(
        &fixture,
        None,
        &request_json(&[key(KERNEL_A, 0x0BAD_C0DE, 4242)]),
    );
    let response = decode_stdout(&run);
    assert!(response.validate().is_ok());
    assert_eq!(response.associations.len(), 0);
    assert_eq!(response.errors.len(), 1);
    assert_eq!(response.errors[0].code, SnapshotErrorCode::Unsupported);
    assert_eq!(response.errors[0].key.cgroup, 0x0BAD_C0DE);
    assert_eq!(response.errors[0].key.tgid, 4242);
    let counters = stderr_counters(&run.stderr);
    assert_eq!(
        counter_value(&counters, "scan_budget_trips"),
        1,
        "exactly one budget trip, stderr: {}",
        run.stderr
    );
    assert_eq!(counter_value(&counters, "deadline_trips"), 0);
    assert!(
        !run.stderr.contains(marker),
        "stderr leaked directory names: {}",
        run.stderr
    );
}

#[test]
fn live_cgroup_without_metadata_stays_unresolved() {
    // No metadata file at all: a captured cgroup bound to a live object
    // stays `Unresolved` — R3 coherence (ADR-0012 (c6)) requires an
    // established identity for `Verified`, and liveness observation
    // establishes none (never an invented one).
    let fixture = Fixture::create("liveness");
    let live = fixture.cgroup_dir("live");
    let response = decode_stdout(&run_serve(
        &fixture,
        None,
        &request_json(&[key(KERNEL_A, live, 4242)]),
    ));
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert_eq!(response.associations[0].evidence.method, "unresolved");
    assert!(
        !response.associations[0].identity.is_resolved(),
        "liveness observation invents no workload identity"
    );
}
