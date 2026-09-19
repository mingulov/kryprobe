// SPDX-License-Identifier: GPL-3.0-or-later
//! T10: CLI end-to-end (spawns the `kryprobe` binary) + parser unit tests.

use kryprobe_testkit::assert_golden;
use std::path::PathBuf;
use std::process::{Command, Output};

fn kryprobe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kryprobe"))
}

fn run(args: &[&str]) -> Output {
    Command::new(kryprobe())
        .args(args)
        .output()
        .expect("spawn kryprobe")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout utf-8")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr utf-8")
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/goldens")
        .join(name)
}

#[test]
fn version_exact_case() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        stdout_of(&output),
        format!("kryprobe {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_case() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    assert!(stdout_of(&output).contains("usage:"));
}

#[test]
fn backends_golden_case() {
    let output = run(&["backends"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    if !btf_available() {
        // BTF-absent hosts render `kcrypto: unavailable (...)`; the golden
        // pins the BTF-present `available` render, so skip the golden here
        // (BTF-adaptive, like the doctor markers below).
        assert!(
            stdout_of(&output).contains("kcrypto: unavailable ("),
            "missing unavailable kcrypto row"
        );
        return;
    }
    assert_golden(&golden_path("backends.txt"), &output.stdout);
}

#[test]
fn backends_json_shape_case() {
    for args in [&["--json", "backends"][..], &["backends", "--json"][..]] {
        let output = run(args);
        assert!(
            output.status.success(),
            "args {args:?}: {}",
            stderr_of(&output)
        );
        let json: serde_json::Value =
            serde_json::from_str(&stdout_of(&output)).expect("backends json");
        let backends = json["backends"].as_array().expect("backends array");
        assert_eq!(backends.len(), 4);
        let ids: Vec<&str> = backends
            .iter()
            .map(|b| b["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["synthetic", "p11", "openssl", "kcrypto"]);
        let caps = &backends[0]["capabilities"];
        for gate in ["uprobe_multi", "cookies", "ringbuf", "btf"] {
            assert!(caps[gate].is_boolean(), "gate {gate}");
        }
        // K2.3: the live kcrypto row mirrors synthetic's capabilities shape.
        let kcrypto_caps = &backends[3]["capabilities"];
        for gate in ["uprobe_multi", "cookies", "ringbuf", "btf"] {
            assert!(kcrypto_caps[gate].is_boolean(), "kcrypto gate {gate}");
        }
    }
}

const PROBE_NAMES: [&str; 17] = [
    "kernel_release",
    "bpf_syscall",
    "map_create",
    "prog_load_minimal",
    "uprobe_multi_link_self",
    "attach_cookies",
    "ringbuf_create",
    "btf_present",
    "userns_create",
    "yama_scope",
    "cap_state",
    "token_create_exists",
    "file_caps_gate",
    "uretprobe_seccomp_fork",
    // K2.3: appended after the existing 14, never reordered.
    "kcrypto_symbols",
    "kcrypto_attach",
    "lockdown",
];

/// K2.3 verdict dimensions (brief-exact spellings).
const VERDICT_DIMS: [&str; 5] = ["symbols", "caps", "btf", "attach", "object"];

fn btf_available_at(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok()
}

fn btf_available() -> bool {
    btf_available_at(std::path::Path::new("/sys/kernel/btf/vmlinux"))
}

#[test]
fn btf_gate_predicate_case() {
    // The golden gate is pure path-existence: a missing path maps to
    // BTF-absent (skip), an existing file maps to present (compare).
    assert!(!btf_available_at(std::path::Path::new(
        "/nonexistent-dir/kryprobe-btf-probe"
    )));
    let probe = std::env::temp_dir().join(format!("kryprobe-btf-{}", std::process::id()));
    std::fs::write(&probe, b"vmlinux").expect("write btf probe");
    assert!(btf_available_at(&probe));
    std::fs::remove_file(&probe).ok();
}

#[test]
fn doctor_human_markers_case() {
    let output = run(&["doctor"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let stdout = stdout_of(&output);
    for name in PROBE_NAMES {
        assert!(
            stdout.contains(&format!("probe {name}:")),
            "missing probe {name}"
        );
    }
    for row in [
        "backend synthetic: active (test-only)",
        "backend p11: not installed",
        "backend openssl: not installed",
    ] {
        assert!(stdout.contains(row), "missing row {row}");
    }
    // K2.3: live kcrypto row (BTF-gated; lane hosts have BTF).
    if btf_available() {
        assert!(
            stdout.contains("backend kcrypto: available"),
            "missing live kcrypto row"
        );
    } else {
        assert!(
            stdout.contains("backend kcrypto: unavailable ("),
            "missing unavailable kcrypto row"
        );
    }
    // K2.3: coverage profile + verdict trailer (verdict value varies by
    // privilege, so the shape — not the value — is pinned here; exact
    // ready/missing mappings ride the cmd_doctor unit truth table).
    assert!(
        stdout.contains("coverage-profile: kernel-crypto-v1"),
        "missing coverage profile"
    );
    let verdict = stdout
        .lines()
        .find(|line| line.starts_with("verdict: "))
        .expect("missing verdict line");
    if verdict == "verdict: ready" {
        // Exact ready render.
    } else {
        let pieces = verdict
            .strip_prefix("verdict: degraded: ")
            .expect("bad verdict render");
        assert!(!pieces.is_empty(), "empty degraded pieces");
        for piece in pieces.split(',') {
            assert!(
                VERDICT_DIMS.contains(&piece),
                "bad verdict dimension {piece}"
            );
        }
    }
}

#[test]
fn doctor_json_shape_case() {
    let output = run(&["doctor", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let json: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("doctor json");
    let probes = json["probes"].as_array().expect("probes array");
    assert_eq!(probes.len(), 17);
    for (probe, want) in probes.iter().zip(PROBE_NAMES) {
        assert_eq!(probe["name"], want);
        let outcome = probe["outcome"].as_str().expect("outcome");
        assert!(
            ["pass", "denied", "skipped"].contains(&outcome),
            "bad outcome {outcome}"
        );
        // Volatile by shape: a passing release row names a dotted version.
        if want == "kernel_release" && outcome == "pass" {
            let detail = probe["detail"].as_str().expect("release detail");
            assert!(
                detail.contains('.') && detail.chars().any(|c| c.is_ascii_digit()),
                "release shape: {detail}"
            );
        }
    }
    assert_eq!(json["backends"].as_array().expect("backends").len(), 4);
    // K2.3: coverage profile + verdict (exact keys, brief-exact spellings).
    assert_eq!(json["coverage_profile"], "kernel-crypto-v1");
    let verdict = &json["verdict"];
    let status = verdict["status"].as_str().expect("verdict status");
    assert!(
        ["ready", "degraded"].contains(&status),
        "bad status {status}"
    );
    let missing = verdict["missing"].as_array().expect("verdict missing");
    if status == "ready" {
        assert!(missing.is_empty(), "ready with missing {missing:?}");
    } else {
        assert!(!missing.is_empty(), "degraded with empty missing");
    }
    for piece in missing {
        let piece = piece.as_str().expect("missing piece str");
        assert!(
            VERDICT_DIMS.contains(&piece),
            "bad verdict dimension {piece}"
        );
    }
}

#[test]
fn inspect_self_case() {
    let pid = std::process::id();
    let output = run(&["inspect", "--pid", &pid.to_string()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert!(stdout_of(&output).contains(&format!("pid: {pid}")));
}

#[test]
fn inspect_self_json_case() {
    let pid = std::process::id();
    let output = run(&["inspect", "--pid", &pid.to_string(), "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let json: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("inspect json");
    assert_eq!(json["pid"], pid);
}

#[test]
fn inspect_gone_case() {
    // Reaped child pid: deterministically gone (modulo instant pid reuse).
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    assert!(child.wait().expect("reap").success());
    let output = run(&["inspect", "--pid", &pid.to_string()]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}",
        stdout_of(&output)
    );
    assert!(stderr_of(&output).contains("target gone"));
}

#[test]
fn inspect_bad_pid_case() {
    for args in [
        &["inspect"][..],
        &["inspect", "--pid", "abc"][..],
        &["inspect", "--pid"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "args {args:?}");
        assert!(stderr_of(&output).contains("usage:"), "args {args:?}");
    }
}

#[test]
fn selftest_synthetic_twice_identical_case() {
    let first = run(&["selftest", "synthetic"]);
    assert!(first.status.success(), "stderr: {}", stderr_of(&first));
    let second = run(&["selftest", "synthetic"]);
    assert!(second.status.success(), "stderr: {}", stderr_of(&second));
    assert!(!first.stdout.is_empty());
    assert_eq!(
        first.stdout, second.stdout,
        "synthetic output must be byte-identical"
    );
    let stderr = stderr_of(&first);
    assert!(
        stderr.contains("phase returned"),
        "stderr summary: {stderr}"
    );
    assert!(stderr.contains("integrity:"), "stderr summary: {stderr}");
}

#[test]
fn selftest_synthetic_out_case() {
    let dir = std::env::temp_dir().join(format!("kryprobe-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("synth.jsonl");
    let output = run(&["selftest", "synthetic", "--out", file.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert!(output.stdout.is_empty(), "file mode prints no stdout");
    let via_file = std::fs::read(&file).expect("read out file");
    let via_stdout = run(&["selftest", "synthetic"]);
    assert_eq!(via_file, via_stdout.stdout);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn report_on_selftest_output_case() {
    let dir = std::env::temp_dir().join(format!("kryprobe-cli-r{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("synth.jsonl");
    let synth = run(&["selftest", "synthetic", "--out", file.to_str().unwrap()]);
    assert!(synth.status.success());
    let output = run(&["report", file.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert!(stdout_of(&output).contains("phase "));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn report_invalid_case() {
    let dir = std::env::temp_dir().join(format!("kryprobe-cli-i{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("bad.jsonl");
    std::fs::write(&file, "not json\n{\"schema\":\"kryprobe.event/v0\"}\n").expect("write bad");
    let output = run(&["report", file.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!stderr_of(&output).is_empty());
    let output = run(&["report", dir.join("missing.jsonl").to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    let output = run(&["report"]);
    assert_eq!(output.status.code(), Some(2));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn stub_commands_case() {
    for sub in ["plan", "observe", "run"] {
        let output = run(&[sub, "--anything", "goes"]);
        assert_eq!(output.status.code(), Some(3), "sub {sub}");
        assert!(
            stderr_of(&output).contains("unsupported-in-thin-spine"),
            "sub {sub}: {}",
            stderr_of(&output)
        );
    }
}

#[test]
fn usage_errors_case() {
    for args in [
        vec![],
        vec!["--bogus"],
        vec!["frobnicate"],
        vec!["doctor", "--bogus"],
        vec!["doctor", "extra"],
        vec!["selftest"],
        vec!["selftest", "bogus"],
        vec!["selftest", "bpf", "--calls", "0"],
        vec!["selftest", "bpf", "--calls", "abc"],
        vec!["report", "a", "b"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "args {args:?}");
        assert!(stderr_of(&output).contains("usage:"), "args {args:?}");
    }
}

// ---------------------------------------------------------------------------
// Parser unit tests (every flag through the library parser).
// ---------------------------------------------------------------------------

use kryprobe_cli::args::{ArgsError, Command as CliCommand, parse};

fn parsed(argv: &[&str]) -> Result<kryprobe_cli::args::Args, ArgsError> {
    let owned: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
    parse(&owned)
}

#[test]
fn parser_globals_case() {
    assert!(parsed(&["kryprobe", "--help"]).is_err());
    assert!(parsed(&["kryprobe", "--version"]).is_err());
    let args = parsed(&["kryprobe", "--json", "doctor"]).expect("global json");
    assert!(matches!(args.command, CliCommand::Doctor { json: true }));
    let args = parsed(&["kryprobe", "doctor", "--json"]).expect("command json");
    assert!(matches!(args.command, CliCommand::Doctor { json: true }));
    let args = parsed(&["kryprobe", "doctor"]).expect("plain doctor");
    assert!(matches!(args.command, CliCommand::Doctor { json: false }));
}

#[test]
fn parser_inspect_case() {
    let args = parsed(&["kryprobe", "inspect", "--pid", "42"]).expect("inspect pid");
    assert!(matches!(
        args.command,
        CliCommand::Inspect {
            pid: 42,
            json: false
        }
    ));
    let args = parsed(&["kryprobe", "inspect", "--pid", "42", "--json"]).expect("inspect json");
    assert!(matches!(
        args.command,
        CliCommand::Inspect {
            pid: 42,
            json: true
        }
    ));
    assert!(parsed(&["kryprobe", "inspect"]).is_err());
    assert!(parsed(&["kryprobe", "inspect", "--pid"]).is_err());
    assert!(parsed(&["kryprobe", "inspect", "--pid", "abc"]).is_err());
    assert!(parsed(&["kryprobe", "inspect", "--pid", "1", "--bogus"]).is_err());
}

#[test]
fn parser_selftest_case() {
    let args = parsed(&["kryprobe", "selftest", "synthetic"]).expect("synth");
    assert!(matches!(
        args.command,
        CliCommand::SelftestSynthetic { out: None }
    ));
    let args = parsed(&["kryprobe", "selftest", "synthetic", "--out", "f"]).expect("synth out");
    assert!(matches!(
        args.command,
        CliCommand::SelftestSynthetic { out: Some(_) }
    ));
    let args = parsed(&["kryprobe", "selftest", "bpf"]).expect("bpf defaults");
    assert!(matches!(
        args.command,
        CliCommand::SelftestBpf {
            calls: 200,
            out: None
        }
    ));
    let args = parsed(&[
        "kryprobe", "selftest", "bpf", "--calls", "20000", "--out", "f",
    ])
    .expect("bpf full");
    assert!(matches!(
        args.command,
        CliCommand::SelftestBpf {
            calls: 20000,
            out: Some(_)
        }
    ));
    let args = parsed(&["kryprobe", "selftest", "token-smoke"]).expect("token");
    assert!(matches!(args.command, CliCommand::SelftestToken));
    assert!(parsed(&["kryprobe", "selftest"]).is_err());
    assert!(parsed(&["kryprobe", "selftest", "bogus"]).is_err());
    assert!(parsed(&["kryprobe", "selftest", "bpf", "--calls", "0"]).is_err());
    assert!(parsed(&["kryprobe", "selftest", "synthetic", "--calls", "5"]).is_err());
}

// ---------------------------------------------------------------------------
// K3 Task 2: watch + live report renders (hand-fed outcomes, no privilege)
// + binary behavior (unpriv exit-4 honesty, parse errors) + privileged
// live proof (ignored, lane lock + lease).
// ---------------------------------------------------------------------------

use kryprobe_core::backend::BackendSummary;
use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCounter, DimensionCoverage, IntegrityRef, IntegritySummary,
    NativeObservation, NativeResult, ValidityInterval,
};
use kryprobe_core::ids::ObservationId;

/// `observation_for_agg`-shaped agg fixture: the exact payload keys the
/// backend's D8 mapping emits (row/family/op/result/algorithm/driver/
/// context/counts/bytes/window/status_canonical).
#[allow(clippy::too_many_arguments)]
fn agg_obs(
    id: u64,
    family: &str,
    op: &str,
    result: &str,
    algorithm: &str,
    driver: &str,
    context: &str,
    calls: u64,
    bytes: u64,
    ok: u64,
    errors: u64,
    queued: u64,
) -> NativeObservation {
    let class = match op {
        "encrypt" => OperationClass::Encrypt,
        "decrypt" => OperationClass::Decrypt,
        "digest" | "finup" => OperationClass::Digest,
        _ => OperationClass::Unknown,
    };
    NativeObservation {
        id: ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Completed,
        call_kind: CallKind::Operation,
        operation_class: class,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(100),
        ended_ns: Some(200),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: serde_json::json!({
            "row": "agg",
            "family": family,
            "op": op,
            "result": result,
            "algorithm": algorithm,
            "driver": driver,
            "context": context,
            "counts": {"calls": calls, "ok": ok, "errors": errors, "queued": queued},
            "bytes": bytes,
            "window": {"first_ns": 100, "last_ns": 200},
            "status_canonical": true,
        }),
    }
}

/// Totals-carrier fixture (the aggregate-completion shape).
fn totals_obs(
    id: u64,
    calls: u64,
    bytes: u64,
    ok: u64,
    errors: u64,
    queued: u64,
) -> NativeObservation {
    NativeObservation {
        id: ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Completed,
        call_kind: CallKind::Unknown,
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(100),
        ended_ns: Some(200),
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: serde_json::json!({
            "row": "totals",
            "counts": {"calls": calls, "ok": ok, "errors": errors, "queued": queued},
            "bytes": bytes,
            "window": {"first_ns": 100, "last_ns": 200},
            "status_canonical": true,
        }),
    }
}

/// First-seen marker fixture (must never render as a table row).
fn ident_obs(id: u64) -> NativeObservation {
    NativeObservation {
        id: ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Discovered,
        call_kind: CallKind::Operation,
        operation_class: OperationClass::Encrypt,
        native_name: None,
        native_code: None,
        native_result: NativeResult::KCrypto { status: 0 },
        started_ns: Some(100),
        ended_ns: None,
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: serde_json::json!({
            "row": "ident",
            "ident_kind": "ident",
            "key_hash": 1234,
            "family": "skcipher",
            "op": "encrypt",
            "result": "ok",
            "context": "process",
            "name_lens": {"alg": 8, "drv": 5},
            "first_seen_ns": 100,
        }),
    }
}

fn dim(status: CoverageStatus, counters: Vec<(&str, u64)>) -> DimensionCoverage {
    let mut dim = DimensionCoverage::new(
        status,
        ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        },
    );
    for (name, value) in counters {
        dim.counters.push(DimensionCounter {
            name: name.to_owned(),
            value,
        });
    }
    dim
}

fn complete_dim() -> DimensionCoverage {
    dim(CoverageStatus::CompleteForDeclaredBoundary, Vec::new())
}

/// Healthy session coverage: every dimension complete.
fn healthy_coverage(decoded: u64) -> CoverageSummary {
    CoverageSummary {
        target_population: complete_dim(),
        object_discovery: complete_dim(),
        attachment: dim(
            CoverageStatus::CompleteForDeclaredBoundary,
            vec![("probes_attached", 9), ("probes_expected", 9)],
        ),
        aggregate_counts: dim(
            CoverageStatus::CompleteForDeclaredBoundary,
            vec![("ktot_gap", 0)],
        ),
        detailed_events: dim(
            CoverageStatus::CompleteForDeclaredBoundary,
            vec![("ring_drops", 0), ("overflow_identities", 0)],
        ),
        attribution: complete_dim(),
        correlation: complete_dim(),
        completion: dim(
            CoverageStatus::CompleteForDeclaredBoundary,
            vec![("observations_decoded", decoded)],
        ),
    }
}

/// Gapped session coverage: attachment + aggregate_counts partial.
fn gapped_coverage() -> CoverageSummary {
    CoverageSummary {
        target_population: complete_dim(),
        object_discovery: complete_dim(),
        attachment: dim(
            CoverageStatus::Partial,
            vec![("probes_attached", 8), ("probes_expected", 9)],
        ),
        aggregate_counts: dim(CoverageStatus::Partial, vec![("ktot_gap", 7)]),
        detailed_events: dim(
            CoverageStatus::CompleteForDeclaredBoundary,
            vec![("ring_drops", 0), ("overflow_identities", 0)],
        ),
        attribution: complete_dim(),
        correlation: complete_dim(),
        completion: dim(
            CoverageStatus::CompleteForDeclaredBoundary,
            vec![("observations_decoded", 2)],
        ),
    }
}

fn outcome_with(
    observations: Vec<NativeObservation>,
    coverage: CoverageSummary,
) -> kryprobe_cli::live::LiveOutcome {
    let decoded = observations.len() as u64;
    kryprobe_cli::live::LiveOutcome {
        observations,
        summary: BackendSummary {
            backend: BackendId::KCrypto,
            observations: decoded,
            integrity: IntegritySummary::default(),
        },
        coverage,
        integrity: IntegritySummary::default(),
    }
}

/// Two-tick cumulative session (mirrors `tests/goldens/watch.txt`).
fn watch_fixture() -> kryprobe_cli::live::LiveOutcome {
    let observations = vec![
        agg_obs(
            1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 10, 1000, 10, 0, 0,
        ),
        agg_obs(
            2, "aead", "decrypt", "error", "gcm(aes)", "aesni", "process", 1, 64, 0, 1, 0,
        ),
        totals_obs(3, 11, 1064, 10, 1, 0),
        agg_obs(
            4, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 25, 2500, 25, 0, 0,
        ),
        agg_obs(
            5, "aead", "decrypt", "error", "gcm(aes)", "aesni", "process", 2, 128, 0, 2, 0,
        ),
        agg_obs(
            6, "aead", "decrypt", "ok", "gcm(aes)", "aesni", "process", 5, 320, 5, 0, 0,
        ),
        totals_obs(7, 32, 2948, 30, 2, 0),
        ident_obs(8),
    ];
    outcome_with(observations, healthy_coverage(8))
}

/// Single-tick gapped session (mirrors `tests/goldens/report_partial.txt`).
fn partial_fixture() -> kryprobe_cli::live::LiveOutcome {
    let observations = vec![
        agg_obs(
            1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 3, 300, 3, 0, 0,
        ),
        totals_obs(2, 10, 1000, 10, 0, 0),
    ];
    outcome_with(observations, gapped_coverage())
}

/// Minimal healthy session (mirrors `tests/goldens/report_live.json`).
fn json_fixture() -> kryprobe_cli::live::LiveOutcome {
    let observations = vec![agg_obs(
        1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 3, 300, 3, 0, 0,
    )];
    outcome_with(observations, healthy_coverage(1))
}

#[test]
fn watch_tables_handfed_markers_case() {
    let text = kryprobe_cli::cmd_watch::render_watch_tables(&watch_fixture());
    assert!(
        text.starts_with("FAMILY OP ALGORITHM DRIVER CALLS BYTES OK QUEUED ERRORS\n"),
        "exact header: {text:?}"
    );
    // Latest-wins per row key, then summed across result classes.
    assert!(
        text.contains("aead decrypt gcm(aes) aesni 7 448 5 0 2\n"),
        "aead row: {text:?}"
    );
    assert!(
        text.contains("skcipher encrypt cbc(aes) aesni 25 2500 25 0 0\n"),
        "skcipher row: {text:?}"
    );
    assert!(
        text.contains("TOTAL - - - 32 2948 30 0 2\n"),
        "totals row: {text:?}"
    );
    assert!(text.ends_with("COMPLETE\n"), "trailer: {text:?}");
    assert!(!text.contains("ident"), "idents never table rows: {text:?}");
}

#[test]
fn report_human_partial_handfed_markers_case() {
    // Report human renders the same tables as watch, plus the verdict.
    let text = kryprobe_cli::cmd_watch::render_watch_tables(&partial_fixture());
    assert!(
        text.contains("skcipher encrypt cbc(aes) aesni 3 300 3 0 0\n"),
        "table row: {text:?}"
    );
    assert!(
        text.ends_with("PARTIAL: attach,capture-integrity\n"),
        "gap dims named per kp2 §8: {text:?}"
    );
}

#[test]
fn report_json_handfed_shape_case() {
    let text = kryprobe_cli::cmd_report::render_report_json(&json_fixture());
    assert!(text.ends_with('\n'), "one doc plus newline: {text:?}");
    let doc: serde_json::Value = serde_json::from_str(text.trim_end()).expect("report json parses");
    let mut keys: Vec<&str> = doc
        .as_object()
        .expect("top-level object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["coverage", "integrity", "observations", "verdict"]);
    // Brief order on the wire starts with `observations` (the byte-exact
    // golden pins the full order).
    assert!(
        text.starts_with("{\"observations\":"),
        "key order: {text:?}"
    );
    assert_eq!(doc["verdict"]["status"], "complete");
    assert_eq!(doc["verdict"]["missing"], serde_json::json!([]));
    assert_eq!(doc["observations"].as_array().expect("obs array").len(), 1);
}

/// Spawn with caller-controlled env + cwd (deterministic locator tiers).
fn run_with(env: &[(&str, &str)], cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(kryprobe());
    cmd.args(args).current_dir(cwd);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn kryprobe")
}

/// Empty scratch dir (locators miss tier 3 here).
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kryprobe-k3-2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn watch_unusable_exit4_case() {
    // All three locator tiers miss (absent env path, no exe-bundled
    // object, empty cwd): the session is unusable even as root — no
    // attach is attempted, so this proves exit 4 without privilege.
    let tier2 = kryprobe()
        .parent()
        .expect("exe parent")
        .join("kryprobe-bpf")
        .join("kcrypto.bpf.o");
    if tier2.is_file() {
        println!("SKIP: exe-bundled object present (tier 2 would hit)");
        return;
    }
    let dir = scratch("watch-4");
    let absent = dir.join("absent.o");
    let output = run_with(
        &[("KRYPROBE_BPF_DIR", absent.to_str().expect("utf-8 tmp"))],
        &dir,
        &["watch", "--system", "--duration", "1"],
    );
    assert_eq!(
        output.status.code(),
        Some(4),
        "stderr: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(stderr.contains("watch:"), "stderr: {stderr}");
    assert!(stderr.contains("object missing"), "stderr: {stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn report_unusable_exit4_case() {
    let tier2 = kryprobe()
        .parent()
        .expect("exe parent")
        .join("kryprobe-bpf")
        .join("kcrypto.bpf.o");
    if tier2.is_file() {
        println!("SKIP: exe-bundled object present (tier 2 would hit)");
        return;
    }
    let dir = scratch("report-4");
    let absent = dir.join("absent.o");
    let output = run_with(
        &[("KRYPROBE_BPF_DIR", absent.to_str().expect("utf-8 tmp"))],
        &dir,
        &["report", "--system", "--duration", "1"],
    );
    assert_eq!(
        output.status.code(),
        Some(4),
        "stderr: {}",
        stderr_of(&output)
    );
    let stderr = stderr_of(&output);
    assert!(stderr.contains("report:"), "stderr: {stderr}");
    assert!(stderr.contains("object missing"), "stderr: {stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn watch_bad_source_is_parse_error_case() {
    // `--source` other than `kernel-crypto` is already a parse error
    // (verified here, not reimplemented in the render path).
    let output = run(&["watch", "--system", "--source", "openssl"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        stderr_of(&output)
    );
    assert!(stderr_of(&output).contains("usage:"));
}

#[test]
fn report_bad_source_is_parse_error_case() {
    let output = run(&["report", "--system", "--source", "openssl"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        stderr_of(&output)
    );
    assert!(stderr_of(&output).contains("usage:"));
}

// --- Privileged live proof (lane lock + lease; honest skip otherwise). ---

/// Suite serialization lock: live sessions attach system-wide sensors.
static LANE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lane_guard() -> std::sync::MutexGuard<'static, ()> {
    LANE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

/// Workspace-relative path of the built kcrypto object.
fn kcrypto_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/kryprobe-bpf/kcrypto.bpf.o")
}

/// Privileged-gate: true when this test must run (root + BTF + object).
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
    if !kcrypto_object_path().is_file() {
        println!("SKIP: {name} requires a prebuilt kcrypto.bpf.o");
        return false;
    }
    true
}

/// Tracing-link count via bpftool (`None` when bpftool itself errors —
/// transient during attach storms; the caller retries).
fn link_count_or_none() -> Option<usize> {
    let output = std::process::Command::new("bpftool")
        .args(["link", "show"])
        .output()
        .or_else(|_| {
            std::process::Command::new("/usr/sbin/bpftool")
                .args(["link", "show"])
                .output()
        })
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8(output.stdout)
            .ok()?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
    )
}

/// Positive-control traffic, gated on both session sensors fully
/// attached (9+9 tracing links) — deterministic, no sleep-guessing.
fn spawn_traffic() -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {
        let start = std::time::Instant::now();
        loop {
            if link_count_or_none().is_some_and(|n| n >= 18) {
                break;
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(60),
                "sensors attach within 60s (links: {:?})",
                link_count_or_none()
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let sk =
            kryprobe_testkit::alg_fixture::skcipher_roundtrip("cbc(aes)", 20).expect("skcipher");
        assert_eq!((sk.enc, sk.dec), (20, 20), "skcipher positive control");
        let single = kryprobe_testkit::alg_fixture::hash_digest("sha512", 8).expect("hash");
        assert_eq!((single.digests, single.digest_len), (8, 64), "hash control");
        let aead = kryprobe_testkit::alg_fixture::aead_roundtrip("gcm(aes)", 10).expect("aead");
        assert_eq!((aead.enc, aead.dec), (10, 10), "aead control");
        kryprobe_testkit::alg_fixture::aead_decrypt_bad_tag("gcm(aes)")
            .expect("bad-tag decrypt must EBADMSG");
    })
}

#[test]
#[ignore = "BPF lane: run under sudo with the lane lock + lease"]
fn watch_live_proves_traffic_case() {
    let _guard = lane_guard();
    if !lane_ready("watch_live_proves_traffic_case") {
        return;
    }
    let traffic = spawn_traffic();
    let output = Command::new(kryprobe())
        .args(["watch", "--system", "--duration", "2"])
        .env("KRYPROBE_BPF_DIR", kcrypto_object_path())
        .output()
        .expect("spawn kryprobe watch");
    traffic.join().expect("traffic joins");
    assert_eq!(
        output.status.code(),
        Some(0),
        "healthy lane exits 0; stderr: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    for marker in ["cbc(aes)", "gcm(aes)", "sha512", "TOTAL", "COMPLETE"] {
        assert!(stdout.contains(marker), "missing {marker}: {stdout}");
    }
}

#[test]
#[ignore = "BPF lane: run under sudo with the lane lock + lease"]
fn report_live_proves_json_case() {
    let _guard = lane_guard();
    if !lane_ready("report_live_proves_json_case") {
        return;
    }
    let traffic = spawn_traffic();
    let output = Command::new(kryprobe())
        .args(["report", "--system", "--duration", "2", "--format", "json"])
        .env("KRYPROBE_BPF_DIR", kcrypto_object_path())
        .output()
        .expect("spawn kryprobe report");
    traffic.join().expect("traffic joins");
    assert_eq!(
        output.status.code(),
        Some(0),
        "healthy lane exits 0; stderr: {}",
        stderr_of(&output)
    );
    let doc: serde_json::Value =
        serde_json::from_str(stdout_of(&output).trim_end()).expect("report json parses");
    for key in ["observations", "coverage", "integrity", "verdict"] {
        assert!(doc.get(key).is_some(), "missing key {key}");
    }
    assert_eq!(doc["verdict"]["status"], "complete");
    // Totals conserved across all ticks (ambient-proof summation).
    let observations = doc["observations"].as_array().expect("obs array");
    let sum = |row: &str, field: &str| -> u64 {
        observations
            .iter()
            .filter(|o| o["backend_payload"]["row"] == row)
            .map(|o| o["backend_payload"][field].as_u64().expect("numeric field"))
            .sum()
    };
    let sum_counts = |row: &str| -> u64 {
        observations
            .iter()
            .filter(|o| o["backend_payload"]["row"] == row)
            .map(|o| {
                o["backend_payload"]["counts"]["calls"]
                    .as_u64()
                    .expect("calls")
            })
            .sum()
    };
    assert_eq!(sum_counts("totals"), sum_counts("agg"), "KTOT == Σagg");
    assert_eq!(
        sum("totals", "bytes"),
        sum("agg", "bytes"),
        "bytes conserved"
    );
    // `--out` writes the same bytes the stdout form prints.
    let dir = scratch("report-out");
    let file = dir.join("report.json");
    let traffic = spawn_traffic();
    let output = Command::new(kryprobe())
        .args([
            "report",
            "--system",
            "--duration",
            "2",
            "--format",
            "json",
            "--out",
            file.to_str().expect("utf-8 tmp"),
        ])
        .env("KRYPROBE_BPF_DIR", kcrypto_object_path())
        .output()
        .expect("spawn kryprobe report --out");
    traffic.join().expect("traffic joins");
    assert_eq!(
        output.status.code(),
        Some(0),
        "healthy lane exits 0; stderr: {}",
        stderr_of(&output)
    );
    assert!(output.stdout.is_empty(), "file mode prints no stdout");
    let via_file = std::fs::read(&file).expect("read out file");
    assert!(
        !via_file.is_empty() && via_file.ends_with(b"\n"),
        "file holds one doc plus newline"
    );
    let file_doc: serde_json::Value = serde_json::from_slice(&via_file).expect("file json parses");
    assert_eq!(file_doc["verdict"]["status"], "complete");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn parser_report_stub_case() {
    let args = parsed(&["kryprobe", "report", "f.jsonl"]).expect("report");
    assert!(matches!(args.command, CliCommand::Report { .. }));
    assert!(parsed(&["kryprobe", "report"]).is_err());
    assert!(parsed(&["kryprobe", "report", "a", "b"]).is_err());
    for sub in ["plan", "observe", "run"] {
        let args = parsed(&["kryprobe", sub, "--anything"]).expect("stub");
        assert!(matches!(args.command, CliCommand::Stub { .. }));
    }
    assert!(parsed(&["kryprobe"]).is_err());
    assert!(parsed(&["kryprobe", "--bogus"]).is_err());
    assert!(parsed(&["kryprobe", "frobnicate"]).is_err());
}
