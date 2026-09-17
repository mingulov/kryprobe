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
    }
}

const PROBE_NAMES: [&str; 14] = [
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
];

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
        "backend kcrypto: unavailable (no backend; needs target BTF when implemented)",
    ] {
        assert!(stdout.contains(row), "missing row {row}");
    }
}

#[test]
fn doctor_json_shape_case() {
    let output = run(&["doctor", "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    let json: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("doctor json");
    let probes = json["probes"].as_array().expect("probes array");
    assert_eq!(probes.len(), 14);
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
