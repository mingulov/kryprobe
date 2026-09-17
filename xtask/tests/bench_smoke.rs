// SPDX-License-Identifier: GPL-3.0-or-later
//! T11: bench lane smoke — machine line, 4 suite rows, honest partials.

use std::path::PathBuf;
use std::process::Command;

fn xtask() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_xtask"))
}

fn bench_output(args: &[&str]) -> std::process::Output {
    Command::new(xtask())
        .arg("bench")
        .args(args)
        .output()
        .expect("spawn xtask bench")
}

fn suite_row(stdout: &str, suite: &str) -> String {
    stdout
        .lines()
        .find(|line| line.starts_with(&format!("{suite}:")))
        .unwrap_or_else(|| panic!("missing {suite} row in:\n{stdout}"))
        .to_owned()
}

#[test]
fn bench_partial_or_clean_case() {
    let output = bench_output(&[]);
    let code = output.status.code();
    assert!(
        matches!(code, Some(0) | Some(4)),
        "exit must be 0 or 4, got {code:?}"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    assert!(
        !stderr.contains("panicked"),
        "bench must never panic: {stderr}"
    );
    // Machine line carries kernel, cpu, nproc, rustc.
    let machine = stdout
        .lines()
        .find(|line| line.starts_with("machine:"))
        .expect("machine line");
    for key in ["kernel=", "cpu=", "nproc=", "rustc="] {
        assert!(machine.contains(key), "machine line lacks {key}: {machine}");
    }
    // All four suite rows present, values recorded (never asserted here).
    for suite in ["attach", "drain", "elf", "e2e"] {
        suite_row(&stdout, suite);
    }
    // Partial exit means attach/drain honestly denied (unprivileged).
    if code == Some(4) {
        for suite in ["attach", "drain"] {
            let row = suite_row(&stdout, suite);
            assert!(
                row.contains("DENIED"),
                "{suite} row must read DENIED: {row}"
            );
        }
    }
}

#[test]
fn bench_json_case() {
    let output = bench_output(&["--json"]);
    let code = output.status.code();
    assert!(
        matches!(code, Some(0) | Some(4)),
        "exit must be 0 or 4, got {code:?}"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("bench json");
    for key in ["kernel", "cpu", "nproc", "rustc"] {
        assert!(json["machine"][key].is_string(), "machine.{key}");
    }
    assert!(
        json["machine"]["nproc"]
            .as_str()
            .expect("nproc")
            .parse::<u32>()
            .is_ok()
    );
    let suites = json["suites"].as_array().expect("suites array");
    assert_eq!(suites.len(), 4);
    let names: Vec<&str> = suites
        .iter()
        .map(|s| s["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["attach", "drain", "elf", "e2e"]);
    for suite in suites {
        let status = suite["status"].as_str().expect("status");
        assert!(["ok", "denied"].contains(&status), "bad status {status}");
    }
    if code == Some(4) {
        assert!(
            suites.iter().any(|s| s["status"] == "denied"),
            "partial needs a denial"
        );
    }
}
