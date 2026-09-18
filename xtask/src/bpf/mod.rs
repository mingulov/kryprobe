// SPDX-License-Identifier: GPL-3.0-or-later
//! xtask BPF lanes: `build --bpf` and `test bpf` (T7 split).

pub(crate) mod strip;

use crate::channel_from_file;
use crate::child::{run_child, run_child_in};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Build the BPF spine object with the pinned nightly (T7b).
pub(crate) fn build_bpf() -> i32 {
    let root = match workspace_root() {
        Some(root) => root,
        None => {
            eprintln!(
                "xtask build --bpf: cannot find workspace root (no crates/bpf-spine above here)"
            );
            return 1;
        }
    };
    let pin_file = root.join("crates/bpf-spine/rust-toolchain.toml");
    let channel = match channel_from_file(&pin_file) {
        Some(channel) => channel,
        None => {
            eprintln!(
                "xtask build --bpf: cannot read pinned channel from {}",
                pin_file.display()
            );
            return 1;
        }
    };
    if !toolchain_present(&channel) {
        eprintln!("xtask build --bpf: BPF toolchain '{channel}' is not installed");
        eprintln!(
            "install it with: rustup toolchain install {channel} -c rust-src --profile minimal"
        );
        return 1;
    }
    if Command::new("bpf-linker")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("xtask build --bpf: `bpf-linker` not found on PATH");
        eprintln!("install it with: cargo install bpf-linker");
        return 1;
    }
    let code = run_child_in(
        &root.join("crates/bpf-spine"),
        "rustup",
        &[
            "run",
            channel.as_str(),
            "cargo",
            "build",
            "--release",
            "--bin",
            "spine",
        ],
    );
    if code != 0 {
        return code;
    }
    let built = root.join("crates/bpf-spine/target/bpfel-unknown-none/release/spine");
    let dest_dir = root.join("target/kryprobe-bpf");
    let dest = dest_dir.join("spine.bpf.o");
    if let Err(err) = fs::create_dir_all(&dest_dir) {
        eprintln!(
            "xtask build --bpf: cannot create {}: {err}",
            dest_dir.display()
        );
        return 1;
    }
    let bytes = match fs::read(&built) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("xtask build --bpf: cannot read {}: {err}", built.display());
            return 1;
        }
    };
    let stripped = match strip::strip_dead_text_funcs(&bytes) {
        Ok((stripped, report)) => {
            if report.removed.is_empty() {
                println!("+ strip: no dead .text functions");
            } else {
                println!(
                    "+ strip: removed {} ({} -> {} .text bytes)",
                    report.removed.join(", "),
                    report.text_before,
                    report.text_after
                );
            }
            stripped
        }
        Err(err) => {
            eprintln!("xtask build --bpf: {err}");
            return 1;
        }
    };
    if let Err(err) = fs::write(&dest, &stripped) {
        eprintln!("xtask build --bpf: cannot write {}: {err}", dest.display());
        return 1;
    }
    println!("+ wrote {} (stripped)", dest.display());
    0
}

/// BPF lane: object (incremental) + fixture bin, then the pipeline tests.
///
/// Unprivileged runs pass through the loader's honest Denied path;
/// privileged runs execute the full attach/drain/loss roundtrip.
pub(crate) fn test_bpf() -> i32 {
    let code = build_bpf();
    if code != 0 {
        return code;
    }
    for bin in ["spine_fixture", "token_worker"] {
        let code = run_child(
            "cargo",
            &[
                "build",
                "--locked",
                "-p",
                "kryprobe-privilege",
                "--bin",
                bin,
            ],
        );
        if code != 0 {
            return code;
        }
    }
    let code = run_child(
        "cargo",
        &[
            "build",
            "--locked",
            "-p",
            "kryprobe-cli",
            "--bin",
            "kryprobe",
        ],
    );
    if code != 0 {
        return code;
    }
    for (package, suite) in [
        ("kryprobe-privilege", "bpf_pipeline"),
        ("kryprobe-privilege", "decoy_pid"),
        ("kryprobe-privilege", "token_plumbing"),
        ("kryprobe-cli", "cli_bpf_e2e"),
    ] {
        let code = run_child(
            "cargo",
            &[
                "test",
                "--locked",
                "-p",
                package,
                "--test",
                suite,
                "--",
                "--include-ignored",
            ],
        );
        if code != 0 {
            return code;
        }
    }
    0
}

/// True when `rustup run <channel> rustc --version` succeeds.
fn toolchain_present(channel: &str) -> bool {
    Command::new("rustup")
        .args(["run", channel, "rustc", "--version"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Walk up to the directory containing `crates/bpf-spine/Cargo.toml`.
fn workspace_root() -> Option<PathBuf> {
    let mut dir = env::current_dir().ok()?;
    loop {
        if dir.join("crates/bpf-spine/Cargo.toml").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}
