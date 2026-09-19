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
    build_bpf_inner(&[
        ("bpf-spine", "spine", "spine.bpf.o", Strip::GcDeadFuncs),
        (
            "bpf-kcrypto",
            "kcrypto",
            "kcrypto.bpf.o",
            Strip::DropUnreferencedText,
        ),
    ])
}

/// Which strip recipe applies to one BPF object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strip {
    /// Spine: GC dead `.text` functions, keep live ones.
    GcDeadFuncs,
    /// Kcrypto (R4): assert zero call relocs, drop `.text` entirely.
    DropUnreferencedText,
}

/// Build each `(crate dir, bin, output, strip)` row with the pinned
/// nightly + bpf-linker, then strip per row. Both BPF crates share the
/// same pinned nightly (a skew fails the build loudly).
fn build_bpf_inner(rows: &[(&str, &str, &str, Strip)]) -> i32 {
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
    for (dir, _, _, _) in rows {
        let pin = root.join("crates").join(dir).join("rust-toolchain.toml");
        match channel_from_file(&pin) {
            Some(other) if other == channel => {}
            Some(other) => {
                eprintln!(
                    "xtask build --bpf: BPF pin skew: {} pins {other}, want {channel}",
                    pin.display()
                );
                return 1;
            }
            None => {
                eprintln!(
                    "xtask build --bpf: cannot read pinned channel from {}",
                    pin.display()
                );
                return 1;
            }
        }
    }
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
    for (dir, bin, out, strip) in rows {
        let code = build_one(&root, &channel, dir, bin, out, *strip);
        if code != 0 {
            return code;
        }
    }
    0
}

/// Build + strip one BPF object row.
fn build_one(
    root: &std::path::Path,
    channel: &str,
    dir: &str,
    bin: &str,
    out: &str,
    strip: Strip,
) -> i32 {
    let code = run_child_in(
        &root.join("crates").join(dir),
        "rustup",
        &["run", channel, "cargo", "build", "--release", "--bin", bin],
    );
    if code != 0 {
        return code;
    }
    let built = root
        .join("crates")
        .join(dir)
        .join("target/bpfel-unknown-none/release")
        .join(bin);
    let dest_dir = root.join("target/kryprobe-bpf");
    let dest = dest_dir.join(out);
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
    let stripped = match strip {
        Strip::GcDeadFuncs => strip::strip_dead_text_funcs(&bytes),
        Strip::DropUnreferencedText => strip::drop_unreferenced_text(&bytes),
    };
    let stripped = match stripped {
        Ok((stripped, report)) => {
            if report.removed.is_empty() {
                println!("+ strip [{out}]: no dead .text functions");
            } else {
                println!(
                    "+ strip [{out}]: removed {} ({} -> {} .text bytes)",
                    report.removed.join(", "),
                    report.text_before,
                    report.text_after
                );
            }
            stripped
        }
        Err(err) => {
            eprintln!("xtask build --bpf [{out}]: {err}");
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
        ("kryprobe-privilege", "kcrypto_attach"),
        ("kryprobe-privilege", "kcrypto_agg"),
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
