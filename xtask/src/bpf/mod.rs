// SPDX-License-Identifier: GPL-3.0-or-later
//! xtask BPF lanes: `build --bpf` and `test bpf` (T7 split).

pub(crate) mod strip;

use crate::channel_from_file;
use crate::child::{run_child, run_child_in_timeout};
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

/// Pinned linker (4B-M6): same fail-loud style as the nightly skew
/// gate — the strip recipes are sensitive to linker output shape.
const PINNED_BPF_LINKER: &str = "0.10.4";

/// True when `bpf-linker --version` output is exactly the pin.
fn linker_version_ok(text: &str) -> bool {
    let mut words = text.split_whitespace();
    matches!(words.next(), Some("bpf-linker")) && words.next() == Some(PINNED_BPF_LINKER)
}

/// Sync key for one BPF lockfile (BP-M2): the lock text minus the
/// root `[[package]]` stanza (the crate's own name/version, which
/// differs by design). Pure over text for tests.
fn lockfile_sync_key(text: &str) -> String {
    let mut kept = Vec::new();
    for stanza in text.split("[[package]]") {
        let root = stanza
            .lines()
            .any(|line| line == "name = \"bpf-spine\"" || line == "name = \"bpf-kcrypto\"");
        if !root {
            kept.push(stanza);
        }
    }
    kept.join("[[package]]")
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
    // BP-M2: the twin lockfiles must agree modulo the root stanza —
    // drift means the two objects resolved different closures.
    let spine_lock = fs::read_to_string(root.join("crates/bpf-spine/Cargo.lock"));
    let kcrypto_lock = fs::read_to_string(root.join("crates/bpf-kcrypto/Cargo.lock"));
    match (&spine_lock, &kcrypto_lock) {
        (Ok(a), Ok(b)) if lockfile_sync_key(a) == lockfile_sync_key(b) => {}
        (Ok(_), Ok(_)) => {
            eprintln!(
                "xtask build --bpf: BPF lockfile skew: crates/bpf-spine/Cargo.lock and \
                 crates/bpf-kcrypto/Cargo.lock disagree past the root stanza"
            );
            return 1;
        }
        _ => {
            eprintln!("xtask build --bpf: cannot read both BPF Cargo.lock files");
            return 1;
        }
    }
    if !toolchain_present(&channel) {
        eprintln!("xtask build --bpf: BPF toolchain '{channel}' is not installed");
        eprintln!(
            "install it with: rustup toolchain install {channel} -c rust-src -c rustfmt -c clippy --profile minimal"
        );
        return 1;
    }
    for component in ["rustfmt", "clippy"] {
        // BP-M1: the lint gates need these components on the pinned nightly.
        let probe = if component == "rustfmt" {
            "fmt"
        } else {
            "clippy"
        };
        if !rustup_probe(&channel, &["cargo", probe, "--version"]) {
            eprintln!(
                "xtask build --bpf: BPF toolchain '{channel}' lacks the {component} component"
            );
            eprintln!("install it with: rustup component add --toolchain {channel} {component}");
            return 1;
        }
    }
    match Command::new("bpf-linker").arg("--version").output() {
        Ok(out) if linker_version_ok(&String::from_utf8_lossy(&out.stdout)) => {}
        Ok(out) => {
            eprintln!(
                "xtask build --bpf: bpf-linker skew: want {PINNED_BPF_LINKER}, got {:?} (docs/dependencies/pins.md)",
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
            );
            return 1;
        }
        Err(_) => {
            eprintln!("xtask build --bpf: `bpf-linker` not found on PATH");
            eprintln!("install it with: cargo install bpf-linker@{PINNED_BPF_LINKER}");
            return 1;
        }
    }
    let code = lint_bpf(&root, &channel, rows);
    if code != 0 {
        return code;
    }
    for (dir, bin, out, strip) in rows {
        let code = build_one(&root, &channel, dir, bin, out, *strip);
        if code != 0 {
            return code;
        }
    }
    0
}

/// Lint budget (BP-M1): fmt is instant; clippy cold-compiles under
/// nightly — 600s bounds a pathological hang, loudly (no retry: a
/// lint failure is a verdict, not a flake).
const LINT_TIMEOUT_SECS: u64 = 600;

/// fmt + clippy per BPF crate under the pinned nightly (BP-M1). No
/// `--all-targets`: the crates are bin-only `no_std` (test targets
/// cannot build there — `can't find crate for test`).
fn lint_bpf(root: &std::path::Path, channel: &str, rows: &[(&str, &str, &str, Strip)]) -> i32 {
    for (dir, _, _, _) in rows {
        let workdir = root.join("crates").join(dir);
        for argv in [
            &["run", channel, "cargo", "fmt", "--check"][..],
            &[
                "run", channel, "cargo", "clippy", "--locked", "--", "-D", "warnings",
            ][..],
        ] {
            match run_child_in_timeout(&workdir, "rustup", argv, LINT_TIMEOUT_SECS) {
                Some(0) => {}
                Some(code) => return code,
                None => {
                    eprintln!(
                        "xtask build --bpf: [{dir}] lint step timed out after {LINT_TIMEOUT_SECS}s"
                    );
                    return 1;
                }
            }
        }
    }
    0
}

/// BPF object build budget (4B-L2): the linker hang flake spins for
/// 7+ minutes on a <1s link — 120s bounds it with a loud retry.
const BUILD_TIMEOUT_SECS: u64 = 120;

/// Build + strip one BPF object row.
fn build_one(
    root: &std::path::Path,
    channel: &str,
    dir: &str,
    bin: &str,
    out: &str,
    strip: Strip,
) -> i32 {
    let workdir = root.join("crates").join(dir);
    // BP-M2: the committed lockfiles are authoritative, like every host lane.
    let argv: &[&str] = &[
        "run",
        channel,
        "cargo",
        "build",
        "--locked",
        "--release",
        "--bin",
        bin,
    ];
    // 4B-L2: timeout → loud retry-once → fail. The retry stays
    // visible so flakes stay counted, never silent.
    let code = match run_child_in_timeout(&workdir, "rustup", argv, BUILD_TIMEOUT_SECS) {
        Some(code) => code,
        None => {
            eprintln!("xtask build --bpf: [{out}] build timed out once; retrying once");
            match run_child_in_timeout(&workdir, "rustup", argv, BUILD_TIMEOUT_SECS) {
                Some(code) => code,
                None => {
                    eprintln!("xtask build --bpf: [{out}] build timed out twice; failing");
                    return 1;
                }
            }
        }
    };
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
        ("kryprobe-privilege", "kcrypto_canary"),
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

/// True when `rustup run <channel> <args...>` succeeds.
fn rustup_probe(channel: &str, args: &[&str]) -> bool {
    let mut full = vec!["run", channel];
    full.extend_from_slice(args);
    Command::new("rustup")
        .args(full)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// True when `rustup run <channel> rustc --version` succeeds.
fn toolchain_present(channel: &str) -> bool {
    rustup_probe(channel, &["rustc", "--version"])
}

/// Walk up to the directory containing `crates/bpf-spine/Cargo.toml`.
fn workspace_root() -> Option<PathBuf> {
    crate::root::climb_to("crates/bpf-spine/Cargo.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_sync_ignores_root_stanza() {
        // BP-M2: the twin lockfiles must agree modulo the root
        // package stanza (the crate name differs by design).
        let spine = "version = 4\n\n[[package]]\nname = \"bpf-spine\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"aya-ebpf\"\nversion = \"0.2.1\"\n";
        let kcrypto = spine.replace("bpf-spine", "bpf-kcrypto");
        assert_eq!(lockfile_sync_key(spine), lockfile_sync_key(&kcrypto));
        let drifted = spine.replace("0.2.1", "0.2.2");
        assert_ne!(lockfile_sync_key(spine), lockfile_sync_key(&drifted));
    }

    #[test]
    fn linker_version_gate() {
        // 4B-M6: exact pin match only — a drifted linker changes
        // emitted objects the strip recipes are sensitive to.
        assert!(linker_version_ok("bpf-linker 0.10.4\n"));
        assert!(!linker_version_ok("bpf-linker 0.10.5\n"));
        assert!(!linker_version_ok("bpf-linker 0.10.4-rc1\n"));
        assert!(!linker_version_ok(""));
        assert!(!linker_version_ok("not-a-linker 0.10.4\n"));
    }
}
