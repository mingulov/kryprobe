// SPDX-License-Identifier: GPL-3.0-or-later
//! xtask: the only supported build/test orchestration entry point.
//!
//! Every child invocation is printed (`+ argv...`) before it runs, and the
//! child exit code is propagated to the caller.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const USAGE: &str = "\
usage: cargo xtask <command> [<lane>]

commands:
  check        verify pinned toolchain, then fmt, clippy, host tests
  build        cargo build --locked --workspace
  build --bpf  build the BPF spine object into target/kryprobe-bpf/
  test host    cargo test --locked --workspace
  test bpf     build BPF object + fixture, run the BPF pipeline lane
";

fn main() {
    let argv: Vec<String> = env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    std::process::exit(run(&argv));
}

fn run(argv: &[String]) -> i32 {
    if argv.len() < 2 {
        eprint!("{USAGE}");
        return 2;
    }
    if argv[1] == "--help" || argv[1] == "help" || argv[1] == "-h" {
        print!("{USAGE}");
        return 0;
    }
    if argv[1] == "check" && argv.len() == 2 {
        return check();
    }
    if argv[1] == "build" && argv.len() == 2 {
        return run_child("cargo", &["build", "--locked", "--workspace"]);
    }
    if argv[1] == "build" && argv.len() == 3 && argv[2] == "--bpf" {
        return build_bpf();
    }
    if argv[1] == "test" && argv.len() == 3 && argv[2] == "host" {
        return run_child("cargo", &["test", "--locked", "--workspace"]);
    }
    if argv[1] == "test" && argv.len() == 3 && argv[2] == "bpf" {
        return test_bpf();
    }
    eprint!("{USAGE}");
    2
}

fn check() -> i32 {
    if let Some(code) = toolchain_failure() {
        return code;
    }
    let steps: &[&[&str]] = &[
        &["fmt", "--check"],
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        &["test", "--locked", "--workspace"],
    ];
    for step in steps {
        let code = run_child("cargo", step);
        if code != 0 {
            return code;
        }
    }
    0
}

/// Fail fast when the active `rustc` is not the pinned toolchain.
/// Returns `Some(exit_code)` when the gate fails, `None` when it passes.
fn toolchain_failure() -> Option<i32> {
    let expected = match pinned_channel() {
        Some(channel) => channel,
        None => {
            eprintln!("xtask check: cannot read pinned channel from rust-toolchain.toml");
            return Some(1);
        }
    };
    let output = match Command::new("rustc").arg("--version").output() {
        Ok(output) => output,
        Err(err) => {
            eprintln!("xtask check: cannot run `rustc --version`: {err}");
            eprintln!("install the pinned toolchain with: rustup toolchain install {expected}");
            return Some(1);
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let install = format!("install the pinned toolchain with: rustup toolchain install {expected}");
    match stdout.split_whitespace().nth(1) {
        Some(version) if version == expected => None,
        Some(version) => {
            eprintln!("xtask check: rustc version mismatch: have '{version}', want '{expected}'");
            eprintln!("{install}");
            Some(1)
        }
        None => {
            eprintln!(
                "xtask check: cannot parse `rustc --version` output: {}",
                stdout.trim()
            );
            eprintln!("{install}");
            Some(1)
        }
    }
}

/// Read the pinned `channel` by walking up from the current directory.
fn pinned_channel() -> Option<String> {
    let mut dir = env::current_dir().ok()?;
    loop {
        let candidate: PathBuf = dir.join("rust-toolchain.toml");
        if candidate.is_file() {
            return channel_from_file(&candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn channel_from_file(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let rest = match line.trim().strip_prefix("channel") {
            Some(rest) => rest,
            None => continue,
        };
        if !rest.trim_start().starts_with('=') {
            continue;
        }
        let mut parts = line.split('"');
        let _before = parts.next()?;
        let channel = parts.next()?;
        if channel.is_empty() {
            continue;
        }
        return Some(channel.to_string());
    }
    None
}

/// Build the BPF spine object with the pinned nightly (T7b).
fn build_bpf() -> i32 {
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
    if let Err(err) = fs::copy(&built, &dest) {
        eprintln!(
            "xtask build --bpf: cannot copy {} to {}: {err}",
            built.display(),
            dest.display()
        );
        return 1;
    }
    println!("+ copied {} to {}", built.display(), dest.display());
    0
}

/// BPF lane: object (incremental) + fixture bin, then the pipeline tests.
///
/// Unprivileged runs pass through the loader's honest Denied path;
/// privileged runs execute the full attach/drain/loss roundtrip.
fn test_bpf() -> i32 {
    let code = build_bpf();
    if code != 0 {
        return code;
    }
    let code = run_child(
        "cargo",
        &[
            "build",
            "--locked",
            "-p",
            "kryprobe-privilege",
            "--bin",
            "spine_fixture",
        ],
    );
    if code != 0 {
        return code;
    }
    run_child(
        "cargo",
        &[
            "test",
            "--locked",
            "-p",
            "kryprobe-privilege",
            "--test",
            "bpf_pipeline",
            "--",
            "--include-ignored",
        ],
    )
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

/// Print the child argv, run it, and return its exit code.
fn run_child(program: &str, args: &[&str]) -> i32 {
    let mut rendered = String::from(program);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    println!("+ {rendered}");
    run_child_spawn(program, args, None)
}

/// Same as [`run_child`] but with an explicit working directory.
fn run_child_in(dir: &Path, program: &str, args: &[&str]) -> i32 {
    let mut rendered = String::from(program);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    println!("+ cd {} && {rendered}", dir.display());
    run_child_spawn(program, args, Some(dir))
}

fn run_child_spawn(program: &str, args: &[&str], dir: Option<&Path>) -> i32 {
    let rendered = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("xtask: cannot run `{rendered}`: {err}");
            return 1;
        }
    };
    let status = match child.wait() {
        Ok(status) => status,
        Err(err) => {
            eprintln!("xtask: cannot wait for `{rendered}`: {err}");
            return 1;
        }
    };
    match status.code() {
        Some(code) => code,
        None => {
            eprintln!("xtask: `{rendered}` terminated by signal");
            1
        }
    }
}
