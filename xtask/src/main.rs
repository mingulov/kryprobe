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
  test host    cargo test --locked --workspace
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
    if argv[1] == "test" && argv.len() == 3 && argv[2] == "host" {
        return run_child("cargo", &["test", "--locked", "--workspace"]);
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

/// Print the child argv, run it, and return its exit code.
fn run_child(program: &str, args: &[&str]) -> i32 {
    let mut rendered = String::from(program);
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    println!("+ {rendered}");
    let mut child = match Command::new(program).args(args).spawn() {
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
