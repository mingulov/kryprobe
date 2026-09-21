// SPDX-License-Identifier: GPL-3.0-or-later
//! xtask: the only supported build/test orchestration entry point.
//!
//! Every child invocation is printed (`+ argv...`) before it runs, and the
//! child exit code is propagated to the caller.

mod bench;
mod bpf;
mod child;
mod manifest;
mod root;
mod seam;

use child::run_child;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const USAGE: &str = "\
usage: cargo xtask <command> [<lane>]

commands:
  check        verify pinned toolchain, then fmt, clippy, doc, host tests
  build        cargo build --locked --workspace
  build --bpf  build the BPF spine + kcrypto objects into target/kryprobe-bpf/
  test host    cargo test --locked --workspace
  test bpf     build BPF object + fixture, run the BPF pipeline lane
  verify generated
               schema-freeze + fixture-validation report tests
  verify supply
               cargo-deny + cargo audit (exit 4 when scanners absent)
  bench [--json]
               receipt suites: attach/drain/elf/e2e (exit 4 when denied)
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
        return bpf::build_bpf();
    }
    if argv[1] == "test" && argv.len() == 3 && argv[2] == "host" {
        return run_child("cargo", &["test", "--locked", "--workspace"]);
    }
    if argv[1] == "test" && argv.len() == 3 && argv[2] == "bpf" {
        return bpf::test_bpf();
    }
    if argv[1] == "verify" && argv.len() == 3 && argv[2] == "generated" {
        return run_child("cargo", &["test", "--locked", "-p", "kryprobe-report"]);
    }
    if argv[1] == "verify" && argv.len() == 3 && argv[2] == "supply" {
        return verify_supply();
    }
    if argv[1] == "bench" && argv.len() == 2 {
        return bench::bench(false);
    }
    if argv[1] == "bench" && argv.len() == 3 && argv[2] == "--json" {
        return bench::bench(true);
    }
    eprint!("{USAGE}");
    2
}

fn check() -> i32 {
    if let Some(code) = toolchain_failure() {
        return code;
    }
    if seam::check_seam() != 0 {
        return 1;
    }
    if manifest::check_manifests() != 0 {
        return 1;
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
        &["doc", "--locked", "--workspace", "--no-deps"],
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

/// Supply-chain lane (4B-H3): `cargo deny` (licenses + bans +
/// advisories per `deny.toml`) then `cargo audit` (RUSTSEC per
/// `audit.toml`). Both need their scanners installed and (for fresh
/// advisories) network — absent scanners exit 4 with the install
/// line, never a silent pass. CI runs this on every push/PR plus a
/// nightly schedule.
fn verify_supply() -> i32 {
    for tool in ["cargo-deny", "cargo-audit"] {
        let probe = Command::new(tool).arg("--version").output();
        if probe.is_err() {
            eprintln!("xtask verify supply: `{tool}` not installed (supply scan unavailable)");
            eprintln!("install it with: cargo install {tool} --locked");
            return 4;
        }
    }
    let deny = run_child("cargo", &["deny", "--locked", "check"]);
    if deny != 0 {
        return deny;
    }
    run_child("cargo", &["audit", "--deny", "warnings"])
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
    let dir = root::climb_to("rust-toolchain.toml")?;
    channel_from_file(&dir.join("rust-toolchain.toml"))
}

pub(crate) fn channel_from_file(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    channel_from_text(&text)
}

fn channel_from_text(text: &str) -> Option<String> {
    for line in text.lines() {
        let rest = match line.trim().strip_prefix("channel") {
            Some(rest) => rest,
            None => continue,
        };
        let after_eq = match rest.trim_start().strip_prefix('=') {
            Some(after_eq) => after_eq,
            None => continue,
        };
        // One matching quote pair after `=`: `"..."` or `'...'`; anything
        // else (unquoted, empty, unclosed) is not a channel.
        let value = after_eq.trim_start();
        let quote = match value.as_bytes().first() {
            Some(b'"') => '"',
            Some(b'\'') => '\'',
            _ => continue,
        };
        let end = match value[1..].find(quote) {
            Some(end) => end,
            None => continue,
        };
        let channel = &value[1..1 + end];
        if channel.is_empty() {
            continue;
        }
        return Some(channel.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::channel_from_file;

    fn read_case(name: &str, body: &str) -> Option<String> {
        let scratch = kryprobe_testkit::TempDir::named(&format!("xtask-channel-{name}"))
            .expect("scratch dir");
        let path = scratch.path().join("rust-toolchain.toml");
        std::fs::write(&path, body).expect("write temp toolchain case");
        channel_from_file(&path)
    }

    #[test]
    fn channel_single_quoted_parses() {
        assert_eq!(
            read_case("single", "channel = 'nightly-2026-09-16'\n").as_deref(),
            Some("nightly-2026-09-16")
        );
    }

    #[test]
    fn channel_double_quoted_parses() {
        assert_eq!(
            read_case("double", "[toolchain]\nchannel = \"1.88\"\n").as_deref(),
            Some("1.88")
        );
    }

    #[test]
    fn channel_unquoted_and_garbage_is_none() {
        assert_eq!(read_case("unquoted", "channel = 1.88\n"), None);
        assert_eq!(read_case("empty", "channel = \"\"\n"), None);
        assert_eq!(read_case("unclosed", "channel = \"1.88\n"), None);
        assert_eq!(read_case("garbage", "[toolchain]\nfoo = 1\n"), None);
        assert_eq!(read_case("missing", "[other]\nchannelx = \"1\"\n"), None);
    }
}
