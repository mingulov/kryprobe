// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe CLI: the outermost ring (T10).
//!
//! Exit codes (kp2 family): 0 clean/success; 1 internal failure; 2
//! usage or invalid input; 3 inconclusive/PARTIAL (ran, coverage
//! gaps receipted); 4 environment-unusable (denied, missing
//! artifacts, uninstalled backends); 10 confirmed policy violation
//! (`check` only).

pub mod args;
mod args_sub;
pub mod cmd_backends;
pub mod cmd_check;
pub mod cmd_doctor;
pub mod cmd_import;
pub mod cmd_inspect;
pub mod cmd_report;
pub mod cmd_selftest;
pub mod cmd_stub;
pub mod cmd_token;
pub mod cmd_watch;
pub mod live;
pub mod runtime_facts;
pub mod selftest_bpf;
pub mod selftest_synth;
pub mod selftest_token;
pub mod token;
pub mod verdict;

use args::{ArgsError, Command, USAGE};
use std::io::Write;

/// Dispatches `argv` (including argv[0]); returns the process exit code.
pub fn run(argv: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let command = match args::parse(argv) {
        Ok(args) => args.command,
        Err(ArgsError::Help) => {
            let _ = writeln!(stdout, "{USAGE}");
            return 0;
        }
        Err(ArgsError::Version) => {
            let _ = writeln!(stdout, "kryprobe {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Err(ArgsError::Usage(reason)) => {
            let _ = writeln!(stderr, "{reason}\n{USAGE}");
            return 2;
        }
    };
    match command {
        Command::Doctor { json, versions } => cmd_doctor::run(json, versions, stdout),
        Command::Backends { json } => cmd_backends::run(json, stdout, stderr),
        Command::Inspect { pid, json } => cmd_inspect::run(pid, json, stdout, stderr),
        Command::SelftestSynthetic { out } => selftest_synth::run(out.as_deref(), stdout, stderr),
        Command::SelftestBpf { calls, out } => {
            selftest_bpf::run(calls, out.as_deref(), stdout, stderr)
        }
        Command::SelftestToken => selftest_token::run(stdout, stderr),
        Command::TokenMint {
            bin,
            receipt,
            force,
        } => cmd_token::run_mint(bin.as_deref(), receipt.as_deref(), force, stdout, stderr),
        Command::TokenStatus { bin } => cmd_token::run_status(bin.as_deref(), stdout),
        Command::Watch {
            source,
            duration,
            token,
        } => cmd_watch::run_watch(&source, duration, token.as_deref(), stdout, stderr),
        Command::Report { file } => cmd_report::run(&file, stdout, stderr),
        Command::ReportLive {
            source,
            duration,
            format,
            out,
            token,
        } => cmd_report::run_report_live(
            &source,
            duration,
            format,
            out.as_deref(),
            token.as_deref(),
            stdout,
            stderr,
        ),
        Command::Check {
            source,
            duration,
            policy,
            token,
        } => cmd_check::run(&source, duration, &policy, token.as_deref(), stdout, stderr),
        Command::Import { file } => cmd_import::run(&file, stdout, stderr),
        Command::Stub { name } => cmd_stub::run(&name, stderr),
    }
}
