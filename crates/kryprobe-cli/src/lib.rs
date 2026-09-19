// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe CLI: the outermost ring (T10).
//!
//! Exit codes: 0 success; 1 runtime/internal failure; 2 usage or invalid
//! input; 3 unsupported/degraded environment (stubs, needs-root, BPF
//! denied, missing artifacts); 4 ran-but-partial (BPF losses receipted).

pub mod args;
mod args_sub;
pub mod cmd_backends;
pub mod cmd_doctor;
pub mod cmd_inspect;
pub mod cmd_report;
pub mod cmd_selftest;
pub mod cmd_stub;
pub mod selftest_bpf;
pub mod selftest_synth;
pub mod selftest_token;

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
        Command::Doctor { json } => cmd_doctor::run(json, stdout),
        Command::Backends { json } => cmd_backends::run(json, stdout, stderr),
        Command::Inspect { pid, json } => cmd_inspect::run(pid, json, stdout, stderr),
        Command::SelftestSynthetic { out } => selftest_synth::run(out.as_deref(), stdout, stderr),
        Command::SelftestBpf { calls, out } => {
            selftest_bpf::run(calls, out.as_deref(), stdout, stderr)
        }
        Command::SelftestToken => selftest_token::run(stdout, stderr),
        Command::Watch { .. } => {
            cmd_stub::run_uninstalled("watch --system", "the kcrypto backend", stderr)
        }
        Command::Report { file } => cmd_report::run(&file, stdout, stderr),
        Command::ReportLive { .. } => {
            cmd_stub::run_uninstalled("report --system", "the kcrypto backend", stderr)
        }
        Command::Check { .. } => {
            cmd_stub::run_uninstalled("check --system", "the kcrypto backend", stderr)
        }
        Command::Stub { name } => cmd_stub::run(&name, stderr),
    }
}
