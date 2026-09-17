// SPDX-License-Identifier: GPL-3.0-or-later
//! Hand argument parser: globals, subcommands, usage errors (exit 2).

use std::path::PathBuf;

/// Full usage text (also the `--help` output).
pub const USAGE: &str = "\
usage: kryprobe [--json] <command> [args]

commands:
  doctor [--json]              probe matrix + backend rows
  backends [--json]            backend registry + states
  inspect --pid N [--json]     snapshot one process
  selftest synthetic [--out F] deterministic scripted session
  selftest bpf [--calls N] [--out F]
                               BPF pipeline against spine_fixture
  selftest token-smoke         root token roundtrip (needs root)
  report FILE                  validate + render a JSONL stream
  plan|observe|run ...         unsupported in thin spine (exit 3)

globals:
  --help                       print this usage (exit 0)
  --version                    print version (exit 0)
  --json                       JSON output (commands that support it)

exit codes: 0 ok; 1 runtime failure; 2 usage/invalid input;
  3 unsupported/degraded; 4 ran-but-partial.
";

/// Early exits plus usage errors (exit 2; reason + [`USAGE`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgsError {
    /// `--help`: print [`USAGE`], exit 0.
    Help,
    /// `--version`: print version, exit 0.
    Version,
    /// Usage/input error reason.
    Usage(String),
}

/// Parsed command with merged `--json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Probe matrix + backend rows.
    Doctor { json: bool },
    /// Backend registry + states.
    Backends { json: bool },
    /// Snapshot one process.
    Inspect { pid: u32, json: bool },
    /// Deterministic scripted session (`--out` or stdout).
    SelftestSynthetic { out: Option<PathBuf> },
    /// BPF pipeline selftest.
    SelftestBpf { calls: u64, out: Option<PathBuf> },
    /// Root token roundtrip.
    SelftestToken,
    /// Validate + render a stream.
    Report { file: PathBuf },
    /// Thin-spine stub (`plan`/`observe`/`run`).
    Stub { name: String },
}

/// Parsed argv: exactly one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Command to dispatch.
    pub command: Command,
}

pub(crate) fn usage(reason: impl Into<String>) -> ArgsError {
    ArgsError::Usage(reason.into())
}

/// Parses argv (including argv[0]); `--help`/`--version` are early exits.
pub fn parse(argv: &[String]) -> Result<Args, ArgsError> {
    let mut rest = argv.get(1..).unwrap_or(&[]);
    let mut json = false;
    while let Some((flag, tail)) = rest.split_first() {
        match flag.as_str() {
            "--help" => return Err(ArgsError::Help),
            "--version" => return Err(ArgsError::Version),
            "--json" => {
                json = true;
                rest = tail;
            }
            _ => break,
        }
    }
    let Some((sub, args)) = rest.split_first() else {
        return Err(usage("missing subcommand"));
    };
    let command = match sub.as_str() {
        "doctor" => parse_simple(args, json, "doctor", |json| Command::Doctor { json })?,
        "backends" => parse_simple(args, json, "backends", |json| Command::Backends { json })?,
        "inspect" => crate::args_sub::parse_inspect(args, json)?,
        "selftest" => crate::args_sub::parse_selftest(args)?,
        "report" => crate::args_sub::parse_report(args)?,
        "plan" | "observe" | "run" => Command::Stub { name: sub.clone() },
        other => return Err(usage(format!("unknown subcommand '{other}'"))),
    };
    Ok(Args { command })
}

/// `doctor`/`backends`: bare or `--json`, nothing else.
fn parse_simple(
    args: &[String],
    json: bool,
    name: &str,
    build: impl Fn(bool) -> Command,
) -> Result<Command, ArgsError> {
    let mut json = json;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            return Err(usage(format!("{name}: unexpected '{arg}'")));
        }
    }
    Ok(build(json))
}
