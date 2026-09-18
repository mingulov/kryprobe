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
    // Global `--json` is threaded through only where a command speaks
    // it; anywhere else it is a usage error (exit 2), never silently
    // discarded.
    let command = match sub.as_str() {
        "doctor" => parse_simple(args, json, "doctor", |json| Command::Doctor { json })?,
        "backends" => parse_simple(args, json, "backends", |json| Command::Backends { json })?,
        "inspect" => crate::args_sub::parse_inspect(args, json)?,
        "selftest" => {
            if json {
                return Err(usage("selftest: --json is not supported"));
            }
            crate::args_sub::parse_selftest(args)?
        }
        "report" => {
            if json {
                return Err(usage("report: --json is not supported"));
            }
            crate::args_sub::parse_report(args)?
        }
        "plan" | "observe" | "run" => {
            if json {
                return Err(usage(format!("{sub}: --json is not supported")));
            }
            Command::Stub { name: sub.clone() }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        std::iter::once("kryprobe")
            .chain(words.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn early_exits_win() {
        assert_eq!(parse(&argv(&["--help"])), Err(ArgsError::Help));
        assert_eq!(parse(&argv(&["--help", "doctor"])), Err(ArgsError::Help));
        assert_eq!(parse(&argv(&["--version"])), Err(ArgsError::Version));
    }

    #[test]
    fn missing_and_unknown_subcommands() {
        assert!(matches!(parse(&argv(&[])), Err(ArgsError::Usage(_))));
        assert!(matches!(
            parse(&argv(&["frobnicate"])),
            Err(ArgsError::Usage(_))
        ));
    }

    #[test]
    fn simple_commands_merge_json() {
        assert_eq!(
            parse(&argv(&["doctor"])).unwrap().command,
            Command::Doctor { json: false }
        );
        assert_eq!(
            parse(&argv(&["--json", "doctor"])).unwrap().command,
            Command::Doctor { json: true }
        );
        assert_eq!(
            parse(&argv(&["backends", "--json"])).unwrap().command,
            Command::Backends { json: true }
        );
        assert!(matches!(
            parse(&argv(&["doctor", "extra"])),
            Err(ArgsError::Usage(_))
        ));
    }

    #[test]
    fn inspect_needs_pid() {
        assert_eq!(
            parse(&argv(&["inspect", "--pid", "1"])).unwrap().command,
            Command::Inspect {
                pid: 1,
                json: false
            }
        );
        for bad in [
            vec!["inspect"],
            vec!["inspect", "--pid"],
            vec!["inspect", "--pid", "nope"],
            vec!["inspect", "--pid", "1", "extra"],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn selftest_grammars() {
        assert_eq!(
            parse(&argv(&["selftest", "synthetic"])).unwrap().command,
            Command::SelftestSynthetic { out: None }
        );
        assert!(matches!(
            parse(&argv(&["selftest"])),
            Err(ArgsError::Usage(_))
        ));
        assert!(matches!(
            parse(&argv(&["selftest", "bpf", "--calls", "0"])),
            Err(ArgsError::Usage(_))
        ));
        assert_eq!(
            parse(&argv(&["selftest", "bpf"])).unwrap().command,
            Command::SelftestBpf {
                calls: 200,
                out: None
            }
        );
        assert_eq!(
            parse(&argv(&["selftest", "token-smoke"])).unwrap().command,
            Command::SelftestToken
        );
        assert!(matches!(
            parse(&argv(&["selftest", "token-smoke", "extra"])),
            Err(ArgsError::Usage(_))
        ));
    }

    #[test]
    fn report_wants_exactly_one_file() {
        assert!(matches!(
            parse(&argv(&["report", "s.jsonl"])).unwrap().command,
            Command::Report { .. }
        ));
        for bad in [vec!["report"], vec!["report", "a", "b"]] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn global_json_rejected_where_unsupported() {
        for words in [
            vec!["--json", "selftest", "synthetic"],
            vec!["--json", "selftest", "bpf"],
            vec!["--json", "selftest", "token-smoke"],
            vec!["--json", "report", "s.jsonl"],
            vec!["--json", "plan"],
            vec!["--json", "observe"],
            vec!["--json", "run"],
        ] {
            let err = parse(&argv(&words)).expect_err("global --json must not be silent");
            assert!(
                matches!(&err, ArgsError::Usage(reason) if reason.contains("--json")),
                "args {words:?} gave {err:?}"
            );
        }
        // Supported commands still merge the global flag.
        assert_eq!(
            parse(&argv(&["--json", "inspect", "--pid", "1"]))
                .unwrap()
                .command,
            Command::Inspect { pid: 1, json: true }
        );
    }

    #[test]
    fn stubs_accept_anything() {
        for sub in ["plan", "observe", "run"] {
            assert_eq!(
                parse(&argv(&[sub, "--anything", "goes"])).unwrap().command,
                Command::Stub {
                    name: sub.to_owned()
                }
            );
        }
    }
}
