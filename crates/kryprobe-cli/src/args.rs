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
  watch --system [--source S] [--duration N]
                               continuous system-wide observe (live kcrypto)
  report --system [--duration N] [--format human|json] [--out F] [--source S]
                               bounded system-wide capture + render (live kcrypto)
  report FILE                  validate + render a JSONL stream
  check --system --policy F [--duration N] [--source S]
                               system-wide policy check (exit 10 on violation)
  plan|observe|run ...         unsupported in thin spine (exit 4)

globals:
  --help                       print this usage (exit 0)
  --version                    print version (exit 0)
  --json                       JSON output (commands that support it)

exit codes: 0 clean/ok; 1 internal failure; 2 usage/invalid input;
  3 inconclusive/PARTIAL; 4 environment-unusable; 10 policy violation.
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

/// Render format for live `report` (default: human).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReportFormat {
    /// Human-readable text summary.
    #[default]
    Human,
    /// Machine-readable JSON.
    Json,
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
    /// Continuous system-wide observe (`--system` select-all; live
    /// kcrypto capture). `duration` is an optional window in seconds;
    /// `None` observes until interrupted.
    Watch {
        /// Accepted `--source` spelling (only `kernel-crypto` in v0.1).
        source: String,
        /// Optional capture window in seconds.
        duration: Option<u64>,
    },
    /// Validate + render a stream.
    Report { file: PathBuf },
    /// Bounded system-wide capture + render (live kcrypto capture).
    /// `duration` is an optional window in seconds; `None` takes the
    /// 60s command default.
    ReportLive {
        /// Accepted `--source` spelling (only `kernel-crypto` in v0.1).
        source: String,
        /// Optional capture window in seconds.
        duration: Option<u64>,
        /// Render format.
        format: ReportFormat,
        /// Output file, or stdout when `None`.
        out: Option<PathBuf>,
    },
    /// System-wide policy check (live kcrypto capture evaluated
    /// against the policy; exit 10 on confirmed violation).
    Check {
        /// Accepted `--source` spelling (only `kernel-crypto` in v0.1).
        source: String,
        /// Optional capture window in seconds.
        duration: Option<u64>,
        /// Policy file (required: v0.1 has no default policy).
        policy: PathBuf,
    },
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
        "watch" => {
            if json {
                return Err(usage("watch: --json is not supported"));
            }
            crate::args_sub::parse_watch(args)?
        }
        "check" => {
            if json {
                return Err(usage("check: --json is not supported"));
            }
            crate::args_sub::parse_check(args)?
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
    fn watch_needs_system_scope() {
        // `--system` select-all is the only v0.1 scope: bare `watch`
        // and flag soup without it are usage errors.
        assert_eq!(
            parse(&argv(&["watch", "--system"])).unwrap().command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: None,
            }
        );
        assert_eq!(
            parse(&argv(&["watch", "--system", "--duration", "60"]))
                .unwrap()
                .command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: Some(60),
            }
        );
        assert_eq!(
            parse(&argv(&["watch", "--source", "kernel-crypto", "--system"]))
                .unwrap()
                .command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: None,
            }
        );
        for bad in [
            vec!["watch"],
            vec!["watch", "--duration", "60"],
            vec!["watch", "--system", "--duration"],
            vec!["watch", "--system", "--duration", "0"],
            vec!["watch", "--system", "--duration", "nope"],
            vec!["watch", "--system", "--source", "openssl"],
            vec!["watch", "--system", "extra"],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn report_live_needs_system_scope() {
        // `report FILE` still renders a file; any `--flag` selects the
        // live grammar, which requires `--system`.
        assert!(matches!(
            parse(&argv(&["report", "s.jsonl"])).unwrap().command,
            Command::Report { .. }
        ));
        assert_eq!(
            parse(&argv(&["report", "--system"])).unwrap().command,
            Command::ReportLive {
                source: "kernel-crypto".to_owned(),
                duration: None,
                format: ReportFormat::Human,
                out: None,
            }
        );
        assert_eq!(
            parse(&argv(&[
                "report",
                "--system",
                "--duration",
                "60",
                "--format",
                "json",
                "--out",
                "o.json",
            ]))
            .unwrap()
            .command,
            Command::ReportLive {
                source: "kernel-crypto".to_owned(),
                duration: Some(60),
                format: ReportFormat::Json,
                out: Some(PathBuf::from("o.json")),
            }
        );
        for bad in [
            vec!["report", "--duration", "60"],
            vec!["report", "--system", "--format", "yaml"],
            vec!["report", "--system", "--format"],
            vec!["report", "--system", "--out"],
            vec!["report", "--system", "--duration", "0"],
            vec!["report", "s.jsonl", "--system"],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn check_needs_system_scope_and_policy() {
        assert_eq!(
            parse(&argv(&["check", "--system", "--policy", "p.yaml"]))
                .unwrap()
                .command,
            Command::Check {
                source: "kernel-crypto".to_owned(),
                duration: None,
                policy: PathBuf::from("p.yaml"),
            }
        );
        assert_eq!(
            parse(&argv(&[
                "check",
                "--system",
                "--duration",
                "60",
                "--policy",
                "p.yaml",
            ]))
            .unwrap()
            .command,
            Command::Check {
                source: "kernel-crypto".to_owned(),
                duration: Some(60),
                policy: PathBuf::from("p.yaml"),
            }
        );
        for bad in [
            vec!["check"],
            vec!["check", "--system"],
            vec!["check", "--policy", "p.yaml"],
            vec!["check", "--system", "--policy"],
            vec!["check", "--system", "--policy", "p.yaml", "--duration", "0"],
            vec![
                "check", "--system", "--policy", "p.yaml", "--format", "json",
            ],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn workload_selectors_deferred_on_system_commands() {
        // kp2 §3: workload scope and report filters need attribution
        // semantics first — v0.1 names the deferral, never a bare parse.
        for cmd in ["watch", "check"] {
            for flag in [
                "--pid",
                "--tree",
                "--cgroup",
                "--cgroup-id",
                "--unit",
                "--comm",
            ] {
                let words: Vec<&str> = if cmd == "check" {
                    vec![cmd, "--system", "--policy", "p.yaml", flag, "x"]
                } else {
                    vec![cmd, "--system", flag, "x"]
                };
                let err = parse(&argv(&words)).expect_err("deferred selector must not parse");
                assert!(
                    matches!(&err, ArgsError::Usage(reason) if reason.contains("deferred")),
                    "{words:?} gave {err:?}"
                );
            }
        }
        for flag in ["--pid", "--cgroup-id"] {
            let words = vec!["report", "--system", flag, "x"];
            let err = parse(&argv(&words)).expect_err("deferred selector must not parse");
            assert!(
                matches!(&err, ArgsError::Usage(reason) if reason.contains("deferred")),
                "{words:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn usage_documents_system_scope() {
        // `--help` output is the contract surface for the new scope.
        for needle in [
            "watch --system",
            "report --system",
            "check --system --policy",
            "--source",
            "--duration",
        ] {
            assert!(USAGE.contains(needle), "usage misses {needle:?}:\n{USAGE}");
        }
    }

    #[test]
    fn global_json_rejected_where_unsupported() {
        for words in [
            vec!["--json", "selftest", "synthetic"],
            vec!["--json", "selftest", "bpf"],
            vec!["--json", "selftest", "token-smoke"],
            vec!["--json", "report", "s.jsonl"],
            vec!["--json", "report", "--system"],
            vec!["--json", "watch", "--system"],
            vec!["--json", "check", "--system", "--policy", "p.yaml"],
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
