// SPDX-License-Identifier: GPL-3.0-or-later
//! Hand argument parser: globals, subcommands, usage errors (exit 2).

use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;
use std::path::PathBuf;

/// Full usage text (also the `--help` output).
pub const USAGE: &str = "\
usage: kryprobe [--json] <command> [args]

commands:
  doctor [--json] [--versions]   probe matrix + backend rows (--versions: artifact versions)
  backends [--json]            backend registry + states
  inspect --pid N [--json]     snapshot one process
  selftest synthetic [--out F] deterministic scripted session
  selftest bpf [--calls N] [--out F]
                               BPF pipeline against spine_fixture
  selftest token-smoke         root token roundtrip (needs root)
  token mint [--bin PATH] [--receipt PATH] [--force]
                               root one-shot file-cap grant + receipt (setcap)
  token status [--bin PATH]     file caps + token-pin usability (never privileged)
  watch --system [--source S] [--duration N] [--token PATH] [--kcrypto-profile P] [--filter-* ...]
                               continuous system-wide observe (live kcrypto)
  report --system [--duration N] [--format human|json|jsonl] [--out F] [--source S] [--token PATH] [--kcrypto-profile P] [--filter-* ...]
                               bounded system-wide capture + render (live kcrypto)
  report FILE                  validate + render a JSONL stream
  check --system --policy F [--duration N] [--source S] [--token PATH] [--kcrypto-profile P]
                               system-wide policy check (exit 10 on violation)
  plan|observe|run ...         unsupported in thin spine (exit 4)

globals:
  --help                       print this usage (exit 0)
  --version                    print version (exit 0)
  --json                       JSON output (commands that support it)

exit codes: 0 clean/ok; 1 internal failure; 2 usage/invalid input;
  3 inconclusive/PARTIAL; 4 environment-unusable; 10 policy violation.

`<command> --help` prints per-command help with examples (exit 0).
";

/// Early exits plus usage errors (exit 2; reason + [`USAGE`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgsError {
    /// `--help`: print [`USAGE`], exit 0.
    Help,
    /// `--version`: print version, exit 0.
    Version,
    /// `<command> --help`: print that command's help, exit 0.
    SubHelp {
        /// Subcommand the help was requested for.
        command: String,
    },
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
    /// Validated event-v0 JSONL stream (session envelope records).
    Jsonl,
}

/// Post-ingestion per-request submitter filter (P6-N3):
/// `--filter-pid`/`--filter-uid`/`--filter-comm` constrain the
/// submitter identity AFTER capture ingestion, per request. All
/// `None` disables filtering (every row renders, no FILTER line).
/// Unknown policy is always `Exclude` from the CLI (unresolvable
/// requests count `unknown`, never admitted-by-default).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterArgs {
    /// Constrain submitter pid (exact match).
    pub pid: Option<u32>,
    /// Constrain submitter uid (exact match).
    pub uid: Option<u32>,
    /// Constrain submitter comm (exact match).
    pub comm: Option<String>,
}

impl FilterArgs {
    /// True when at least one constraint is set (filtering active).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.pid.is_some() || self.uid.is_some() || self.comm.is_some()
    }
}

/// Parsed command with merged `--json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Probe matrix + backend rows.
    Doctor {
        /// Render JSON instead of human tables.
        json: bool,
        /// Artifact versions (binary + BPF objects) instead of probes.
        versions: bool,
    },
    /// Backend registry + states.
    Backends {
        /// Render JSON instead of human rows.
        json: bool,
    },
    /// Snapshot one process.
    Inspect {
        /// Target process id.
        pid: u32,
        /// Render JSON instead of human rows.
        json: bool,
    },
    /// Deterministic scripted session (`--out` or stdout).
    SelftestSynthetic {
        /// Output file, or stdout when `None`.
        out: Option<PathBuf>,
    },
    /// BPF pipeline selftest.
    SelftestBpf {
        /// Fixture call count.
        calls: u64,
        /// Output file, or stdout when `None`.
        out: Option<PathBuf>,
    },
    /// Root token roundtrip.
    SelftestToken,
    /// Root one-shot file-cap grant (`token mint`): `--bin` target
    /// (default: current exe), `--receipt` copy, `--force` overwrite
    /// plus foreign-binary override.
    TokenMint {
        /// Binary to grant caps on (`None` selects the current exe).
        bin: Option<PathBuf>,
        /// Receipt copy destination (`None` prints stdout only).
        receipt: Option<PathBuf>,
        /// Overwrite an existing receipt; also allows a target that
        /// is not the running kryprobe binary.
        force: bool,
    },
    /// File caps + token-pin usability (`token status`, unprivileged).
    TokenStatus {
        /// Binary to inspect (`None` selects the current exe).
        bin: Option<PathBuf>,
    },
    /// Continuous system-wide observe (`--system` select-all; live
    /// kcrypto capture). `duration` is an optional window in seconds;
    /// `None` observes until interrupted.
    Watch {
        /// Accepted `--source` spelling (only `kernel-crypto` in v0.1).
        source: String,
        /// Optional capture window in seconds.
        duration: Option<u64>,
        /// Explicit BPF token path (overrides env + default pin).
        token: Option<PathBuf>,
        /// Capture profile (`api-returns` default, `request-lifecycle`).
        profile: LifecycleProfile,
        /// Post-ingestion submitter filter (all-`None` disables).
        filter: FilterArgs,
    },
    /// Validate + render a stream.
    Report {
        /// Stream file to validate and render.
        file: PathBuf,
    },
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
        /// Explicit BPF token path (overrides env + default pin).
        token: Option<PathBuf>,
        /// Capture profile (`api-returns` default, `request-lifecycle`).
        profile: LifecycleProfile,
        /// Post-ingestion submitter filter (all-`None` disables).
        filter: FilterArgs,
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
        /// Explicit BPF token path (overrides env + default pin).
        token: Option<PathBuf>,
        /// Capture profile (`api-returns` default, `request-lifecycle`).
        profile: LifecycleProfile,
    },
    /// Thin-spine stub (`plan`/`observe`/`run`).
    Stub {
        /// Stub subcommand name (echoed in the refusal).
        name: String,
    },
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
    // P6 discovery path: `<command> --help` wins anywhere in the tail
    // (early exit, no capture, exit 0) — uniformly, one site, so no
    // subcommand grammar can strand it as "unexpected".
    if args.iter().any(|arg| arg == "--help") {
        return Err(ArgsError::SubHelp {
            command: sub.clone(),
        });
    }
    // Global `--json` is threaded through only where a command speaks
    // it; anywhere else it is a usage error (exit 2), never silently
    // discarded.
    let command = match sub.as_str() {
        "doctor" => parse_doctor(args, json)?,
        "backends" => parse_simple(args, json, "backends", |json| Command::Backends { json })?,
        "inspect" => crate::args_sub::parse_inspect(args, json)?,
        "selftest" => {
            reject_json("selftest", json)?;
            crate::args_sub::parse_selftest(args)?
        }
        "report" => {
            reject_json("report", json)?;
            crate::args_sub::parse_report(args)?
        }
        "watch" => {
            reject_json("watch", json)?;
            crate::args_sub::parse_watch(args)?
        }
        "check" => {
            reject_json("check", json)?;
            crate::args_sub::parse_check(args)?
        }
        "token" => {
            reject_json("token", json)?;
            crate::args_sub::parse_token(args)?
        }
        "plan" | "observe" | "run" => {
            reject_json(sub, json)?;
            Command::Stub { name: sub.clone() }
        }
        other => return Err(usage(format!("unknown subcommand '{other}'"))),
    };
    Ok(Args { command })
}

/// `doctor`/`backends`: bare or `--json`, nothing else.
/// Reject global `--json` for subcommands that do not speak it
/// (1A-L6: one guard helper, not seven inline copies).
fn reject_json(sub: &str, json: bool) -> Result<(), ArgsError> {
    if json {
        return Err(usage(format!("{sub}: --json is not supported")));
    }
    Ok(())
}

/// `doctor`: bare, `--json`, `--versions` (each at most once,
/// any order); anything else is a usage error.
fn parse_doctor(args: &[String], json: bool) -> Result<Command, ArgsError> {
    let mut json = json;
    let mut versions = false;
    for arg in args {
        if arg == "--json" {
            json = true;
        } else if arg == "--versions" {
            versions = true;
        } else {
            return Err(usage(format!("doctor: unexpected '{arg}'")));
        }
    }
    Ok(Command::Doctor { json, versions })
}

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

/// Per-command help (`<command> --help`, exit 0). `None` for unknown
/// names (the caller then reports unknown-subcommand, exit 2).
#[must_use]
pub fn subcommand_help(command: &str) -> Option<&'static str> {
    match command {
        "doctor" => Some(DOCTOR_HELP),
        "backends" => Some(BACKENDS_HELP),
        "inspect" => Some(INSPECT_HELP),
        "selftest" => Some(SELFTEST_HELP),
        "token" => Some(TOKEN_HELP),
        "watch" => Some(WATCH_HELP),
        "report" => Some(REPORT_HELP),
        "check" => Some(CHECK_HELP),
        "plan" | "observe" | "run" => Some(STUB_HELP),
        _ => None,
    }
}

const DOCTOR_HELP: &str = "\
usage: kryprobe doctor [--json] [--versions]

Probe matrix + backend rows (--versions: artifact versions instead).

exits: 0 ok; 1 internal failure; 2 usage/invalid input.
";

const BACKENDS_HELP: &str = "\
usage: kryprobe backends [--json]

Backend registry + states.

exits: 0 ok; 1 internal failure; 2 usage/invalid input.
";

const INSPECT_HELP: &str = "\
usage: kryprobe inspect --pid N [--json]

Snapshot one process (--pid exactly once).

exits: 0 ok; 1 internal failure; 2 usage/invalid input.
";

const SELFTEST_HELP: &str = "\
usage: kryprobe selftest synthetic [--out F]
       kryprobe selftest bpf [--calls N] [--out F]
       kryprobe selftest token-smoke      (needs root)

Deterministic scripted session (synthetic), BPF pipeline against
spine_fixture (bpf, default 200 calls), or root token roundtrip.

exits: 0 ok; 1 internal failure; 2 usage/invalid input.
";

const TOKEN_HELP: &str = "\
usage: kryprobe token mint [--bin PATH] [--receipt PATH] [--force]
       kryprobe token status [--bin PATH]

Root one-shot file-cap grant + receipt (mint), or file caps +
token-pin usability, never privileged (status).

setup:
  install:    sudo packaging/install.sh   # mint is a step inside
  privilege:  kryprobe token status       # verify effective caps

exits: 0 ok; 1 internal failure; 2 usage/invalid input.
";

const WATCH_HELP: &str = "\
usage: kryprobe watch --system [--source kernel-crypto] [--duration N] [--token PATH] [--kcrypto-profile P] [--filter-pid N] [--filter-uid N] [--filter-comm S]

Continuous system-wide observe (live kcrypto capture), rendered as
aggregated human tables. --system is required (system scope only).

flags:
  --system               select-all scope (required)
  --source S             only 'kernel-crypto' in v0.1
  --duration N           capture window in seconds (>= 1; default: until stdin closes)
  --token PATH           explicit BPF token path (overrides env + default pin)
  --kcrypto-profile P    api-returns (default) | request-lifecycle
  --filter-pid N         admit only submitter pid N (exact; post-ingestion)
  --filter-uid N         admit only submitter uid N (exact; post-ingestion)
  --filter-comm S        admit only submitter comm S (exact decoded display name; post-ingestion)

filters (--filter-*): constrain the submitter identity AFTER capture
ingestion, per request — capture is unfiltered, views filter. Rows
failing a constraint hide (FILTERED OUT); rows the filter cannot
evaluate stay visible and count UNKNOWN (lifecycle rows always:
frozen edges carry no task identity). Tallies ride the FILTER line
plus coverage counters (filter_admitted/filter_filtered/
filter_unknown); an admitted completion follows its request.

capture profiles (--kcrypto-profile):
  api-returns        per-API return tallies + caller contexts (default;
                     kernel 6.12+ with BTF, bpf(), ringbuf)
  request-lifecycle  per-request submit/terminal lifecycles (needs
                     kernel 7.0+ fsession attach, type 58; pre-7.0
                     kernels refuse it typed, never a silent no-op)

setup:
  install:    sudo packaging/install.sh
              (install -> token mint -> token status + doctor verify;
              re-mint after every binary swap)
  privilege:  kryprobe token status   # file caps + usability, unprivileged
              kryprobe doctor         # probe matrix must pass first

examples:
  kryprobe watch --system --duration 30
  kryprobe watch --system --duration 30 --kcrypto-profile request-lifecycle
  kryprobe watch --system --kcrypto-profile frobnicate
      # exit 2: unsupported profile (names api-returns|request-lifecycle)

exits: 0 session complete (read the coverage trailer: exit 0 is NOT
  proof of complete coverage); 1 internal failure; 2 usage/invalid
  input; 3 PARTIAL (SIGINT-cut window - tables are the preserved
  evidence); 4 environment-unusable.
";

const REPORT_HELP: &str = "\
usage: kryprobe report FILE
       kryprobe report --system [--duration N] [--format human|json|jsonl] [--out F] [--source kernel-crypto] [--token PATH] [--kcrypto-profile P] [--filter-pid N] [--filter-uid N] [--filter-comm S]

Validate + render a JSONL stream (FILE), or bounded system-wide
capture + render (live mode needs --system; default window 60s).

flags (live mode):
  --system               select-all scope (required for live capture)
  --duration N           capture window in seconds (>= 1)
  --format F             human (default) | json | jsonl
  --out F                output file (default: stdout)
  --source S             only 'kernel-crypto' in v0.1
  --token PATH           explicit BPF token path (overrides env + default pin)
  --kcrypto-profile P    api-returns (default) | request-lifecycle
  --filter-pid N         admit only submitter pid N (exact; post-ingestion)
  --filter-uid N         admit only submitter uid N (exact; post-ingestion)
  --filter-comm S        admit only submitter comm S (exact decoded display name; post-ingestion)

filters (--filter-*): constrain the submitter identity AFTER capture
ingestion, per request — capture is unfiltered, views filter. Rows
failing a constraint hide (FILTERED OUT); rows the filter cannot
evaluate stay visible and count UNKNOWN (lifecycle rows always:
frozen edges carry no task identity). Tallies ride the FILTER line,
coverage counters, and the session envelope; an admitted completion
follows its request.

capture profiles (--kcrypto-profile):
  api-returns        per-API return tallies + caller contexts (default;
                     kernel 6.12+ with BTF, bpf(), ringbuf)
  request-lifecycle  per-request submit/terminal lifecycles (needs
                     kernel 7.0+ fsession attach, type 58; pre-7.0
                     kernels refuse it typed, never a silent no-op)

setup:
  install:    sudo packaging/install.sh
              (install -> token mint -> token status + doctor verify;
              re-mint after every binary swap)
  privilege:  kryprobe token status   # file caps + usability, unprivileged
              kryprobe doctor         # probe matrix must pass first

examples:
  kryprobe report session.jsonl
  kryprobe report --system --duration 10 --format json
  kryprobe report --system --duration 10 --format json --kcrypto-profile frobnicate
      # exit 2: unsupported profile (names api-returns|request-lifecycle)

exits: 0 verdict clean/complete; 1 internal failure; 2 usage/invalid
  input; 3 PARTIAL/inconclusive (coverage gaps - the report names
  them); 4 environment-unusable.
";

const CHECK_HELP: &str = "\
usage: kryprobe check --system --policy F [--duration N] [--source kernel-crypto] [--token PATH] [--kcrypto-profile P]

System-wide policy check: live kcrypto capture evaluated against
the policy (--policy required: v0.1 has no default policy).

flags:
  --system               select-all scope (required)
  --policy F             policy file (required)
  --duration N           capture window in seconds (>= 1)
  --source S             only 'kernel-crypto' in v0.1
  --token PATH           explicit BPF token path (overrides env + default pin)
  --kcrypto-profile P    api-returns (default) | request-lifecycle

capture profiles (--kcrypto-profile):
  api-returns        per-API return tallies + caller contexts (default;
                     kernel 6.12+ with BTF, bpf(), ringbuf)
  request-lifecycle  per-request submit/terminal lifecycles (needs
                     kernel 7.0+ fsession attach, type 58; pre-7.0
                     kernels refuse it typed, never a silent no-op)

setup:
  install:    sudo packaging/install.sh
              (install -> token mint -> token status + doctor verify;
              re-mint after every binary swap)
  privilege:  kryprobe token status   # file caps + usability, unprivileged
              kryprobe doctor         # probe matrix must pass first

examples:
  kryprobe check --system --policy policy/kcrypto-baseline.yaml --duration 30
  kryprobe check --system --policy policy/kcrypto-baseline.yaml --kcrypto-profile frobnicate
      # exit 2: unsupported profile (names api-returns|request-lifecycle)

exits: 0 clean (no confirmed violation); 1 internal failure;
  2 usage/invalid input; 3 inconclusive (gaps void the verdict);
  4 environment-unusable; 10 policy violation.
";

const STUB_HELP: &str = "\
plan|observe|run are unsupported in the thin spine (exit 4).
";

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
            Command::Doctor {
                json: false,
                versions: false
            }
        );
        assert_eq!(
            parse(&argv(&["--json", "doctor"])).unwrap().command,
            Command::Doctor {
                json: true,
                versions: false
            }
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
    fn doctor_versions_flag() {
        assert_eq!(
            parse(&argv(&["doctor", "--versions"])).unwrap().command,
            Command::Doctor {
                json: false,
                versions: true
            }
        );
        assert_eq!(
            parse(&argv(&["--json", "doctor", "--versions"]))
                .unwrap()
                .command,
            Command::Doctor {
                json: true,
                versions: true
            }
        );
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
                token: None,
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&["watch", "--system", "--duration", "60"]))
                .unwrap()
                .command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: Some(60),
                token: None,
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&["watch", "--source", "kernel-crypto", "--system"]))
                .unwrap()
                .command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: None,
                token: None,
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
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
                token: None,
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
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
                token: None,
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&["report", "--system", "--format", "jsonl"]))
                .unwrap()
                .command,
            Command::ReportLive {
                source: "kernel-crypto".to_owned(),
                duration: None,
                format: ReportFormat::Jsonl,
                out: None,
                token: None,
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
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
                token: None,
                profile: LifecycleProfile::ApiReturns,
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
                token: None,
                profile: LifecycleProfile::ApiReturns,
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
            "--token",
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
    fn import_command_retired() {
        // ADR-0004: the `import` command is retired (kernel-only scope).
        // Any `import` argv is an unknown subcommand (usage error, exit 2),
        // and USAGE no longer advertises it. Historical `import_shell`
        // records still validate structurally (`report FILE`); see the
        // report-crate compatibility test, not the parser.
        for words in [
            vec!["import"],
            vec!["import", "r.json"],
            vec!["import", "a", "b"],
            vec!["--json", "import", "r.json"],
        ] {
            let err = parse(&argv(&words)).expect_err("import must not parse");
            assert!(
                matches!(&err, ArgsError::Usage(reason) if reason.contains("unknown subcommand")),
                "args {words:?} gave {err:?}"
            );
        }
        assert!(
            !USAGE.contains("import FILE"),
            "usage must not advertise import:\n{USAGE}"
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

    #[test]
    fn k5_token_grammars() {
        // Bare verbs with all-defaults.
        assert_eq!(
            parse(&argv(&["token", "mint"])).unwrap().command,
            Command::TokenMint {
                bin: None,
                receipt: None,
                force: false,
            }
        );
        assert_eq!(
            parse(&argv(&["token", "status"])).unwrap().command,
            Command::TokenStatus { bin: None }
        );
        // Full mint spelling.
        assert_eq!(
            parse(&argv(&[
                "token",
                "mint",
                "--bin",
                "k",
                "--receipt",
                "r.json",
                "--force",
            ]))
            .unwrap()
            .command,
            Command::TokenMint {
                bin: Some(PathBuf::from("k")),
                receipt: Some(PathBuf::from("r.json")),
                force: true,
            }
        );
        assert_eq!(
            parse(&argv(&["token", "status", "--bin", "k"]))
                .unwrap()
                .command,
            Command::TokenStatus {
                bin: Some(PathBuf::from("k")),
            }
        );
        for bad in [
            vec!["token"],
            vec!["token", "frobnicate"],
            vec!["token", "mint", "--bin"],
            vec!["token", "mint", "--receipt"],
            vec!["token", "mint", "extra"],
            vec!["token", "mint", "--pin", "p"],
            vec!["token", "status", "--receipt", "r"],
            vec!["token", "status", "extra"],
            vec!["--json", "token", "mint"],
            vec!["--json", "token", "status"],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
        assert!(
            USAGE.contains("token mint") && USAGE.contains("token status"),
            "usage lists token mint|status:\n{USAGE}"
        );
    }

    #[test]
    fn f8a_live_commands_accept_kcrypto_profile() {
        // Round-1 (sol-M5/astra-M8): live entry points select the
        // capture profile by name; unset keeps api-returns, garbage
        // is a usage error (never a silent default).
        use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;
        assert_eq!(
            parse(&argv(&[
                "watch",
                "--system",
                "--kcrypto-profile",
                "request-lifecycle",
            ]))
            .unwrap()
            .command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: None,
                token: None,
                profile: LifecycleProfile::RequestLifecycle,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&["watch", "--system"])).unwrap().command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: None,
                token: None,
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&[
                "report",
                "--system",
                "--kcrypto-profile",
                "request-lifecycle",
            ]))
            .unwrap()
            .command,
            Command::ReportLive {
                source: "kernel-crypto".to_owned(),
                duration: None,
                format: ReportFormat::Human,
                out: None,
                token: None,
                profile: LifecycleProfile::RequestLifecycle,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&[
                "check",
                "--system",
                "--policy",
                "p.yaml",
                "--kcrypto-profile",
                "request-lifecycle",
            ]))
            .unwrap()
            .command,
            Command::Check {
                source: "kernel-crypto".to_owned(),
                duration: None,
                policy: PathBuf::from("p.yaml"),
                token: None,
                profile: LifecycleProfile::RequestLifecycle,
            }
        );
        for bad in [
            vec!["watch", "--system", "--kcrypto-profile", "lifecycle"],
            vec!["watch", "--system", "--kcrypto-profile"],
            vec!["report", "--system", "--kcrypto-profile", "bogus"],
            vec![
                "check",
                "--system",
                "--policy",
                "p.yaml",
                "--kcrypto-profile",
                "bogus",
            ],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "{bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn k5_live_commands_accept_token_path() {
        assert_eq!(
            parse(&argv(&["watch", "--system", "--token", "t"]))
                .unwrap()
                .command,
            Command::Watch {
                source: "kernel-crypto".to_owned(),
                duration: None,
                token: Some(PathBuf::from("t")),
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&["report", "--system", "--token", "t"]))
                .unwrap()
                .command,
            Command::ReportLive {
                source: "kernel-crypto".to_owned(),
                duration: None,
                format: ReportFormat::Human,
                out: None,
                token: Some(PathBuf::from("t")),
                profile: LifecycleProfile::ApiReturns,
                filter: FilterArgs::default(),
            }
        );
        assert_eq!(
            parse(&argv(&[
                "check", "--system", "--policy", "p.yaml", "--token", "t",
            ]))
            .unwrap()
            .command,
            Command::Check {
                source: "kernel-crypto".to_owned(),
                duration: None,
                policy: PathBuf::from("p.yaml"),
                token: Some(PathBuf::from("t")),
                profile: LifecycleProfile::ApiReturns,
            }
        );
        for bad in [
            vec!["watch", "--system", "--token"],
            vec!["report", "--system", "--token"],
            vec!["check", "--system", "--policy", "p.yaml", "--token"],
            vec!["report", "s.jsonl", "--token", "t"],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn subcommand_help_wins_anywhere_in_tail() {
        // P6 discovery path: `--help` after any flags is an early
        // exit naming the subcommand — never "unexpected".
        for tail in [
            vec!["watch", "--help"],
            vec!["watch", "--system", "--help"],
            vec!["report", "--help"],
            vec!["check", "--system", "--policy", "p", "--help"],
            vec!["doctor", "--help"],
        ] {
            assert!(
                matches!(parse(&argv(&tail)), Err(ArgsError::SubHelp { .. })),
                "args {tail:?} must request subcommand help"
            );
        }
        assert_eq!(
            parse(&argv(&["watch", "--help"])),
            Err(ArgsError::SubHelp {
                command: "watch".to_owned()
            })
        );
        // Unknown subcommands still report unknown (the help
        // request carries the name; dispatch rejects it, exit 2).
        assert_eq!(
            parse(&argv(&["frobnicate", "--help"])),
            Err(ArgsError::SubHelp {
                command: "frobnicate".to_owned()
            })
        );
        assert_eq!(subcommand_help("frobnicate"), None);
    }

    #[test]
    fn every_subcommand_has_help() {
        for sub in [
            "doctor", "backends", "inspect", "selftest", "token", "watch", "report", "check",
            "plan", "observe", "run",
        ] {
            assert!(
                subcommand_help(sub)
                    .is_some_and(|text| text.contains("usage:") || text.contains("unsupported")),
                "{sub} has help text"
            );
        }
    }

    #[test]
    fn live_capture_helps_name_profile_floor() {
        // The three live-capture helps pin the same contract: both
        // profiles, the 7.0+ lifecycle floor, and their own exits.
        for sub in ["watch", "report", "check"] {
            let text = subcommand_help(sub).expect("help exists");
            assert!(text.contains("api-returns"), "{sub} names api-returns");
            assert!(
                text.contains("request-lifecycle"),
                "{sub} names request-lifecycle"
            );
            assert!(text.contains("7.0"), "{sub} names the kernel floor");
            assert!(text.contains("unsupported profile"), "{sub} shows one");
        }
        let watch = subcommand_help("watch").expect("watch help");
        assert!(
            watch.contains("is NOT") && watch.contains("proof of complete coverage"),
            "watch exit 0 is never coverage proof: {watch}"
        );
    }

    #[test]
    fn kcrypto_profile_parses_per_subcommand() {
        use LifecycleProfile::{ApiReturns, RequestLifecycle};
        // Default is api-returns everywhere.
        for tail in [
            vec!["watch", "--system"],
            vec!["report", "--system"],
            vec!["check", "--system", "--policy", "p"],
        ] {
            let command = parse(&argv(&tail)).unwrap().command;
            let profile = match command {
                Command::Watch { profile, .. }
                | Command::ReportLive { profile, .. }
                | Command::Check { profile, .. } => profile,
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!(profile, ApiReturns, "default for {tail:?}");
        }
        // Explicit request-lifecycle selects per subcommand.
        assert!(matches!(
            parse(&argv(&[
                "watch",
                "--system",
                "--kcrypto-profile",
                "request-lifecycle"
            ]))
            .unwrap()
            .command,
            Command::Watch {
                profile: RequestLifecycle,
                ..
            }
        ));
        // Unsupported profiles are usage errors naming the supported set.
        for tail in [
            vec!["watch", "--system", "--kcrypto-profile", "frobnicate"],
            vec!["report", "--system", "--kcrypto-profile", "frobnicate"],
            vec![
                "check",
                "--system",
                "--policy",
                "p",
                "--kcrypto-profile",
                "frobnicate",
            ],
        ] {
            match parse(&argv(&tail)) {
                Err(ArgsError::Usage(reason)) => assert!(
                    reason.contains("api-returns|request-lifecycle"),
                    "names supported profiles: {reason}"
                ),
                other => panic!("args {tail:?} must be a usage error, got {other:?}"),
            }
        }
    }

    #[test]
    fn watch_accepts_request_filter_flags() {
        // P6-N3 RED: post-ingestion per-request submitter filters
        // (pid/uid/comm) on the watch path.
        assert!(matches!(
            parse(&argv(&["watch", "--system", "--filter-pid", "123"]))
                .unwrap()
                .command,
            Command::Watch {
                filter: FilterArgs {
                    pid: Some(123),
                    uid: None,
                    comm: None,
                },
                ..
            }
        ));
        assert!(matches!(
            parse(&argv(&[
                "watch",
                "--system",
                "--filter-uid",
                "1000",
                "--filter-comm",
                "bash"
            ]))
            .unwrap()
            .command,
            Command::Watch {
                filter: FilterArgs {
                    pid: None,
                    uid: Some(1000),
                    comm: Some(_),
                },
                ..
            }
        ));
        for bad in [
            vec!["watch", "--system", "--filter-pid", "nope"],
            vec!["watch", "--system", "--filter-uid", "-1"],
            vec!["watch", "--system", "--filter-pid"],
        ] {
            assert!(
                matches!(parse(&argv(&bad)), Err(ArgsError::Usage(_))),
                "args {bad:?} must be a usage error"
            );
        }
    }

    #[test]
    fn report_live_accepts_request_filter_flags() {
        // P6-N3 RED: the same filter surface on report --system.
        assert!(matches!(
            parse(&argv(&["report", "--system", "--filter-comm", "crypt"]))
                .unwrap()
                .command,
            Command::ReportLive {
                filter: FilterArgs {
                    pid: None,
                    uid: None,
                    comm: Some(_),
                },
                ..
            }
        ));
        assert!(matches!(
            parse(&argv(&["report", "--system", "--filter-uid", "x"])),
            Err(ArgsError::Usage(_))
        ));
    }

    #[test]
    fn watch_and_report_help_name_filter_flags() {
        // P6-N3 RED: the discovery path documents the filter surface.
        for help in [WATCH_HELP, REPORT_HELP] {
            for flag in ["--filter-pid", "--filter-uid", "--filter-comm"] {
                assert!(help.contains(flag), "help names {flag}");
            }
        }
    }
}
