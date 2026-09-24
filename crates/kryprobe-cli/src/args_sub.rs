// SPDX-License-Identifier: GPL-3.0-or-later
//! Subcommand grammars: inspect, selftest, report, watch, check.

use crate::args::{ArgsError, Command, ReportFormat, usage};
use std::path::PathBuf;

/// Default fixture calls for `selftest bpf` (matches the T7 lane).
const DEFAULT_CALLS: u64 = 200;

/// Only `--source` spelling accepted in v0.1 (kp2 §2: the CLI carries a
/// source concept from the start; kernel-only scope per ADR-0004, so no
/// other source is accepted).
const KERNEL_CRYPTO_SOURCE: &str = "kernel-crypto";

/// Parses `inspect --pid N [--json]` (requires exactly one pid).
pub(crate) fn parse_inspect(args: &[String], json: bool) -> Result<Command, ArgsError> {
    let mut pid: Option<u32> = None;
    let mut json = json;
    let mut rest = args;
    while let Some((arg, tail)) = rest.split_first() {
        match arg.as_str() {
            "--json" => {
                json = true;
                rest = tail;
            }
            "--pid" => {
                let Some((value, tail)) = tail.split_first() else {
                    return Err(usage("inspect: --pid needs a value"));
                };
                pid = Some(value.parse().map_err(|_| usage("inspect: invalid --pid"))?);
                rest = tail;
            }
            other => return Err(usage(format!("inspect: unexpected '{other}'"))),
        }
    }
    let Some(pid) = pid else {
        return Err(usage("inspect: missing --pid N"));
    };
    Ok(Command::Inspect { pid, json })
}

/// Parses `selftest synthetic|bpf|token-smoke` plus each lane's flags.
pub(crate) fn parse_selftest(args: &[String]) -> Result<Command, ArgsError> {
    let Some((target, rest)) = args.split_first() else {
        return Err(usage("selftest: missing target"));
    };
    match target.as_str() {
        "synthetic" => {
            let out = parse_out_only(rest, "selftest synthetic")?;
            Ok(Command::SelftestSynthetic { out })
        }
        "bpf" => {
            let mut calls = DEFAULT_CALLS;
            let mut out = None;
            let mut rest = rest;
            while let Some((arg, tail)) = rest.split_first() {
                match arg.as_str() {
                    "--calls" => {
                        let Some((value, tail)) = tail.split_first() else {
                            return Err(usage("selftest bpf: --calls needs a value"));
                        };
                        calls = value
                            .parse()
                            .map_err(|_| usage("selftest bpf: invalid --calls"))?;
                        if calls == 0 {
                            return Err(usage("selftest bpf: --calls must be >= 1"));
                        }
                        rest = tail;
                    }
                    "--out" => {
                        let Some((value, tail)) = tail.split_first() else {
                            return Err(usage("selftest bpf: --out needs a value"));
                        };
                        out = Some(PathBuf::from(value));
                        rest = tail;
                    }
                    other => return Err(usage(format!("selftest bpf: unexpected '{other}'"))),
                }
            }
            Ok(Command::SelftestBpf { calls, out })
        }
        "token-smoke" => {
            if let Some((arg, _)) = rest.split_first() {
                return Err(usage(format!("selftest token-smoke: unexpected '{arg}'")));
            }
            Ok(Command::SelftestToken)
        }
        other => Err(usage(format!("selftest: unknown target '{other}'"))),
    }
}

/// Only `--out FILE` is accepted after the target.
fn parse_out_only(args: &[String], what: &str) -> Result<Option<PathBuf>, ArgsError> {
    let mut out = None;
    let mut rest = args;
    while let Some((arg, tail)) = rest.split_first() {
        if arg != "--out" {
            return Err(usage(format!("{what}: unexpected '{arg}'")));
        }
        let Some((value, tail)) = tail.split_first() else {
            return Err(usage(format!("{what}: --out needs a value")));
        };
        out = Some(PathBuf::from(value));
        rest = tail;
    }
    Ok(out)
}

/// Parses `report FILE` (stream mode) or `report --system …` (live mode).
pub(crate) fn parse_report(args: &[String]) -> Result<Command, ArgsError> {
    // Two modes: `report FILE` validates + renders a stream (unchanged),
    // while any `--flag` selects the live system-wide capture grammar
    // (kp2 §2), which requires `--system`.
    if args.iter().any(|arg| arg.starts_with("--")) {
        return parse_report_live(args);
    }
    if args.len() != 1 {
        return Err(usage("report: want exactly one FILE"));
    }
    Ok(Command::Report {
        file: PathBuf::from(&args[0]),
    })
}

/// Workload selectors and display filters stay out of v0.1 (kp2 §3:
/// `--system` is the honest mode; report filtering and workload scope
/// need attribution semantics first). Name the deferral instead of a
/// bare "unexpected" so callers learn the boundary.
fn is_deferred_selector(arg: &str) -> bool {
    matches!(
        arg,
        "--pid" | "--tree" | "--cgroup" | "--cgroup-id" | "--unit" | "--comm"
    )
}

fn deferred(what: &str, arg: &str) -> ArgsError {
    usage(format!(
        "{what}: {arg} is deferred in v0.1 (system scope only)"
    ))
}

/// Takes the value after a `--flag` (missing value is a usage error).
fn take_value<'a>(
    tail: &'a [String],
    flag: &str,
    what: &str,
) -> Result<(&'a str, &'a [String]), ArgsError> {
    let Some((value, rest)) = tail.split_first() else {
        return Err(usage(format!("{what}: {flag} needs a value")));
    };
    Ok((value, rest))
}

/// Only `kernel-crypto` exists in v0.1; anything else is invalid input
/// (exit 2), never a silent default.
fn parse_source(value: &str, what: &str) -> Result<String, ArgsError> {
    if value == KERNEL_CRYPTO_SOURCE {
        Ok(value.to_owned())
    } else {
        Err(usage(format!(
            "{what}: unsupported --source '{value}' (only '{KERNEL_CRYPTO_SOURCE}' in v0.1)"
        )))
    }
}

/// Capture window in seconds; zero or unparseable is a usage error.
fn parse_duration(value: &str, what: &str) -> Result<u64, ArgsError> {
    let seconds: u64 = value
        .parse()
        .map_err(|_| usage(format!("{what}: invalid --duration")))?;
    if seconds == 0 {
        return Err(usage(format!("{what}: --duration must be >= 1")));
    }
    Ok(seconds)
}

/// `watch --system [--source S] [--duration N] [--token PATH]`:
/// continuous system-wide observe. `--system` is required (select-all
/// is the only v0.1 scope).
pub(crate) fn parse_watch(args: &[String]) -> Result<Command, ArgsError> {
    let mut system = false;
    let mut source = KERNEL_CRYPTO_SOURCE.to_owned();
    let mut duration = None;
    let mut token = None;
    let mut rest = args;
    while let Some((arg, tail)) = rest.split_first() {
        match arg.as_str() {
            "--system" => {
                system = true;
                rest = tail;
            }
            "--source" => {
                let (value, next) = take_value(tail, "--source", "watch")?;
                source = parse_source(value, "watch")?;
                rest = next;
            }
            "--duration" => {
                let (value, next) = take_value(tail, "--duration", "watch")?;
                duration = Some(parse_duration(value, "watch")?);
                rest = next;
            }
            "--token" => {
                let (value, next) = take_value(tail, "--token", "watch")?;
                token = Some(PathBuf::from(value));
                rest = next;
            }
            other if is_deferred_selector(other) => return Err(deferred("watch", other)),
            other => return Err(usage(format!("watch: unexpected '{other}'"))),
        }
    }
    if !system {
        return Err(usage("watch: missing --system (system scope only in v0.1)"));
    }
    Ok(Command::Watch {
        source,
        duration,
        token,
    })
}

/// `report --system [--duration N] [--format human|json] [--out F]
/// [--source S] [--token PATH]`: bounded system-wide capture + render.
fn parse_report_live(args: &[String]) -> Result<Command, ArgsError> {
    let mut system = false;
    let mut source = KERNEL_CRYPTO_SOURCE.to_owned();
    let mut duration = None;
    let mut format = ReportFormat::Human;
    let mut out = None;
    let mut token = None;
    let mut rest = args;
    while let Some((arg, tail)) = rest.split_first() {
        match arg.as_str() {
            "--system" => {
                system = true;
                rest = tail;
            }
            "--source" => {
                let (value, next) = take_value(tail, "--source", "report")?;
                source = parse_source(value, "report")?;
                rest = next;
            }
            "--token" => {
                let (value, next) = take_value(tail, "--token", "report")?;
                token = Some(PathBuf::from(value));
                rest = next;
            }
            "--duration" => {
                let (value, next) = take_value(tail, "--duration", "report")?;
                duration = Some(parse_duration(value, "report")?);
                rest = next;
            }
            "--format" => {
                let (value, next) = take_value(tail, "--format", "report")?;
                format = match value {
                    "human" => ReportFormat::Human,
                    "json" => ReportFormat::Json,
                    "jsonl" => ReportFormat::Jsonl,
                    _ => {
                        return Err(usage(format!(
                            "report: unsupported --format '{value}' (human|json|jsonl)"
                        )));
                    }
                };
                rest = next;
            }
            "--out" => {
                let (value, next) = take_value(tail, "--out", "report")?;
                out = Some(PathBuf::from(value));
                rest = next;
            }
            other if is_deferred_selector(other) => return Err(deferred("report", other)),
            other => return Err(usage(format!("report: unexpected '{other}'"))),
        }
    }
    if !system {
        return Err(usage(
            "report: missing --system (live report needs --system; 'report FILE' renders a file)",
        ));
    }
    Ok(Command::ReportLive {
        source,
        duration,
        format,
        out,
        token,
    })
}

/// `check --system --policy F [--duration N] [--source S] [--token PATH]`:
/// system-wide policy check. `--policy` is required (v0.1 has no
/// default policy).
pub(crate) fn parse_check(args: &[String]) -> Result<Command, ArgsError> {
    let mut system = false;
    let mut source = KERNEL_CRYPTO_SOURCE.to_owned();
    let mut duration = None;
    let mut policy = None;
    let mut token = None;
    let mut rest = args;
    while let Some((arg, tail)) = rest.split_first() {
        match arg.as_str() {
            "--system" => {
                system = true;
                rest = tail;
            }
            "--source" => {
                let (value, next) = take_value(tail, "--source", "check")?;
                source = parse_source(value, "check")?;
                rest = next;
            }
            "--duration" => {
                let (value, next) = take_value(tail, "--duration", "check")?;
                duration = Some(parse_duration(value, "check")?);
                rest = next;
            }
            "--policy" => {
                let (value, next) = take_value(tail, "--policy", "check")?;
                policy = Some(PathBuf::from(value));
                rest = next;
            }
            "--token" => {
                let (value, next) = take_value(tail, "--token", "check")?;
                token = Some(PathBuf::from(value));
                rest = next;
            }
            other if is_deferred_selector(other) => return Err(deferred("check", other)),
            other => return Err(usage(format!("check: unexpected '{other}'"))),
        }
    }
    if !system {
        return Err(usage("check: missing --system (system scope only in v0.1)"));
    }
    let Some(policy) = policy else {
        return Err(usage("check: missing --policy FILE"));
    };
    Ok(Command::Check {
        source,
        duration,
        policy,
        token,
    })
}

/// `token mint [--bin PATH] [--receipt PATH] [--force]` /
/// `token status [--bin PATH]` (K5: mint-once delegation surface).
/// No `--pin` spelling exists in the setcap branch (unknown flags are
/// usage errors, never silently ignored).
pub(crate) fn parse_token(args: &[String]) -> Result<Command, ArgsError> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(usage("token: missing verb (mint|status)"));
    };
    match verb.as_str() {
        "mint" => {
            let mut bin = None;
            let mut receipt = None;
            let mut force = false;
            let mut rest = rest;
            while let Some((arg, tail)) = rest.split_first() {
                match arg.as_str() {
                    "--bin" => {
                        let (value, next) = take_value(tail, "--bin", "token mint")?;
                        bin = Some(PathBuf::from(value));
                        rest = next;
                    }
                    "--receipt" => {
                        let (value, next) = take_value(tail, "--receipt", "token mint")?;
                        receipt = Some(PathBuf::from(value));
                        rest = next;
                    }
                    "--force" => {
                        force = true;
                        rest = tail;
                    }
                    other => return Err(usage(format!("token mint: unexpected '{other}'"))),
                }
            }
            Ok(Command::TokenMint {
                bin,
                receipt,
                force,
            })
        }
        "status" => {
            let mut bin = None;
            let mut rest = rest;
            while let Some((arg, tail)) = rest.split_first() {
                match arg.as_str() {
                    "--bin" => {
                        let (value, next) = take_value(tail, "--bin", "token status")?;
                        bin = Some(PathBuf::from(value));
                        rest = next;
                    }
                    other => return Err(usage(format!("token status: unexpected '{other}'"))),
                }
            }
            Ok(Command::TokenStatus { bin })
        }
        other => Err(usage(format!(
            "token: unknown verb '{other}' (mint|status)"
        ))),
    }
}
