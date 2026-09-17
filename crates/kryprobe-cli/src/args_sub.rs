// SPDX-License-Identifier: GPL-3.0-or-later
//! Subcommand grammars: inspect, selftest, report.

use crate::args::{ArgsError, Command, usage};
use std::path::PathBuf;

/// Default fixture calls for `selftest bpf` (matches the T7 lane).
const DEFAULT_CALLS: u64 = 200;

pub fn parse_inspect(args: &[String], json: bool) -> Result<Command, ArgsError> {
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

pub fn parse_selftest(args: &[String]) -> Result<Command, ArgsError> {
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

pub fn parse_report(args: &[String]) -> Result<Command, ArgsError> {
    if args.len() != 1 || args[0].starts_with("--") {
        return Err(usage("report: want exactly one FILE"));
    }
    Ok(Command::Report {
        file: PathBuf::from(&args[0]),
    })
}
