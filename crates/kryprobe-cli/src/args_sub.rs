// SPDX-License-Identifier: GPL-3.0-or-later
//! Subcommand grammars: inspect, selftest, report, watch, check.

use crate::args::{ArgsError, Command, FilterArgs, ReportFormat, usage};
use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;
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
    matches!(arg, "--pid" | "--tree" | "--unit" | "--comm")
}

fn deferred(what: &str, arg: &str) -> ArgsError {
    usage(format!(
        "{what}: {arg} is deferred in v0.1 (system scope only)"
    ))
}

/// Pod/runtime/container workload selectors are not M1 CLI views:
/// pod and runtime selectors refuse until M2, and the container
/// selector is not exposed (container grouping via `--group-by
/// container` is the M1 container view).
fn is_m2_selector(arg: &str) -> bool {
    matches!(
        arg,
        "--filter-pod" | "--filter-runtime" | "--filter-container"
    )
}

fn m2_refusal(what: &str, arg: &str) -> ArgsError {
    if arg == "--filter-container" {
        usage(format!(
            "{what}: {arg} is not supported in M1 (M1 views: --filter-cgroup-id only; container grouping via --group-by container)"
        ))
    } else {
        usage(format!(
            "{what}: {arg} is refused until M2 (M1 supports cgroup-id views only)"
        ))
    }
}

/// The old scope-ish spellings are superseded by the explicit
/// post-ingestion view flag: name the supported spelling instead of a
/// bare "unexpected" so callers learn the boundary.
fn is_cgroup_hint(arg: &str) -> bool {
    matches!(arg, "--cgroup" | "--cgroup-id")
}

fn cgroup_hint(what: &str, arg: &str) -> ArgsError {
    usage(format!(
        "{what}: {arg} is not supported (use --filter-cgroup-id ID for cgroup views)"
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

/// Capture profile by exact name; anything else is invalid input
/// (exit 2), never a silent default.
fn parse_profile(value: &str, what: &str) -> Result<LifecycleProfile, ArgsError> {
    LifecycleProfile::parse(value).ok_or_else(|| {
        usage(format!(
            "{what}: unsupported --kcrypto-profile '{value}' (api-returns|request-lifecycle)"
        ))
    })
}

/// Submitter id constraint (exact u32 — pid or uid); unparseable is
/// a usage error (no silent default, no truncation).
fn parse_filter_id(value: &str, flag: &str, what: &str) -> Result<u32, ArgsError> {
    value.parse::<u32>().map_err(|_| {
        usage(format!(
            "{what}: invalid {flag} '{value}' (exact unsigned id)"
        ))
    })
}

/// Workload row grouping by exact name; anything else is invalid
/// input (exit 2), never a silent default.
fn parse_group_by(
    value: &str,
    what: &str,
) -> Result<kryprobe_report::workload::GroupBy, ArgsError> {
    use kryprobe_report::workload::GroupBy;
    match value {
        "none" => Ok(GroupBy::None),
        "cgroup" => Ok(GroupBy::Cgroup),
        "container" => Ok(GroupBy::Container),
        _ => Err(usage(format!(
            "{what}: unsupported --group-by '{value}' (none|cgroup|container)"
        ))),
    }
}

/// Exact cgroup-id view: unparseable or 0 is a usage error (the
/// unreadable marker is never selectable, even as a view).
fn parse_filter_cgroup_id(value: &str, what: &str) -> Result<u64, ArgsError> {
    let id: u64 = value.parse().map_err(|_| {
        usage(format!(
            "{what}: invalid --filter-cgroup-id '{value}' (exact cgroup id)"
        ))
    })?;
    if id == 0 {
        return Err(usage(format!(
            "{what}: --filter-cgroup-id refuses 0 (unreadable marker, never selectable)"
        )));
    }
    Ok(id)
}

/// M1 workload/profile combination rule: workload views need the
/// api-returns `KCTX` maps (the lifecycle profile carries none).
fn check_workload_profile(
    what: &str,
    workload: bool,
    profile: LifecycleProfile,
) -> Result<(), ArgsError> {
    if workload && profile != LifecycleProfile::ApiReturns {
        return Err(usage(format!(
            "{what}: workload views need the api-returns profile (request-lifecycle carries no workload maps)"
        )));
    }
    Ok(())
}

/// M1 workload/filter combination rule: submitter filters constrain
/// per-request submitter identity, which workload context rows do
/// not carry — combining them would misfilter, so it refuses.
fn check_workload_filters(
    what: &str,
    workload: bool,
    filter: &FilterArgs,
) -> Result<(), ArgsError> {
    if workload && filter.is_active() {
        return Err(usage(format!(
            "{what}: workload views cannot combine with --filter-pid/--filter-uid/--filter-comm (submitter filters need request rows)"
        )));
    }
    Ok(())
}

/// `watch --system [--source S] [--duration N] [--token PATH]`:
/// continuous system-wide observe. `--system` is required (select-all
/// is the only v0.1 scope). M1 workload flags (`--group-by`,
/// `--filter-cgroup-id`, `--workload-metadata`) select the typed
/// workload render instead of the historical tables.
pub(crate) fn parse_watch(args: &[String]) -> Result<Command, ArgsError> {
    let mut system = false;
    let mut source = KERNEL_CRYPTO_SOURCE.to_owned();
    let mut duration = None;
    let mut token = None;
    let mut profile = LifecycleProfile::default();
    let mut filter = FilterArgs::default();
    let mut group_by = kryprobe_report::workload::GroupBy::None;
    let mut filter_cgroup_id = None;
    let mut workload_metadata = None;
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
            "--kcrypto-profile" => {
                let (value, next) = take_value(tail, "--kcrypto-profile", "watch")?;
                profile = parse_profile(value, "watch")?;
                rest = next;
            }
            "--filter-pid" => {
                let (value, next) = take_value(tail, "--filter-pid", "watch")?;
                filter.pid = Some(parse_filter_id(value, "--filter-pid", "watch")?);
                rest = next;
            }
            "--filter-uid" => {
                let (value, next) = take_value(tail, "--filter-uid", "watch")?;
                filter.uid = Some(parse_filter_id(value, "--filter-uid", "watch")?);
                rest = next;
            }
            "--filter-comm" => {
                let (value, next) = take_value(tail, "--filter-comm", "watch")?;
                filter.comm = Some(value.to_owned());
                rest = next;
            }
            "--group-by" => {
                let (value, next) = take_value(tail, "--group-by", "watch")?;
                group_by = parse_group_by(value, "watch")?;
                rest = next;
            }
            "--filter-cgroup-id" => {
                let (value, next) = take_value(tail, "--filter-cgroup-id", "watch")?;
                filter_cgroup_id = Some(parse_filter_cgroup_id(value, "watch")?);
                rest = next;
            }
            "--workload-metadata" => {
                let (value, next) = take_value(tail, "--workload-metadata", "watch")?;
                workload_metadata = Some(PathBuf::from(value));
                rest = next;
            }
            other if is_m2_selector(other) => return Err(m2_refusal("watch", other)),
            other if is_cgroup_hint(other) => return Err(cgroup_hint("watch", other)),
            other if is_deferred_selector(other) => return Err(deferred("watch", other)),
            other => return Err(usage(format!("watch: unexpected '{other}'"))),
        }
    }
    if !system {
        return Err(usage("watch: missing --system (system scope only in v0.1)"));
    }
    let workload = group_by != kryprobe_report::workload::GroupBy::None
        || filter_cgroup_id.is_some()
        || workload_metadata.is_some();
    check_workload_profile("watch", workload, profile)?;
    check_workload_filters("watch", workload, &filter)?;
    Ok(Command::Watch {
        source,
        duration,
        token,
        profile,
        filter,
        group_by,
        filter_cgroup_id,
        workload_metadata,
    })
}

/// `report --system [--duration N] [--format human|json] [--out F]
/// [--source S] [--token PATH]`: bounded system-wide capture + render.
/// M1 workload flags (`--group-by`, `--filter-cgroup-id`,
/// `--workload-metadata`, `--format workload-json`) select the typed
/// workload report instead of the historical formats.
fn parse_report_live(args: &[String]) -> Result<Command, ArgsError> {
    let mut system = false;
    let mut source = KERNEL_CRYPTO_SOURCE.to_owned();
    let mut duration = None;
    let mut format = ReportFormat::Human;
    let mut out = None;
    let mut token = None;
    let mut profile = LifecycleProfile::default();
    let mut filter = FilterArgs::default();
    let mut group_by = kryprobe_report::workload::GroupBy::None;
    let mut filter_cgroup_id = None;
    let mut workload_metadata = None;
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
                    "workload-json" => ReportFormat::WorkloadJson,
                    _ => {
                        return Err(usage(format!(
                            "report: unsupported --format '{value}' (human|json|jsonl|workload-json)"
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
            "--kcrypto-profile" => {
                let (value, next) = take_value(tail, "--kcrypto-profile", "report")?;
                profile = parse_profile(value, "report")?;
                rest = next;
            }
            "--filter-pid" => {
                let (value, next) = take_value(tail, "--filter-pid", "report")?;
                filter.pid = Some(parse_filter_id(value, "--filter-pid", "report")?);
                rest = next;
            }
            "--filter-uid" => {
                let (value, next) = take_value(tail, "--filter-uid", "report")?;
                filter.uid = Some(parse_filter_id(value, "--filter-uid", "report")?);
                rest = next;
            }
            "--filter-comm" => {
                let (value, next) = take_value(tail, "--filter-comm", "report")?;
                filter.comm = Some(value.to_owned());
                rest = next;
            }
            "--group-by" => {
                let (value, next) = take_value(tail, "--group-by", "report")?;
                group_by = parse_group_by(value, "report")?;
                rest = next;
            }
            "--filter-cgroup-id" => {
                let (value, next) = take_value(tail, "--filter-cgroup-id", "report")?;
                filter_cgroup_id = Some(parse_filter_cgroup_id(value, "report")?);
                rest = next;
            }
            "--workload-metadata" => {
                let (value, next) = take_value(tail, "--workload-metadata", "report")?;
                workload_metadata = Some(PathBuf::from(value));
                rest = next;
            }
            other if is_m2_selector(other) => return Err(m2_refusal("report", other)),
            other if is_cgroup_hint(other) => return Err(cgroup_hint("report", other)),
            other if is_deferred_selector(other) => return Err(deferred("report", other)),
            other => return Err(usage(format!("report: unexpected '{other}'"))),
        }
    }
    if !system {
        return Err(usage(
            "report: missing --system (live report needs --system; 'report FILE' renders a file)",
        ));
    }
    let workload = group_by != kryprobe_report::workload::GroupBy::None
        || filter_cgroup_id.is_some()
        || workload_metadata.is_some()
        || format == ReportFormat::WorkloadJson;
    check_workload_profile("report", workload, profile)?;
    check_workload_filters("report", workload, &filter)?;
    // The brief-exact JSON doc and the JSONL envelopes render live
    // observations, which carry no workload rows: workload flags
    // combine only with human (workload text) or workload-json.
    if workload && matches!(format, ReportFormat::Json | ReportFormat::Jsonl) {
        return Err(usage(
            "report: --group-by/--filter-cgroup-id/--workload-metadata need --format human or --format workload-json".to_string(),
        ));
    }
    Ok(Command::ReportLive {
        source,
        duration,
        format,
        out,
        token,
        profile,
        filter,
        group_by,
        filter_cgroup_id,
        workload_metadata,
    })
}

/// `check --system --policy F [--duration N] [--source S] [--token PATH]`:
/// system-wide policy check. `--policy` is required (v0.1 has no
/// default policy). `--filter-cgroup-id` scopes the check to one
/// exact cgroup view over the typed workload report.
pub(crate) fn parse_check(args: &[String]) -> Result<Command, ArgsError> {
    let mut system = false;
    let mut source = KERNEL_CRYPTO_SOURCE.to_owned();
    let mut duration = None;
    let mut policy = None;
    let mut token = None;
    let mut profile = LifecycleProfile::default();
    let mut filter_cgroup_id = None;
    let mut workload_metadata = None;
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
            "--kcrypto-profile" => {
                let (value, next) = take_value(tail, "--kcrypto-profile", "check")?;
                profile = parse_profile(value, "check")?;
                rest = next;
            }
            "--filter-cgroup-id" => {
                let (value, next) = take_value(tail, "--filter-cgroup-id", "check")?;
                filter_cgroup_id = Some(parse_filter_cgroup_id(value, "check")?);
                rest = next;
            }
            "--workload-metadata" => {
                let (value, next) = take_value(tail, "--workload-metadata", "check")?;
                workload_metadata = Some(PathBuf::from(value));
                rest = next;
            }
            "--group-by" => {
                return Err(usage(
                    "check: --group-by is not supported (grouping is a report rendering axis)"
                        .to_string(),
                ));
            }
            other if is_m2_selector(other) => return Err(m2_refusal("check", other)),
            other if is_cgroup_hint(other) => return Err(cgroup_hint("check", other)),
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
    // System-wide checks evaluate live observations, which take no
    // metadata: the file only feeds scoped checks.
    if workload_metadata.is_some() && filter_cgroup_id.is_none() {
        return Err(usage(
            "check: --workload-metadata needs --filter-cgroup-id (system-wide checks take no metadata)"
                .to_string(),
        ));
    }
    check_workload_profile("check", filter_cgroup_id.is_some(), profile)?;
    Ok(Command::Check {
        source,
        duration,
        policy,
        token,
        profile,
        filter_cgroup_id,
        workload_metadata,
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
