// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2B unprivileged workload helper: fixed executable, fixed
//! stdio protocol. Reads one snapshot request on stdin, writes one
//! snapshot response on stdout, attests and reports counters on stderr.
//!
//! Launch contract (spec §5.2 binding placement): the Stage 3 launcher
//! starts this exact binary under an established non-root principal with
//! empty capability sets, no-new-privs, and stdio-only descriptors,
//! before capture threads own authority fds. The helper re-verifies all
//! of that itself, before parsing any metadata or request byte, and
//! refuses typed otherwise. `--attest` reports the boundary without
//! touching metadata or stdin.

mod cache;
mod host_reader;
mod ipc;
mod metadata;
mod resolver;

use host_reader::HostView;
use ipc::{
    EXIT_OK, EXIT_REFUSED, EXIT_USAGE, attestation_line, check_attestation, collect_attestation,
    default_request_budget, error_line, read_request_with_timeout, write_response,
};
use kryprobe_core::workload::{HELPER_REQUEST_TIMEOUT_NS, MetadataUnavailable};
use metadata::load_metadata_file;
use resolver::{Clock, Resolver};
use std::path::PathBuf;
use std::time::Duration;

/// Parsed helper invocation.
#[derive(Debug, PartialEq, Eq)]
struct Args {
    /// Optional validated metadata snapshot file.
    metadata: Option<PathBuf>,
    /// Report attestation only (no metadata/stdin reads).
    attest: bool,
    /// Root for `/proc`-relative reads (fixture override for tests).
    proc_root: PathBuf,
    /// Root for cgroupfs-relative reads (fixture override for tests).
    cgroup_root: PathBuf,
    /// Refuse unless no-new-privs is set (installed-launcher mode).
    require_no_new_privs: bool,
}

impl Args {
    fn defaults() -> Self {
        Self {
            metadata: None,
            attest: false,
            proc_root: PathBuf::from("/proc"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            require_no_new_privs: false,
        }
    }
}

/// Usage text (static; the only stdout content besides protocol bytes).
const USAGE: &str = "usage: kryprobe-workload-helper [--attest] [--metadata FILE] [--proc-root DIR] [--cgroup-root DIR] [--require-no-new-privs]\n";

/// Parse the fixed flag vocabulary. Anything else is a usage error —
/// the helper takes no subcommands, no executable paths, and no network
/// or runtime options in M1.
fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut args = Args::defaults();
    let mut index = 1;
    while index < argv.len() {
        match argv[index].as_str() {
            "--attest" => args.attest = true,
            "--require-no-new-privs" => args.require_no_new_privs = true,
            "--metadata" => {
                index += 1;
                let value = argv.get(index).ok_or("missing value for --metadata")?;
                args.metadata = Some(PathBuf::from(value));
            }
            "--proc-root" => {
                index += 1;
                let value = argv.get(index).ok_or("missing value for --proc-root")?;
                args.proc_root = PathBuf::from(value);
            }
            "--cgroup-root" => {
                index += 1;
                let value = argv.get(index).ok_or("missing value for --cgroup-root")?;
                args.cgroup_root = PathBuf::from(value);
            }
            "--help" | "-h" => return Err(USAGE.to_string()),
            _other => return Err(format!("unknown argument\n{USAGE}")),
        }
        index += 1;
    }
    Ok(args)
}

/// Boot-nanosecond clock over the host view. A mid-request clock loss
/// fails closed as expired (`u64::MAX`): TTLs lapse and the deadline
/// trips rather than serving stale bindings.
struct UptimeClock<'a> {
    view: &'a HostView,
}

impl Clock for UptimeClock<'_> {
    fn now_ns(&self) -> u64 {
        self.view.boot_time_ns().unwrap_or(u64::MAX)
    }
}

/// Emit one stderr JSON error line.
fn refuse(kind: MetadataUnavailable) -> i32 {
    eprintln!("{}", error_line(kind));
    EXIT_REFUSED
}

fn run_attest(args: &Args) -> i32 {
    match collect_attestation() {
        Ok(attestation) => {
            println!("{}", attestation_line(&attestation));
            match check_attestation(&attestation, args.require_no_new_privs) {
                Ok(()) => EXIT_OK,
                Err(kind) => refuse(kind),
            }
        }
        Err(kind) => refuse(kind),
    }
}

fn run_serve(args: &Args) -> i32 {
    // 1. Self-attestation first: no metadata or request byte is parsed
    // until the unprivileged boundary is established.
    let attestation = match collect_attestation() {
        Ok(attestation) => attestation,
        Err(kind) => return refuse(kind),
    };
    if let Err(kind) = check_attestation(&attestation, args.require_no_new_privs) {
        return refuse(kind);
    }
    eprintln!("{}", attestation_line(&attestation));

    // 2. Optional validated metadata (untrusted input, bounded load).
    let snapshot = match &args.metadata {
        Some(path) => match load_metadata_file(path) {
            Ok(snapshot) => Some(snapshot),
            Err(kind) => return refuse(kind),
        },
        None => None,
    };

    // 3. One stdin request under the frozen helper timeout.
    let view = HostView::new(&args.proc_root, &args.cgroup_root);
    let start_ns = match view.boot_time_ns() {
        Ok(now) => now,
        Err(_) => return refuse(MetadataUnavailable::UnsupportedEnvironment),
    };
    let stdin = std::io::stdin();
    let request = match read_request_with_timeout(
        stdin,
        default_request_budget(),
        Duration::from_nanos(HELPER_REQUEST_TIMEOUT_NS),
    ) {
        Ok(request) => request,
        Err(kind) => return refuse(kind),
    };

    // 4. Conservative join: frozen pure answer plus verified liveness.
    let clock = UptimeClock { view: &view };
    let mut resolver = Resolver::new(view.clone(), snapshot);
    let response = match resolver.resolve(&request, &clock, start_ns) {
        Ok(response) => response,
        Err(kind) => return refuse(kind),
    };

    // 5. Exactly one stdout document, then the counters line. A failed
    // write is a failure, never a silent success.
    let stdout = std::io::stdout();
    if write_response(stdout.lock(), &response).is_err() {
        return refuse(MetadataUnavailable::HelperRefused);
    }
    let counters = serde_json::json!({ "helper_counters": resolver.counters() });
    eprintln!("{counters}");
    EXIT_OK
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse_args(&argv) {
        Ok(args) => args,
        Err(text) => {
            eprint!("{text}");
            std::process::exit(EXIT_USAGE);
        }
    };
    let code = if args.attest {
        run_attest(&args)
    } else {
        run_serve(&args)
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    #[test]
    fn defaults_serve_stdin() {
        let args = parse_args(&argv(&["helper"])).expect("parses");
        assert_eq!(args, Args::defaults());
        assert!(!args.attest);
    }

    #[test]
    fn all_flags_parse() {
        let args = parse_args(&argv(&[
            "helper",
            "--attest",
            "--metadata",
            "m.json",
            "--proc-root",
            "/p",
            "--cgroup-root",
            "/c",
            "--require-no-new-privs",
        ]))
        .expect("parses");
        assert!(args.attest);
        assert_eq!(args.metadata, Some(PathBuf::from("m.json")));
        assert_eq!(args.proc_root, PathBuf::from("/p"));
        assert_eq!(args.cgroup_root, PathBuf::from("/c"));
        assert!(args.require_no_new_privs);
    }

    #[test]
    fn unknown_or_missing_values_are_usage_errors() {
        assert!(parse_args(&argv(&["helper", "--exec", "/bin/x"])).is_err());
        assert!(parse_args(&argv(&["helper", "--metadata"])).is_err());
        assert!(parse_args(&argv(&["helper", "serve"])).is_err());
        assert!(parse_args(&argv(&["helper", "--help"])).is_err());
    }

    #[test]
    fn uptime_clock_fails_closed_on_loss() {
        let view = HostView::new(
            std::path::Path::new("/nonexistent-proc-root"),
            std::path::Path::new("/nonexistent-cgroup-root"),
        );
        let clock = UptimeClock { view: &view };
        assert_eq!(clock.now_ns(), u64::MAX);
    }
}
