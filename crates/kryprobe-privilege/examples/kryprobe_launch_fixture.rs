// SPDX-License-Identifier: GPL-3.0-or-later
//! Launch-boundary test fixture (NEVER shipped): a fake workload
//! helper driven by a JSON sidecar, speaking the real `--attest` and
//! serve protocols through real confinement.
//!
//! Why a binary: fd-exec with `CLOEXEC` (C1 A1) cannot run scripts —
//! the interpreter re-opens `/proc/self/fd/N` after `exec`, when the
//! fd is already gone — while any surviving fd breaks the frozen
//! stdio-only attestation the real helper enforces on itself. Scripts
//! are therefore unusable as fixtures; this ELF fixture is.
//!
//! Sidecar: `<argv[0]-stem>.fixture.json` next to `argv[0]` (the
//! launcher sets `argv[0]` to the helper path, so parallel tests
//! never share state). All fields optional unless noted:
//!
//! - `attest_garbage`: print this line instead of an attestation.
//! - `attest_exit`: exit code for the attest path (default 0;
//!   without garbage the exit is silent).
//! - `forge_uid`/`forge_euid`: replace ids in honest attestations.
//! - `refuse`: serve prints `{"error":NAME}` on stderr, exits 1.
//! - `crash`: serve SIGKILLs itself (after the count below).
//! - `stall_secs`: serve sleeps this long, then exits 0.
//! - `echo_unresolved`: serve answers EVERY request key with an
//!   unresolved echo association (key verbatim + empty identity +
//!   unresolved hook-context evidence), binding to any chunk — the
//!   C3 multi-request oracle (a fixed canned file cannot bind to
//!   more than one chunk).
//! - `canned`: serve file to substitute + emit (REQUIRED unless
//!   refuse/crash/stall/echo/retainer is set).
//! - `session_placeholder`: substituted with the request session
//!   (default: 32 zeros).
//! - `argv_log`: append `argv` one-per-line here (serve path).
//! - `count`: append one `x` line here per serve invocation.
//! - `shrink_pipes`: `fcntl(F_SETPIPE_SZ)` fds 1+2 to this capacity
//!   at startup (the pipe is shared, so the parent's reads feel the
//!   backpressure too — the C1 small-pipe oracle, with no launcher
//!   test seam: the production spawn path runs unchanged).
//! - `pipe_report`: write the actual post-shrink capacities here
//!   (the oracle asserts them — no vacuous green).
//! - `spawn_retainer`: `{"sleep_secs": N, "pidfile": PATH}` — fork a
//!   grandchild holding every stdio fd, append its pid, and exit 0
//!   immediately WITHOUT reading stdin (the C1 exited-child oracle).
//!
//! Relative paths resolve against the sidecar directory. A missing
//! or unparsable sidecar exits 3 loudly (tests always write one).
//!
//! Test-only Cargo gate: this file lives in `examples/`, so the
//! DEFAULT `cargo build` (dev or release) never builds it and the
//! default `cargo install` never ships it (it installs `[[bin]]`
//! targets only) — `src/bin/` autodiscovery was the hole (a normal
//! build produced a shippable artifact). Explicit example selection
//! (`--example kryprobe_launch_fixture`) still can build it;
//! `cargo test` DOES (to `<profile>/examples/`), which is the only
//! build that spawns it.
//!
//! Anti-confusion (why its real-IPC wire output cannot be mistaken
//! for the real helper): (1) path separation — production discovery
//! is the FIXED sibling and the launcher spawns this fixture only
//! through test-only explicit override paths, never via discovery;
//! (2) mode separation — without its `<stem>.fixture.json` sidecar
//! (which production never ships) it exits 3 before printing any
//! protocol byte, so a stray copy at the sibling path cannot answer;
//! (3) the wire shapes stay frozen-identical on purpose — no
//! discriminator field exists because the parsers deny unknown
//! fields, so the separation above, not the bytes, is the guard.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Sidecar defaults: 32-zero session placeholder.
const PLACEHOLDER: &str = "00000000000000000000000000000000";

/// Collected boundary, same JSON shape as the real helper.
struct Attestation {
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    caps_zero: bool,
    no_new_privs: bool,
    fds: Vec<u32>,
}

/// Read one `/proc/self/status` field line (`Uid:`/`Gid:`/`CapXxx:`).
fn status_field(status: &str, key: &str) -> Option<String> {
    status.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        (name == key).then(|| rest.trim().to_string())
    })
}

/// Honest boundary collect (mirrors the real helper: kernel ids,
/// all-zero caps check, `no_new_privs`, fd set minus the transient
/// highest lister fd).
fn collect() -> Option<Attestation> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let ids: Vec<u32> = status_field(&status, "Uid")?
        .split_whitespace()
        .filter_map(|part| part.parse().ok())
        .collect();
    let gids: Vec<u32> = status_field(&status, "Gid")?
        .split_whitespace()
        .filter_map(|part| part.parse().ok())
        .collect();
    let zero = |key: &str| status_field(&status, key).as_deref() == Some("0000000000000000");
    let caps_zero = zero("CapEff") && zero("CapPrm") && zero("CapInh") && zero("CapAmb");
    let no_new_privs = status_field(&status, "NoNewPrivs").as_deref() == Some("1");
    let mut fds: Vec<u32> = std::fs::read_dir("/proc/self/fd")
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter_map(|name| name.parse().ok())
        .collect();
    fds.sort_unstable();
    fds.pop()?;
    Some(Attestation {
        uid: *ids.first()?,
        euid: *ids.get(1)?,
        gid: *gids.first()?,
        egid: *gids.get(1)?,
        caps_zero,
        no_new_privs,
        fds,
    })
}

/// Render one `{"attestation":{...}}` line (frozen shape).
fn attestation_line(attestation: &Attestation) -> String {
    let caps = if attestation.caps_zero { "0" } else { "1" };
    let fds = attestation
        .fds
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"attestation\":{{\"uid\":{},\"euid\":{},\"gid\":{},\"egid\":{},\
         \"caps\":{{\"eff\":\"{caps}\",\"prm\":\"{caps}\",\"inh\":\"{caps}\",\"amb\":\"{caps}\"}},\
         \"no_new_privs\":{},\"fds\":[{fds}]}}}}",
        attestation.uid,
        attestation.euid,
        attestation.gid,
        attestation.egid,
        attestation.no_new_privs,
    )
}

/// Resolve a sidecar path (relative joins the sidecar directory).
fn resolve(dir: &Path, value: &serde_json::Value) -> Option<PathBuf> {
    let text = value.as_str()?;
    let path = PathBuf::from(text);
    Some(if path.is_absolute() {
        path
    } else {
        dir.join(path)
    })
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let exe = PathBuf::from(argv.first().map(String::as_str).unwrap_or("fixture"));
    let dir = exe.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
    let stem = exe
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("fixture");
    let sidecar_path = dir.join(format!("{stem}.fixture.json"));
    let sidecar_text = std::fs::read_to_string(&sidecar_path).unwrap_or_else(|_| {
        eprintln!("launch-fixture: missing sidecar {}", sidecar_path.display());
        std::process::exit(3);
    });
    let sidecar: serde_json::Value = serde_json::from_str(&sidecar_text).unwrap_or_else(|_| {
        eprintln!(
            "launch-fixture: unparsable sidecar {}",
            sidecar_path.display()
        );
        std::process::exit(3);
    });
    if let Some(size) = sidecar.get("shrink_pipes").and_then(|v| v.as_i64()) {
        // Deterministic backpressure: shrink before any byte moves.
        // SAFETY: fcntl on live stdio pipe fds. Note the odd
        // convention: success returns the new capacity (not 0).
        for fd in [1, 2] {
            if unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, size as libc::c_int) } < 0 {
                eprintln!("launch-fixture: cannot shrink pipe {fd}");
                std::process::exit(3);
            }
        }
        // Self-verification: report the actual capacities so the
        // oracle can prove the backpressure existed (no vacuous
        // green from an unshrunk pipe).
        if let Some(report) = sidecar.get("pipe_report").and_then(|v| resolve(&dir, v)) {
            let mut text = String::new();
            for fd in [1, 2] {
                // SAFETY: fcntl read on live stdio pipe fds.
                let got = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
                if got < 0 {
                    eprintln!("launch-fixture: cannot read pipe {fd} size");
                    std::process::exit(3);
                }
                text.push_str(&format!("{got}\n"));
            }
            std::fs::write(&report, text).unwrap_or_else(|_| std::process::exit(3));
        }
    }
    let code = if argv.iter().any(|arg| arg == "--attest") {
        run_attest(&sidecar)
    } else {
        run_serve(&dir, &argv, &sidecar)
    };
    std::process::exit(code);
}

/// Attest path: garbage line, silent exit, or the honest boundary.
fn run_attest(sidecar: &serde_json::Value) -> i32 {
    let exit = sidecar
        .get("attest_exit")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0) as i32;
    if let Some(garbage) = sidecar.get("attest_garbage").and_then(|v| v.as_str()) {
        println!("{garbage}");
        return exit;
    }
    if sidecar.get("attest_exit").is_some() {
        return exit;
    }
    let mut attestation = collect().unwrap_or_else(|| std::process::exit(3));
    if let Some(uid) = sidecar.get("forge_uid").and_then(|v| v.as_u64()) {
        attestation.uid = uid as u32;
    }
    if let Some(euid) = sidecar.get("forge_euid").and_then(|v| v.as_u64()) {
        attestation.euid = euid as u32;
    }
    println!("{}", attestation_line(&attestation));
    exit
}

/// Serve path: stdin request in; refusal/crash/stall/retainer or
/// the canned response (session-substituted) plus stderr
/// attestation out.
fn run_serve(dir: &Path, argv: &[String], sidecar: &serde_json::Value) -> i32 {
    if let Some(retainer) = sidecar.get("spawn_retainer") {
        // Exited child + pipe-retaining descendant: fork first (the
        // grandchild holds every stdio fd open), record its pid, and
        // exit 0 WITHOUT reading stdin — stdout/stderr never see EOF.
        let sleep_secs = retainer.get("sleep_secs").and_then(|v| v.as_u64());
        let pidfile = retainer.get("pidfile").and_then(|v| resolve(dir, v));
        let (Some(sleep_secs), Some(pidfile)) = (sleep_secs, pidfile) else {
            eprintln!("launch-fixture: spawn_retainer needs sleep_secs + pidfile");
            return 3;
        };
        // SAFETY: fork with no locks held (single-threaded startup).
        let forked = unsafe { libc::fork() };
        if forked < 0 {
            return 3;
        }
        if forked == 0 {
            std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
            std::process::exit(0);
        }
        use std::io::Write;
        let mut pids = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&pidfile)
            .unwrap_or_else(|_| std::process::exit(3));
        writeln!(pids, "{forked}").unwrap_or_else(|_| std::process::exit(3));
        return 0;
    }
    let mut request = String::new();
    std::io::stdin()
        .read_to_string(&mut request)
        .unwrap_or_else(|_| std::process::exit(3));
    if let Some(path) = sidecar.get("argv_log").and_then(|v| resolve(dir, v)) {
        let mut logged = String::new();
        for arg in argv {
            logged.push_str(arg);
            logged.push('\n');
        }
        std::fs::write(&path, logged).unwrap_or_else(|_| std::process::exit(3));
    }
    if let Some(path) = sidecar.get("count").and_then(|v| resolve(dir, v)) {
        use std::io::Write;
        let mut count = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap_or_else(|_| std::process::exit(3));
        count
            .write_all(b"x\n")
            .unwrap_or_else(|_| std::process::exit(3));
    }
    if sidecar
        .get("crash")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        // SAFETY: SIGKILL to self only (never returns).
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        std::process::abort();
    }
    if let Some(secs) = sidecar.get("stall_secs").and_then(|v| v.as_u64()) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
        return 0;
    }
    if let Some(name) = sidecar.get("refuse").and_then(|v| v.as_str()) {
        eprintln!("{{\"error\":\"{name}\"}}");
        return 1;
    }
    if sidecar
        .get("echo_unresolved")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return run_echo_unresolved(&request);
    }
    let canned_path = sidecar.get("canned").and_then(|v| resolve(dir, v));
    let Some(canned_path) = canned_path else {
        eprintln!("launch-fixture: serve needs canned, refuse, crash, stall_secs, or echo");
        return 3;
    };
    let session = serde_json::from_str::<serde_json::Value>(&request)
        .ok()
        .and_then(|parsed| parsed.get("session_id")?.as_str().map(str::to_string));
    let Some(session) = session else {
        eprintln!("launch-fixture: request carries no session_id");
        return 3;
    };
    let placeholder = sidecar
        .get("session_placeholder")
        .and_then(|v| v.as_str())
        .unwrap_or(PLACEHOLDER);
    let canned = std::fs::read_to_string(&canned_path).unwrap_or_else(|_| std::process::exit(3));
    let mut attestation = collect().unwrap_or_else(|| std::process::exit(3));
    if let Some(uid) = sidecar.get("forge_uid").and_then(|v| v.as_u64()) {
        attestation.uid = uid as u32;
    }
    if let Some(euid) = sidecar.get("forge_euid").and_then(|v| v.as_u64()) {
        attestation.euid = euid as u32;
    }
    eprintln!("{}", attestation_line(&attestation));
    print!("{}", canned.replace(placeholder, &session));
    eprintln!("{{\"helper_counters\":{{}}}}");
    0
}

/// Echo every request key back as an unresolved association: the
/// response binds to ANY chunk (session match, keys drawn from the
/// request, single-chunk exact coverage, matching counters).
fn run_echo_unresolved(request: &str) -> i32 {
    let parsed = serde_json::from_str::<serde_json::Value>(request).unwrap_or_else(|_| {
        eprintln!("launch-fixture: request is not JSON");
        std::process::exit(3);
    });
    let session = parsed
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            eprintln!("launch-fixture: request carries no session_id");
            std::process::exit(3);
        });
    let keys = parsed
        .get("keys")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| {
            eprintln!("launch-fixture: request carries no keys");
            std::process::exit(3);
        });
    let scope = keys
        .first()
        .and_then(|key| key.get("kernel_scope"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            eprintln!("launch-fixture: request keys carry no kernel_scope");
            std::process::exit(3);
        });
    let associations: Vec<serde_json::Value> = keys
        .iter()
        .map(|key| {
            serde_json::json!({
                "key": key,
                "identity": {
                    "container": null, "pod": null, "cluster": null,
                    "node": null, "ancestor_container": null,
                },
                "evidence": {
                    "relationship": "hook_context",
                    "method": "unresolved",
                    "source": "unknown",
                    "status": "unresolved",
                },
            })
        })
        .collect();
    let response = serde_json::json!({
        "session_id": session,
        "kernel_identity": {"known": scope},
        "associations": associations,
        "errors": [],
        "status": "complete",
        "chunk": {"index": 0, "total": 1},
        "counters": {
            "resolved": 0,
            "unresolved": associations.len(),
            "refused": 0,
        },
    });
    let attestation = collect().unwrap_or_else(|| std::process::exit(3));
    eprintln!("{}", attestation_line(&attestation));
    print!("{response}");
    0
}
