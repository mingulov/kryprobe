// SPDX-License-Identifier: GPL-3.0-or-later
//! Host capability probe rows: BTF, userns, Yama, caps, gates, fork probe.
//!
//! Micro-borrow: the fork-child hazard probe follows the p11scope
//! `uretprobe_hazard.rs` fork pattern (child does the risky call, parent
//! reads only the exit status; `Unknown` stays `Skipped`, never tiered).

use crate::probe::{ProbeOutcome, cap_names, yama_verdict};

/// Info-only: is vmlinux BTF present on this host?
pub fn btf_present() -> ProbeOutcome {
    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        ProbeOutcome::pass("vmlinux BTF present")
    } else {
        ProbeOutcome::skipped("no vmlinux BTF on this host")
    }
}

fn wait_child(pid: libc::pid_t) -> Option<i32> {
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EINTR {
                continue;
            }
            return None;
        }
        break;
    }
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    }
}

/// Tries `unshare(CLONE_NEWUSER)` in a forked child (never the caller).
pub fn userns_create() -> ProbeOutcome {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return ProbeOutcome::skipped("fork failed for userns probe");
    }
    if pid == 0 {
        let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        if r == 0 {
            unsafe { libc::_exit(0) };
        }
        let e = unsafe { *libc::__errno_location() };
        if e == libc::EPERM || e == libc::EACCES {
            unsafe { libc::_exit(2) };
        }
        unsafe { libc::_exit(3) };
    }
    match wait_child(pid) {
        Some(0) => ProbeOutcome::pass("CLONE_NEWUSER unshare succeeded"),
        Some(2) => ProbeOutcome::denied("userns_create", libc::EPERM),
        Some(_) | None => ProbeOutcome::skipped("userns unshare inconclusive"),
    }
}

/// Reads the Yama ptrace scope and maps it to a verdict string.
pub fn yama_scope() -> ProbeOutcome {
    let text = match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(t) => t,
        Err(_) => return ProbeOutcome::skipped("yama scope unreadable"),
    };
    match text.trim().parse::<u32>() {
        Ok(n) => ProbeOutcome::pass(format!("scope {n}: {}", yama_verdict(n))),
        Err(_) => ProbeOutcome::skipped("yama scope unparseable"),
    }
}

/// Parses CapEff and lists the effective capability names.
pub fn cap_state() -> ProbeOutcome {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return ProbeOutcome::skipped("CapEff unreadable"),
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            match u64::from_str_radix(hex.trim(), 16) {
                Ok(bits) => {
                    let names = cap_names(bits);
                    let list = if names.is_empty() {
                        "none".to_string()
                    } else {
                        names.join(", ")
                    };
                    return ProbeOutcome::pass(format!("CapEff {list}"));
                }
                Err(_) => return ProbeOutcome::skipped("CapEff unparseable"),
            }
        }
    }
    ProbeOutcome::skipped("CapEff missing from status")
}

/// Info-only: does `unprivileged_bpf_disabled` leave a file-caps gate open?
pub fn file_caps_gate() -> ProbeOutcome {
    let text = match std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
        Ok(t) => t,
        Err(_) => return ProbeOutcome::skipped("unprivileged_bpf_disabled unreadable"),
    };
    match text.trim() {
        "0" => ProbeOutcome::pass("unprivileged BPF allowed (0); file caps not required"),
        "1" => ProbeOutcome::pass("unprivileged BPF disabled (1); file caps may grant BPF"),
        "2" => ProbeOutcome::pass("unprivileged BPF fully disabled (2); file caps may grant BPF"),
        other => ProbeOutcome::skipped(format!(
            "unprivileged_bpf_disabled has unknown value '{other}'"
        )),
    }
}

/// Fork-child liveness probe; any hazard signal stays `Skipped`.
pub fn uretprobe_seccomp_fork() -> ProbeOutcome {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return ProbeOutcome::skipped("fork failed for seccomp probe");
    }
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    match wait_child(pid) {
        Some(0) => ProbeOutcome::pass("fork-ok, no hazard signal"),
        _ => ProbeOutcome::skipped("fork child reported a hazard signal"),
    }
}
