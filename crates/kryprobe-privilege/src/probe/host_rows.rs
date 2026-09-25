// SPDX-License-Identifier: GPL-3.0-or-later
//! Host capability probe rows: BTF, userns, Yama, caps, gates, fork probe.
//!
//! Micro-borrow: the fork-child hazard probe follows the p11scope
//! `uretprobe_hazard.rs` fork pattern (child does the risky call, parent
//! reads only the exit status; `Unknown` stays `Skipped`, never tiered).

use crate::btf_resolve::{resolve_kfunc_ids, resolve_lifecycle_ids};
use crate::probe::ProbeOutcome;
use crate::probe::bpf_prog::load_minimal_fsession;
use crate::probe::{cap_names, yama_verdict};

/// Gate: can this kernel run the lifecycle session sensor (T06 W8)?
/// Pass requires a minimal `TRACING` load with
/// `expected_attach_type = 58` against our real attach target
/// (ratification C: the kfunc filter gates on the attach type, so a
/// plain fentry probe would `-EACCES` and misreport) — the load is
/// the floor discriminator (guest-proven: the session kfuncs exist
/// even on 6.12, so their BTF presence only gates the cheap
/// unprivileged pre-check, never the verdict). Missing kfuncs fail
/// with the cause named; a permission refusal on the load reports
/// `Denied` (capability unproven, not absent — see `cap_state`); any
/// other load errno fails loud.
pub fn fsession_capable() -> ProbeOutcome {
    match resolve_kfunc_ids() {
        Ok(ids) if ids.len() != 2 => {
            return ProbeOutcome::failed(format!(
                "session kfuncs incomplete ({} of 2 resolved; kernel 7.0+ required)",
                ids.len()
            ));
        }
        Err(err) => {
            return ProbeOutcome::failed(format!(
                "session kfuncs absent ({err}; kcrypto lifecycle needs kernel 7.0+)"
            ));
        }
        Ok(_) => {}
    }
    let target = resolve_lifecycle_ids()
        .ok()
        .and_then(|ids| ids.get("crypto_skcipher_encrypt").copied());
    let Some(target) = target else {
        return ProbeOutcome::pass(
            "session kfuncs present (load check skipped: no kcrypto attach target)",
        );
    };
    match load_minimal_fsession(target) {
        Ok(_) => ProbeOutcome::pass("session kfuncs present; fsession loads with attach type 58"),
        Err(errno) if errno == libc::EPERM || errno == libc::EACCES => {
            ProbeOutcome::denied("fsession_load (session kfuncs present)", errno)
        }
        Err(errno) => ProbeOutcome::failed(format!(
            "attach type 58 refused (errno {errno}) despite session kfuncs"
        )),
    }
}

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
