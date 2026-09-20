// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime facts (1B-M8): host identity for session gates and renders.
//!
//! One home for the `/proc` reads, the CapEff decode, the BPF
//! bring-up predicates, and the composed [`live_runtime`] (gate bools
//! from the committed privilege probes, context from direct reads).
//! std-only; the probes themselves live behind the privilege boundary.

use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_privilege::probe::{
    ProbeOutcome, attach_cookies, btf_present, ringbuf_create, uprobe_multi_link_self,
    userns_create,
};

/// Capability names by number, 0–40, VERIFIED against
/// `/usr/include/linux/capability.h` + `capsh --decode` on this host
/// (bit 11 = `NET_BROADCAST`, 21 = `SYS_ADMIN`, 38 = `PERFMON`,
/// 39 = `BPF`, 40 = `CHECKPOINT_RESTORE`).
///
/// This deliberately does NOT reuse
/// [`kryprobe_privilege::probe::cap_names`]: that table used to omit
/// `CAP_NET_BROADCAST`, shifting every name from index 11 on by one
/// (fixed by the K5 wave — the shared table now decodes the same
/// verified order; dedup of the two tables is parked as
/// non-load-bearing, so this surface keeps its own copy).
const CAP_NAMES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// Lowercase capability name for the `status` csv (`cap_bpf` style,
/// matching the mint receipt); numbers past the table render `cap_<n>`
/// so nothing decodes silently blank.
#[must_use]
pub fn cap_display_name(cap: u32) -> String {
    CAP_NAMES
        .get(cap as usize)
        .map(|name| name.to_lowercase())
        .unwrap_or_else(|| format!("cap_{cap}"))
}

/// Uppercase names for a bitmask (the `cap_names` shape, verified
/// order; unknown high bits ignored — the shared-table precedent).
fn cap_names_verified(bits: u64) -> Vec<String> {
    CAP_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| bits & (1u64 << i) != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect()
}

/// Kernel release context (`/proc` read; `unknown` when unreadable —
/// receipt metadata and session context only, never a gate). One copy
/// (1B-M8): the watch and token modules shared this verbatim.
pub fn os_release() -> String {
    let text = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    if text.is_empty() {
        String::from("unknown")
    } else {
        text
    }
}

/// Yama scope context (informational only, never a gate; 0 when
/// unreadable — mirrors the fail-soft context reads).
fn yama_scope() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Effective capability names from CapEff (fail-closed: unreadable or
/// unparseable reads as no caps, never as privileged; verified order —
/// see [`CAP_NAMES`]).
#[must_use]
pub fn effective_cap_names() -> Vec<String> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:")
            && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
        {
            return cap_names_verified(bits);
        }
    }
    Vec::new()
}

/// Ruling-literal delegation predicate: effective `CAP_BPF` (the
/// doctor `token_delegated` pass condition — file caps granted by
/// `token mint` always include it).
#[must_use]
pub fn caps_have_bpf(caps: &[String]) -> bool {
    caps.iter().any(|cap| cap == "CAP_BPF")
}

/// Bring-up predicate: `CAP_BPF` or `CAP_SYS_ADMIN` (either loads BPF;
/// the live pre-flight must not refuse a process that can load).
#[must_use]
pub fn caps_allow_bpf_bringup(caps: &[String]) -> bool {
    caps.iter()
        .any(|cap| cap == "CAP_BPF" || cap == "CAP_SYS_ADMIN")
}

/// Bring-up predicate over the live process.
#[must_use]
pub fn process_has_bpf_caps() -> bool {
    caps_allow_bpf_bringup(&effective_cap_names())
}

/// Live host facts for the session gate: gate bools from the committed
/// privilege probes (`Pass` ⟺ present — probe details are human verdicts,
/// never parsed back), context from direct `/proc` reads. std-only
/// (ADR-0002 Rule B: no `libc::` in the CLI crate).
pub fn live_runtime() -> RuntimeCapabilities {
    let pass = |outcome: ProbeOutcome| matches!(outcome, ProbeOutcome::Pass { .. });
    RuntimeCapabilities {
        kernel_release: os_release(),
        uprobe_multi: pass(uprobe_multi_link_self()),
        cookies: pass(attach_cookies()),
        ringbuf: pass(ringbuf_create()),
        btf_present: pass(btf_present()),
        userns: pass(userns_create()),
        yama_scope: yama_scope(),
        caps: effective_cap_names(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_runtime_reports_without_privilege() {
        // Shape smoke (moved with the facts, 1B-M8): always runs,
        // release never empty.
        let runtime = live_runtime();
        assert!(!runtime.kernel_release.is_empty());
    }

    #[test]
    fn bringup_predicates_read_caps() {
        // `CAP_BPF` or `CAP_SYS_ADMIN` loads BPF; anything else refuses.
        let bpf = vec!["CAP_BPF".to_owned()];
        let admin = vec!["CAP_SYS_ADMIN".to_owned()];
        let none: Vec<String> = vec!["CAP_NET_RAW".to_owned()];
        assert!(caps_have_bpf(&bpf));
        assert!(!caps_have_bpf(&admin));
        assert!(caps_allow_bpf_bringup(&bpf));
        assert!(caps_allow_bpf_bringup(&admin));
        assert!(!caps_allow_bpf_bringup(&none));
        assert!(!caps_allow_bpf_bringup(&[]));
    }

    #[test]
    fn display_name_matches_verified_table() {
        // Lowercase csv spelling; past-the-table renders `cap_<n>`.
        assert_eq!(cap_display_name(39), "cap_bpf");
        assert_eq!(cap_display_name(11), "cap_net_broadcast");
        assert_eq!(cap_display_name(99), "cap_99");
    }
}
