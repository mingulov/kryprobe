// SPDX-License-Identifier: GPL-3.0-or-later
//! Privilege detection for artifact trust (H-SEC-01).
//!
//! Env/CWD-steered artifact tiers (BPF objects, helper binaries) are
//! refused when the process is elevated: euid 0, or effective
//! `CAP_BPF`/`CAP_SYS_ADMIN` (file-cap deployment). [`elevated_with`]
//! is the pure predicate (unit-tested); [`process_is_elevated`] reads
//! live state.

/// Linux capability numbers (kernel UAPI, stable).
const CAP_SYS_ADMIN: u32 = 21;
const CAP_BPF: u32 = 39;

/// Whether these credentials can load BPF outside ambient authority.
fn has_elevating_caps(capeff: u64) -> bool {
    capeff & ((1u64 << CAP_BPF) | (1u64 << CAP_SYS_ADMIN)) != 0
}

/// Pure elevation predicate (unit-tested): euid 0, or effective
/// `CAP_BPF`/`CAP_SYS_ADMIN` (file-cap deployment can load BPF).
#[must_use]
pub fn elevated_with(euid: u32, capeff: u64) -> bool {
    euid == 0 || has_elevating_caps(capeff)
}

/// Live elevation check over the current process.
///
/// Fail-open on unreadable/unparseable `/proc/self/status` (the
/// `cmd_token::effective_cap_names` convention): hiding self-status
/// from the process itself already implies deeper compromise, and
/// euid 0 short-circuits before any read.
#[must_use]
pub fn process_is_elevated() -> bool {
    // SAFETY: trivial getter.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:")
            && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
        {
            return has_elevating_caps(bits);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::elevated_with;

    #[test]
    fn elevation_truth_table() {
        // Root is elevated regardless of caps.
        assert!(elevated_with(0, 0));
        assert!(elevated_with(0, 0xffff_ffff_ffff_ffff));
        // File-cap steady state: CAP_BPF (39) and/or CAP_SYS_ADMIN (21).
        assert!(elevated_with(1000, 1u64 << 39));
        assert!(elevated_with(1000, 1u64 << 21));
        assert!(elevated_with(1000, (1u64 << 38) | (1u64 << 39)));
        // Anything else is not elevated.
        assert!(!elevated_with(1000, 0));
        assert!(!elevated_with(1000, 1u64 << 12)); // CAP_NET_ADMIN alone
        assert!(!elevated_with(1000, (1u64 << 12) | (1u64 << 38))); // no BPF/admin
    }

    #[test]
    fn self_check_does_not_panic() {
        let _ = super::process_is_elevated();
    }
}
