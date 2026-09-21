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
/// Fail-CLOSED on unreadable/unparseable `/proc/self/status` (G10:
/// fail-open let a mount-namespace without `/proc` convince a file-cap
/// process it was unprivileged, re-enabling env/CWD artifact tiers —
/// no compromise needed, just `unshare -m`). euid 0 short-circuits
/// before any read. [`elevated_with_status`] is the pure form for tests.
#[must_use]
pub fn process_is_elevated() -> bool {
    // SAFETY: trivial getter.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return true;
    }
    elevated_with_status(
        euid,
        &std::fs::read_to_string("/proc/self/status").unwrap_or_default(),
    )
}

/// Pure elevation check over an euid + status text (unit-tested):
/// euid 0 is elevated; otherwise a parseable `CapEff` decides, and a
/// missing/unparseable `CapEff` line fails closed (elevated).
#[must_use]
pub fn elevated_with_status(euid: u32, status: &str) -> bool {
    if euid == 0 {
        return true;
    }
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:")
            && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
        {
            return has_elevating_caps(bits);
        }
    }
    true
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

    #[test]
    fn status_parse_fails_closed() {
        use super::elevated_with_status;
        // Parseable CapEff decides.
        assert!(elevated_with_status(
            1000,
            "Name:\tx\nCapEff:\t0000008000000000\n"
        ));
        assert!(!elevated_with_status(
            1000,
            "Name:\tx\nCapEff:\t0000000000000000\n"
        ));
        // Missing/unparseable CapEff fails closed (G10 mount-ns bypass).
        assert!(elevated_with_status(1000, ""));
        assert!(elevated_with_status(1000, "Name:\tx\n"));
        assert!(elevated_with_status(1000, "CapEff:\tnot-hex\n"));
        // Root is elevated regardless of status text.
        assert!(elevated_with_status(0, ""));
    }
}
