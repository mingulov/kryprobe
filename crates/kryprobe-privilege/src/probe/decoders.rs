// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure probe decoders: kernel releases, capability bits, Yama scopes.

/// Parses `maj.min` from a `uname -r` style release string.
pub fn parse_kernel_release(text: &str) -> Option<(u32, u32)> {
    fn leading_num(s: &str) -> Option<u32> {
        s.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()
    }
    let mut parts = text.split('.');
    let major = leading_num(parts.next()?)?;
    let minor = parts.next().and_then(leading_num).unwrap_or(0);
    Some((major, minor))
}

const CAP_TABLE: [&str; 41] = [
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

/// Decodes a capability bitmask into names (unknown high bits ignored).
pub fn cap_names(bits: u64) -> Vec<String> {
    CAP_TABLE
        .iter()
        .enumerate()
        .filter(|(i, _)| bits & (1u64 << i) != 0)
        .map(|(_, n)| n.to_string())
        .collect()
}

/// Maps a Yama scope value to its verdict string.
pub fn yama_verdict(scope: u32) -> &'static str {
    match scope {
        0 => "classic ptrace permissions",
        1 => "restricted: child or explicit declared attach only",
        2 => "admin-only attach",
        3 => "no attach",
        _ => "unknown scope",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::KERNEL_FLOOR;

    #[test]
    fn release_compare_table() {
        let cases = [
            ("7.0.0-x", Some((7, 0)), true),
            ("6.12.32", Some((6, 12)), true),
            ("6.12", Some((6, 12)), true),
            ("6.11.9", Some((6, 11)), false),
            ("5.15.0-generic", Some((5, 15)), false),
            ("6", Some((6, 0)), false),
            ("not-a-release", None, false),
            ("", None, false),
        ];
        for (text, parsed, meets) in cases {
            assert_eq!(parse_kernel_release(text), parsed, "input {text:?}");
            assert_eq!(
                parsed.is_some_and(|v| v >= KERNEL_FLOOR),
                meets,
                "floor {text:?}"
            );
        }
    }

    #[test]
    fn cap_bits_table() {
        assert!(cap_names(0).is_empty());
        assert_eq!(cap_names(1), ["CAP_CHOWN"]);
        // UAPI order (`linux/capability.h` + `capsh --decode`): 11 is
        // BROADCAST (the table used to omit it, shifting 11–39 by one).
        assert_eq!(cap_names(1 << 11), ["CAP_NET_BROADCAST"]);
        assert_eq!(cap_names(1 << 12), ["CAP_NET_ADMIN"]);
        assert_eq!(cap_names(1 << 18), ["CAP_SYS_CHROOT"]);
        assert_eq!(cap_names(1 << 19), ["CAP_SYS_PTRACE"]);
        assert_eq!(cap_names(1 << 36), ["CAP_BLOCK_SUSPEND"]);
        assert_eq!(cap_names(1 << 37), ["CAP_AUDIT_READ"]);
        assert_eq!(cap_names(1 << 38), ["CAP_PERFMON"]);
        assert_eq!(cap_names(1 << 39), ["CAP_BPF"]);
        assert_eq!(cap_names(1 << 40), ["CAP_CHECKPOINT_RESTORE"]);
        assert_eq!(cap_names((1 << 38) | (1 << 39)), ["CAP_PERFMON", "CAP_BPF"]);
        assert!(cap_names(1 << 63).is_empty());
    }

    #[test]
    fn yama_table() {
        assert_eq!(yama_verdict(0), "classic ptrace permissions");
        assert_eq!(
            yama_verdict(1),
            "restricted: child or explicit declared attach only"
        );
        assert_eq!(yama_verdict(2), "admin-only attach");
        assert_eq!(yama_verdict(3), "no attach");
        assert_eq!(yama_verdict(9), "unknown scope");
    }
}
