// SPDX-License-Identifier: GPL-3.0-or-later
//! K5 Task 3: kcrypto attribution offset resolution (live BTF, unprivileged).
//!
//! `resolve_kcrypto_offsets` reads `/sys/kernel/btf/vmlinux` (world-readable;
//! no caps) and resolves the 7 K5 attribution offsets the BPF parent/params
//! chases need. Fail-soft by contract: unresolvable members yield `*_ok=false`
//! + zeros, never `Err` (hard `Err` only when BTF itself is unreadable).
//!
//! Skips honestly when BTF is absent (the `kcrypto_agg` idiom).

use kryprobe_privilege::btf_resolve::resolve_kcrypto_offsets;

/// Live vmlinux BTF must be present for the resolver to run.
fn btf_available() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

#[test]
fn k5_offsets_live_btf() {
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let off = resolve_kcrypto_offsets().expect("live BTF resolves");
    assert!(off.task_tgid > 0 && off.task_tgid < 8192);
    if off.parent_ok {
        assert!(off.task_real_parent > 0);
    }
}

#[test]
fn k5_offsets_fail_soft_invariant() {
    // Kernel-independent: a disabled group carries all-zero offsets (the
    // BPF gates its chases on the flags, so a false flag must never pair
    // with a nonzero offset the BPF would trust if misread).
    if !btf_available() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let off = resolve_kcrypto_offsets().expect("live BTF resolves");
    if !off.parent_ok {
        assert_eq!(off.task_real_parent, 0, "parent off => zero real_parent");
        assert_eq!(off.task_tgid, 0, "parent off => zero tgid");
        assert_eq!(off.task_comm, 0, "parent off => zero comm");
    }
    if !off.params_ok {
        assert_eq!(off.cra_blocksize, 0, "params off => zero blocksize");
        assert_eq!(off.cra_ivsize, 0, "params off => zero ivsize");
        assert_eq!(off.cra_min_keysize, 0, "params off => zero min_keysize");
        assert_eq!(off.cra_max_keysize, 0, "params off => zero max_keysize");
    }
}
