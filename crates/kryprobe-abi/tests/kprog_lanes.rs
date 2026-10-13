// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Task 06: per-program lane pins (ADR-0013).
//!
//! The 9 fexit programs own disjoint lanes in the formerly shared
//! per-CPU slots (`KTOT`, `KCTLCOUNT`, `KDROPS`, `KCTX_DROPS`,
//! `KATTRLOSS`), which restores exactness without BPF atomic RMW: the
//! trampoline guard serializes each program against itself per CPU,
//! and distinct programs touch disjoint slots. Ordinals follow BPF
//! declaration order; the BPF twin + `max_entries` expressions are
//! pinned below (twin direction per `kcrypto_agg.rs` module docs:
//! duplication + backstops, since the BPF crate is GPL-2.0-only and
//! cannot link this GPL-3.0 crate).

use kryprobe_abi::kcrypto_agg::{
    KATTRLOSS_SLOTS, KDROPS_SITES_PER_PROG, KDROPS_SLOTS, KPROG_AEADDEC, KPROG_AEADENC,
    KPROG_AHASH, KPROG_ALLOC, KPROG_DESTROY, KPROG_FINUP, KPROG_SHASH, KPROG_SKDEC, KPROG_SKENC,
    KTOT_SLOTS, N_KPROGS,
};
use kryprobe_abi::kcrypto_ctx::{KCTLCOUNT_SLOTS, KCTX_DROPS_SLOTS};

#[test]
fn program_ordinals_pinned_in_declaration_order() {
    assert_eq!(KPROG_ALLOC, 0);
    assert_eq!(KPROG_DESTROY, 1);
    assert_eq!(KPROG_SKENC, 2);
    assert_eq!(KPROG_SKDEC, 3);
    assert_eq!(KPROG_AEADENC, 4);
    assert_eq!(KPROG_AEADDEC, 5);
    assert_eq!(KPROG_AHASH, 6);
    assert_eq!(KPROG_SHASH, 7);
    assert_eq!(KPROG_FINUP, 8);
    assert_eq!(N_KPROGS, 9);
}

#[test]
fn per_program_slot_counts_pinned() {
    assert_eq!(KTOT_SLOTS, N_KPROGS);
    assert_eq!(KCTLCOUNT_SLOTS, N_KPROGS);
    assert_eq!(KCTX_DROPS_SLOTS, N_KPROGS);
    assert_eq!(KATTRLOSS_SLOTS, N_KPROGS);
    assert_eq!(KDROPS_SITES_PER_PROG, 8);
    assert_eq!(KDROPS_SLOTS, N_KPROGS * KDROPS_SITES_PER_PROG);
    assert_eq!(KDROPS_SLOTS, 72);
}

/// BPF twin backstop: the sensor source must declare the same
/// ordinals, count, and `max_entries` expressions (else the twin
/// drifted from this contract).
#[test]
fn bpf_twin_matches_abi_consts() {
    let src = include_str!("../../bpf-kcrypto/src/bin/kcrypto.rs");
    for (name, val) in [
        ("KPROG_ALLOC", 0),
        ("KPROG_DESTROY", 1),
        ("KPROG_SKENC", 2),
        ("KPROG_SKDEC", 3),
        ("KPROG_AEADENC", 4),
        ("KPROG_AEADDEC", 5),
        ("KPROG_AHASH", 6),
        ("KPROG_SHASH", 7),
        ("KPROG_FINUP", 8),
        ("N_KPROGS", 9),
    ] {
        let decl = format!("const {name}: u32 = {val};");
        assert!(src.contains(&decl), "BPF twin missing `{decl}`");
    }
    assert!(
        src.contains(
            "static KTOT: PerCpuArray<VAgg> = PerCpuArray::with_max_entries(N_KPROGS, 0);"
        ),
        "KTOT must size by N_KPROGS"
    );
    assert!(
        src.contains(
            "static KCTLCOUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(N_KPROGS, 0);"
        ),
        "KCTLCOUNT must size by N_KPROGS"
    );
    assert!(
        src.contains(
            "static KCTX_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(N_KPROGS, 0);"
        ),
        "KCTX_DROPS must size by N_KPROGS"
    );
    assert!(
        src.contains(
            "static KATTRLOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(N_KPROGS, 0);"
        ),
        "KATTRLOSS must size by N_KPROGS"
    );
    assert!(
        src.contains(
            "static KDROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(N_KPROGS * 8, 0);"
        ),
        "KDROPS must size by N_KPROGS * 8"
    );
}
