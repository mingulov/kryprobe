// SPDX-License-Identifier: GPL-3.0-or-later
//! K1 Task 2: frozen kcrypto aggregate-layout pins (userspace side).
//!
//! Every number below is computed BY HAND from the Task-2 brief (struct
//! field lists), not copied from compiler output: a mismatch means the
//! mirror drifted from the spec (or the BPF twin did — the privileged
//! exactness suite is the cross-workspace backstop).

use kryprobe_abi::kcrypto_agg::{
    KAgg, KCTL_GAP, KCTL_GENCHANGE, KCTL_HEALTH, KCTL_IDENT, KCTL_OVERFLOW, KCTX_KTHREAD,
    KCTX_PROC, KCTX_SOFTIRQ, KCTX_UNKNOWN, KConfig, KCtl, KFAM_AEAD, KFAM_AHASH, KFAM_ANY,
    KFAM_SHASH, KFAM_SK, KIDN_DROPS, KOP_ALLOC, KOP_DEC, KOP_DESTROY, KOP_DIGEST, KOP_ENC,
    KOP_FINUP, KRES_ERR, KRES_OK, KRES_QUEUED, KRES_UNOBSERVED, KWHO_DROPS, KWhoKey, VAgg, VParams,
    VWho,
};

#[test]
fn kconfig_size_align_and_offsets_pinned() {
    // 11 x u32 (44B K1 head: the 6 P2/task offsets + pf_kthread + the
    // AEAD/ahash length offsets + shash_base + _pad as 11th word; brief
    // C2 + the K4-fix3 shash resolution) + 7 x u32 K5 offsets + 2 flag
    // bytes + 2 pad bytes = 76B. Append-only: every K1 offset below is
    // unchanged.
    assert_eq!(std::mem::size_of::<KConfig>(), 76);
    assert_eq!(std::mem::align_of::<KConfig>(), 4);
    assert_eq!(std::mem::offset_of!(KConfig, sk_req_base), 0);
    assert_eq!(std::mem::offset_of!(KConfig, async_tfm), 4);
    assert_eq!(std::mem::offset_of!(KConfig, tfm_alg), 8);
    assert_eq!(std::mem::offset_of!(KConfig, alg_name), 12);
    assert_eq!(std::mem::offset_of!(KConfig, alg_drv), 16);
    assert_eq!(std::mem::offset_of!(KConfig, task_flags), 20);
    assert_eq!(std::mem::offset_of!(KConfig, pf_kthread), 24);
    assert_eq!(std::mem::offset_of!(KConfig, aead_cryptlen_off), 28);
    assert_eq!(std::mem::offset_of!(KConfig, ahash_nbytes_off), 32);
    assert_eq!(std::mem::offset_of!(KConfig, shash_base), 36);
    assert_eq!(std::mem::offset_of!(KConfig, _pad), 40);
    assert_eq!(std::mem::offset_of!(KConfig, task_real_parent), 44);
    assert_eq!(std::mem::offset_of!(KConfig, task_tgid), 48);
    assert_eq!(std::mem::offset_of!(KConfig, task_comm), 52);
    assert_eq!(std::mem::offset_of!(KConfig, cra_blocksize), 56);
    assert_eq!(std::mem::offset_of!(KConfig, cra_ivsize), 60);
    assert_eq!(std::mem::offset_of!(KConfig, cra_min_keysize), 64);
    assert_eq!(std::mem::offset_of!(KConfig, cra_max_keysize), 68);
    assert_eq!(std::mem::offset_of!(KConfig, parent_ok), 72);
    assert_eq!(std::mem::offset_of!(KConfig, params_ok), 73);
    assert_eq!(std::mem::offset_of!(KConfig, _pad2), 74);
}

#[test]
fn kagg_size_align_and_offsets_pinned() {
    // 4 head bytes + 16 x u64 + 16 x u64 = 260, packed (align 1): any
    // u64-aligned layout would round to a multiple of 8.
    assert_eq!(std::mem::size_of::<KAgg>(), 260);
    assert_eq!(std::mem::align_of::<KAgg>(), 1);
    assert_eq!(std::mem::offset_of!(KAgg, fam), 0);
    assert_eq!(std::mem::offset_of!(KAgg, op), 1);
    assert_eq!(std::mem::offset_of!(KAgg, res), 2);
    assert_eq!(std::mem::offset_of!(KAgg, ctx), 3);
    assert_eq!(std::mem::offset_of!(KAgg, alg), 4);
    assert_eq!(std::mem::offset_of!(KAgg, drv), 132);
}

#[test]
fn vagg_size_align_and_offsets_pinned() {
    // 7 named scalars + 8 histogram lanes = 15 x u64 = 120. Field order
    // is the brief's verbatim `VAgg { calls, bytes, ok, errors, queued,
    // first_ns, last_ns, lat }` (C8 names the 7th scalar `ok`; the brief
    // literal fixes its position third, with the result counters).
    assert_eq!(std::mem::size_of::<VAgg>(), 120);
    assert_eq!(std::mem::align_of::<VAgg>(), 8);
    assert_eq!(std::mem::offset_of!(VAgg, calls), 0);
    assert_eq!(std::mem::offset_of!(VAgg, bytes), 8);
    assert_eq!(std::mem::offset_of!(VAgg, ok), 16);
    assert_eq!(std::mem::offset_of!(VAgg, errors), 24);
    assert_eq!(std::mem::offset_of!(VAgg, queued), 32);
    assert_eq!(std::mem::offset_of!(VAgg, first_ns), 40);
    assert_eq!(std::mem::offset_of!(VAgg, last_ns), 48);
    assert_eq!(std::mem::offset_of!(VAgg, lat), 56);
}

#[test]
fn kctl_size_align_and_offsets_pinned() {
    // kind u8 + 3 pad + 5 x u64 = 48.
    assert_eq!(std::mem::size_of::<KCtl>(), 48);
    assert_eq!(std::mem::align_of::<KCtl>(), 8);
    assert_eq!(std::mem::offset_of!(KCtl, kind), 0);
    assert_eq!(std::mem::offset_of!(KCtl, key_hash), 8);
    assert_eq!(std::mem::offset_of!(KCtl, val0), 16);
    assert_eq!(std::mem::offset_of!(KCtl, val1), 24);
    assert_eq!(std::mem::offset_of!(KCtl, val2), 32);
    assert_eq!(std::mem::offset_of!(KCtl, val3), 40);
}

#[test]
fn k5_who_mirror_sizes() {
    assert_eq!(std::mem::size_of::<KWhoKey>(), 16);
    assert_eq!(std::mem::size_of::<VWho>(), 80);
    assert_eq!(std::mem::offset_of!(VWho, cgroup), 24);
    assert_eq!(std::mem::offset_of!(VWho, stack), 52);
    // Full hand-computed layout (brief verbatim field order):
    // comm[16] @0, tid @16, uid @20, cgroup @24, ppid @32, pcomm[16]
    // @36, stack @52, calls @56, first_ns @64, last_ns @72.
    assert_eq!(std::mem::align_of::<KWhoKey>(), 8);
    assert_eq!(std::mem::align_of::<VWho>(), 8);
    assert_eq!(std::mem::offset_of!(KWhoKey, kh), 0);
    assert_eq!(std::mem::offset_of!(KWhoKey, tgid), 8);
    assert_eq!(std::mem::offset_of!(KWhoKey, _pad), 12);
    assert_eq!(std::mem::offset_of!(VWho, comm), 0);
    assert_eq!(std::mem::offset_of!(VWho, tid), 16);
    assert_eq!(std::mem::offset_of!(VWho, uid), 20);
    assert_eq!(std::mem::offset_of!(VWho, ppid), 32);
    assert_eq!(std::mem::offset_of!(VWho, pcomm), 36);
    assert_eq!(std::mem::offset_of!(VWho, calls), 56);
    assert_eq!(std::mem::offset_of!(VWho, first_ns), 64);
    assert_eq!(std::mem::offset_of!(VWho, last_ns), 72);
}

#[test]
fn k5_params_mirror_sizes() {
    // 4 x u32, no padding (16B per-kh crypto params).
    assert_eq!(std::mem::size_of::<VParams>(), 16);
    assert_eq!(std::mem::align_of::<VParams>(), 4);
    assert_eq!(std::mem::offset_of!(VParams, blocksize), 0);
    assert_eq!(std::mem::offset_of!(VParams, ivsize), 4);
    assert_eq!(std::mem::offset_of!(VParams, min_keysize), 8);
    assert_eq!(std::mem::offset_of!(VParams, max_keysize), 12);
    // Attribution drops ride their own reserved KIDN key, distinct
    // from the ring-reserve counter.
    assert_eq!(KWHO_DROPS, u64::MAX - 1);
    assert_ne!(KWHO_DROPS, KIDN_DROPS);
}

#[test]
fn kcrypto_enum_values_pinned() {
    // Families: alloc/destroy carry no resolved family (ANY).
    assert_eq!(KFAM_ANY, 0);
    assert_eq!(KFAM_SK, 1);
    assert_eq!(KFAM_AEAD, 2);
    assert_eq!(KFAM_AHASH, 3);
    assert_eq!(KFAM_SHASH, 4);
    // Ops: one per attach point, digest shared by ahash/shash.
    assert_eq!(KOP_ALLOC, 1);
    assert_eq!(KOP_DESTROY, 2);
    assert_eq!(KOP_ENC, 3);
    assert_eq!(KOP_DEC, 4);
    assert_eq!(KOP_DIGEST, 5);
    assert_eq!(KOP_FINUP, 6);
    // RES per C7: the fexit sensor classifies every int-returning call;
    // void-return destroy lands in UNOBSERVED (alloc via ERR_PTR).
    assert_eq!(KRES_OK, 0);
    assert_eq!(KRES_ERR, 1);
    assert_eq!(KRES_QUEUED, 2);
    assert_eq!(KRES_UNOBSERVED, 3);
    // CTX order per C7: process, kthread, softirq, unknown. The BPF
    // never writes SOFTIRQ (no stable detector — honest zero, pinned by
    // the privileged suite); UNKNOWN covers a failed task read.
    assert_eq!(KCTX_PROC, 0);
    assert_eq!(KCTX_KTHREAD, 1);
    assert_eq!(KCTX_SOFTIRQ, 2);
    assert_eq!(KCTX_UNKNOWN, 3);
    // Ring kinds per C6: the BPF emits IDENT + OVERFLOW only; the rest
    // are reserved (zero-pinned by the privileged suite).
    assert_eq!(KCTL_IDENT, 1);
    assert_eq!(KCTL_GENCHANGE, 2);
    assert_eq!(KCTL_GAP, 3);
    assert_eq!(KCTL_OVERFLOW, 4);
    assert_eq!(KCTL_HEALTH, 5);
    // Reserved KIDN key: ring-reserve-failure counter.
    assert_eq!(KIDN_DROPS, u64::MAX);
}
