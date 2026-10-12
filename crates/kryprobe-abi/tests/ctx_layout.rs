// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Task 01: frozen ctx-v1 layout pins (ADR-0008 §§(a)–(c),(f)).
//!
//! Every number below is computed BY HAND from ADR-0008, not copied
//! from compiler output: a mismatch means the mirror drifted from the
//! contract (the Task-02 BPF twin + privileged exactness suite join as
//! the cross-workspace backstop when the BPF side lands).

use kryprobe_abi::kcrypto_ctx::{
    KCTL_CTX_OVERFLOW, KCTLCLOSED_CLOSED, KCTLCLOSED_OPEN, KCTLCOUNT_SLOTS, KCTX_DROPS_SLOTS,
    KCTX_MAX_ENTRIES, KCTXOVF_MAX_ENTRIES, KCtxKey, VCtx, kctx_entry_bytes, kctx_map_bytes,
};

#[test]
fn kctx_key_size_align_and_offsets_pinned() {
    // u64 kh @0, u64 cgroup @8, u32 tgid @16, u32 uid @20,
    // u64 start_ns @24: 32B, align 8, zero padding.
    assert_eq!(std::mem::size_of::<KCtxKey>(), 32);
    assert_eq!(std::mem::align_of::<KCtxKey>(), 8);
    assert_eq!(std::mem::offset_of!(KCtxKey, kh), 0);
    assert_eq!(std::mem::offset_of!(KCtxKey, cgroup), 8);
    assert_eq!(std::mem::offset_of!(KCtxKey, tgid), 16);
    assert_eq!(std::mem::offset_of!(KCtxKey, uid), 20);
    assert_eq!(std::mem::offset_of!(KCtxKey, start_ns), 24);
}

#[test]
fn vctx_size_align_and_offsets_pinned() {
    // 7 x u64 = 56B, align 8 (no lat histogram by design).
    assert_eq!(std::mem::size_of::<VCtx>(), 56);
    assert_eq!(std::mem::align_of::<VCtx>(), 8);
    assert_eq!(std::mem::offset_of!(VCtx, calls), 0);
    assert_eq!(std::mem::offset_of!(VCtx, bytes), 8);
    assert_eq!(std::mem::offset_of!(VCtx, ok), 16);
    assert_eq!(std::mem::offset_of!(VCtx, errors), 24);
    assert_eq!(std::mem::offset_of!(VCtx, queued), 32);
    assert_eq!(std::mem::offset_of!(VCtx, first_ns), 40);
    assert_eq!(std::mem::offset_of!(VCtx, last_ns), 48);
}

#[test]
fn capacity_fence_and_overflow_consts_pinned() {
    assert_eq!(KCTX_MAX_ENTRIES, 1024);
    assert_eq!(KCTX_DROPS_SLOTS, 9);
    // New ring kind value; the 48-byte KCtl layout is unchanged.
    assert_eq!(KCTL_CTX_OVERFLOW, 6);
    // Fence control (ADR-0009): closed flag + per-CPU count + gate.
    assert_eq!(KCTLCLOSED_OPEN, 0);
    assert_eq!(KCTLCLOSED_CLOSED, 1);
    assert_eq!(KCTLCOUNT_SLOTS, 9);
    assert_eq!(KCTXOVF_MAX_ENTRIES, 256);
}

#[test]
fn per_cpu_arithmetic_endpoints_pinned() {
    // ADR-0008 §(b) table, recomputed here from the const fns.
    assert_eq!(kctx_entry_bytes(1), 88);
    assert_eq!(kctx_map_bytes(1), 90_112);
    assert_eq!(kctx_entry_bytes(12), 704);
    assert_eq!(kctx_map_bytes(12), 720_896);
    assert_eq!(kctx_entry_bytes(1024), 57_376);
    assert_eq!(kctx_map_bytes(1024), 58_753_024);
    assert_eq!(kctx_entry_bytes(65_536), 3_670_048);
    assert_eq!(kctx_map_bytes(65_536), 3_758_129_152);
}
