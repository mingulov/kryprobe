// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF spine: entry/return uprobe-multi self-test programs.
//!
//! Cookie layout: `(generation << 32) | offset_index`. Programs drop (and
//! account) disarmed runs, stale generations, out-of-range indices, and
//! TGID mismatches; otherwise they bump `COUNT[idx]` and emit one
//! [`SpineEvent`] per hit. Only aya-ebpf map/program types plus
//! kryprobe-abi layouts are used here (no BPF-side loader logic).
//!
//! Micro-borrows: cookie-as-plan-index + in-BPF TGID guard (osslscope
//! `count.rs` pattern, reimplemented).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_attach_cookie, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, uprobe, uretprobe},
    maps::{Array, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    EbpfContext,
};
use kryprobe_abi::SpineEvent;

/// `COUNT` slots (offset_index 0..64); frozen, asserted by the loader.
const COUNT_ENTRIES: u32 = 64;
/// `LOSS` slot: ringbuf reservation failures.
const LOSS_RING: u32 = 0;
/// `LOSS` slot: disarmed / stale generation / bad index / TGID-guard drops.
const LOSS_DROP: u32 = 1;
/// `SpineEvent.flags` bit marking return-probe records.
const FLAG_RETURN: u32 = 1;

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(2, 0);
#[map]
static START: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(COUNT_ENTRIES, 0);
#[map]
static LOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

/// Frozen wire + map dims (the raw loader re-asserts `SPINE_MAPS`).
const _: () = assert!(size_of::<SpineEvent>() == 64);
const _: () = assert!(align_of::<SpineEvent>() == 8);

/// Wrapping per-CPU increment; returns the post-increment value as `seq`.
fn bump(map: &PerCpuArray<u64>, idx: u32) -> u64 {
    if let Some(ptr) = map.get_ptr_mut(idx) {
        // SAFETY: per-CPU pointer is valid for this CPU for this statement.
        unsafe {
            *ptr = (*ptr).wrapping_add(1);
            *ptr
        }
    } else {
        0
    }
}

fn emit(ctx: *mut core::ffi::c_void, is_return: bool) -> u32 {
    if START.get(0).copied().unwrap_or(0) == 0 {
        // Hit before arming: a real anomaly, accounted, never silent.
        bump(&LOSS, LOSS_DROP);
        return 0;
    }
    // SAFETY: BPF helpers with the program ctx pointer.
    let cookie = unsafe { bpf_get_attach_cookie(ctx) };
    let gen = (cookie >> 32) as u32;
    let idx = cookie as u32;
    if gen != CONFIG.get(0).copied().unwrap_or(0) as u32 || idx >= COUNT_ENTRIES {
        bump(&LOSS, LOSS_DROP);
        return 0;
    }
    let want_tgid = CONFIG.get(1).copied().unwrap_or(0) as u32;
    let id = bpf_get_current_pid_tgid();
    let tgid = (id >> 32) as u32;
    // Fail closed: no TGID pinned (want == 0) matches nothing, since
    // no real process has TGID 0. Callers always pin the target.
    if tgid != want_tgid {
        bump(&LOSS, LOSS_DROP);
        return 0;
    }
    let seq = bump(&COUNT, idx);
    let Some(mut entry) = EVENTS.reserve::<SpineEvent>(0) else {
        bump(&LOSS, LOSS_RING);
        return 0;
    };
    // Slot init through the entry deref: `MaybeUninit::write` takes the
    // event by value, and the 28-byte zero tail of that aggregate copy
    // fuses into a `memset` call (as does any repeat/loop/literal zero
    // chain). The call pulls the whole compiler_builtins mem blob into
    // `.text`; the uncalled siblings are unreachable and the kernel
    // verifier rejects the program. Volatile stores are preserved
    // exactly, so no builtin call can form.
    let slot: &mut core::mem::MaybeUninit<SpineEvent> = &mut entry;
    let ptr = slot.as_mut_ptr();
    // SAFETY: the slot is exclusively ours until `submit`, and every
    // field is written before the entry is committed.
    unsafe {
        core::ptr::addr_of_mut!((*ptr).cookie).write(cookie);
        core::ptr::addr_of_mut!((*ptr).tgid).write(tgid);
        core::ptr::addr_of_mut!((*ptr).tid).write(id as u32);
        core::ptr::addr_of_mut!((*ptr).monotonic_ns).write(bpf_ktime_get_ns());
        core::ptr::addr_of_mut!((*ptr).seq).write(seq);
        core::ptr::addr_of_mut!((*ptr).flags).write(if is_return { FLAG_RETURN } else { 0 });
        for i in 0..28 {
            core::ptr::addr_of_mut!((*ptr).reserved[i]).write_volatile(0);
        }
    }
    entry.submit(0);
    0
}

/// Entry self-test: one [`SpineEvent`] per hit, `flags == 0`.
#[uprobe(multi)]
pub fn spine_selftest(ctx: ProbeContext) -> u32 {
    emit(ctx.as_ptr(), false)
}

/// Return self-test: same record with the return flag set.
#[uretprobe(multi)]
pub fn spine_selftest_ret(ctx: RetProbeContext) -> u32 {
    emit(ctx.as_ptr(), true)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // panic = "abort": unreachable in verified code; aborts the program.
    unsafe { core::hint::unreachable_unchecked() }
}

/// Kernel license marker: this object is GPL-2.0-only BPF.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

