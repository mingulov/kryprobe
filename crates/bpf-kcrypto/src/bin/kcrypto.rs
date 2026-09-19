// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF kcrypto sensor skeleton (K1 Task 1): the five Task-2 maps
//! at their frozen dims plus one no-op fentry program.
//!
//! Task 2 replaces the no-op with the 9 real fentry programs; the maps
//! below are already the exact Task-2 contract (the raw loader asserts
//! `KCRYPTO_MAPS` against them). The program body intentionally touches
//! nothing: with zero call relocs the R4 strip drops `.text` entirely,
//! and the loader proves the fentry load+attach path through this shape.
//!
//! Layout constraints inherited by Task 2 (see the asserts below):
//! `KAggSkel` is 260 bytes only as `packed` (any `u64`-aligned struct
//! rounds to a multiple of 8); `VAggSkel` carries one reserved `u64` to
//! reach the planned 120 bytes — Task 2 names the 7th counter.

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, map},
    maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::FEntryContext,
};

/// `KCFG` value: the 6 loader-resolved offsets + kthread flag + pad.
#[repr(C)]
pub struct KConfigSkel {
    pub sk_req_base: u32,
    pub async_tfm: u32,
    pub tfm_alg: u32,
    pub alg_name: u32,
    pub alg_drv: u32,
    pub task_flags: u32,
    pub pf_kthread: u32,
    pub _pad: u32,
}

/// `KAGG` key: context + algorithm identity (128B + 128B names).
/// `packed`: 4 + 256 = 260 bytes admits no alignment padding.
#[repr(C, packed)]
pub struct KAggSkel {
    pub fam: u8,
    pub op: u8,
    pub res: u8,
    pub ctx: u8,
    pub alg: [u64; 16],
    pub drv: [u64; 16],
}

/// Aggregate counters + latency histogram. The 7th counter is reserved:
/// the plan pins 120 bytes (7 + 8 `u64`) while naming 6 + `lat` — Task 2
/// names `_rsv` (the natural 7th is `ok`, beside `errors`/`queued`).
#[repr(C)]
pub struct VAggSkel {
    pub calls: u64,
    pub bytes: u64,
    pub errors: u64,
    pub queued: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    pub _rsv: u64,
    pub lat: [u64; 8],
}

const _: () = assert!(size_of::<KConfigSkel>() == 32);
const _: () = assert!(size_of::<KAggSkel>() == 260);
const _: () = assert!(size_of::<VAggSkel>() == 120);

#[map]
static KCFG: Array<KConfigSkel> = Array::with_max_entries(1, 0);
#[map]
static KAGG: PerCpuHashMap<KAggSkel, VAggSkel> = PerCpuHashMap::with_max_entries(256, 0);
#[map]
static KTOT: PerCpuArray<VAggSkel> = PerCpuArray::with_max_entries(1, 0);
#[map]
static KIDN: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);
#[map]
static KRING: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Skeleton probe: attaches anywhere (reads no context), observes
/// nothing. The section suffix is a placeholder: the privileged lane
/// loads these same bytes once per attach point with that point's
/// `attach_btf_id` (the value binds, not the section name).
#[fentry(function = "crypto_alloc_tfm_node")]
pub fn kcrypto_skel(_ctx: FEntryContext) -> i32 {
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Dead code: the crate is audited panic-free (no panic!/unwrap/
    // expect/runtime-assert, no div/mod, no indexing). Keep it that way:
    // if a panic path is ever introduced, the `unreachable_unchecked`
    // below is live UB.
    unsafe { core::hint::unreachable_unchecked() }
}

/// Kernel license marker: this object is GPL-2.0-only BPF.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";
