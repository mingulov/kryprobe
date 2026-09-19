// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF kcrypto sensor (K1 Task 2): 9 fexit programs + aggregate
//! maps + control ring.
//!
//! Each program observes one kernel crypto call at function EXIT: it
//! reads the return value (`bpf_get_func_ret`), chases the request/tfm
//! identity with loader-resolved offsets (from `KCFG`, G6 option (a) —
//! aya-ebpf 0.2.1 has no CO-RE), classifies context (`PF_KTHREAD`), and
//! records one observation into the per-CPU aggregates (`KAGG` + `KTOT`,
//! totals always) with first-seen identity events on `KRING` (gated by
//! `KIDN`).
//!
//! Twin: `crates/kryprobe-abi/src/kcrypto_agg.rs` mirrors every struct,
//! enum value, and the identity hash byte-for-byte (deliberate
//! duplication across workspaces; the layout pins + privileged
//! exactness suite fail on drift).
//!
//! Honest limitations (single exit edge only):
//! - `lat` stays 0 (no duration from one edge; C4). `first_ns`/`last_ns`
//!   stamp the first/last SEEN exit edge (C4).
//! - `ctx` is never `SOFTIRQ` (no stable in-BPF softirq detector).
//! - Identity chase failures (null/exotic inputs) skip the observation
//!   entirely (including `KTOT`): `KTOT` counts attributed observations,
//!   so it equals the `KAGG` sum whenever `KAGG` does not overflow.
//!
//! Privacy: the sensor reads pointers (for chasing), `cra_name`,
//! `cra_driver_name`, the requested alloc name, length words, the shash
//! `len` argument, and `task_struct.flags`. It never touches keys, IVs,
//! plaintext, ciphertext, digests, or request buffers (kp2 §9 from the
//! first commit).
//!
//! Build constraints (R4: the xtask strip fails the build on ANY call
//! reloc, so this crate must be call-free):
//! - every helper is `#[inline(always)]` (a failure to inline is a loud
//!   compile error, not a silent call); this includes the return-value
//!   reader (aya's `FExitContext::ret` is NOT `inline(always)`, so the
//!   same logic is re-implemented below rather than trusted to inline);
//! - zeroing uses `volatile` stores (LLVM fuses plain zero chains into
//!   `memset` calls — spine precedent); varying-value stores are plain;
//! - no indexing (raw pointers + bounded `while` loops), no div/mod, no
//!   `panic!`/`unwrap`/`expect`, no `static` data beyond the maps (the
//!   raw loader supports no `.rodata` map), no string literals or const
//!   arrays (only scalar consts, which lower to immediates).
//! - the `KAGG` key keeps the brief's `#[repr(C, packed)]` shape and is
//!   touched through byte pointers only (packed field access would be
//!   unaligned word loads — the exactness suite proves the discipline).

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::{
        bpf_get_current_task, bpf_get_func_ret, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf,
    },
    macros::{fexit, map},
    maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::FExitContext,
};
use core::mem::MaybeUninit;

// ---------------------------------------------------------------------------
// Twinned enum values (mirror: kryprobe-abi/src/kcrypto_agg.rs)
// ---------------------------------------------------------------------------

const KFAM_ANY: u8 = 0;
const KFAM_SK: u8 = 1;
const KFAM_AEAD: u8 = 2;
const KFAM_AHASH: u8 = 3;
const KFAM_SHASH: u8 = 4;

const KOP_ALLOC: u8 = 1;
const KOP_DESTROY: u8 = 2;
const KOP_ENC: u8 = 3;
const KOP_DEC: u8 = 4;
const KOP_DIGEST: u8 = 5;
const KOP_FINUP: u8 = 6;

const KRES_OK: u8 = 0;
const KRES_ERR: u8 = 1;
const KRES_QUEUED: u8 = 2;
const KRES_UNOBSERVED: u8 = 3;

const KCTX_PROC: u8 = 0;
const KCTX_KTHREAD: u8 = 1;
const KCTX_UNKNOWN: u8 = 3;

const KCTL_IDENT: u8 = 1;
const KCTL_OVERFLOW: u8 = 4;

/// Reserved `KIDN` key: ring-reserve-failure counter (saturating `u8`).
const KIDN_DROPS: u64 = u64::MAX;

/// `BPF_NOEXIST` (`enum bpf_map_update_elem_flags`, UAPI `linux/bpf.h`).
const BPF_NOEXIST: u64 = 1;

/// FNV-1a 64 offset basis / prime (twinned hash inputs + order).
const FNV_BASIS: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

/// `EINPROGRESS` / `EBUSY` (UAPI `asm-generic/errno.h`, arch-independent
/// values): the async-queued pair for result classification.
const EINPROGRESS: i32 = 115;
const EBUSY: i32 = 16;

/// `MAX_ERRNO` (UAPI `linux/err.h`): a pointer return `>= -MAX_ERRNO` is
/// an `ERR_PTR`, not a valid `struct crypto_tfm *`.
const MAX_ERRNO: u64 = 4095;

// ---------------------------------------------------------------------------
// Twinned structs (mirror: kryprobe-abi/src/kcrypto_agg.rs)
// ---------------------------------------------------------------------------

/// `KCFG` value: the 8 loader-resolved offsets + kthread flag + pad.
#[repr(C)]
pub struct KConfig {
    pub sk_req_base: u32,
    pub async_tfm: u32,
    pub tfm_alg: u32,
    pub alg_name: u32,
    pub alg_drv: u32,
    pub task_flags: u32,
    pub pf_kthread: u32,
    pub aead_cryptlen_off: u32,
    pub ahash_nbytes_off: u32,
    pub _pad: u32,
}

/// `KAGG` key: attribution head + 128B alg + 128B drv, 260B packed.
///
/// Same shape as the ABI twin (`fam`/`op`/`res`/`ctx` + `[u64; 16]` +
/// `[u64; 16]`); every access below goes through byte pointers, never
/// through (unaligned) fields.
#[repr(C, packed)]
pub struct KAgg {
    pub fam: u8,
    pub op: u8,
    pub res: u8,
    pub ctx: u8,
    pub alg: [u64; 16],
    pub drv: [u64; 16],
}

/// Aggregate counters + latency histogram (120B): `KAGG`/`KTOT` value.
///
/// Field order is the brief's verbatim `VAgg { calls, bytes, ok, errors,
/// queued, first_ns, last_ns, lat }` (C8).
#[repr(C)]
pub struct VAgg {
    pub calls: u64,
    pub bytes: u64,
    pub ok: u64,
    pub errors: u64,
    pub queued: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    pub lat: [u64; 8],
}

/// Ring control event (48B): hash references, never full identity.
#[repr(C)]
pub struct KCtl {
    pub kind: u8,
    pub _p: [u8; 3],
    pub key_hash: u64,
    pub val0: u64,
    pub val1: u64,
    pub val2: u64,
    pub val3: u64,
}

// SAME numbers as the ABI mirrors + loader KCRYPTO_MAPS (duplication
// deliberate + cited: a dims drift must fail here AND at load).
const _: () = assert!(size_of::<KConfig>() == 40);
const _: () = assert!(size_of::<KAgg>() == 260);
const _: () = assert!(size_of::<VAgg>() == 120);
const _: () = assert!(size_of::<KCtl>() == 48);

#[map]
static KCFG: Array<KConfig> = Array::with_max_entries(1, 0);
#[map]
static KAGG: PerCpuHashMap<KAgg, VAgg> = PerCpuHashMap::with_max_entries(256, 0);
#[map]
static KTOT: PerCpuArray<VAgg> = PerCpuArray::with_max_entries(1, 0);
#[map]
static KIDN: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);
#[map]
static KRING: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

// ---------------------------------------------------------------------------
// Helpers (all #[inline(always)]: R4 call-free)
// ---------------------------------------------------------------------------

/// Probe-read one word; faults fold to 0 (callers treat 0 as "skip").
#[inline(always)]
fn read_u64(addr: u64) -> u64 {
    // SAFETY: probe-read faults safely into Err -> 0.
    unsafe { bpf_probe_read_kernel(addr as *const u64) }.unwrap_or(0)
}

/// Probe-read one `u32`; faults fold to 0 (callers treat 0 as "skip",
/// except the context classifier, which fail-opens to `PROC`).
#[inline(always)]
fn read_u32(addr: u64) -> u32 {
    // SAFETY: probe-read faults safely into Err -> 0.
    unsafe { bpf_probe_read_kernel(addr as *const u32) }.unwrap_or(0)
}

/// Probe-read a 128B name (`cra_name`-sized) into `dst` (a 128B stack
/// range). `false` = unreadable source, fail-closed by the caller.
#[inline(always)]
fn read_name(src: u64, dst: *mut u8) -> bool {
    if src == 0 {
        return false;
    }
    // SAFETY: `dst` spans 128 exclusive stack bytes (caller contract).
    let slice = unsafe { core::slice::from_raw_parts_mut(dst, 128) };
    // SAFETY: probe-read faults safely into Err.
    unsafe { bpf_probe_read_kernel_buf(src as *const u8, slice) }.is_ok()
}

/// Read the traced function's return register (`bpf_get_func_ret`,
/// helper 184, Linux 5.17+). `None` = helper refused (fail-closed by the
/// caller: an unclassified observation is skipped, never misbucketed).
///
/// Same logic as aya's `FExitContext::ret` (including the `black_box`
/// spill that breaks the verifier-side scalar link between the helper
/// status and the return value on kernels 5.17–6.7 — aya-ebpf 0.2.1
/// `programs/fexit.rs`, Linux commits d028f87517d6 + 9e314f5d8682),
/// re-implemented `#[inline(always)]` because aya's method is not and R4
/// fails the build on any call reloc.
#[inline(always)]
fn func_ret(ctx: &FExitContext) -> Option<u64> {
    let mut ret_val = 0u64;
    // SAFETY: helper with (ctx, out-pointer); `ret_val` is a live stack slot.
    let err = unsafe { bpf_get_func_ret(ctx.as_ptr(), &raw mut ret_val) };
    let err = core::hint::black_box(err);
    if err == 0 { Some(ret_val) } else { None }
}

/// Classify an `int`-returning crypto call: 0 → ok; `-EINPROGRESS`/
/// `-EBUSY` → queued; other `<0` → errors. Positive returns are
/// unexpected from these entry points and count as ok (non-error).
#[inline(always)]
fn classify_ret(ret: i32) -> u8 {
    if ret == 0 {
        KRES_OK
    } else if ret == -EINPROGRESS || ret == -EBUSY {
        KRES_QUEUED
    } else if ret < 0 {
        KRES_ERR
    } else {
        KRES_OK
    }
}

/// Classify the alloc path: `ERR_PTR` (`IS_ERR_VALUE`, `linux/err.h`) →
/// errors, else ok.
#[inline(always)]
fn classify_alloc_ptr(ret: u64) -> u8 {
    if ret >= 0u64.wrapping_sub(MAX_ERRNO) {
        KRES_ERR
    } else {
        KRES_OK
    }
}

/// Context classifier: `PF_KTHREAD` on current task flags -> kthread,
/// else process; a failed task read -> unknown. The flags read
/// fail-opens to `PROC` (a skipped observation would break call
/// exactness; the current task + flags read cannot realistically fail).
/// `SOFTIRQ` is never returned (no stable detector).
#[inline(always)]
fn classify_ctx(task_flags: u32, pf_kthread: u32) -> u8 {
    // SAFETY: helper with no pointer arguments.
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return KCTX_UNKNOWN;
    }
    let flags = read_u32(task.wrapping_add(task_flags as u64));
    if flags & pf_kthread != 0 {
        KCTX_KTHREAD
    } else {
        KCTX_PROC
    }
}

/// Chase `req -> base -> tfm -> __crt_alg` for request-shaped args.
/// `base_off` is `sk_req_base` for skcipher; AEAD/ahash pass literal 0
/// for `base` (first member — host-BTF-verified: `aead_request.base` @ 0
/// and `ahash_request.base` @ 0 on `/sys/kernel/btf/vmlinux`; C3: the
/// loader asserts 0-ness from live BTF at resolve time and the suite
/// re-verifies). Returns 0 when the chain breaks (skip).
#[inline(always)]
fn chase_req(req: u64, base_off: u32, async_tfm: u32, tfm_alg: u32) -> u64 {
    let base = req.wrapping_add(base_off as u64);
    let tfm = read_u64(base.wrapping_add(async_tfm as u64));
    if tfm == 0 {
        return 0;
    }
    read_u64(tfm.wrapping_add(tfm_alg as u64))
}

/// Chase `tfm -> __crt_alg` for direct-tfm args (destroy `arg1`; shash
/// `tfm` read at `desc` + literal 0 — host-BTF-verified first members
/// (`shash_desc.tfm` @ 0, `crypto_shash.base` @ 0, so the shash tfm
/// pointer IS the `crypto_tfm` numerically — C3, loader-asserted). 0 =
/// skip.
#[inline(always)]
fn chase_tfm(tfm: u64, tfm_alg: u32) -> u64 {
    if tfm == 0 {
        return 0;
    }
    read_u64(tfm.wrapping_add(tfm_alg as u64))
}

/// In-place per-CPU slot update (current CPU's copy, exclusive).
///
/// First-touch stamps `first_ns` when the lane was fresh (`calls == 0`);
/// exactly one of `ok`/`errors`/`queued` increments per classified
/// observation (`UNOBSERVED` increments none — there is no return value
/// to classify); `lat` is never written (stays 0 — C4, no durations from
/// a single edge).
///
/// # Safety
///
/// `slot` must be a live per-CPU map value pointer for this CPU.
#[inline(always)]
unsafe fn update_slot(slot: *mut VAgg, nbytes: u64, now: u64, res: u8) {
    unsafe {
        let calls = core::ptr::addr_of_mut!((*slot).calls);
        let was = *calls;
        *calls = was.saturating_add(1);
        let bytes = core::ptr::addr_of_mut!((*slot).bytes);
        *bytes = (*bytes).saturating_add(nbytes);
        if res == KRES_OK {
            let ok = core::ptr::addr_of_mut!((*slot).ok);
            *ok = (*ok).saturating_add(1);
        } else if res == KRES_ERR {
            let errors = core::ptr::addr_of_mut!((*slot).errors);
            *errors = (*errors).saturating_add(1);
        } else if res == KRES_QUEUED {
            let queued = core::ptr::addr_of_mut!((*slot).queued);
            *queued = (*queued).saturating_add(1);
        }
        if was == 0 {
            core::ptr::addr_of_mut!((*slot).first_ns).write(now);
        }
        core::ptr::addr_of_mut!((*slot).last_ns).write(now);
    }
}

/// Zero a `VAgg` init slot in place (volatile stores: plain zero
/// chains fuse into `memset` calls and break R4). The caller borrows
/// the slot directly (`&*slot.as_ptr()`): no `assume_init` copy, so the
/// miss path holds exactly one 120B value next to the 260B key (the BPF
/// frame is 512B and an `assume_init` copy of either slot overflows it).
#[inline(always)]
fn vagg_zero_slot(slot: *mut VAgg) {
    unsafe {
        core::ptr::addr_of_mut!((*slot).calls).write_volatile(0);
        core::ptr::addr_of_mut!((*slot).bytes).write_volatile(0);
        core::ptr::addr_of_mut!((*slot).ok).write_volatile(0);
        core::ptr::addr_of_mut!((*slot).errors).write_volatile(0);
        core::ptr::addr_of_mut!((*slot).queued).write_volatile(0);
        core::ptr::addr_of_mut!((*slot).first_ns).write_volatile(0);
        core::ptr::addr_of_mut!((*slot).last_ns).write_volatile(0);
        let mut lane = core::ptr::addr_of_mut!((*slot).lat).cast::<u64>();
        let mut b = 0u32;
        while b < 8 {
            lane.write_volatile(0);
            lane = lane.add(1);
            b += 1;
        }
    }
}

/// Identity hash over `(fam, op, alg bytes, drv bytes)` (twinned FNV-1a:
/// same inputs, same byte order as the ABI mirror). `res`/`ctx` are
/// excluded so one gate covers all rows of an identity.
#[inline(always)]
fn ident_hash(key: &KAgg) -> u64 {
    let raw = (key as *const KAgg).cast::<u8>();
    let mut hash = FNV_BASIS;
    hash ^= unsafe { *raw } as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    hash ^= unsafe { *raw.add(1) } as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    let mut p = unsafe { raw.add(4) };
    let mut i = 0u32;
    while i < 256 {
        hash ^= unsafe { *p } as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        p = unsafe { p.add(1) };
        i += 1;
    }
    hash
}

/// NUL-scan one 128B name (bounded `strnlen`): the C5 `val1` input.
#[inline(always)]
fn name_len(base: *const u8) -> u32 {
    let mut len = 0u32;
    while len < 128 {
        if unsafe { *base.add(len as usize) } == 0 {
            break;
        }
        len += 1;
    }
    len
}

/// Emit one control event (`val0` = packed head, `val1` = packed name
/// lengths, `val2` = event `now`, `val3` = reserved zero — C5).
/// Reserve failure feeds the [`KIDN_DROPS`] saturating counter instead
/// (control-event volume is identity-bounded to ~512 per attach lifetime
/// against ~18k ring capacity, so this is defensive-only — but never
/// silent).
#[inline(always)]
fn emit_ctl(kind: u8, key_hash: u64, head: u64, lens: u64, now: u64) {
    let Some(mut entry) = KRING.reserve::<KCtl>(0) else {
        let drops = KIDN_DROPS;
        if let Some(slot) = KIDN.get_ptr_mut(&drops) {
            unsafe {
                *slot = (*slot).saturating_add(1);
            }
        } else {
            let one: u8 = 1;
            let _ = KIDN.insert(&drops, &one, BPF_NOEXIST);
        }
        return;
    };
    // Slot init through the entry deref (spine discipline): every field
    // written before submit; zero fields via volatile stores (plain
    // zero chains fuse into `memset` calls and break R4).
    let slot: &mut MaybeUninit<KCtl> = &mut entry;
    let ptr = slot.as_mut_ptr();
    unsafe {
        core::ptr::addr_of_mut!((*ptr).kind).write(kind);
        let mut pad = core::ptr::addr_of_mut!((*ptr)._p).cast::<u8>();
        let mut i = 0u32;
        while i < 3 {
            pad.write_volatile(0);
            pad = pad.add(1);
            i += 1;
        }
        core::ptr::addr_of_mut!((*ptr).key_hash).write(key_hash);
        core::ptr::addr_of_mut!((*ptr).val0).write(head);
        core::ptr::addr_of_mut!((*ptr).val1).write(lens);
        core::ptr::addr_of_mut!((*ptr).val2).write(now);
        core::ptr::addr_of_mut!((*ptr).val3).write_volatile(0);
    }
    entry.submit(0);
}

/// `KAGG`-full path: totals already updated; count the overflow per
/// identity in `KIDN` (saturating) and emit one `OVERFLOW` event on the
/// first overflow per identity (ring volume stays identity-bounded).
/// A concurrent inserter winning the race just moves the count (benign);
/// a full `KIDN` stays silent (observable via the `KTOT`-vs-sum gap +
/// the `KIDN` dump, totals still preserved).
#[inline(always)]
fn overflow_path(key_hash: u64, head: u64, lens: u64, now: u64) {
    if let Some(slot) = KIDN.get_ptr_mut(&key_hash) {
        // Benign race: concurrent CPUs may lose an increment on this
        // shared (non-per-CPU) diagnostic counter; magnitude hint only.
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
        return;
    }
    let one: u8 = 1;
    if KIDN.insert(&key_hash, &one, BPF_NOEXIST).is_ok() {
        emit_ctl(KCTL_OVERFLOW, key_hash, head, lens, now);
    } else if let Some(slot) = KIDN.get_ptr_mut(&key_hash) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Record one attributed observation: build the key (volatile-zeroed,
/// then filled), update `KTOT` always, update-or-insert `KAGG` (overflow
/// path on map-full), then the first-seen `KIDN` gate + `IDENT` event
/// (`OVERFLOW` when the gate itself is full — C5/C6).
///
/// `cra_src` = 128B name source (`cra_name`, or the requested alloc
/// name); `drv_src` = `cra_driver_name` source, or 0 on the alloc path
/// (driver unknown yet — the pre-zeroed bytes stay).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn observe(
    fam: u8,
    op: u8,
    res: u8,
    nbytes: u64,
    cra_src: u64,
    drv_src: u64,
    task_flags: u32,
    pf_kthread: u32,
) -> i32 {
    let mut slot = MaybeUninit::<KAgg>::uninit();
    let base = slot.as_mut_ptr().cast::<u8>();
    let mut p = base;
    let mut i = 0u32;
    while i < 260 {
        unsafe {
            p.write_volatile(0);
        }
        p = unsafe { p.add(1) };
        i += 1;
    }
    if !read_name(cra_src, unsafe { base.add(4) }) {
        return 0;
    }
    if drv_src != 0 && !read_name(drv_src, unsafe { base.add(132) }) {
        return 0;
    }
    let ctx = classify_ctx(task_flags, pf_kthread);
    unsafe {
        *base = fam;
        *base.add(1) = op;
        *base.add(2) = res;
        *base.add(3) = ctx;
    }
    // Borrow the slot directly (no `assume_init` copy: a second 260B
    // key on the 512B frame overflows it).
    //
    // SAFETY: all 260 bytes initialized above (zeroed, then filled head
    // + names; the alloc path's drv bytes stay zero by construction).
    let key_ref: &KAgg = unsafe { &*slot.as_ptr() };
    let hash = ident_hash(key_ref);
    let head = (fam as u64) | ((op as u64) << 8) | ((res as u64) << 16) | ((ctx as u64) << 24);
    let alg_len = name_len(unsafe { base.add(4) });
    let drv_len = name_len(unsafe { base.add(132) });
    let lens = (alg_len as u64) | ((drv_len as u64) << 32);
    // SAFETY: helper with no pointer arguments.
    let now = unsafe { bpf_ktime_get_ns() };
    // Totals FIRST: always updated, even on attribution overflow.
    if let Some(tot) = KTOT.get_ptr_mut(0) {
        unsafe {
            update_slot(tot, nbytes, now, res);
        }
    }
    if let Some(found) = KAGG.get_ptr_mut(key_ref) {
        unsafe {
            update_slot(found, nbytes, now, res);
        }
    } else {
        // Insert-zero + in-place fill: correct under every percpu
        // broadcast semantic (a fresh key has no events on any CPU yet)
        // and race-safe via `BPF_NOEXIST` (a concurrent winner's row is
        // found by the re-lookup below and updated normally). The zero
        // value lives in its own init slot (borrowed, never copied).
        let mut zslot = MaybeUninit::<VAgg>::uninit();
        vagg_zero_slot(zslot.as_mut_ptr());
        // SAFETY: fully zeroed by `vagg_zero_slot` above.
        let zero_ref: &VAgg = unsafe { &*zslot.as_ptr() };
        let _ = KAGG.insert(key_ref, zero_ref, BPF_NOEXIST);
        match KAGG.get_ptr_mut(key_ref) {
            Some(filled) => unsafe {
                update_slot(filled, nbytes, now, res);
            },
            None => {
                overflow_path(hash, head, lens, now);
                return 0;
            }
        }
    }
    // First-seen gate: exactly one `IDENT` per identity (the `is_ok`
    // resolves the concurrent-inserter race). A full `KIDN` (insert
    // failed AND the key is still absent — not a lost race) emits
    // `OVERFLOW` instead; the `KAGG` row still carries the full identity.
    if KIDN.get_ptr(&hash).is_none() {
        let zero: u8 = 0;
        if KIDN.insert(&hash, &zero, BPF_NOEXIST).is_ok() {
            emit_ctl(KCTL_IDENT, hash, head, lens, now);
        } else if KIDN.get_ptr(&hash).is_none() {
            overflow_path(hash, head, lens, now);
        }
    }
    0
}

/// Loaded `KCFG` row, as stack scalars.
struct Cfg {
    sk_req_base: u32,
    async_tfm: u32,
    tfm_alg: u32,
    alg_name: u32,
    alg_drv: u32,
    task_flags: u32,
    pf_kthread: u32,
    aead_cryptlen_off: u32,
    ahash_nbytes_off: u32,
}

/// Load the `KCFG` row into stack scalars (`None` = skipped observation;
/// all-zero config = unconfigured, fail-closed via the `pf_kthread`
/// gate: zero-init reads would otherwise mis-chase and misclassify).
#[inline(always)]
fn load_cfg() -> Option<Cfg> {
    match KCFG.get(0) {
        Some(cfg) => {
            if cfg.pf_kthread == 0 {
                return None;
            }
            Some(Cfg {
                sk_req_base: cfg.sk_req_base,
                async_tfm: cfg.async_tfm,
                tfm_alg: cfg.tfm_alg,
                alg_name: cfg.alg_name,
                alg_drv: cfg.alg_drv,
                task_flags: cfg.task_flags,
                pf_kthread: cfg.pf_kthread,
                aead_cryptlen_off: cfg.aead_cryptlen_off,
                ahash_nbytes_off: cfg.ahash_nbytes_off,
            })
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------
// Programs (9 fexit points; section suffix = attach symbol)
// ---------------------------------------------------------------------------

/// `crypto_alloc_tfm_node(alg_name, ...)` exit: requested-name identity
/// (`drv` zeros — the driver is not chosen yet); result via `ERR_PTR`.
#[fexit(function = "crypto_alloc_tfm_node")]
pub fn kcrypto_alloc(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let name: u64 = ctx.arg(0);
    if name == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    observe(
        KFAM_ANY,
        KOP_ALLOC,
        classify_alloc_ptr(ret),
        0,
        name,
        0,
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_destroy_tfm(mem, tfm)` exit: `arg1` is the `struct crypto_tfm
/// *` (BTF proto + `linux/crypto.h` decl), chased for `(cra, drv)`.
/// Void return → `RES_UNOBSERVED` (C7: no return value to classify).
///
/// KNOWN LIMITATION (kernel behavior, proven by kretprobe
/// `evidence/k1-2/step3-destroy-unobservable.txt`): at the exit edge the
/// tfm allocation is already zeroed (`*(tfm+32) == 0`: crypto key hygiene
/// zeroes the tfm before freeing it), so the chase yields 0 and the
/// observation skips via the standard chase-failure path. Destroy rows
/// therefore never materialize on this kernel — the program fires,
/// reads `arg1`, and fail-closes rather than misattributing. (An entry
/// edge could read the live tfm, but C1 mandates all-fexit.)
#[fexit(function = "crypto_destroy_tfm")]
pub fn kcrypto_destroy(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let tfm: u64 = ctx.arg(1);
    let alg = chase_tfm(tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_ANY,
        KOP_DESTROY,
        KRES_UNOBSERVED,
        0,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_skcipher_encrypt(req)` exit: `cryptlen` @ 0 bytes (first member
/// — host-BTF-verified: `skcipher_request.cryptlen` @ 0 on
/// `/sys/kernel/btf/vmlinux`; C3: the loader asserts 0-ness from live BTF
/// at resolve time and the suite re-verifies).
#[fexit(function = "crypto_skcipher_encrypt")]
pub fn kcrypto_skenc(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    let nbytes = read_u32(req) as u64;
    let alg = chase_req(req, cfg.sk_req_base, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_SK,
        KOP_ENC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_skcipher_decrypt(req)` exit: `cryptlen` @ 0 bytes (first member).
#[fexit(function = "crypto_skcipher_decrypt")]
pub fn kcrypto_skdec(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    let nbytes = read_u32(req) as u64;
    let alg = chase_req(req, cfg.sk_req_base, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_SK,
        KOP_DEC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_aead_encrypt(req)` exit: `base` @ 0 (first member); bytes from
/// the KCFG `aead_cryptlen_off` (C2 — all families fill bytes).
#[fexit(function = "crypto_aead_encrypt")]
pub fn kcrypto_aeadenc(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    let nbytes = read_u32(req.wrapping_add(cfg.aead_cryptlen_off as u64)) as u64;
    let alg = chase_req(req, 0, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_AEAD,
        KOP_ENC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_aead_decrypt(req)` exit: `base` @ 0 (first member); bytes from
/// the KCFG `aead_cryptlen_off` (C2).
#[fexit(function = "crypto_aead_decrypt")]
pub fn kcrypto_aeaddec(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    let nbytes = read_u32(req.wrapping_add(cfg.aead_cryptlen_off as u64)) as u64;
    let alg = chase_req(req, 0, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_AEAD,
        KOP_DEC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_ahash_digest(req)` exit: `base` @ 0 (first member); bytes from
/// the KCFG `ahash_nbytes_off` (C2).
#[fexit(function = "crypto_ahash_digest")]
pub fn kcrypto_ahash(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    let nbytes = read_u32(req.wrapping_add(cfg.ahash_nbytes_off as u64)) as u64;
    let alg = chase_req(req, 0, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_AHASH,
        KOP_DIGEST,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_shash_digest(desc, data, len, out)` exit: `tfm` @ 0 in the desc,
/// `base` @ 0 in `crypto_shash` (first members — C3); `len` = `arg2`.
#[fexit(function = "crypto_shash_digest")]
pub fn kcrypto_shash(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let desc: u64 = ctx.arg(0);
    if desc == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    let len: u64 = ctx.arg(2);
    let tfm = read_u64(desc);
    let alg = chase_tfm(tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_SHASH,
        KOP_DIGEST,
        classify_ret(ret as i32),
        len,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

/// `crypto_shash_finup(desc, data, len, out)` exit: same chase as digest.
#[fexit(function = "crypto_shash_finup")]
pub fn kcrypto_finup(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        return 0;
    };
    let desc: u64 = ctx.arg(0);
    if desc == 0 {
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        return 0;
    };
    let len: u64 = ctx.arg(2);
    let tfm = read_u64(desc);
    let alg = chase_tfm(tfm, cfg.tfm_alg);
    if alg == 0 {
        return 0;
    }
    observe(
        KFAM_SHASH,
        KOP_FINUP,
        classify_ret(ret as i32),
        len,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        cfg.task_flags,
        cfg.pf_kthread,
    )
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Dead code: the crate is audited panic-free (no panic!/unwrap/
    // expect, no div/mod, no indexing, every helper inlined). Keep it
    // that way: if a panic path is ever introduced, the
    // `unreachable_unchecked` below is live UB.
    unsafe { core::hint::unreachable_unchecked() }
}

/// Kernel license marker: this object is GPL-2.0-only BPF.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";
