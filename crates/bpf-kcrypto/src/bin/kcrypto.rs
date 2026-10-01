// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF kcrypto sensor (K1 Task 2): 9 fexit programs + aggregate
//! maps + control ring + K5 caller-attribution maps (`KWHO`/`KSTACK`/
//! `KERR`/`KPARAMS`).
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
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_get_func_ret, bpf_get_stackid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
    },
    macros::{fexit, map},
    maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf, StackTrace},
    programs::FExitContext,
};
// Raw `bpf_get_current_comm` (the safe wrapper's `Result<[u8; 16]>`
// copies do not fit the 512B frame; `current_comm` below keeps one
// 16B buffer). Reached via `generated` because the safe wrapper
// shadows the raw name in `helpers`.
use aya_ebpf::helpers::generated::bpf_get_current_comm as bpf_get_current_comm_raw;
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
// Op 2 (destroy) stays reserved: its exit cannot establish a live transform.
const KOP_ENC: u8 = 3;
const KOP_DEC: u8 = 4;
const KOP_DIGEST: u8 = 5;
const KOP_FINUP: u8 = 6;

const KRES_OK: u8 = 0;
const KRES_ERR: u8 = 1;
const KRES_QUEUED: u8 = 2;
// Result 3 (unobserved) stays reserved for the unobservable destroy boundary.

const KCTX_PROC: u8 = 0;
const KCTX_KTHREAD: u8 = 1;
const KCTX_UNKNOWN: u8 = 3;

const KCTL_IDENT: u8 = 1;
const KCTL_OVERFLOW: u8 = 4;

/// Reserved `KIDN` key: ring-reserve-failure counter (saturating `u8`).
const KIDN_DROPS: u64 = u64::MAX;

/// Reserved `KIDN` key: K5 attribution-insert-failure counter
/// (`KWHO`/`KERR`/`KPARAMS` insert failed while the key stayed absent —
/// saturating `u8`, surfaced as `who_drops`).
const KWHO_DROPS: u64 = u64::MAX - 1;

/// `KDROPS` sites: pre-`KTOT` skip accounting (fix wave, G-C1). Every
/// `return 0` before the `KTOT` update bumps one site (exact per-CPU
/// `u64` — no saturation, no races); userspace folds lanes and
/// surfaces per-site coverage counters. Order is a BPF/userspace
/// contract (`KDROP_SITES` pins it).
const KDROPS_CFG: u32 = 0;
const KDROPS_FRET: u32 = 1;
const KDROPS_ARGNULL: u32 = 2;
const KDROPS_CHASE: u32 = 3;
const KDROPS_NAME: u32 = 4;
/// Destroy exclusion, separately keyed: live transform identity is
/// unavailable at the exit edge (C7), so this is expected, never a loss
/// signal. Excluded from loss verdicts, still counted (never silent).
const KDROPS_DESTROY: u32 = 5;
// Sites 6–7 are spare, reserved (BPF never writes them).

/// `BPF_NOEXIST` (`enum bpf_map_update_elem_flags`, UAPI `linux/bpf.h`).
const BPF_NOEXIST: u64 = 1;
/// `BPF_ANY` (`enum bpf_map_update_elem_flags`, UAPI `linux/bpf.h`):
/// insert-or-update, for the R1 identity cache (misses insert;
/// concurrent winners write the same deterministic value).
const BPF_ANY: u64 = 0;

/// `BPF_F_FAST_STACK_CMP` (`enum bpf_stack_build_id_flags`, UAPI
/// `linux/bpf.h`): compare-and-reuse stack ids instead of allocating a
/// fresh id per call.
const BPF_F_FAST_STACK_CMP: u64 = 512;

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

/// `KCFG` value: the K1 offsets + kthread flag + pad (44B head,
/// offsets unchanged) + the 7 K5 attribution offsets +
/// `parent_ok`/`params_ok` + pad (76B total).
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
    pub shash_base: u32,
    pub _pad: u32,
    pub task_real_parent: u32,
    pub task_tgid: u32,
    pub task_comm: u32,
    pub cra_blocksize: u32,
    pub cra_ivsize: u32,
    pub cra_min_keysize: u32,
    pub cra_max_keysize: u32,
    pub parent_ok: u8,
    pub params_ok: u8,
    pub _pad2: [u8; 2],
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

/// `KWHO` key: row hash + thread-group id (16B).
#[repr(C)]
pub struct KWhoKey {
    pub kh: u64,
    pub tgid: u32,
    pub _pad: u32,
}

/// `KWHO` value: caller identity + call tallies (80B). First-seen
/// fields are insert-frozen; the hit path touches only `tid`/`comm`
/// (last-writer), `calls`, `last_ns`.
#[repr(C)]
pub struct VWho {
    pub comm: [u8; 16],
    pub tid: u32,
    pub uid: u32,
    pub cgroup: u64,
    pub ppid: u32,
    pub pcomm: [u8; 16],
    pub stack: i32,
    pub calls: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

/// `KPARAMS` value: per-`kh` crypto parameters (16B).
#[repr(C)]
pub struct VParams {
    pub blocksize: u32,
    pub ivsize: u32,
    pub min_keysize: u32,
    pub max_keysize: u32,
}

/// `KIDENT` value: memoized canonical `(cra_name, cra_driver_name)`
/// (256B, R1). Byte-laid (align 1) so a hit copies straight into the
/// `KAgg` slot's name lanes and a miss inserts straight from them —
/// zero extra stack on the 512B frame. Keyed by the `crypto_alg`
/// address: on the req paths both names are pure functions of `alg`
/// (kernel static strings); the alloc path never touches the cache
/// (requested-name identity, `drv_src == 0`).
#[repr(C)]
pub struct VIdent {
    pub name: [u8; 128],
    pub drv: [u8; 128],
}

// SAME numbers as the ABI mirrors + loader KCRYPTO_MAPS (duplication
// deliberate + cited: a dims drift must fail here AND at load).
const _: () = assert!(size_of::<KConfig>() == 76);
const _: () = assert!(size_of::<KAgg>() == 260);
const _: () = assert!(size_of::<VAgg>() == 120);
const _: () = assert!(size_of::<KCtl>() == 48);
const _: () = assert!(size_of::<KWhoKey>() == 16);
const _: () = assert!(size_of::<VWho>() == 80);
const _: () = assert!(size_of::<VParams>() == 16);
const _: () = assert!(size_of::<VIdent>() == 256);

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
#[map]
static KWHO: PerCpuHashMap<KWhoKey, VWho> = PerCpuHashMap::with_max_entries(2048, 0);
#[map]
static KSTACK: StackTrace = StackTrace::with_max_entries(1024, 0);
#[map]
static KERR: HashMap<u64, i32> = HashMap::with_max_entries(256, 0);
#[map]
static KPARAMS: HashMap<u64, VParams> = HashMap::with_max_entries(256, 0);
#[map]
static KDROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);
#[map]
static KIDENT: HashMap<u64, VIdent> = HashMap::with_max_entries(256, 0);

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

/// Probe-read a 16B `comm` (`TASK_COMM_LEN`) into `dst` (a 16B stack
/// range). `false` = unreadable source, fail-soft zeros by the caller.
#[inline(always)]
fn read_comm(src: u64, dst: *mut u8) -> bool {
    if src == 0 {
        return false;
    }
    // SAFETY: `dst` spans 16 exclusive stack bytes (caller contract).
    let slice = unsafe { core::slice::from_raw_parts_mut(dst, 16) };
    // SAFETY: probe-read faults safely into Err.
    unsafe { bpf_probe_read_kernel_buf(src as *const u8, slice) }.is_ok()
}

/// Current-task `comm` into `dst` (a 16B stack range), fail-soft zeros
/// (pre-zeroed; a nonzero helper status keeps the zeros).
#[inline(always)]
fn current_comm(dst: *mut u8) {
    let mut p = dst;
    let mut i = 0u32;
    while i < 16 {
        unsafe {
            p.write_volatile(0);
        }
        p = unsafe { p.add(1) };
        i += 1;
    }
    // SAFETY: `dst` spans 16 exclusive stack bytes (caller contract);
    // the helper writes at most `size_of_buf` bytes.
    let _ = unsafe { bpf_get_current_comm_raw(dst as *mut _, 16) };
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

/// Chase a live `tfm -> __crt_alg` (the shash sites add the KCFG `shash_base` to the
/// `shash_desc.tfm` pointer first — `crypto_shash.base` is @ 0 on 7.0
/// but @ 8 on 6.12, so the shash pointer is NOT the `crypto_tfm`
/// numerically on every kernel; the offset is loader-resolved, and
/// `shash_desc.tfm` @ 0 stays a C3 loader-asserted first member). 0 =
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
///
/// Hashes the canonical key (fix wave, G-I1): the rewrite lands
/// BEFORE the hashes, so post-NUL bytes are zero here and the plain
/// full-width hash equals the ABI twins' canonical stream on every
/// input. (Rewrite-before-hash is safe only because the scan above
/// yields one range state — with 129 exact-len paths it forks through
/// these loops and blows the 1M budget, observed E2BIG.)
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

/// Row hash over the FULL `KAgg` key: FNV-1a over `fam`, `op`,
/// `res`, `ctx`, then the 128 `alg` bytes + 128 `drv` bytes (twinned
/// byte order with the ABI `kh_of`; each (result, context) row of an
/// identity hashes distinctly so who-rows join agg rows exactly).
#[inline(always)]
fn kh_of(key: &KAgg) -> u64 {
    let raw = (key as *const KAgg).cast::<u8>();
    let mut hash = FNV_BASIS;
    let mut h = 0u32;
    while h < 4 {
        hash ^= unsafe { *raw.add(h as usize) } as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        h += 1;
    }
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

/// NUL-scan one 128B name (bounded `strnlen`, the C5 `val1` input)
/// AND NUL-canonicalize it in place, single pass (fix wave, G-I1):
/// zero every byte at/after the first NUL so the `KAGG` map key — and
/// the hashes over it — are canonical (kernel heap padding past the
/// NUL used to split logical identities into phantom keys, burning
/// the 256-entry map). Returns the first-NUL index (128 when the name
/// has no NUL). One 128-iteration pass (the scan and the rewrite
/// fused): fewer hot-path instructions means a smaller preemption
/// window means fewer `bpf_prog_active` guard-skips (G-C1 root cause —
/// every skip is an event whose program never runs, uncountable
/// in-product, so the window is minimized, not merely bounded).
/// Branchless prefix latch — NO early exit: a `break` produces 129
/// exact-len paths that multiply every downstream loop past the
/// verifier's 1M-insn budget (observed E2BIG); this yields one range
/// state instead (the `byte != 0` diamonds rejoin within each
/// iteration). The keep-mask is `black_box`'d: LLVM otherwise proves
/// the `{0, 0xFF}` range and rewrites the byte-select as branches,
/// defeating verifier state-merging (observed E2BIG); opaque, it
/// emits one straight-line AND. Register scalars only — no new stack
/// slots (the 512B frame binds).
#[inline(always)]
fn canon_len(name: *mut u8) -> u32 {
    let mut len = 0u32;
    let mut nz = 1u32;
    let mut i = 0u32;
    while i < 128 {
        let byte = unsafe { *name.add(i as usize) };
        nz &= u32::from(byte != 0);
        len += nz;
        // `nz` (post-update) is 1 iff byte `i` is still inside the
        // leading-nonzero prefix — it already encodes keep/drop.
        let keep = core::hint::black_box((nz * 0xFF) as u8);
        unsafe {
            *name.add(i as usize) = byte & keep;
        }
        i += 1;
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
        if let Some(slot) = KIDN.get_ptr_mut(drops) {
            unsafe {
                *slot = (*slot).saturating_add(1);
            }
        } else {
            let one: u8 = 1;
            let _ = KIDN.insert(drops, one, BPF_NOEXIST);
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
/// a full `KIDN` stays SILENT by design (C9): a per-observation `OVERFLOW`
/// here would flood the ring (kp2 S7: rare control events only).
/// Observable instead via the `KTOT`-vs-sum gap (K2 publishes as
/// `attribution_overflow`) + the `KIDN` dump showing full; totals preserved.
#[inline(always)]
fn overflow_path(key_hash: u64, head: u64, lens: u64, now: u64) {
    if let Some(slot) = KIDN.get_ptr_mut(key_hash) {
        // Benign race: concurrent CPUs may lose an increment on this
        // shared (non-per-CPU) diagnostic counter; magnitude hint only.
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
        return;
    }
    let one: u8 = 1;
    if KIDN.insert(key_hash, one, BPF_NOEXIST).is_ok() {
        emit_ctl(KCTL_OVERFLOW, key_hash, head, lens, now);
    } else if let Some(slot) = KIDN.get_ptr_mut(key_hash) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Pre-`KTOT` skip accounting: bump this CPU's lane for `site`
/// (exact `u64` per-CPU — no saturation, no races; userspace folds
/// lanes). A missing slot (live-impossible on a `PerCpuArray`) is
/// ignored: the observation is already skipped, and a counter for the
/// counter would recurse.
#[inline(always)]
fn drop_inc(site: u32) {
    if let Some(slot) = KDROPS.get_ptr_mut(site) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Attribution-drop counter: `KWHO`/`KERR`/`KPARAMS` insert failed
/// while the key stayed absent (saturating `u8` at the `KWHO_DROPS`
/// reserved `KIDN` key — never silent, distinct from ring drops).
#[inline(always)]
fn who_drops_inc() {
    let drops = KWHO_DROPS;
    if let Some(slot) = KIDN.get_ptr_mut(drops) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    } else {
        let one: u8 = 1;
        let _ = KIDN.insert(drops, one, BPF_NOEXIST);
    }
}

/// In-place per-CPU who-lane update (current CPU's copy, exclusive):
/// first-touch stamps `first_ns` when the lane was fresh (`calls == 0`
/// — the broadcast insert carries `calls == 0`); `tid`/`comm` refresh
/// last-writer; identity fields are insert-frozen.
///
/// # Safety
///
/// `slot` must be a live per-CPU map value pointer for this CPU.
#[inline(always)]
unsafe fn update_who_slot(slot: *mut VWho, tid: u32, comm: &[u8; 16], now: u64) {
    unsafe {
        let calls = core::ptr::addr_of_mut!((*slot).calls);
        let was = *calls;
        *calls = was.saturating_add(1);
        if was == 0 {
            core::ptr::addr_of_mut!((*slot).first_ns).write(now);
        }
        core::ptr::addr_of_mut!((*slot).last_ns).write(now);
        core::ptr::addr_of_mut!((*slot).tid).write(tid);
        let mut dst = core::ptr::addr_of_mut!((*slot).comm).cast::<u8>();
        let mut src = comm as *const [u8; 16] as *const u8;
        let mut i = 0u32;
        while i < 16 {
            dst.write(*src);
            dst = dst.add(1);
            src = src.add(1);
            i += 1;
        }
    }
}

/// Parent chase on who-miss (1A-M8): `ppid`/`pcomm` iff
/// `parent_ok`, fail-soft zeros otherwise (`pcomm`/`ppid` are
/// pre-zeroed by the caller, so no zero chain fuses into memset).
///
/// # Safety
///
/// `base` must be a writable `VWho` slot.
#[inline(always)]
unsafe fn chase_parent(base: *mut VWho) {
    // K5 tail of KCFG (miss-only lookup: keeps the per-event
    // `Cfg` at 40B and no borrow live across the populate).
    // `None` (unreadable map — essentially never) degrades to
    // flags-off: identity without parent, never a skip.
    if let Some(row) = KCFG.get(0)
        && row.parent_ok != 0
    {
        // SAFETY: helper with no pointer arguments.
        let task = unsafe { bpf_get_current_task() };
        if task != 0 {
            let parent = read_u64(task.wrapping_add(row.task_real_parent as u64));
            if parent != 0 {
                unsafe {
                    core::ptr::addr_of_mut!((*base).ppid)
                        .write(read_u32(parent.wrapping_add(row.task_tgid as u64)));
                    let psrc = parent.wrapping_add(row.task_comm as u64);
                    let pdst = core::ptr::addr_of_mut!((*base).pcomm).cast::<u8>();
                    let _ = read_comm(psrc, pdst);
                }
            }
        }
    }
}

/// Who-miss upsert (1A-M8): populate the identity value at `base`
/// (comm/tid/uid/cgroup, parent chase, stack id, zero tallies) and
/// insert with `calls == 0` (the percpu insert broadcasts to every
/// lane; the re-lookup below updates this CPU's lane in place — the
/// KAGG insert-zero precedent, so idle lanes stay zero and the fold
/// stays exact).
///
/// # Safety
///
/// `base` must span a writable `VWho` (the scratch head); `wkey` and
/// `comm` must be live across the call.
#[inline(always)]
unsafe fn who_upsert(
    base: *mut VWho,
    ctx: &FExitContext,
    wkey: &KWhoKey,
    tid: u32,
    comm: &[u8; 16],
    now: u64,
) {
    // SAFETY: every field written below before any read/insert
    // (`scratch` contract: `VWho` @ 0 spans 80 bytes).
    unsafe {
        let mut dst = core::ptr::addr_of_mut!((*base).comm).cast::<u8>();
        let mut src = comm as *const [u8; 16] as *const u8;
        let mut i = 0u32;
        while i < 16 {
            dst.write(*src);
            dst = dst.add(1);
            src = src.add(1);
            i += 1;
        }
        core::ptr::addr_of_mut!((*base).tid).write(tid);
        // SAFETY: helpers with no pointer arguments (results used
        // inline: no temporary survives to the frame).
        core::ptr::addr_of_mut!((*base).uid).write(bpf_get_current_uid_gid() as u32);
        core::ptr::addr_of_mut!((*base).cgroup).write(bpf_get_current_cgroup_id());
        // Parent chase iff `parent_ok`, fail-soft zeros (`pcomm`
        // pre-zeroed: volatile, so no zero chain fuses into memset;
        // `ppid` likewise, overwritten on chase success).
        let mut pcomm = core::ptr::addr_of_mut!((*base).pcomm).cast::<u8>();
        let mut j = 0u32;
        while j < 16 {
            pcomm.write_volatile(0);
            pcomm = pcomm.add(1);
            j += 1;
        }
        core::ptr::addr_of_mut!((*base).ppid).write_volatile(0);
        chase_parent(base);
        // Stack id, first-seen only: the raw helper return (id, or
        // the negative errno when the helper refuses — no row).
        // The `&KSTACK` address is the same map-reference pattern
        // aya's own map methods emit (an `R_BPF_64_64` reloc the
        // raw loader patches by symbol name); `ctx.as_ptr()` feeds
        // the `ARG_PTR_TO_CTX` slot (kernel-stack collection needs
        // no regs from it).
        let stack_map = &KSTACK as *const StackTrace as *mut _;
        // SAFETY: (fexit ctx, stack-trace map, kernel-stack flags).
        core::ptr::addr_of_mut!((*base).stack).write(bpf_get_stackid(
            ctx.as_ptr(),
            stack_map,
            BPF_F_FAST_STACK_CMP,
        ) as i32);
        // Zero tallies + stamps: the percpu insert broadcasts this
        // value to every lane, so idle lanes must hold calls == 0
        // with zero stamps (the KAGG `vagg_zero_slot` precedent);
        // the re-lookup below stamps the inserting lane via
        // `update_who_slot` (first_ns = last_ns = now, calls = 1).
        core::ptr::addr_of_mut!((*base).calls).write_volatile(0);
        core::ptr::addr_of_mut!((*base).first_ns).write_volatile(0);
        core::ptr::addr_of_mut!((*base).last_ns).write_volatile(0);
    }
    // SAFETY: fully initialized above.
    let who_ref: &VWho = unsafe { &*base };
    let _ = KWHO.insert(wkey, who_ref, BPF_NOEXIST);
    match KWHO.get_ptr_mut(wkey) {
        Some(filled) => unsafe {
            update_who_slot(filled, tid, comm, now);
        },
        None => {
            who_drops_inc();
        }
    }
}

/// Per-kh crypto params, insert-if-absent (1A-M8): static per alg;
/// no row when `alg == 0` (e.g. a failed alloc — userspace omits
/// the keys then, never zero-fills). Reuses the scratch head: the
/// who value is already copied into the map above.
///
/// # Safety
///
/// `scratch` @ 0 must span 80 writable bytes; the who init value
/// there must be dead (copied into the map by the insert).
#[inline(always)]
unsafe fn record_params(scratch: *mut u8, kh: u64, alg: u64) {
    if alg != 0
        && let Some(row) = KCFG.get(0)
        && row.params_ok != 0
        && KPARAMS.get_ptr(kh).is_none()
    {
        // SAFETY: `scratch` @ 0 spans 80 bytes; the who init
        // value above is dead (copied into the map by the
        // insert).
        unsafe {
            let pslot = scratch as *mut VParams;
            core::ptr::addr_of_mut!((*pslot).blocksize)
                .write(read_u32(alg.wrapping_add(row.cra_blocksize as u64)));
            core::ptr::addr_of_mut!((*pslot).ivsize)
                .write(read_u32(alg.wrapping_add(row.cra_ivsize as u64)));
            core::ptr::addr_of_mut!((*pslot).min_keysize)
                .write(read_u32(alg.wrapping_add(row.cra_min_keysize as u64)));
            core::ptr::addr_of_mut!((*pslot).max_keysize)
                .write(read_u32(alg.wrapping_add(row.cra_max_keysize as u64)));
            // SAFETY: fully initialized above.
            let params_ref: &VParams = &*pslot;
            let _ = KPARAMS.insert(kh, params_ref, BPF_NOEXIST);
        }
        if KPARAMS.get_ptr(kh).is_none() {
            who_drops_inc();
        }
    }
}

/// First nonzero return per kh, insert-if-absent only (1A-M8).
#[inline(always)]
fn record_kerr(kh: u64, kerr: i32) {
    if kerr != 0 && KERR.get_ptr(kh).is_none() {
        let _ = KERR.insert(kh, kerr, BPF_NOEXIST);
        if KERR.get_ptr(kh).is_none() {
            who_drops_inc();
        }
    }
}

/// Record one caller-attribution observation (row hash `kh`,
/// precomputed): per-(`kh`, `tgid`) first-seen identity insert or hit
/// update, plus the per-`kh` first-errno (`KERR`) + crypto-params
/// (`KPARAMS`) rows.
///
/// Runs AFTER the agg update + first-seen gate: a who-path failure
/// (map-full insert loss) counts `who_drops` and returns, never
/// disturbing the already-recorded aggregate observation. Identity
/// chases (parent, stack, params) run on miss only, never per event.
///
/// `scratch` is the caller's 120B init scratch (the shared `aux`
/// slot in `observe()`), carved as `VWho` @ 0 (miss init, then
/// `VParams` @ 0 — disjoint: the who insert copies the value into the
/// map first), `KWhoKey` @ 80, `comm` @ 96 (112B used). No separate
/// allocas: the 512B frame fits no more slots (every `let`-bound
/// pointer/temporary below is one the backend keeps — bind nothing
/// cheaply recomputed).
///
/// # Safety
///
/// `scratch` must span 120 exclusive stack bytes, 8-aligned.
#[inline(always)]
fn who_record(ctx: &FExitContext, kh: u64, now: u64, alg: u64, kerr: i32, scratch: *mut u8) {
    // SAFETY: helper with no pointer arguments.
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    // SAFETY: `scratch` spans 120 bytes; the key/comm carves below are
    // inside it (80..112), disjoint from the `VWho` head.
    let wkey_ptr = unsafe { scratch.add(80) } as *mut KWhoKey;
    unsafe {
        core::ptr::addr_of_mut!((*wkey_ptr).kh).write(kh);
        core::ptr::addr_of_mut!((*wkey_ptr).tgid).write(tgid);
        core::ptr::addr_of_mut!((*wkey_ptr)._pad).write_volatile(0);
    }
    // SAFETY: fully initialized above.
    let wkey: &KWhoKey = unsafe { &*wkey_ptr };
    current_comm(unsafe { scratch.add(96) });
    // SAFETY: `current_comm` writes all 16 bytes.
    let comm: &[u8; 16] = unsafe { &*(scratch.add(96) as *const [u8; 16]) };
    if let Some(found) = KWHO.get_ptr_mut(wkey) {
        unsafe {
            update_who_slot(found, tid, comm, now);
        }
    } else {
        // Miss: populate the identity + insert (`who_upsert`), then
        // the per-alg params row; the who value is already copied
        // into the map when the scratch head is reused.
        let base = scratch as *mut VWho;
        // SAFETY: `base` is the scratch head (a writable `VWho`);
        // `wkey`/`comm` carves are live across the call.
        unsafe {
            who_upsert(base, ctx, wkey, tid, comm, now);
        }
        // SAFETY: scratch @ 0 spans 80 bytes; the who init value is
        // dead (copied into the map by the insert above).
        unsafe {
            record_params(scratch, kh, alg);
        }
    }
    record_kerr(kh, kerr);
}

/// Record one attributed observation: build the key (volatile-zeroed,
/// then filled), update `KTOT` always, update-or-insert `KAGG` (overflow
/// path on map-full), then the first-seen `KIDN` gate + `IDENT` event.
/// A full `KIDN` stays SILENT by design (C9): a per-observation `OVERFLOW`
/// here would flood the ring (kp2 S7: rare control events only).
/// Observable instead via the `KTOT`-vs-sum gap (K2 publishes as
/// `attribution_overflow`) + the `KIDN` dump showing full; totals preserved.
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
    cfg: &Cfg,
    alg: u64,
    kerr: i32,
    ctx: &FExitContext,
) -> i32 {
    let mut slot = MaybeUninit::<KAgg>::uninit();
    let base = slot.as_mut_ptr().cast::<u8>();
    // R1 identity cache: on the req paths (`alg != 0`, `drv_src !=
    // 0`) both names are pure functions of the `crypto_alg` address,
    // so a hit copies the memoized canonical bytes and skips both
    // 128B probe-reads (plus the 260B zero: the copy + head writes
    // below fill every lane). The alloc path always misses
    // (requested-name identity, `drv_src == 0`). Hit bytes are
    // re-scanned with the slow path below, so downstream is
    // bit-identical on both paths.
    let cacheable = alg != 0 && drv_src != 0;
    let mut hit = false;
    if cacheable && let Some(found) = KIDENT.get_ptr(alg) {
        // SAFETY: map-owned 256 bytes, live across the call.
        let cached: &VIdent = unsafe { &*found };
        // R1: NO validation reads on the hit path — measured
        // (prof2 vs P9 c-driver) that per-call probe cost
        // dominates, so a tripwire's 2 calls cost as much as
        // the 2 saved reads. Exactness rests on the
        // documented alg-stability assumption + the exactness
        // lanes, which fail on any misattribution.
        let src = cached as *const VIdent as *const u8;
        // SAFETY: `base.add(4)..base.add(260)` spans the
        // name lanes (the head is written below).
        let dst = unsafe { base.add(4) };
        let mut j = 0u32;
        while j < 256 {
            unsafe {
                *dst.add(j as usize) = *src.add(j as usize);
            }
            j += 1;
        }
        hit = true;
    }
    if !hit {
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
            drop_inc(KDROPS_NAME);
            return 0;
        }
        if drv_src != 0 && !read_name(drv_src, unsafe { base.add(132) }) {
            drop_inc(KDROPS_NAME);
            return 0;
        }
    }
    let ctx_class = classify_ctx(cfg.task_flags, cfg.pf_kthread);
    unsafe {
        *base = fam;
        *base.add(1) = op;
        *base.add(2) = res;
        *base.add(3) = ctx_class;
    }
    // G-I1: single-pass scan + rewrite BEFORE the hashes (the scan
    // yields one range state, so the rewritten bytes stay single-state
    // through them — see `ident_hash`). The alloc path's drv bytes are
    // pre-zeroed, so its length is 0 without a wasted scan. Runs before
    // the `key_ref` borrow below (no shared borrow live across the
    // mutation).
    let alg_len = canon_len(unsafe { base.add(4) });
    let drv_len = if drv_src != 0 {
        canon_len(unsafe { base.add(132) })
    } else {
        0
    };
    if cacheable && !hit {
        // Memoize the just-canonicalized bytes (miss only; the
        // alloc path never inserts). Best-effort: a full map keeps
        // the correct slow path, uncached.
        // SAFETY: `base.add(4)` spans the 256 canonical name bytes
        // scanned above; `VIdent` is byte-laid (align 1).
        let ident: &VIdent = unsafe { &*(base.add(4) as *const VIdent) };
        let _ = KIDENT.insert(alg, ident, BPF_ANY);
    }
    // Borrow the slot directly (no `assume_init` copy: a second 260B
    // key on the 512B frame overflows it).
    //
    // SAFETY: all 260 bytes initialized above (zeroed, then filled head
    // + names, now canonical; the alloc path's drv bytes stay zero by
    // construction).
    let key_ref: &KAgg = unsafe { &*slot.as_ptr() };
    let hash = ident_hash(key_ref);
    let kh = kh_of(key_ref);
    let head =
        (fam as u64) | ((op as u64) << 8) | ((res as u64) << 16) | ((ctx_class as u64) << 24);
    let lens = (alg_len as u64) | ((drv_len as u64) << 32);
    // SAFETY: helper with no pointer arguments.
    let now = unsafe { bpf_ktime_get_ns() };
    // Shared 120B init scratch (the 512B frame fits no second large
    // slot): the `VAgg` insert-zero below, then the `VWho` (80B) and
    // `VParams` (16B) init values in `who_record` — disjoint lifetimes,
    // raw-pointer-typed at each use (LLVM stack coloring is not
    // trusted to merge separate slots on this backend).
    let mut aux = MaybeUninit::<[u64; 15]>::uninit();
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
        // value lives in the shared init slot (borrowed, never copied).
        // SAFETY: `aux` spans 120 exclusive stack bytes, 8-aligned.
        vagg_zero_slot(aux.as_mut_ptr() as *mut VAgg);
        // SAFETY: fully zeroed by `vagg_zero_slot` above.
        let zero_ref: &VAgg = unsafe { &*(aux.as_ptr() as *const VAgg) };
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
    // failed AND the key is still absent — not a lost race) stays SILENT
    // by design (C9): the 257th+ distinct identity gets no ring event,
    // because a per-observation `OVERFLOW` here would flood the ring
    // (kp2 S7: rare control events only). Observable via the
    // `KTOT`-vs-sum gap (K2 `attribution_overflow`) + the `KIDN` dump
    // showing full; the `KAGG` row still carries the full identity.
    if KIDN.get_ptr(hash).is_none() {
        let zero: u8 = 0;
        if KIDN.insert(hash, zero, BPF_NOEXIST).is_ok() {
            emit_ctl(KCTL_IDENT, hash, head, lens, now);
        } else if KIDN.get_ptr(hash).is_none() {
            overflow_path(hash, head, lens, now);
        }
    }
    // Caller attribution, after the agg update + first-seen gate (never
    // disturbs them: who-path loss counts `who_drops` only).
    // SAFETY: `aux` spans 120 exclusive stack bytes, 8-aligned; the
    // `VAgg` zero above is dead (copied into the map by the insert, or
    // never built on the hit path).
    who_record(ctx, kh, now, alg, kerr, aux.as_mut_ptr() as *mut u8);
    0
}

/// Loaded `KCFG` row, as stack scalars (K1 head only: the K5 tail is
/// read by a second miss-only `KCFG` lookup in `who_record`, so the
/// per-event `Cfg` stays 40B and the 512B frame fits).
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
    shash_base: u32,
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
                shash_base: cfg.shash_base,
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
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let name: u64 = ctx.arg(0);
    if name == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let res = classify_alloc_ptr(ret);
    // First-errno input: the decoded negative errno of an `ERR_PTR`
    // (else 0 = no record); the params chase runs on the returned tfm
    // (else 0 = no row).
    let kerr = if res == KRES_ERR {
        (ret as i64) as i32
    } else {
        0
    };
    let alg = if res == KRES_ERR {
        0
    } else {
        chase_tfm(ret, cfg.tfm_alg)
    };
    observe(KFAM_ANY, KOP_ALLOC, res, 0, name, 0, &cfg, alg, kerr, &ctx)
}

/// `crypto_destroy_tfm(mem, tfm)` exit cannot establish a live transform.
/// A final release already freed it; even a successful probe read could
/// return recycled storage. Zeroing before free does not preserve zeroes
/// after free (6.12 reproduced a nonzero chase followed by a name fault).
/// Retain the attached boundary and its explicit skip count, without
/// reading either argument or target memory. C1 remains fexit-only; C7
/// supplies no destroy identity or return-value observation.
#[fexit(function = "crypto_destroy_tfm")]
pub fn kcrypto_destroy(_ctx: FExitContext) -> i32 {
    if load_cfg().is_none() {
        drop_inc(KDROPS_CFG);
        return 0;
    }
    // Separately keyed expected exclusion, not a measured operation loss.
    drop_inc(KDROPS_DESTROY);
    0
}

/// `crypto_skcipher_encrypt(req)` exit: `cryptlen` @ 0 bytes (first member
/// — host-BTF-verified: `skcipher_request.cryptlen` @ 0 on
/// `/sys/kernel/btf/vmlinux`; C3: the loader asserts 0-ness from live BTF
/// at resolve time and the suite re-verifies).
#[fexit(function = "crypto_skcipher_encrypt")]
pub fn kcrypto_skenc(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let nbytes = read_u32(req) as u64;
    let alg = chase_req(req, cfg.sk_req_base, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    observe(
        KFAM_SK,
        KOP_ENC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        &cfg,
        alg,
        ret as i32,
        &ctx,
    )
}

/// `crypto_skcipher_decrypt(req)` exit: `cryptlen` @ 0 bytes (first member).
#[fexit(function = "crypto_skcipher_decrypt")]
pub fn kcrypto_skdec(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let nbytes = read_u32(req) as u64;
    let alg = chase_req(req, cfg.sk_req_base, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    observe(
        KFAM_SK,
        KOP_DEC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        &cfg,
        alg,
        ret as i32,
        &ctx,
    )
}

/// `crypto_aead_encrypt(req)` exit: `base` @ 0 (first member); bytes from
/// the KCFG `aead_cryptlen_off` (C2 — all families fill bytes).
#[fexit(function = "crypto_aead_encrypt")]
pub fn kcrypto_aeadenc(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let nbytes = read_u32(req.wrapping_add(cfg.aead_cryptlen_off as u64)) as u64;
    let alg = chase_req(req, 0, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    observe(
        KFAM_AEAD,
        KOP_ENC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        &cfg,
        alg,
        ret as i32,
        &ctx,
    )
}

/// `crypto_aead_decrypt(req)` exit: `base` @ 0 (first member); bytes from
/// the KCFG `aead_cryptlen_off` (C2).
#[fexit(function = "crypto_aead_decrypt")]
pub fn kcrypto_aeaddec(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let nbytes = read_u32(req.wrapping_add(cfg.aead_cryptlen_off as u64)) as u64;
    let alg = chase_req(req, 0, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    observe(
        KFAM_AEAD,
        KOP_DEC,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        &cfg,
        alg,
        ret as i32,
        &ctx,
    )
}

/// `crypto_ahash_digest(req)` exit: `base` @ 0 (first member); bytes from
/// the KCFG `ahash_nbytes_off` (C2).
#[fexit(function = "crypto_ahash_digest")]
pub fn kcrypto_ahash(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let req: u64 = ctx.arg(0);
    if req == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let nbytes = read_u32(req.wrapping_add(cfg.ahash_nbytes_off as u64)) as u64;
    let alg = chase_req(req, 0, cfg.async_tfm, cfg.tfm_alg);
    if alg == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    observe(
        KFAM_AHASH,
        KOP_DIGEST,
        classify_ret(ret as i32),
        nbytes,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        &cfg,
        alg,
        ret as i32,
        &ctx,
    )
}

/// `crypto_shash_digest(desc, data, len, out)` exit: `tfm` @ 0 in the desc
/// (first member — C3); the `crypto_shash`→`crypto_tfm` step adds the
/// KCFG `shash_base` (loader-resolved: @0 on 7.0, @8 on 6.12);
/// `len` = `arg2`.
#[fexit(function = "crypto_shash_digest")]
pub fn kcrypto_shash(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let desc: u64 = ctx.arg(0);
    if desc == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let len: u64 = ctx.arg(2);
    let shash = read_u64(desc);
    if shash == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    let alg = chase_tfm(shash.wrapping_add(cfg.shash_base as u64), cfg.tfm_alg);
    if alg == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    observe(
        KFAM_SHASH,
        KOP_DIGEST,
        classify_ret(ret as i32),
        len,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        &cfg,
        alg,
        ret as i32,
        &ctx,
    )
}

/// `crypto_shash_finup(desc, data, len, out)` exit: same chase as digest.
#[fexit(function = "crypto_shash_finup")]
pub fn kcrypto_finup(ctx: FExitContext) -> i32 {
    let Some(cfg) = load_cfg() else {
        drop_inc(KDROPS_CFG);
        return 0;
    };
    let desc: u64 = ctx.arg(0);
    if desc == 0 {
        drop_inc(KDROPS_ARGNULL);
        return 0;
    }
    let Some(ret) = func_ret(&ctx) else {
        drop_inc(KDROPS_FRET);
        return 0;
    };
    let len: u64 = ctx.arg(2);
    let shash = read_u64(desc);
    if shash == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    let alg = chase_tfm(shash.wrapping_add(cfg.shash_base as u64), cfg.tfm_alg);
    if alg == 0 {
        drop_inc(KDROPS_CHASE);
        return 0;
    }
    observe(
        KFAM_SHASH,
        KOP_FINUP,
        classify_ret(ret as i32),
        len,
        alg.wrapping_add(cfg.alg_name as u64),
        alg.wrapping_add(cfg.alg_drv as u64),
        &cfg,
        alg,
        ret as i32,
        &ctx,
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
#[unsafe(link_section = "license")]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";
