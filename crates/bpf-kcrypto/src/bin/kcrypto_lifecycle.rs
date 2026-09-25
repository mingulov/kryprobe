// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF lifecycle sensor (T06 grown by the T07.2 alloc site
//! and the T07.3 destroy site): 4 fsession programs + edge ring +
//! per-CPU aggregate/loss counters + config gate.
//!
//! Each program observes one required site through ONE
//! `BPF_TRACE_FSESSION` link (floor 7.0+, attach value 58): the same
//! program runs at function ENTRY (`is_return == false`) and EXIT
//! (`is_return == true`), distinguished at runtime via the
//! `bpf_session_is_return` kfunc. The op programs read the request
//! pointer (`arg0`); the exit runs additionally read the return
//! value (`bpf_get_func_ret`). Every run stamps `bpf_ktime_get_ns`
//! and the op programs emit one 48-byte v4 [`LEdge`] record on
//! `LRING` per observed half — the record names the frontend
//! transform behind the op (`req->base->tfm` chased at the `LCFG`
//! request-link words, minus `sk_base` to the frontend; 0 when the
//! link was unreadable), so op-first observations admit their
//! transform (T07.3 first-seen) and attribute to it (T08).
//!
//! The alloc program observes `crypto_alloc_skcipher(alg_name, type,
//! mask)`: the entry run bounded-copies the requested name (63-byte
//! bound plus NUL, `TRUNCATED` when the bound fills — a
//! null/unreadable name admits as empty/unknown, never dropped,
//! since the attempt token, not the name, is the pairing key) plus
//! the type/mask words, and the exit run classifies the return
//! BEFORE dereference (ERR_PTR = errno failure with a zeroed name,
//! never chased; NULL = unclassifiable, `LLOSS_FRET`-dropped, never
//! a fabricated errno). Success emits the raw frontend pointer plus
//! the resolved driver name chased through
//! `(frontend + sk_base)->__crt_alg->cra_driver_name` at the
//! `LCFG`-pinned offsets (an unreadable chase admits as
//! empty/unknown — missing provenance is unknown, never fabricated).
//! Each half emits one 112-byte v1 [`LTfm`] record carrying the
//! attempt token.
//!
//! The destroy program observes `crypto_destroy_tfm(mem, tfm)`: the
//! entry run snapshots the frontend `mem` plus the refcount
//! (value + observed bit, read at `tfm + refcnt_off` when the
//! kernel carries the field) and the exit run emits the bare
//! return (token only — the call returns void, so no status read
//! and no arg re-read). Each half emits one 112-byte v1 [`LTfm`]
//! record at the destroy site carrying the attempt token.
//!
//! Invocation identity (round-8 W8): the kernel owns pairing. The
//! per-call session cookie (`bpf_session_cookie`, zeroed by the
//! kernel before the entry run) carries the invocation id: the entry
//! run issues one id from its CPU's `LCTR` lane FOR ITS OWN PROGRAM
//! (`(seq << 17) | (lane << 14) | (cpu << 1)`, bit 0 reserved +
//! always clear — distinct across CPUs AND site programs without
//! atomics) and stores it into the cookie; the exit run of the SAME
//! call reads the SAME cookie back. There are no slots, no
//! quarantine, no thread checks: a skipped entry leaves the cookie
//! zero, so the exit emits TAINTED with invocation 0 instead of
//! joining another call; nested same-key calls pair exactly by
//! distinct cookies. Userspace joins a return ONLY to the outstanding
//! invocation with the SAME id, so transport loss can strand an id
//! but never misjoin one. The alloc and destroy programs mint
//! attempt tokens from their own `LCTR` lanes with the same layout
//! (the 3-bit lane field keeps every program's ids disjoint — the
//! token namespace can never alias an invocation id).
//!
//! Cookie discipline: the pointer is re-fetched in every run via the
//! kfunc and never stored (the slot belongs to this call's kernel
//! frame only). The entry run must branch on `is_return` BEFORE
//! touching status: the return slot reads zeroed on entry. Cookie
//! values never leave the kernel except as opaque invocation ids on
//! edges (the cookie ADDRESS is never read, stored, or emitted).
//!
//! Counters (unchanged semantics): `LAGG` counts accepted edges per
//! hook (post-gate, pre-reserve — before the ring reserve, so
//! reserve failures count as accepted-but-untransported): after a
//! quiet drain with an empty close ring, `sum(LAGG) == consumed +
//! LLOSS_RESERVE + LLOSS_NOSLOT` exactly. Every counter lane is
//! single-writer by construction: per-CPU AND per-program (each hook
//! id has exactly one writer program-phase, and the kernel
//! per-program recursion guard serializes each program against
//! itself per CPU even across interrupts; an NMI reentry would
//! require the NMI path to call the traced function, which no NMI
//! path does).
//!
//! Twin: `crates/kryprobe-abi/src/kcrypto_lifecycle.rs` mirrors every
//! struct, enum value, and map dim byte-for-byte (deliberate
//! duplication across workspaces; the layout pins + privileged decode
//! suite fail on drift).
//!
//! Honest limitations (T07.2 profile scope):
//! - skcipher allocation only: `crypto_alloc_skcipher` entry/return
//!   is captured; release (`tfm_release`/final-free, T07.3) and
//!   aead/setkey/config (T07.4) are not.
//! - No lengths/flags capture (T08); op `aux` stays 0.
//! - No callback/completion observation (T09 adapters).
//! - Floor 7.0+: fsession attach refuses typed below it (no 6.x
//!   lifecycle; `api-returns` keeps its own contract).
//!
//! Privacy: the sensor reads argument pointers (pairing keys and
//! public algorithm/driver names only), the return register, the
//! config word, and the per-call cookie. It never touches keys, IVs,
//! plaintext, ciphertext, digests, request buffers, or cookie
//! addresses.
//!
//! Fail-closed gates: a wrong/missing `LCFG` magic disarms every
//! program (`LLOSS_DISABLED`, never silent); null keys feed
//! `LLOSS_BADKEY` (pre-accept, unagg'd — unreadable input never
//! counts as accepted); ring reserve failures feed `LLOSS_RESERVE`;
//! exhausted invocation ids feed `LLOSS_NOSLOT` (post-accept pure
//! drop, agg'd — the cookie stays zero and nothing emits, so the
//! exit reads a zero cookie and taints by construction: never a
//! wrapped id, never a phantom submit).
//!
//! Build constraints (R4: the xtask strip fails the build on ANY call
//! reloc, so this crate must be call-free):
//! - every helper is `#[inline(always)]` (a failure to inline is a loud
//!   compile error, not a silent call); this includes the return-value
//!   reader (aya's `FExitContext::ret` is NOT `inline(always)`, so the
//!   same logic is re-implemented below rather than trusted to inline);
//! - kfunc calls are sentinel immediates (`KFUNC_IS_RETURN_SENTINEL`,
//!   `KFUNC_COOKIE_SENTINEL`: plain `call imm` insns with NO
//!   relocations — the privileged loader rewrites each to
//!   `BPF_PSEUDO_KFUNC_CALL` with the vmlinux BTF id before load, and
//!   an unrewritten sentinel is refused by the verifier as a helper
//!   id out of range, never silently misbound);
//! - zeroing uses `volatile` stores (LLVM fuses plain zero chains into
//!   `memset` calls — spine precedent); varying-value stores are plain;
//! - no indexing (raw pointers + bounded `while` loops), no div/mod, no
//!   `panic!`/`unwrap!`/`expect`, no `static` data beyond the maps (the
//!   raw loader supports no `.rodata` map), no string literals or const
//!   arrays (only scalar consts, which lower to immediates).
//! - the floor is 7.0+: no pre-7.0 verifier workarounds are carried
//!   (the 5.17–6.7 scalar-link spill is gone; the VM matrix proves
//!   exit reads on 7.0.y and 7.2.y).

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::{bpf_get_func_ret, bpf_ktime_get_ns},
    macros::map,
    maps::{Array, PerCpuArray, RingBuf},
    programs::FEntryContext,
};
use core::ffi::c_void;
use core::mem::MaybeUninit;

// ---------------------------------------------------------------------------
// Twinned enum values (mirror: kryprobe-abi/src/kcrypto_lifecycle.rs)
// ---------------------------------------------------------------------------

const LEDGE_MAGIC: u16 = 0x434c;
const LEDGE_VERSION: u8 = 4;

const LEDGE_SUBMIT: u8 = 1;
const LEDGE_RETURN: u8 = 2;

const LEDGE_TAINTED: u16 = 0x0001;

const LSITE_ENC: u16 = 1;
const LSITE_DEC: u16 = 2;

const LTFM_MAGIC: u16 = 0x544c;
const LTFM_VERSION: u8 = 1;
const LTFM_SITE_ALLOC_SK: u16 = 1;
const LTFM_SITE_DESTROY: u16 = 2;
const LTFM_SITE_SETKEY_SK: u16 = 3;
const LTFM_SITE_SETAUTHSIZE: u16 = 4;
const LTFM_SITE_SETKEY_AEAD: u16 = 6;
const LTFM_TRUNCATED: u16 = 0x0002;

const LCONFIG_MAGIC: u32 = 0x3143_4c4b;
const LCONFIG_VERSION: u32 = 3;

const LLOSS_RESERVE: u32 = 0;
const LLOSS_DISABLED: u32 = 1;
const LLOSS_BADKEY: u32 = 2;
const LLOSS_FRET: u32 = 3;
const LLOSS_NOSLOT: u32 = 4;
/// `LLOSS` lanes per class: one per hook (BPF hook order: the 16
/// `LAGG_*` hooks, enc-sub first); the lane index doubles as the
/// hook id. Entry `class * LLOSS_LANES + hook`; userspace folds the
/// sixteen.
const LLOSS_LANES: u32 = 16;

const LAGG_ENC_SUB: u32 = 0;
const LAGG_ENC_RET: u32 = 1;
const LAGG_DEC_SUB: u32 = 2;
const LAGG_DEC_RET: u32 = 3;
const LAGG_ALLOCSK_SUB: u32 = 4;
const LAGG_ALLOCSK_RET: u32 = 5;
const LAGG_DESTROY_SUB: u32 = 6;
const LAGG_DESTROY_RET: u32 = 7;
const LAGG_SETKEYSK_SUB: u32 = 8;
const LAGG_SETKEYSK_RET: u32 = 9;
const LAGG_SETAUTH_SUB: u32 = 10;
const LAGG_SETAUTH_RET: u32 = 11;
const LAGG_SETKEYAEAD_SUB: u32 = 14;
const LAGG_SETKEYAEAD_RET: u32 = 15;

/// `LCTR` lane per site program: encrypt takes lane zero, decrypt
/// lane one, alloc-sk lane two, destroy lane three, setkey-sk lane
/// four, setauthsize lane five, setkey-aead lane six (lane seven
/// stays spare). The 3-bit lane field rides invocation bits 14–16,
/// so the independent sequences can never alias (a one-bit lane
/// would alias lane two onto the op lanes' sequence space).
const LCTR_ENC: u32 = 0;
const LCTR_DEC: u32 = 1;
const LCTR_ALLOCSK: u32 = 2;
const LCTR_DESTROY: u32 = 3;
const LCTR_SETKEYSK: u32 = 4;
const LCTR_SETAUTH: u32 = 5;
const LCTR_SETKEYAEAD: u32 = 6;

/// `ERR_PTR` floor: returns at or above `-4095` are errno failures
/// (`IS_ERR_VALUE` — never dereferenced, never chased).
const ERR_PTR_MIN: u64 = 0xFFFF_FFFF_FFFF_F001;

/// Session-kfunc call sentinels: `call imm` immediates with NO
/// relocations (R4-safe by construction). The privileged loader
/// rewrites each to `BPF_PSEUDO_KFUNC_CALL` + vmlinux BTF id before
/// load; the values collide with no real helper id (helpers are
/// small), so an unrewritten stub fails verifier load loudly.
/// `0x5F4B…` = "_K" marker + kfunc index.
const KFUNC_IS_RETURN_SENTINEL: usize = 0x5F4B_0001;
const KFUNC_COOKIE_SENTINEL: usize = 0x5F4B_0002;

// ---------------------------------------------------------------------------
// Twinned structs (mirror: kryprobe-abi/src/kcrypto_lifecycle.rs)
// ---------------------------------------------------------------------------

/// Raw lifecycle edge (48 bytes; field order pinned by ABI tests).
/// `tfm` is the frontend transform pointer behind the op
/// (`req->base->tfm` chased at the `LCFG` request-link words, minus
/// `sk_base` to the frontend — the tracker normalizes every pairing
/// pointer uniformly), 0 when the link was unreadable.
#[repr(C)]
struct LEdge {
    magic: u16,
    version: u8,
    edge: u8,
    site: u16,
    flags: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    aux: u32,
    invoc: u64,
    tfm: u64,
}

/// Sensor config (64 bytes, `LCFG` key 0): v3 adds the destroy
/// refcount words and the op request-link words to the v2 chase
/// offsets. Word order pinned by ABI tests.
#[repr(C)]
struct LConfig {
    magic: u32,
    version: u32,
    flags: u32,
    tfm_alg: u32,
    alg_drv: u32,
    sk_base: u32,
    refcnt_off: u32,
    refcnt_present: u32,
    req_base: u32,
    req_tfm: u32,
    reserved: [u8; 24],
}

/// Raw transform edge (112 bytes; field order pinned by ABI tests).
/// `reserved` names the alignment pad before `token` (bytes 36–39):
/// the emitter zeroes it per record (ring memory is uninitialized —
/// an unnamed gap would carry stale bytes through the transport).
#[repr(C)]
struct LTfm {
    magic: u16,
    version: u8,
    edge: u8,
    site: u16,
    flags: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    aux: u32,
    aux2: u32,
    reserved: u32,
    token: u64,
    name: [u8; 64],
}
const _: () = assert!(size_of::<LEdge>() == 48);
const _: () = assert!(size_of::<LConfig>() == 64);
const _: () = assert!(size_of::<LTfm>() == 112);

#[map]
static LCFG: Array<LConfig> = Array::with_max_entries(1, 0);
#[map]
static LRING: RingBuf = RingBuf::with_byte_size(262_144, 0);
#[map]
static LLOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5 * LLOSS_LANES, 0);
#[map]
static LAGG: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);
#[map]
static LCTR: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);

// ---------------------------------------------------------------------------
// Helpers (all #[inline(always)]: R4 call-free)
// ---------------------------------------------------------------------------

/// Session phase: true on the exit run, false on the entry run
/// (`bpf_session_is_return` kfunc via the loader-rewritten stub;
/// the context pointer passes through unchanged — `KF_ARG_PTR_TO_CTX`).
#[inline(always)]
fn session_is_return(ctx: *mut c_void) -> bool {
    // SAFETY: loader-rewritten kfunc stub (sentinel immediate, no
    // relocs); the context outlives the call by kernel contract.
    unsafe {
        let fun: unsafe extern "C" fn(*mut c_void) -> u64 =
            core::mem::transmute(KFUNC_IS_RETURN_SENTINEL);
        fun(ctx) != 0
    }
}

/// Per-call cookie slot (`bpf_session_cookie` kfunc via the
/// loader-rewritten stub). Re-fetched in every run, never stored:
/// the slot belongs to this call's kernel frame only. Zeroed by the
/// kernel before the entry run; a skipped entry leaves it zero.
#[inline(always)]
fn session_cookie(ctx: *mut c_void) -> *mut u64 {
    // SAFETY: loader-rewritten kfunc stub (sentinel immediate, no
    // relocs); the returned slot is this call's exclusive word.
    unsafe {
        let fun: unsafe extern "C" fn(*mut c_void) -> *mut u64 =
            core::mem::transmute(KFUNC_COOKIE_SENTINEL);
        fun(ctx)
    }
}

/// Read the traced function's return register (`bpf_get_func_ret`,
/// helper 184). `None` = helper refused (fail-closed by the caller
/// into `LLOSS_FRET`: an unclassified return is skipped, never
/// misbucketed).
///
/// Same logic as aya's `FExitContext::ret`, re-implemented
/// `#[inline(always)]` because aya's method is not and R4 fails the
/// build on any call reloc. The 5.17–6.7 scalar-link spill is gone:
/// the floor is 7.0+ and the VM matrix proves exit reads there.
#[inline(always)]
fn func_ret(ctx: *mut c_void) -> Option<u64> {
    let mut ret_val = 0u64;
    // SAFETY: helper with (ctx, out-pointer); `ret_val` is a live stack slot.
    let err = unsafe { bpf_get_func_ret(ctx, &raw mut ret_val) };
    if err == 0 { Some(ret_val) } else { None }
}

/// Bounded kernel string copy (`bpf_probe_read_kernel_str`, helper
/// 115). Re-implemented `#[inline(always)]` (same R4 rationale as
/// [`func_ret`]). Returns the helper's length-or-error: bytes copied
/// including the NUL when the string fit, `size` when the bound
/// filled, negative on fault.
#[inline(always)]
fn probe_read_str(dst: *mut u8, size: u32, src: *const c_void) -> i64 {
    // SAFETY: helper with (dst, size, src); `dst` is a live stack
    // buffer of `size` bytes, `src` a kernel string pointer.
    unsafe {
        let fun: unsafe extern "C" fn(*mut c_void, u32, *const c_void) -> i64 =
            core::mem::transmute(115usize);
        fun(dst.cast(), size, src)
    }
}

/// Fixed-width kernel read (`bpf_probe_read_kernel`, helper 113).
/// Re-implemented `#[inline(always)]` (same R4 rationale as
/// [`func_ret`]). `true` = all `size` bytes landed.
#[inline(always)]
fn probe_read(dst: *mut u8, size: u32, src: *const c_void) -> bool {
    // SAFETY: helper with (dst, size, src); `dst` is a live stack
    // slot of `size` bytes.
    unsafe {
        let fun: unsafe extern "C" fn(*mut c_void, u32, *const c_void) -> i64 =
            core::mem::transmute(113usize);
        fun(dst.cast(), size, src) == 0
    }
}

/// Name field width: 63 bytes + NUL (the wire bound).
const NAME_LEN: usize = 64;

/// 8-aligned stack name slot: `zero_name` and the emitter's copy
/// loop use `u64` volatile accesses, which require 8-byte alignment
/// a bare `[u8; 64]` does not guarantee (D2: byte-aligned storage +
/// word accesses is instant UB, even when the backend happens to
/// over-align the slot).
#[repr(C, align(8))]
struct NameSlot([u8; NAME_LEN]);

/// Zero a stack name slot through volatile 8-byte stores (plain
/// zero chains fuse into `memset` calls and break R4; volatile
/// stores never fuse). Raw-slot writes only — sound on
/// uninitialized slots (the spine `MaybeUninit` idiom: callers hold
/// an uninit slot, zero it here, and borrow it only after). The
/// `NameSlot` parameter (not a bare array) carries the 8-alignment
/// the word stores need — callers cannot pass a byte-aligned buffer
/// by construction (D2 type-level fix).
#[inline(always)]
fn zero_name(slot: *mut NameSlot) {
    let mut i = 0usize;
    while i < NAME_LEN {
        unsafe {
            (slot.cast::<u8>().add(i) as *mut u64).write_volatile(0);
        }
        i += 8;
    }
}

/// Bounded-copy the kernel string at `src` into `slot` (pre-zeroed
/// by the caller — a fault must leave empty/unknown, never stack
/// garbage). Returns true when the bound filled (`TRUNCATED` —
/// conservatively set even for an exact-63 fit, which is
/// indistinguishable from a longer string; the flag claims less
/// certainty, never more). A null `src` or a fault re-zeroes the
/// slot and reports untruncated: missing provenance is unknown,
/// never fabricated, never dropped.
#[inline(always)]
fn copy_name(slot: *mut NameSlot, src: u64) -> bool {
    // SAFETY: pre-zeroed by contract (fully initialized); exclusive
    // stack slot.
    let buf = unsafe { &mut (*slot).0 };
    if src == 0 {
        zero_name(slot);
        return false;
    }
    let ret = probe_read_str(buf.as_mut_ptr(), NAME_LEN as u32, src as *const c_void);
    if ret < 0 || ret > NAME_LEN as i64 {
        zero_name(slot);
        return false;
    }
    if ret == NAME_LEN as i64 {
        // The bound filled: force the terminator (the copy may not
        // have written one) and flag truncation.
        buf[NAME_LEN - 1] = 0;
        return true;
    }
    false
}

/// Chase offsets for the driver-name read (`LCFG` words 12/16/20 —
/// volatile reads, copied once like [`cfg_armed`]).
#[inline(always)]
fn chase_offsets() -> (u32, u32, u32) {
    let Some(cfg) = LCFG.get(0) else {
        return (0, 0, 0);
    };
    let tfm_alg = unsafe { core::ptr::addr_of!(cfg.tfm_alg).read_volatile() };
    let alg_drv = unsafe { core::ptr::addr_of!(cfg.alg_drv).read_volatile() };
    let sk_base = unsafe { core::ptr::addr_of!(cfg.sk_base).read_volatile() };
    (tfm_alg, alg_drv, sk_base)
}

/// Resolve the driver name for a freshly allocated frontend `tfm`:
/// `(tfm + sk_base)->__crt_alg->cra_driver_name` at the
/// `LCFG`-pinned offsets, bounded-copied into `slot`. The frontend
/// is a `struct crypto_skcipher *`, NOT a `struct crypto_tfm *` —
/// the embedded base sits at `sk_base` (8 on 64-bit: `reqsize` +
/// alignment padding), and `__crt_alg` is relative to THAT (T07.2d:
/// chasing `tfm + tfm_alg` reads the `exit` callback slot and copies
/// kernel code bytes as the "name"). Any unreadable link
/// (null/out-of-range pointer, faulted read) leaves the slot
/// empty/unknown: missing provenance is unknown, never fabricated.
/// Returns the truncation flag for the resolved name.
#[inline(always)]
fn chase_drv_name(slot: *mut NameSlot, tfm: u64) -> bool {
    // Pre-zero: every early return below must leave empty/unknown.
    zero_name(slot);
    if tfm == 0 {
        return false;
    }
    let (tfm_alg, alg_drv, sk_base) = chase_offsets();
    let Some(base_at) = tfm.checked_add(u64::from(sk_base)) else {
        return false;
    };
    let Some(alg_at) = base_at.checked_add(u64::from(tfm_alg)) else {
        return false;
    };
    let mut alg: u64 = 0;
    if !probe_read(
        core::ptr::addr_of_mut!(alg).cast(),
        8,
        alg_at as *const c_void,
    ) || alg == 0
    {
        return false;
    }
    let Some(name_at) = alg.checked_add(u64::from(alg_drv)) else {
        return false;
    };
    copy_name(slot, name_at)
}

/// Request-link offsets (`LCFG` words 32/36 + `sk_base` — volatile
/// reads, copied once like [`chase_offsets`]). Only read on armed
/// runs (the prologues gate first): on a missing map the zeros
/// would fabricate a chase, so callers never run disarmed.
#[inline(always)]
fn req_link_offsets() -> (u32, u32, u32) {
    let Some(cfg) = LCFG.get(0) else {
        return (0, 0, 0);
    };
    let req_base = unsafe { core::ptr::addr_of!(cfg.req_base).read_volatile() };
    let req_tfm = unsafe { core::ptr::addr_of!(cfg.req_tfm).read_volatile() };
    let sk_base = unsafe { core::ptr::addr_of!(cfg.sk_base).read_volatile() };
    (req_base, req_tfm, sk_base)
}

/// Resolve the frontend transform behind an op request: `req` +
/// `req_base` is the embedded `crypto_async_request`, whose `tfm`
/// member names the BASE (`__crypto_skcipher_cast` inverts it) —
/// subtract `sk_base` to the frontend so EVERY pairing pointer the
/// tracker sees is a frontend (uniform normalization: op-first and
/// alloc-first observations of one transform meet at one identity).
/// Any unreadable link (null request, overflowed arithmetic, faulted
/// read, null tfm, underflowed subtraction) yields 0: unknown, never
/// fabricated — the op still joins by invocation.
#[inline(always)]
fn chase_req_tfm(req: u64) -> u64 {
    if req == 0 {
        return 0;
    }
    let (req_base, req_tfm, sk_base) = req_link_offsets();
    let Some(base_at) = req.checked_add(u64::from(req_base)) else {
        return 0;
    };
    let Some(tfm_at) = base_at.checked_add(u64::from(req_tfm)) else {
        return 0;
    };
    let mut base: u64 = 0;
    if !probe_read(
        core::ptr::addr_of_mut!(base).cast(),
        8,
        tfm_at as *const c_void,
    ) || base == 0
    {
        return 0;
    }
    base.saturating_sub(u64::from(sk_base))
}

/// Refcount words (`LCFG` 24/28 — volatile reads, copied once).
#[inline(always)]
fn refcnt_words() -> (u32, u32) {
    let Some(cfg) = LCFG.get(0) else {
        return (0, 0);
    };
    let off = unsafe { core::ptr::addr_of!(cfg.refcnt_off).read_volatile() };
    let present = unsafe { core::ptr::addr_of!(cfg.refcnt_present).read_volatile() };
    (off, present)
}

/// Read the destroy-entry refcount: `tfm` (arg1, already the base) +
/// `refcnt_off`, when the kernel carries the field. Returns (value,
/// observed): unobserved on an absent field, a non-1 presence word
/// (corruption reads as absent — the tracker fails closed on
/// unobserved), null tfm, overflowed arithmetic, or faulted read.
#[inline(always)]
fn read_refcnt(tfm: u64) -> (u32, u32) {
    let (off, present) = refcnt_words();
    if present != 1 || tfm == 0 {
        return (0, 0);
    }
    let Some(at) = tfm.checked_add(u64::from(off)) else {
        return (0, 0);
    };
    let mut val: u32 = 0;
    if !probe_read(core::ptr::addr_of_mut!(val).cast(), 4, at as *const c_void) {
        return (0, 0);
    }
    (val, 1)
}

/// Config gate: true only when magic+version match exactly and no
/// unknown flag is set (an unwritten/zeroed `LCFG` disarms the sensor
/// — fail closed).
#[inline(always)]
fn cfg_armed() -> bool {
    let Some(cfg) = LCFG.get(0) else {
        return false;
    };
    // Volatile reads: the map value may change under us; copy once.
    let magic = unsafe { core::ptr::addr_of!(cfg.magic).read_volatile() };
    let version = unsafe { core::ptr::addr_of!(cfg.version).read_volatile() };
    let flags = unsafe { core::ptr::addr_of!(cfg.flags).read_volatile() };
    magic == LCONFIG_MAGIC && version == LCONFIG_VERSION && flags == 0
}

/// Saturating loss bump (current CPU's lane FOR THIS HOOK —
/// `class * LLOSS_LANES + hook` — exclusive: per-CPU plus
/// per-program, since an interrupt can run a different program on
/// this CPU mid-bump. Callers pass their `LAGG_*` hook id).
#[inline(always)]
fn loss_inc(class: u32, hook: u32) {
    if let Some(slot) = LLOSS.get_ptr_mut(class * LLOSS_LANES + hook) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Saturating per-CPU accepted-edge bump (post-gate, pre-reserve: an
/// accepted edge that the ring cannot take still counts here AND in
/// `LLOSS_RESERVE` — the canary reconciles the two). Already
/// per-program: each hook id has exactly one writer program-phase,
/// so the lane is exclusive (same kernel-guard argument as `LCTR`).
#[inline(always)]
fn agg_inc(idx: u32) {
    if let Some(slot) = LAGG.get_ptr_mut(idx) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Emit one edge record: reserve 48 bytes, fill every field, submit.
/// Reserve failure feeds `LLOSS_RESERVE` (never silent).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn emit_edge(
    site: u16,
    edge: u8,
    key: u64,
    now: u64,
    status: i32,
    tainted: bool,
    invoc: u64,
    tfm: u64,
    hook: u32,
) {
    let Some(mut entry) = LRING.reserve::<LEdge>(0) else {
        loss_inc(LLOSS_RESERVE, hook);
        return;
    };
    // Slot init through the entry deref (spine discipline): every field
    // written before submit; zero fields via volatile stores (plain
    // zero chains fuse into `memset` calls and break R4).
    let slot: &mut MaybeUninit<LEdge> = &mut entry;
    let ptr = slot.as_mut_ptr();
    let flags: u16 = if tainted { LEDGE_TAINTED } else { 0 };
    unsafe {
        core::ptr::addr_of_mut!((*ptr).magic).write(LEDGE_MAGIC);
        core::ptr::addr_of_mut!((*ptr).version).write(LEDGE_VERSION);
        core::ptr::addr_of_mut!((*ptr).edge).write(edge);
        core::ptr::addr_of_mut!((*ptr).site).write(site);
        core::ptr::addr_of_mut!((*ptr).flags).write(flags);
        core::ptr::addr_of_mut!((*ptr).key).write(key);
        core::ptr::addr_of_mut!((*ptr).ts_ns).write(now);
        core::ptr::addr_of_mut!((*ptr).status).write(status);
        core::ptr::addr_of_mut!((*ptr).aux).write_volatile(0);
        core::ptr::addr_of_mut!((*ptr).invoc).write(invoc);
        // Volatile: the chased frontend is data-dependent but
        // zero-heavy (unreadable links, null tfms) at the record
        // tail — a plain store here fuses into a `memset` call
        // under inlining (T07.2d R4 lesson); volatile never fuses.
        core::ptr::addr_of_mut!((*ptr).tfm).write_volatile(tfm);
    }
    entry.submit(0);
}

/// Emit one transform edge record: reserve 112 bytes, fill every
/// field, submit. Reserve failure feeds `LLOSS_RESERVE` (never
/// silent). `name` copies from the caller's 8-aligned `NameSlot`
/// through volatile 8-byte loads (the stack source may be
/// known-zero — plain loads would fuse into a `memset` call, an R4
/// break) and plain 8-byte stores into the reserved record.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn emit_tfm_edge(
    site: u16,
    edge: u8,
    key: u64,
    now: u64,
    status: i32,
    aux: u32,
    aux2: u32,
    tainted: bool,
    truncated: bool,
    token: u64,
    name: &NameSlot,
    hook: u32,
) {
    let Some(mut entry) = LRING.reserve::<LTfm>(0) else {
        loss_inc(LLOSS_RESERVE, hook);
        return;
    };
    let slot: &mut MaybeUninit<LTfm> = &mut entry;
    let ptr = slot.as_mut_ptr();
    let mut flags: u16 = 0;
    if tainted {
        flags |= LEDGE_TAINTED;
    }
    if truncated {
        flags |= LTFM_TRUNCATED;
    }
    unsafe {
        core::ptr::addr_of_mut!((*ptr).magic).write(LTFM_MAGIC);
        core::ptr::addr_of_mut!((*ptr).version).write(LTFM_VERSION);
        core::ptr::addr_of_mut!((*ptr).edge).write(edge);
        core::ptr::addr_of_mut!((*ptr).site).write(site);
        core::ptr::addr_of_mut!((*ptr).flags).write(flags);
        core::ptr::addr_of_mut!((*ptr).key).write(key);
        core::ptr::addr_of_mut!((*ptr).ts_ns).write(now);
        // Volatile: the success path folds status/aux/aux2 to 0, and
        // four adjacent constant-zero stores fuse into a `memset`
        // call — an R4 break (same discipline as `emit_edge`'s aux).
        // Volatile stores never fuse; non-constant values (entry
        // type/mask, failure errno) store identically.
        core::ptr::addr_of_mut!((*ptr).status).write_volatile(status);
        core::ptr::addr_of_mut!((*ptr).aux).write_volatile(aux);
        core::ptr::addr_of_mut!((*ptr).aux2).write_volatile(aux2);
        core::ptr::addr_of_mut!((*ptr).reserved).write_volatile(0);
        core::ptr::addr_of_mut!((*ptr).token).write(token);
        let mut i = 0usize;
        while i < NAME_LEN {
            // Volatile loads: the stack source may be known-zero (the
            // failure path zeroes but never fills it), and plain
            // loads let LLVM fuse the copy into a `memset` call —
            // an R4 break. Volatile loads are opaque, so the copy
            // survives as loads + stores.
            let word = (name.0.as_ptr().add(i) as *const u64).read_volatile();
            (core::ptr::addr_of_mut!((*ptr).name).cast::<u8>().add(i) as *mut u64).write(word);
            i += 8;
        }
    }
    entry.submit(0);
}

/// Current CPU number (`bpf_get_smp_processor_id`, helper 8).
/// Re-implemented `#[inline(always)]` (same R4 rationale as
/// [`func_ret`]: the generated aya binding carries no inline
/// attribute and outlines into a call reloc).
#[inline(always)]
fn cpu_id() -> u32 {
    // SAFETY: helper with no pointer arguments (id 8, all kernels).
    unsafe {
        let fun: unsafe extern "C" fn() -> u32 = core::mem::transmute(8usize);
        fun()
    }
}

/// CPU tag width: 13 bits cover 8192 CPUs (the x86-64 `NR_CPUS`
/// ceiling); ids from higher-numbered CPUs refuse loudly rather
/// than alias.
const INVOC_CPU_BITS: u32 = 13;
/// CPUs covered by the tag (`1 << 13`).
const INVOC_CPU_MAX: u32 = 1 << INVOC_CPU_BITS;
/// Program-lane field width: 3 bits cover the 8 site-program lanes
/// (op lanes 0–1, alloc-sk lane 2, T07.3/T07.4 lanes 3–7).
const INVOC_LANE_BITS: u32 = 3;
/// Highest lane the field covers.
const INVOC_LANE_MAX: u32 = 1 << INVOC_LANE_BITS;
/// Lane-field shift: past the reserved bit 0 + the cpu tag.
const INVOC_LANE_SHIFT: u32 = 1 + INVOC_CPU_BITS;
/// Sequence shift: past reserved bit + cpu tag + lane field.
const INVOC_SEQ_SHIFT: u32 = 1 + INVOC_CPU_BITS + INVOC_LANE_BITS;
/// Per-program per-CPU sequence ceiling: 47 bits (ids stay in 64
/// bits with tag + lane field + reserved bit).
const INVOC_SEQ_MAX: u64 = (1 << (64 - INVOC_SEQ_SHIFT)) - 1;

/// Take the next invocation id: `(per-program per-CPU sequence <<
/// 17) | (lane << 14) | (cpu << 1)` (bit 0 reserved + always
/// clear). The sequence lane is this CPU's cell FOR THIS PROGRAM
/// (non-atomic bump, exclusive: per-CPU via `migrate_disable`,
/// per-program via the kernel per-program recursion guard, which
/// serializes each program against itself per CPU even across
/// interrupts; an NMI reentry would require the NMI path to call
/// the traced function, which no NMI path does). The cpu tag keeps
/// ids distinct across CPUs, the lane field across the site
/// programs. 0 is never issued (it means "no invocation" on
/// slotless edges). `None` = the lane is uncovered, the cpu tag
/// overflowed, the sequence saturated, or the map lookup failed —
/// the caller refuses the submit through the NOSLOT path (never a
/// wrapped/aliased id).
#[inline(always)]
fn invoc_next(lane: u32) -> Option<u64> {
    if lane >= INVOC_LANE_MAX {
        return None;
    }
    let cpu = cpu_id();
    if cpu >= INVOC_CPU_MAX {
        return None;
    }
    let slot = LCTR.get_ptr_mut(lane)?;
    // SAFETY: per-CPU per-program lane pointer from a checked
    // lookup; this program's exclusive cell on this CPU (see
    // above), so plain RMW is exact — no lost update, no reuse.
    let seq = unsafe {
        let prev = *slot;
        if prev >= INVOC_SEQ_MAX {
            return None;
        }
        *slot = prev + 1;
        prev + 1
    };
    Some((seq << INVOC_SEQ_SHIFT) | (u64::from(lane) << INVOC_LANE_SHIFT) | (u64::from(cpu) << 1))
}

/// Shared run prologue: config gate + null-key gate. Returns the
/// timestamp on success; counts the refusal class and returns `None`
/// otherwise.
#[inline(always)]
fn run_prologue(key: u64, hook: u32) -> Option<u64> {
    if !cfg_armed() {
        loss_inc(LLOSS_DISABLED, hook);
        return None;
    }
    if key == 0 {
        loss_inc(LLOSS_BADKEY, hook);
        return None;
    }
    // SAFETY: helper with no pointer arguments.
    Some(unsafe { bpf_ktime_get_ns() })
}

/// One site's session program (shared by encrypt/decrypt bodies):
/// entry run issues the invocation into the cookie and emits the
/// submit; exit run reads the cookie back and emits the return.
/// `lane`/`site`/`sub_hook`/`ret_hook` pin the caller's identity.
#[inline(always)]
fn site_run(ctx: &FEntryContext, lane: u32, site: u16, sub_hook: u32, ret_hook: u32) -> i32 {
    let raw = ctx.as_ptr();
    let key: u64 = ctx.arg(0);
    if session_is_return(raw) {
        // ---- exit run: pair by cookie, never by address ----
        let Some(now) = run_prologue(key, ret_hook) else {
            return 0;
        };
        // Re-fetch the cookie in this run (never stored): a zero
        // cookie means the entry run never executed (guard skip) —
        // emit TAINTED with id 0 instead of joining another call.
        let invoc = unsafe { *session_cookie(raw) };
        if invoc == 0 {
            agg_inc(ret_hook);
            // Tainted by invocation (no id) — but the request link
            // still chases: taint never hides the transform.
            let tfm = chase_req_tfm(key);
            emit_edge(site, LEDGE_RETURN, key, now, 0, true, 0, tfm, ret_hook);
            return 0;
        }
        let Some(ret) = func_ret(raw) else {
            // The call exited without a readable status: a pre-accept
            // drop (unagg'd, like BADKEY — unreadable input never
            // counts as accepted), so the FRET loss counts it and the
            // reconciliation equation is untouched.
            loss_inc(LLOSS_FRET, ret_hook);
            return 0;
        };
        agg_inc(ret_hook);
        let tfm = chase_req_tfm(key);
        emit_edge(
            site,
            LEDGE_RETURN,
            key,
            now,
            ret as i32,
            false,
            invoc,
            tfm,
            ret_hook,
        );
        return 0;
    }
    // ---- entry run: issue the invocation into the cookie ----
    let Some(now) = run_prologue(key, sub_hook) else {
        return 0;
    };
    agg_inc(sub_hook);
    let Some(invoc) = invoc_next(lane) else {
        // No invocation id (cpu/sequence bound or map failure): a
        // post-accept drop (agg'd — accepted-but-untransported, the
        // equation's NOSLOT term). The cookie stays zero and nothing
        // emits, so the exit run taints by construction (never a
        // wrapped id, never a phantom submit).
        loss_inc(LLOSS_NOSLOT, sub_hook);
        return 0;
    };
    unsafe {
        *session_cookie(raw) = invoc;
    }
    let tfm = chase_req_tfm(key);
    emit_edge(site, LEDGE_SUBMIT, key, now, 0, false, invoc, tfm, sub_hook);
    0
}

/// Shared run prologue for the transform programs (alloc AND
/// destroy): the config gate plus the timestamp. Unlike
/// [`run_prologue`] there is no null-key gate: a null/unreadable
/// name admits as empty/unknown (the attempt token, not the name,
/// is the pairing key), and a null/ERR destroy `mem` emits as a
/// classified no-op release (observed, never dropped).
#[inline(always)]
fn alloc_prologue(hook: u32) -> Option<u64> {
    if !cfg_armed() {
        loss_inc(LLOSS_DISABLED, hook);
        return None;
    }
    // SAFETY: helper with no pointer arguments.
    Some(unsafe { bpf_ktime_get_ns() })
}

/// The `crypto_alloc_skcipher` session program: entry run mints the
/// attempt token into the cookie and emits the submit (requested
/// name + type + mask); exit run classifies the return BEFORE
/// dereference and emits the return (frontend pointer + resolved
/// driver name on success, errno + empty name on ERR_PTR failure).
/// A zero cookie (skipped entry) emits TAINTED with token 0 and the
/// real classification — twin-valid shapes the tracker refuses
/// quietly, so an unpaired exit disturbs no outstanding attempt.
#[inline(always)]
fn alloc_run(ctx: &FEntryContext) -> i32 {
    let raw = ctx.as_ptr();
    if session_is_return(raw) {
        // ---- exit run: classify, then pair by cookie ----
        let Some(now) = alloc_prologue(LAGG_ALLOCSK_RET) else {
            return 0;
        };
        let Some(ret) = func_ret(raw) else {
            loss_inc(LLOSS_FRET, LAGG_ALLOCSK_RET);
            return 0;
        };
        // Re-fetch the cookie in this run (never stored).
        let token = unsafe { *session_cookie(raw) };
        if ret == 0 {
            // Neither success-ptr nor ERR_PTR: unclassifiable (no
            // honest kernel produces it) — a pre-accept drop
            // (unagg'd, like BADKEY), never a fabricated errno.
            loss_inc(LLOSS_FRET, LAGG_ALLOCSK_RET);
            return 0;
        }
        agg_inc(LAGG_ALLOCSK_RET);
        if ret >= ERR_PTR_MIN {
            // ERR_PTR failure: errno status, zero key, zeroed name —
            // classified, never dereferenced, never chased.
            let mut slot = MaybeUninit::<NameSlot>::uninit();
            // The pointer stays typed as *mut NameSlot, so word
            // accesses keep their 8-alignment by construction (D2).
            let raw_slot = slot.as_mut_ptr();
            zero_name(raw_slot);
            // SAFETY: volatile-zeroed above; exclusive stack slot.
            let name = unsafe { &*raw_slot };
            emit_tfm_edge(
                LTFM_SITE_ALLOC_SK,
                LEDGE_RETURN,
                0,
                now,
                ret as i32,
                0,
                0,
                token == 0,
                false,
                token,
                name,
                LAGG_ALLOCSK_RET,
            );
            return 0;
        }
        // Success: frontend pointer + resolved driver name (an
        // unreadable chase admits as empty/unknown).
        let mut slot = MaybeUninit::<NameSlot>::uninit();
        // The pointer stays typed as *mut NameSlot, so word
        // accesses keep their 8-alignment by construction (D2).
        let raw_slot = slot.as_mut_ptr();
        let truncated = chase_drv_name(raw_slot, ret);
        // SAFETY: `chase_drv_name` leaves the slot fully initialized
        // on every path (zeroed, then helper-overwritten in part).
        let name = unsafe { &*raw_slot };
        emit_tfm_edge(
            LTFM_SITE_ALLOC_SK,
            LEDGE_RETURN,
            ret,
            now,
            0,
            0,
            0,
            token == 0,
            truncated,
            token,
            name,
            LAGG_ALLOCSK_RET,
        );
        return 0;
    }
    // ---- entry run: mint the token, copy the request ----
    let Some(now) = alloc_prologue(LAGG_ALLOCSK_SUB) else {
        return 0;
    };
    agg_inc(LAGG_ALLOCSK_SUB);
    let Some(token) = invoc_next(LCTR_ALLOCSK) else {
        // No attempt token: post-accept drop (agg'd NOSLOT — the
        // cookie stays zero and nothing emits, so the exit taints
        // by construction, exactly like the op path).
        loss_inc(LLOSS_NOSLOT, LAGG_ALLOCSK_SUB);
        return 0;
    };
    unsafe {
        *session_cookie(raw) = token;
    }
    let mut slot = MaybeUninit::<NameSlot>::uninit();
    // The pointer stays typed as *mut NameSlot, so word
    // accesses keep their 8-alignment by construction (D2).
    let raw_slot = slot.as_mut_ptr();
    zero_name(raw_slot);
    let truncated = copy_name(raw_slot, ctx.arg(0));
    // SAFETY: volatile-zeroed above; `copy_name` keeps the slot
    // fully initialized on every path (zeroed, then
    // helper-overwritten in part).
    let name = unsafe { &*raw_slot };
    emit_tfm_edge(
        LTFM_SITE_ALLOC_SK,
        LEDGE_SUBMIT,
        0,
        now,
        0,
        ctx.arg::<u64>(1) as u32,
        ctx.arg::<u64>(2) as u32,
        false,
        truncated,
        token,
        name,
        LAGG_ALLOCSK_SUB,
    );
    0
}

/// The `crypto_destroy_tfm` session program (T07.3): entry run
/// mints the attempt token into the cookie and emits the submit
/// (frontend `mem` + refcount value/observed); exit run emits the
/// bare return (token only — the call returns void, so NO status
/// read and NO arg re-read: reading either would emit garbage as
/// truth; the token joins to the parked entry, same discipline as
/// alloc returns not repeating names). A zero cookie (skipped
/// entry) emits TAINTED with token 0 and the exit taints by
/// construction, exactly like the alloc path.
#[inline(always)]
fn destroy_run(ctx: &FEntryContext) -> i32 {
    let raw = ctx.as_ptr();
    if session_is_return(raw) {
        // ---- exit run: complete by cookie ----
        let Some(now) = alloc_prologue(LAGG_DESTROY_RET) else {
            return 0;
        };
        let token = unsafe { *session_cookie(raw) };
        agg_inc(LAGG_DESTROY_RET);
        let mut slot = MaybeUninit::<NameSlot>::uninit();
        // The pointer stays typed as *mut NameSlot, so word
        // accesses keep their 8-alignment by construction (D2).
        let raw_slot = slot.as_mut_ptr();
        zero_name(raw_slot);
        // SAFETY: volatile-zeroed above; exclusive stack slot.
        let name = unsafe { &*raw_slot };
        emit_tfm_edge(
            LTFM_SITE_DESTROY,
            LEDGE_RETURN,
            0,
            now,
            0,
            0,
            0,
            token == 0,
            false,
            token,
            name,
            LAGG_DESTROY_RET,
        );
        return 0;
    }
    // ---- entry run: mint the token, snapshot mem + refcount ----
    let Some(now) = alloc_prologue(LAGG_DESTROY_SUB) else {
        return 0;
    };
    agg_inc(LAGG_DESTROY_SUB);
    let Some(token) = invoc_next(LCTR_DESTROY) else {
        // No attempt token: post-accept drop (agg'd NOSLOT — the
        // cookie stays zero and nothing emits, so the exit taints
        // by construction, exactly like the alloc path).
        loss_inc(LLOSS_NOSLOT, LAGG_DESTROY_SUB);
        return 0;
    };
    unsafe {
        *session_cookie(raw) = token;
    }
    let mem: u64 = ctx.arg(0);
    let tfm: u64 = ctx.arg(1);
    let (refcnt, observed) = read_refcnt(tfm);
    let mut slot = MaybeUninit::<NameSlot>::uninit();
    // The pointer stays typed as *mut NameSlot, so word
    // accesses keep their 8-alignment by construction (D2).
    let raw_slot = slot.as_mut_ptr();
    zero_name(raw_slot);
    // SAFETY: volatile-zeroed above; exclusive stack slot.
    let name = unsafe { &*raw_slot };
    emit_tfm_edge(
        LTFM_SITE_DESTROY,
        LEDGE_SUBMIT,
        mem,
        now,
        0,
        refcnt,
        observed,
        false,
        false,
        token,
        name,
        LAGG_DESTROY_SUB,
    );
    0
}

/// The configuration session program (T07.4), parametrized by
/// site, token lane, agg lanes, and the length-argument index
/// (`len_arg`: 2 for the setkey sites' `keylen`, 1 for
/// setauthsize's `authsize`): entry run mints the attempt token
/// into the cookie and emits the submit (frontend arg0 + scalar
/// length); exit run reads the errno return and emits the return
/// (errno + token; every other word zero). ZERO pointer
/// dereferences on this path — every word is an argument register
/// or the return register; the key buffer (setkey arg1) is not
/// named in any read. A zero cookie (skipped entry) emits TAINTED
/// with token 0 and the real errno — twin-valid shapes the
/// tracker refuses quietly, so an unpaired exit disturbs no
/// outstanding attempt.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn config_run(
    ctx: &FEntryContext,
    site: u16,
    lane: u32,
    sub: u32,
    ret: u32,
    len_arg: usize,
) -> i32 {
    let raw = ctx.as_ptr();
    if session_is_return(raw) {
        // ---- exit run: errno, then pair by cookie ----
        let Some(now) = alloc_prologue(ret) else {
            return 0;
        };
        let Some(errno) = func_ret(raw) else {
            loss_inc(LLOSS_FRET, ret);
            return 0;
        };
        let token = unsafe { *session_cookie(raw) };
        agg_inc(ret);
        let mut slot = MaybeUninit::<NameSlot>::uninit();
        // The pointer stays typed as *mut NameSlot, so word
        // accesses keep their 8-alignment by construction (D2).
        let raw_slot = slot.as_mut_ptr();
        zero_name(raw_slot);
        // SAFETY: volatile-zeroed above; exclusive stack slot.
        let name = unsafe { &*raw_slot };
        emit_tfm_edge(
            site,
            LEDGE_RETURN,
            0,
            now,
            errno as i32,
            0,
            0,
            token == 0,
            false,
            token,
            name,
            ret,
        );
        return 0;
    }
    // ---- entry run: mint the token, snapshot frontend + length ----
    let Some(now) = alloc_prologue(sub) else {
        return 0;
    };
    agg_inc(sub);
    let Some(token) = invoc_next(lane) else {
        // No attempt token: post-accept drop (agg'd NOSLOT — the
        // cookie stays zero and nothing emits, so the exit taints
        // by construction, exactly like the alloc path).
        loss_inc(LLOSS_NOSLOT, sub);
        return 0;
    };
    unsafe {
        *session_cookie(raw) = token;
    }
    let tfm: u64 = ctx.arg(0);
    let len: u64 = ctx.arg(len_arg);
    let mut slot = MaybeUninit::<NameSlot>::uninit();
    // The pointer stays typed as *mut NameSlot, so word
    // accesses keep their 8-alignment by construction (D2).
    let raw_slot = slot.as_mut_ptr();
    zero_name(raw_slot);
    // SAFETY: volatile-zeroed above; exclusive stack slot.
    let name = unsafe { &*raw_slot };
    emit_tfm_edge(
        site,
        LEDGE_SUBMIT,
        tfm,
        now,
        0,
        len as u32,
        0,
        false,
        false,
        token,
        name,
        sub,
    );
    0
}

// ---------------------------------------------------------------------------
// Programs (one fsession link per site; section names pinned by the manifest)
// ---------------------------------------------------------------------------

/// `crypto_skcipher_encrypt(req)` session: submit at entry, paired
/// return at exit, joined by the kernel-zeroed cookie.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fsession/crypto_skcipher_encrypt")]
pub fn lc_enc(ctx: *mut c_void) -> i32 {
    let ctx = FEntryContext::new(ctx);
    site_run(&ctx, LCTR_ENC, LSITE_ENC, LAGG_ENC_SUB, LAGG_ENC_RET)
}

/// `crypto_skcipher_decrypt(req)` session: submit at entry, paired
/// return at exit, joined by the kernel-zeroed cookie.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fsession/crypto_skcipher_decrypt")]
pub fn lc_dec(ctx: *mut c_void) -> i32 {
    let ctx = FEntryContext::new(ctx);
    site_run(&ctx, LCTR_DEC, LSITE_DEC, LAGG_DEC_SUB, LAGG_DEC_RET)
}

/// `crypto_alloc_skcipher(alg_name, type, mask)` session: submit at
/// entry (requested name + type + mask + fresh attempt token),
/// classified return at exit (frontend pointer + driver name, or
/// errno), joined by the kernel-zeroed cookie.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fsession/crypto_alloc_skcipher")]
pub fn lc_alloc(ctx: *mut c_void) -> i32 {
    let ctx = FEntryContext::new(ctx);
    alloc_run(&ctx)
}

/// `crypto_destroy_tfm(mem, tfm)` session: submit at entry
/// (frontend + refcount snapshot + fresh attempt token), bare
/// return at exit (token only — void call), joined by the
/// kernel-zeroed cookie.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fsession/crypto_destroy_tfm")]
pub fn lc_destroy(ctx: *mut c_void) -> i32 {
    let ctx = FEntryContext::new(ctx);
    destroy_run(&ctx)
}

/// `crypto_skcipher_setkey(tfm, key, keylen)` session: submit at
/// entry (frontend + key LENGTH + fresh attempt token — the key
/// buffer is never read), errno return at exit, joined by the
/// kernel-zeroed cookie.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fsession/crypto_skcipher_setkey")]
pub fn lc_setkey_sk(ctx: *mut c_void) -> i32 {
    let ctx = FEntryContext::new(ctx);
    config_run(
        &ctx,
        LTFM_SITE_SETKEY_SK,
        LCTR_SETKEYSK,
        LAGG_SETKEYSK_SUB,
        LAGG_SETKEYSK_RET,
        2,
    )
}

/// `crypto_aead_setauthsize(tfm, authsize)` session: submit at
/// entry (frontend + authsize + fresh attempt token), errno
/// return at exit, joined by the kernel-zeroed cookie.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fsession/crypto_aead_setauthsize")]
pub fn lc_setauthsize(ctx: *mut c_void) -> i32 {
    let ctx = FEntryContext::new(ctx);
    config_run(
        &ctx,
        LTFM_SITE_SETAUTHSIZE,
        LCTR_SETAUTH,
        LAGG_SETAUTH_SUB,
        LAGG_SETAUTH_RET,
        1,
    )
}

/// `crypto_aead_setkey(tfm, key, keylen)` session: submit at entry
/// (frontend + key LENGTH + fresh attempt token — the key buffer
/// is never read), errno return at exit, joined by the
/// kernel-zeroed cookie.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fsession/crypto_aead_setkey")]
pub fn lc_setkey_aead(ctx: *mut c_void) -> i32 {
    let ctx = FEntryContext::new(ctx);
    config_run(
        &ctx,
        LTFM_SITE_SETKEY_AEAD,
        LCTR_SETKEYAEAD,
        LAGG_SETKEYAEAD_SUB,
        LAGG_SETKEYAEAD_RET,
        2,
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

/// Kernel license marker: this object is GPL-2.0-only BPF (kfunc
/// calls require a GPL-compatible license).
#[unsafe(link_section = "license")]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";
