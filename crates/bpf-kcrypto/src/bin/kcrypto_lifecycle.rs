// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF lifecycle sensor (T06): 2 fsession programs + edge
//! ring + per-CPU aggregate/loss counters + config gate.
//!
//! Each program observes one T04-qualified site through ONE
//! `BPF_TRACE_FSESSION` link (floor 7.0+, attach value 58): the same
//! program runs at function ENTRY (`is_return == false`) and EXIT
//! (`is_return == true`), distinguished at runtime via the
//! `bpf_session_is_return` kfunc. Both runs read the request pointer
//! (`arg0`); the exit run additionally reads the return value
//! (`bpf_get_func_ret`). Every run stamps `bpf_ktime_get_ns` and the
//! program emits one 40-byte v3 [`LEdge`] record on `LRING` per
//! observed half.
//!
//! Invocation identity (round-8 W8): the kernel owns pairing. The
//! per-call session cookie (`bpf_session_cookie`, zeroed by the
//! kernel before the entry run) carries the invocation id: the entry
//! run issues one id from its CPU's `LCTR` lane FOR ITS OWN PROGRAM
//! (`(seq << 15) | (lane << 14) | (cpu << 1)`, bit 0 reserved +
//! always clear — distinct across CPUs AND site programs without
//! atomics) and stores it into the cookie; the exit run of the SAME
//! call reads the SAME cookie back. There are no slots, no
//! quarantine, no thread checks: a skipped entry leaves the cookie
//! zero, so the exit emits TAINTED with invocation 0 instead of
//! joining another call; nested same-key calls pair exactly by
//! distinct cookies. Userspace joins a return ONLY to the outstanding
//! invocation with the SAME id, so transport loss can strand an id
//! but never misjoin one.
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
//! Honest limitations (T06 profile scope):
//! - No transform chase: `tfm_id` stays unknown until T07 wires the
//!   allocation sites; the edge key is the raw request pointer.
//! - No lengths/flags capture (T08); `aux` stays 0.
//! - No callback/completion observation (T09 adapters).
//! - Floor 7.0+: fsession attach refuses typed below it (no 6.x
//!   lifecycle; `api-returns` keeps its own contract).
//!
//! Privacy: the sensor reads argument pointers (pairing keys only),
//! the return register, the config word, and the per-call cookie. It
//! never touches keys, IVs, plaintext, ciphertext, digests, request
//! buffers, or cookie addresses.
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
const LEDGE_VERSION: u8 = 3;

const LEDGE_SUBMIT: u8 = 1;
const LEDGE_RETURN: u8 = 2;

const LEDGE_TAINTED: u16 = 0x0001;

const LSITE_ENC: u16 = 1;
const LSITE_DEC: u16 = 2;

const LCONFIG_MAGIC: u32 = 0x3143_4c4b;
const LCONFIG_VERSION: u32 = 1;

const LLOSS_RESERVE: u32 = 0;
const LLOSS_DISABLED: u32 = 1;
const LLOSS_BADKEY: u32 = 2;
const LLOSS_FRET: u32 = 3;
const LLOSS_NOSLOT: u32 = 4;
/// `LLOSS` lanes per class: one per hook (BPF hook order: enc-sub,
/// enc-ret, dec-sub, dec-ret); the lane index doubles as the hook id.
/// Entry `class * LLOSS_LANES + hook`; userspace folds the four.
const LLOSS_LANES: u32 = 4;

const LAGG_ENC_SUB: u32 = 0;
const LAGG_ENC_RET: u32 = 1;
const LAGG_DEC_SUB: u32 = 2;
const LAGG_DEC_RET: u32 = 3;

/// `LCTR` lane per site program: encrypt takes lane zero, decrypt
/// lane one. The lane bit rides invocation bit 14, so the two
/// independent sequences can never alias.
const LCTR_ENC: u32 = 0;
const LCTR_DEC: u32 = 1;

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

/// Raw lifecycle edge (40 bytes; field order pinned by ABI tests).
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
}

/// Sensor config (64 bytes, `LCFG` key 0).
#[repr(C)]
struct LConfig {
    magic: u32,
    version: u32,
    flags: u32,
    reserved: [u8; 52],
}
const _: () = assert!(size_of::<LEdge>() == 40);
const _: () = assert!(size_of::<LConfig>() == 64);

#[map]
static LCFG: Array<LConfig> = Array::with_max_entries(1, 0);
#[map]
static LRING: RingBuf = RingBuf::with_byte_size(262_144, 0);
#[map]
static LLOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5 * LLOSS_LANES, 0);
#[map]
static LAGG: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);
#[map]
static LCTR: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

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

/// Emit one edge record: reserve 40 bytes, fill every field, submit.
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
/// Lane-bit shift: past the reserved bit 0 + the cpu tag.
const INVOC_LANE_SHIFT: u32 = 1 + INVOC_CPU_BITS;
/// Sequence shift: past reserved bit + cpu tag + lane bit.
const INVOC_SEQ_SHIFT: u32 = 1 + INVOC_CPU_BITS + 1;
/// Per-program per-CPU sequence ceiling: 49 bits (ids stay in 64
/// bits with tag + lane + reserved bit).
const INVOC_SEQ_MAX: u64 = (1 << (64 - INVOC_SEQ_SHIFT)) - 1;

/// Take the next invocation id: `(per-program per-CPU sequence <<
/// 15) | (lane << 14) | (cpu << 1)` (bit 0 reserved + always
/// clear). The sequence lane is this CPU's cell FOR THIS PROGRAM
/// (`LCTR_ENC`/`LCTR_DEC` — non-atomic bump, exclusive: per-CPU via
/// `migrate_disable`, per-program via the kernel per-program
/// recursion guard, which serializes each program against itself
/// per CPU even across interrupts; an NMI reentry would require
/// the NMI path to call the traced function, which no NMI path
/// does). The cpu tag keeps ids distinct across CPUs, the lane bit
/// across the two site programs. 0 is never issued (it means "no
/// invocation" on slotless edges). `None` = the cpu tag overflowed,
/// the sequence saturated, or the map lookup failed — the caller
/// refuses the submit through the NOSLOT path (never a
/// wrapped/aliased id).
#[inline(always)]
fn invoc_next(lane: u32) -> Option<u64> {
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
            emit_edge(site, LEDGE_RETURN, key, now, 0, true, 0, ret_hook);
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
        emit_edge(
            site,
            LEDGE_RETURN,
            key,
            now,
            ret as i32,
            false,
            invoc,
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
    emit_edge(site, LEDGE_SUBMIT, key, now, 0, false, invoc, sub_hook);
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
