// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF lifecycle sensor (T06): 4 fentry/fexit programs + edge
//! ring + identity slots + per-CPU aggregate/loss counters + config gate.
//!
//! Each program observes one T04-qualified api edge at function ENTRY
//! or EXIT: it reads the request pointer (`arg0`), stamps
//! `bpf_ktime_get_ns`, and emits one 32-byte v2 [`LEdge`] record on
//! `LRING`. Return edges additionally read the return value
//! (`bpf_get_func_ret`); submit edges carry status 0. Userspace pairs
//! entry with return by key and decodes T05 `Edge` events.
//!
//! First-wins pairing (round-2 U1/U2): `LSTATE` holds one slot per
//! outstanding address. A submit nests (slot present) or finds the
//! table full → the edge is TAINTED (`LEDGE_TAINTED`) or dropped
//! (`LLOSS_NOSLOT`); a return with no slot (pre-attach call) is
//! TAINTED. Userspace refuses tainted edges without disturbing the
//! outstanding id, so a nested reuse can never steal another
//! invocation's return. `LAGG` counts accepted edges per hook
//! (post-gate, pre-reserve — before the slot claim, so NOSLOT
//! drops count as accepted-but-untransported): after a quiet drain
//! with an empty close ring, `sum(LAGG) == consumed +
//! LLOSS_RESERVE + LLOSS_NOSLOT` exactly.
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
//!
//! Privacy: the sensor reads argument pointers (pairing keys only),
//! the return register, and the config word. It never touches keys,
//! IVs, plaintext, ciphertext, digests, or request buffers.
//!
//! Fail-closed gates: a wrong/missing `LCFG` magic disarms every
//! program (`LLOSS_DISABLED`, never silent); null keys feed
//! `LLOSS_BADKEY`; ring reserve failures feed `LLOSS_RESERVE`.
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

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::{bpf_get_func_ret, bpf_ktime_get_ns},
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use core::mem::MaybeUninit;

// ---------------------------------------------------------------------------
// Twinned enum values (mirror: kryprobe-abi/src/kcrypto_lifecycle.rs)
// ---------------------------------------------------------------------------

const LEDGE_MAGIC: u16 = 0x434c;
const LEDGE_VERSION: u8 = 2;

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

const LAGG_ENC_SUB: u32 = 0;
const LAGG_ENC_RET: u32 = 1;
const LAGG_DEC_SUB: u32 = 2;
const LAGG_DEC_RET: u32 = 3;

/// Outstanding-call slots: one presence marker per live address
/// (mirrors the userspace decode bound — global, so cross-CPU
/// completion stays coherent).
const LSTATE_MAX: u32 = 4096;

// ---------------------------------------------------------------------------
// Twinned structs (mirror: kryprobe-abi/src/kcrypto_lifecycle.rs)
// ---------------------------------------------------------------------------

/// Raw lifecycle edge (32 bytes; field order pinned by ABI tests).
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
}

/// Sensor config (64 bytes, `LCFG` key 0).
#[repr(C)]
struct LConfig {
    magic: u32,
    version: u32,
    flags: u32,
    reserved: [u8; 52],
}

const _: () = assert!(size_of::<LEdge>() == 32);
const _: () = assert!(size_of::<LConfig>() == 64);

#[map]
static LCFG: Array<LConfig> = Array::with_max_entries(1, 0);
#[map]
static LRING: RingBuf = RingBuf::with_byte_size(262_144, 0);
#[map]
static LLOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);
#[map]
static LSTATE: HashMap<u64, u8> = HashMap::with_max_entries(LSTATE_MAX, 0);
#[map]
static LAGG: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

// ---------------------------------------------------------------------------
// Helpers (all #[inline(always)]: R4 call-free)
// ---------------------------------------------------------------------------

/// Read the traced function's return register (`bpf_get_func_ret`,
/// helper 184, Linux 5.17+). `None` = helper refused (fail-closed by
/// the caller into `LLOSS_FRET`: an unclassified return is skipped,
/// never misbucketed).
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

/// Saturating per-CPU loss bump (current CPU's lane, exclusive).
#[inline(always)]
fn loss_inc(idx: u32) {
    if let Some(slot) = LLOSS.get_ptr_mut(idx) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Saturating per-CPU accepted-edge bump (post-gate, pre-reserve: an
/// accepted edge that the ring cannot take still counts here AND in
/// `LLOSS_RESERVE` — the canary reconciles the two).
#[inline(always)]
fn agg_inc(idx: u32) {
    if let Some(slot) = LAGG.get_ptr_mut(idx) {
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}

/// Emit one edge record: reserve 32 bytes, fill every field, submit.
/// Reserve failure feeds `LLOSS_RESERVE` (never silent).
#[inline(always)]
fn emit_edge(site: u16, edge: u8, key: u64, now: u64, status: i32, tainted: bool) {
    let Some(mut entry) = LRING.reserve::<LEdge>(0) else {
        loss_inc(LLOSS_RESERVE);
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
    }
    entry.submit(0);
}

/// Shared entry prologue: config gate + null-key gate. Returns the
/// timestamp on success; counts the refusal class and returns `None`
/// otherwise.
#[inline(always)]
fn edge_prologue(key: u64) -> Option<u64> {
    if !cfg_armed() {
        loss_inc(LLOSS_DISABLED);
        return None;
    }
    if key == 0 {
        loss_inc(LLOSS_BADKEY);
        return None;
    }
    // SAFETY: helper with no pointer arguments.
    Some(unsafe { bpf_ktime_get_ns() })
}

/// Submit-side slot claim: `Some(false)` = clean (slot claimed,
/// emit untainted); `Some(true)` = nested (slot held — emit TAINTED,
/// the outstanding call keeps its pairing); `None` = table full
/// (drop + `LLOSS_NOSLOT`, never evicting another call's slot).
#[inline(always)]
fn submit_claim(key: u64) -> Option<bool> {
    if LSTATE.get_ptr(key).is_some() {
        return Some(true);
    }
    let one: u8 = 1;
    if LSTATE.insert(key, one, 0).is_err() {
        loss_inc(LLOSS_NOSLOT);
        return None;
    }
    Some(false)
}

/// Return-side slot release: true = clean (slot held, released, emit
/// untainted); false = no slot (pre-attach call or a dropped submit
/// — emit TAINTED, never joined to a stranger's id).
#[inline(always)]
fn return_release(key: u64) -> bool {
    if LSTATE.get_ptr(key).is_none() {
        return false;
    }
    let _ = LSTATE.remove(key);
    true
}

// ---------------------------------------------------------------------------
// Programs (2 sites x 2 edges; section names pinned by the manifest)
// ---------------------------------------------------------------------------

/// `crypto_skcipher_encrypt(req)` entry: submit-side edge, status 0.
/// Claims the key's slot (nested → tainted, full → dropped).
#[fentry(function = "crypto_skcipher_encrypt")]
pub fn lc_enc_entry(ctx: FEntryContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    agg_inc(LAGG_ENC_SUB);
    let Some(tainted) = submit_claim(key) else {
        return 0;
    };
    emit_edge(LSITE_ENC, LEDGE_SUBMIT, key, now, 0, tainted);
    0
}

/// `crypto_skcipher_encrypt(req)` exit: return-side edge with the
/// native return status. Releases the key's slot (absent → tainted).
#[fexit(function = "crypto_skcipher_encrypt")]
pub fn lc_enc_exit(ctx: FExitContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    let Some(ret) = func_ret(&ctx) else {
        loss_inc(LLOSS_FRET);
        return 0;
    };
    agg_inc(LAGG_ENC_RET);
    let clean = return_release(key);
    emit_edge(LSITE_ENC, LEDGE_RETURN, key, now, ret as i32, !clean);
    0
}

/// `crypto_skcipher_decrypt(req)` entry: submit-side edge, status 0.
/// Claims the key's slot (nested → tainted, full → dropped).
#[fentry(function = "crypto_skcipher_decrypt")]
pub fn lc_dec_entry(ctx: FEntryContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    agg_inc(LAGG_DEC_SUB);
    let Some(tainted) = submit_claim(key) else {
        return 0;
    };
    emit_edge(LSITE_DEC, LEDGE_SUBMIT, key, now, 0, tainted);
    0
}

/// `crypto_skcipher_decrypt(req)` exit: return-side edge with the
/// native return status. Releases the key's slot (absent → tainted).
#[fexit(function = "crypto_skcipher_decrypt")]
pub fn lc_dec_exit(ctx: FExitContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    let Some(ret) = func_ret(&ctx) else {
        loss_inc(LLOSS_FRET);
        return 0;
    };
    agg_inc(LAGG_DEC_RET);
    let clean = return_release(key);
    emit_edge(LSITE_DEC, LEDGE_RETURN, key, now, ret as i32, !clean);
    0
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
