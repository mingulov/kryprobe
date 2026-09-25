// SPDX-License-Identifier: GPL-2.0-only
//! KryProbe BPF lifecycle sensor (T06): 4 fentry/fexit programs + edge
//! ring + identity slots + per-CPU aggregate/loss counters + config gate.
//!
//! Each program observes one T04-qualified api edge at function ENTRY
//! or EXIT: it reads the request pointer (`arg0`), stamps
//! `bpf_ktime_get_ns`, and emits one 40-byte v3 [`LEdge`] record on
//! `LRING`. Return edges additionally read the return value
//! (`bpf_get_func_ret`); submit edges carry status 0. Userspace pairs
//! entry with return by (key, invocation) and decodes T05 `Edge`
//! events.
//!
//! Invocation identity (round-4 W4): every submit takes the next id
//! from its CPU's `LCTR` sequence lane, tagged with the cpu number
//! (`(seq << 14) | (cpu << 1)`, bit 0 reserved for the poison tag —
//! distinct across CPUs without atomics);
//! the `LSTATE` slot stores it and the matching return carries it
//! back on the edge. Userspace joins a return ONLY to the
//! outstanding id with the SAME invocation, so a lost return + lost
//! submit can no longer alias one call's return onto another call's
//! id — pairing soundness no longer depends on lossless transport.
//! A submit nests (slot present) → the edge is TAINTED
//! (`LEDGE_TAINTED`); a return with no slot (pre-attach call) is
//! TAINTED. Userspace refuses tainted edges (a tainted submit on an
//! outstanding key gaps that id), so a nested reuse can never steal
//! another invocation's return.
//!
//! NOSLOT quarantine (round-4 W4): a submit dropped for a full table
//! leaves a GHOST invocation — it will return, but holds no slot,
//! so its return would consume the next call's slot and misjoin.
//! The dropped key quarantines in `LQ` (ghost count per key) instead:
//! submits for a quarantined key emit TAINTED without claiming, and
//! the ghost's own return emits TAINTED and decrements toward
//! release. Invariant: a quarantined key holds no `LSTATE` slot (the
//! quarantine starts slotless — a held slot nests instead of
//! refusing — and quarantined submits never claim), so the first
//! return during quarantine is always the ghost's. A full
//! quarantine table sets the sticky `LGLB` overflow bit (all later
//! edges taint — session fail-closed, counted via `LLOSS_NOSLOT`).
//! `LAGG` counts accepted edges per hook
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

/// `LSTATE` slot: one packed `u64` (a struct value would fuse
/// into a `memset` call and break R4, so the state rides one word
/// of pure arithmetic). Layout: bit 0 = poison (disturbed pairing),
/// bits 1–13 = cpu tag, bits 14–55 = per-CPU sequence, bits 56–63 =
/// nesting depth. Bits 0–55 are the invocation identity the return
/// carries back; the depth never leaves the slot. Fresh invocation
/// ids always have bit 0 clear; the poison bit doubles as a
/// guaranteed-mismatch tag (a poisoned return can never equal a
/// submitted id). The poison is STICKY (cleared only when the slot
/// frees at depth 0): the first nested return cannot name the
/// remaining invocation, so every edge stays tainted until the key
/// fully unwinds — no later same-key call can claim a clean slot
/// over an outstanding invocation.
const _: () = assert!(size_of::<LEdge>() == 40);
const _: () = assert!(size_of::<LConfig>() == 64);

#[map]
static LCFG: Array<LConfig> = Array::with_max_entries(1, 0);
#[map]
static LRING: RingBuf = RingBuf::with_byte_size(262_144, 0);
#[map]
static LLOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);
#[map]
static LSTATE: HashMap<u64, u64> = HashMap::with_max_entries(LSTATE_MAX, 0);
#[map]
static LAGG: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);
#[map]
static LCTR: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static LQ: HashMap<u64, u8> = HashMap::with_max_entries(LSTATE_MAX, 0);
#[map]
static LGLB: Array<u64> = Array::with_max_entries(1, 0);

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

/// Emit one edge record: reserve 40 bytes, fill every field, submit.
/// Reserve failure feeds `LLOSS_RESERVE` (never silent).
#[inline(always)]
fn emit_edge(site: u16, edge: u8, key: u64, now: u64, status: i32, tainted: bool, invoc: u64) {
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

/// Poison tag: bit 0 of the packed slot word (fresh invocation ids
/// always have it clear).
const INVOC_POISON: u64 = 1;
/// CPU tag width: 13 bits cover 8192 CPUs (the x86-64 `NR_CPUS`
/// ceiling); ids from higher-numbered CPUs refuse loudly rather
/// than alias.
const INVOC_CPU_BITS: u32 = 13;
/// CPUs covered by the tag (`1 << 13`).
const INVOC_CPU_MAX: u32 = 1 << INVOC_CPU_BITS;
/// Sequence shift: past the poison bit + the cpu tag.
const INVOC_SEQ_SHIFT: u32 = 1 + INVOC_CPU_BITS;
/// Depth shift: past the 56-bit invocation identity.
const INVOC_DEPTH_SHIFT: u32 = 56;
/// Identity mask: bits 0–55 (poison + cpu + sequence, no depth).
const INVOC_ID_MASK: u64 = (1 << INVOC_DEPTH_SHIFT) - 1;
/// Per-CPU sequence ceiling: 42 bits (ids stay in 64 bits with tag
/// + poison + depth).
const INVOC_SEQ_MAX: u64 = (1 << (INVOC_DEPTH_SHIFT - INVOC_SEQ_SHIFT)) - 1;
/// Nesting depth ceiling: saturates (fail-closed taint) past 255.
const INVOC_DEPTH_MAX: u64 = 0xff;

/// Take the next invocation id: `(per-CPU sequence << 14) | (cpu <<
/// 1)` (bit 0 clear — the poison tag; depth is slot-local, never
/// part of the id). The sequence lane is this CPU's own
/// (non-atomic bump — BPF runs migration-disabled, so the cpu read
/// and the lane bump cannot split across CPUs; same discipline as
/// [`loss_inc`]/[`agg_inc`]). The cpu tag keeps ids distinct across
/// CPUs. 0 is never issued (it means "no invocation" on slotless
/// edges). `None` = the cpu tag overflowed, the sequence saturated,
/// or the map lookup failed — the caller refuses the submit through
/// the NOSLOT path (never a wrapped/aliased id).
#[inline(always)]
fn invoc_next() -> Option<u64> {
    let cpu = cpu_id();
    if cpu >= INVOC_CPU_MAX {
        return None;
    }
    let slot = LCTR.get_ptr_mut(0)?;
    // SAFETY: per-CPU lane pointer from a checked lookup; this CPU's
    // exclusive cell (migration-disabled), so plain RMW is exact.
    let seq = unsafe {
        let prev = *slot;
        if prev >= INVOC_SEQ_MAX {
            return None;
        }
        *slot = prev + 1;
        prev + 1
    };
    Some((seq << INVOC_SEQ_SHIFT) | (u64::from(cpu) << 1))
}

/// `LGLB` bit 0: quarantine overflow (sticky — all later edges
/// taint; the session is fail-closed).
const LGLB_OVERFLOW: u64 = 1;
/// `LQ` count meaning stuck-quarantined: 255 ghosts saturated, never
/// clears (the key taints forever — fail-closed, never a hole).
const LQ_STUCK: u8 = u8::MAX;

/// Quarantine overflow set? (Once set, `LQ` counts freeze —
/// tracking may have gaps, so counts are meaningless — and every
/// edge taints.)
#[inline(always)]
fn quarantine_overflowed() -> bool {
    let Some(word) = LGLB.get(0) else {
        return false;
    };
    *word & LGLB_OVERFLOW != 0
}

/// Quarantine a NOSLOT-dropped key: bump its ghost count (stuck at
/// 255), inserting on first drop. A full quarantine table sets the
/// sticky overflow bit instead. Frozen once overflowed.
#[inline(always)]
fn quarantine_noslot(key: u64) {
    if quarantine_overflowed() {
        return;
    }
    if let Some(count) = LQ.get_ptr_mut(key) {
        // SAFETY: map value pointer from a checked lookup.
        unsafe {
            if *count < LQ_STUCK {
                *count += 1;
            }
        }
        return;
    }
    if LQ.insert(key, 1, 0).is_err()
        && let Some(word) = LGLB.get_ptr_mut(0)
    {
        // SAFETY: map value pointer from a checked lookup;
        // idempotent set (every writer sets the same bit).
        unsafe {
            *word |= LGLB_OVERFLOW;
        }
    }
}

/// Submit-side quarantine probe: true = taint without claiming
/// (global overflow, or this key has ghosts outstanding).
#[inline(always)]
fn submit_quarantined(key: u64) -> bool {
    if quarantine_overflowed() {
        return true;
    }
    LQ.get_ptr(key).is_some()
}

/// Return-side ghost resolution: true = this return resolves one
/// ghost (tainted edge, no slot touch). Decrements toward release;
/// stuck counts never clear. Callers check overflow FIRST (an
/// overflowed session taints without consuming quarantine counts).
#[inline(always)]
fn ghost_returned(key: u64) -> bool {
    let Some(count) = LQ.get_ptr_mut(key) else {
        return false;
    };
    // SAFETY: map value pointer from a checked lookup.
    unsafe {
        if *count == LQ_STUCK {
            return true;
        }
        if *count <= 1 {
            let _ = LQ.remove(key);
        } else {
            *count -= 1;
        }
    }
    true
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

/// Submit-side slot claim: `Some(false)` = clean (slot claimed at
/// depth 1 for `invoc`, emit untainted); `Some(true)` = disturbed
/// (slot held — depth +1 saturating, poison STICKY, store the new
/// `invoc`, emit TAINTED; the decoder gaps the outstanding id, since
/// no future return can be attributed); `None` = table full (drop +
/// `LLOSS_NOSLOT`, never evicting another call's slot).
#[inline(always)]
fn submit_claim(key: u64, invoc: u64) -> Option<bool> {
    if let Some(slot) = LSTATE.get_ptr_mut(key) {
        // SAFETY: map value pointer from a checked lookup; one word
        // RMW (pure arithmetic — no struct literal, R4 holds).
        unsafe {
            let stored = *slot;
            let depth = stored >> INVOC_DEPTH_SHIFT;
            let deeper = if depth < INVOC_DEPTH_MAX {
                depth + 1
            } else {
                depth
            };
            *slot = (deeper << INVOC_DEPTH_SHIFT) | (invoc & INVOC_ID_MASK) | INVOC_POISON;
        }
        return Some(true);
    }
    if LSTATE
        .insert(key, (1 << INVOC_DEPTH_SHIFT) | invoc, 0)
        .is_err()
    {
        // The dropped submit leaves a ghost invocation (it WILL
        // return, slotless): quarantine the key so the ghost's
        // return resolves here instead of consuming another call's
        // slot — then count the admission refusal.
        quarantine_noslot(key);
        loss_inc(LLOSS_NOSLOT);
        return None;
    }
    Some(false)
}

/// Return-side slot release: `(clean, invoc)` — clean means the slot
/// word had the poison bit clear (poison clear implies depth 1: the
/// slot never nested — released; emit untainted with the stored
/// invocation). No slot (pre-attach call or a dropped submit) emits
/// TAINTED with invoc 0. A POISONED slot emits TAINTED with the
/// stored identity (whose poison bit can never equal a submitted
/// id, so userspace refuses it on invocation inequality even past
/// the taint check) and decrements toward 0 — the slot frees only at
/// full unwind, so no later call claims a clean slot over an
/// outstanding invocation. Never joined to a stranger's id.
#[inline(always)]
fn return_release(key: u64) -> (bool, u64) {
    let Some(slot) = LSTATE.get_ptr_mut(key) else {
        return (false, 0);
    };
    // SAFETY: map value pointer from a checked lookup.
    unsafe {
        let stored = *slot;
        let depth = stored >> INVOC_DEPTH_SHIFT;
        let identity = stored & INVOC_ID_MASK;
        if stored & INVOC_POISON == 0 {
            let _ = LSTATE.remove(key);
            return (true, identity);
        }
        if depth <= 1 {
            let _ = LSTATE.remove(key);
        } else {
            *slot = ((depth - 1) << INVOC_DEPTH_SHIFT) | identity;
        }
        (false, identity)
    }
}

// ---------------------------------------------------------------------------
// Programs (2 sites x 2 edges; section names pinned by the manifest)
// ---------------------------------------------------------------------------

/// `crypto_skcipher_encrypt(req)` entry: submit-side edge, status 0.
/// Takes an invocation id, then claims the key's slot (nested →
/// tainted, full → dropped).
#[fentry(function = "crypto_skcipher_encrypt")]
pub fn lc_enc_entry(ctx: FEntryContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    agg_inc(LAGG_ENC_SUB);
    let Some(invoc) = invoc_next() else {
        loss_inc(LLOSS_NOSLOT);
        return 0;
    };
    if submit_quarantined(key) {
        emit_edge(LSITE_ENC, LEDGE_SUBMIT, key, now, 0, true, invoc);
        return 0;
    }
    let Some(tainted) = submit_claim(key, invoc) else {
        return 0;
    };
    emit_edge(LSITE_ENC, LEDGE_SUBMIT, key, now, 0, tainted, invoc);
    0
}

/// `crypto_skcipher_encrypt(req)` exit: return-side edge with the
/// native return status. Resolves ghosts, else releases the key's
/// slot (absent → tainted); the edge carries the slot's invocation
/// for the userspace join.
#[fexit(function = "crypto_skcipher_encrypt")]
pub fn lc_enc_exit(ctx: FExitContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    let Some(ret) = func_ret(&ctx) else {
        // The call exited without a readable status: resolve its
        // outstanding presence (slot release + ghost resolution —
        // each no-ops when absent, and the quarantine invariant
        // guarantees at most one hits) unless the session
        // overflowed (frozen tables). No edge to emit; the FRET
        // loss counts it.
        if !quarantine_overflowed() {
            let _ = return_release(key);
            let _ = ghost_returned(key);
        }
        loss_inc(LLOSS_FRET);
        return 0;
    };
    agg_inc(LAGG_ENC_RET);
    if quarantine_overflowed() || ghost_returned(key) {
        emit_edge(LSITE_ENC, LEDGE_RETURN, key, now, ret as i32, true, 0);
        return 0;
    }
    let (clean, invoc) = return_release(key);
    emit_edge(LSITE_ENC, LEDGE_RETURN, key, now, ret as i32, !clean, invoc);
    0
}

/// `crypto_skcipher_decrypt(req)` entry: submit-side edge, status 0.
/// Takes an invocation id, then claims the key's slot (nested →
/// tainted, full → dropped).
#[fentry(function = "crypto_skcipher_decrypt")]
pub fn lc_dec_entry(ctx: FEntryContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    agg_inc(LAGG_DEC_SUB);
    let Some(invoc) = invoc_next() else {
        loss_inc(LLOSS_NOSLOT);
        return 0;
    };
    if submit_quarantined(key) {
        emit_edge(LSITE_DEC, LEDGE_SUBMIT, key, now, 0, true, invoc);
        return 0;
    }
    let Some(tainted) = submit_claim(key, invoc) else {
        return 0;
    };
    emit_edge(LSITE_DEC, LEDGE_SUBMIT, key, now, 0, tainted, invoc);
    0
}

/// `crypto_skcipher_decrypt(req)` exit: return-side edge with the
/// native return status. Resolves ghosts, else releases the key's
/// slot (absent → tainted); the edge carries the slot's invocation
/// for the userspace join.
#[fexit(function = "crypto_skcipher_decrypt")]
pub fn lc_dec_exit(ctx: FExitContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key) else {
        return 0;
    };
    let Some(ret) = func_ret(&ctx) else {
        // The call exited without a readable status: resolve its
        // outstanding presence (slot release + ghost resolution —
        // each no-ops when absent, and the quarantine invariant
        // guarantees at most one hits) unless the session
        // overflowed (frozen tables). No edge to emit; the FRET
        // loss counts it.
        if !quarantine_overflowed() {
            let _ = return_release(key);
            let _ = ghost_returned(key);
        }
        loss_inc(LLOSS_FRET);
        return 0;
    };
    agg_inc(LAGG_DEC_RET);
    if quarantine_overflowed() || ghost_returned(key) {
        emit_edge(LSITE_DEC, LEDGE_RETURN, key, now, ret as i32, true, 0);
        return 0;
    }
    let (clean, invoc) = return_release(key);
    emit_edge(LSITE_DEC, LEDGE_RETURN, key, now, ret as i32, !clean, invoc);
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
