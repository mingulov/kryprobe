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
//! Invocation identity (round-4 W4, race-hardened round-6 W6,
//! lane-split round-7 W7): every submit takes the next id from its
//! CPU's `LCTR` sequence lane FOR ITS OWN PROGRAM (`(seq << 15) |
//! (lane << 14) | (cpu << 1)`, bit 0 reserved + always clear —
//! distinct across CPUs AND entry programs without atomics); the
//! `LSTATE` slot stores it plus the entry thread id, and the
//! matching return carries the invocation back on the edge.
//! Userspace joins a return ONLY to the outstanding id with the
//! SAME invocation, so a lost return + lost submit can no longer
//! alias one call's return onto another call's id — pairing
//! soundness no longer depends on lossless transport. A submit
//! that loses its claim (slot present — nested or racing)
//! quarantines the key and emits TAINTED (`LEDGE_TAINTED`); a return
//! with no slot (pre-attach call) is TAINTED. Userspace refuses
//! tainted edges (a tainted submit on an outstanding key gaps that
//! id), so a contended reuse can never steal another invocation's
//! return.
//!
//! NOSLOT quarantine (round-4 W4, hardened round-5 W5, merged
//! round-6 W6): a submit dropped for a full table — or refused for
//! an exhausted invocation id — leaves a GHOST invocation: it will
//! return, but holds no slot, so its return would consume the next
//! call's slot and misjoin. The dropped key quarantines in `LQ`
//! (STICKY presence) instead: submits for a quarantined key emit
//! TAINTED without claiming, and returns for it emit TAINTED without
//! touching `LSTATE`. Round-6 also routes CLAIM CONTENTION here (a
//! lost `BPF_NOEXIST` race quarantines instead of overwriting or
//! poisoning — no cross-CPU slot write exists anymore), so quarantine
//! is the single contention mechanism. The quarantine NEVER clears
//! (round-5: clearing on the first return misattributes when several
//! ghosts share the key; counting ghosts races across CPUs) — a
//! disturbed key taints for the session, fail-closed. A quarantined
//! key's held slot is never reclaimed (bounded by quarantine
//! capacity; pressure routes through NOSLOT → overflow, same profile
//! as the round-5 sticky poison). A full quarantine table sets the
//! sticky `LGLB` overflow bit (all later edges taint — session
//! fail-closed, counted via `LLOSS_NOSLOT`).
//!
//! Race-freedom (round-7 W7): `LSTATE` slots are IMMUTABLE —
//! written exactly once by a kernel-atomic create-only insert
//! (`BPF_NOEXIST`: exactly one racing claimer wins; losers observe
//! `EEXIST`), never mutated afterwards, deleted only by a return
//! that first verified the key unquarantined AND the slot's entry
//! thread id against its own. A return whose entry never executed
//! (late attach, kernel recursion-guard skip) owns no slot: on a
//! thread mismatch it emits TAINTED and touches
//! nothing — never consuming, deleting, or quarantining over a live
//! call's slot (same-thread returns are LIFO-ordered, so a match is
//! genuinely the claimer's own return; cross-thread matches are
//! impossible since two live threads never share a tid). Quarantined
//! paths never touch `LSTATE`, so a stale return can never consume
//! a live slot however CPUs interleave; every decision is locally
//! fail-closed (the userspace decoder, single-threaded, serializes
//! joins). The remaining shared writes are convergent by
//! construction: quarantine is insert-only presence (every racing
//! writer inserts the same constant) and the `LGLB` overflow bit is
//! set-only (racing `|=` writers set the same bit — the result
//! cannot clear). Every counter lane is single-writer by
//! construction: per-CPU AND per-program (`LCTR` one lane per entry
//! program, `LLOSS` one lane per class per program, `LAGG` already
//! one lane per hook — round-7: `migrate_disable` does NOT stop an
//! interrupt running a DIFFERENT program on the same CPU mid-RMW,
//! so per-CPU alone lost updates; per-program lanes close it
//! because the kernel per-program recursion guard serializes each
//! program against itself per CPU, and an NMI reentry would require
//! the NMI path to call the traced function, which no NMI path
//! does).
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
/// `LLOSS` lanes per class: one per program (round-7 W7 — the lane
/// index doubles as the hook id, same order as `LAGG_*` below).
/// Entry `class * LLOSS_LANES + hook`; userspace folds the four.
const LLOSS_LANES: u32 = 4;

const LAGG_ENC_SUB: u32 = 0;
const LAGG_ENC_RET: u32 = 1;
const LAGG_DEC_SUB: u32 = 2;
const LAGG_DEC_RET: u32 = 3;

/// `LCTR` lane per entry program (round-7 W7): encrypt-entry takes
/// lane 0, decrypt-entry lane 1. The lane bit rides invocation bit
/// 14, so the two independent sequences can never alias.
const LCTR_ENC: u32 = 0;
const LCTR_DEC: u32 = 1;

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

/// `LSTATE` slot (16 bytes): the invocation identity the return
/// carries back, PLUS the claiming thread id (round-7 W7: a return
/// proves slot ownership by matching its own tid — a missed-entry
/// return taints instead of consuming a stranger's slot). Layout:
/// `invoc` (bit 0 = reserved, always clear; bits 1–13 = cpu tag;
/// bit 14 = entry-program lane; bits 15–63 = per-program per-CPU
/// sequence), `tid` (entry thread, `bpf_get_current_pid_tgid` low
/// half), `rsv` (zero). The slot is IMMUTABLE: written once by the
/// winning `BPF_NOEXIST` claim, never mutated, removed only by a
/// return that first verified the key unquarantined AND the tid.
/// Built as two scalar `u64` stores (a struct literal risks an
/// LLVM `memset` fusion that breaks R4 — spine discipline).
#[repr(C)]
#[derive(Clone, Copy)]
struct LSlot {
    invoc: u64,
    tid: u32,
    rsv: u32,
}
const _: () = assert!(size_of::<LEdge>() == 40);
const _: () = assert!(size_of::<LConfig>() == 64);
const _: () = assert!(size_of::<LSlot>() == 16);

#[map]
static LCFG: Array<LConfig> = Array::with_max_entries(1, 0);
#[map]
static LRING: RingBuf = RingBuf::with_byte_size(262_144, 0);
#[map]
static LLOSS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5 * LLOSS_LANES, 0);
#[map]
static LSTATE: HashMap<u64, LSlot> = HashMap::with_max_entries(LSTATE_MAX, 0);
#[map]
static LAGG: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);
#[map]
static LCTR: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);
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

/// Saturating loss bump (current CPU's lane FOR THIS PROGRAM —
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
/// per-program: each hook id has exactly one writer program, so the
/// lane is exclusive (same kernel-guard argument as `LCTR`).
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

/// Current thread id: `bpf_get_current_pid_tgid` low half (helper
/// 14, all kernels — the "pid" is the tid from userspace's view).
/// Re-implemented `#[inline(always)]` (same R4 rationale as
/// [`func_ret`]: aya's `#[inline]`-only wrapper may outline into a
/// call reloc). fentry and fexit of one call run on the same thread,
/// so the claim stores it and the release proves ownership against
/// it (round-7 W7); migration cannot change it.
#[inline(always)]
fn thread_id() -> u32 {
    // SAFETY: helper with no pointer arguments (id 14, all kernels).
    unsafe {
        let fun: unsafe extern "C" fn() -> u64 = core::mem::transmute(14usize);
        fun() as u32
    }
}

/// Map-update flag: create only, fail when the key exists
/// (kernel UAPI `BPF_NOEXIST = 1`, `include/uapi/linux/bpf.h` —
/// the claim race resolves inside the kernel, atomically).
const BPF_NOEXIST: u64 = 1;
/// `insert` failure when the key already exists: aya-ebpf 0.2.1
/// surfaces the raw helper return, i.e. negated errno (`-EEXIST`,
/// `EEXIST = 17`, `include/uapi/asm-generic/errno-base.h`).
const ERR_EEXIST: i32 = -17;
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
/// across the two entry programs. 0 is never issued (it means "no
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

/// `LGLB` bit 0: quarantine overflow (sticky — all later edges
/// taint; the session is fail-closed).
const LGLB_OVERFLOW: u64 = 1;
/// Quarantine overflow set? (Every edge taints past this point.)
#[inline(always)]
fn quarantine_overflowed() -> bool {
    let Some(word) = LGLB.get(0) else {
        return false;
    };
    *word & LGLB_OVERFLOW != 0
}

/// Quarantine a refused key (NOSLOT drop, exhausted invocation
/// id, or — round-6 — lost claim race): STICKY presence — insert
/// once, never clear (round-5:
/// clearing misattributes shared ghosts; counting races). A full
/// quarantine table sets the sticky overflow bit instead. Frozen
/// once overflowed (the bit already covers everything).
#[inline(always)]
fn quarantine_noslot(key: u64) {
    if quarantine_overflowed() {
        return;
    }
    if LQ.get_ptr(key).is_some() {
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
/// (global overflow, or this key quarantined).
#[inline(always)]
fn submit_quarantined(key: u64) -> bool {
    if quarantine_overflowed() {
        return true;
    }
    LQ.get_ptr(key).is_some()
}

/// Return-side quarantine probe: true = tainted edge, no join (the
/// quarantine is sticky — presence never clears, so there is no
/// ghost accounting to race). Callers check overflow FIRST.
#[inline(always)]
fn ghost_returned(key: u64) -> bool {
    LQ.get_ptr(key).is_some()
}

/// Shared entry prologue: config gate + null-key gate. Returns the
/// timestamp on success; counts the refusal class and returns `None`
/// otherwise.
#[inline(always)]
fn edge_prologue(key: u64, hook: u32) -> Option<u64> {
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

/// Submit-side slot claim (round-6 W6, owned round-7 W7):
/// `Some(false)` = clean (slot claimed for `invoc` + this thread,
/// emit untainted); `Some(true)` = contended (the kernel-atomic
/// `BPF_NOEXIST` insert lost with `EEXIST` — nested or racing — so
/// the key quarantines and the edge emits TAINTED; the decoder gaps
/// the outstanding id, since no future return can be attributed);
/// `None` = table full (quarantine the ghost key +
/// `LLOSS_NOSLOT`, never evicting another call's slot). There is NO
/// lookup-then-insert: exactly one racing claimer wins inside the
/// kernel, and losers never write the slot — the holder's slot is
/// immutable, so no interleave can overwrite, corrupt, or
/// misattribute it. A contended claim emits a (counted) tainted
/// edge, so it needs no loss class of its own.
#[inline(always)]
fn submit_claim(key: u64, invoc: u64, hook: u32) -> Option<bool> {
    // Slot image: two scalar stores (`invoc`, then `tid` + zero
    // `rsv` as one word — never a struct literal, R4).
    let raw = [invoc, u64::from(thread_id())];
    // SAFETY: `LSlot` is `#[repr(C)]`, 16 bytes, 8-aligned — the
    // `[u64; 2]` image is layout-identical with all-valid fields.
    let slot_value: &LSlot = unsafe { &*raw.as_ptr().cast::<LSlot>() };
    match LSTATE.insert(key, slot_value, BPF_NOEXIST) {
        Ok(()) => Some(false),
        Err(ERR_EEXIST) => {
            // Lost the claim race (or nested on a held slot): the
            // holder's integrity is now suspect — quarantine the key
            // (its return taints here) and emit TAINTED. The slot is
            // deliberately untouched: no stale pointer, no poison
            // store, nothing a racing return can trip over.
            quarantine_noslot(key);
            Some(true)
        }
        Err(_) => {
            // The dropped submit leaves a ghost invocation (it WILL
            // return, slotless): quarantine the key so the ghost's
            // return taints here instead of consuming another call's
            // slot — then count the admission refusal.
            quarantine_noslot(key);
            loss_inc(LLOSS_NOSLOT, hook);
            None
        }
    }
}

/// Return-side slot release: `(clean, invoc)` — clean means a slot
/// was held AND its entry thread id matches this return's thread
/// (ownership proved; released; emit untainted with the stored
/// invocation). No slot, or a slot owned by ANOTHER thread
/// (pre-attach call, kernel-skipped entry, or a stranger's live
/// slot), emits TAINTED with invoc 0 and removes NOTHING — a
/// missed-entry return can neither consume nor delete another
/// call's slot, and never quarantines over it (the holder's
/// completion stays intact). The read-then-remove is sound WITHOUT
/// atomicity: slots are immutable (insert-once, never mutated); a
/// racing contender quarantines rather than claiming, while
/// quarantined returns never touch `LSTATE`; and same-thread
/// returns are LIFO-ordered, so a tid match is genuinely the
/// claimer's own return (two live threads never share a tid).
/// Under kernel cell reuse the read can return an unrelated slot —
/// then either the tid mismatches (tainted here) or the invocation
/// belongs to another key's submit (refused downstream on
/// invocation inequality — fail-closed). Never joined to a
/// stranger's id.
#[inline(always)]
fn return_release(key: u64) -> (bool, u64) {
    let Some(slot) = LSTATE.get_ptr(key) else {
        return (false, 0);
    };
    // SAFETY: map value pointer from a checked lookup; two word
    // reads of an immutable cell. The only concurrent remover is a
    // same-key return that proved ownership (only owners remove);
    // quarantine-era removals are gone (quarantined paths never
    // touch `LSTATE`), so removal implies a genuine owner return.
    let stored = unsafe { *slot };
    if stored.tid != thread_id() {
        return (false, 0);
    }
    let _ = LSTATE.remove(key);
    (true, stored.invoc)
}

// ---------------------------------------------------------------------------
// Programs (2 sites x 2 edges; section names pinned by the manifest)
// ---------------------------------------------------------------------------

/// `crypto_skcipher_encrypt(req)` entry: submit-side edge, status 0.
/// Takes an invocation id, then claims the key's slot (contended →
/// quarantined + tainted, full → dropped).
#[fentry(function = "crypto_skcipher_encrypt")]
pub fn lc_enc_entry(ctx: FEntryContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key, LAGG_ENC_SUB) else {
        return 0;
    };
    agg_inc(LAGG_ENC_SUB);
    let Some(invoc) = invoc_next(LCTR_ENC) else {
        // No invocation id (cpu/sequence bound or map failure): the
        // call still executes and returns slotless — a ghost.
        // Quarantine the key (its return taints here) and count it.
        quarantine_noslot(key);
        loss_inc(LLOSS_NOSLOT, LAGG_ENC_SUB);
        return 0;
    };
    if submit_quarantined(key) {
        emit_edge(
            LSITE_ENC,
            LEDGE_SUBMIT,
            key,
            now,
            0,
            true,
            invoc,
            LAGG_ENC_SUB,
        );
        return 0;
    }
    let Some(tainted) = submit_claim(key, invoc, LAGG_ENC_SUB) else {
        return 0;
    };
    emit_edge(
        LSITE_ENC,
        LEDGE_SUBMIT,
        key,
        now,
        0,
        tainted,
        invoc,
        LAGG_ENC_SUB,
    );
    0
}

/// `crypto_skcipher_encrypt(req)` exit: return-side edge with the
/// native return status. Resolves ghosts, else releases the key's
/// slot (absent → tainted); the edge carries the slot's invocation
/// for the userspace join.
#[fexit(function = "crypto_skcipher_encrypt")]
pub fn lc_enc_exit(ctx: FExitContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key, LAGG_ENC_RET) else {
        return 0;
    };
    let Some(ret) = func_ret(&ctx) else {
        // The call exited without a readable status: release its own
        // slot if the key is live (ownership is proved inside
        // `return_release` — a missed-entry FRET taints there and
        // removes nothing). A ghost's slot stays: quarantined paths
        // never touch `LSTATE`, and overflow freezes the tables. No
        // edge to emit; the FRET loss counts it.
        if !quarantine_overflowed() && !ghost_returned(key) {
            let _ = return_release(key);
        }
        loss_inc(LLOSS_FRET, LAGG_ENC_RET);
        return 0;
    };
    agg_inc(LAGG_ENC_RET);
    if quarantine_overflowed() {
        emit_edge(
            LSITE_ENC,
            LEDGE_RETURN,
            key,
            now,
            ret as i32,
            true,
            0,
            LAGG_ENC_RET,
        );
        return 0;
    }
    if ghost_returned(key) {
        // Quarantine shadows the slot: emit tainted and touch nothing
        // (quarantined paths never touch `LSTATE`, so a stale return
        // can never consume a live slot; future claims stay blocked
        // by the sticky quarantine).
        emit_edge(
            LSITE_ENC,
            LEDGE_RETURN,
            key,
            now,
            ret as i32,
            true,
            0,
            LAGG_ENC_RET,
        );
        return 0;
    }
    let (clean, invoc) = return_release(key);
    emit_edge(
        LSITE_ENC,
        LEDGE_RETURN,
        key,
        now,
        ret as i32,
        !clean,
        invoc,
        LAGG_ENC_RET,
    );
    0
}

/// `crypto_skcipher_decrypt(req)` entry: submit-side edge, status 0.
/// Takes an invocation id, then claims the key's slot (contended →
/// quarantined + tainted, full → dropped).
#[fentry(function = "crypto_skcipher_decrypt")]
pub fn lc_dec_entry(ctx: FEntryContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key, LAGG_DEC_SUB) else {
        return 0;
    };
    agg_inc(LAGG_DEC_SUB);
    let Some(invoc) = invoc_next(LCTR_DEC) else {
        // No invocation id (cpu/sequence bound or map failure): the
        // call still executes and returns slotless — a ghost.
        // Quarantine the key (its return taints here) and count it.
        quarantine_noslot(key);
        loss_inc(LLOSS_NOSLOT, LAGG_DEC_SUB);
        return 0;
    };
    if submit_quarantined(key) {
        emit_edge(
            LSITE_DEC,
            LEDGE_SUBMIT,
            key,
            now,
            0,
            true,
            invoc,
            LAGG_DEC_SUB,
        );
        return 0;
    }
    let Some(tainted) = submit_claim(key, invoc, LAGG_DEC_SUB) else {
        return 0;
    };
    emit_edge(
        LSITE_DEC,
        LEDGE_SUBMIT,
        key,
        now,
        0,
        tainted,
        invoc,
        LAGG_DEC_SUB,
    );
    0
}

/// `crypto_skcipher_decrypt(req)` exit: return-side edge with the
/// native return status. Resolves ghosts, else releases the key's
/// slot (absent → tainted); the edge carries the slot's invocation
/// for the userspace join.
#[fexit(function = "crypto_skcipher_decrypt")]
pub fn lc_dec_exit(ctx: FExitContext) -> i32 {
    let key: u64 = ctx.arg(0);
    let Some(now) = edge_prologue(key, LAGG_DEC_RET) else {
        return 0;
    };
    let Some(ret) = func_ret(&ctx) else {
        // The call exited without a readable status: release its own
        // slot if the key is live (ownership is proved inside
        // `return_release` — a missed-entry FRET taints there and
        // removes nothing). A ghost's slot stays: quarantined paths
        // never touch `LSTATE`, and overflow freezes the tables. No
        // edge to emit; the FRET loss counts it.
        if !quarantine_overflowed() && !ghost_returned(key) {
            let _ = return_release(key);
        }
        loss_inc(LLOSS_FRET, LAGG_DEC_RET);
        return 0;
    };
    agg_inc(LAGG_DEC_RET);
    if quarantine_overflowed() {
        emit_edge(
            LSITE_DEC,
            LEDGE_RETURN,
            key,
            now,
            ret as i32,
            true,
            0,
            LAGG_DEC_RET,
        );
        return 0;
    }
    if ghost_returned(key) {
        // Quarantine shadows the slot: emit tainted and touch nothing
        // (quarantined paths never touch `LSTATE`, so a stale return
        // can never consume a live slot; future claims stay blocked
        // by the sticky quarantine).
        emit_edge(
            LSITE_DEC,
            LEDGE_RETURN,
            key,
            now,
            ret as i32,
            true,
            0,
            LAGG_DEC_RET,
        );
        return 0;
    }
    let (clean, invoc) = return_release(key);
    emit_edge(
        LSITE_DEC,
        LEDGE_RETURN,
        key,
        now,
        ret as i32,
        !clean,
        invoc,
        LAGG_DEC_RET,
    );
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
