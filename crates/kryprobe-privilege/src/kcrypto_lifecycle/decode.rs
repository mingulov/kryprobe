// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw-edge decode: v6 `LEdge` bytes → T05 `Edge` events (P3: the v5
//! submit-side driver word (F05) + return-side no-chase twin (R2) +
//! entry-side scalar request metadata with submit-lifetime binding;
//! P4: callback halves — `edge = LEDGE_CALLBACK` with a qualified
//! site — validated by the twin and joined through the decoder-owned
//! [`AsyncAdapter`](crate::kcrypto_lifecycle::async_adapter::AsyncAdapter)
//! identity relation).
//!
//! The op join is keyed by the BPF invocation id alone (W8 fsession:
//! the entry run mints one id per call and stores it in the
//! kernel-zeroed per-call session cookie; the exit run of the SAME
//! call reads the SAME cookie back). A submit admits a fresh opaque
//! id under its invocation, and a return joins the outstanding id
//! for its invocation — nested same-key calls pair exactly, since
//! distinct calls carry distinct cookies whatever request pointer
//! they share. Callback halves name NO invocation (`invoc == 0`)
//! and join by key through the adapter relation (every submit is
//! covered from admission, so early callbacks join; the relation
//! retires tokens on sync returns, terminal callbacks, and gaps).
//! Raw keys never leave this module (only opaque ids reach `Edge`);
//! every refusal is counted, never silent.
//!
//! Pairing soundness never depends on lossless transport: a return
//! from a DIFFERENT invocation — a later call after a lost return +
//! lost submit — names an invocation with no outstanding id (or a
//! live unrelated one it cannot alias onto: the lookup misses and
//! the return refuses unknown with the table kept).
//!
//! Disturbance signals (W8): per-call cookies isolate invocations,
//! so BPF TAINTS what it cannot pair and tainted edges disturb
//! NOTHING — a tainted edge names no invocation (`invoc` 0: entry
//! id-exhaustion, or an exit over a zero cookie from a skipped entry
//! or a pre-attach call) and every tainted edge refuses quietly. A
//! same-invocation resubmit (BPF ids are unique — this is twin drift
//! or a replay) gaps the old id `IdentityAmbiguous` and admits
//! fresh. An id whose return never arrives lingers until `finish`
//! reconciles it (no prompt key-gap: under nesting, a second submit
//! on the same key is a live second call, not proof the first ended).
//! Site is stored per submit and checked per return (one call, one
//! function — cross-site returns refuse stale).

use crate::kcrypto_lifecycle::async_adapter::{AdapterStats, AsyncAdapter, classify_return};
use kryprobe_abi::kcrypto_lifecycle::{
    LDIR_DEC, LDIR_ENC, LEDGE_CALLBACK, LEDGE_INVOC_POISON, LEDGE_MAGIC, LEDGE_RETURN,
    LEDGE_SUBMIT, LEDGE_TAINTED, LEDGE_TRUNCATED, LEDGE_VERSION, LFAM_SK, LMETA_CRYPTLEN_OK,
    LMETA_REQFLAGS_OK, LSITE_CB_CRYPTD, LSITE_CB_KXC, LSITE_DEC, LSITE_ENC,
};
use kryprobe_core::kcrypto::{
    Edge, GapReason, LifecycleFamily, OpDirection, RequestMeta, ReturnDisposition,
};
use std::collections::{HashMap, VecDeque};

/// Record twin size: `LEdge` is 112 bytes on the ring (v6: the API
/// input length rides at 28..32, the transform word at 40..48, the
/// request flags at 48..52, family/dir/validity at 52..56, and the
/// driver name at 56..112).
const RECORD_LEN: usize = 112;

/// Driver-name field length (v6 `LEdge::drv`: 55 bytes max + NUL).
const DRV_LEN: usize = 56;

/// Token-space partition floor (contract §8, P4r4): issued ids live
/// BELOW this line (`1..REFUSED_FLOOR`); decoder-refusal contention
/// tokens live AT OR ABOVE it (`REFUSED_FLOOR..=u64::MAX`, top bit
/// set). The two ranges can never meet however the allocators are
/// driven — issuing stops at the floor (loud refusal) and refusal
/// minting stops at the floor (loud slot recycle) — so
/// `clear_uncovered` on an issued id can never erase another
/// refusal's contention.
const REFUSED_FLOOR: u64 = 1 << 63;

/// One validated raw edge (post-twin-checks, pre-join).
///
/// `Debug` is manual: [`RawEdge::key`] and [`RawEdge::tfm`] are raw
/// kernel pointers and render as `<redacted>` (round-1
/// sol-m9/astra-m9); [`RawEdge::drv`] renders (public inventory).
#[derive(Clone, PartialEq, Eq)]
pub struct RawEdge {
    /// [`LEDGE_SUBMIT`], [`LEDGE_RETURN`], or [`LEDGE_CALLBACK`]
    /// (validated).
    pub edge: u8,
    /// [`LSITE_ENC`] / [`LSITE_DEC`] on op edges, [`LSITE_CB_CRYPTD`] /
    /// [`LSITE_CB_KXC`] on callback halves (validated; op attribution
    /// is T07/T08 scope — T06 validates the twin but carries no op).
    pub site: u16,
    /// [`LEDGE_TAINTED`] was set (BPF could not pair this edge).
    pub tainted: bool,
    /// Raw kernel request pointer (validated pairing-adjacent
    /// material; never leaves decode — the join keys by [`RawEdge::invoc`]).
    pub key: u64,
    /// Edge timestamp (ns).
    pub ts_ns: u64,
    /// Native return status (return edges) or 0 (submit edges).
    pub status: i32,
    /// BPF invocation id (the op-join identity; 0 on tainted
    /// edges, which name no invocation, and 0 on callback halves,
    /// which join by key through the adapter relation).
    pub invoc: u64,
    /// Frontend transform pointer behind the op (0 when the request
    /// link was unreadable — unknown, feeds first-seen admission;
    /// never leaves decode except into the tracker's opaque ids).
    /// Submit edges only (R2: returns carry 0 — the twin refuses a
    /// return-side word, since honest BPF never chases at exit).
    pub tfm: u64,
    /// Runtime-selected driver name behind the submit's transform
    /// (empty when the driver chase was unreadable — unknown, feeds
    /// first-seen provenance; public inventory, never a secret).
    /// Submit edges only (returns carry empty — the twin refuses a
    /// return-side name).
    pub drv: String,
    /// The driver word filled the bound (D9: clipped names read as
    /// partial, never complete — carried into the generation).
    pub truncated: bool,
    /// API input length chased at entry (`None` when the chase was
    /// unreadable — unknown, never 0-as-data; `None` on returns,
    /// which carry no metadata).
    pub cryptlen: Option<u32>,
    /// Request flags chased at entry (`None` when unreadable — a
    /// valid zero stays `Some(0)`; `None` on returns).
    pub req_flags: Option<u32>,
    /// Crypto family behind the op (wire-pinned; skcipher-only in v6).
    pub family: LifecycleFamily,
    /// Operation direction behind the op (wire-pinned, echoes the site).
    pub direction: OpDirection,
}

impl std::fmt::Debug for RawEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEdge")
            .field("edge", &self.edge)
            .field("site", &self.site)
            .field("tainted", &self.tainted)
            .field("key", &"<redacted>")
            .field("ts_ns", &self.ts_ns)
            .field("status", &self.status)
            .field("invoc", &self.invoc)
            .field("tfm", &"<redacted>")
            .field("drv", &self.drv)
            .field("cryptlen", &self.cryptlen)
            .field("req_flags", &self.req_flags)
            .field("family", &self.family)
            .field("direction", &self.direction)
            .finish()
    }
}

/// Why one ring record produced no edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeDrop {
    /// Record is not exactly 112 bytes.
    BadLength,
    /// Magic is not [`LEDGE_MAGIC`].
    BadMagic,
    /// Version is not [`LEDGE_VERSION`].
    BadVersion,
    /// Edge kind is neither submit, return, nor callback.
    BadEdge,
    /// Site is neither encrypt/decrypt (op edges) nor a qualified
    /// callback site (callback halves).
    BadSite,
    /// Flags carry bits outside tainted/truncated.
    BadFlags,
    /// v6 metadata word violates the contract: nonzero metadata on
    /// a return edge (R2 extended — returns are never chased) or a
    /// callback half (callback halves never chase submit-owned
    /// facts), `mflags` bits outside cryptlen/req-flags-valid, a
    /// nonzero value word without its validity bit, a non-skcipher
    /// family, or a direction that does not echo the site.
    BadMeta,
    /// Null pairing key (the BPF `BADKEY` gate should have dropped it).
    NullKey,
    /// Submit edge with a nonzero status (ABI: submit edges carry 0 —
    /// a status here is twin drift, silently discarded before).
    BadSubmitStatus,
    /// Clean (untainted) op edge with a malformed invocation id: 0
    /// ("no invocation", tainted edges only) or the reserved bit set
    /// (no honest-BPF path sets it — W8 mints cookie ids with bit 0
    /// clear); or a callback half with a NONZERO id (callback halves
    /// name no fsession invocation — the relation joins by key).
    /// Honest BPF never emits either shape — fail closed, never join.
    BadInvoc,
    /// Return edge or callback half with a nonzero transform word
    /// (R2: honest BPF never chases at exit, and callback halves
    /// never chase submit-owned facts — a word here is twin drift).
    BadReturnTfm,
    /// Driver-name field violates the contract: no NUL within 56
    /// bytes, invalid UTF-8, or a name on a return edge or callback
    /// half (returns carry no name — the submit's admission owns the
    /// provenance; callbacks carry no name — no chase, no cookie).
    BadDrv,
}

/// Named decode loss counters (loss ledger feed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeStats {
    /// Submits admitted (fresh opaque ids issued).
    pub admitted: u64,
    /// Submits refused (table full, id space exhausted, or BPF
    /// [`LEDGE_TAINTED`] — never admitted, never disturbing: a
    /// tainted edge names no invocation, so there is nothing to gap).
    pub submit_refused: u64,
    /// Returns for invocations with no outstanding submit (lost
    /// submit, pre-attach call, or BPF taint — never joined, never
    /// disturbing).
    pub unknown_invoc_returns: u64,
    /// Records failing twin validation.
    pub bad_records: u64,
    /// Gaps synthesized for same-invocation resubmits (BPF ids are
    /// unique — a resubmit means the old id's return never arrived).
    pub gaps_synthesized: u64,
    /// Returns refused against an outstanding submit: predating it,
    /// or from the other site (one call, one function — refused,
    /// never joined, outstanding kept).
    pub stale_returns: u64,
}

/// Validate one ring record against the v6 `LEdge` twin: exact length,
/// magic, version, edge kind, site, defined-only flags, non-null
/// key, zero status on submit edges (ANY status on callback halves —
/// classification is the adapter's job, never the twin's), the
/// invocation id (nonzero unpoisoned on clean op edges; 0 ONLY on
/// callback halves, which join by key), the transform word (submit
/// edges: ANY u64 — 0 is unknown, never refused; return edges and
/// callback halves: 0 ONLY — R2, honest BPF never chases at exit,
/// and callback halves never chase submit-owned facts), the
/// entry-side metadata (submit edges: validity-gated `cryptlen` /
/// `req_flags`, skcipher family, site-echoing direction; return
/// edges and callback halves: all-zero ONLY), and the driver name
/// (submit edges: NUL-terminated UTF-8 within 56 bytes, empty when
/// unknown; return edges and callback halves: empty ONLY).
pub fn decode_record(bytes: &[u8]) -> Result<RawEdge, DecodeDrop> {
    if bytes.len() != RECORD_LEN {
        return Err(DecodeDrop::BadLength);
    }
    let u16le = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
    let u32le = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    let u64le = |i: usize| {
        u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ])
    };
    if u16le(0) != LEDGE_MAGIC {
        return Err(DecodeDrop::BadMagic);
    }
    if bytes[2] != LEDGE_VERSION {
        return Err(DecodeDrop::BadVersion);
    }
    let edge = bytes[3];
    if edge != LEDGE_SUBMIT && edge != LEDGE_RETURN && edge != LEDGE_CALLBACK {
        return Err(DecodeDrop::BadEdge);
    }
    let is_callback = edge == LEDGE_CALLBACK;
    let site = u16le(4);
    let site_ok = if is_callback {
        site == LSITE_CB_CRYPTD || site == LSITE_CB_KXC
    } else {
        site == LSITE_ENC || site == LSITE_DEC
    };
    if !site_ok {
        return Err(DecodeDrop::BadSite);
    }
    let flags = u16le(6);
    // Callback halves carry NO flags (never tainted — no cookie to
    // lose; never truncated — no name): any bit is twin drift.
    if is_callback {
        if flags != 0 {
            return Err(DecodeDrop::BadFlags);
        }
    } else if flags & !(LEDGE_TAINTED | LEDGE_TRUNCATED) != 0 {
        return Err(DecodeDrop::BadFlags);
    }
    let key = u64le(8);
    if key == 0 {
        return Err(DecodeDrop::NullKey);
    }
    let ts_ns = u64le(16);
    let status = i32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    if edge == LEDGE_SUBMIT && status != 0 {
        return Err(DecodeDrop::BadSubmitStatus);
    }
    let invoc = u64le(32);
    let tainted = flags & LEDGE_TAINTED != 0;
    let truncated = flags & LEDGE_TRUNCATED != 0;
    if is_callback {
        if invoc != 0 {
            return Err(DecodeDrop::BadInvoc);
        }
    } else if !tainted && (invoc == 0 || invoc & LEDGE_INVOC_POISON != 0) {
        return Err(DecodeDrop::BadInvoc);
    }
    let tfm = u64le(40);
    if edge != LEDGE_SUBMIT && tfm != 0 {
        return Err(DecodeDrop::BadReturnTfm);
    }
    // Entry-side metadata (P3): returns carry all-zero words (R2
    // extended — honest BPF never chases at exit); submits carry
    // validity-gated scalars, the skcipher family, and the
    // site-echoing direction. Callback halves carry all-zero words
    // (P4: no chase, no cookie, no name).
    let cryptlen_word = u32le(28);
    let req_flags_word = u32le(48);
    let fam = bytes[52];
    let dir = bytes[53];
    let mflags = u16le(54);
    let (cryptlen, req_flags) = if edge != LEDGE_SUBMIT {
        if cryptlen_word != 0 || req_flags_word != 0 || fam != 0 || dir != 0 || mflags != 0 {
            return Err(DecodeDrop::BadMeta);
        }
        (None, None)
    } else {
        if mflags & !(LMETA_CRYPTLEN_OK | LMETA_REQFLAGS_OK) != 0 {
            return Err(DecodeDrop::BadMeta);
        }
        if fam != LFAM_SK {
            return Err(DecodeDrop::BadMeta);
        }
        let want_dir = if site == LSITE_ENC {
            LDIR_ENC
        } else {
            LDIR_DEC
        };
        if dir != want_dir {
            return Err(DecodeDrop::BadMeta);
        }
        // A nonzero value without its validity bit is twin drift
        // (honest BPF zeroes the word when the chase is unreadable);
        // a valid zero stays `Some(0)`, never confused with unknown.
        if mflags & LMETA_CRYPTLEN_OK == 0 && cryptlen_word != 0 {
            return Err(DecodeDrop::BadMeta);
        }
        if mflags & LMETA_REQFLAGS_OK == 0 && req_flags_word != 0 {
            return Err(DecodeDrop::BadMeta);
        }
        (
            (mflags & LMETA_CRYPTLEN_OK != 0).then_some(cryptlen_word),
            (mflags & LMETA_REQFLAGS_OK != 0).then_some(req_flags_word),
        )
    };
    // Callback halves take the else arm (Decrypt) — a placeholder
    // that never leaves decode: `Edge::Callback` carries no
    // direction, and op attribution is T07/T08 scope.
    let direction = if site == LSITE_ENC {
        OpDirection::Encrypt
    } else {
        OpDirection::Decrypt
    };
    let mut drv_field = [0u8; DRV_LEN];
    drv_field.copy_from_slice(&bytes[56..56 + DRV_LEN]);
    let drv_len = drv_field
        .iter()
        .position(|b| *b == 0)
        .ok_or(DecodeDrop::BadDrv)?;
    let drv = std::str::from_utf8(&drv_field[..drv_len]).map_err(|_| DecodeDrop::BadDrv)?;
    if edge != LEDGE_SUBMIT && (!drv.is_empty() || truncated) {
        return Err(DecodeDrop::BadDrv);
    }
    Ok(RawEdge {
        edge,
        site,
        tainted,
        key,
        ts_ns,
        status,
        invoc,
        tfm,
        drv: drv.to_owned(),
        truncated,
        cryptlen,
        req_flags,
        family: LifecycleFamily::Skcipher,
        direction,
    })
}

/// One outstanding invocation: the opaque id plus the submit facts
/// the joining return needs (its site for the staleness check, its
/// key for adapter retirement, its flags for backlog consent).
///
/// `Debug` is manual: [`Outstanding::key`] is a raw kernel pointer
/// and renders as `<redacted>` (round-1 sol-m9/astra-m9).
#[derive(Clone, Copy)]
struct Outstanding {
    /// Opaque id issued at submit.
    id: u64,
    /// Submit timestamp (returns predating it are stale).
    submit_ts: u64,
    /// Submit site (one call, one function).
    submit_site: u16,
    /// Submit key (raw pairing material — adapter retirement only,
    /// never rendered, never leaves decode).
    key: u64,
    /// Submit-time request flags (`None` when the entry chase was
    /// unreadable — unknown flags never imply backlog consent).
    req_flags: Option<u32>,
}

impl std::fmt::Debug for Outstanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outstanding")
            .field("id", &self.id)
            .field("submit_ts", &self.submit_ts)
            .field("submit_site", &self.submit_site)
            .field("key", &"<redacted>")
            .field("req_flags", &self.req_flags)
            .finish()
    }
}

/// Bounded invocation→id join: submits admit fresh opaque ids,
/// returns join the outstanding id for their invocation, callback
/// halves join by key through the adapter relation.
///
/// `Debug` is manual: the outstanding table holds kernel-issued call
/// identities, so only its length renders (round-1 sol-m9/astra-m9).
pub struct LifecycleDecoder {
    /// Maximum outstanding invocations (admission refuses past this).
    capacity: usize,
    /// Next opaque id (starts at 1; 0 is never issued; stops at
    /// [`REFUSED_FLOOR`] — the top-bit refusal range is never
    /// issued, so issuing can never meet refusal tokens).
    next_id: u64,
    /// Next refusal-contention token (counts DOWN from `u64::MAX`,
    /// stops at [`REFUSED_FLOOR`]).
    /// Decoder-admission refusals (full table, exhausted id space)
    /// never enter `outstanding`, so they mint no issued id — yet
    /// they keep contention (contract §8: a refused submit keeps
    /// its key contended) under one of these tokens, which live
    /// ONLY in the `uncovered` map. Top-down within the
    /// at-or-above-floor range so they can NEVER collide with
    /// issued ids (which count UP from 1 below the floor): the
    /// partition holds unconditionally, not after 2^64 admissions.
    /// Parks below the floor rather than wrapping into the issued
    /// range or silently reissuing (P4r4/P4r5: parked refusals
    /// recycle the oldest refusal-range slot loud — never a
    /// still-issued slot — or gap the refused key now when none
    /// is recyclable).
    next_refused: u64,
    /// Outstanding BPF invocation → submit facts. The invocation is
    /// the op-join identity: a return joins ONLY the id outstanding
    /// under its own invocation.
    outstanding: HashMap<u64, Outstanding>,
    /// Loss counters.
    stats: DecodeStats,
    /// Callback-adapter identity relation (P4: key → token cover;
    /// same capacity scale as the outstanding table — one
    /// decode-bound scale for all decode tables).
    adapter: AsyncAdapter,
    /// Refusal contention (P4r2, contract §8; P4r3: decoder
    /// refusals included): refused token → key for submits the
    /// adapter could not cover AND submits the decoder could not
    /// admit (P4R2-N1: an admitted-but-uncovered token and a
    /// never-admitted submit are equally unattributable). A callback
    /// naming a contended key gaps instead of joining — the
    /// evidence is unattributable. Cleared when the refused token
    /// completes by an adapter-visible path (sync-terminal return
    /// or decoder gap); entries for queued-forever tokens linger
    /// until the sensor drains (bounded below, never silent).
    uncovered: HashMap<u64, u64>,
    /// Contended key → outstanding refused count (drives the
    /// callback branch; kept in sync with `uncovered`).
    uncovered_keys: HashMap<u64, u64>,
    /// Refused-token FIFO oldest-first (loud overflow eviction).
    uncovered_order: VecDeque<u64>,
}

impl std::fmt::Debug for LifecycleDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifecycleDecoder")
            .field("capacity", &self.capacity)
            .field("next_id", &self.next_id)
            .field("outstanding", &self.outstanding.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl LifecycleDecoder {
    /// New decoder with a bounded outstanding table.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_id: 1,
            next_refused: u64::MAX,
            outstanding: HashMap::new(),
            stats: DecodeStats::default(),
            adapter: AsyncAdapter::new(capacity),
            uncovered: HashMap::new(),
            uncovered_keys: HashMap::new(),
            uncovered_order: VecDeque::new(),
        }
    }

    /// Current loss counters.
    #[must_use]
    pub fn stats(&self) -> DecodeStats {
        self.stats
    }

    /// Current callback-adapter loss counters (the P4 feed:
    /// submits cover, sync returns and gaps retire, callbacks
    /// resolve through the relation).
    #[must_use]
    pub fn adapter_stats(&self) -> AdapterStats {
        self.adapter.stats()
    }

    /// Feed one ring record: validate, join, and emit zero or more
    /// T05 edges. Invalid records count `bad_records` and emit nothing.
    /// The composed step for tests and single-record harnesses;
    /// production ([`SensorCore::ingest_records`](crate::kcrypto_lifecycle::sensor::SensorCore::ingest_records))
    /// splits [`decode_record`] + [`LifecycleDecoder::join`] to tally
    /// the per-hook hit between validation and join (`feed` cannot
    /// report the hook). Held gate: no production caller by design.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Edge> {
        match decode_record(bytes) {
            Ok(raw) => self.join(raw),
            Err(_) => {
                self.count_bad_record();
                Vec::new()
            }
        }
    }

    /// Join one validated raw edge (the post-parse half of [`Self::feed`],
    /// split so the sensor tallies per-hook hits from the same parse).
    /// Tainted edges refuse quietly WITHOUT touching the table:
    /// per-call cookies isolate invocations, so a tainted edge (which
    /// names no invocation) disturbs no outstanding id — the paired
    /// exit of a live call still arrives under its own cookie.
    ///
    /// Compatibility entry (P3): carries no transform binding — the
    /// sensor resolves submit lifetimes through [`Self::join_with_tfm`].
    pub fn join(&mut self, raw: RawEdge) -> Vec<Edge> {
        self.join_inner(raw, None, None)
    }

    /// Join one validated raw edge with its submit-lifetime binding
    /// (P3): `tfm_id` is the live generation behind the submit's
    /// frontend (resolved by the sensor AFTER first-seen admission),
    /// `epoch` that generation's configuration era AT SUBMIT.
    /// Unknown/ambiguous binding stays explicit (`None`) and never
    /// destroys the invocation identity; an epoch without a
    /// generation is not expressible and coerces to `None` (a caller
    /// slip must not mint phantom keying eras). Returns ignore both
    /// (the binding rode the submit).
    pub fn join_with_tfm(
        &mut self,
        raw: RawEdge,
        tfm_id: Option<u64>,
        epoch: Option<u64>,
    ) -> Vec<Edge> {
        let epoch = if tfm_id.is_none() { None } else { epoch };
        self.join_inner(raw, tfm_id, epoch)
    }

    /// Shared join body: taint refusal, then
    /// submit/complete/callback dispatch.
    fn join_inner(&mut self, raw: RawEdge, tfm_id: Option<u64>, epoch: Option<u64>) -> Vec<Edge> {
        if raw.tainted {
            // Callback halves from bytes are never tainted (the twin
            // pins `flags == 0`); a hand-built tainted callback lands
            // here and counts without joining, like a return.
            if raw.edge == LEDGE_SUBMIT {
                self.stats.submit_refused += 1;
            } else {
                self.stats.unknown_invoc_returns += 1;
            }
            return Vec::new();
        }
        if raw.edge == LEDGE_SUBMIT {
            self.submit(raw, tfm_id, epoch)
        } else if raw.edge == LEDGE_CALLBACK {
            self.callback(raw)
        } else {
            self.complete(raw)
        }
    }

    /// Count one record that failed twin validation (the caller's
    /// parse already classified it; this only bumps the counter).
    pub fn count_bad_record(&mut self) {
        self.stats.bad_records += 1;
    }

    /// Retain refusal contention for a DECODER-refused submit
    /// (contract §8, P4r3): admission refusals never reach
    /// `note_submit`, so without this the refused key keeps no
    /// contention and a later callback joins the wrong live token
    /// (P4R2-N1). Mints a contention-only token (never an issued
    /// id — nothing is emitted for the refused submit) while the
    /// refusal range lasts; past the floor the allocator parks and
    /// the refusal recycles loud instead (P4r4/P4r5 — never below
    /// the floor, never silent reuse, never a still-issued slot).
    fn retain_refused(&mut self, req_key: u64, out: &mut Vec<Edge>) {
        if self.next_refused >= REFUSED_FLOOR {
            let token = self.next_refused;
            // At or above the floor, hence nonzero: cannot underflow.
            self.next_refused -= 1;
            self.retain_contention(req_key, token, out);
        } else {
            self.retain_refused_exhausted(req_key, out);
        }
    }

    /// Retain refusal contention after the refusal-token range is
    /// exhausted (contract §8, P4r4/P4r5): NEVER mint below the
    /// floor (issued-id range) and NEVER silently reissue a
    /// resident token. The contention table is SHARED — adapter
    /// cover-refusals retain under the submit's issued id (below
    /// the floor, possibly still outstanding) while decoder
    /// refusals retain under refusal-range tokens — so recycle
    /// the oldest REFUSAL-RANGE slot only, LOUD: evict it with a
    /// key gap exactly like capacity overflow, then reuse its
    /// (now unresident, still refusal-range) token for the new
    /// entry. Still-issued slots are skipped, never recycled:
    /// reusing one would alias the new refusal to another
    /// request's id, whose later retirement (`clear_uncovered`
    /// on sync-terminal return or same-invocation replacement)
    /// would silently erase this refusal's contention and misjoin
    /// a callback (P4R4-N1). Net table size unchanged, so the
    /// map, the key counts, and the FIFO all stay bounded. With
    /// no refusal-range slot to recycle (empty table, or only
    /// still-issued slots, at exhaustion), gap the refused key
    /// now (loud) and retain nothing — the refusal itself stays
    /// counted by the caller.
    fn retain_refused_exhausted(&mut self, req_key: u64, out: &mut Vec<Edge>) {
        let mut skipped: Vec<u64> = Vec::new();
        let mut slot: Option<(u64, u64)> = None;
        while let Some(old) = self.uncovered_order.pop_front() {
            if old < REFUSED_FLOOR {
                // Still-issued slot — an adapter-refused submit's
                // own id, possibly still outstanding: never
                // recycle (P4R4-N1). Hold it aside and scan on.
                skipped.push(old);
            } else if let Some(old_key) = self.uncovered.remove(&old) {
                slot = Some((old, old_key));
                break;
            }
        }
        // Skipped issued slots keep their FIFO places (oldest
        // first; anything no longer resident drops).
        for tok in skipped.into_iter().rev() {
            if self.uncovered.contains_key(&tok) {
                self.uncovered_order.push_front(tok);
            }
        }
        let Some((old, old_key)) = slot else {
            // No refusal-range slot to recycle: gap the refused
            // key now (loud) and retain nothing — the refusal
            // itself stays counted by the caller.
            out.extend(self.adapter.gap_key(req_key));
            return;
        };
        Self::decrement_key(&mut self.uncovered_keys, old_key);
        out.extend(self.adapter.gap_key(old_key));
        self.uncovered.insert(old, req_key);
        self.uncovered_keys
            .entry(req_key)
            .and_modify(|n| *n += 1)
            .or_insert(1);
        self.uncovered_order.push_back(old);
    }

    /// Retain refusal contention for a submit the adapter could
    /// not cover (contract §8): past the decode-scale bound the
    /// oldest contention is forgotten LOUD — its key gaps at this
    /// submit (edges appended to `out`) instead of growing without
    /// bound or misjoining silently.
    fn retain_contention(&mut self, req_key: u64, token: u64, out: &mut Vec<Edge>) {
        if self.uncovered.len() >= self.capacity
            && let Some(old) = self.uncovered_order.pop_front()
            && let Some(old_key) = self.uncovered.remove(&old)
        {
            Self::decrement_key(&mut self.uncovered_keys, old_key);
            out.extend(self.adapter.gap_key(old_key));
        }
        self.uncovered.insert(token, req_key);
        self.uncovered_keys
            .entry(req_key)
            .and_modify(|n| *n += 1)
            .or_insert(1);
        self.uncovered_order.push_back(token);
    }

    /// Clear refusal contention for `token` (its sync-terminal
    /// return or decoder gap completed it — no callback
    /// attribution outstanding). No-op for covered/unknown tokens.
    fn clear_uncovered(&mut self, token: u64) {
        if let Some(key) = self.uncovered.remove(&token) {
            Self::decrement_key(&mut self.uncovered_keys, key);
            if let Some(pos) = self.uncovered_order.iter().position(|t| *t == token) {
                self.uncovered_order.remove(pos);
            }
        }
    }

    /// Decrement a contended key's refused count (drop at zero).
    fn decrement_key(uncovered_keys: &mut HashMap<u64, u64>, key: u64) {
        if let Some(n) = uncovered_keys.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                uncovered_keys.remove(&key);
            }
        }
    }

    /// Admit a submit under a fresh opaque id, keyed by its BPF
    /// invocation. A same-invocation resubmit (BPF ids are unique —
    /// this is twin drift or a replay) gaps the old id
    /// (`IdentityAmbiguous` — its return never arrived) first, and
    /// the old token retires in the adapter relation (its callbacks,
    /// if any, diagnose against the gap instead of misjoining; any
    /// contention it held clears — a gapped token needs no
    /// attribution). A full table or an exhausted id space refuses
    /// (counted, no phantom) — and retains refusal contention under
    /// a contention-only token (P4r3: a refused submit keeps its
    /// key contended on EVERY refusal path, so a later callback
    /// naming that key gaps instead of joining the wrong token).
    /// Same-key submits with FRESH
    /// invocations admit alongside (nested calls pair exactly —
    /// never gapped). The submit-lifetime binding (`tfm_id` +
    /// submit-pinned `epoch`) and the entry-side wire metadata ride
    /// the emitted edge; the submit's key + timestamp cover it in
    /// the adapter relation from admission (early callbacks must
    /// join) — or, past live capacity, retain refusal contention
    /// (a later callback naming that key gaps instead of joining
    /// the wrong token).
    fn submit(&mut self, raw: RawEdge, tfm_id: Option<u64>, epoch: Option<u64>) -> Vec<Edge> {
        let mut out = Vec::new();
        if let Some(old) = self.outstanding.remove(&raw.invoc) {
            self.stats.gaps_synthesized += 1;
            self.adapter.note_gap(old.key, old.id);
            self.clear_uncovered(old.id);
            out.push(Edge::Gap {
                id: old.id,
                reason: GapReason::IdentityAmbiguous,
            });
        }
        if self.outstanding.len() >= self.capacity {
            self.stats.submit_refused += 1;
            self.retain_refused(raw.key, &mut out);
            return out;
        }
        // The floor is never issued (partition headroom, P4r4):
        // exhaustion refuses admission instead of minting into the
        // refusal-token range (lifetime-unique ids are a T08
        // prerequisite; disjoint ranges are a §8 prerequisite).
        if self.next_id >= REFUSED_FLOOR {
            self.stats.submit_refused += 1;
            self.retain_refused(raw.key, &mut out);
            return out;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.outstanding.insert(
            raw.invoc,
            Outstanding {
                id,
                submit_ts: raw.ts_ns,
                submit_site: raw.site,
                key: raw.key,
                req_flags: raw.req_flags,
            },
        );
        if !self.adapter.note_submit(raw.key, id, raw.ts_ns) {
            self.retain_contention(raw.key, id, &mut out);
        }
        self.stats.admitted += 1;
        out.push(Edge::Submit {
            id,
            tfm_id,
            ts_ns: raw.ts_ns,
            meta: RequestMeta {
                family: raw.family,
                direction: raw.direction,
                cryptlen: raw.cryptlen,
                req_flags: raw.req_flags,
                epoch,
                // v6 submits are skcipher-only (the twin refuses any
                // other family): no AEAD extension rides them. The v7
                // wire slice carries `RawEdge` AEAD scalars here.
                aead: None,
            },
        });
        out
    }

    /// Join a return to the outstanding id for its invocation. Unknown
    /// invocations count and emit nothing — no phantom completions. A
    /// return PREDATING the outstanding submit, or from the OTHER site
    /// (one call, one function — a cross-site return cannot be this
    /// invocation's), is stale and is refused without disturbing the
    /// outstanding id. Ties join (coarse-clock ambiguity, pinned).
    /// The return classifies through the adapter contract (P4: the
    /// SUBMIT's flags gate `-EBUSY` backlog consent — unknown flags
    /// never imply it); a sync-terminal return retires its token in
    /// the adapter relation (and clears any contention it held — a
    /// sync result needs no callback attribution), while
    /// `Queued`/`Unresolved` returns keep cover (terminal truth may
    /// still arrive via callback).
    fn complete(&mut self, raw: RawEdge) -> Vec<Edge> {
        let open = match self.outstanding.get(&raw.invoc) {
            None => {
                self.stats.unknown_invoc_returns += 1;
                return Vec::new();
            }
            Some(open) => {
                if raw.ts_ns < open.submit_ts || raw.site != open.submit_site {
                    self.stats.stale_returns += 1;
                    return Vec::new();
                }
                *open
            }
        };
        self.outstanding.remove(&raw.invoc);
        let disposition = classify_return(raw.status, open.req_flags);
        if disposition == ReturnDisposition::Terminal {
            self.adapter.note_sync_return(open.key, open.id);
            self.clear_uncovered(open.id);
        }
        vec![Edge::Return {
            id: open.id,
            ts_ns: raw.ts_ns,
            status: raw.status,
            disposition,
        }]
    }

    /// Join a callback half by key through the adapter identity
    /// relation (contract §8 dispatch): a CONTENDED key gaps every
    /// live token under it first (unattributable evidence — a
    /// refused submit is outstanding under that key — never joins
    /// the wrong token); otherwise exactly-one-live joins (a
    /// terminal callback retires live → dead; progress never
    /// retires), multi-live gaps every live token loud, newest-dead
    /// re-joins for reducer diagnosis, else a counted orphan. The
    /// adapter pins each live token's submit timestamp, so a
    /// callback predating its submit is consumed stale, never
    /// joined. Emits zero or more edges (the callback edge and/or
    /// identity gaps).
    fn callback(&mut self, raw: RawEdge) -> Vec<Edge> {
        if self.uncovered_keys.contains_key(&raw.key) {
            return self.adapter.gap_key(raw.key);
        }
        self.adapter
            .resolve_callback(raw.key, raw.ts_ns, raw.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_core::kcrypto::{LifecycleReducer, Terminal};

    /// Token-space partition pinned by these tests (P4r4): issued
    /// ids below, refusal-contention tokens at/above. The boundary
    /// value is asserted behaviorally on both sides (every issued
    /// id `< PARTITION`, every refusal token `>= PARTITION`), so
    /// the source constant cannot drift from this pin. Seeds skip
    /// astronomically large valid prefixes; only boundary suffixes
    /// run live.
    const PARTITION: u64 = 1 << 63;

    fn raw(edge: u8, key: u64, invoc: u64, ts_ns: u64, status: i32) -> RawEdge {
        RawEdge {
            edge,
            site: if edge == LEDGE_CALLBACK {
                LSITE_CB_CRYPTD
            } else {
                LSITE_ENC
            },
            tainted: false,
            key,
            ts_ns,
            status,
            invoc,
            tfm: 0,
            drv: String::new(),
            truncated: false,
            cryptlen: if edge == LEDGE_SUBMIT { Some(16) } else { None },
            req_flags: if edge == LEDGE_SUBMIT { Some(0) } else { None },
            family: LifecycleFamily::Skcipher,
            direction: OpDirection::Encrypt,
        }
    }

    #[test]
    fn decoder_boundary_issued_refusal_ranges_never_meet() {
        // P4R3-N1: forcing the issued allocator against the refusal
        // range must refuse LOUD (never mint an issued id a refusal
        // token could meet) and must never misjoin.
        let mut d = LifecycleDecoder::new(4);
        d.next_id = PARTITION - 2;
        let mut reducer = LifecycleReducer::new(4);
        let mut records = Vec::new();
        for row in [
            raw(LEDGE_SUBMIT, 0xA21, 0xA210, 100, 0), // A: id PARTITION-2
            raw(LEDGE_RETURN, 0xA21, 0xA210, 110, -libc::EINPROGRESS),
            raw(LEDGE_SUBMIT, 0xD21, 0xD210, 180, 0), // D: id PARTITION-1
            raw(LEDGE_SUBMIT, 0xE21, 0xE210, 190, 0), // X: refused (floor)
            raw(LEDGE_SUBMIT, 0xA21, 0xA212, 200, 0), // B: refused (floor)
        ] {
            for e in d.join(row) {
                records.extend(reducer.apply(e));
            }
        }
        // The issued allocator stops AT the floor: loud refusal,
        // contention kept under refusal-range tokens.
        assert_eq!(d.next_id, PARTITION);
        assert_eq!(d.stats().submit_refused, 2);
        assert_eq!(d.uncovered.get(&u64::MAX), Some(&0xE21));
        assert_eq!(d.uncovered.get(&(u64::MAX - 1)), Some(&0xA21));
        assert!(d.uncovered.keys().all(|t| *t >= PARTITION));
        // D's sync return retires D's own issued token only — B's
        // refusal contention survives (the ranges never meet).
        for e in d.join(raw(LEDGE_RETURN, 0xD21, 0xD210, 230, 0)) {
            records.extend(reducer.apply(e));
        }
        assert!(d.uncovered_keys.contains_key(&0xA21));
        let callback = d.join(raw(LEDGE_CALLBACK, 0xA21, 0, 250, 0));
        for e in callback.iter().cloned() {
            records.extend(reducer.apply(e));
        }
        assert_eq!(d.adapter_stats().ambiguous_keys, 1);
        assert!(
            !records
                .iter()
                .any(|r| r.id == PARTITION - 2 && r.terminal == Terminal::Callback(0)),
            "a forced meeting attempt must refuse loud, never join B's terminal to A"
        );
    }

    #[test]
    fn decoder_boundary_refusal_tokens_stop_at_floor() {
        // P4R3-N1/N2 (floor): the last fresh refusal token is the
        // floor itself (top bit set); past it the allocator parks
        // — it never mints below the floor and never silently
        // reuses. The parked refusal recycles the oldest slot LOUD
        // (eviction gap), keeping every table bounded.
        let mut d = LifecycleDecoder::new(2);
        let _ = d.join(raw(LEDGE_SUBMIT, 0xB31, 0xB310, 100, 0));
        let _ = d.join(raw(LEDGE_SUBMIT, 0xF31, 0xF311, 110, 0));
        // Outstanding full (2/2); park the issued allocator past
        // the floor too so every further submit refuses.
        d.next_id = u64::MAX;
        d.next_refused = PARTITION;
        let before = d.adapter_stats();
        d.join(raw(LEDGE_SUBMIT, 0xB31, 0xB312, 200, 0)); // R1: token PARTITION
        assert_eq!(d.next_refused, PARTITION - 1);
        assert_eq!(d.uncovered.get(&PARTITION), Some(&0xB31));
        d.join(raw(LEDGE_SUBMIT, 0xC31, 0xC312, 210, 0)); // R2: parked, loud recycle
        let after = d.adapter_stats();
        // Every table bounded; every resident token refusal-range;
        // the parked allocator never wrapped or re-minted.
        assert!(d.uncovered.len() <= d.capacity);
        assert!(d.uncovered_keys.len() <= d.capacity);
        assert!(d.uncovered_order.len() <= d.capacity);
        assert!(d.uncovered.keys().all(|t| *t >= PARTITION));
        assert_eq!(d.next_refused, PARTITION - 1);
        // Loud, exactly once: the evicted key's live cover gaps.
        assert_eq!(d.stats().submit_refused, 2);
        assert_eq!(after.ambiguous_keys, before.ambiguous_keys + 1);
        assert_eq!(after.callback_orphans, before.callback_orphans);
    }

    #[test]
    fn decoder_boundary_saturated_refusals_keep_every_table_bounded() {
        // P4R3-N2: a parked (saturated) refusal allocator must keep
        // EVERY contention table bounded — map, key counts, and FIFO
        // alike — with loud per-refusal accounting and no silent
        // token reuse. Seeded after prior refusals minted MAX-1 then
        // MAX-2.
        let mut d = LifecycleDecoder::new(2);
        d.next_id = u64::MAX; // Issued allocator exhausted: every submit refuses.
        d.next_refused = 1; // Refusal range fully spent: every refusal recycles.
        let mut ignored = Vec::new();
        d.retain_contention(0xF30, u64::MAX - 1, &mut ignored);
        d.retain_contention(0xF31, u64::MAX - 2, &mut ignored);
        assert!(ignored.is_empty());
        for i in 0..8u64 {
            d.join(raw(LEDGE_SUBMIT, 0xF40 + i, 0xF400 + 2 * i, 100 + i, 0));
        }
        assert_eq!(d.stats().submit_refused, 8);
        assert!(d.uncovered.len() <= d.capacity);
        assert!(d.uncovered_keys.len() <= d.capacity);
        assert!(d.uncovered_order.len() <= d.capacity);
        assert!(d.uncovered.keys().all(|t| *t >= PARTITION));
        assert_eq!(
            d.next_refused, 1,
            "a parked allocator never wraps or re-mints"
        );
        // Loud, exactly once per refusal: no live cover exists, so
        // each recycled eviction reads orphan (counted, never silent).
        assert_eq!(d.adapter_stats().callback_orphans, 8);
        assert_eq!(d.adapter_stats().ambiguous_keys, 0);
    }

    /// Assert every contention table stays bounded and mutually
    /// consistent (map, key counts, and FIFO within capacity;
    /// FIFO tokens exactly the map keys, unique; key counts
    /// exactly the map multiplicities).
    fn assert_contention_bounded(d: &LifecycleDecoder) {
        assert!(d.uncovered.len() <= d.capacity);
        assert!(d.uncovered_keys.len() <= d.capacity);
        assert!(d.uncovered_order.len() <= d.capacity);
        assert_eq!(d.uncovered.len(), d.uncovered_order.len());
        let mut counts = HashMap::new();
        for key in d.uncovered.values() {
            *counts.entry(*key).or_insert(0_u64) += 1;
        }
        assert_eq!(counts, d.uncovered_keys);
        let tokens: std::collections::HashSet<_> = d.uncovered_order.iter().copied().collect();
        assert_eq!(tokens.len(), d.uncovered_order.len());
        assert_eq!(tokens, d.uncovered.keys().copied().collect());
    }

    /// Mixed-table exhaustion setup (P4R4-N1): capacity two; two
    /// covered queued submits fill adapter cover; two further
    /// admitted submits lose cover and retain contention under
    /// their still-issued ids; then two decoder refusals (X, then
    /// B reusing A's key) join with the refusal allocator seeded
    /// at `refused_seed`. Returns the decoder, a reducer, and the
    /// records emitted so far.
    fn mixed_issued_refusal_table(
        refused_seed: u64,
    ) -> (
        LifecycleDecoder,
        LifecycleReducer,
        Vec<kryprobe_core::kcrypto::RequestRecord>,
    ) {
        const A_KEY: u64 = 0x71;
        let mut d = LifecycleDecoder::new(2);
        let mut reducer = LifecycleReducer::new(8);
        let mut records = Vec::new();
        for row in [
            raw(LEDGE_SUBMIT, 0x71, 0x710, 1000, 0), // A: id 1, covered
            raw(LEDGE_RETURN, 0x71, 0x710, 1010, -libc::EINPROGRESS),
            raw(LEDGE_SUBMIT, 0x72, 0x720, 1020, 0), // Q: id 2, covered
            raw(LEDGE_RETURN, 0x72, 0x720, 1030, -libc::EINPROGRESS),
            raw(LEDGE_SUBMIT, 0x73, 0x730, 1040, 0), // D: id 3, cover refused
            raw(LEDGE_SUBMIT, 0x74, 0x740, 1050, 0), // E: id 4, cover refused
        ] {
            for e in d.join(row) {
                records.extend(reducer.apply(e));
            }
            assert_contention_bounded(&d);
        }
        assert_eq!(d.uncovered.get(&3), Some(&0x73));
        assert_eq!(d.uncovered.get(&4), Some(&0x74));
        d.next_refused = refused_seed; // skip the astronomical refusal prefix only
        for row in [
            raw(LEDGE_SUBMIT, 0x75, 0x750, 1090, 0), // X: last fresh token
            raw(LEDGE_SUBMIT, A_KEY, 0x711, 1100, 0), // B: A's key, exhausted
        ] {
            for e in d.join(row) {
                records.extend(reducer.apply(e));
            }
            assert_contention_bounded(&d);
        }
        assert_eq!(d.stats().admitted, 4);
        assert_eq!(d.stats().submit_refused, 2);
        assert!(
            d.uncovered_keys.contains_key(&A_KEY),
            "B must keep A's key contended"
        );
        (d, reducer, records)
    }

    #[test]
    fn decoder_boundary_exhausted_recycle_skips_issued_sync_return() {
        // P4R4-N1 (sync-return retirement): the exhausted recycle
        // must reuse a refusal-range slot ONLY — never E's
        // still-issued id — so E's sync return retires E alone
        // and B's contention survives to gap A (never misjoin).
        let (mut d, mut reducer, mut records) = mixed_issued_refusal_table(PARTITION);
        // B recycled X's refusal-range token; E's issued slot is untouched.
        assert_eq!(d.uncovered.get(&PARTITION), Some(&0x71));
        assert_eq!(d.uncovered.get(&4), Some(&0x74));
        assert_eq!(d.next_refused, PARTITION - 1);
        for e in d.join(raw(LEDGE_RETURN, 0x74, 0x740, 1130, 0)) {
            records.extend(reducer.apply(e));
        }
        assert!(
            records
                .iter()
                .any(|r| r.id == 4 && r.terminal == Terminal::Sync(0) && r.duration_ns == Some(80)),
            "E keeps its own sync terminal"
        );
        assert!(
            d.uncovered_keys.contains_key(&0x71),
            "E's retirement must clear E only, never decoder-refused B"
        );
        for e in d.join(raw(LEDGE_CALLBACK, 0x71, 0, 1200, 0)) {
            records.extend(reducer.apply(e));
        }
        assert_contention_bounded(&d);
        assert_eq!(d.adapter_stats().ambiguous_keys, 1);
        assert!(
            !records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Callback(0)),
            "recycling a still-issued token must not let its retirement erase B and give B's terminal to A"
        );
        assert!(
            records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Unknown && r.duration_ns.is_none()),
            "A gaps on its contended key"
        );
    }

    #[test]
    fn decoder_boundary_exhausted_recycle_skips_issued_duplicate_invoc() {
        // P4R4-N1 (same-invocation retirement): the duplicate-submit
        // path retires through the same `clear_uncovered` — it must
        // likewise clear E alone and leave B's contention intact.
        let (mut d, mut reducer, mut records) = mixed_issued_refusal_table(PARTITION);
        assert_eq!(d.uncovered.get(&PARTITION), Some(&0x71));
        assert_eq!(d.uncovered.get(&4), Some(&0x74));
        // E's invocation resubmits: the old id gaps ambiguous and
        // retires; the resubmit admits fresh (E left room).
        for e in d.join(raw(LEDGE_SUBMIT, 0x79, 0x740, 1130, 0)) {
            records.extend(reducer.apply(e));
        }
        assert_eq!(d.stats().gaps_synthesized, 1);
        assert_eq!(d.stats().admitted, 5);
        assert!(
            d.uncovered_keys.contains_key(&0x71),
            "duplicate-invocation retirement must clear E only, never B"
        );
        for e in d.join(raw(LEDGE_CALLBACK, 0x71, 0, 1200, 0)) {
            records.extend(reducer.apply(e));
        }
        assert_contention_bounded(&d);
        assert_eq!(d.adapter_stats().ambiguous_keys, 1);
        assert!(
            !records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Callback(0)),
            "duplicate-invocation retirement must not erase B and misjoin A"
        );
        assert!(
            records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Unknown && r.duration_ns.is_none()),
            "A gaps on its contended key"
        );
    }

    #[test]
    fn decoder_boundary_post_exhaustion_admits_gap_now_loud() {
        // P4R4-N1 (post-exhaustion admission): adapter-refused D/E
        // admitted AFTER refusal exhaustion leave a table with NO
        // refusal-range slot — the next decoder refusal must gap
        // the refused key NOW (loud) and retain nothing, never
        // borrow a still-issued id. Every earlier eviction is a
        // counted orphan (no live cover under those keys); the
        // gap-now hits live cover (ambiguous).
        let mut d = LifecycleDecoder::new(2);
        d.next_refused = PARTITION + 2; // skip the astronomical prefix only
        let mut reducer = LifecycleReducer::new(8);
        let mut records = Vec::new();
        for row in [
            raw(LEDGE_SUBMIT, 0x61, 0x610, 2000, 0), // A: id 1, covered
            raw(LEDGE_SUBMIT, 0x62, 0x620, 2010, 0), // Q: id 2, covered
            raw(LEDGE_SUBMIT, 0x6A, 0x6A0, 2020, 0), // F0: token PARTITION+2
            raw(LEDGE_SUBMIT, 0x6B, 0x6B0, 2021, 0), // F1: token PARTITION+1
            raw(LEDGE_SUBMIT, 0x6C, 0x6C0, 2022, 0), // F2: token PARTITION
            raw(LEDGE_RETURN, 0x61, 0x610, 2030, -libc::EINPROGRESS),
            raw(LEDGE_RETURN, 0x62, 0x620, 2031, -libc::EINPROGRESS),
            raw(LEDGE_SUBMIT, 0x63, 0x630, 2040, 0), // D: id 3, cover refused
            raw(LEDGE_SUBMIT, 0x64, 0x640, 2050, 0), // E: id 4, cover refused
        ] {
            for e in d.join(row) {
                records.extend(reducer.apply(e));
            }
            assert_contention_bounded(&d);
        }
        assert_eq!(d.next_refused, PARTITION - 1);
        assert_eq!(d.uncovered.get(&3), Some(&0x63));
        assert_eq!(d.uncovered.get(&4), Some(&0x64));
        assert!(d.uncovered.keys().all(|t| *t < PARTITION));
        // B reuses A's key at exhaustion: no refusal-range slot —
        // gap A's live cover now (loud), retain nothing.
        for e in d.join(raw(LEDGE_SUBMIT, 0x61, 0x611, 2100, 0)) {
            records.extend(reducer.apply(e));
        }
        assert_eq!(d.stats().submit_refused, 4);
        assert_eq!(d.adapter_stats().callback_orphans, 3);
        assert_eq!(d.adapter_stats().ambiguous_keys, 1);
        assert!(!d.uncovered_keys.contains_key(&0x61));
        assert_eq!(d.uncovered.get(&3), Some(&0x63));
        assert_eq!(d.uncovered.get(&4), Some(&0x64));
        assert!(
            records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Unknown && r.duration_ns.is_none()),
            "the gap-now refusal gaps A loud at the refusing submit"
        );
        // D's sync return retires D alone; E's issued slot is intact.
        for e in d.join(raw(LEDGE_RETURN, 0x63, 0x630, 2130, 0)) {
            records.extend(reducer.apply(e));
        }
        assert!(
            records
                .iter()
                .any(|r| r.id == 3 && r.terminal == Terminal::Sync(0) && r.duration_ns == Some(90)),
            "D keeps its own sync terminal"
        );
        assert_eq!(d.uncovered.get(&4), Some(&0x64));
        // The late callback rejoins A's tombstone for reducer
        // diagnosis: counted, never a second terminal for A.
        for e in d.join(raw(LEDGE_CALLBACK, 0x61, 0, 2150, 0)) {
            records.extend(reducer.apply(e));
        }
        assert_contention_bounded(&d);
        assert_eq!(
            records.iter().filter(|r| r.id == 1).count(),
            1,
            "A completes exactly once, as Unknown"
        );
        assert!(
            !records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Callback(0)),
            "post-exhaustion admits must not reintroduce issued tokens as reusable refusal identities"
        );
    }

    #[test]
    fn decoder_boundary_mixed_fresh_token_control() {
        // Positive control for the mixed-table shape: with one
        // fresh refusal token left, B needs no recycle — E's
        // retirement is trivially safe and A still gaps (the
        // setup itself never misjoins).
        let (mut d, mut reducer, mut records) = mixed_issued_refusal_table(PARTITION + 1);
        assert!(d.uncovered.keys().all(|t| *t >= PARTITION));
        assert_eq!(d.uncovered.get(&PARTITION), Some(&0x71));
        assert_eq!(d.next_refused, PARTITION - 1);
        for e in d.join(raw(LEDGE_RETURN, 0x74, 0x740, 1130, 0)) {
            records.extend(reducer.apply(e));
        }
        assert!(d.uncovered_keys.contains_key(&0x71));
        for e in d.join(raw(LEDGE_CALLBACK, 0x71, 0, 1200, 0)) {
            records.extend(reducer.apply(e));
        }
        assert_contention_bounded(&d);
        assert_eq!(d.adapter_stats().ambiguous_keys, 1);
        assert!(
            !records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Callback(0))
        );
        assert!(
            records
                .iter()
                .any(|r| r.id == 1 && r.terminal == Terminal::Unknown && r.duration_ns.is_none())
        );
    }
}
