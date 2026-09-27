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
    /// Next opaque id (starts at 1; 0 is never issued).
    next_id: u64,
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
    /// Refusal contention (P4r2, contract §8): refused token →
    /// key for submits the adapter could not cover. A callback
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
    /// (counted, no phantom). Same-key submits with FRESH
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
            return out;
        }
        // `u64::MAX` is never issued (sentinel headroom): exhaustion
        // refuses admission instead of wrapping ids (lifetime-unique
        // ids are a T08 prerequisite).
        if self.next_id == u64::MAX {
            self.stats.submit_refused += 1;
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
