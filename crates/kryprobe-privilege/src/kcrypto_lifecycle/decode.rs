// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw-edge decode: v3 `LEdge` bytes → T05 `Edge` events (T06).
//!
//! The join is keyed by (kernel request pointer, BPF invocation id):
//! a submit admits a fresh opaque id recording its invocation, and a
//! return joins the outstanding id for its key ONLY when the
//! invocation matches. Raw keys never leave this module (only opaque
//! ids reach `Edge`); every refusal is counted, never silent.
//!
//! Invocation identity (round-4 W4): BPF issues one id per submit
//! and the slot carries it to the matching return, so a return from
//! a DIFFERENT invocation — a later call after a lost return + lost
//! submit, or a nested call's return — can never alias onto the
//! outstanding id: the invocation mismatches and the return refuses
//! stale with the outstanding id kept. Pairing soundness no longer
//! depends on lossless transport.
//!
//! Disturbance signals (unchanged): BPF TAINTS what it cannot pair —
//! a submit nested over an outstanding call, or a return with no
//! outstanding submit. A tainted submit on an outstanding key gaps
//! that id `IdentityAmbiguous` promptly; tainted returns and
//! tainted submits with nothing outstanding refuse quietly. A CLEAN
//! same-key submit while an id is outstanding proves the old
//! invocation ended without a delivered return (the BPF slot empties
//! only on a return release): the old id gaps `IdentityAmbiguous`
//! and the new submit admits fresh. Site is stored per submit and
//! checked per return (one call, one function — cross-site returns
//! refuse stale).

use kryprobe_abi::kcrypto_lifecycle::{
    LEDGE_INVOC_POISON, LEDGE_MAGIC, LEDGE_RETURN, LEDGE_SUBMIT, LEDGE_TAINTED, LEDGE_VERSION,
    LSITE_DEC, LSITE_ENC,
};
use kryprobe_core::kcrypto::{Edge, GapReason, ReturnDisposition};
use std::collections::HashMap;

/// Record twin size: `LEdge` is 40 bytes on the ring.
const RECORD_LEN: usize = 40;

/// One validated raw edge (post-twin-checks, pre-join).
///
/// `Debug` is manual: [`RawEdge::key`] is a raw kernel pointer and
/// renders as `<redacted>` (round-1 sol-m9/astra-m9).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RawEdge {
    /// [`LEDGE_SUBMIT`] or [`LEDGE_RETURN`] (validated).
    pub edge: u8,
    /// [`LSITE_ENC`] or [`LSITE_DEC`] (validated; op attribution is
    /// T07/T08 scope — T06 validates the twin but carries no op).
    pub site: u16,
    /// [`LEDGE_TAINTED`] was set (BPF could not pair this edge).
    pub tainted: bool,
    /// Raw kernel request pointer (join key; never leaves decode).
    pub key: u64,
    /// Edge timestamp (ns).
    pub ts_ns: u64,
    /// Native return status (return edges) or 0 (submit edges).
    pub status: i32,
    /// BPF invocation id (the join identity; 0 on slotless edges).
    pub invoc: u64,
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
            .finish()
    }
}

/// Why one ring record produced no edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeDrop {
    /// Record is not exactly 40 bytes.
    BadLength,
    /// Magic is not [`LEDGE_MAGIC`].
    BadMagic,
    /// Version is not [`LEDGE_VERSION`].
    BadVersion,
    /// Edge kind is neither submit nor return.
    BadEdge,
    /// Site is neither encrypt nor decrypt.
    BadSite,
    /// Flags carry bits outside [`LEDGE_TAINTED`].
    BadFlags,
    /// v1 defines no aux; nonzero is twin drift.
    BadAux,
    /// Null pairing key (the BPF `BADKEY` gate should have dropped it).
    NullKey,
    /// Submit edge with a nonzero status (ABI: submit edges carry 0 —
    /// a status here is twin drift, silently discarded before).
    BadSubmitStatus,
    /// Clean (untainted) edge with a malformed invocation id: 0
    /// ("no invocation", slotless tainted edges only) or the poison
    /// bit set (poisoned slots always taint). Honest BPF never emits
    /// either shape — fail closed, never join.
    BadInvoc,
}

/// Named decode loss counters (loss ledger feed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeStats {
    /// Submits admitted (fresh opaque ids issued).
    pub admitted: u64,
    /// Submits refused (table full, id space exhausted, or BPF
    /// [`LEDGE_TAINTED`] nesting taint — never admitted; a tainted
    /// submit on an outstanding key additionally gaps that id, since
    /// no future return can be attributed after the disturbance).
    pub submit_refused: u64,
    /// Returns for keys with no outstanding submit (lost submit,
    /// pre-attach call, or BPF taint — never joined, never disturbing).
    pub unknown_key_returns: u64,
    /// Records failing twin validation.
    pub bad_records: u64,
    /// Gaps synthesized for clean same-key submits while an id is
    /// outstanding (transport loss: the old return never arrived).
    pub gaps_synthesized: u64,
    /// Returns refused against an outstanding submit: a different
    /// invocation, predating it, or from the other site (one call,
    /// one function — refused, never joined, outstanding kept).
    pub stale_returns: u64,
}

/// Validate one ring record against the v3 `LEdge` twin: exact length,
/// magic, version, edge kind, site, defined-only flags, zero aux,
/// non-null key, zero status on submit edges, and the invocation id.
pub fn decode_record(bytes: &[u8]) -> Result<RawEdge, DecodeDrop> {
    if bytes.len() != RECORD_LEN {
        return Err(DecodeDrop::BadLength);
    }
    let u16le = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
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
    if edge != LEDGE_SUBMIT && edge != LEDGE_RETURN {
        return Err(DecodeDrop::BadEdge);
    }
    let site = u16le(4);
    if site != LSITE_ENC && site != LSITE_DEC {
        return Err(DecodeDrop::BadSite);
    }
    let flags = u16le(6);
    if flags & !LEDGE_TAINTED != 0 {
        return Err(DecodeDrop::BadFlags);
    }
    let key = u64le(8);
    if key == 0 {
        return Err(DecodeDrop::NullKey);
    }
    let ts_ns = u64le(16);
    let status = i32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    if u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]) != 0 {
        return Err(DecodeDrop::BadAux);
    }
    if edge == LEDGE_SUBMIT && status != 0 {
        return Err(DecodeDrop::BadSubmitStatus);
    }
    let invoc = u64le(32);
    let tainted = flags & LEDGE_TAINTED != 0;
    if !tainted && (invoc == 0 || invoc & LEDGE_INVOC_POISON != 0) {
        return Err(DecodeDrop::BadInvoc);
    }
    Ok(RawEdge {
        edge,
        site,
        tainted,
        key,
        ts_ns,
        status,
        invoc,
    })
}

/// Classify a native return status per the T06 adapter contract:
/// `-EINPROGRESS` queues for async completion; `-EBUSY` is
/// [`ReturnDisposition::Unresolved`] (design:71 — accepted backlog
/// only when the path/flags contract establishes it, and this edge
/// carries no flags); every other status — 0, positive, or a sync
/// error — is terminal with that status.
fn classify_return(status: i32) -> ReturnDisposition {
    if status == -libc::EINPROGRESS {
        ReturnDisposition::Queued
    } else if status == -libc::EBUSY {
        ReturnDisposition::Unresolved
    } else {
        ReturnDisposition::Terminal
    }
}

/// Bounded key→id join: submits admit fresh opaque ids, returns join
/// the outstanding id for their key.
///
/// `Debug` is manual: the outstanding table is keyed by raw kernel
/// pointers, so only its length renders (round-1 sol-m9/astra-m9).
pub struct LifecycleDecoder {
    /// Maximum outstanding keys (admission refuses past this).
    capacity: usize,
    /// Next opaque id (starts at 1; 0 is never issued).
    next_id: u64,
    /// Outstanding key → (opaque id, submit ts, submit site, BPF
    /// invocation id). The invocation is the join identity: a return
    /// joins ONLY on invocation equality.
    outstanding: HashMap<u64, (u64, u64, u16, u64)>,
    /// Loss counters.
    stats: DecodeStats,
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
        }
    }

    /// Current loss counters.
    #[must_use]
    pub fn stats(&self) -> DecodeStats {
        self.stats
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
    /// A tainted SUBMIT on an outstanding key gaps that id
    /// (`IdentityAmbiguous`) FIRST: the BPF slot poisoned, so no
    /// future return can be attributed to the outstanding invocation
    /// (the first return could be either call's — joining it would
    /// complete the wrong invocation with a trusted terminal).
    /// Tainted submits with no outstanding id, and all tainted
    /// returns, refuse without touching the table.
    pub fn join(&mut self, raw: RawEdge) -> Vec<Edge> {
        if raw.tainted {
            if raw.edge == LEDGE_SUBMIT {
                self.stats.submit_refused += 1;
                if let Some((old_id, _, _, _)) = self.outstanding.remove(&raw.key) {
                    self.stats.gaps_synthesized += 1;
                    return vec![Edge::Gap {
                        id: old_id,
                        reason: GapReason::IdentityAmbiguous,
                    }];
                }
            } else {
                self.stats.unknown_key_returns += 1;
            }
            return Vec::new();
        }
        if raw.edge == LEDGE_SUBMIT {
            self.submit(raw)
        } else {
            self.complete(raw)
        }
    }

    /// Count one record that failed twin validation (the caller's
    /// parse already classified it; this only bumps the counter).
    pub fn count_bad_record(&mut self) {
        self.stats.bad_records += 1;
    }

    /// Admit a submit under a fresh opaque id, recording its BPF
    /// invocation. A clean same-key submit while an id is outstanding
    /// proves the old invocation ended without a delivered return
    /// (the BPF slot empties only on a return release, so a clean
    /// claim means the previous occupant returned): the old id gaps
    /// (`IdentityAmbiguous` — its return never arrived) first. A
    /// full table or an exhausted id space refuses (counted, no
    /// phantom).
    fn submit(&mut self, raw: RawEdge) -> Vec<Edge> {
        let mut out = Vec::new();
        if let Some((old_id, _, _, _)) = self.outstanding.remove(&raw.key) {
            self.stats.gaps_synthesized += 1;
            out.push(Edge::Gap {
                id: old_id,
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
        self.outstanding
            .insert(raw.key, (id, raw.ts_ns, raw.site, raw.invoc));
        self.stats.admitted += 1;
        out.push(Edge::Submit {
            id,
            tfm_id: None,
            ts_ns: raw.ts_ns,
        });
        out
    }

    /// Join a return to the outstanding id for its key — ONLY on
    /// invocation equality. Unknown keys count and emit nothing — no
    /// phantom completions. A return from a DIFFERENT invocation (a
    /// later call after a lost return + lost submit, or a nested
    /// call's return), a return PREDATING the outstanding submit, or
    /// a return from the OTHER site (one call, one function — a
    /// cross-site return cannot be this invocation's), is stale and
    /// is refused without disturbing the outstanding id. Ties join
    /// (coarse-clock ambiguity, pinned).
    fn complete(&mut self, raw: RawEdge) -> Vec<Edge> {
        let id = match self.outstanding.get(&raw.key) {
            None => {
                self.stats.unknown_key_returns += 1;
                return Vec::new();
            }
            Some(&(id, submit_ts, submit_site, submit_invoc)) => {
                if raw.invoc != submit_invoc || raw.ts_ns < submit_ts || raw.site != submit_site {
                    self.stats.stale_returns += 1;
                    return Vec::new();
                }
                id
            }
        };
        self.outstanding.remove(&raw.key);
        vec![Edge::Return {
            id,
            ts_ns: raw.ts_ns,
            status: raw.status,
            disposition: classify_return(raw.status),
        }]
    }
}
