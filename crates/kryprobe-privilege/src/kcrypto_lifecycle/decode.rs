// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw-edge decode: `LEdge` bytes → T05 `Edge` events (T06).
//!
//! The join is keyed by the kernel request pointer carried in each
//! record: a submit admits a fresh opaque id, the matching return
//! joins the outstanding id for its key. Raw keys never leave this
//! module (only opaque ids reach `Edge`); every refusal is counted,
//! never silent.
//!
//! Reuse rule (round-1 sol-M3/astra-M3): a request address reused
//! while its id is still outstanding gaps the old id
//! (`IdentityAmbiguous` — the old fact is refused, never trusted) and
//! admits fresh. A late return PREDATING the fresh submit is stale
//! (counted, never joined); a same-tick-or-later late return still
//! joins current — key+clock alone cannot tell those generations
//! apart, so T08 closes the remainder with BPF-side generations.
//! Nominal (non-reused) traffic pairs exactly.

use kryprobe_abi::kcrypto_lifecycle::{
    LEDGE_MAGIC, LEDGE_RETURN, LEDGE_SUBMIT, LEDGE_VERSION, LSITE_DEC, LSITE_ENC,
};
use kryprobe_core::kcrypto::{Edge, GapReason, ReturnDisposition};
use std::collections::HashMap;

/// Record twin size: `LEdge` is 32 bytes on the ring.
const RECORD_LEN: usize = 32;

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
    /// Raw kernel request pointer (join key; never leaves decode).
    pub key: u64,
    /// Edge timestamp (ns).
    pub ts_ns: u64,
    /// Native return status (return edges) or 0 (submit edges).
    pub status: i32,
}

impl std::fmt::Debug for RawEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawEdge")
            .field("edge", &self.edge)
            .field("site", &self.site)
            .field("key", &"<redacted>")
            .field("ts_ns", &self.ts_ns)
            .field("status", &self.status)
            .finish()
    }
}

/// Why one ring record produced no edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeDrop {
    /// Record is not exactly 32 bytes.
    BadLength,
    /// Magic is not [`LEDGE_MAGIC`].
    BadMagic,
    /// Version is not [`LEDGE_VERSION`].
    BadVersion,
    /// Edge kind is neither submit nor return.
    BadEdge,
    /// Site is neither encrypt nor decrypt.
    BadSite,
    /// v1 defines no flags; nonzero is twin drift.
    BadFlags,
    /// v1 defines no aux; nonzero is twin drift.
    BadAux,
    /// Null pairing key (the BPF `BADKEY` gate should have dropped it).
    NullKey,
}

/// Named decode loss counters (loss ledger feed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeStats {
    /// Submits admitted (fresh opaque ids issued).
    pub admitted: u64,
    /// Submits refused (table full or id space exhausted).
    pub submit_refused: u64,
    /// Returns for keys with no outstanding submit.
    pub unknown_key_returns: u64,
    /// Records failing twin validation.
    pub bad_records: u64,
    /// Gaps synthesized for reuse-while-outstanding.
    pub gaps_synthesized: u64,
    /// Returns predating the outstanding submit for their key (late
    /// edges from a gapped generation — refused, never joined).
    pub stale_returns: u64,
}

/// Validate one ring record against the `LEdge` twin: exact length,
/// magic, version, edge kind, site, zero flags/aux, non-null key.
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
    if u16le(6) != 0 {
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
    Ok(RawEdge {
        edge,
        site,
        key,
        ts_ns,
        status,
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
    /// Outstanding key → (opaque id, submit ts).
    outstanding: HashMap<u64, (u64, u64)>,
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
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Edge> {
        match decode_record(bytes) {
            Ok(raw) => self.join(raw),
            Err(_) => {
                self.count_bad_record();
                Vec::new()
            }
        }
    }

    /// Join one validated raw edge (the post-parse half of [`feed`],
    /// split so the sensor tallies per-hook hits from the same parse).
    pub fn join(&mut self, raw: RawEdge) -> Vec<Edge> {
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

    /// Admit a submit under a fresh opaque id. Reuse-while-outstanding
    /// gaps the old id (`IdentityAmbiguous`) first; a full table or an
    /// exhausted id space refuses (counted, no phantom).
    fn submit(&mut self, raw: RawEdge) -> Vec<Edge> {
        let mut out = Vec::new();
        if let Some((old_id, _)) = self.outstanding.remove(&raw.key) {
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
        self.outstanding.insert(raw.key, (id, raw.ts_ns));
        self.stats.admitted += 1;
        out.push(Edge::Submit {
            id,
            tfm_id: None,
            ts_ns: raw.ts_ns,
        });
        out
    }

    /// Join a return to the outstanding id for its key. Unknown keys
    /// (lost submit, pre-attach call) count and emit nothing — no
    /// phantom completions. A return PREDATING the outstanding
    /// submit is stale (a late edge from a gapped generation:
    /// same-address invocations never overlap in real time, so the
    /// current invocation's return cannot predate its submit) and is
    /// refused without disturbing the outstanding id (round-1
    /// sol-M3/astra-M3). Ties join (coarse-clock ambiguity, pinned).
    fn complete(&mut self, raw: RawEdge) -> Vec<Edge> {
        let id = match self.outstanding.get(&raw.key) {
            None => {
                self.stats.unknown_key_returns += 1;
                return Vec::new();
            }
            Some(&(id, submit_ts)) => {
                if raw.ts_ns < submit_ts {
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
