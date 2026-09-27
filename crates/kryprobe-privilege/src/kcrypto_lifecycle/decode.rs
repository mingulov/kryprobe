// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw-edge decode: v6 `LEdge` bytes → T05 `Edge` events (P3: the v5
//! submit-side driver word (F05) + return-side no-chase twin (R2) +
//! entry-side scalar request metadata with submit-lifetime binding).
//!
//! The join is keyed by the BPF invocation id alone (W8 fsession: the
//! entry run mints one id per call and stores it in the kernel-zeroed
//! per-call session cookie; the exit run of the SAME call reads the
//! SAME cookie back). A submit admits a fresh opaque id under its
//! invocation, and a return joins the outstanding id for its
//! invocation — nested same-key calls pair exactly, since distinct
//! calls carry distinct cookies whatever request pointer they share.
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

use kryprobe_abi::kcrypto_lifecycle::{
    LDIR_DEC, LDIR_ENC, LEDGE_INVOC_POISON, LEDGE_MAGIC, LEDGE_RETURN, LEDGE_SUBMIT, LEDGE_TAINTED,
    LEDGE_TRUNCATED, LEDGE_VERSION, LFAM_SK, LMETA_CRYPTLEN_OK, LMETA_REQFLAGS_OK, LSITE_DEC,
    LSITE_ENC,
};
use kryprobe_core::kcrypto::{
    Edge, GapReason, LifecycleFamily, OpDirection, RequestMeta, ReturnDisposition,
};
use std::collections::HashMap;

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
    /// [`LEDGE_SUBMIT`] or [`LEDGE_RETURN`] (validated).
    pub edge: u8,
    /// [`LSITE_ENC`] or [`LSITE_DEC`] (validated; op attribution is
    /// T07/T08 scope — T06 validates the twin but carries no op).
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
    /// BPF invocation id (the join identity; 0 on tainted edges,
    /// which name no invocation).
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
    /// Edge kind is neither submit nor return.
    BadEdge,
    /// Site is neither encrypt nor decrypt.
    BadSite,
    /// Flags carry bits outside tainted/truncated.
    BadFlags,
    /// v6 metadata word violates the contract: nonzero metadata on
    /// a return edge (R2 extended — returns are never chased),
    /// `mflags` bits outside cryptlen/req-flags-valid, a nonzero
    /// value word without its validity bit, a non-skcipher family,
    /// or a direction that does not echo the site.
    BadMeta,
    /// Null pairing key (the BPF `BADKEY` gate should have dropped it).
    NullKey,
    /// Submit edge with a nonzero status (ABI: submit edges carry 0 —
    /// a status here is twin drift, silently discarded before).
    BadSubmitStatus,
    /// Clean (untainted) edge with a malformed invocation id: 0
    /// ("no invocation", tainted edges only) or the reserved bit set
    /// (no honest-BPF path sets it — W8 mints cookie ids with bit 0
    /// clear). Honest BPF never emits either shape — fail closed,
    /// never join.
    BadInvoc,
    /// Return edge with a nonzero transform word (R2: honest BPF
    /// never chases at exit — a return-side word is twin drift).
    BadReturnTfm,
    /// Driver-name field violates the contract: no NUL within 56
    /// bytes, invalid UTF-8, or a name on a return edge (returns
    /// carry no name — the submit's admission owns the provenance).
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
/// key, zero status on submit edges, the invocation id, the
/// transform word (submit edges: ANY u64 — 0 is unknown, never
/// refused; return edges: 0 ONLY — R2, honest BPF never chases at
/// exit), the entry-side metadata (submit edges: validity-gated
/// `cryptlen` / `req_flags`, skcipher family, site-echoing
/// direction; return edges: all-zero ONLY), and the driver name
/// (submit edges: NUL-terminated UTF-8 within 56 bytes, empty when
/// unknown; return edges: empty ONLY).
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
    if edge != LEDGE_SUBMIT && edge != LEDGE_RETURN {
        return Err(DecodeDrop::BadEdge);
    }
    let site = u16le(4);
    if site != LSITE_ENC && site != LSITE_DEC {
        return Err(DecodeDrop::BadSite);
    }
    let flags = u16le(6);
    if flags & !(LEDGE_TAINTED | LEDGE_TRUNCATED) != 0 {
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
    if !tainted && (invoc == 0 || invoc & LEDGE_INVOC_POISON != 0) {
        return Err(DecodeDrop::BadInvoc);
    }
    let tfm = u64le(40);
    if edge == LEDGE_RETURN && tfm != 0 {
        return Err(DecodeDrop::BadReturnTfm);
    }
    // Entry-side metadata (P3): returns carry all-zero words (R2
    // extended — honest BPF never chases at exit); submits carry
    // validity-gated scalars, the skcipher family, and the
    // site-echoing direction.
    let cryptlen_word = u32le(28);
    let req_flags_word = u32le(48);
    let fam = bytes[52];
    let dir = bytes[53];
    let mflags = u16le(54);
    let (cryptlen, req_flags) = if edge == LEDGE_RETURN {
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
    if edge == LEDGE_RETURN && (!drv.is_empty() || truncated) {
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

/// Bounded invocation→id join: submits admit fresh opaque ids,
/// returns join the outstanding id for their invocation.
///
/// `Debug` is manual: the outstanding table holds kernel-issued call
/// identities, so only its length renders (round-1 sol-m9/astra-m9).
pub struct LifecycleDecoder {
    /// Maximum outstanding invocations (admission refuses past this).
    capacity: usize,
    /// Next opaque id (starts at 1; 0 is never issued).
    next_id: u64,
    /// Outstanding BPF invocation → (opaque id, submit ts, submit
    /// site). The invocation is the join identity: a return joins
    /// ONLY the id outstanding under its own invocation.
    outstanding: HashMap<u64, (u64, u64, u16)>,
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

    /// Shared join body: taint refusal, then submit/complete dispatch.
    fn join_inner(&mut self, raw: RawEdge, tfm_id: Option<u64>, epoch: Option<u64>) -> Vec<Edge> {
        if raw.tainted {
            if raw.edge == LEDGE_SUBMIT {
                self.stats.submit_refused += 1;
            } else {
                self.stats.unknown_invoc_returns += 1;
            }
            return Vec::new();
        }
        if raw.edge == LEDGE_SUBMIT {
            self.submit(raw, tfm_id, epoch)
        } else {
            self.complete(raw)
        }
    }

    /// Count one record that failed twin validation (the caller's
    /// parse already classified it; this only bumps the counter).
    pub fn count_bad_record(&mut self) {
        self.stats.bad_records += 1;
    }

    /// Admit a submit under a fresh opaque id, keyed by its BPF
    /// invocation. A same-invocation resubmit (BPF ids are unique —
    /// this is twin drift or a replay) gaps the old id
    /// (`IdentityAmbiguous` — its return never arrived) first. A
    /// full table or an exhausted id space refuses (counted, no
    /// phantom). Same-key submits with FRESH invocations admit
    /// alongside (nested calls pair exactly — never gapped). The
    /// submit-lifetime binding (`tfm_id` + submit-pinned `epoch`)
    /// and the entry-side wire metadata ride the emitted edge.
    fn submit(&mut self, raw: RawEdge, tfm_id: Option<u64>, epoch: Option<u64>) -> Vec<Edge> {
        let mut out = Vec::new();
        if let Some((old_id, _, _)) = self.outstanding.remove(&raw.invoc) {
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
            .insert(raw.invoc, (id, raw.ts_ns, raw.site));
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
    fn complete(&mut self, raw: RawEdge) -> Vec<Edge> {
        let id = match self.outstanding.get(&raw.invoc) {
            None => {
                self.stats.unknown_invoc_returns += 1;
                return Vec::new();
            }
            Some(&(id, submit_ts, submit_site)) => {
                if raw.ts_ns < submit_ts || raw.site != submit_site {
                    self.stats.stale_returns += 1;
                    return Vec::new();
                }
                id
            }
        };
        self.outstanding.remove(&raw.invoc);
        vec![Edge::Return {
            id,
            ts_ns: raw.ts_ns,
            status: raw.status,
            disposition: classify_return(raw.status),
        }]
    }
}
