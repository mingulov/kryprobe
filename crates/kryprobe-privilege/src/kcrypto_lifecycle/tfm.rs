// SPDX-License-Identifier: GPL-3.0-or-later
//! Transform-lifetime tracker: v1 `LTfm` bytes → opaque generations (T07).
//!
//! The join is keyed by the BPF attempt token alone (T07.2: the
//! alloc-entry run mints one id per call and stores it in the
//! kernel-zeroed per-call session cookie; the exit run of the SAME
//! call reads the SAME cookie back). An entry parks its requested
//! provenance under its token, and the return for that token either
//! assigns a fresh opaque generation (success: the frontend pointer
//! normalizes to the canonical base by the configured offset) or
//! records a classified failure (ERR_PTR: counted, no generation,
//! never dereferenced). The token namespace is separate from
//! invocation ids (own BPF counter lanes, own table here — an
//! attempt token can never alias an invocation id).
//!
//! Raw pointers never leave this module (only opaque ids reach
//! [`GenerationInfo`]); every refusal is counted, never silent.
//! Missing metadata is unknown (empty names), never fabricated.
//! T07.3 adds the destroy join (retire on proved final-free,
//! ambiguity otherwise — never inference) and first-seen admission
//! (op edges name their transform; unknown stays unknown).
//! Configuration epochs (T07.4): setkey/setauthsize halves join by
//! token like every other site; a success bumps the generation's
//! epoch (failures record, never bump — a failed rekey changes no
//! kernel state). Config edges on unknown bases admit first-seen
//! (a live edge observes a live transform, op or config alike).

use kryprobe_abi::kcrypto_lifecycle::{
    LEDGE_INVOC_POISON, LEDGE_RETURN, LEDGE_SUBMIT, LEDGE_TAINTED, LTFM_MAGIC, LTFM_SITE_ALLOC_SK,
    LTFM_SITE_DESTROY, LTFM_SITE_SETAUTHSIZE, LTFM_SITE_SETKEY_AEAD, LTFM_SITE_SETKEY_SK,
    LTFM_TRUNCATED, LTFM_VERSION,
};
use std::collections::HashMap;

/// Record twin size: `LTfm` is 112 bytes on the ring.
const RECORD_LEN: usize = 112;

/// Name field width: 63 bytes + NUL (BPF-bound provenance).
const NAME_LEN: usize = 64;

/// `ERR_PTR` floor (`IS_ERR_VALUE` — mirrors the BPF classifier):
/// returns at or above `(u64)-4095` are errno failures, and a
/// success edge carrying such a key is twin drift.
const ERR_PTR_FLOOR: u64 = 0xFFFF_FFFF_FFFF_F001;
/// Most-negative native errno the BPF can emit (`(0xFFFF...F001 as
/// i32)` — failures carry `[MIN_ERRNO, -1]` exactly).
const MIN_ERRNO: i32 = -4095;

/// One validated transform edge (post-twin-checks, pre-join).
///
/// `Debug` is manual: [`RawTfm::key`] is a raw kernel pointer and
/// renders as `<redacted>`; `name` is public inventory and renders.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RawTfm {
    /// [`LEDGE_SUBMIT`] or [`LEDGE_RETURN`] (validated).
    pub edge: u8,
    /// [`LTFM_SITE_ALLOC_SK`] or [`LTFM_SITE_DESTROY`] (validated;
    /// later sites join as their halves land).
    pub site: u16,
    /// [`LEDGE_TAINTED`] was set (BPF could not pair this edge).
    pub tainted: bool,
    /// [`LTFM_TRUNCATED`] was set (partial name provenance).
    pub truncated: bool,
    /// Raw kernel transform pointer (validated pairing-adjacent
    /// material; never leaves the tracker — generations carry
    /// opaque ids).
    pub key: u64,
    /// Edge timestamp (ns).
    pub ts_ns: u64,
    /// Native status (return edges) or 0 (entry edges).
    pub status: i32,
    /// Alloc-entry requested alg type (provenance; else 0).
    pub aux: u32,
    /// Alloc-entry requested alg mask (provenance; else 0).
    pub aux2: u32,
    /// BPF attempt token (the join identity; 0 on tainted edges,
    /// which name no attempt).
    pub token: u64,
    /// NUL-terminated name bytes (requested on entry, resolved
    /// driver on success returns, empty on failures).
    pub name: [u8; NAME_LEN],
}

impl std::fmt::Debug for RawTfm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTfm")
            .field("edge", &self.edge)
            .field("site", &self.site)
            .field("tainted", &self.tainted)
            .field("truncated", &self.truncated)
            .field("key", &"<redacted>")
            .field("ts_ns", &self.ts_ns)
            .field("status", &self.status)
            .field("aux", &self.aux)
            .field("aux2", &self.aux2)
            .field("token", &self.token)
            .field("name", &self.name)
            .finish()
    }
}

/// Why one ring record produced no transform edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TfmDrop {
    /// Record is not exactly 112 bytes.
    BadLength,
    /// Magic is not [`LTFM_MAGIC`].
    BadMagic,
    /// Version is not [`LTFM_VERSION`].
    BadVersion,
    /// Edge kind is neither submit nor return.
    BadEdge,
    /// Site is not an implemented transform site.
    BadSite,
    /// Flags carry bits outside tainted/truncated.
    BadFlags,
    /// Entry edge with a nonzero key (entries carry no pointer yet).
    BadEntryKey,
    /// Successful return with a null key (success must name a tfm).
    NullKey,
    /// Successful return with an ERR_PTR-range key (the BPF
    /// classifies those as failures — never emitted as success).
    BadSuccessKey,
    /// Failed return with a nonzero key (failures name nothing —
    /// BPF classifies ERR_PTR before dereference).
    BadFailureKey,
    /// Return with a non-native failure status (failures carry
    /// `[-4095, -1]` exactly — the BPF's `(ret as i32)` over the
    /// ERR_PTR range; positive or out-of-range statuses are drift).
    BadFailureStatus,
    /// Entry edge with a nonzero status.
    BadEntryStatus,
    /// Return edge with a nonzero aux word (T07.2 defines none).
    BadAux,
    /// Clean (untainted) edge with a malformed attempt token: 0
    /// ("no attempt", tainted edges only) or the reserved bit set
    /// (no honest-BPF path sets it). Honest BPF never emits either
    /// shape — fail closed, never join.
    BadToken,
    /// Name field violates the contract: no NUL within 64 bytes,
    /// invalid UTF-8, a name on a failure return, or any name on a
    /// destroy/config half (destroy and config carry no names, ever).
    BadName,
    /// Destroy half with a nonzero status (the call returns void —
    /// there is no status to snapshot at entry either).
    BadDestroyStatus,
    /// Destroy entry with aux2 bits beyond the observed bit (only
    /// bit 0 is defined).
    BadDestroyAux2,
    /// Destroy return with a nonzero key (the bare return carries
    /// the token only — the join replays the parked entry).
    BadDestroyKey,
    /// Destroy return with a nonzero aux/aux2 word (bare return —
    /// the refcount snapshot lives on the entry).
    BadDestroyAux,
    /// Config entry with a nonzero status (the errno exists only
    /// at return — entries carry the frontend + length).
    BadConfigStatus,
    /// Config entry with a nonzero aux2 word (no second scalar is
    /// defined on this path).
    BadConfigAux2,
    /// Config return with a nonzero key (the errno return carries
    /// the token only — the join replays the parked entry).
    BadConfigKey,
    /// Config return with a nonzero aux/aux2 word (the length
    /// snapshot lives on the entry).
    BadConfigAux,
    /// Reserved pad (bytes 36–39) nonzero (the BPF zeroes the
    /// alignment gap per record — anything else is wire drift).
    BadReserved,
}

/// Named tracker loss counters (loss ledger feed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TfmStats {
    /// Entries admitted (fresh pending attempts).
    pub admitted: u64,
    /// Returns paired to an outstanding attempt (success or failure).
    pub completed: u64,
    /// Paired failures (ERR_PTR classified, no generation).
    pub failed_allocs: u64,
    /// Returns for tokens with no outstanding entry (lost entry,
    /// pre-attach call, or BPF taint — never joined, never
    /// disturbing).
    pub unknown_returns: u64,
    /// Entries refused (same-token resubmit — first entry stands).
    pub submit_refused: u64,
    /// Tainted edges refused quietly (BPF could not pair them —
    /// nothing disturbed).
    pub tainted_refused: u64,
    /// Entries refused past the pending table bound.
    pub table_full: u64,
    /// Returns predating their entry (corruption or replay —
    /// refused with the attempt kept; ties join).
    pub stale_returns: u64,
    /// Records failing twin validation.
    pub bad_records: u64,
    /// First-seen attempts with a 0 transform word (unreadable
    /// request link — admitted nothing, counted as a sensor-truth
    /// gap, never silent).
    pub unlinked_ops: u64,
    /// Paired destroy returns (every classification — the destroy
    /// analog of `completed`).
    pub releases: u64,
    /// Generations retired on a proved final-free.
    pub retired: u64,
    /// Releases that proved nothing (retained/unobserved/impossible
    /// refcount) — the generation flags ambiguous and stays live.
    pub ambiguous_releases: u64,
    /// Releases of a null/ERR frontend (the kernel returns early —
    /// no dec-test, no free — counted, disturb nothing).
    pub noop_releases: u64,
    /// Releases for a base with no live generation (T07-R2-05:
    /// verdict-neutral INVENTORY, never loss — the destroy edge
    /// carries no family, so an expected digest/shash release
    /// (destroy-observed-only families) is indistinguishable from
    /// a destroy-only missed identity. A missed identity that is
    /// USED or CONFIGURED still votes loss via
    /// `unobserved_boundary`/`config_unlinked`/D4 — only the
    /// never-observed-at-all lifetime stays silent here, honestly
    /// unclassifiable).
    pub unknown_releases: u64,
    /// Generations forced-retired as ambiguous by a new alloc at
    /// their live base (the old lifetime ended unobserved).
    pub forced_retires: u64,
    /// Success completions and first-seen admissions refused past
    /// the live-table bound (D4 — the attempt still consumes).
    pub live_full: u64,
    /// Retired tombstones evicted past the history bound (D4 —
    /// oldest first, live entries never evict).
    pub tombstone_evictions: u64,
    /// Twin-valid returns for a parked entry of the other site
    /// (alloc↔destroy cross — refused with the entry kept, so the
    /// true return still pairs).
    pub mismatched_returns: u64,
    /// Destroy returns whose entry-bound generation no longer holds
    /// the base (a realloc or an overlapping destroy retired /
    /// superseded it between entry and return — the return retires
    /// NOTHING, so an old destroy can never donate its retire to a
    /// new lifetime reusing the address).
    pub stale_releases: u64,
    /// Paired config returns, success and failure alike (the
    /// config analog of `completed` — every joined pair).
    pub configs_joined: u64,
    /// Joined configs with a nonzero errno (recorded on the
    /// generation, never bump the epoch — a failed rekey changes
    /// no kernel state).
    pub configs_failed: u64,
    /// Joined configs with no attributable generation (a null
    /// frontend key, or a D4/id-exhaustion admission refusal whose
    /// reason is already counted — never a phantom).
    pub config_unlinked: u64,
    /// Pending attempts finalized at close without their return
    /// (T07-06: unknown outcome — alloc/config count only; a
    /// dangling destroy on a still-live bound generation ALSO
    /// marks it ambiguous, counted below).
    pub unfinished: u64,
    /// First-seen admissions (T07-02/R2-01: the lifetime's
    /// creation boundary was never observed — a missed free
    /// could have swapped the lifetime under the address, so the
    /// generation carries an uncertain identity and exact reuse
    /// voids from admission, not from a later config).
    pub unobserved_boundary: u64,
}

/// Normalize a frontend transform pointer to the canonical base
/// identity: `ptr + off`, where `off` is the family frontend's
/// `base` offset (BTF-resolved at bring-up; skcipher 8 on 64-bit —
/// `reqsize` + alignment padding). Wrapping offsets refuse (`None` —
/// never a wrapped identity).
#[must_use]
pub fn normalize_frontend(ptr: u64, off: u64) -> Option<u64> {
    ptr.checked_add(off)
}

/// Route one ring record: true when its magic names a transform
/// edge (short reads are never transform edges — the op decoder
/// refuses them as twin drift).
#[must_use]
pub fn is_tfm_record(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && u16::from_le_bytes([bytes[0], bytes[1]]) == LTFM_MAGIC
}

/// Decode a NUL-terminated name field: must terminate within the
/// field and decode as UTF-8 (kernel C strings; drift refuses).
fn decode_name(field: &[u8; NAME_LEN]) -> Result<String, TfmDrop> {
    let len = field.iter().position(|b| *b == 0).ok_or(TfmDrop::BadName)?;
    std::str::from_utf8(&field[..len])
        .map(str::to_owned)
        .map_err(|_| TfmDrop::BadName)
}

/// Validate one ring record against the v1 `LTfm` twin: exact
/// length, magic, version, edge kind, implemented site,
/// defined-only flags, the key rules (entry zero / success
/// non-null / failure zero), zero status on entries, zero aux on
/// returns, the attempt token, and the NUL-terminated name.
pub fn decode_tfm_record(bytes: &[u8]) -> Result<RawTfm, TfmDrop> {
    if bytes.len() != RECORD_LEN {
        return Err(TfmDrop::BadLength);
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
    if u16le(0) != LTFM_MAGIC {
        return Err(TfmDrop::BadMagic);
    }
    if bytes[2] != LTFM_VERSION {
        return Err(TfmDrop::BadVersion);
    }
    let edge = bytes[3];
    if edge != LEDGE_SUBMIT && edge != LEDGE_RETURN {
        return Err(TfmDrop::BadEdge);
    }
    let site = u16le(4);
    let is_config_site = site == LTFM_SITE_SETKEY_SK
        || site == LTFM_SITE_SETAUTHSIZE
        || site == LTFM_SITE_SETKEY_AEAD;
    if site != LTFM_SITE_ALLOC_SK && site != LTFM_SITE_DESTROY && !is_config_site {
        return Err(TfmDrop::BadSite);
    }
    let flags = u16le(6);
    if flags & !(LEDGE_TAINTED | LTFM_TRUNCATED) != 0 {
        return Err(TfmDrop::BadFlags);
    }
    let key = u64le(8);
    let ts_ns = u64le(16);
    let status = i32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    let aux = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    let aux2 = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
    // T07-10: bytes 36–39 are the zeroed alignment pad — a changed
    // reserved word refuses (twin drift, never joined).
    if bytes[36] != 0 || bytes[37] != 0 || bytes[38] != 0 || bytes[39] != 0 {
        return Err(TfmDrop::BadReserved);
    }
    let token = u64le(40);
    let mut name = [0u8; NAME_LEN];
    name.copy_from_slice(&bytes[48..48 + NAME_LEN]);
    let tainted = flags & LEDGE_TAINTED != 0;
    let truncated = flags & LTFM_TRUNCATED != 0;
    if site == LTFM_SITE_DESTROY {
        // T07.3 destroy twin: entry admits ANY key (the canonical
        // base — destroy arg1, including null/ERR — classified at
        // the join as a no-op release, never refused here) with the
        // refcount value in aux and the observed bit alone in aux2;
        // the bare return carries the token only (void call — every
        // other word zero, the join replays the parked entry).
        // Neither half carries a status or a name, ever.
        if status != 0 {
            return Err(TfmDrop::BadDestroyStatus);
        }
        if name.iter().any(|b| *b != 0) {
            return Err(TfmDrop::BadName);
        }
        if edge == LEDGE_SUBMIT {
            if aux2 & !1 != 0 {
                return Err(TfmDrop::BadDestroyAux2);
            }
        } else {
            if key != 0 {
                return Err(TfmDrop::BadDestroyKey);
            }
            if aux != 0 || aux2 != 0 {
                return Err(TfmDrop::BadDestroyAux);
            }
        }
    } else if is_config_site {
        // T07.4 config twin: entry admits ANY key (the frontend
        // arg0 — a null key classifies at the join as unlinked,
        // never refused here) with the length scalar in aux and
        // zero status/aux2; the errno return carries status +
        // token only (every other word zero, the join replays the
        // parked entry). Neither half carries a name, ever. Any
        // nonzero status is a failure verdict (native errnos AND
        // unrecognized values both record — a weird kernel return
        // is truth, not drift; only 0 bumps the epoch).
        if name.iter().any(|b| *b != 0) {
            return Err(TfmDrop::BadName);
        }
        if edge == LEDGE_SUBMIT {
            if status != 0 {
                return Err(TfmDrop::BadConfigStatus);
            }
            if aux2 != 0 {
                return Err(TfmDrop::BadConfigAux2);
            }
        } else {
            if key != 0 {
                return Err(TfmDrop::BadConfigKey);
            }
            if aux != 0 || aux2 != 0 {
                return Err(TfmDrop::BadConfigAux);
            }
        }
    } else if edge == LEDGE_SUBMIT {
        if key != 0 {
            return Err(TfmDrop::BadEntryKey);
        }
        if status != 0 {
            return Err(TfmDrop::BadEntryStatus);
        }
    } else {
        if status == 0 {
            if key == 0 {
                return Err(TfmDrop::NullKey);
            }
            // D8: the BPF classifies ERR_PTR-range returns as
            // failures before dereference — a success carrying one
            // is twin drift, not a pointer (it would normalize to a
            // phantom generation).
            if key >= ERR_PTR_FLOOR {
                return Err(TfmDrop::BadSuccessKey);
            }
        } else {
            // D8: failures carry native errnos only (the BPF emits
            // `(ret as i32)` over exactly the ERR_PTR range).
            if !(MIN_ERRNO..0).contains(&status) {
                return Err(TfmDrop::BadFailureStatus);
            }
            if key != 0 {
                return Err(TfmDrop::BadFailureKey);
            }
        }
        if aux != 0 || aux2 != 0 {
            return Err(TfmDrop::BadAux);
        }
        if status != 0 && name.iter().any(|b| *b != 0) {
            return Err(TfmDrop::BadName);
        }
    }
    if !tainted && (token == 0 || token & LEDGE_INVOC_POISON != 0) {
        return Err(TfmDrop::BadToken);
    }
    // Name bytes must decode even when empty (empty is unknown, a
    // missing NUL is drift) — including on tainted edges, whose
    // twin fields still validate (only the token is excused).
    decode_name(&name)?;
    Ok(RawTfm {
        edge,
        site,
        tainted,
        truncated,
        key,
        ts_ns,
        status,
        aux,
        aux2,
        token,
        name,
    })
}

/// One opaque transform generation (public view: no pointers —
/// the canonical base stays inside the tracker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationInfo {
    /// Opaque generation id (1, 2, ...; never 0).
    pub id: u64,
    /// Requested algorithm name (empty when unreadable — unknown).
    pub req_name: String,
    /// Requested alg type provenance.
    pub alg_type: u32,
    /// Requested alg mask provenance.
    pub alg_mask: u32,
    /// Resolved driver name (empty when unreadable — unknown).
    pub drv_name: String,
    /// The requested name was truncated at the wire bound (partial
    /// provenance — recorded, never silently complete).
    pub name_truncated: bool,
    /// The resolved driver name was truncated at the wire bound
    /// (D9: the return half carries its own flag — a short request
    /// paired with a flagged driver selection must not read as a
    /// complete driver name).
    pub drv_truncated: bool,
    /// Admitted first-seen from an op/config edge (allocated before
    /// attach or on an unhooked path — creation provenance unknown
    /// BY CONSTRUCTION, distinct from "saw the alloc, name
    /// unreadable"; op-admitted generations may still carry the
    /// submit's runtime-selected driver — F05 selected metadata).
    pub first_seen: bool,
    /// Retired: a proved final-free ended this lifetime (normal
    /// retire) or a new alloc proved it ended unobserved (forced
    /// retire — always paired with `ambiguous`).
    pub retired: bool,
    /// Ambiguous: some release observation left this lifetime's end
    /// (or its identity) less than exactly known — any ambiguity
    /// anywhere disables exact reuse claims (`reuse_exact`).
    pub ambiguous: bool,
    /// Configuration epoch: the number of SUCCESSFUL setkey /
    /// setauthsize configurations joined on this lifetime
    /// (saturating — failures record, never bump, so one keying
    /// era is never split in two; retire preserves the final
    /// epoch, and reuse mints epoch 0, never inherits).
    pub epoch: u64,
    /// Joined configuration attempts on this lifetime, success
    /// and failure alike.
    pub configs: u64,
    /// Site of the most recent joined config (one of the
    /// `LTFM_SITE_SETKEY_*` / `LTFM_SITE_SETAUTHSIZE` ids;
    /// meaningful only when `configs > 0`).
    pub last_config_site: u16,
    /// Length scalar of the most recent joined config (key length
    /// or authsize — lengths only, never key bytes; meaningful
    /// only when `configs > 0`).
    pub last_config_len: u32,
    /// Errno of the most recent joined config (0 on success;
    /// meaningful only when `configs > 0`).
    pub last_config_errno: i32,
}

/// One pending attempt (entry parked, return outstanding): an
/// allocation (provenance waits for the return), a destroy (the
/// frontend + refcount snapshot waits for the bare return), or a
/// configuration (the frontend + length snapshot waits for the
/// errno return). Tokens are lane-disjoint across sites (BPF
/// `LCTR` lanes), so one table serves all — a cross-site return
/// for a parked token refuses as mismatched with the entry kept.
enum PendingAttempt {
    /// Allocation entry parked.
    Alloc {
        /// Requested name from the entry edge.
        req_name: String,
        /// Requested alg type from the entry edge.
        alg_type: u32,
        /// Requested alg mask from the entry edge.
        alg_mask: u32,
        /// Entry edge truncation flag.
        truncated: bool,
        /// Entry edge timestamp (stale returns refuse against it).
        ts_ns: u64,
    },
    /// Destroy entry parked.
    Destroy {
        /// Canonical base from the entry edge (T07-03: destroy arg1
        /// — null/ERR classifies at completion as a no-op release).
        mem: u64,
        /// Refcount value snapshot from the entry edge.
        refcnt: u32,
        /// The snapshot is a real read (observed bit).
        observed: bool,
        /// Generation id holding the base at ENTRY (`None` when the
        /// base was unmapped — the return retires NOTHING unless
        /// the same id still holds the base, so a realloc between
        /// the halves can never donate its retire to the new
        /// lifetime; ids are stable under tombstone eviction,
        /// indices are not).
        bound_id: Option<u64>,
        /// Entry edge timestamp (stale returns refuse against it).
        ts_ns: u64,
    },
    /// Configuration entry parked.
    Config {
        /// Frontend from the entry edge (normalized at completion;
        /// null classifies as unlinked, never a phantom).
        key: u64,
        /// Length scalar from the entry edge (key length or
        /// authsize — lengths only, never key bytes).
        len: u32,
        /// Entry site (one of the three config sites — a return
        /// from any other site refuses as mismatched).
        site: u16,
        /// Generation id holding the base at ENTRY (`None` when the
        /// base was unmapped — the return attributes NOTHING unless
        /// the same id still holds the base, so a config straddling
        /// a reuse can never bump the new lifetime's epoch).
        bound_id: Option<u64>,
        /// Entry edge timestamp (stale returns refuse against it).
        ts_ns: u64,
    },
}

impl PendingAttempt {
    /// Entry timestamp (stale checks are site-agnostic).
    fn ts_ns(&self) -> u64 {
        match self {
            PendingAttempt::Alloc { ts_ns, .. }
            | PendingAttempt::Destroy { ts_ns, .. }
            | PendingAttempt::Config { ts_ns, .. } => *ts_ns,
        }
    }

    /// Entry site (cross-site returns refuse as mismatched).
    fn site(&self) -> u16 {
        match self {
            PendingAttempt::Alloc { .. } => LTFM_SITE_ALLOC_SK,
            PendingAttempt::Destroy { .. } => LTFM_SITE_DESTROY,
            PendingAttempt::Config { site, .. } => *site,
        }
    }
}

/// One assigned generation (tracker-private wrapper: the live
/// table owns canonical-base identity — the base keys the map, so
/// the generation itself carries no pointer at all).
struct Generation {
    /// Public view (pointer-free).
    info: GenerationInfo,
}

/// Bounded attempt-token→generation join: alloc entries park
/// requested provenance (returns assign generations or classify
/// failures) and destroy entries park the frontend + refcount
/// snapshot (returns retire or mark ambiguous); op edges admit
/// first-seen generations for pre-attach transforms.
///
/// `Debug` is manual: the tables hold kernel-issued identities, so
/// only their lengths render.
pub struct TransformTracker {
    /// Maximum pending attempts AND live generations AND retired
    /// tombstones (D4: one bound per table — total memory stays
    /// O(3 × capacity)).
    capacity: usize,
    /// BTF-resolved `crypto_skcipher.base` offset: frontend→base
    /// normalization adds this (the same `sk_base` word the BPF
    /// chase adds — resolved per kernel at arm, never hardcoded).
    frontend_off: u64,
    /// The kernel carries `crypto_tfm.refcnt` (arm-time verdict).
    /// False (7.2+) means unconditional destroy: every observed
    /// destroy retires, and the refcount snapshot is ignored.
    refcnt_present: bool,
    /// Next opaque id (starts at 1; 0 is never issued).
    next_id: u64,
    /// Outstanding attempt token → parked entry. The token is the
    /// join identity: a return completes ONLY the entry outstanding
    /// under its own token.
    pending: HashMap<u64, PendingAttempt>,
    /// Assigned generations, in assignment order (live + retired
    /// tombstones — tombstones evict FIFO past the bound, so this
    /// is recent history, not the full assignment log).
    generations: Vec<Generation>,
    /// Canonical base → index into `generations`, for LIVE
    /// generations only (one id per base — a new alloc at a live
    /// base forced-retires the old lifetime first, so lifetimes
    /// never merge). Indices shift on tombstone eviction (fixed up
    /// there — eviction is rare, lookups are per-op).
    live: HashMap<u64, usize>,
    /// Loss counters.
    stats: TfmStats,
}

impl std::fmt::Debug for TransformTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransformTracker")
            .field("capacity", &self.capacity)
            .field("next_id", &self.next_id)
            .field("pending", &self.pending.len())
            .field("generations", &self.generations.len())
            .field("live", &self.live.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl TransformTracker {
    /// New tracker with bounded tables. `frontend_off` is the
    /// BTF-resolved `crypto_skcipher.base` offset the arm hands down
    /// (8 on 64-bit kernels — `reqsize` + alignment padding);
    /// `refcnt_present` is the arm's kernel verdict (false on 7.2+:
    /// always-final mode).
    #[must_use]
    pub fn new(capacity: usize, frontend_off: u32, refcnt_present: bool) -> Self {
        Self {
            capacity,
            frontend_off: u64::from(frontend_off),
            refcnt_present,
            next_id: 1,
            pending: HashMap::new(),
            generations: Vec::new(),
            live: HashMap::new(),
            stats: TfmStats::default(),
        }
    }

    /// Current loss counters.
    #[must_use]
    pub fn stats(&self) -> TfmStats {
        self.stats
    }

    /// Assigned generations, in assignment order (pointer-free views;
    /// live + recent-retired tombstones — see the struct docs).
    #[must_use]
    pub fn generations(&self) -> Vec<GenerationInfo> {
        self.generations.iter().map(|g| g.info.clone()).collect()
    }

    /// Exact reuse claims are sound only when every lifetime
    /// boundary was observed exactly: any ambiguous release,
    /// forced retire, D4 refusal (`live_full`/`table_full` — a
    /// lifetime unadmitted is a boundary unobserved), unfinished
    /// close, first-seen admission (unobserved creation), corrupt
    /// record, unpaired edge, unjoinable return, or cross-site
    /// return (cumulative counters — tombstone eviction cannot
    /// erase them) disables the claim that a base's lifetimes
    /// chained exactly end-to-start. (R2-01: a corrupt/unpaired/
    /// unjoinable/crossed record can hide a creation or
    /// destruction boundary, so every identity-affecting refusal
    /// voids — except `unknown_releases`, which post-R2-05 counts
    /// expected destroy-only family traffic as inventory, and the
    /// kept-attempt classes `submit_refused`/`stale_returns`/
    /// `stale_releases`, whose first/true pairing still stands.)
    #[must_use]
    pub fn reuse_exact(&self) -> bool {
        self.stats.ambiguous_releases == 0
            && self.stats.forced_retires == 0
            && self.stats.live_full == 0
            && self.stats.table_full == 0
            && self.stats.unfinished == 0
            && self.stats.unobserved_boundary == 0
            && self.stats.bad_records == 0
            && self.stats.tainted_refused == 0
            && self.stats.unknown_returns == 0
            && self.stats.mismatched_returns == 0
    }

    /// Admit the transform behind an op submit edge (first-seen):
    /// `frontend` normalizes to the canonical base; an already-live
    /// base admits nothing (one lifetime, one id — first admission
    /// wins, a later name never backfills: the admitting edge owns
    /// the provenance). A fresh admission carries the submit's
    /// runtime-selected driver (`drv`, empty when the chase was
    /// unreadable — F05: selected metadata captured, allocation /
    /// requested name / previous configuration stay unknown) with
    /// its truncation bit (`drv_truncated` — D9: clipped names read
    /// as partial), flagged `first_seen` — AND counts
    /// `unobserved_boundary` (R2-01: the creation boundary is
    /// unobserved AT admission, so exactness voids from the
    /// admitting edge, never from a later config). A 0 frontend
    /// (unreadable request link) admits nothing and counts
    /// `unlinked_ops`. Past the live bound the admission refuses
    /// (`live_full`) — D4, no silent LRU. Issues the next opaque
    /// id (id exhaustion refuses like the submit path — the
    /// `u64::MAX` sentinel is never issued).
    pub fn admit_first_seen(
        &mut self,
        frontend: u64,
        drv: &str,
        drv_truncated: bool,
    ) -> Option<u64> {
        if frontend == 0 {
            self.stats.unlinked_ops += 1;
            return None;
        }
        let base = match normalize_frontend(frontend, self.frontend_off) {
            Some(base) => base,
            None => {
                self.count_bad_record();
                return None;
            }
        };
        if self.live.contains_key(&base) {
            return None;
        }
        if self.live.len() >= self.capacity || self.next_id == u64::MAX {
            self.stats.live_full += 1;
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.stats.unobserved_boundary += 1;
        self.live.insert(base, self.generations.len());
        self.generations.push(Generation {
            info: GenerationInfo {
                id,
                req_name: String::new(),
                alg_type: 0,
                alg_mask: 0,
                drv_name: drv.to_owned(),
                name_truncated: false,
                drv_truncated,
                first_seen: true,
                retired: false,
                ambiguous: false,
                epoch: 0,
                configs: 0,
                last_config_site: 0,
                last_config_len: 0,
                last_config_errno: 0,
            },
        });
        Some(id)
    }

    /// Feed one ring record: validate, join, and report newly
    /// assigned generation ids (empty unless a success return paired).
    /// Invalid records count `bad_records` and emit nothing.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u64> {
        match decode_tfm_record(bytes) {
            Ok(raw) => self.join(raw),
            Err(_) => {
                self.count_bad_record();
                Vec::new()
            }
        }
    }

    /// Join one validated raw edge. Tainted edges refuse quietly
    /// WITHOUT touching the tables: per-call cookies isolate
    /// attempts, so a tainted edge (which names no attempt)
    /// disturbs no outstanding token.
    pub fn join(&mut self, raw: RawTfm) -> Vec<u64> {
        if raw.tainted {
            self.stats.tainted_refused += 1;
            return Vec::new();
        }
        if raw.edge == LEDGE_SUBMIT {
            self.submit(raw);
            Vec::new()
        } else {
            self.complete(raw)
        }
    }

    /// Count one record that failed twin validation (the caller's
    /// parse already classified it; this only bumps the counter).
    pub fn count_bad_record(&mut self) {
        self.stats.bad_records += 1;
    }

    /// Finalize pending attempts at close (T07-06): entries
    /// without returns finalize as UNKNOWN, never joined. Alloc
    /// and config attempts count `unfinished` (no generation
    /// exists to taint / the epoch simply excludes the unknown
    /// config — lifetime boundaries are unaffected). A dangling
    /// destroy whose entry-bound generation STILL holds the base
    /// marks it ambiguous and counts `ambiguous_releases` (its
    /// end is no longer exactly knowable — `reuse_exact` voids —
    /// while the generation stays live, end unproven). A
    /// dangling destroy whose bound generation already retired
    /// (or never existed) counts `unfinished` only — the proved
    /// end stands.
    pub fn finish(&mut self) {
        for (_, attempt) in std::mem::take(&mut self.pending) {
            self.stats.unfinished += 1;
            let PendingAttempt::Destroy {
                mem,
                bound_id: Some(bound),
                ..
            } = attempt
            else {
                continue;
            };
            // Destroy keys are canonical bases (T07-03 — direct
            // lookup, never normalized).
            if let Some(&idx) = self.live.get(&mem)
                && self.generations[idx].info.id == bound
            {
                self.generations[idx].info.ambiguous = true;
                self.stats.ambiguous_releases += 1;
            }
        }
    }

    /// Park an entry under a fresh pending attempt, keyed by its
    /// token. A same-token resubmit (BPF tokens are unique — this
    /// is twin drift or a replay) refuses with the FIRST entry
    /// standing (fail closed: first-seen wins). A full table or an
    /// exhausted id space refuses (counted, no phantom).
    fn submit(&mut self, raw: RawTfm) {
        if self.pending.contains_key(&raw.token) {
            self.stats.submit_refused += 1;
            return;
        }
        if self.pending.len() >= self.capacity {
            self.stats.table_full += 1;
            return;
        }
        // `u64::MAX` is never issued (sentinel headroom): exhaustion
        // refuses admission instead of wrapping ids.
        if self.next_id == u64::MAX {
            self.stats.submit_refused += 1;
            return;
        }
        // Entry-bound generation (R1/T07-01): the lifetime holding
        // the base RIGHT NOW (stable id, not the eviction-shifting
        // index) — completions honor it, never the return-time
        // occupant. Destroy keys are ALREADY the canonical base
        // (T07-03: the BPF emits destroy arg1, family-agnostic —
        // never normalized); config keys are frontends (normalized
        // with the skcipher word, exactly as before). Null/ERR keys
        // and unmapped bases bind `None` (classified at completion,
        // exactly as before).
        // Destroy keys bind WITHOUT normalization (the match arms
        // below branch per site — the destroy arm looks the base up
        // directly, the config arm normalizes its frontend first).
        let destroy_bound =
            (raw.site == LTFM_SITE_DESTROY && raw.key != 0 && raw.key < ERR_PTR_FLOOR)
                .then(|| self.live.get(&raw.key))
                .flatten()
                .map(|&idx| self.generations[idx].info.id);
        let entry = match raw.site {
            LTFM_SITE_DESTROY => PendingAttempt::Destroy {
                mem: raw.key,
                refcnt: raw.aux,
                observed: raw.aux2 & 1 == 1,
                bound_id: destroy_bound,
                ts_ns: raw.ts_ns,
            },
            LTFM_SITE_SETKEY_SK | LTFM_SITE_SETAUTHSIZE | LTFM_SITE_SETKEY_AEAD => {
                let bound_id = normalize_frontend(raw.key, self.frontend_off)
                    .and_then(|base| self.live.get(&base))
                    .map(|&idx| self.generations[idx].info.id);
                PendingAttempt::Config {
                    key: raw.key,
                    len: raw.aux,
                    site: raw.site,
                    bound_id,
                    ts_ns: raw.ts_ns,
                }
            }
            // Only alloc + destroy + config sites decode (anything
            // else refused as `BadSite` pre-join — this arm is alloc).
            _ => {
                // Infallible: `decode_tfm_record` validated the name
                // before the join (empty is unknown, never a
                // defaulted fabrication).
                let name = decode_name(&raw.name).unwrap_or_default();
                PendingAttempt::Alloc {
                    req_name: name,
                    alg_type: raw.aux,
                    alg_mask: raw.aux2,
                    truncated: raw.truncated,
                    ts_ns: raw.ts_ns,
                }
            }
        };
        self.pending.insert(raw.token, entry);
        self.stats.admitted += 1;
    }

    /// Complete the attempt outstanding under the return's token.
    /// Unknown tokens count and emit nothing — no phantom
    /// generations. A return predating its entry is stale and is
    /// refused with the attempt kept (clock skew or replay — the
    /// entry's data stands). A return for a parked entry of the
    /// OTHER site is mismatched and is refused with the entry kept
    /// (twin-valid halves, wrong pairing — the true return still
    /// pairs). Alloc returns assign or classify (see
    /// `complete_alloc`); destroy returns retire or mark ambiguous
    /// (see `complete_destroy`); config returns record and bump
    /// epochs (see `complete_config`).
    fn complete(&mut self, raw: RawTfm) -> Vec<u64> {
        let Some(entry) = self.pending.remove(&raw.token) else {
            self.stats.unknown_returns += 1;
            return Vec::new();
        };
        if raw.ts_ns < entry.ts_ns() {
            // Stale return (corruption or replay — the exit cannot
            // predate the entry): refuse with the attempt kept, so
            // the true return still pairs. Ties join.
            self.stats.stale_returns += 1;
            self.pending.insert(raw.token, entry);
            return Vec::new();
        }
        if entry.site() != raw.site {
            self.stats.mismatched_returns += 1;
            self.pending.insert(raw.token, entry);
            return Vec::new();
        }
        match entry {
            PendingAttempt::Alloc {
                req_name,
                alg_type,
                alg_mask,
                truncated,
                ..
            } => self.complete_alloc(raw, req_name, alg_type, alg_mask, truncated),
            PendingAttempt::Destroy {
                mem,
                refcnt,
                observed,
                bound_id,
                ..
            } => {
                self.complete_destroy(mem, refcnt, observed, bound_id);
                Vec::new()
            }
            PendingAttempt::Config {
                key,
                len,
                site,
                bound_id,
                ..
            } => {
                self.complete_config(raw, key, len, site, bound_id);
                Vec::new()
            }
        }
    }

    /// Complete an allocation attempt: a failure classifies without
    /// a generation; a success normalizes the frontend to the
    /// canonical base and assigns a fresh opaque id. A success at an
    /// already-LIVE base forced-retires the old lifetime as
    /// ambiguous first (its free went unobserved — keeping it live
    /// would let a stale destroy merge lifetimes; the new lifetime
    /// takes the base fresh). Past the live bound the completion
    /// consumes the attempt but assigns nothing (`live_full`).
    fn complete_alloc(
        &mut self,
        raw: RawTfm,
        req_name: String,
        alg_type: u32,
        alg_mask: u32,
        truncated: bool,
    ) -> Vec<u64> {
        self.stats.completed += 1;
        if raw.status != 0 {
            self.stats.failed_allocs += 1;
            return Vec::new();
        }
        let base = match normalize_frontend(raw.key, self.frontend_off) {
            Some(base) => base,
            None => {
                self.count_bad_record();
                return Vec::new();
            }
        };
        if let Some(&old_idx) = self.live.get(&base) {
            // The slab handed out a live address: the old lifetime
            // ended off-sensor. Forced-retire it as ambiguous (its
            // end is unobserved BY CONSTRUCTION now) so the base
            // frees for exactly one live id.
            self.generations[old_idx].info.retired = true;
            self.generations[old_idx].info.ambiguous = true;
            self.live.remove(&base);
            self.stats.forced_retires += 1;
            self.evict_tombstones();
        }
        if self.live.len() >= self.capacity || self.next_id == u64::MAX {
            self.stats.live_full += 1;
            return Vec::new();
        }
        // Infallible: validated pre-join (see `submit`).
        let drv_name = decode_name(&raw.name).unwrap_or_default();
        let id = self.next_id;
        self.next_id += 1;
        self.live.insert(base, self.generations.len());
        self.generations.push(Generation {
            info: GenerationInfo {
                id,
                req_name,
                alg_type,
                alg_mask,
                drv_name,
                name_truncated: truncated,
                drv_truncated: raw.truncated,
                first_seen: false,
                retired: false,
                ambiguous: false,
                epoch: 0,
                configs: 0,
                last_config_site: 0,
                last_config_len: 0,
                last_config_errno: 0,
            },
        });
        vec![id]
    }

    /// Complete a destroy attempt (the parked entry's canonical
    /// base + refcount snapshot; the bare return carries nothing):
    /// null/ERR keys are no-op releases (the kernel returns early —
    /// counted, disturb nothing); the return retires NOTHING unless
    /// the entry-bound generation still holds the base (a realloc
    /// or an overlapping destroy between the halves counts
    /// `stale_releases` — an old destroy never donates its retire
    /// to a new lifetime); unbound entries on unmapped bases count
    /// `unknown_releases` (never a phantom); unbound entries whose
    /// base became live between the halves ALSO count unknown (the
    /// entry observed no live lifetime — attributing to the
    /// newcomer would merge across the unobserved boundary); on
    /// always-final kernels (no `refcnt` field) every observed
    /// destroy retires; otherwise only an OBSERVED refcount
    /// of exactly 1 retires (the observer rule — the dec freed under
    /// either historical semantic). Anything else — retained,
    /// unobserved, or the impossible 0 — marks the generation
    /// ambiguous and leaves it live (a later final destroy still
    /// joins and retires it; the flag survives).
    ///
    /// The key is the CANONICAL BASE, never normalized (T07-03: the
    /// BPF emits destroy arg1 — family-agnostic, so a shash destroy
    /// can no longer misjoin through the skcipher-only word; digest
    /// destroys without an admission path land `unknown_releases`).
    fn complete_destroy(&mut self, mem: u64, refcnt: u32, observed: bool, bound_id: Option<u64>) {
        self.stats.releases += 1;
        // IS_ERR_OR_NULL: the kernel's early return (no dec-test).
        if mem == 0 || mem >= ERR_PTR_FLOOR {
            self.stats.noop_releases += 1;
            return;
        }
        let base = mem;
        // Entry-bound lifetime (R1/T07-01): the return honors the
        // ENTRY's occupant, never the return-time one. Bound-but-
        // superseded (realloc or overlapping destroy retired it
        // between the halves) counts stale and retires nothing;
        // unbound entries attribute nothing even when the base has
        // since become live (the entry observed no live lifetime).
        let occupant = self
            .live
            .get(&base)
            .map(|&idx| (idx, self.generations[idx].info.id));
        let idx = match (bound_id, occupant) {
            (Some(bound), Some((idx, id))) if bound == id => idx,
            (Some(_), _) => {
                self.stats.stale_releases += 1;
                return;
            }
            (None, _) => {
                self.stats.unknown_releases += 1;
                return;
            }
        };
        if !self.refcnt_present || (observed && refcnt == 1) {
            self.generations[idx].info.retired = true;
            self.live.remove(&base);
            self.stats.retired += 1;
            self.evict_tombstones();
        } else {
            self.generations[idx].info.ambiguous = true;
            self.stats.ambiguous_releases += 1;
        }
    }

    /// Complete a configuration attempt (the parked entry's
    /// frontend + length snapshot; the errno return carries the
    /// verdict): the return attributes NOTHING unless the
    /// entry-bound generation still holds the base (a config
    /// straddling a reuse unlinks — it must never bump the new
    /// lifetime's epoch); unbound entries on still-unmapped bases
    /// admit first-seen (a config edge observes a live transform
    /// exactly like an op edge — same EMPTY-provenance rule);
    /// unbound entries whose base became live between the halves
    /// unlink (the entry observed no live lifetime); a null key or
    /// a D4/id-exhaustion admission refusal counts
    /// `config_unlinked` (the refusal reason is already counted —
    /// never a phantom). Every attributable pair records
    /// site/len/errno and bumps `configs`; ONLY a zero errno bumps
    /// `epoch` (a failed rekey changes no kernel state — bumping
    /// would split one keying era into two), saturating.
    fn complete_config(
        &mut self,
        raw: RawTfm,
        key: u64,
        len: u32,
        site: u16,
        bound_id: Option<u64>,
    ) {
        self.stats.configs_joined += 1;
        if key == 0 {
            self.stats.config_unlinked += 1;
            return;
        }
        let base = match normalize_frontend(key, self.frontend_off) {
            Some(base) => base,
            None => {
                self.count_bad_record();
                return;
            }
        };
        // Entry-bound lifetime (R1/T07-01, config twin): the return
        // honors the ENTRY's occupant. Bound-but-superseded unlinks
        // (the config ran on the old lifetime — or a dead one —
        // never the newcomer); unbound entries admit first-seen
        // ONLY when the base is still unmapped (a base that became
        // live between the halves leaves the config's true target
        // unknowable — ring order is not kernel order).
        let occupant = self
            .live
            .get(&base)
            .map(|&idx| (idx, self.generations[idx].info.id));
        let idx = match (bound_id, occupant) {
            (Some(bound), Some((idx, id))) if bound == id => idx,
            (Some(_), _) | (None, Some(_)) => {
                self.stats.config_unlinked += 1;
                return;
            }
            (None, None) => match self.admit_first_seen(key, "", false) {
                Some(_) => match self.live.get(&base) {
                    // Admission just inserted this base (total
                    // lookup — no indexing panics on this path).
                    Some(&idx) => idx,
                    None => {
                        self.stats.config_unlinked += 1;
                        return;
                    }
                },
                None => {
                    self.stats.config_unlinked += 1;
                    return;
                }
            },
        };
        // T07-02/R2-01: a config attributed to a first-seen
        // lifetime lands on an uncertain identity (creation
        // boundary never observed — a missed free could have
        // swapped the lifetime under the address). Attributed
        // best-effort — F06 partial, never a confident old
        // identity — with the uncertainty already counted once at
        // admission (no per-config double count).
        let info = &mut self.generations[idx].info;
        info.configs += 1;
        info.last_config_site = site;
        info.last_config_len = len;
        info.last_config_errno = raw.status;
        if raw.status == 0 {
            info.epoch = info.epoch.saturating_add(1);
        } else {
            self.stats.configs_failed += 1;
        }
    }

    /// Evict oldest-first retired tombstones while the history
    /// exceeds the bound (D4): live entries never evict (only
    /// retired indices are candidates), each eviction counts, and
    /// the live index fixup keeps the table exact. Total memory:
    /// live ≤ capacity, tombstones ≤ capacity, pending ≤ capacity.
    fn evict_tombstones(&mut self) {
        while self.generations.len() - self.live.len() > self.capacity {
            let Some(pos) = self.generations.iter().position(|g| g.info.retired) else {
                break;
            };
            self.generations.remove(pos);
            for idx in self.live.values_mut() {
                if *idx > pos {
                    *idx -= 1;
                }
            }
            self.stats.tombstone_evictions += 1;
        }
    }
}
