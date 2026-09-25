// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto lifecycle wire layouts (T06): userspace mirrors of the
//! BPF-side structs.
//!
//! Twin: `crates/bpf-kcrypto/src/bin/kcrypto_lifecycle.rs` (the BPF
//! sensor owns the originals; this module mirrors field order, sizes
//! and enum values byte-for-byte). Same twin discipline as
//! [`crate::kcrypto_agg`]: the BPF crate is a separate workspace, so
//! sharing is replaced by duplication + backstops — the layout pins in
//! `crates/kryprobe-abi/tests/kcrypto_lifecycle_layout.rs` and the
//! privileged decode suite fail on any drift.
//!
//! `no_std` (`core`-only): integers are native little-endian on the
//! supported x86-64 target (same assumption as [`crate::SpineEvent`]).
//!
//! Privacy: [`LEdge::key`] carries a raw kernel request pointer
//! kernel→userspace (pairing material only, like the aggregate
//! sensor's chase reads). It must never leave the privilege boundary:
//! the decoder maps it to an opaque id immediately, and no report,
//! log, or error string renders it. [`LTfm::key`] carries a raw
//! kernel transform pointer under the same promise (the tracker maps
//! it to an opaque generation immediately); [`LTfm::name`] is public
//! algorithm inventory and renders plainly.

// ---------------------------------------------------------------------------
// Enum values (twinned in kcrypto_lifecycle.rs; pinned by layout tests)
// ---------------------------------------------------------------------------

/// `LEdge.magic`: `LC` (little-endian u16).
pub const LEDGE_MAGIC: u16 = 0x434c;
/// `LEdge.version` the T07.3 decoder understands (v4: `tfm` carries
/// the frontend transform pointer behind the op — first-seen
/// admission + T08 attribution; v1/v2/v3 records refuse — versions
/// never mix, so an old decoder misreading the longer record is
/// impossible).
pub const LEDGE_VERSION: u8 = 5;

/// `LEdge.edge`: function entry (submit-side observation).
pub const LEDGE_SUBMIT: u8 = 1;
/// `LEdge.edge`: function return (return-side observation).
pub const LEDGE_RETURN: u8 = 2;

/// `LEdge.site`: `crypto_skcipher_encrypt`.
pub const LSITE_ENC: u16 = 1;
/// `LEdge.site`: `crypto_skcipher_decrypt`.
pub const LSITE_DEC: u16 = 2;

/// `LTfm.magic`: `LT` (little-endian u16).
pub const LTFM_MAGIC: u16 = 0x544c;
/// `LTfm.version` the T07 tracker understands (v1: 112-byte
/// transform edge; versions never mix with `LEdge` v3).
pub const LTFM_VERSION: u8 = 1;

/// `LTfm.site`: `crypto_alloc_skcipher` (T07.2).
pub const LTFM_SITE_ALLOC_SK: u16 = 1;
/// `LTfm.site`: `crypto_destroy_tfm` (T07.3).
pub const LTFM_SITE_DESTROY: u16 = 2;
/// `LTfm.site`: `crypto_skcipher_setkey` (T07.4).
pub const LTFM_SITE_SETKEY_SK: u16 = 3;
/// `LTfm.site`: `crypto_aead_setauthsize` (T07.4).
pub const LTFM_SITE_SETAUTHSIZE: u16 = 4;
/// `LTfm.site`: `crypto_alloc_aead` (T07.4).
pub const LTFM_SITE_ALLOC_AEAD: u16 = 5;
/// `LTfm.site`: `crypto_aead_setkey` (T07.4).
pub const LTFM_SITE_SETKEY_AEAD: u16 = 6;

/// `LTfm.flags` bit 1: the `name` field was truncated at 63 bytes +
/// NUL (the kernel string ran longer; provenance is partial —
/// recorded, never refused, never silently complete).
pub const LTFM_TRUNCATED: u16 = 0x0002;

/// `LEdge.flags` bit 0: BPF pairing taint (W8). Set on a return
/// emitted over a zero session cookie — the entry run never executed
/// (config/key guard skip, NOSLOT id-exhaustion drop, or pre-attach
/// call) — so the edge names no invocation (`invoc` 0). Honest BPF
/// never emits a tainted submit (NOSLOT drops silently); the decoder
/// refuses every tainted edge WITHOUT disturbing the table
/// (per-call cookies isolate invocations — a tainted edge disturbs
/// no outstanding id).
pub const LEDGE_TAINTED: u16 = 0x0001;
/// v5 submit edges: the driver word filled the 64-byte bound (the
/// selected name may continue past it — D9: a clipped name reads as
/// partial, never complete).
pub const LEDGE_TRUNCATED: u16 = 0x0002;

/// `LConfig.magic`: `KLC1` (little-endian u32).
pub const LCONFIG_MAGIC: u32 = 0x3143_4c4b;
/// `LConfig.version` the T07.3 sensor understands (v3: the chase
/// offsets ride in the config words, plus the destroy refcount
/// words and the op request-link words; older versions refuse —
/// versions never mix).
pub const LCONFIG_VERSION: u32 = 3;
/// `LConfig.flags` bit 0: disarmed (D1). The disarm writes the armed
/// value back with ONLY this bit set — magic, version, offsets and
/// tail preserved bit-for-bit — so a hook racing the disarm reads
/// either the fully-armed value or a flags-nonzero value (its gate
/// requires flags == 0, so it stops), never valid offsets mixed with
/// zeroed words. The value 1 is load-bearing: armed flags are 0, so
/// the disarm changes exactly ONE byte of the 64-byte value (byte 8),
/// and a single differing byte cannot tear under concurrent
/// aligned-word readers — every racing read observes the old value
/// or the new value, never a mixture.
pub const LCONFIG_DISABLED: u32 = 1;

/// `LLOSS[0]`: ringbuf reservation failures (kernel-side loss).
pub const LLOSS_RESERVE: u32 = 0;
/// `LLOSS[1]`: edges dropped while disarmed (bad/missing LCFG magic).
pub const LLOSS_DISABLED: u32 = 1;
/// `LLOSS[2]`: edges dropped for a null request key.
pub const LLOSS_BADKEY: u32 = 2;
/// `LLOSS[3]`: return edges dropped because the return register read
/// was refused (aggregate-sensor `KDROPS_FRET` precedent: an
/// unclassified return is skipped, never misbucketed).
pub const LLOSS_FRET: u32 = 3;
/// `LLOSS[4]`: submit edges dropped on invocation-id exhaustion
/// (W8: post-accept pure drop, agg'd — accepted-but-untransported,
/// the equation's NOSLOT term; the cookie stays zero and nothing
/// emits, so the exit taints by construction — never a wrapped id,
/// never a phantom submit).
pub const LLOSS_NOSLOT: u32 = 4;

/// `LAGG[0]`: accepted encrypt-submit edges (post-gate, pre-reserve).
pub const LAGG_ENC_SUB: u32 = 0;
/// `LAGG[1]`: accepted encrypt-return edges.
pub const LAGG_ENC_RET: u32 = 1;
/// `LAGG[2]`: accepted decrypt-submit edges.
pub const LAGG_DEC_SUB: u32 = 2;
/// `LAGG[3]`: accepted decrypt-return edges.
pub const LAGG_DEC_RET: u32 = 3;
/// `LAGG[4]`: accepted skcipher-alloc-submit edges (T07.2).
pub const LAGG_ALLOCSK_SUB: u32 = 4;
/// `LAGG[5]`: accepted skcipher-alloc-return edges (T07.2).
pub const LAGG_ALLOCSK_RET: u32 = 5;
/// `LAGG[6]`: accepted destroy-submit edges (T07.3).
pub const LAGG_DESTROY_SUB: u32 = 6;
/// `LAGG[7]`: accepted destroy-return edges (T07.3).
pub const LAGG_DESTROY_RET: u32 = 7;
/// `LAGG[8]`: accepted skcipher-setkey-submit edges (T07.4).
pub const LAGG_SETKEYSK_SUB: u32 = 8;
/// `LAGG[9]`: accepted skcipher-setkey-return edges (T07.4).
pub const LAGG_SETKEYSK_RET: u32 = 9;
/// `LAGG[10]`: accepted setauthsize-submit edges (T07.4).
pub const LAGG_SETAUTH_SUB: u32 = 10;
/// `LAGG[11]`: accepted setauthsize-return edges (T07.4).
pub const LAGG_SETAUTH_RET: u32 = 11;
/// `LAGG[12]`: accepted aead-alloc-submit edges (T07.4).
pub const LAGG_ALLOCAEAD_SUB: u32 = 12;
/// `LAGG[13]`: accepted aead-alloc-return edges (T07.4).
pub const LAGG_ALLOCAEAD_RET: u32 = 13;
/// `LAGG[14]`: accepted aead-setkey-submit edges (T07.4).
pub const LAGG_SETKEYAEAD_SUB: u32 = 14;
/// `LAGG[15]`: accepted aead-setkey-return edges (T07.4).
pub const LAGG_SETKEYAEAD_RET: u32 = 15;

// ---------------------------------------------------------------------------
// Structs (twinned in kcrypto_lifecycle.rs; pinned by layout tests)
// ---------------------------------------------------------------------------

/// One raw lifecycle edge on `LRING` (112 bytes, v5): site, edge
/// kind, pairing key, timestamp, the return status (return edges
/// only; submit edges carry 0), the BPF invocation id, the frontend
/// transform pointer behind the op (T07.3 first-seen admission +
/// T08 attribution; 0 when the request link was unreadable), and the
/// runtime-selected driver name (T07-04/F05: submit edges only).
///
/// [`LEdge::tfm`] is the raw `crypto_skcipher` frontend pointer the
/// op ran against (`req->base->tfm` chased BPF-side at the
/// `LCFG`-pinned offsets — ENTRY run only: R2 proved the exit-side
/// chase can read freed request memory after an async completion,
/// so returns carry 0 and the transform association comes from the
/// submit's word alone; a return without submit evidence leaves the
/// association unknown). The tracker normalizes it to the canonical
/// base with the same `sk_base` word the alloc join uses, so op-first
/// and alloc-first observations of one transform meet at one
/// identity. 0 admits as unknown (missing link, never fabricated,
/// never refused — the op still joins by invocation).
///
/// [`LEdge::drv`] is the `cra_driver_name` behind the submit's
/// transform (the F05 selected metadata for pre-attach transforms —
/// allocation/requested name/previous configuration stay unknown;
/// empty when the driver chase was unreadable). Returns carry no
/// name (the twin refuses one — the submit's admission owns the
/// provenance).
///
/// [`LEdge::invoc`] is the return-carried invocation identity
/// (round-4 W4, race-hardened round-6 W6, lane-split round-7 W7,
/// cookie-carried round-8 W8, 3-bit lanes T07.2): every submit takes
/// `(per-program per-CPU sequence << 17) | (lane << 14) | (cpu << 1)`
/// from its own program's BPF `LCTR` lane (bit 0 reserved + always
/// clear; 0 is never issued, it means "no invocation"); the entry
/// run stores it in the kernel-zeroed per-call session cookie and
/// the exit run of the SAME call reads the SAME cookie back. The
/// decoder joins a return ONLY to an outstanding id with the SAME
/// invocation — a lost return + lost submit can no longer alias one
/// call's return onto another call's id, whatever the transport
/// drops. Pairing soundness no longer depends on lossless delivery.
/// The decoder additionally refuses malformed clean ids (0, or
/// reserved-bit-set — `DecodeDrop::BadInvoc`); honest BPF never
/// emits them.
///
/// [`LEdge::invoc`] bit 0: reserved (W8 mints cookie ids with it
/// clear — a pure validity check, not a state tag).
pub const LEDGE_INVOC_POISON: u64 = 1;
///
/// `Debug` is manual: [`LEdge::key`] and [`LEdge::tfm`] are raw
/// kernel pointers and render as `<redacted>` (round-1
/// sol-m9/astra-m9 — Debug output is a log surface and must keep
/// the module's no-render promise).
/// `invoc` is a counter, not an address, and renders plainly;
/// `drv` renders (driver names are public inventory, not secrets).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LEdge {
    /// Must be [`LEDGE_MAGIC`].
    pub magic: u16,
    /// Must be [`LEDGE_VERSION`].
    pub version: u8,
    /// [`LEDGE_SUBMIT`] or [`LEDGE_RETURN`].
    pub edge: u8,
    /// [`LSITE_ENC`] or [`LSITE_DEC`].
    pub site: u16,
    /// Flag bits ([`LEDGE_TAINTED`] + [`LEDGE_TRUNCATED`] defined;
    /// BPF writes 0 for clean untruncated edges).
    pub flags: u16,
    /// Raw kernel request pointer (pairing material; see module docs).
    pub key: u64,
    /// `bpf_ktime_get_ns()` at the edge.
    pub ts_ns: u64,
    /// Native return status (return edges) or 0 (submit edges).
    pub status: i32,
    /// Reserved auxiliary word (BPF writes 0).
    pub aux: u32,
    /// BPF invocation id (≥1 on cookie-carrying edges; 0 with taint
    /// when the return's session cookie reads zero).
    pub invoc: u64,
    /// Raw kernel frontend transform pointer behind the op (0 when
    /// the request link was unreadable — unknown, see struct docs).
    /// Submit edges only (R2: returns carry 0, never chased).
    pub tfm: u64,
    /// Runtime-selected driver name behind the submit's transform
    /// (NUL-terminated, 63 bytes max + NUL; empty when the driver
    /// chase was unreadable — unknown, never fabricated). Submit
    /// edges only (returns carry empty — the twin refuses a name).
    pub drv: [u8; 64],
}

impl core::fmt::Debug for LEdge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LEdge")
            .field("magic", &self.magic)
            .field("version", &self.version)
            .field("edge", &self.edge)
            .field("site", &self.site)
            .field("flags", &self.flags)
            .field("key", &"<redacted>")
            .field("ts_ns", &self.ts_ns)
            .field("status", &self.status)
            .field("aux", &self.aux)
            .field("invoc", &self.invoc)
            .field("tfm", &"<redacted>")
            .field("drv", &self.drv)
            .finish()
    }
}

impl LEdge {
    /// Manually-maintained field list (R6: the K1 Task 3 allowlist
    /// tripwire extends to lifecycle transport — declaration order,
    /// pinned by `allowlist_field_set_matches_docs`; adding a field
    /// without updating this list + the test + the doc fails the
    /// build — deliberate friction, same as `KConfig::FIELDS`).
    pub const FIELDS: &[&str] = &[
        "magic", "version", "edge", "site", "flags", "key", "ts_ns", "status", "aux", "invoc",
        "tfm", "drv",
    ];
}

/// One raw transform edge on `LRING` (112 bytes): allocation
/// entry/return halves (T07.2), release halves (T07.3) and
/// configuration halves (T07.4), joined userspace-side by the
/// BPF attempt token.
///
/// Layout mirrors [`LEdge`] through `status`, then carries the
/// site/edge-specific auxiliaries, the attempt token, and the
/// bounded name. Field contract by site (BPF writes exactly this;
/// the tracker refuses drift):
///
/// - alloc entry: `key` 0, `status` 0, `aux` = requested alg
///   type, `aux2` = requested alg mask, `token` the fresh attempt
///   id, `name` the requested algorithm name.
/// - alloc return: `key` = frontend transform pointer (success)
///   or 0 (failure), `status` 0 or the native errno, `aux`/`aux2`
///   0, `token` the entry's id, `name` the resolved driver name
///   (success) or empty (failure).
/// - destroy/config halves: T07.3/T07.4 define their words; until
///   then the tracker refuses those sites.
///
/// [`LTfm::token`] is the allocation-attempt identity (T07.2: the
/// entry run mints one id per call from its own `LCTR` lane and
/// stores it in the kernel-zeroed per-call session cookie; the
/// exit run of the SAME call reads the SAME cookie back). The mint
/// shares the invocation layout (`(seq << 17) | (lane << 14) |
/// (cpu << 1)`, bit 0 reserved + always clear) with the alloc
/// program's own lane value, so the namespace is separate from
/// invocation ids (own counter lane, own tracker table — an attempt
/// token can never alias an invocation id). 0 means "no attempt"
/// (tainted edges only).
///
/// `Debug` is manual: [`LTfm::key`] is a raw kernel pointer and
/// renders as `<redacted>` (same promise as [`LEdge`]); `name`
/// renders (algorithm names are public inventory, not secrets).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LTfm {
    /// Must be [`LTFM_MAGIC`].
    pub magic: u16,
    /// Must be [`LTFM_VERSION`].
    pub version: u8,
    /// [`LEDGE_SUBMIT`] or [`LEDGE_RETURN`] (shared kind tags).
    pub edge: u8,
    /// [`LTFM_SITE_ALLOC_SK`] et al (validated per task phase).
    pub site: u16,
    /// Flag bits ([`LEDGE_TAINTED`] + [`LTFM_TRUNCATED`] defined).
    pub flags: u16,
    /// Raw kernel transform pointer (pairing material; see module docs).
    pub key: u64,
    /// `bpf_ktime_get_ns()` at the edge.
    pub ts_ns: u64,
    /// Native status (return edges) or 0 (entry edges).
    pub status: i32,
    /// Site/edge word: alloc-entry alg type, else 0 (T07.2).
    pub aux: u32,
    /// Site/edge word: alloc-entry alg mask, else 0 (T07.2).
    pub aux2: u32,
    /// Attempt token (≥1 on clean edges; 0 with taint). Preceded by
    /// 4 BPF-zeroed reserved bytes (offsets 36–39, the alignment pad
    /// — the emitter writes them per record; decoders ignore them).
    pub token: u64,
    /// NUL-terminated name (63 bytes max + NUL; empty where unused).
    pub name: [u8; 64],
}

impl core::fmt::Debug for LTfm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LTfm")
            .field("magic", &self.magic)
            .field("version", &self.version)
            .field("edge", &self.edge)
            .field("site", &self.site)
            .field("flags", &self.flags)
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

impl LTfm {
    /// Manually-maintained field list (R6 allowlist tripwire —
    /// declaration order; the 4-byte alignment pad before `token`
    /// is unnamed by design and stays out of the list).
    pub const FIELDS: &[&str] = &[
        "magic", "version", "edge", "site", "flags", "key", "ts_ns", "status", "aux", "aux2",
        "token", "name",
    ];
}

/// Lifecycle sensor config in `LCFG` (64 bytes, key 0).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LConfig {
    /// Must be [`LCONFIG_MAGIC`] or the sensor stays disarmed.
    pub magic: u32,
    /// Must be [`LCONFIG_VERSION`].
    pub version: u32,
    /// Feature flags (armed: 0; disarmed: [`LCONFIG_DISABLED`];
    /// the BPF gate requires exactly 0, so any nonzero value fails
    /// closed).
    pub flags: u32,
    /// `crypto_tfm.__crt_alg` byte offset (BTF-resolved at arm).
    pub tfm_alg: u32,
    /// `crypto_alg.cra_driver_name` byte offset (BTF-resolved at arm).
    pub alg_drv: u32,
    /// `crypto_skcipher.base` byte offset (BTF-resolved at arm).
    pub sk_base: u32,
    /// `crypto_tfm.refcnt` byte offset (BTF-resolved at arm; read by
    /// the destroy program — meaningful only when
    /// `refcnt_present` is 1).
    pub refcnt_off: u32,
    /// 1 when `crypto_tfm` carries `refcnt` on this kernel (the
    /// destroy program reads it), 0 when the field is absent
    /// (7.2+: unconditional destroy — every observed destroy
    /// retires; the tracker runs in always-final mode).
    pub refcnt_present: u32,
    /// `skcipher_request.base` byte offset (BTF-resolved at arm;
    /// the op programs' request→base link for first-seen).
    pub req_base: u32,
    /// `crypto_async_request.tfm` byte offset (BTF-resolved at arm;
    /// the op programs' base→frontend link for first-seen).
    pub req_tfm: u32,
    /// Reserved (loader writes 0).
    pub reserved: [u8; 24],
}

impl LConfig {
    /// Manually-maintained field list (R6 allowlist tripwire —
    /// declaration order, loader-written config like `KConfig`).
    pub const FIELDS: &[&str] = &[
        "magic",
        "version",
        "flags",
        "tfm_alg",
        "alg_drv",
        "sk_base",
        "refcnt_off",
        "refcnt_present",
        "req_base",
        "req_tfm",
        "reserved",
    ];
}
