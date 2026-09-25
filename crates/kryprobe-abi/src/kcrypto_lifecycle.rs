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
//! log, or error string renders it.

// ---------------------------------------------------------------------------
// Enum values (twinned in kcrypto_lifecycle.rs; pinned by layout tests)
// ---------------------------------------------------------------------------

/// `LEdge.magic`: `LC` (little-endian u16).
pub const LEDGE_MAGIC: u16 = 0x434c;
/// `LEdge.version` the T06 decoder understands (v3: `invoc` carries
/// the BPF invocation id; v1/v2 records refuse — versions never mix,
/// so an old decoder misreading the longer record is impossible).
pub const LEDGE_VERSION: u8 = 3;

/// `LEdge.edge`: function entry (submit-side observation).
pub const LEDGE_SUBMIT: u8 = 1;
/// `LEdge.edge`: function return (return-side observation).
pub const LEDGE_RETURN: u8 = 2;

/// `LEdge.site`: `crypto_skcipher_encrypt`.
pub const LSITE_ENC: u16 = 1;
/// `LEdge.site`: `crypto_skcipher_decrypt`.
pub const LSITE_DEC: u16 = 2;

/// `LEdge.flags` bit 0: BPF pairing taint (W8). Set on a return
/// emitted over a zero session cookie — the entry run never executed
/// (config/key guard skip, NOSLOT id-exhaustion drop, or pre-attach
/// call) — so the edge names no invocation (`invoc` 0). Honest BPF
/// never emits a tainted submit (NOSLOT drops silently); the decoder
/// refuses every tainted edge WITHOUT disturbing the table
/// (per-call cookies isolate invocations — a tainted edge disturbs
/// no outstanding id). No other flag bit is defined.
pub const LEDGE_TAINTED: u16 = 0x0001;

/// `LConfig.magic`: `KLC1` (little-endian u32).
pub const LCONFIG_MAGIC: u32 = 0x3143_4c4b;
/// `LConfig.version` the T06 sensor understands.
pub const LCONFIG_VERSION: u32 = 1;

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

// ---------------------------------------------------------------------------
// Structs (twinned in kcrypto_lifecycle.rs; pinned by layout tests)
// ---------------------------------------------------------------------------

/// One raw lifecycle edge on `LRING` (40 bytes): site, edge kind,
/// pairing key, timestamp, the return status (return edges only;
/// submit edges carry 0), and the BPF invocation id.
///
/// [`LEdge::invoc`] is the return-carried invocation identity
/// (round-4 W4, race-hardened round-6 W6, lane-split round-7 W7,
/// cookie-carried round-8 W8): every submit takes
/// `(per-program per-CPU sequence << 15) | (lane << 14) | (cpu << 1)`
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
/// `Debug` is manual: [`LEdge::key`] is a raw kernel pointer and
/// renders as `<redacted>` (round-1 sol-m9/astra-m9 — Debug output is
/// a log surface and must keep the module's no-render promise).
/// `invoc` is a counter, not an address, and renders plainly.
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
    /// Flag bits (only [`LEDGE_TAINTED`] defined; BPF writes 0 for
    /// clean edges).
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
            .finish()
    }
}

/// Lifecycle sensor config in `LCFG` (64 bytes, key 0).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LConfig {
    /// Must be [`LCONFIG_MAGIC`] or the sensor stays disarmed.
    pub magic: u32,
    /// Must be [`LCONFIG_VERSION`].
    pub version: u32,
    /// Feature flags (T06 defines none; must be 0).
    pub flags: u32,
    /// Reserved (loader writes 0).
    pub reserved: [u8; 52],
}
