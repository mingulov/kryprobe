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
/// `LEdge.version` the T06 decoder understands.
pub const LEDGE_VERSION: u8 = 1;

/// `LEdge.edge`: function entry (submit-side observation).
pub const LEDGE_SUBMIT: u8 = 1;
/// `LEdge.edge`: function return (return-side observation).
pub const LEDGE_RETURN: u8 = 2;

/// `LEdge.site`: `crypto_skcipher_encrypt`.
pub const LSITE_ENC: u16 = 1;
/// `LEdge.site`: `crypto_skcipher_decrypt`.
pub const LSITE_DEC: u16 = 2;

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

// ---------------------------------------------------------------------------
// Structs (twinned in kcrypto_lifecycle.rs; pinned by layout tests)
// ---------------------------------------------------------------------------

/// One raw lifecycle edge on `LRING` (32 bytes): site, edge kind,
/// pairing key, timestamp, and the return status (return edges only;
/// submit edges carry 0).
///
/// `Debug` is manual: [`LEdge::key`] is a raw kernel pointer and
/// renders as `<redacted>` (round-1 sol-m9/astra-m9 — Debug output is
/// a log surface and must keep the module's no-render promise).
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
    /// Reserved flags (BPF writes 0).
    pub flags: u16,
    /// Raw kernel request pointer (pairing material; see module docs).
    pub key: u64,
    /// `bpf_ktime_get_ns()` at the edge.
    pub ts_ns: u64,
    /// Native return status (return edges) or 0 (submit edges).
    pub status: i32,
    /// Reserved auxiliary word (BPF writes 0).
    pub aux: u32,
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
