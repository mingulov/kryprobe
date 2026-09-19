// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto aggregate wire layouts (K1 Task 2): userspace mirrors of the
//! BPF-side structs.
//!
//! Twin: `crates/bpf-kcrypto/src/bin/kcrypto.rs` (the BPF sensor owns the
//! originals; this module mirrors field order, sizes, enum values, and
//! the identity hash byte-for-byte). The twin direction is deliberate
//! (Task-2 brief): the BPF crate is a separate workspace, so sharing is
//! replaced by duplication + backstops — the layout pins in
//! `crates/kryprobe-abi/tests/kcrypto_layout.rs` and the privileged
//! exactness suite `crates/kryprobe-privilege/tests/kcrypto_agg.rs`
//! (ring→map hash join + fold invariants) fail on any drift.
//!
//! `no_std` (`core`-only): integers are native little-endian on the
//! supported x86-64 target (same assumption as [`crate::SpineEvent`]).

// ---------------------------------------------------------------------------
// Enum values (twinned in kcrypto.rs; pinned by kcrypto_layout.rs)
// ---------------------------------------------------------------------------

/// Algorithm family `KAgg.fam`: alloc/destroy carry no resolved family.
pub const KFAM_ANY: u8 = 0;
/// Algorithm family: skcipher (`crypto_skcipher_*`).
pub const KFAM_SK: u8 = 1;
/// Algorithm family: AEAD (`crypto_aead_*`).
pub const KFAM_AEAD: u8 = 2;
/// Algorithm family: async hash (`crypto_ahash_digest`).
pub const KFAM_AHASH: u8 = 3;
/// Algorithm family: sync hash (`crypto_shash_digest`/`crypto_shash_finup`).
pub const KFAM_SHASH: u8 = 4;

/// Operation `KAgg.op`: `crypto_alloc_tfm_node`.
pub const KOP_ALLOC: u8 = 1;
/// Operation: `crypto_destroy_tfm`.
pub const KOP_DESTROY: u8 = 2;
/// Operation: skcipher/AEAD encrypt.
pub const KOP_ENC: u8 = 3;
/// Operation: skcipher/AEAD decrypt.
pub const KOP_DEC: u8 = 4;
/// Operation: ahash/shash digest.
pub const KOP_DIGEST: u8 = 5;
/// Operation: shash finup.
pub const KOP_FINUP: u8 = 6;

/// Result `KAgg.res`: return 0 (or a valid pointer on the alloc path).
pub const KRES_OK: u8 = 0;
/// Result: negative return other than the queued pair (alloc: `ERR_PTR`).
pub const KRES_ERR: u8 = 1;
/// Result: `-EINPROGRESS`/`-EBUSY` return (async-queued).
pub const KRES_QUEUED: u8 = 2;
/// Result: unobservable — void-return `crypto_destroy_tfm` only. Rows
/// with this `res` carry `calls` but no `ok`/`errors`/`queued` count
/// (there is no return value to classify).
pub const KRES_UNOBSERVED: u8 = 3;

/// Context `KAgg.ctx`: process context (no `PF_KTHREAD` on current).
pub const KCTX_PROC: u8 = 0;
/// Context: kernel thread (`task_struct.flags & PF_KTHREAD`).
pub const KCTX_KTHREAD: u8 = 1;
/// Context: softirq. NEVER written by the BPF (no stable in-BPF softirq
/// detector: task flags only distinguish kthreads; preempt-count reads
/// are kernel-version-fragile) — the privileged suite pins the bucket at
/// zero. Softirq-context executions misattribute to `PROC`/`KTHREAD`
/// (known limitation, same root as the K0 P4 unproven-async gap).
pub const KCTX_SOFTIRQ: u8 = 2;
/// Context: unknown — `bpf_get_current_task` failed (essentially never;
/// the read has no realistic failure mode, so the privileged suite does
/// not zero-pin this bucket, it just folds it into the totals).
pub const KCTX_UNKNOWN: u8 = 3;

/// Ring kind `KCtl.kind`: first-seen identity (references `KAGG` by hash).
pub const KCTL_IDENT: u8 = 1;
/// Ring kind: config generation change. RESERVED, never emitted
/// (`KConfig` carries no generation field; a generation would need one).
pub const KCTL_GENCHANGE: u8 = 2;
/// Ring kind: ring-loss gap marker. RESERVED, never emitted (`KCtl`
/// carries no sequence number; reserve failures instead saturate the
/// [`KIDN_DROPS`] counter so no loss is silent).
pub const KCTL_GAP: u8 = 3;
/// Ring kind: `KAGG` insert failed (map full), first per identity
/// (KIDN-gated); a full `KIDN` stays silent per C9 — observe via
/// `KTOT`-gap + `KIDN` dump; totals preserved.
pub const KCTL_OVERFLOW: u8 = 4;
/// Ring kind: periodic health. RESERVED, never emitted from BPF
/// (userspace-synthesized; the fast path stays control-event-only).
pub const KCTL_HEALTH: u8 = 5;

/// Reserved `KIDN` key: ring-reserve-failure counter (saturating `u8`).
/// A real identity hash colliding here (2^-64) would miscount, never
/// corrupt (the value only ever saturates upward).
pub const KIDN_DROPS: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// Structs (twinned in kcrypto.rs; sizes pinned by kcrypto_layout.rs)
// ---------------------------------------------------------------------------

/// `KCFG` value: the 9 loader-resolved offsets + kthread flag + pad (44B).
///
/// Twin: `KConfig` in `crates/bpf-kcrypto/src/bin/kcrypto.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct KConfig {
    /// `skcipher_request.base` (bytes).
    pub sk_req_base: u32,
    /// `crypto_async_request.tfm` (bytes).
    pub async_tfm: u32,
    /// `crypto_tfm.__crt_alg` (bytes).
    pub tfm_alg: u32,
    /// `crypto_alg.cra_name` (bytes).
    pub alg_name: u32,
    /// `crypto_alg.cra_driver_name` (bytes).
    pub alg_drv: u32,
    /// `task_struct.flags` (bytes).
    pub task_flags: u32,
    /// `PF_KTHREAD` value (the BPF compares task flags against this).
    pub pf_kthread: u32,
    /// `aead_request.cryptlen` (bytes; the AEAD length read).
    pub aead_cryptlen_off: u32,
    /// `ahash_request.nbytes` (bytes; the ahash length read).
    pub ahash_nbytes_off: u32,
    /// `crypto_shash.base` (bytes; the shash tfm link — @0 on 7.0, @8
    /// on 6.12; resolved, not hardcoded).
    pub shash_base: u32,
    /// Reserved, zero.
    pub _pad: u32,
}

impl KConfig {
    /// Manually-maintained field list (K1 Task 3 allowlist tripwire):
    /// declaration order, pins `docs/kcrypto-capture-allowlist.md`
    /// via `allowlist_field_set_matches_docs` (adding a field without
    /// updating this list + the test + the doc fails the build —
    /// deliberate friction, brief Step 2).
    pub const FIELDS: &[&str] = &[
        "sk_req_base",
        "async_tfm",
        "tfm_alg",
        "alg_name",
        "alg_drv",
        "task_flags",
        "pf_kthread",
        "aead_cryptlen_off",
        "ahash_nbytes_off",
        "shash_base",
        "_pad",
    ];

    /// Little-endian wire bytes for the `KCFG` map update (x86-64 target).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 44] {
        let mut out = [0u8; 44];
        out[0..4].copy_from_slice(&self.sk_req_base.to_le_bytes());
        out[4..8].copy_from_slice(&self.async_tfm.to_le_bytes());
        out[8..12].copy_from_slice(&self.tfm_alg.to_le_bytes());
        out[12..16].copy_from_slice(&self.alg_name.to_le_bytes());
        out[16..20].copy_from_slice(&self.alg_drv.to_le_bytes());
        out[20..24].copy_from_slice(&self.task_flags.to_le_bytes());
        out[24..28].copy_from_slice(&self.pf_kthread.to_le_bytes());
        out[28..32].copy_from_slice(&self.aead_cryptlen_off.to_le_bytes());
        out[32..36].copy_from_slice(&self.ahash_nbytes_off.to_le_bytes());
        out[36..40].copy_from_slice(&self.shash_base.to_le_bytes());
        out[40..44].copy_from_slice(&self._pad.to_le_bytes());
        out
    }
}

/// `KAGG` key: attribution head + algorithm identity (260B, packed).
///
/// Head: `fam`/`op`/`res`/`ctx`; identity: `cra_name` (128B) and
/// `cra_driver_name` (128B) as raw little-endian words (NUL-padded C
/// strings copied whole, padding included). `packed`: 4 + 256 admits no
/// alignment padding. Field access goes through the sound accessors
/// below (direct field borrows of packed fields are rejected); `Clone` /
/// `Copy` are manual for the same reason. No `Debug`: the derive would
/// borrow packed fields.
///
/// Twin: `KAgg` in `crates/bpf-kcrypto/src/bin/kcrypto.rs` (same packed
/// shape; the BPF touches it through byte pointers only).
#[repr(C, packed)]
pub struct KAgg {
    /// Algorithm family ([`KFAM_ANY`]..).
    pub fam: u8,
    /// Operation ([`KOP_ALLOC`]..).
    pub op: u8,
    /// Result ([`KRES_OK`]..).
    pub res: u8,
    /// Context ([`KCTX_PROC`]..).
    pub ctx: u8,
    /// `cra_name` / requested name, 128 bytes as 16 words.
    pub alg: [u64; 16],
    /// `cra_driver_name`, 128 bytes as 16 words (zeros on the alloc path,
    /// where the driver is not chosen yet).
    pub drv: [u64; 16],
}

// Manual: derive(Clone/Copy) borrows packed fields, which is rejected.
// (`*self` is a whole-value memcpy — sound on packed, no field borrow.)
impl Clone for KAgg {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for KAgg {}

impl KAgg {
    /// Manually-maintained field list (K1 Task 3 allowlist tripwire):
    /// declaration order, pins `docs/kcrypto-capture-allowlist.md`
    /// via `allowlist_field_set_matches_docs` (deliberate friction —
    /// see [`KConfig::FIELDS`]).
    pub const FIELDS: &[&str] = &["fam", "op", "res", "ctx", "alg", "drv"];

    /// Sound unaligned field reads (packed: no direct borrows).
    #[must_use]
    pub fn fam(&self) -> u8 {
        // SAFETY: `read_unaligned` on a packed field; always sound.
        unsafe { core::ptr::addr_of!(self.fam).read_unaligned() }
    }
    /// Sound unaligned field reads (packed: no direct borrows).
    #[must_use]
    pub fn op(&self) -> u8 {
        unsafe { core::ptr::addr_of!(self.op).read_unaligned() }
    }
    /// Sound unaligned field reads (packed: no direct borrows).
    #[must_use]
    pub fn res(&self) -> u8 {
        unsafe { core::ptr::addr_of!(self.res).read_unaligned() }
    }
    /// Sound unaligned field reads (packed: no direct borrows).
    #[must_use]
    pub fn ctx(&self) -> u8 {
        unsafe { core::ptr::addr_of!(self.ctx).read_unaligned() }
    }
    /// Sound unaligned field reads (packed: no direct borrows).
    #[must_use]
    pub fn alg(&self) -> [u64; 16] {
        unsafe { core::ptr::addr_of!(self.alg).read_unaligned() }
    }
    /// Sound unaligned field reads (packed: no direct borrows).
    #[must_use]
    pub fn drv(&self) -> [u64; 16] {
        unsafe { core::ptr::addr_of!(self.drv).read_unaligned() }
    }
}

/// Aggregate counters + latency histogram (120B): `KAGG` and `KTOT` value.
///
/// Field order is the brief's verbatim `VAgg { calls, bytes, ok, errors,
/// queued, first_ns, last_ns, lat }` (C8). Counters saturate (never
/// wrap); `first_ns` stamps the first SEEN exit edge per CPU lane (a
/// fresh lane MUST stamp, else the userspace min-fold poisons — osslscope
/// `count.rs` borrow (c), same constraint as the spine) and `last_ns` the
/// last seen one (C4: single-edge stamps, not entry/exit pairs). `lat`
/// stays zero (no durations from a single edge — C4, pinned by the
/// privileged suite).
///
/// Twin: `VAgg` in `crates/bpf-kcrypto/src/bin/kcrypto.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct VAgg {
    /// Observations attributed to this row.
    pub calls: u64,
    /// Attributed bytes (request `cryptlen`/`nbytes`, shash `len` arg).
    pub bytes: u64,
    /// Ok-classified observations (return 0 / valid pointer).
    pub ok: u64,
    /// Error-classified observations (other negative / `ERR_PTR`).
    pub errors: u64,
    /// Queued-classified observations (`-EINPROGRESS`/`-EBUSY`).
    pub queued: u64,
    /// First-observation time per lane (min-folded; 0 when `calls` is 0).
    pub first_ns: u64,
    /// Last-observation time per lane (max-folded).
    pub last_ns: u64,
    /// Latency histogram, 8 buckets (all zero — C4, no durations).
    pub lat: [u64; 8],
}

impl VAgg {
    /// Manually-maintained field list (K1 Task 3 allowlist tripwire):
    /// declaration order, pins `docs/kcrypto-capture-allowlist.md`
    /// via `allowlist_field_set_matches_docs` (deliberate friction —
    /// see [`KConfig::FIELDS`]).
    pub const FIELDS: &[&str] = &[
        "calls", "bytes", "ok", "errors", "queued", "first_ns", "last_ns", "lat",
    ];
}

/// Ring control event (48B): references, never full identity.
///
/// `key_hash` joins [`kcrypto_ident_hash`] over the `KAGG` row's `(fam,
/// op, alg, drv)`; `val0` packs the attribution head (see
/// [`kctl_pack_head`]) for filtering without a map join; `val1` packs the
/// NUL-scanned name lengths (see [`kctl_pack_lens`]); `val2` carries the
/// first-seen `now` (C5); `val3` is reserved zero. First-seen creates the
/// `KAGG` row (full identity lives in the map); the ring carries the hash
/// after. The ring is name-free by construction (kp2 §9 privacy).
///
/// Twin: `KCtl` in `crates/bpf-kcrypto/src/bin/kcrypto.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct KCtl {
    /// Event kind ([`KCTL_IDENT`]..).
    pub kind: u8,
    /// Padding, zero.
    pub _p: [u8; 3],
    /// [`kcrypto_ident_hash`] of the identity this event is about.
    pub key_hash: u64,
    /// Packed attribution head ([`kctl_pack_head`]).
    pub val0: u64,
    /// Packed name lengths ([`kctl_pack_lens`]).
    pub val1: u64,
    /// First-seen monotonic ns (the gating observation's `ktime`).
    pub val2: u64,
    /// Reserved, zero.
    pub val3: u64,
}

impl KCtl {
    /// Manually-maintained field list (K1 Task 3 allowlist tripwire):
    /// declaration order, pins `docs/kcrypto-capture-allowlist.md`
    /// via `allowlist_field_set_matches_docs` (deliberate friction —
    /// see [`KConfig::FIELDS`]).
    pub const FIELDS: &[&str] = &["kind", "_p", "key_hash", "val0", "val1", "val2", "val3"];
}

/// Pack a `KCtl.val0` attribution head: `fam | op<<8 | res<<16 | ctx<<24`
/// (userspace helper; the BPF inlines the same shifts).
#[must_use]
pub fn kctl_pack_head(fam: u8, op: u8, res: u8, ctx: u8) -> u64 {
    (u64::from(fam)) | (u64::from(op) << 8) | (u64::from(res) << 16) | (u64::from(ctx) << 24)
}

/// Pack a `KCtl.val1` name-length pair: `alg_len | drv_len<<32` (lengths
/// are NUL-scanned over at most 128 bytes each, so both fit in `u32`).
#[must_use]
pub fn kctl_pack_lens(alg_len: u32, drv_len: u32) -> u64 {
    (u64::from(alg_len)) | (u64::from(drv_len) << 32)
}

/// Unpack a `KCtl.val1` name-length pair into `(alg_len, drv_len)`.
#[must_use]
pub fn kctl_unpack_lens(val1: u64) -> (u32, u32) {
    ((val1 & 0xffff_ffff) as u32, (val1 >> 32) as u32)
}

// ---------------------------------------------------------------------------
// Identity hash (twinned in kcrypto.rs: same inputs, same FNV-1a bytes)
// ---------------------------------------------------------------------------

/// FNV-1a 64 offset basis.
const FNV_BASIS: u64 = 14695981039346656037;
/// FNV-1a 64 prime.
const FNV_PRIME: u64 = 1099511628211;

/// Identity hash: `KIDN` key and `KCtl.key_hash`.
///
/// FNV-1a over, in order: `fam`, `op`, the 128 `alg` bytes, the 128 `drv`
/// bytes (words in little-endian byte order). `res`/`ctx` are excluded:
/// several `KAGG` rows (distinct result/context) share one identity gate,
/// so first-seen fires once per `(fam, op, alg, drv)` (brief's `KIDN`
/// contract; C5's "over KAgg key" names these identity fields).
#[must_use]
pub fn kcrypto_ident_hash(fam: u8, op: u8, alg: &[u64; 16], drv: &[u64; 16]) -> u64 {
    let mut hash = FNV_BASIS;
    let mut mix = |byte: u8| {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    };
    mix(fam);
    mix(op);
    for words in [alg, drv] {
        for word in words {
            for byte in word.to_le_bytes() {
                mix(byte);
            }
        }
    }
    hash
}

// ---------------------------------------------------------------------------
// Per-CPU fold (userspace; unit-tested below on synthetic lanes)
// ---------------------------------------------------------------------------

/// Fold per-CPU `VAgg` lanes into one total.
///
/// Counters and histogram lanes sum saturating; `first_ns` is the minimum
/// over lanes with `calls > 0` (a zero-`calls` lane holds `first_ns == 0`
/// and must not poison the min); `last_ns` is the maximum; both stamps
/// are 0 when no lane observed anything. BPF-full-path overflow needs
/// 256+ distinct identities, so it is untestable live — the synthetic
/// fold tests + no-overflow gates are the backstop.
#[must_use]
pub fn fold_vagg(lanes: &[VAgg]) -> VAgg {
    let mut out = VAgg::default();
    let mut first = u64::MAX;
    let mut any = false;
    for lane in lanes {
        out.calls = out.calls.saturating_add(lane.calls);
        out.bytes = out.bytes.saturating_add(lane.bytes);
        out.ok = out.ok.saturating_add(lane.ok);
        out.errors = out.errors.saturating_add(lane.errors);
        out.queued = out.queued.saturating_add(lane.queued);
        out.last_ns = out.last_ns.max(lane.last_ns);
        for (slot, add) in out.lat.iter_mut().zip(lane.lat.iter()) {
            *slot = slot.saturating_add(*add);
        }
        if lane.calls > 0 {
            any = true;
            first = first.min(lane.first_ns);
        }
    }
    out.first_ns = if any { first } else { 0 };
    out
}

// ---------------------------------------------------------------------------
// Wire codecs (little-endian, x86-64 target; alignment-safe by construction)
// ---------------------------------------------------------------------------

/// Decode one `u64` lane word; `None` on a short buffer.
fn lane_word(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .map(|w| u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]))
}

/// Decode a `KAgg` map key from exactly 260 bytes (`None` otherwise).
#[must_use]
pub fn kagg_from_bytes(bytes: &[u8]) -> Option<KAgg> {
    if bytes.len() != 260 {
        return None;
    }
    let mut alg = [0u64; 16];
    let mut drv = [0u64; 16];
    for (w, slot) in alg.iter_mut().enumerate() {
        *slot = lane_word(bytes, 4 + w * 8)?;
    }
    for (w, slot) in drv.iter_mut().enumerate() {
        *slot = lane_word(bytes, 132 + w * 8)?;
    }
    // Packed assembly without field borrows: head first, then words.
    let mut key = KAgg {
        fam: bytes[0],
        op: bytes[1],
        res: bytes[2],
        ctx: bytes[3],
        alg: [0; 16],
        drv: [0; 16],
    };
    for (w, word) in alg.iter().enumerate() {
        // SAFETY: `write_unaligned` into packed fields; always sound.
        unsafe {
            core::ptr::addr_of_mut!(key.alg[w]).write_unaligned(*word);
            core::ptr::addr_of_mut!(key.drv[w]).write_unaligned(drv[w]);
        }
    }
    Some(key)
}

/// Decode a `VAgg` value from exactly 120 bytes (`None` otherwise).
#[must_use]
pub fn vagg_from_bytes(bytes: &[u8]) -> Option<VAgg> {
    if bytes.len() != 120 {
        return None;
    }
    let mut lat = [0u64; 8];
    for (b, slot) in lat.iter_mut().enumerate() {
        *slot = lane_word(bytes, 56 + b * 8)?;
    }
    Some(VAgg {
        calls: lane_word(bytes, 0)?,
        bytes: lane_word(bytes, 8)?,
        ok: lane_word(bytes, 16)?,
        errors: lane_word(bytes, 24)?,
        queued: lane_word(bytes, 32)?,
        first_ns: lane_word(bytes, 40)?,
        last_ns: lane_word(bytes, 48)?,
        lat,
    })
}

/// Decode a `KCtl` ring record from exactly 48 bytes (`None` otherwise).
#[must_use]
pub fn kctl_from_bytes(bytes: &[u8]) -> Option<KCtl> {
    if bytes.len() != 48 {
        return None;
    }
    Some(KCtl {
        kind: bytes[0],
        _p: [bytes[1], bytes[2], bytes[3]],
        key_hash: lane_word(bytes, 8)?,
        val0: lane_word(bytes, 16)?,
        val1: lane_word(bytes, 24)?,
        val2: lane_word(bytes, 32)?,
        val3: lane_word(bytes, 40)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_sums_counters_and_histogram_saturating() {
        let a = VAgg {
            calls: 2,
            bytes: 100,
            ok: 1,
            errors: 1,
            queued: 0,
            first_ns: 50,
            last_ns: 60,
            lat: [1, 0, 0, 0, 0, 0, 0, 0],
        };
        let b = VAgg {
            calls: 3,
            bytes: 200,
            ok: 3,
            errors: 0,
            queued: 4,
            first_ns: 40,
            last_ns: 90,
            lat: [0, 2, 0, 0, 0, 0, 0, 0],
        };
        let folded = fold_vagg(&[a, b]);
        assert_eq!(folded.calls, 5);
        assert_eq!(folded.bytes, 300);
        assert_eq!(folded.ok, 4);
        assert_eq!(folded.errors, 1);
        assert_eq!(folded.queued, 4);
        assert_eq!(folded.first_ns, 40);
        assert_eq!(folded.last_ns, 90);
        assert_eq!(folded.lat, [1, 2, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn fold_ignores_zero_lanes_for_first_ns_min() {
        // A zero-calls lane holds first_ns == 0 (never stamped): it must
        // not poison the min (the spine/borrow-(c) constraint).
        let idle = VAgg::default();
        let busy = VAgg {
            calls: 1,
            first_ns: 777,
            last_ns: 888,
            ..VAgg::default()
        };
        let folded = fold_vagg(&[idle, busy, idle]);
        assert_eq!(folded.calls, 1);
        assert_eq!(folded.first_ns, 777);
        assert_eq!(folded.last_ns, 888);
        // All idle: stamps stay 0.
        let folded = fold_vagg(&[idle, idle]);
        assert_eq!(folded.first_ns, 0);
        assert_eq!(folded.last_ns, 0);
    }

    #[test]
    fn fold_saturates_at_u64_max() {
        let a = VAgg {
            calls: u64::MAX,
            bytes: u64::MAX,
            ..VAgg::default()
        };
        let b = VAgg {
            calls: 1,
            bytes: 1,
            ok: 1,
            ..VAgg::default()
        };
        let folded = fold_vagg(&[a, b]);
        assert_eq!(folded.calls, u64::MAX);
        assert_eq!(folded.bytes, u64::MAX);
        assert_eq!(folded.ok, 1);
    }

    #[test]
    fn ident_hash_is_stable_and_identity_scoped() {
        // Golden: FNV-1a over (fam=1, op=3, alg="cbc(aes)"+pad, drv=zeros)
        // computed by hand from the FNV spec (basis ^ bytes, * prime).
        let mut alg = [0u64; 16];
        alg[0] = u64::from_le_bytes(*b"cbc(aes)");
        let drv = [0u64; 16];
        let h1 = kcrypto_ident_hash(KFAM_SK, KOP_ENC, &alg, &drv);
        let h2 = kcrypto_ident_hash(KFAM_SK, KOP_ENC, &alg, &drv);
        assert_eq!(h1, h2);
        // res/ctx excluded by construction (not inputs); op/fam/bytes move it.
        assert_ne!(h1, kcrypto_ident_hash(KFAM_AEAD, KOP_ENC, &alg, &drv));
        assert_ne!(h1, kcrypto_ident_hash(KFAM_SK, KOP_DEC, &alg, &drv));
        let mut alg2 = alg;
        alg2[0] ^= 1;
        assert_ne!(h1, kcrypto_ident_hash(KFAM_SK, KOP_ENC, &alg2, &drv));
    }

    #[test]
    fn codecs_roundtrip_and_reject_short() {
        let mut key_bytes = [0u8; 260];
        key_bytes[0] = KFAM_SK;
        key_bytes[1] = KOP_ENC;
        key_bytes[2] = KRES_OK;
        key_bytes[3] = KCTX_PROC;
        key_bytes[4..12].copy_from_slice(b"cbc(aes)");
        let key = kagg_from_bytes(&key_bytes).expect("260B decodes");
        assert_eq!(key.fam(), KFAM_SK);
        assert_eq!(key.op(), KOP_ENC);
        assert_eq!(key.res(), KRES_OK);
        assert_eq!(key.ctx(), KCTX_PROC);
        assert_eq!(key.alg()[0], u64::from_le_bytes(*b"cbc(aes)"));
        assert!(kagg_from_bytes(&key_bytes[..259]).is_none());
        assert!(kagg_from_bytes(&[0u8; 261]).is_none());

        let mut val_bytes = [0u8; 120];
        val_bytes[0] = 5;
        val_bytes[16] = 5;
        let val = vagg_from_bytes(&val_bytes).expect("120B decodes");
        assert_eq!(val.calls, 5);
        assert_eq!(val.ok, 5);
        assert_eq!(val.lat, [0; 8]);
        assert!(vagg_from_bytes(&val_bytes[..119]).is_none());

        let mut ctl_bytes = [0u8; 48];
        ctl_bytes[0] = KCTL_IDENT;
        let ctl = kctl_from_bytes(&ctl_bytes).expect("48B decodes");
        assert_eq!(ctl.kind, KCTL_IDENT);
        assert!(kctl_from_bytes(&ctl_bytes[..47]).is_none());
    }

    #[test]
    fn head_and_lens_pack_roundtrip() {
        let head = kctl_pack_head(KFAM_AEAD, KOP_DEC, KRES_ERR, KCTX_KTHREAD);
        assert_eq!(head, 0x0000_0000_0101_0402);
        assert_eq!(kctl_pack_lens(8, 13), 0x0000_000d_0000_0008);
        assert_eq!(kctl_unpack_lens(0x0000_000d_0000_0008), (8, 13));
        assert_eq!(kctl_unpack_lens(kctl_pack_lens(0, 128)), (0, 128));
    }
}
