// SPDX-License-Identifier: GPL-3.0-or-later
//! ctx-v1 context-accounting wire layouts (ADR-0008): userspace mirrors
//! of the Task-02 BPF-side structs.
//!
//! Twin direction (same rule as [`crate::kcrypto_agg`]): the BPF sensor
//! owns the originals; this module mirrors field order, sizes, and enum
//! values. Drift backstops: the layout pins in
//! `crates/kryprobe-abi/tests/ctx_layout.rs` fail on any change, and the
//! Task-02 BPF twin + privileged exactness suite join the backstop when
//! the BPF side lands. Until then this module is the frozen reference
//! the BPF twin must match byte-for-byte.
//!
//! `no_std` (`core`-only): integers are native little-endian on the
//! supported x86-64 target.

/// `KCTX` capacity: context rows (`max_entries = 1024`, ADR-0008 §(c)).
pub const KCTX_MAX_ENTRIES: u32 = 1024;

/// `VCtx` value size in bytes (7 × u64, no `lat`).
pub const VCTX_SIZE: usize = 56;

/// `KCtxKey` size in bytes.
pub const KCTX_KEY_SIZE: usize = 32;

/// Ring kind `KCtl.kind`: `KCTX` insert refused (map full), first per
/// `kh`. The 48-byte ring layout is unchanged; only the kind value is
/// new. Twin to follow in Task 02.
pub const KCTL_CTX_OVERFLOW: u8 = 6;

/// `KCTX_DROPS` value: exact per-CPU refused-insert count (a real u64
/// count, never a saturating flag). `PerCpuArray<u64>` with 1 slot.
pub const KCTX_DROPS_SLOTS: u32 = 1;

/// `KCTLFENCE` control word (M1 control ABI v1, ADR-0008 §(f)): bit 63
/// is `CLOSED`, bits 0..62 are the active-writer count.
pub const KCTLFENCE_CLOSED_BIT: u64 = 1 << 63;
/// Mask for the active-writer count within the fence word.
pub const KCTLFENCE_COUNT_MASK: u64 = (1 << 63) - 1;

/// `KCTX` key: accounting identity (32B, `repr(C)`, align 8, no padding).
///
/// `kh` is [`crate::kcrypto_agg::kh_of`] over the full `KAgg` row;
/// `cgroup`/`start_ns` zero means unreadable (own bucket, never merged).
/// Twin (Task 02): `KCtxKey` in `crates/bpf-kcrypto/src/bin/kcrypto.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct KCtxKey {
    /// Row hash over the full `KAgg` row.
    pub kh: u64,
    /// Event-time cgroup id; 0 = unreadable.
    pub cgroup: u64,
    /// Event-time thread-group id.
    pub tgid: u32,
    /// Event-time uid (low 32).
    pub uid: u32,
    /// Task start time, boot-time ns; 0 = unreadable.
    pub start_ns: u64,
}

impl KCtxKey {
    /// Manually-maintained field list (allowlist tripwire, declaration
    /// order — same deliberate friction as `KConfig::FIELDS`).
    pub const FIELDS: &[&str] = &["kh", "cgroup", "tgid", "uid", "start_ns"];
}

/// Context counters (56B): `KCTX` value.
///
/// Same fold semantics as [`crate::kcrypto_agg::VAgg`] minus the
/// always-zero `lat` histogram (C4: no durations from a single edge).
/// Counters saturate (never wrap); `first_ns` stamps the first SEEN
/// exit edge per CPU lane and `last_ns` the last seen one.
/// Twin (Task 02): `VCtx` in `crates/bpf-kcrypto/src/bin/kcrypto.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct VCtx {
    /// Observations attributed to this row.
    pub calls: u64,
    /// Attributed bytes.
    pub bytes: u64,
    /// Ok-classified observations.
    pub ok: u64,
    /// Error-classified observations.
    pub errors: u64,
    /// Queued-classified observations.
    pub queued: u64,
    /// First-observation time per lane (min-folded; 0 when `calls` is 0).
    pub first_ns: u64,
    /// Last-observation time per lane (max-folded).
    pub last_ns: u64,
}

impl VCtx {
    /// Manually-maintained field list (allowlist tripwire, declaration
    /// order — same deliberate friction as `KConfig::FIELDS`).
    pub const FIELDS: &[&str] = &[
        "calls", "bytes", "ok", "errors", "queued", "first_ns", "last_ns",
    ];
}

/// Per-entry bytes of a full `KCTX` row at `ncpus` possible CPUs:
/// 32B shared key + 56B per lane (ADR-0008 §(b), lower bound before
/// kernel htab overhead).
#[must_use]
pub const fn kctx_entry_bytes(ncpus: u64) -> u64 {
    KCTX_KEY_SIZE as u64 + VCTX_SIZE as u64 * ncpus
}

/// Full-map bytes at `ncpus` possible CPUs (1024 entries).
#[must_use]
pub const fn kctx_map_bytes(ncpus: u64) -> u64 {
    KCTX_MAX_ENTRIES as u64 * kctx_entry_bytes(ncpus)
}

/// Fold per-CPU `VCtx` lanes into one total (same contract as
/// [`crate::kcrypto_agg::fold_vagg`]: saturating sums, min `first_ns`
/// over busy lanes, max `last_ns`, zero stamps when idle).
#[must_use]
pub fn fold_vctx(lanes: &[VCtx]) -> VCtx {
    let mut out = VCtx::default();
    let mut first = u64::MAX;
    let mut any = false;
    for lane in lanes {
        out.calls = out.calls.saturating_add(lane.calls);
        out.bytes = out.bytes.saturating_add(lane.bytes);
        out.ok = out.ok.saturating_add(lane.ok);
        out.errors = out.errors.saturating_add(lane.errors);
        out.queued = out.queued.saturating_add(lane.queued);
        out.last_ns = out.last_ns.max(lane.last_ns);
        if lane.calls > 0 {
            any = true;
            first = first.min(lane.first_ns);
        }
    }
    out.first_ns = if any { first } else { 0 };
    out
}

/// Decode one `u64` lane word; `None` on a short buffer.
fn lane_word(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .map(|w| u64::from_le_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]))
}

/// Decode one `u32` field; `None` on a short buffer.
fn lane_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// Decode a `KCtxKey` map key from exactly 32 bytes (`None` otherwise).
#[must_use]
pub fn kctx_key_from_bytes(bytes: &[u8]) -> Option<KCtxKey> {
    if bytes.len() != KCTX_KEY_SIZE {
        return None;
    }
    Some(KCtxKey {
        kh: lane_word(bytes, 0)?,
        cgroup: lane_word(bytes, 8)?,
        tgid: lane_u32(bytes, 16)?,
        uid: lane_u32(bytes, 20)?,
        start_ns: lane_word(bytes, 24)?,
    })
}

/// Decode a `VCtx` value from exactly 56 bytes (`None` otherwise).
#[must_use]
pub fn vctx_from_bytes(bytes: &[u8]) -> Option<VCtx> {
    if bytes.len() != VCTX_SIZE {
        return None;
    }
    Some(VCtx {
        calls: lane_word(bytes, 0)?,
        bytes: lane_word(bytes, 8)?,
        ok: lane_word(bytes, 16)?,
        errors: lane_word(bytes, 24)?,
        queued: lane_word(bytes, 32)?,
        first_ns: lane_word(bytes, 40)?,
        last_ns: lane_word(bytes, 48)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcrypto_agg::kh_of;

    #[test]
    fn arithmetic_endpoints_match_adr() {
        assert_eq!(kctx_entry_bytes(1), 88);
        assert_eq!(kctx_map_bytes(1), 90_112);
        assert_eq!(kctx_entry_bytes(12), 704);
        assert_eq!(kctx_map_bytes(12), 720_896);
        assert_eq!(kctx_entry_bytes(1024), 57_376);
        assert_eq!(kctx_map_bytes(1024), 58_753_024);
        assert_eq!(kctx_entry_bytes(65_536), 3_670_048);
        assert_eq!(kctx_map_bytes(65_536), 3_758_129_152);
    }

    #[test]
    fn key_codec_round_trips() {
        let key = KCtxKey {
            kh: kh_of(1, 3, 0, 0, &[0; 16], &[0; 16]),
            cgroup: 43812,
            tgid: 1000,
            uid: 1000,
            start_ns: 555,
        };
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&key.kh.to_le_bytes());
        bytes[8..16].copy_from_slice(&key.cgroup.to_le_bytes());
        bytes[16..20].copy_from_slice(&key.tgid.to_le_bytes());
        bytes[20..24].copy_from_slice(&key.uid.to_le_bytes());
        bytes[24..32].copy_from_slice(&key.start_ns.to_le_bytes());
        assert_eq!(kctx_key_from_bytes(&bytes), Some(key));
        assert_eq!(kctx_key_from_bytes(&bytes[..31]), None);
        assert_eq!(vctx_from_bytes(&[0u8; 56]).unwrap().calls, 0);
        assert_eq!(vctx_from_bytes(&[0u8; 55]), None);
    }

    #[test]
    fn fold_skips_idle_lanes_for_first_ns() {
        let busy = VCtx {
            calls: 5,
            first_ns: 100,
            last_ns: 200,
            ..VCtx::default()
        };
        let idle = VCtx::default();
        let folded = fold_vctx(&[idle, busy, idle]);
        assert_eq!(folded.calls, 5);
        assert_eq!(folded.first_ns, 100);
        assert_eq!(folded.last_ns, 200);
        assert_eq!(fold_vctx(&[idle, idle]).first_ns, 0);
    }
}
