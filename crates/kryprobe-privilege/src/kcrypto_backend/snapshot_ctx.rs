// SPDX-License-Identifier: GPL-3.0-or-later
//! ctx-v1 context snapshot (M1 Task 02): `KCTX` walk + `KCTX_DROPS` fold.
//!
//! Mirrors the [`snapshot_who`](super::snapshot_who) discipline: full
//! map walk, per-CPU lane decode + fold, structural failures loud via
//! [`SnapshotError::Map`](super::SnapshotError). No joins (context
//! rows carry no stack/errno/params references — those stay on the
//! `KWHO` path); the exact refused-insert count folds from
//! `KCTX_DROPS` (absent key reads healthy-zero).

use super::SnapshotError;
use crate::btf_resolve::ConfiguredKcrypto;
use crate::mapops::{MapOpsError, map_get_next_key, map_lookup_bytes, percpu_buffer_len};
use kryprobe_abi::kcrypto_ctx::{
    KCtxKey, VCtx, kctx_key_from_bytes, try_fold_vctx, vctx_from_bytes,
};

/// One snapshotted context row: the folded `KCTX` value for its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtxSnapshot {
    /// The `KCTX` key (row hash + event-time context).
    pub key: KCtxKey,
    /// The percpu-folded `KCTX` value (counters summed, stamps
    /// min/maxed over busy lanes).
    pub val: VCtx,
}

/// Walk `KCTX` and fold every row, plus the exact `KCTX_DROPS` count.
/// Structural failures (unverified topology, walk errors, undecodable
/// lanes) fail the whole snapshot as [`SnapshotError::Map`].
pub fn snapshot_ctx(maps: &ConfiguredKcrypto) -> Result<(Vec<CtxSnapshot>, u64), SnapshotError> {
    let (ncpu, value_len) = percpu_buffer_len(56)?;
    let mut out = Vec::new();
    let mut lanes: Vec<VCtx> = Vec::with_capacity(ncpu);
    let mut key: Option<Vec<u8>> = None;
    loop {
        // SAFETY: KCTX key is KCtxKey, exactly 32B (bpf-kcrypto map def).
        let next = unsafe {
            map_get_next_key(
                &maps.loaded.maps.ctx,
                key.as_deref(),
                32,
                "snapshot/ctx-iter",
            )
        }?;
        let Some(k) = next else { break };
        key = Some(k.clone());
        let ctx_key = kctx_key_from_bytes(&k).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/ctx-key".to_owned(),
            errno: libc::EBADMSG,
        })?;
        // SAFETY: KCTX is PerCpuHashMap<KCtxKey, VCtx>; VCtx is 56B
        // (vctx_from_bytes); ncpu is possible_cpus.
        let raw =
            unsafe { map_lookup_bytes(&maps.loaded.maps.ctx, &k, value_len, "snapshot/ctx-val") }?;
        lanes.clear();
        for c in 0..ncpu {
            let lane = raw
                .get(c * 56..(c + 1) * 56)
                .and_then(vctx_from_bytes)
                .ok_or_else(|| MapOpsError::LookupFailed {
                    stage: "snapshot/ctx-lane".to_owned(),
                    errno: libc::EBADMSG,
                })?;
            lanes.push(lane);
        }
        // F8a: checked lane fold — a saturated per-key row fails
        // the whole snapshot (ADR-0008 §(e): saturation refuses the
        // receipt).
        let val = try_fold_vctx(&lanes).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/ctx-lane-overflow".to_owned(),
            errno: libc::EOVERFLOW,
        })?;
        out.push(CtxSnapshot { key: ctx_key, val });
    }
    let drops = read_kctx_drops(maps)?;
    Ok((out, drops))
}

/// Read the exact `KCTX_DROPS` refused-insert count (folded over
/// lanes). Absent key reads healthy-zero; any other errno fails loud
/// (same rule as the `snapshot_who` tail).
pub(crate) fn read_kctx_drops(maps: &ConfiguredKcrypto) -> Result<u64, SnapshotError> {
    let (ncpu, value_len) = percpu_buffer_len(8)?;
    // SAFETY: KCTX_DROPS is PerCpuArray<u64>, 1 slot (bpf-kcrypto map
    // def); value_len is ncpu * 8.
    let raw = match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.ctx_drops,
            &0u32.to_le_bytes(),
            value_len,
            "snapshot/ctx-drops",
        )
    } {
        Ok(raw) => raw,
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => return Ok(0),
        Err(err) => return Err(err.into()),
    };
    sum_u64_lanes(&raw, ncpu)
}

/// Checked sum of one `u64`-per-lane array slice (F8a): a short
/// buffer fails `EBADMSG` (same as before); a lane-sum overflow
/// fails `EOVERFLOW` (ADR-0008 §(e): saturation refuses the receipt
/// — never a silent wrap).
fn sum_u64_lanes(raw: &[u8], ncpu: usize) -> Result<u64, SnapshotError> {
    let mut total = 0u64;
    for c in 0..ncpu {
        let lane = raw
            .get(c * 8..(c + 1) * 8)
            .ok_or_else(|| MapOpsError::LookupFailed {
                stage: "snapshot/ctx-drops-lane".to_owned(),
                errno: libc::EBADMSG,
            })?;
        let mut word = [0u8; 8];
        word.copy_from_slice(lane);
        total = total.checked_add(u64::from_le_bytes(word)).ok_or_else(|| {
            MapOpsError::LookupFailed {
                stage: "snapshot/ctx-drops-overflow".to_owned(),
                errno: libc::EOVERFLOW,
            }
        })?;
    }
    Ok(total)
}

/// Terminal ctx-v1 attribution account from one post-fence read (M1
/// early gate): rows + present sum + exact drops from the `KCTX` walk,
/// the `KTOT` system ledger, and the checked unknown difference. Every
/// field is fail-soft (`None` = unreadable, never a silent zero); the
/// judge recomputes the identity (see [`CtxTerminal`]).
pub fn snapshot_ctx_terminal(maps: &ConfiguredKcrypto) -> crate::kcrypto_snapshot::CtxTerminal {
    use crate::kcrypto_snapshot::{CtxTerminal, ParsedRow, parse_snapshot_row, read_ktot_checked};
    let (rows, present_calls, drops) = match snapshot_ctx(maps) {
        Ok((rows, drops)) => {
            // F8a: checked present sum — saturation refuses the
            // present operand (=> unknown None => the judge INVALIDs
            // the leg), same fail-soft shape as the checked_sub below.
            let present = sum_present_calls(&rows);
            (Some(rows.len() as u64), present, Some(drops))
        }
        Err(_) => (None, None, None),
    };
    // N5: checked KTOT fold — a saturated system ledger refuses the
    // system operand (EOVERFLOW → None, same fail-soft shape).
    let system_calls = read_ktot_checked(maps).ok().flatten().and_then(|totals| {
        match parse_snapshot_row(totals.as_bytes()) {
            Ok(ParsedRow::Totals { vagg }) => Some(vagg.calls),
            _ => None,
        }
    });
    let unknown_calls = match (system_calls, present_calls) {
        (Some(system), Some(present)) => system.checked_sub(present),
        _ => None,
    };
    CtxTerminal {
        rows,
        present_calls,
        system_calls,
        unknown_calls,
        drops,
    }
}

/// Checked sum of folded per-key `calls` (F8a + N5): `None` on
/// overflow or on an already-saturated input row (ADR-0008 §(e):
/// saturation refuses the receipt operand — never a silent wrap).
fn sum_present_calls(rows: &[CtxSnapshot]) -> Option<u64> {
    rows.iter().try_fold(0u64, |acc, row| {
        // N5: a MAX row is saturated in-BPF (or a saturated fold) —
        // refuse even when the running sum would not overflow.
        if row.val.calls == u64::MAX {
            return None;
        }
        acc.checked_add(row.val.calls)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with_calls(calls: u64) -> CtxSnapshot {
        CtxSnapshot {
            key: KCtxKey::default(),
            val: VCtx {
                calls,
                ..VCtx::default()
            },
        }
    }

    #[test]
    fn present_sum_clean() {
        let rows = vec![snapshot_with_calls(100), snapshot_with_calls(23)];
        assert_eq!(sum_present_calls(&rows), Some(123));
        assert_eq!(sum_present_calls(&[]), Some(0));
    }

    #[test]
    fn present_sum_overflow_refuses() {
        // F8a (M1 review): ADR-0008 §(e) — saturation refuses the
        // receipt operand.
        let rows = vec![snapshot_with_calls(u64::MAX), snapshot_with_calls(1)];
        assert_eq!(sum_present_calls(&rows), None);
    }

    #[test]
    fn present_sum_refuses_already_saturated_row() {
        // N5 (A3 review): a lone MAX row is already saturated —
        // 0+MAX overflowing nothing must still refuse.
        let rows = vec![snapshot_with_calls(u64::MAX)];
        assert_eq!(sum_present_calls(&rows), None);
    }

    #[test]
    fn drops_lanes_clean() {
        let mut raw = vec![0u8; 16];
        raw[0..8].copy_from_slice(&40u64.to_le_bytes());
        raw[8..16].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(sum_u64_lanes(&raw, 2).unwrap(), 42);
    }

    #[test]
    fn drops_lanes_short_buffer_is_ebadmsg() {
        let raw = vec![0u8; 8];
        let err = sum_u64_lanes(&raw, 2).unwrap_err();
        let stage = format!("{err:?}");
        assert!(stage.contains("snapshot/ctx-drops-lane"), "{stage}");
    }

    #[test]
    fn drops_lanes_overflow_is_eoverflow() {
        // F8a (M1 review): ADR-0008 §(e) — saturation refuses the
        // receipt, never a silent wrap.
        let mut raw = vec![0u8; 16];
        raw[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        raw[8..16].copy_from_slice(&1u64.to_le_bytes());
        let err = sum_u64_lanes(&raw, 2).unwrap_err();
        let stage = format!("{err:?}");
        assert!(stage.contains("snapshot/ctx-drops-overflow"), "{stage}");
    }
}
