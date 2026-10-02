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
use kryprobe_abi::kcrypto_ctx::{KCtxKey, VCtx, fold_vctx, kctx_key_from_bytes, vctx_from_bytes};

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
        out.push(CtxSnapshot {
            key: ctx_key,
            val: fold_vctx(&lanes),
        });
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
        total = total.saturating_add(u64::from_le_bytes(word));
    }
    Ok(total)
}

/// Terminal ctx-v1 attribution account from one post-fence read (M1
/// early gate): rows + present sum + exact drops from the `KCTX` walk,
/// the `KTOT` system ledger, and the checked unknown difference. Every
/// field is fail-soft (`None` = unreadable, never a silent zero); the
/// judge recomputes the identity (see [`CtxTerminal`]).
pub fn snapshot_ctx_terminal(maps: &ConfiguredKcrypto) -> crate::kcrypto_snapshot::CtxTerminal {
    use crate::kcrypto_snapshot::{CtxTerminal, ParsedRow, parse_snapshot_row, read_ktot};
    let (rows, present_calls, drops) = match snapshot_ctx(maps) {
        Ok((rows, drops)) => {
            let present = rows
                .iter()
                .fold(0u64, |acc, row| acc.saturating_add(row.val.calls));
            (Some(rows.len() as u64), Some(present), Some(drops))
        }
        Err(_) => (None, None, None),
    };
    let system_calls = read_ktot(maps).ok().flatten().and_then(|totals| {
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
