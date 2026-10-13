// SPDX-License-Identifier: GPL-3.0-or-later
//! Caller-identity snapshot (1A-M10): KWHO walk + joins.

use super::SnapshotError;
use crate::btf_resolve::ConfiguredKcrypto;
use crate::mapops::{MapOpsError, map_get_next_key, map_lookup_bytes, percpu_buffer_len};
use kryprobe_abi::kcrypto_agg::{
    KATTRLOSS_SLOTS, KWhoKey, VParams, VWho, kattrloss_fold, kwho_key_from_bytes, try_fold_vwho,
    vparams_from_bytes, vwho_from_bytes,
};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// K5 attribution snapshot (Task 3; who-row DECODE is Task 4).
// ---------------------------------------------------------------------------

/// One snapshotted caller-identity row: the folded `KWHO` value plus its
/// joins (`KSTACK` frames, first errno, crypto params). Task 4 decodes
/// these into `row="who"` observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoSnapshot {
    /// The `KWHO` key (row hash + tgid).
    pub key: KWhoKey,
    /// The percpu-folded `KWHO` value (calls summed, stamps min/maxed,
    /// insertion-frozen identity from the unique marked lane,
    /// `tid`/`comm` from the latest-writer lane).
    pub val: VWho,
    /// Kernel stack IPs for `val.stack` (truncated at the first zero;
    /// empty when `stack` is negative or the `KSTACK` row is absent).
    pub stack_ips: Vec<u64>,
    /// First nonzero return for `key.kh` (`None` when `KERR` has no row).
    /// Keyed by crypto identity alone: the failure may originate from a
    /// different TGID sharing this `kh` (audit X3, documented trade-off).
    pub first_errno: Option<i32>,
    /// Crypto params for `key.kh` (`None` when `KPARAMS` has no row —
    /// params chase skipped or `alg == 0`).
    pub params: Option<VParams>,
}

/// Fold per-CPU `VWho` lanes into one qualified total (the checked
/// [`try_fold_vwho`](kryprobe_abi::kcrypto_agg::try_fold_vwho)
/// contract for who rows): insertion-frozen identity from the unique
/// marked lane, `tid`/`comm` from the latest writer, `calls` summed
/// checked, stamps min/maxed over busy lanes. `None` refuses missing
/// or conflicting provenance (and saturated `calls`) — callers fail
/// the snapshot loud via `snapshot/who-provenance`, never guess from
/// numeric zeros.
pub(crate) fn fold_vwho(lanes: &[VWho]) -> Option<VWho> {
    try_fold_vwho(lanes)
}

/// Decode one `KSTACK` value (1016B = 127 LE u64 frames, zero-padded)
/// into the frame prefix: truncated at the FIRST zero (frames fill
/// contiguously from index 0, and 0 is never a valid kernel IP).
pub(crate) fn stack_ips_from_bytes(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    for i in 0..bytes.len() / 8 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        let ip = u64::from_le_bytes(word);
        if ip == 0 {
            break;
        }
        out.push(ip);
    }
    out
}

/// Read the `KATTRLOSS` WHO-loss flag as part of the terminal
/// sample: CPU lanes x per-program slots folded with saturation at
/// 255 into the `who_drops` diagnostic (F02/BPF2 — a flag, never an
/// exact lost-call count). Unlike the retired lazy `KIDN` marker, the
/// indication survives a full identity gate. Any lookup failure —
/// including a missing map/slot (`ENOENT`) — refuses loud: a
/// `PerCpuArray` slot always exists on a live map, so absence means a
/// wrong map, never healthy-zero (a short lane buffer likewise
/// refuses with `EBADMSG`).
pub(crate) fn read_kwho_drops(maps: &ConfiguredKcrypto) -> Result<u64, SnapshotError> {
    let (ncpu, value_len) = percpu_buffer_len(8)?;
    let mut values = Vec::with_capacity(ncpu * KATTRLOSS_SLOTS as usize);
    for prog in 0..KATTRLOSS_SLOTS {
        // SAFETY: KATTRLOSS is PerCpuArray<u64> with one slot per
        // program (bpf-kcrypto map def); value_len is ncpu * 8.
        let raw = unsafe {
            map_lookup_bytes(
                &maps.loaded.maps.attr_loss,
                &prog.to_le_bytes(),
                value_len,
                "snapshot/who-drops",
            )
        }?;
        for c in 0..ncpu {
            let lane = raw
                .get(c * 8..(c + 1) * 8)
                .ok_or_else(|| MapOpsError::LookupFailed {
                    stage: "snapshot/who-drops-lane".to_owned(),
                    errno: libc::EBADMSG,
                })?;
            let mut word = [0u8; 8];
            word.copy_from_slice(lane);
            values.push(u64::from_le_bytes(word));
        }
    }
    Ok(kattrloss_fold(&values))
}

/// Joined attribution for one who row: the three map joins
/// (`KSTACK`/`KERR`/`KPARAMS`) factored out so quiescent rows reuse
/// them from [`WhoCache`] instead of re-reading the maps (H4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WhoJoins {
    /// Kernel stack IPs for the row's stack id.
    pub stack_ips: Vec<u64>,
    /// First nonzero return for the row hash.
    pub first_errno: Option<i32>,
    /// Crypto params for the row hash.
    pub params: Option<VParams>,
}

/// Cross-tick who-join cache (H4): one entry per live `(kh, tgid)`
/// key, each pinned to the `(last_ns, stack)` it was joined at. A
/// hit reuses the joins (skips 3 map reads); any advance rejoins. The
/// entry count is bounded by the live `KWHO` key set (≤2048 map
/// entries); dead keys linger until the session ends (bounded, small:
/// ~100B per entry worst case).
///
/// Correctness: a hit requires the folded `last_ns` (max lane write
/// time) AND the stack id to be unchanged. Any new who-event for the
/// key advances `last_ns` (folded max), and all three joins derive
/// from the same events — so a hit implies an unchanged map entry
/// (tgid-recycle safe: recycled tgids with new activity advance the
/// stamp; quiescent keys keep valid joins).
#[derive(Debug, Default)]
pub struct WhoCache {
    entries: HashMap<(u64, u32), (u64, i32, WhoJoins)>,
}

impl WhoCache {
    /// Empty cache (cold: every row rejoins once).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Cached joins for a row stamped `(last_ns, stack)` (`None` =
    /// rejoin: cold key, advanced stamp, or changed stack id).
    #[must_use]
    pub fn lookup(&self, kh: u64, tgid: u32, last_ns: u64, stack: i32) -> Option<WhoJoins> {
        match self.entries.get(&(kh, tgid)) {
            Some((cached_ns, cached_stack, joins))
                if *cached_ns == last_ns && *cached_stack == stack =>
            {
                Some(joins.clone())
            }
            _ => None,
        }
    }

    /// Stores joins for a row stamped `(last_ns, stack)` (overwrites
    /// any previous entry for the key).
    pub fn store(&mut self, kh: u64, tgid: u32, last_ns: u64, stack: i32, joins: WhoJoins) {
        self.entries.insert((kh, tgid), (last_ns, stack, joins));
    }
}

/// Snapshot the K5 attribution maps of a configured sensor: full `KWHO`
/// walk (key iteration + percpu fold) with per-row `KSTACK`/`KERR`/
/// `KPARAMS` joins, plus the `KATTRLOSS` insert-loss flag. Map order.
///
/// Join-miss discipline (fail-soft, never fatal): a negative `stack`
/// (raw helper errno — no `KSTACK` row) or an absent `KSTACK` row yields
/// empty `stack_ips`; an absent `KERR`/`KPARAMS` row yields `None`.
/// `KSTACK` join for one stack id: kernel stack IPs, truncated at
/// the first zero; empty when the id is negative or the row is
/// absent. Other map errors fail loud.
fn join_stack(maps: &ConfiguredKcrypto, stack: i32) -> Result<Vec<u64>, SnapshotError> {
    if stack < 0 {
        return Ok(Vec::new());
    }
    // SAFETY: KSTACK is an aya StackTrace map: the kernel stack
    // value is 127 × u64 = 1016B, always.
    match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.stack,
            &(stack as u32).to_le_bytes(),
            1016,
            "snapshot/who-stack",
        )
    } {
        Ok(raw) => Ok(stack_ips_from_bytes(&raw)),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => Ok(Vec::new()),
        Err(err) => Err(err.into()),
    }
}

/// `KERR` + `KPARAMS` joins for one row hash: first errno + crypto
/// params (`None` each when the row is absent). Other map errors, or
/// a present-but-undecodable value, fail loud.
fn join_err_params(
    maps: &ConfiguredKcrypto,
    kh: u64,
) -> Result<(Option<i32>, Option<VParams>), SnapshotError> {
    // SAFETY: KERR is HashMap<u64, i32>; value_len 4 is exact.
    let first_errno = match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.err,
            &kh.to_le_bytes(),
            4,
            "snapshot/who-err",
        )
    } {
        Ok(raw) => {
            let word: [u8; 4] = raw.try_into().map_err(|_| MapOpsError::LookupFailed {
                stage: "snapshot/who-err".to_owned(),
                errno: libc::EBADMSG,
            })?;
            Some(i32::from_le_bytes(word))
        }
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => None,
        Err(err) => return Err(err.into()),
    };
    // SAFETY: KPARAMS is HashMap<u64, VParams>; VParams is 16B
    // (vparams_from_bytes).
    let params = match unsafe {
        map_lookup_bytes(
            &maps.loaded.maps.params,
            &kh.to_le_bytes(),
            16,
            "snapshot/who-params",
        )
    } {
        Ok(raw) => Some(
            vparams_from_bytes(&raw).ok_or_else(|| MapOpsError::LookupFailed {
                stage: "snapshot/who-params".to_owned(),
                errno: libc::EBADMSG,
            })?,
        ),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => None,
        Err(err) => return Err(err.into()),
    };
    Ok((first_errno, params))
}

/// Structural failures (unverified topology, walk errors, undecodable lanes)
/// fail the whole snapshot as [`SnapshotError::Map`] (a broken
/// post-attach read must be loud, never a silent zero).
pub fn snapshot_who(maps: &ConfiguredKcrypto) -> Result<(Vec<WhoSnapshot>, u64), SnapshotError> {
    snapshot_who_cached(maps, &mut WhoCache::new())
}

/// [`snapshot_who`] with a caller-held join cache (H4): quiescent
/// rows skip all three joins; changed rows join through the
/// within-tick `kh` dedup (same crypto identity across tgids looks
/// up `KERR`/`KPARAMS` once per tick, not once per row). The lane
/// buffer is hoisted out of the row loop (M8: one alloc per snapshot,
/// not per row).
pub fn snapshot_who_cached(
    maps: &ConfiguredKcrypto,
    cache: &mut WhoCache,
) -> Result<(Vec<WhoSnapshot>, u64), SnapshotError> {
    let (ncpu, value_len) = percpu_buffer_len(88)?;
    let mut out = Vec::new();
    let mut lanes: Vec<VWho> = Vec::with_capacity(ncpu);
    let mut tick_err: HashMap<u64, (Option<i32>, Option<VParams>)> = HashMap::new();
    let mut key: Option<Vec<u8>> = None;
    loop {
        // SAFETY: KWHO key is KWhoKey, exactly 16B (bpf-kcrypto map def).
        let next = unsafe {
            map_get_next_key(
                &maps.loaded.maps.who,
                key.as_deref(),
                16,
                "snapshot/who-iter",
            )
        }?;
        let Some(k) = next else { break };
        let who_key = kwho_key_from_bytes(&k).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/who-key".to_owned(),
            errno: libc::EBADMSG,
        })?;
        // SAFETY: KWHO is PerCpuHashMap<KWhoKey, VWho>; VWho is 88B
        // (vwho_from_bytes); ncpu is possible_cpus.
        let raw =
            unsafe { map_lookup_bytes(&maps.loaded.maps.who, &k, value_len, "snapshot/who-val") }?;
        lanes.clear();
        for c in 0..ncpu {
            let lane = raw
                .get(c * 88..(c + 1) * 88)
                .and_then(vwho_from_bytes)
                .ok_or_else(|| MapOpsError::LookupFailed {
                    stage: "snapshot/who-lane".to_owned(),
                    errno: libc::EBADMSG,
                })?;
            lanes.push(lane);
        }
        // Missing/conflicting insertion provenance (or saturated
        // calls) refuses the whole snapshot: a broken post-attach
        // read must be loud, never a silent zero identity.
        let val = fold_vwho(&lanes).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/who-provenance".to_owned(),
            errno: libc::EBADMSG,
        })?;
        let joins = match cache.lookup(who_key.kh, who_key.tgid, val.last_ns, val.stack) {
            Some(joins) => joins,
            None => {
                let stack_ips = join_stack(maps, val.stack)?;
                // `KERR`/`KPARAMS` key on `kh` alone: rows sharing one
                // crypto identity across tgids share these joins
                // within the tick.
                let (first_errno, params) = match tick_err.get(&who_key.kh) {
                    Some(cached) => *cached,
                    None => {
                        let joined = join_err_params(maps, who_key.kh)?;
                        tick_err.insert(who_key.kh, joined);
                        joined
                    }
                };
                let joins = WhoJoins {
                    stack_ips,
                    first_errno,
                    params,
                };
                cache.store(
                    who_key.kh,
                    who_key.tgid,
                    val.last_ns,
                    val.stack,
                    joins.clone(),
                );
                joins
            }
        };
        out.push(WhoSnapshot {
            key: who_key,
            val,
            stack_ips: joins.stack_ips,
            first_errno: joins.first_errno,
            params: joins.params,
        });
        key = Some(k);
    }
    let drops = read_kwho_drops(maps)?;
    Ok((out, drops))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kattrloss_read_refuses_on_unreadable_map() {
        // F02: a missing/unreadable `KATTRLOSS` map refuses measurement
        // (never healthy-zero): bad-fd lookups fail before any byte is
        // read, and the error surfaces typed (topology first when the
        // host topology itself is unreadable).
        let sensor = crate::mapops::topology_tests::sensor();
        let err = read_kwho_drops(&sensor).expect_err("unreadable KATTRLOSS must refuse");
        match err {
            SnapshotError::Map(MapOpsError::LookupFailed { stage, .. }) => assert!(
                stage == "snapshot/who-drops" || stage.starts_with("percpu/"),
                "typed read refusal, got stage {stage:?}"
            ),
            other => panic!("expected a typed map refusal, got {other:?}"),
        }
    }
}
