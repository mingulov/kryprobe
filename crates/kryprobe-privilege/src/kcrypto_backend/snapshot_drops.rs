// SPDX-License-Identifier: GPL-3.0-or-later
//! Drop accounting (1A-M10): KDROP fold + snapshot, and the
//! shared [`SnapshotError`].

use crate::btf_resolve::ConfiguredKcrypto;
use crate::mapops::{MapOpsError, map_lookup_bytes, percpu_buffer_len};
/// Attribution-snapshot failure: an underlying map walk/read failure
/// (stage + errno preserved). Per-row join misses degrade instead (empty
/// `stack_ips`, `None` errno/params — the snapshot caller rule: unjoined
/// is unknown, never misattributed, never fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Underlying map walk/read failure.
    Map(MapOpsError),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Map(err) => write!(f, "who snapshot: {err}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<MapOpsError> for SnapshotError {
    fn from(err: MapOpsError) -> Self {
        Self::Map(err)
    }
}

/// `KDROPS` site names by index (fix wave, G-C1): the BPF/userspace
/// order contract — index order pins exactly (see
/// `kdrop_site_names_pin_eight`). Sites 0–4 are unexpected loss;
/// `destroy_skip` is C7-expected (always skips, separately keyed);
/// spares are reserved (BPF never writes them).
pub const KDROP_SITES: [&str; 8] = [
    "cfg_fail",
    "fret_fail",
    "arg_null",
    "chase_fail",
    "name_fail",
    "destroy_skip",
    "spare_6",
    "spare_7",
];

/// `KDROPS` index of the destroy C7-expected skip (surfaced, but
/// excluded from loss verdicts — sites below this index are the
/// unexpected-loss set).
pub const KDROP_DESTROY: usize = 5;

/// Fold one `KDROPS` percpu read (`ncpu` LE `u64` lanes) into a site
/// total. `None` on a truncated input slice. This decoder check cannot
/// protect a kernel lookup buffer: its full size must be established
/// before BPF is called. Saturating (never wraps —
/// magnitude honesty at scale).
#[must_use]
pub fn fold_drop_lanes(raw: &[u8], ncpu: usize) -> Option<u64> {
    if raw.len() < 8 * ncpu {
        return None;
    }
    let mut total = 0u64;
    for c in 0..ncpu {
        let mut word = [0u8; 8];
        word.copy_from_slice(&raw[c * 8..(c + 1) * 8]);
        total = total.saturating_add(u64::from_le_bytes(word));
    }
    Some(total)
}

/// Snapshot the `KDROPS` pre-`KTOT` drop sites of a configured sensor:
/// one percpu lookup + fold per site, in [`KDROP_SITES`] order.
/// Structural failures fail the whole snapshot (the
/// [`super::snapshot_who`] discipline: loud, never a silent zero).
pub fn snapshot_drops(sensor: &ConfiguredKcrypto) -> Result<[u64; 8], SnapshotError> {
    let (ncpu, value_len) = percpu_buffer_len(8)?;
    let mut out = [0u64; 8];
    for (site, slot) in out.iter_mut().enumerate() {
        // SAFETY: KDROPS is PerCpuArray<u64> (bpf-kcrypto map def);
        // 8B × possible_cpus matches the kernel's write.
        let raw = unsafe {
            map_lookup_bytes(
                &sensor.loaded.maps.drops,
                &(site as u32).to_le_bytes(),
                value_len,
                "snapshot/drops",
            )
        }?;
        *slot = fold_drop_lanes(&raw, ncpu).ok_or_else(|| MapOpsError::LookupFailed {
            stage: "snapshot/drops-lane".to_owned(),
            errno: libc::EBADMSG,
        })?;
    }
    Ok(out)
}
