// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto snapshot rows: map walk + row codec + ring drain (K2 Task 1).
//!
//! Data foundation for Task 2's backend: [`snapshot_rows`] walks the K1
//! sensor maps (`KAGG` full walk + percpu [`fold_vagg`], `KTOT`,
//! `KIDN[KIDN_DROPS]`, `KRING` drain) and packs everything into
//! versioned snapshot rows; [`parse_snapshot_row`] is the fallible
//! decode entry Task 2's `decode` calls per [`RawEvent`], and the
//! `raw_event_for_*` constructors wrap typed rows into `RawEvent`s with
//! D7 headers.
//!
//! Row wire (D7): `ver:u8` (`0x01`) + `kind:u8` (`1` agg / `2` totals /
//! `3` ident) + body. Agg body = `KAgg` key bytes (260) + folded `VAgg`
//! (120) = 382B; totals body = folded `VAgg` (120) = 122B; ident body =
//! `KCtl` ring record (48) = 50B. Header (D7): `backend_id` 3,
//! `event_kind` observation, `flags` bit0 `status_canonical`, `tgid`/
//! `tid`/`cpu` zero (system-wide aggregates have no single owner —
//! documented-unknown per C10, never fabricated), `monotonic_ns` from
//! the row (`VAgg.last_ns` for agg/totals, `KCtl.val2` first-seen ns
//! for idents).
//!
//! v0.1 limits (documented, Task 2 owns the steady state): live ticks
//! share one session drain ([`session_drain`] +
//! [`snapshot_rows_with_drain`], one barrier window per tick); the
//! one-shot [`snapshot_rows`] wrapper (spawn/stop per call) is retained
//! for single snapshots such as `finalize`. The `KIDN_DROPS` read is validated but
//! not retained ([`SnapshotRows`] carries no drops field — callers pass
//! their own [`map_lookup_bytes`] read to
//! [`shared_losses_from_snapshot`]); drain queue stats are discarded
//! (queue 1024 + concurrent recv: drops are practically impossible at
//! KIDN-gated record counts, and [`shared_losses_from_snapshot`] pins
//! queue 0).
//!
//! Privacy (kp2 S9): snapshot bytes re-encode K1 map/ring bytes only —
//! aggregate counters, algorithm/driver names, and identity hashes. No
//! keys, IVs, plaintext, ciphertext, digests, buffers, or pointers flow
//! through these paths or logs (the K1 canary + tripwire suites stay
//! green and unmodified).
//!
//! No new privileged syscall sites: map access reuses [`crate::mapops`],
//! the ring reuses [`DrainThread`], time is unprivileged `clock_gettime`.

use kryprobe_abi::kcrypto_agg::{
    KAgg, KCTL_IDENT, KCTL_OVERFLOW, KCtl, KIDN_DROPS, VAgg, fold_vagg, kagg_from_bytes,
    kctl_from_bytes, vagg_from_bytes,
};
use kryprobe_abi::{ABI_VERSION, BACKEND_KCRYPTO, EVENT_OBSERVATION, RawEventHeader};
use kryprobe_core::DrainConfig;
use kryprobe_core::backend::RawEvent;
use kryprobe_core::error::{BackendError, InputReason};
use kryprobe_core::evidence::SharedLosses;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use crate::btf_resolve::ConfiguredKcrypto;
use crate::drain::{DrainError, DrainEvent, DrainThread};
use crate::mapops::{MapOpsError, map_get_next_key, map_lookup_bytes, possible_cpus};

/// Snapshot row wire version (D7).
pub const SNAPSHOT_VERSION: u8 = 0x01;
/// Snapshot row kind: aggregate (key + folded value).
pub const ROW_KIND_AGG: u8 = 1;
/// Snapshot row kind: totals (folded value only).
pub const ROW_KIND_TOTALS: u8 = 2;
/// Snapshot row kind: ring identity record.
pub const ROW_KIND_IDENT: u8 = 3;
/// Agg row bytes: ver + kind + `KAgg` (260) + folded `VAgg` (120).
pub const ROW_BYTES_LEN: usize = 382;
/// Totals row bytes: ver + kind + folded `VAgg` (120).
pub const TOTALS_BYTES_LEN: usize = 122;
/// Ident row bytes: ver + kind + `KCtl` (48).
pub const IDENT_BYTES_LEN: usize = 50;

/// Shared exact-length check (1A-M5): the three row newtypes are
/// thin wrappers over this, so the invariant lives in one place.
fn check_len(bytes: &[u8], expect: usize, reason: &'static str) -> Result<(), BackendError> {
    if bytes.len() != expect {
        return Err(BackendError::CorruptInput(InputReason::new(reason)));
    }
    Ok(())
}

/// One `KAGG` snapshot row: exactly 382 bytes (D7). The field is
/// private (1A-M5) — callers read through [`RowBytes::as_bytes`],
/// so post-construction mutation cannot compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowBytes(Vec<u8>);

impl RowBytes {
    /// Wrap exact-length bytes; anything else is [`BackendError::CorruptInput`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, BackendError> {
        check_len(&bytes, ROW_BYTES_LEN, "snapshot_row_len")?;
        Ok(Self(bytes))
    }

    /// Read-only view of the row bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for RowBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// One `KTOT` snapshot row: exactly 122 bytes (D7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotalsBytes(Vec<u8>);

impl TotalsBytes {
    /// Wrap exact-length bytes; anything else is [`BackendError::CorruptInput`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, BackendError> {
        check_len(&bytes, TOTALS_BYTES_LEN, "snapshot_totals_len")?;
        Ok(Self(bytes))
    }

    /// Read-only view of the row bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for TotalsBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// One `KRING` snapshot record: exactly 50 bytes (D7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentBytes(Vec<u8>);

impl IdentBytes {
    /// Wrap exact-length bytes; anything else is [`BackendError::CorruptInput`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, BackendError> {
        check_len(&bytes, IDENT_BYTES_LEN, "snapshot_ident_len")?;
        Ok(Self(bytes))
    }

    /// Read-only view of the record bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for IdentBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// One snapshot pass over a configured kcrypto sensor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRows {
    /// Full `KAGG` walk (key iteration + percpu fold), map order.
    pub rows: Vec<RowBytes>,
    /// `KTOT` row (`None` only if the key reads `ENOENT` — impossible
    /// on the array map, but the shape stays honest).
    pub totals: Option<TotalsBytes>,
    /// `KRING` `IDENT` + `OVERFLOW` records drained since the last call,
    /// ring order.
    pub idents: Vec<IdentBytes>,
    /// `OVERFLOW`-kind records in this drain (healthy: 0).
    pub overflow_identities: u64,
    /// `KIDN[KIDN_DROPS]` at snapshot time (M3: retained, not
    /// discarded — the feed and finalize reuse the closing snapshot's
    /// value instead of re-reading the key at session end).
    pub drops: u8,
    /// Snapshot wall (`CLOCK_MONOTONIC`, taken before the walk).
    pub monotonic_ns: u64,
}

/// Decoded snapshot row.
// By-value decode result, moved once per row: the 380B `Agg` variant is
// the row shape itself (no indirection — Task 2 matches by value).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy)]
pub enum ParsedRow {
    /// Aggregate row: attribution key + folded counters.
    Agg {
        /// Attribution key.
        kagg: KAgg,
        /// Folded counters.
        vagg: VAgg,
    },
    /// Totals row: folded counters.
    Totals {
        /// Folded counters.
        vagg: VAgg,
    },
    /// Ring identity record.
    Ident {
        /// Identity control record.
        kctl: KCtl,
    },
}

// Manual: `KAgg` is packed without `Debug`, so the fields print through
// the sound unaligned accessors (names only — no secret bytes exist on
// this path to leak).
impl std::fmt::Debug for ParsedRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Agg { kagg, vagg } => f
                .debug_struct("Agg")
                .field("fam", &kagg.fam())
                .field("op", &kagg.op())
                .field("res", &kagg.res())
                .field("ctx", &kagg.ctx())
                .field("alg", &kagg.alg())
                .field("drv", &kagg.drv())
                .field("vagg", vagg)
                .finish(),
            Self::Totals { vagg } => f.debug_struct("Totals").field("vagg", vagg).finish(),
            Self::Ident { kctl } => f.debug_struct("Ident").field("kctl", kctl).finish(),
        }
    }
}

/// Fallible snapshot-row decode (Task 2's entry): ver/kind/len checks
/// fail as [`BackendError::CorruptInput`] with pinned reason strings.
/// Check order is version → kind → length.
pub fn parse_snapshot_row(payload: &[u8]) -> Result<ParsedRow, BackendError> {
    let corrupt = |reason: &'static str| BackendError::CorruptInput(InputReason::new(reason));
    // A short buffer has no version/kind to verify: it reports the
    // earliest check it cannot satisfy, never panics.
    if payload.first() != Some(&SNAPSHOT_VERSION) {
        return Err(corrupt("snapshot_version"));
    }
    let Some(kind) = payload.get(1) else {
        return Err(corrupt("snapshot_kind"));
    };
    match *kind {
        ROW_KIND_AGG => {
            if payload.len() != ROW_BYTES_LEN {
                return Err(corrupt("snapshot_row_len"));
            }
            // Exact slices: the decoders only fail on wrong length, so
            // the fallbacks below are unreachable-but-honest.
            let kagg =
                kagg_from_bytes(&payload[2..262]).ok_or_else(|| corrupt("snapshot_row_len"))?;
            let vagg =
                vagg_from_bytes(&payload[262..382]).ok_or_else(|| corrupt("snapshot_row_len"))?;
            Ok(ParsedRow::Agg { kagg, vagg })
        }
        ROW_KIND_TOTALS => {
            if payload.len() != TOTALS_BYTES_LEN {
                return Err(corrupt("snapshot_totals_len"));
            }
            let vagg =
                vagg_from_bytes(&payload[2..122]).ok_or_else(|| corrupt("snapshot_totals_len"))?;
            Ok(ParsedRow::Totals { vagg })
        }
        ROW_KIND_IDENT => {
            if payload.len() != IDENT_BYTES_LEN {
                return Err(corrupt("snapshot_ident_len"));
            }
            let kctl =
                kctl_from_bytes(&payload[2..50]).ok_or_else(|| corrupt("snapshot_ident_len"))?;
            Ok(ParsedRow::Ident { kctl })
        }
        _ => Err(corrupt("snapshot_kind")),
    }
}

/// D7 snapshot header: kcrypto backend, observation kind, `status_canonical`.
fn snapshot_header(payload_len: usize, monotonic_ns: u64) -> RawEventHeader {
    RawEventHeader {
        abi_version: ABI_VERSION,
        backend_id: BACKEND_KCRYPTO,
        event_kind: EVENT_OBSERVATION,
        flags: 0x0001, // bit0: status_canonical (D7).
        total_len: (size_of::<RawEventHeader>() + payload_len) as u32,
        // System-wide aggregates: no single tgid/tid/cpu — zeros are
        // documented-unknown per C10, never fabricated attribution.
        cpu: 0,
        session_cookie: 0,
        monotonic_ns,
        tgid: 0,
        tid: 0,
        process_generation: 0,
        plan_generation: 0,
        reserved: 0,
    }
}

/// Wrap an agg row into a borrowed [`RawEvent`] (infallible: the typed
/// row guarantees exact length, so every lookup below hits; the `0`
/// fallbacks are unreachable-but-panic-free).
pub fn raw_event_for_agg(row: &RowBytes) -> RawEvent<'_> {
    let monotonic_ns = row
        .0
        .get(262..382)
        .and_then(vagg_from_bytes)
        .map(|vagg| vagg.last_ns)
        .unwrap_or(0);
    RawEvent {
        header: snapshot_header(row.0.len(), monotonic_ns),
        payload: &row.0,
    }
}

/// Wrap a totals row into a borrowed [`RawEvent`] (infallible; see
/// [`raw_event_for_agg`]).
pub fn raw_event_for_totals(totals: &TotalsBytes) -> RawEvent<'_> {
    let monotonic_ns = totals
        .0
        .get(2..122)
        .and_then(vagg_from_bytes)
        .map(|vagg| vagg.last_ns)
        .unwrap_or(0);
    RawEvent {
        header: snapshot_header(totals.0.len(), monotonic_ns),
        payload: &totals.0,
    }
}

/// Wrap an ident record into a borrowed [`RawEvent`] (infallible; the
/// stamp is the record's first-seen ns — see [`raw_event_for_agg`]).
pub fn raw_event_for_ident(ident: &IdentBytes) -> RawEvent<'_> {
    let monotonic_ns = ident
        .0
        .get(2..50)
        .and_then(kctl_from_bytes)
        .map(|kctl| kctl.val2)
        .unwrap_or(0);
    RawEvent {
        header: snapshot_header(ident.0.len(), monotonic_ns),
        payload: &ident.0,
    }
}

/// Wrap row bytes into a borrowed [`RawEvent`] with a caller-supplied
/// stamp (H3): the tick loop parses each row once and reuses the
/// parsed stamp instead of re-slicing the payload for the header.
/// Same header shape as the `raw_event_for_*` constructors — only the
/// stamp source differs (parsed, not re-parsed).
pub fn raw_event_stamped(payload: &[u8], monotonic_ns: u64) -> RawEvent<'_> {
    RawEvent {
        header: snapshot_header(payload.len(), monotonic_ns),
        payload,
    }
}

/// Build the shared loss feed from a snapshot plus the caller's own
/// `KIDN[KIDN_DROPS]` read (v0.1: the short-lived drain keeps no queue
/// accounting, so the queue pins 0 — K3 feeds the result once).
#[must_use]
pub fn shared_losses_from_snapshot(_snap: &SnapshotRows, drops: u8) -> SharedLosses {
    SharedLosses::new(u64::from(drops), 0)
}

/// `CLOCK_MONOTONIC` now (unprivileged; the snapshot wall). The
/// syscall lives in [`host::monotonic_ns`](crate::host::monotonic_ns)
/// (single unsafe site); this keeps the snapshot error vocabulary.
fn monotonic_now() -> Result<u64, MapOpsError> {
    crate::host::monotonic_ns().map_err(|err| MapOpsError::LookupFailed {
        stage: "snapshot/clock".to_owned(),
        errno: err.raw_os_error().unwrap_or(libc::EIO),
    })
}

/// Little-endian `VAgg` encode: the exact inverse of [`vagg_from_bytes`]
/// (field order per the struct decl; offsets mirror the decoder).
fn vagg_to_bytes(vagg: &VAgg) -> [u8; 120] {
    let mut out = [0u8; 120];
    let words = [
        vagg.calls,
        vagg.bytes,
        vagg.ok,
        vagg.errors,
        vagg.queued,
        vagg.first_ns,
        vagg.last_ns,
    ];
    for (i, word) in words.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    for (i, bucket) in vagg.lat.iter().enumerate() {
        out[56 + i * 8..64 + i * 8].copy_from_slice(&bucket.to_le_bytes());
    }
    out
}

/// Full `KAGG` walk: key iteration + per-key percpu lookup + [`fold_vagg`].
fn walk_kagg(sensor: &ConfiguredKcrypto) -> Result<Vec<RowBytes>, MapOpsError> {
    let ncpu = possible_cpus() as usize;
    let mut rows = Vec::new();
    // M8: one lane buffer per walk, cleared per row (not one alloc
    // per row per tick).
    let mut lanes: Vec<VAgg> = Vec::with_capacity(ncpu);
    let mut key: Option<Vec<u8>> = None;
    loop {
        // SAFETY: KAGG key is KAgg, exactly 260B (bpf-kcrypto map def).
        let next = unsafe {
            map_get_next_key(
                &sensor.loaded.maps.agg,
                key.as_deref(),
                260,
                "snapshot/kagg-iter",
            )
        }?;
        let Some(k) = next else { break };
        // SAFETY: KAGG is PerCpuHashMap<KAgg, VAgg>; VAgg is 120B
        // (vagg_to_bytes [u8; 120]); ncpu is possible_cpus, and the
        // kernel writes all possible lanes.
        let raw = unsafe {
            map_lookup_bytes(&sensor.loaded.maps.agg, &k, 120 * ncpu, "snapshot/kagg-val")
        }?;
        lanes.clear();
        for c in 0..ncpu {
            let lane = raw
                .get(c * 120..(c + 1) * 120)
                .and_then(vagg_from_bytes)
                .ok_or_else(|| MapOpsError::LookupFailed {
                    stage: "snapshot/kagg-lane".to_owned(),
                    errno: libc::EBADMSG,
                })?;
            lanes.push(lane);
        }
        let folded = fold_vagg(&lanes);
        // Hand bytes → typed: the kernel hands exactly 260 key bytes,
        // so the row assembles to exactly 382 by construction.
        let mut bytes = Vec::with_capacity(ROW_BYTES_LEN);
        bytes.push(SNAPSHOT_VERSION);
        bytes.push(ROW_KIND_AGG);
        bytes.extend_from_slice(&k);
        bytes.extend_from_slice(&vagg_to_bytes(&folded));
        debug_assert_eq!(bytes.len(), ROW_BYTES_LEN);
        rows.push(RowBytes(bytes));
        key = Some(k);
    }
    Ok(rows)
}

/// `KTOT` read + percpu fold (`None` on `ENOENT` only — any other errno
/// fails the snapshot).
fn read_ktot(sensor: &ConfiguredKcrypto) -> Result<Option<TotalsBytes>, MapOpsError> {
    let ncpu = possible_cpus() as usize;
    // SAFETY: KTOT is PerCpuArray<VAgg>; VAgg is 120B
    // (vagg_to_bytes [u8; 120]); ncpu is possible_cpus.
    let raw = match unsafe {
        map_lookup_bytes(
            &sensor.loaded.maps.total,
            &0u32.to_le_bytes(),
            120 * ncpu,
            "snapshot/ktot",
        )
    } {
        Ok(raw) => raw,
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => {
            return Ok(None);
        }
        Err(err) => return Err(err),
    };
    let mut lanes = Vec::with_capacity(ncpu);
    for c in 0..ncpu {
        let lane = raw
            .get(c * 120..(c + 1) * 120)
            .and_then(vagg_from_bytes)
            .ok_or_else(|| MapOpsError::LookupFailed {
                stage: "snapshot/ktot-lane".to_owned(),
                errno: libc::EBADMSG,
            })?;
        lanes.push(lane);
    }
    let mut bytes = Vec::with_capacity(TOTALS_BYTES_LEN);
    bytes.push(SNAPSHOT_VERSION);
    bytes.push(ROW_KIND_TOTALS);
    bytes.extend_from_slice(&vagg_to_bytes(&fold_vagg(&lanes)));
    debug_assert_eq!(bytes.len(), TOTALS_BYTES_LEN);
    Ok(Some(TotalsBytes(bytes)))
}

/// Read `KIDN[KIDN_DROPS]` (the ring-reserve counter) into
/// [`SnapshotRows::drops`]. Absent key = healthy zero; any other errno
/// fails the snapshot (a broken `KIDN` read must be loud, never a
/// silent zero).
fn read_kidn_drops(sensor: &ConfiguredKcrypto) -> Result<u8, MapOpsError> {
    // SAFETY: KIDN is HashMap<u64, u8>; value_len 1 is exact.
    match unsafe {
        map_lookup_bytes(
            &sensor.loaded.maps.ident,
            &KIDN_DROPS.to_le_bytes(),
            1,
            "snapshot/kidn-drops",
        )
    } {
        Ok(value) => Ok(value.first().copied().unwrap_or(0)),
        Err(MapOpsError::LookupFailed { errno, .. }) if errno == libc::ENOENT => Ok(0),
        Err(err) => Err(err),
    }
}

/// `KRING` max entries: the 1MiB ringbuf (`KCRYPTO_MAPS` dims; the K1
/// suites hardcode the same `1 << 20`, and K1 dims are frozen).
const KRING_MAX_ENTRIES: u32 = 1 << 20;

/// Short-lived drain budgets: deep enough that KIDN-gated record counts
/// (at most one `IDENT` + one `OVERFLOW` per identity, 256 identities)
/// can never fill the queue behind a concurrently-draining receiver.
const DRAIN_BUDGET: DrainConfig = DrainConfig {
    max_events_per_iter: 1024,
    queue_depth: 1024,
    poll_timeout_ms: 10,
};

/// Map a drain setup failure onto [`MapOpsError`] (errno preserved, stage
/// names the snapshot ring path — the only error shape [`snapshot_rows`]
/// returns).
fn drain_setup_error(err: DrainError) -> MapOpsError {
    match err {
        DrainError::ConfigInvalid { reason } => MapOpsError::LookupFailed {
            stage: format!("snapshot/ring-config:{reason}"),
            errno: libc::EINVAL,
        },
        DrainError::MmapFailed { stage, errno } => MapOpsError::LookupFailed {
            stage: format!("snapshot/ring-{stage}"),
            errno,
        },
        DrainError::EpollFailed { stage, errno } => MapOpsError::LookupFailed {
            stage: format!("snapshot/ring-{stage}"),
            errno,
        },
    }
}

/// Push one ring record into the ident set: `IDENT`/`OVERFLOW` kinds
/// encode as [`IdentBytes`] (`OVERFLOW` additionally counted); reserved
/// kinds (`GENCHANGE`/`GAP`/`HEALTH`, never emitted — K1 pins) skip
/// forward-compatibly. Non-48B payloads fail loud (BPF/ABI drift).
fn push_ident_record(
    record: Vec<u8>,
    idents: &mut Vec<IdentBytes>,
    overflow_identities: &mut u64,
) -> Result<(), MapOpsError> {
    if record.len() != 48 {
        return Err(MapOpsError::LookupFailed {
            stage: "snapshot/ring-record-len".to_owned(),
            errno: libc::EBADMSG,
        });
    }
    let kctl = kctl_from_bytes(&record).ok_or_else(|| MapOpsError::LookupFailed {
        stage: "snapshot/ring-record-decode".to_owned(),
        errno: libc::EBADMSG,
    })?;
    match kctl.kind {
        KCTL_IDENT | KCTL_OVERFLOW => {
            if kctl.kind == KCTL_OVERFLOW {
                *overflow_identities = overflow_identities.saturating_add(1);
            }
            let mut bytes = Vec::with_capacity(IDENT_BYTES_LEN);
            bytes.push(SNAPSHOT_VERSION);
            bytes.push(ROW_KIND_IDENT);
            bytes.extend_from_slice(&record);
            debug_assert_eq!(bytes.len(), IDENT_BYTES_LEN);
            idents.push(IdentBytes(bytes));
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Collect ring records until the barrier checkpoint, then sweep the
/// post-barrier tail the worker may have pushed before observing stop.
fn collect_until_barrier(
    drain: &DrainThread,
    idents: &mut Vec<IdentBytes>,
    overflow_identities: &mut u64,
) -> Result<(), MapOpsError> {
    loop {
        match drain.receiver().recv_timeout(Duration::from_secs(5)) {
            Ok(DrainEvent::Record(record)) => {
                push_ident_record(record, idents, overflow_identities)?;
            }
            Ok(DrainEvent::Barrier(_)) => {
                while let Ok(DrainEvent::Record(record)) = drain.receiver().try_recv() {
                    push_ident_record(record, idents, overflow_identities)?;
                }
                return Ok(());
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err(MapOpsError::LookupFailed {
                    stage: "snapshot/ring-drain".to_owned(),
                    errno: libc::ETIMEDOUT,
                });
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(MapOpsError::LookupFailed {
                    stage: "snapshot/ring-drain".to_owned(),
                    errno: libc::EPIPE,
                });
            }
        }
    }
}

/// Spawn the session `KRING` drain: one spawn per session, shared by
/// every tick through [`snapshot_rows_with_drain`] (2B-C1 — a per-tick
/// spawn/stop pays thread + ~2MB mmap + epoll + up to 10ms quantum on
/// every tick, making sub-100ms cadence unachievable). Stop it once,
/// after the closing tick, via [`DrainThread::stop`].
pub fn session_drain(sensor: &ConfiguredKcrypto) -> Result<DrainThread, MapOpsError> {
    DrainThread::spawn(&sensor.loaded.maps.ring, KRING_MAX_ENTRIES, &DRAIN_BUDGET)
        .map_err(drain_setup_error)
}

/// Drain one barrier window through a session drain: inject `barrier`,
/// collect records up to it, sweep the in-channel tail.
///
/// Window-attribution note: records the worker pushes after emitting
/// the barrier but before the sweep observe no newer barrier yet, so
/// the sweep attributes them to this window (up to one tick early).
/// Every record is still consumed exactly once — no loss, no
/// duplication — and the per-call tail-race loss below cannot occur
/// while the drain stays open.
fn drain_idents_with(
    drain: &DrainThread,
    barrier: u64,
) -> Result<(Vec<IdentBytes>, u64), MapOpsError> {
    // The worker emits the barrier after the backlog it observed, so
    // records collected before the barrier are exactly this window.
    drain.inject_barrier(barrier);
    let mut idents = Vec::new();
    let mut overflow_identities = 0;
    collect_until_barrier(drain, &mut idents, &mut overflow_identities)?;
    Ok((idents, overflow_identities))
}

/// Drain `KRING` through a short-lived [`DrainThread`] (spawn/stop per
/// call): one-shot wrapper retained for single snapshots such as
/// `finalize`. Live ticks share a [`session_drain`] instead (2B-C1).
/// Drain stats are discarded (see the module docs).
///
/// Tail-race warning (ACCEPTED v0.1 limitation of the one-shot path
/// only): records pushed in the microsecond window between the
/// post-barrier tail sweep (see `collect_until_barrier`) and `stop()`
/// are consumed from the ring but undelivered — lost, not re-readable
/// on a later call. The session path cannot hit this window (the drain
/// stays open across ticks); only session-end records arriving after
/// the closing window are at risk.
///
/// Scope: quiescent-ring runs are unaffected; only sustained
/// new-identity/overflow traffic landing in that microsecond window is
/// at risk. Counts/bytes/totals are unaffected — `KAGG` rows still
/// decode with full identity in-row; only first-seen `EVENT` timing /
/// `OVERFLOW` signals are at risk.
///
/// Caller rule: treat unjoined hashes (ident never seen for a row) as
/// unknown (`coverage_gap`/`unknown`) — never misattribute, crash, or
/// silently drop.
fn drain_idents(sensor: &ConfiguredKcrypto) -> Result<(Vec<IdentBytes>, u64), MapOpsError> {
    let drain = session_drain(sensor)?;
    let result = drain_idents_with(&drain, 1);
    // Always joined (even on collect failure) so the thread never escapes.
    let _stats = drain.stop();
    result
}

/// Snapshot every kcrypto map through a session drain: same walk as
/// [`snapshot_rows`], but the `KRING` window runs on the shared
/// [`DrainThread`] instead of a per-call spawn/stop (2B-C1).
///
/// `barrier` identifies this window on the drain: nonzero, distinct
/// per call within the drain's life (a tick counter satisfies this;
/// the id rides the `Barrier` event for debuggability — collection
/// consumes exactly one barrier per call, so sequential windows never
/// coalesce).
pub fn snapshot_rows_with_drain(
    sensor: &ConfiguredKcrypto,
    drain: &DrainThread,
    barrier: u64,
) -> Result<SnapshotRows, MapOpsError> {
    let monotonic_ns = monotonic_now()?;
    let rows = walk_kagg(sensor)?;
    let totals = read_ktot(sensor)?;
    let drops = read_kidn_drops(sensor)?;
    let (idents, overflow_identities) = drain_idents_with(drain, barrier)?;
    Ok(SnapshotRows {
        rows,
        totals,
        idents,
        overflow_identities,
        drops,
        monotonic_ns,
    })
}

/// Snapshot every kcrypto map of a configured sensor: `KAGG` full walk +
/// percpu fold, `KTOT`, the `KIDN_DROPS` validation read, and a `KRING`
/// drain. Map order for rows, ring order for idents.
///
/// One-shot form (spawn/stop per call): retained for single snapshots
/// such as `finalize`. Live ticks use [`snapshot_rows_with_drain`].
pub fn snapshot_rows(sensor: &ConfiguredKcrypto) -> Result<SnapshotRows, MapOpsError> {
    let monotonic_ns = monotonic_now()?;
    let rows = walk_kagg(sensor)?;
    let totals = read_ktot(sensor)?;
    let drops = read_kidn_drops(sensor)?;
    let (idents, overflow_identities) = drain_idents(sensor)?;
    Ok(SnapshotRows {
        rows,
        totals,
        idents,
        overflow_identities,
        drops,
        monotonic_ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vagg_encode_inverts_decode() {
        let vagg = VAgg {
            calls: 7,
            bytes: 224,
            ok: 6,
            errors: 1,
            queued: 0,
            first_ns: 100,
            last_ns: 200,
            lat: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let bytes = vagg_to_bytes(&vagg);
        assert_eq!(bytes.len(), 120);
        // Spot-check offsets against the decoder's layout.
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 200);
        assert_eq!(u64::from_le_bytes(bytes[112..120].try_into().unwrap()), 8);
        assert_eq!(vagg_from_bytes(&bytes).expect("roundtrip"), vagg);
        assert_eq!(
            vagg_from_bytes(&vagg_to_bytes(&VAgg::default())).expect("zero roundtrip"),
            VAgg::default()
        );
    }

    #[test]
    fn fixed_bytes_reject_wrong_len() {
        // 1A-M5: each newtype enforces its exact length (pins the
        // shared check through the refactor).
        for (len, ok) in [(ROW_BYTES_LEN - 1, false), (ROW_BYTES_LEN, true)] {
            assert_eq!(RowBytes::new(vec![0u8; len]).is_ok(), ok, "row {len}");
        }
        for (len, ok) in [(TOTALS_BYTES_LEN + 1, false), (TOTALS_BYTES_LEN, true)] {
            assert_eq!(TotalsBytes::new(vec![0u8; len]).is_ok(), ok, "totals {len}");
        }
        for (len, ok) in [(0, false), (IDENT_BYTES_LEN, true)] {
            assert_eq!(IdentBytes::new(vec![0u8; len]).is_ok(), ok, "ident {len}");
        }
    }

    #[test]
    fn fixed_bytes_expose_read_only_view() {
        // 1A-M5: callers read through as_bytes/AsRef — the field is
        // private, so post-construction mutation cannot compile.
        let row = RowBytes::new(vec![7u8; ROW_BYTES_LEN]).expect("hand row");
        assert_eq!(row.as_bytes().len(), ROW_BYTES_LEN);
        assert_eq!(row.as_bytes()[0], 7);
        let as_ref: &[u8] = row.as_ref();
        assert_eq!(as_ref.len(), ROW_BYTES_LEN);
    }

    #[test]
    fn monotonic_clock_is_live() {
        let first = monotonic_now().expect("clock reads");
        let second = monotonic_now().expect("clock reads");
        assert!(first > 0, "CLOCK_MONOTONIC is nonzero");
        assert!(second >= first, "CLOCK_MONOTONIC never goes backwards");
    }

    #[test]
    fn stamped_event_matches_parsed_stamp_header() {
        // H3: the stamped constructor carries the same header the
        // parsing constructor derives — only the stamp source differs.
        let vagg = VAgg {
            calls: 7,
            bytes: 224,
            ok: 6,
            errors: 1,
            queued: 0,
            first_ns: 100,
            last_ns: 200,
            lat: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut bytes = vec![SNAPSHOT_VERSION, ROW_KIND_TOTALS];
        bytes.extend_from_slice(&vagg_to_bytes(&vagg));
        let totals = TotalsBytes::new(bytes).expect("hand totals");
        let parsed = raw_event_for_totals(&totals);
        let stamped = raw_event_stamped(&totals.0, 200);
        assert_eq!(stamped.header, parsed.header, "same header shape");
        assert_eq!(stamped.header.monotonic_ns, 200);
        assert_eq!(stamped.payload, parsed.payload);
    }
}
