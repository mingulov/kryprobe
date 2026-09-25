// SPDX-License-Identifier: GPL-3.0-or-later
//! Lifecycle sensor: one owner, one drain, one terminal ledger (T06).
//!
//! [`SensorCore`] is the pure ingest path (ring records → decode →
//! reducer → completed records), unit-tested without privilege.
//! [`LifecycleSensor`] wraps it with the configured kernel sensor and
//! the mmap'd ring; `drain_once` is the single drain. The terminal
//! ledger ([`LifecycleLedger`]) is the single place completed records
//! and loss meet: kernel `LLOSS` counters + decode stats + reducer
//! stats, snapshotted together.

use crate::btf_resolve::{ConfiguredError, ConfiguredPoint};
use crate::drain::DrainError;
use crate::drain::area::RingArea;
use crate::drain::frame::consume_range;
use crate::kcrypto_lifecycle::decode::{DecodeStats, LifecycleDecoder, decode_record};
use crate::kcrypto_lifecycle::profile::{
    LIFECYCLE_MAPS, LifecycleProfile, SessionGuard, acquire_kcrypto_session,
};
use crate::kcrypto_lifecycle::{ConfiguredLifecycle, load_lifecycle_configured};
use crate::mapops::{MapOpsError, map_lookup_percpu_sum};
use kryprobe_abi::kcrypto_lifecycle::{LEDGE_RETURN, LSITE_DEC};
use kryprobe_core::kcrypto::{LifecycleReducer, ReducerStats, RequestRecord};
use std::os::fd::RawFd;

/// Tally slot for a validated raw edge: `[enc-submit, enc-return,
/// dec-submit, dec-return]`. Validated inputs only (`decode_record`
/// guarantees site ∈ {enc, dec} and edge ∈ {submit, return}).
fn edge_slot(site: u16, edge: u8) -> usize {
    let site_idx = u16::from(site == LSITE_DEC);
    let edge_idx = u16::from(edge == LEDGE_RETURN);
    (site_idx * 2 + edge_idx) as usize
}

/// `LRING` size (single source: the profile manifest's frozen dims).
fn ring_max() -> usize {
    LIFECYCLE_MAPS
        .iter()
        .find(|(name, _)| *name == "LRING")
        .map(|(_, dims)| dims.max_entries as usize)
        .expect("manifest carries LRING")
}

/// Terminal ledger: completed records plus every loss class,
/// snapshotted together (the single terminal accounting point).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleLedger {
    /// Completed request records (grounded + truthless-drained).
    pub completed: Vec<RequestRecord>,
    /// Per-hook raw-edge hits `[enc-submit, enc-return, dec-submit,
    /// dec-return]` (the VM gate's "post-GO event per required hook").
    pub edge_hits: [u64; 4],
    /// Decode loss counters.
    pub decode: DecodeStats,
    /// Reducer counters.
    pub reducer: ReducerStats,
    /// Kernel `LLOSS` per-class totals (reserve/disabled/badkey/fret).
    pub kernel_loss: [u64; 4],
    /// Completions dropped from retention past the ledger bound
    /// (explicit loss; a draining reader never drops).
    pub retained_dropped: u64,
}

/// Pure ingest core: decoder + reducer + completed records (no fds,
/// no syscalls — the unit-testable heart of the drain).
#[derive(Debug)]
pub struct SensorCore {
    decoder: LifecycleDecoder,
    reducer: LifecycleReducer,
    completed: Vec<RequestRecord>,
    edge_hits: [u64; 4],
    ledger_capacity: usize,
    retained_dropped: u64,
}

impl SensorCore {
    /// New core with bounded decode + reducer tables and a bounded
    /// completed-retention ledger (design C12: every output queue has
    /// a configured bound — round-1 astra-M7).
    #[must_use]
    pub fn new(decode_capacity: usize, reducer_capacity: usize, ledger_capacity: usize) -> Self {
        Self {
            decoder: LifecycleDecoder::new(decode_capacity),
            reducer: LifecycleReducer::new(reducer_capacity),
            completed: Vec::new(),
            edge_hits: [0; 4],
            ledger_capacity,
            retained_dropped: 0,
        }
    }

    /// Retain completions up to the ledger bound; past the bound the
    /// records are dropped but COUNTED (explicit loss, never silent
    /// growth — a draining reader via [`Self::take_completed`] never
    /// drops).
    fn retain(&mut self, done: impl IntoIterator<Item = RequestRecord>) {
        for record in done {
            if self.completed.len() < self.ledger_capacity {
                self.completed.push(record);
            } else {
                self.retained_dropped += 1;
            }
        }
    }

    /// Drain retained completions (the live tick's read path);
    /// drained records free retention for new ones.
    pub fn take_completed(&mut self) -> Vec<RequestRecord> {
        std::mem::take(&mut self.completed)
    }

    /// Ingest raw ring records: validate once, tally the per-hook hit,
    /// join to edges, apply to the reducer, append completions to the
    /// ledger. Returns the newly completed record count.
    pub fn ingest_records(&mut self, records: &[Vec<u8>]) -> usize {
        let mut newly = 0;
        for record in records {
            let raw = match decode_record(record) {
                Ok(raw) => raw,
                Err(_) => {
                    self.decoder.count_bad_record();
                    continue;
                }
            };
            let slot = edge_slot(raw.site, raw.edge);
            self.edge_hits[slot] += 1;
            for edge in self.decoder.join(raw) {
                let done = self.reducer.apply(edge);
                newly += done.len();
                self.retain(done);
            }
        }
        newly
    }

    /// Drain pending truthless (stop-the-world; see reducer `finish`).
    /// Returns the drained records (also retained per the ledger bound).
    pub fn finish(&mut self, stop_ns: u64) -> Vec<RequestRecord> {
        let done = self.reducer.finish(stop_ns);
        self.retain(done.iter().copied());
        done
    }

    /// Snapshot the terminal ledger with caller-supplied kernel loss
    /// (the sensor shell reads `LLOSS`; tests inject).
    #[must_use]
    pub fn ledger(&self, kernel_loss: [u64; 4]) -> LifecycleLedger {
        LifecycleLedger {
            completed: self.completed.clone(),
            edge_hits: self.edge_hits,
            decode: self.decoder.stats(),
            reducer: self.reducer.stats(),
            kernel_loss,
            retained_dropped: self.retained_dropped,
        }
    }
}

/// One drain's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Raw records consumed from the ring.
    pub records: usize,
    /// Newly completed request records.
    pub completed: usize,
    /// Stopped on a busy/torn record: more may arrive later.
    pub busy: bool,
}

/// Attached lifecycle sensor: the single owner (configured maps,
/// programs, links), the single drain (mmap'd ring + consumer
/// position), and the ingest core feeding the terminal ledger.
pub struct LifecycleSensor {
    configured: ConfiguredLifecycle,
    area: RingArea,
    consumer: u64,
    core: SensorCore,
    session: SessionGuard,
}

impl std::fmt::Debug for LifecycleSensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual (KCryptoBackend idiom): the mmap'd area holds raw
        // mapping pointers that must never render into diagnostics.
        f.debug_struct("LifecycleSensor")
            .field("links", &self.configured.links.len())
            .field("consumer", &self.consumer)
            .field("completed", &self.core.completed.len())
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl LifecycleSensor {
    /// Bring up the sensor: resolve + load + configure + attach every
    /// required edge (see [`load_lifecycle_configured`]), then mmap
    /// the ring. Fails unless the full profile attaches.
    pub fn bring_up(
        object_bytes: &[u8],
        token_fd: Option<RawFd>,
    ) -> Result<(Self, Vec<ConfiguredPoint>), ConfiguredError> {
        // Claim the process share first (no duplicate capture: a live
        // api-returns session refuses this typed). Any later failure
        // drops the local hold (a failed bring-up holds nothing).
        let session =
            acquire_kcrypto_session(LifecycleProfile::RequestLifecycle).map_err(|busy| {
                ConfiguredError::SessionBusy {
                    live: busy.live,
                    want: busy.want,
                }
            })?;
        let (configured, points) = load_lifecycle_configured(object_bytes, token_fd)?;
        let area =
            RingArea::map(&configured.loaded.maps.ring, ring_max() as u32).map_err(|err| {
                ConfiguredError::AttachSetup {
                    detail: format!("lring mmap: {err}"),
                }
            })?;
        Ok((
            Self {
                configured,
                area,
                consumer: 0,
                core: SensorCore::new(4096, 4096, 4096),
                session,
            },
            points,
        ))
    }

    /// Drain once: walk newly produced records (at most `budget`
    /// visits), ingest them, advance the consumer. Pure frame walk +
    /// [`SensorCore::ingest_records`]; the VM canary covers this shell.
    pub fn drain_once(&mut self, budget: usize) -> Result<DrainOutcome, DrainError> {
        let max = ring_max() as u64;
        let producer = self.area.producer();
        let mut buf = vec![0u8; 2 * max as usize];
        self.area.snapshot_into(&mut buf, self.consumer, producer);
        let consumed = consume_range(&buf, max - 1, self.consumer, producer, budget);
        let completed = self.core.ingest_records(&consumed.records);
        self.consumer = consumed.consumer;
        self.area.set_consumer(consumed.consumer);
        Ok(DrainOutcome {
            records: consumed.records.len(),
            completed,
            busy: consumed.busy,
        })
    }

    /// Snapshot the terminal ledger (reads `LLOSS` per-class totals).
    pub fn ledger(&self) -> Result<LifecycleLedger, MapOpsError> {
        let mut kernel_loss = [0u64; 4];
        for (idx, slot) in kernel_loss.iter_mut().enumerate() {
            *slot = map_lookup_percpu_sum(
                &self.configured.loaded.maps.loss,
                idx as u32,
                "lifecycle_sensor/lloss",
            )?;
        }
        Ok(self.core.ledger(kernel_loss))
    }

    /// Drain retained completions (the live tick's read path).
    pub fn take_completed(&mut self) -> Vec<RequestRecord> {
        self.core.take_completed()
    }

    /// Live attach count: one link per required edge (the session
    /// coverage counts this — links exist only for attached points).
    #[must_use]
    pub fn attached_points(&self) -> usize {
        self.configured.links.len()
    }

    /// Drain pending truthless (stop-the-world): the live driver's
    /// final reconciliation (see reducer `finish`).
    pub fn finish(&mut self, stop_ns: u64) -> Vec<RequestRecord> {
        self.core.finish(stop_ns)
    }
}
