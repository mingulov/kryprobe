// SPDX-License-Identifier: GPL-3.0-or-later
//! Drain worker thread: epoll pace, budget, bounded queue (T7c2 split).

use super::area::RingArea;
use super::{DrainEvent, DrainStats};
use crate::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};

/// Drain worker: owns the mappings + epoll fd for the thread.
pub(crate) struct Worker {
    pub(crate) _owned: OwnedFd,
    pub(crate) area: RingArea,
    pub(crate) _epoll: OwnedFd,
    pub(crate) tx: SyncSender<DrainEvent>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) barrier: Arc<AtomicU64>,
    pub(crate) budget: usize,
    pub(crate) timeout_ms: i32,
}

impl Worker {
    /// Forwards walked records to the bounded queue (a full queue
    /// counts a drop per record, never blocks). False when the
    /// collector is gone (the walk ends early).
    fn forward(&self, records: Vec<Vec<u8>>, stats: &mut DrainStats) -> bool {
        for record in records {
            stats.records += 1;
            match self.tx.try_send(DrainEvent::Record(record)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => stats.queue_drops += 1,
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        true
    }

    /// Delivers one pending userspace barrier marker, if any (a full
    /// queue re-arms it for the next pass). False when the collector
    /// is gone.
    fn forward_barrier(&self) -> bool {
        let pending = self.barrier.swap(0, Ordering::AcqRel);
        if pending != 0 {
            match self.tx.try_send(DrainEvent::Barrier(pending)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => self.barrier.store(pending, Ordering::Release),
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        true
    }

    pub(crate) fn run(self) -> DrainStats {
        let mut stats = DrainStats::default();
        let mut consumer = self.area.consumer();
        let mut disconnected = false;
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        'run: while !self.stop.load(Ordering::Acquire) {
            // SAFETY: epoll fd live; events buffer valid for one entry.
            unsafe {
                libc::epoll_wait(
                    self._epoll.as_raw_fd(),
                    events.as_mut_ptr(),
                    1,
                    self.timeout_ms,
                )
            };
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            let producer = self.area.producer();
            if producer != consumer {
                // Live walk (H1): per-record volatile reads straight
                // from the mapping — no snapshot, no torn bulk copy.
                let out = self.area.consume_live(consumer, producer, self.budget);
                consumer = out.consumer;
                self.area.set_consumer(consumer);
                if !self.forward(out.records, &mut stats) {
                    disconnected = true;
                    break 'run;
                }
            }
            if !self.forward_barrier() {
                disconnected = true;
                break 'run;
            }
        }
        // Final sweep (P7/T12): one bounded non-blocking pass over
        // records committed but never polled when stop landed —
        // without it the stop-time ring residue vanishes silently
        // (the drain-stop loss window: consumed by nobody, counted
        // nowhere). No epoll wait here: the sweep reads the producer
        // once and walks at most `budget` visits, so stop stays
        // prompt and bounded. Skipped only when the collector is
        // gone (no receiver can take the sweep).
        if !disconnected {
            let producer = self.area.producer();
            if producer != consumer {
                let out = self.area.consume_live(consumer, producer, self.budget);
                self.area.set_consumer(out.consumer);
                self.forward(out.records, &mut stats);
            }
            self.forward_barrier();
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::Worker;
    use crate::drain::DrainEvent;
    use crate::drain::area::RingArea;
    use crate::fd::OwnedFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    /// Test worker over a simulated ring (the fds are never polled:
    /// every test here pre-sets stop, so only the final sweep runs).
    /// Holds the epoll serial lock for the worker's lifetime
    /// (P7-N4): the `drain.rs` exact-count test cannot run while a
    /// worker epoll exists, so parallel lib tests never skew it.
    fn worker_with(
        area: RingArea,
        tx: std::sync::mpsc::SyncSender<DrainEvent>,
        stop: Arc<AtomicBool>,
    ) -> (Worker, std::sync::MutexGuard<'static, ()>) {
        // Serial first (P7-N4): the lock precedes fd creation, so
        // no worker epoll can exist inside the exact-count window.
        let guard = crate::drain::EPOLL_TEST_LOCK.lock().expect("epoll serial");
        // SAFETY: fresh fds, owned by the wrappers from here.
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(null >= 0, "null opens");
        let owned = unsafe { OwnedFd::from_raw_fd(null) };
        let raw_epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(raw_epoll >= 0, "epoll creates");
        let epoll = unsafe { OwnedFd::from_raw_fd(raw_epoll) };
        (
            Worker {
                _owned: owned,
                area,
                _epoll: epoll,
                tx,
                stop,
                barrier: Arc::new(AtomicU64::new(0)),
                budget: 64,
                timeout_ms: 1,
            },
            guard,
        )
    }

    /// P7/T12 drain-stop regression (deterministic, no BPF, no
    /// sleeps): stop pre-set before the first poll with three
    /// committed-but-never-polled records in the ring — the worker
    /// still sweeps them exactly once before returning. Without the
    /// final sweep the loop never runs and all three vanish.
    #[test]
    fn stopped_worker_sweeps_committed_ring_before_return() {
        let area = RingArea::test_area(4096);
        let mut pos = 0u64;
        for i in 0..3u8 {
            pos = area.test_commit(pos, &[i; 8]);
        }
        area.test_set_producer(pos);
        area.set_consumer(0);
        let (tx, rx) = std::sync::mpsc::sync_channel::<DrainEvent>(16);
        let stop = Arc::new(AtomicBool::new(true));
        let (worker, _epoll) = worker_with(area, tx, stop);
        let stats = worker.run();
        assert_eq!(stats.records, 3, "final sweep delivers committed records");
        assert_eq!(stats.queue_drops, 0, "no queue pressure");
        let mut got = Vec::new();
        while let Ok(DrainEvent::Record(bytes)) = rx.try_recv() {
            got.push(bytes);
        }
        assert_eq!(
            got,
            vec![vec![0u8; 8], vec![1u8; 8], vec![2u8; 8]],
            "records delivered exactly once in ring order"
        );
        assert!(
            rx.try_recv().is_err(),
            "no duplicate or phantom fourth record"
        );
    }

    /// Q09 mechanism pin (deterministic, no BPF, no sleeps): a
    /// 1-deep channel, pre-filled — every swept record hits `Full`
    /// and counts `queue_drops` (never blocks, never vanishes
    /// silently). Only the prefill is receivable.
    #[test]
    fn stopped_worker_counts_full_queue_as_drops() {
        let area = RingArea::test_area(4096);
        let mut pos = 0u64;
        for i in 0..2u8 {
            pos = area.test_commit(pos, &[i; 8]);
        }
        area.test_set_producer(pos);
        area.set_consumer(0);
        let (tx, rx) = std::sync::mpsc::sync_channel::<DrainEvent>(1);
        tx.try_send(DrainEvent::Barrier(9)).expect("prefill fits");
        let stop = Arc::new(AtomicBool::new(true));
        let (worker, _epoll) = worker_with(area, tx, stop);
        let stats = worker.run();
        assert_eq!(stats.records, 2, "both records walked");
        assert_eq!(stats.queue_drops, 2, "both counted as queue drops");
        assert!(
            matches!(rx.try_recv(), Ok(DrainEvent::Barrier(9))),
            "only the prefill is receivable"
        );
        assert!(rx.try_recv().is_err(), "swept records never queued");
    }
}
