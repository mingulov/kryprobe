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
    pub(crate) fn run(self) -> DrainStats {
        let mut stats = DrainStats::default();
        let mut consumer = self.area.consumer();
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
                for record in out.records {
                    stats.records += 1;
                    match self.tx.try_send(DrainEvent::Record(record)) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => stats.queue_drops += 1,
                        Err(TrySendError::Disconnected(_)) => break 'run,
                    }
                }
            }
            let pending = self.barrier.swap(0, Ordering::AcqRel);
            if pending != 0 {
                match self.tx.try_send(DrainEvent::Barrier(pending)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => self.barrier.store(pending, Ordering::Release),
                    Err(TrySendError::Disconnected(_)) => break 'run,
                }
            }
        }
        stats
    }
}
