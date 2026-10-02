// SPDX-License-Identifier: GPL-3.0-or-later
//! Ringbuf drain: mmap/epoll shell over the pure frame walk (T7c2).
//!
//! Layout (libbpf protocol): consumer page `mmap(fd, 0)` holds the u64
//! consumer position at offset 0; `mmap(fd, page)` of
//! `page + 2 * max_entries` holds the u64 producer position at offset 0
//! and the double-mapped data area after one page. Each iteration walks
//! the mapping live ([`area::RingArea::consume_live`], H1): per-record
//! `AtomicU32` Acquire header loads (pairing the kernel's commit
//! `xchg`), no shared reference over live bytes, no snapshot — a bulk
//! copy over concurrently-committed bytes tears (any arch), while the
//! live walk stops on busy and revalidates every header it copies
//! under (a wrap overwrite mid-copy discards, never emits torn).
//!
//! Alignment: ring offsets advance in multiples of 8 by construction
//! (see `frame` tests); record bytes are copied out and parsed
//! field-wise, so `split_header`'s alignment check never applies here.

pub(crate) mod area;
pub mod frame;
mod worker;

use crate::fd::OwnedFd;
use kryprobe_core::DrainConfig;
use kryprobe_core::evidence::SharedLosses;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Receiver;

/// Drained stream item: record bytes or an injected barrier.
#[derive(Debug, PartialEq, Eq)]
pub enum DrainEvent {
    /// One drained ring record's bytes.
    Record(Vec<u8>),
    /// Userspace-injected barrier marker id.
    Barrier(u64),
}

/// End-of-drain counters for the loss ledger.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainStats {
    /// Records walked, including those refused by the bounded queue.
    pub records: u64,
    /// Records dropped on a full drain queue.
    pub queue_drops: u64,
    /// Bytes still unread after the bounded final sweep; never a record count.
    pub backlog_bytes: u64,
    /// The final sweep stopped on a busy or invalid ring frame.
    pub busy: bool,
}

/// Checked worker failure with its known statistics. A panic leaves them
/// unknown (`None`), never a fabricated zero-loss receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainFailure {
    /// Failure observed while polling, forwarding, or joining.
    pub error: DrainError,
    /// Measurements retained before failure, when the worker returned them.
    pub stats: Option<DrainStats>,
}

impl std::fmt::Display for DrainFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; partial drain statistics: {:?}",
            self.error, self.stats
        )
    }
}

impl std::error::Error for DrainFailure {}

impl DrainStats {
    /// Combine both shared-layer observation points into one
    /// [`SharedLosses`](kryprobe_core::evidence::SharedLosses) for the
    /// driver report's shared feed: the drain's own queue drops plus the
    /// BPF-side ringbuf reservation count (`LOSS[0]`, read by the caller
    /// from the `LOSS` map and passed in). Records delivered are not a
    /// loss and stay out. The caller feeds the result once via
    /// `DriverReport::feed_shared_losses`, after the drain stops.
    #[must_use]
    pub fn shared_losses(&self, ring_reservation_failures: u64) -> SharedLosses {
        SharedLosses::new(ring_reservation_failures, self.queue_drops)
    }
}

/// Drain failure: config, mapping, or epoll setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainError {
    /// The OS refused to create the worker thread.
    ThreadSpawnFailed {
        /// OS error detail, without ring data.
        detail: String,
    },
    /// The worker panicked; its final statistics are unavailable.
    WorkerPanicked,
    /// The collector disappeared before forwarding completed.
    CollectorDisconnected,
    /// Drain configuration rejected.
    ConfigInvalid {
        /// Rejection reason.
        reason: String,
    },
    /// Ringbuf mapping failed.
    MmapFailed {
        /// Setup stage that failed.
        stage: String,
        /// Kernel errno.
        errno: i32,
    },
    /// Epoll setup failed.
    EpollFailed {
        /// Setup stage that failed.
        stage: String,
        /// Kernel errno.
        errno: i32,
    },
    /// Sensor-state protocol violation (M1: ADMIT → DRAIN → CLOSED).
    StateInvalid {
        /// Required state for the attempted call.
        expected: &'static str,
        /// State the sensor is actually in.
        actual: &'static str,
    },
}

impl std::fmt::Display for DrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ThreadSpawnFailed { detail } => write!(f, "drain worker spawn: {detail}"),
            Self::WorkerPanicked => write!(f, "drain worker panicked"),
            Self::CollectorDisconnected => write!(f, "drain collector disconnected"),
            Self::ConfigInvalid { reason } => write!(f, "invalid drain config: {reason}"),
            Self::MmapFailed { stage, errno } => {
                write!(f, "ringbuf mmap failed at {stage}: errno {errno}")
            }
            Self::EpollFailed { stage, errno } => {
                write!(f, "epoll setup failed at {stage}: errno {errno}")
            }
            Self::StateInvalid { expected, actual } => {
                write!(
                    f,
                    "sensor state invalid: expected {expected}, sensor is {actual}"
                )
            }
        }
    }
}

impl std::error::Error for DrainError {}

/// Lifetime `DrainThread` spawns in this process (observability + lane
/// tests: one session drain serves any number of windows with a single
/// spawn; per-call drains spawn per snapshot).
static SPAWNS: AtomicU64 = AtomicU64::new(0);

/// Number of successful [`DrainThread::spawn`] calls so far in this process.
#[must_use]
pub fn drain_spawns() -> u64 {
    SPAWNS.load(Ordering::Relaxed)
}

/// Ringbuf drain thread: epoll-paced, budgeted, bounded queue.
#[derive(Debug)]
pub struct DrainThread {
    join: Option<std::thread::JoinHandle<Result<DrainStats, DrainFailure>>>,
    rx: Receiver<DrainEvent>,
    stop: Arc<AtomicBool>,
    barrier: Arc<AtomicU64>,
}

impl DrainThread {
    /// Spawn a drain over `map_fd` (dup'd). `max_entries` must be a power of two.
    pub fn spawn(
        map_fd: &OwnedFd,
        max_entries: u32,
        config: &DrainConfig,
    ) -> Result<Self, DrainError> {
        config.validate().map_err(|err| DrainError::ConfigInvalid {
            reason: err.to_string(),
        })?;
        if !max_entries.is_power_of_two() {
            return Err(DrainError::ConfigInvalid {
                reason: format!("max_entries {max_entries} is not a power of two"),
            });
        }
        // CLOEXEC clone (T16 B11): a plain `dup` would clear the flag
        // and leak this fd through any later exec (cf. `EPOLL_CLOEXEC`
        // below and the discipline in `token::spawn`).
        let owned = map_fd
            .try_clone_cloexec()
            .map_err(|err| DrainError::MmapFailed {
                stage: "dup".to_owned(),
                errno: err.raw_os_error().unwrap_or(libc::EIO),
            })?;
        let area = area::RingArea::map(&owned, max_entries)?;
        let raw_epoll = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if raw_epoll < 0 {
            return Err(DrainError::EpollFailed {
                stage: "create".to_owned(),
                errno: std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            });
        }
        // SAFETY: create returned an open fd; the guard is its sole owner.
        let epoll = unsafe { OwnedFd::from_raw_fd(raw_epoll) };
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0,
        };
        // SAFETY: epoll fd + owned map fd are live; event is a valid pointer.
        let ctl = unsafe {
            libc::epoll_ctl(
                epoll.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                owned.as_raw_fd(),
                &mut event,
            )
        };
        if ctl != 0 {
            return Err(DrainError::EpollFailed {
                stage: "add".to_owned(),
                errno: std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            });
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(config.queue_depth as usize);
        let stop = Arc::new(AtomicBool::new(false));
        let pending: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let worker = worker::Worker {
            _owned: owned,
            area,
            _epoll: epoll,
            tx,
            stop: stop.clone(),
            barrier: pending.clone(),
            budget: config.max_events_per_iter as usize,
            timeout_ms: config.poll_timeout_ms as i32,
        };
        let join = std::thread::Builder::new()
            .name("kryprobe-drain".to_owned())
            .spawn(move || worker.run())
            .map_err(|err| DrainError::ThreadSpawnFailed {
                detail: err.to_string(),
            })?;
        SPAWNS.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            join: Some(join),
            rx,
            stop,
            barrier: pending,
        })
    }

    /// Borrow the event receiver.
    pub fn receiver(&self) -> &Receiver<DrainEvent> {
        &self.rx
    }

    /// Queue a userspace barrier marker into the event stream.
    pub fn inject_barrier(&self, id: u64) {
        self.barrier.store(id.max(1), Ordering::Release);
    }

    /// Signal stop, join the thread, return its counters.
    pub fn stop(self) -> Result<DrainStats, DrainFailure> {
        self.stop_and_drain().0
    }

    /// Signal stop, join the worker, THEN sweep the channel to empty:
    /// records the worker forwarded after the collector's last
    /// `try_recv` (the drain-stop race window) are collected in
    /// channel order, never dropped with the channel. The join
    /// happens-before the sweep, so the tail is complete without any
    /// sleep or retry. Returns the worker counters plus the tail.
    pub fn stop_and_drain(mut self) -> (Result<DrainStats, DrainFailure>, Vec<DrainEvent>) {
        self.stop.store(true, Ordering::Release);
        let stats = match self.join.take() {
            Some(handle) => handle.join().unwrap_or(Err(DrainFailure {
                error: DrainError::WorkerPanicked,
                stats: None,
            })),
            None => Err(DrainFailure {
                error: DrainError::StateInvalid {
                    expected: "running worker",
                    actual: "joined",
                },
                stats: None,
            }),
        };
        let mut tail = Vec::new();
        while let Ok(event) = self.rx.try_recv() {
            tail.push(event);
        }
        (stats, tail)
    }
}

impl Drop for DrainThread {
    /// Backstop only: closes the worker lifetime even on an unwinding caller.
    /// Prefer [`DrainThread::stop`], which joins and returns [`DrainStats`].
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Serializes the process-global epoll assertions (P7-N4):
/// lib tests run in parallel threads, so the exact before/after
/// epoll count below and every test that creates epoll instances
/// ([`worker`](crate::drain::worker) tests) hold this lock — the
/// assertion is unchanged, only scoped against concurrent creators.
#[cfg(test)]
pub(crate) static EPOLL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{DrainEvent, DrainStats, DrainThread, EPOLL_TEST_LOCK, drain_spawns};
    use crate::fd::OwnedFd;
    use kryprobe_core::DrainConfig;
    use kryprobe_core::evidence::SharedLosses;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Live epoll fds in this process (drain-specific leak signal —
    /// measured under [`EPOLL_TEST_LOCK`], so concurrent epoll
    /// creators in this binary cannot skew the exact delta where a
    /// raw fd count would be noise).
    fn epoll_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("fd dir reads")
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                std::fs::read_link(entry.path())
                    .is_ok_and(|target| target.to_string_lossy() == "anon_inode:[eventpoll]")
            })
            .count()
    }

    #[test]
    fn failed_spawn_leaks_no_thread_no_epoll() {
        // M-T4: spawn over a non-map fd fails closed at mmap with no
        // worker thread (spawn counter holds) and no epoll instance
        // left behind, over repeated failures. Holds the epoll
        // serial lock (P7-N4): the before/after count is exact only
        // when no other test thread creates epoll instances inside
        // the window.
        let _epoll = EPOLL_TEST_LOCK.lock().expect("epoll serial");
        let config = DrainConfig {
            max_events_per_iter: 64,
            queue_depth: 16,
            poll_timeout_ms: 10,
        };
        let spawns_before = drain_spawns();
        let epoll_before = epoll_fds();
        for _ in 0..32 {
            // SAFETY: fresh `open` fd, owned by the wrapper from here.
            let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
            assert!(raw >= 0, "null opens");
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            let Err(err) = DrainThread::spawn(&owned, 4096, &config) else {
                panic!("non-map fd must reject");
            };
            assert!(
                matches!(err, super::DrainError::MmapFailed { .. }),
                "fails at mmap, got {err:?}"
            );
        }
        assert_eq!(drain_spawns(), spawns_before, "no worker spawned");
        assert_eq!(epoll_fds(), epoll_before, "no epoll leaked");
    }

    /// P7/T12 drain-stop regression (deterministic, no BPF, no
    /// sleeps): the fake worker forwards records only AFTER
    /// observing stop — the race window a sweep-then-join collector
    /// misses. Join-then-sweep collects all four in order plus the
    /// worker counters. The worker cannot send before stop (it spins
    /// on the flag) and the join happens-before the sweep, so the
    /// outcome is timing-independent.
    #[test]
    fn stop_and_drain_collects_records_sent_after_stop() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<DrainEvent>(16);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let join = std::thread::spawn(move || {
            while !stop_w.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            for i in 0..4u8 {
                tx.try_send(DrainEvent::Record(vec![i]))
                    .expect("bounded tail fits the queue");
            }
            Ok(DrainStats {
                records: 4,
                queue_drops: 0,
                ..DrainStats::default()
            })
        });
        let drain = DrainThread {
            join: Some(join),
            rx,
            stop,
            barrier: Arc::new(AtomicU64::new(0)),
        };
        let (stats, tail) = drain.stop_and_drain();
        let stats = stats.expect("joined worker");
        assert_eq!(stats.records, 4, "worker counters join");
        assert_eq!(stats.queue_drops, 0, "no queue pressure");
        let records: Vec<Vec<u8>> = tail
            .into_iter()
            .filter_map(|event| match event {
                DrainEvent::Record(bytes) => Some(bytes),
                DrainEvent::Barrier(_) => None,
            })
            .collect();
        assert_eq!(
            records,
            vec![vec![0], vec![1], vec![2], vec![3]],
            "in-flight tail collected in order"
        );
    }

    #[test]
    fn drain_stats_combine_with_ring_into_shared_losses() {
        let stats = DrainStats {
            records: 10,
            queue_drops: 5,
            ..DrainStats::default()
        };
        // Records delivered are not a loss; the ring count rides in from
        // the BPF LOSS[0] reader alongside the drain's queue drops.
        assert_eq!(stats.shared_losses(3), SharedLosses::new(3, 5));
        assert_eq!(
            DrainStats::default().shared_losses(0),
            SharedLosses::default()
        );
    }

    #[test]
    fn panicked_worker_keeps_tail_and_refuses_zero_statistics() {
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        let join = std::thread::spawn(move || {
            tx.send(DrainEvent::Record(vec![9]))
                .expect("collector alive");
            panic!("scripted worker panic");
        });
        let drain = DrainThread {
            join: Some(join),
            rx,
            stop: Arc::new(AtomicBool::new(false)),
            barrier: Arc::new(AtomicU64::new(0)),
        };
        let (result, tail) = drain.stop_and_drain();
        assert_eq!(tail, vec![DrainEvent::Record(vec![9])]);
        let failure = result.expect_err("panic cannot produce clean counters");
        assert_eq!(failure.error, super::DrainError::WorkerPanicked);
        assert_eq!(failure.stats, None);
    }

    #[test]
    fn stop_only_identity_and_overflow_tail_reaches_snapshot_decoder_once() {
        use crate::kcrypto_snapshot::{
            ParsedRow, SnapshotRows, append_drain_tail, parse_snapshot_row,
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let join = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            for kind in [
                kryprobe_abi::kcrypto_agg::KCTL_IDENT,
                kryprobe_abi::kcrypto_agg::KCTL_OVERFLOW,
            ] {
                let mut bytes = vec![0; 48];
                bytes[0] = kind;
                tx.send(DrainEvent::Record(bytes)).unwrap();
            }
            Ok(DrainStats {
                records: 2,
                ..Default::default()
            })
        });
        let drain = DrainThread {
            join: Some(join),
            rx,
            stop,
            barrier: Arc::new(AtomicU64::new(0)),
        };
        let (stats, tail) = drain.stop_and_drain();
        assert_eq!(stats.unwrap().records, 2);
        let mut snap = SnapshotRows {
            rows: Vec::new(),
            totals: None,
            idents: Vec::new(),
            overflow_identities: 0,
            drops: 0,
            monotonic_ns: 0,
            lagmax_ns: None,
        };
        append_drain_tail(&mut snap, tail).unwrap();
        let kinds: Vec<_> = snap
            .idents
            .iter()
            .map(|row| match parse_snapshot_row(row.as_bytes()).unwrap() {
                ParsedRow::Ident { kctl } => kctl.kind,
                _ => panic!("identity"),
            })
            .collect();
        assert_eq!(kinds, vec![1, 4]);
        assert_eq!(snap.overflow_identities, 1);
        assert!(
            append_drain_tail(&mut snap, vec![DrainEvent::Record(vec![0; 47])]).is_err(),
            "malformed forwarded tail fails closed"
        );
    }
}
