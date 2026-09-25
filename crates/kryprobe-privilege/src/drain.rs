// SPDX-License-Identifier: GPL-3.0-or-later
//! Ringbuf drain: mmap/epoll shell over the pure frame walk (T7c2).
//!
//! Layout (libbpf protocol): consumer page `mmap(fd, 0)` holds the u64
//! consumer position at offset 0; `mmap(fd, page)` of
//! `page + 2 * max_entries` holds the u64 producer position at offset 0
//! and the double-mapped data area after one page. Each iteration copies
//! only the pending window into a reusable full-size view and runs the
//! pure [`frame`] walk over it (pending bytes are stable: the kernel
//! appends past `producer` and fails reservations on a full ring
//! instead of wrapping over `consumer`).
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
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DrainStats {
    /// Records delivered.
    pub records: u64,
    /// Records dropped on a full drain queue.
    pub queue_drops: u64,
}

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
}

impl std::fmt::Display for DrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigInvalid { reason } => write!(f, "invalid drain config: {reason}"),
            Self::MmapFailed { stage, errno } => {
                write!(f, "ringbuf mmap failed at {stage}: errno {errno}")
            }
            Self::EpollFailed { stage, errno } => {
                write!(f, "epoll setup failed at {stage}: errno {errno}")
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
    join: Option<std::thread::JoinHandle<DrainStats>>,
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
            mask: u64::from(max_entries) - 1,
        };
        let join = std::thread::spawn(move || worker.run());
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
    pub fn stop(mut self) -> DrainStats {
        self.stop.store(true, Ordering::Release);
        match self.join.take() {
            Some(handle) => handle.join().unwrap_or_default(),
            None => DrainStats::default(),
        }
    }
}

impl Drop for DrainThread {
    /// Backstop only: signals stop without joining, so counters are lost.
    /// Prefer [`DrainThread::stop`], which joins and returns [`DrainStats`].
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{DrainStats, DrainThread, drain_spawns};
    use crate::fd::OwnedFd;
    use kryprobe_core::DrainConfig;
    use kryprobe_core::evidence::SharedLosses;

    /// Live epoll fds in this process (drain-specific leak signal —
    /// no other unprivileged lib test creates epoll instances, so an
    /// exact delta is meaningful where a raw fd count would be noise).
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
        // left behind, over repeated failures.
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

    #[test]
    fn drain_stats_combine_with_ring_into_shared_losses() {
        let stats = DrainStats {
            records: 10,
            queue_drops: 5,
        };
        // Records delivered are not a loss; the ring count rides in from
        // the BPF LOSS[0] reader alongside the drain's queue drops.
        assert_eq!(stats.shared_losses(3), SharedLosses::new(3, 5));
        assert_eq!(
            DrainStats::default().shared_losses(0),
            SharedLosses::default()
        );
    }
}
