// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 writer admission/close fence, userspace side (ADR-0009).
//!
//! A `CLOSED` flag word plus a per-CPU active-writer count. BPF
//! admits at hook entry with increment-then-check (plain per-CPU
//! ops — no BPF atomic RMW exists on this target): increment this
//! CPU's lane, then read `CLOSED`; a closed entrant decrements and
//! refuses without touching data. Userspace closes by setting
//! `CLOSED`, then waits for every lane to drain with a fixed poll
//! bound. See ADR-0009 for the airtightness argument.
//!
//! [`bpf_admit_twins`] are faithful userspace twins of the BPF admit /
//! release pair (same op sequence on the same word shapes):
//! interleaving tests run deterministically here, while the
//! privileged lane proves live drain behavior separately. (No BPF
//! codegen proof is needed for the fence itself: it uses only map
//! lookup/update and plain arithmetic, like every existing counter.)

use crate::bpfloader::KcryptoMaps;
use crate::mapops::{MapOpsError, map_lookup_bytes, map_update_bytes, percpu_buffer_len};
use kryprobe_abi::kcrypto_ctx::{KCTLCLOSED_CLOSED, KCTLCLOSED_OPEN};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Userspace fence controller: close + drain-wait over the shared
/// control words.
///
/// Test instances own heap words; production instances (Task 02
/// loader) drive the `KCTLCLOSED`/`KCTLCOUNT` map fds — same
/// protocol, same word shapes.
#[derive(Debug)]
pub struct FenceController {
    closed: Arc<AtomicU8>,
    lanes: Vec<Arc<AtomicU64>>,
}

/// Outcome of one close attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    /// Drained cleanly: no admitted writer remains on any lane.
    Quiescent(QuiescentReceipt),
    /// Writers still inside (admitted before `CLOSED` landed): no
    /// receipt, no exact accounting from this attempt.
    Pending,
}

/// Proof of a drained fence: the completion bound. Created only by a
/// close that observed every lane at zero after setting `CLOSED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuiescentReceipt {
    /// Completion timestamp (monotonic ns) recorded after the drain.
    pub fence_ns: u64,
}

impl CloseOutcome {
    /// True when writers are still inside: retry or give up, but never
    /// treat the snapshot as exact.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// True only for a drained fence with its receipt.
    #[must_use]
    pub fn is_quiescent_receipt(&self) -> bool {
        matches!(self, Self::Quiescent(_))
    }

    /// True only for a drained fence.
    #[must_use]
    pub fn quiescent(&self) -> bool {
        self.is_quiescent_receipt()
    }

    /// The receipt, or a panic with the caller's message (test/oracle
    /// use; production matches on the enum).
    #[must_use]
    pub fn expect(self, msg: &str) -> QuiescentReceipt {
        match self {
            Self::Quiescent(receipt) => receipt,
            Self::Pending => panic!("{msg}: fence still pending"),
        }
    }
}

impl QuiescentReceipt {
    /// Receipts always affirm quiescence (they cannot be constructed
    /// without a drained close).
    #[must_use]
    pub fn quiescent(&self) -> bool {
        true
    }
}

impl FenceController {
    /// Test controller over fresh zero words (open, no writers) with
    /// `lanes` per-CPU lanes.
    #[must_use]
    pub fn new_for_test(lanes: usize) -> Self {
        Self {
            closed: Arc::new(AtomicU8::new(KCTLCLOSED_OPEN)),
            lanes: (0..lanes).map(|_| Arc::new(AtomicU64::new(0))).collect(),
        }
    }

    /// Attempt close: set `CLOSED` once, then spin up to `polls` times
    /// for every lane to reach zero. At all-zero, record the
    /// completion bound and return the receipt. On exhaustion return
    /// `Pending`: timeout never yields `Quiescent`. `polls == 0`
    /// still sets `CLOSED` (refusing later entrants) but checks once.
    pub fn try_close(&self, polls: u32) -> CloseOutcome {
        self.closed.store(KCTLCLOSED_CLOSED, Ordering::SeqCst);
        for _ in 0..polls {
            if self.all_zero() {
                return CloseOutcome::Quiescent(QuiescentReceipt { fence_ns: now_ns() });
            }
            std::hint::spin_loop();
        }
        if self.all_zero() {
            CloseOutcome::Quiescent(QuiescentReceipt { fence_ns: now_ns() })
        } else {
            CloseOutcome::Pending
        }
    }

    /// True when every lane reads zero.
    fn all_zero(&self) -> bool {
        self.lanes
            .iter()
            .all(|lane| lane.load(Ordering::Acquire) == 0)
    }

    /// Current total active-writer count (saturating sum over lanes).
    #[must_use]
    pub fn active_count(&self) -> u64 {
        self.lanes.iter().fold(0u64, |acc, lane| {
            acc.saturating_add(lane.load(Ordering::Acquire))
        })
    }

    /// Whether `CLOSED` is set.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != KCTLCLOSED_OPEN
    }
}

/// Faithful userspace twins of the BPF admit/release pair on one
/// lane, for deterministic interleaving tests. `admit` performs the
/// BPF entry sequence (increment the lane, then read `CLOSED`;
/// decrement-and-refuse when closed) and reports admission without
/// touching any data map; `release` performs the single epilogue
/// decrement. The closures borrow the controller's shared words.
///
/// Panics when `lane` is out of range (test-only wiring error).
pub fn bpf_admit_twins(
    fence: &FenceController,
    lane: usize,
) -> (impl Fn() -> bool + '_, impl Fn() + '_) {
    let slot = fence.lanes[lane].clone();
    let closed = fence.closed.clone();
    let admit = move || {
        slot.fetch_add(1, Ordering::AcqRel);
        if closed.load(Ordering::Acquire) != KCTLCLOSED_OPEN {
            slot.fetch_sub(1, Ordering::Release);
            false
        } else {
            true
        }
    };
    let slot = fence.lanes[lane].clone();
    let release = move || {
        slot.fetch_sub(1, Ordering::Release);
    };
    (admit, release)
}

/// Open the kernel fence after map creation, before attach: write
/// `CLOSED = 0` explicitly (fresh maps read zero, but the protocol
/// step is explicit — admission is open by construction from the
/// first attach).
pub fn open_kernel_fence(maps: &KcryptoMaps) -> Result<(), MapOpsError> {
    map_update_bytes(
        &maps.ctl_closed,
        &0u32.to_le_bytes(),
        &[KCTLCLOSED_OPEN],
        "fence/open",
    )
}

/// Close the kernel fence: write `CLOSED = 1`, then wait (bounded)
/// for every `KCTLCOUNT` lane to drain to zero. At all-zero, sleep a
/// visibility grace and re-scan: only a second all-zero read records
/// the completion bound and returns the `Quiescent` receipt. On
/// deadline exhaustion return `Pending` (timeout never yields
/// `Quiescent`). Map faults fail loud ([`MapOpsError`]) — a broken
/// control read is structural, never a silent zero.
///
/// Why the grace + rescan (F1): a first all-zero read can race a
/// still-invisible admitted increment (BPF store → other-CPU map-read
/// visibility latency). After the grace any such store is visible,
/// and no NEW admission can start past `CLOSED` (refused entrants
/// touch nothing) — so the second all-zero read proves quiescence.
/// Callers detach links BEFORE calling (see
/// `detach_and_close_fence`): no new invocations can start at all
/// past detach, and the polls drain the stragglers.
pub fn close_kernel_fence(maps: &KcryptoMaps) -> Result<CloseOutcome, MapOpsError> {
    map_update_bytes(
        &maps.ctl_closed,
        &0u32.to_le_bytes(),
        &[KCTLCLOSED_CLOSED],
        "fence/close",
    )?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if kernel_lanes_drained(maps)? {
            // Visibility grace (F1): >100x any store-visibility or
            // detach latency; burns deadline like any other wait.
            std::thread::sleep(Duration::from_millis(5));
            if kernel_lanes_drained(maps)? {
                return Ok(CloseOutcome::Quiescent(QuiescentReceipt {
                    fence_ns: now_ns(),
                }));
            }
        }
        if Instant::now() >= deadline {
            return Ok(CloseOutcome::Pending);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// True when every `KCTLCOUNT` lane reads zero.
fn kernel_lanes_drained(maps: &KcryptoMaps) -> Result<bool, MapOpsError> {
    let (ncpu, value_len) = percpu_buffer_len(8)?;
    // SAFETY: KCTLCOUNT is PerCpuArray<u64>, 1 slot (bpf-kcrypto map
    // def); value_len is ncpu * 8.
    let raw = unsafe {
        map_lookup_bytes(
            &maps.ctl_count,
            &0u32.to_le_bytes(),
            value_len,
            "fence/drain",
        )
    }?;
    for c in 0..ncpu {
        let lane = raw
            .get(c * 8..(c + 1) * 8)
            .ok_or_else(|| MapOpsError::LookupFailed {
                stage: "fence/drain-lane".to_owned(),
                errno: libc::EBADMSG,
            })?;
        let mut word = [0u8; 8];
        word.copy_from_slice(lane);
        if u64::from_le_bytes(word) != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Monotonic clock for the fence-completion bound.
fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Test/close-path clock only (host wall fallback where no boot-time
    // source is plumbed): the bound orders the terminal reads, it is not
    // compared against BPF `ktime` stamps.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_close_is_immediately_quiescent() {
        let fence = FenceController::new_for_test(4);
        let outcome = fence.try_close(0);
        assert!(outcome.is_quiescent_receipt());
        assert!(fence.is_closed());
        assert_eq!(fence.active_count(), 0);
    }

    #[test]
    fn twin_admit_release_round_trips() {
        let fence = FenceController::new_for_test(4);
        let (admit, release) = bpf_admit_twins(&fence, 2);
        assert!(admit());
        assert_eq!(fence.active_count(), 1);
        release();
        assert_eq!(fence.active_count(), 0);
    }

    #[test]
    fn refused_entrant_leaves_no_count() {
        let fence = FenceController::new_for_test(4);
        let _ = fence.try_close(0);
        let (admit, _) = bpf_admit_twins(&fence, 1);
        assert!(!admit());
        assert_eq!(fence.active_count(), 0);
    }

    #[test]
    fn drain_waits_for_every_lane() {
        let fence = FenceController::new_for_test(2);
        let (admit0, release0) = bpf_admit_twins(&fence, 0);
        let (admit1, release1) = bpf_admit_twins(&fence, 1);
        assert!(admit0());
        assert!(admit1());
        assert!(fence.try_close(10).is_pending());
        release0();
        assert!(fence.try_close(10).is_pending(), "lane 1 still busy");
        release1();
        assert!(fence.try_close(10).is_quiescent_receipt());
    }
}
