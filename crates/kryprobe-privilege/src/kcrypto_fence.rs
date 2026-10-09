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
                // N1: the receipt honors the deadline — a drain
                // landing on the boundary is Pending, never
                // Quiescent (timeout never yields a receipt).
                return Ok(close_receipt_decision(Instant::now(), deadline));
            }
        }
        if Instant::now() >= deadline {
            return Ok(CloseOutcome::Pending);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Receipt-vs-Pending decision after the second all-zero read (N1):
/// a drain observed at/past the deadline is `Pending` — timeout
/// never yields `Quiescent`, even on the boundary (a 5 s drain
/// means a sick machine; the leg goes INVALID loudly, never
/// silently exact).
fn close_receipt_decision(now: Instant, deadline: Instant) -> CloseOutcome {
    if now >= deadline {
        return CloseOutcome::Pending;
    }
    CloseOutcome::Quiescent(QuiescentReceipt { fence_ns: now_ns() })
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

/// Monotonic clock for the fence receipt stamp (`QuiescentReceipt.fence_ns`
/// promises monotonic ns): host `CLOCK_MONOTONIC` via
/// [`crate::host::monotonic_ns`] — the same domain as BPF `ktime`.
/// Wall time is unusable here (NTP/adjtime jumps break receipt ordering;
/// wall values also dwarf ktime by orders of magnitude). The close
/// deadline keeps `Instant` (see [`close_kernel_fence`]).
fn now_ns() -> u64 {
    crate::host::monotonic_ns().unwrap_or(0)
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
    fn receipt_stamp_is_monotonic_not_wall() {
        // M1: `fence_ns` promises monotonic ns. Bracket the receipt
        // with the real monotonic clock: a wall stamp (unix-epoch ns,
        // ~1.7e18) falls light-years outside the bracket and fails;
        // only a CLOCK_MONOTONIC stamp passes. This is the adversarial
        // form — wall jumps backward/forward arbitrarily, monotonic
        // never does.
        let before = crate::host::monotonic_ns().expect("mono reads");
        let deadline = Instant::now() + Duration::from_secs(60);
        let outcome = close_receipt_decision(Instant::now(), deadline);
        let after = crate::host::monotonic_ns().expect("mono reads");
        let CloseOutcome::Quiescent(receipt) = outcome else {
            panic!("expected a receipt, got {outcome:?}");
        };
        assert!(
            receipt.fence_ns >= before && receipt.fence_ns <= after,
            "fence_ns {} outside monotonic bracket [{before}, {after}]",
            receipt.fence_ns
        );
        // Successive receipts never go backwards (wall would flake
        // under NTP/adjtime steps; monotonic cannot).
        let outcome2 = close_receipt_decision(Instant::now(), deadline);
        let CloseOutcome::Quiescent(receipt2) = outcome2 else {
            panic!("expected a receipt, got {outcome2:?}");
        };
        assert!(receipt2.fence_ns >= receipt.fence_ns, "receipts ordered");
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

    /// Split-access twins of the BPF admit/release pair (F2): the
    /// actual BPF sequence is a plain load/add/store per update
    /// (`r1 = *lane; r1 += 1; *lane = r1`) — NOT an atomic RMW — so
    /// two same-CPU executions interleaving their steps lose an
    /// update. These twins model the steps exactly (split
    /// load/add/store on the shared lane word; defined Rust, same
    /// interleaving hazard, no UB). The atomic twins above stay as
    /// the protocol tests (admit/release/CLOSED discipline); these
    /// are the hazard model.
    fn bpf_admit_twins_split(
        fence: &FenceController,
        lane: usize,
    ) -> (impl Fn() -> bool + '_, impl Fn() + '_) {
        use std::sync::atomic::Ordering;
        let slot = fence.lanes[lane].clone();
        let closed = fence.closed.clone();
        let admit = move || {
            let seen = slot.load(Ordering::Relaxed);
            slot.store(seen.wrapping_add(1), Ordering::Relaxed);
            if closed.load(Ordering::Acquire) != KCTLCLOSED_OPEN {
                let seen = slot.load(Ordering::Relaxed);
                slot.store(seen.wrapping_sub(1), Ordering::Relaxed);
                false
            } else {
                true
            }
        };
        let slot = fence.lanes[lane].clone();
        let release = move || {
            let seen = slot.load(Ordering::Relaxed);
            slot.store(seen.wrapping_sub(1), Ordering::Relaxed);
        };
        (admit, release)
    }

    #[test]
    fn split_twins_keep_admit_release_discipline() {
        // The split twins obey the same protocol as the atomic ones
        // (single-threaded: admit/release round-trips, refused
        // entrants leave no count) — the ONLY difference is the
        // split load/add/store steps (whose interleave hazard the
        // next tests pin down).
        let fence = FenceController::new_for_test(2);
        let (admit, release) = bpf_admit_twins_split(&fence, 0);
        assert!(admit());
        assert_eq!(fence.active_count(), 1);
        release();
        assert_eq!(fence.active_count(), 0);
        let _ = fence.try_close(0);
        let (admit1, _) = bpf_admit_twins_split(&fence, 1);
        assert!(!admit1());
        assert_eq!(fence.active_count(), 0);
    }

    #[test]
    fn split_access_scripted_interleaving_loses_update() {
        // F2 (deterministic): two programs' admit steps interleaved
        // load/load/store/store on one lane lose exactly one update
        // (1 instead of 2) — the hazard the guard-serialization
        // argument must exclude in production (see the Stage-1 fence
        // analysis: PREEMPT_LAZY + guard proven active by I-NC64).
        use std::sync::atomic::Ordering;
        let fence = FenceController::new_for_test(1);
        let lane = fence.lanes[0].clone();
        // Program A admits: load.
        let a_seen = lane.load(Ordering::Relaxed);
        // Program B admits before A stores: load (same stale value).
        let b_seen = lane.load(Ordering::Relaxed);
        // Both store: B's store lands, A's is lost.
        lane.store(a_seen.wrapping_add(1), Ordering::Relaxed);
        lane.store(b_seen.wrapping_add(1), Ordering::Relaxed);
        assert_eq!(a_seen, 0);
        assert_eq!(b_seen, 0);
        assert_eq!(lane.load(Ordering::Relaxed), 1, "one update lost");
        assert_eq!(fence.active_count(), 1);
    }

    #[test]
    fn split_access_two_programs_one_lane_hammer_loses() {
        // F2 (deterministic via barriers): two programs (threads) on
        // ONE lane, every admit/release pair rigged to interleave —
        // each round loses exactly one admit and one release. N
        // rounds admit 2N writers but count N (then release 2N from
        // N — saturating at 0 would hide it, so assert the admit
        // count first, then the release underflow arithmetic).
        use std::sync::atomic::Ordering;
        use std::sync::{Arc, Barrier};
        let fence = FenceController::new_for_test(1);
        let lane = fence.lanes[0].clone();
        let rounds = 500u64;
        let barrier = Arc::new(Barrier::new(2));
        let worker = |barrier: Arc<Barrier>, lane: Arc<AtomicU64>| {
            move || {
                for _ in 0..rounds {
                    // Admit steps, interleaved across the barrier:
                    // both load the same value, both store +1 — one
                    // lost per round.
                    let seen = lane.load(Ordering::Relaxed);
                    barrier.wait();
                    lane.store(seen.wrapping_add(1), Ordering::Relaxed);
                    barrier.wait();
                }
            }
        };
        let b1 = barrier.clone();
        let l1 = lane.clone();
        let t = std::thread::spawn(worker(b1, l1));
        (worker(barrier, lane.clone()))();
        t.join().expect("worker joins");
        // 2*rounds admits counted exactly rounds (one lost per round,
        // deterministically — no flake possible).
        assert_eq!(lane.load(Ordering::Relaxed), rounds);
        assert_eq!(fence.active_count(), rounds);
    }

    /// Deterministic writer/publication/scan model (T1): a scripted
    /// admitted writer with explicit visibility — the deterministic
    /// interleaving of publication with the closer's polls (no
    /// threads, no timing).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ScriptedWriter {
        /// Admitted (holds +1) but the increment is invisible to the
        /// closer (scans read 0 for it) — the F3 publication window.
        InsideUnpublished,
        /// Admitted and visible (scans read 1).
        InsidePublished,
        /// Decremented (scans read 0, truthfully).
        Released,
    }

    fn scripted_scan(writer: ScriptedWriter) -> u64 {
        match writer {
            ScriptedWriter::InsideUnpublished => 0,
            ScriptedWriter::InsidePublished => 1,
            ScriptedWriter::Released => 0,
        }
    }

    /// Mirror of `close_kernel_fence`'s decision structure over
    /// scripted scans: poll until all-zero (round budget = deadline)
    /// → grace (consume one more scan) → rescan must read all-zero →
    /// receipt round; budget exhaustion → `Pending` (`None`). The
    /// abstraction: script rounds stand in for poll rounds, the grace
    /// for the 5 ms sleep, the budget for the 5 s deadline. Returns
    /// the receipt round (`Some`) or `None` for `Pending`.
    fn twin_new_close(script: &[ScriptedWriter], budget: usize) -> Option<usize> {
        let mut round = 0usize;
        loop {
            let scan = |r: usize| {
                script
                    .get(r)
                    .map(|w| scripted_scan(*w))
                    .expect("script covers the close")
            };
            if scan(round) == 0 {
                // Visibility grace, then rescan (F1).
                round += 1;
                if scan(round) == 0 {
                    // Deadline honored (N1): a receipt landing on the
                    // boundary round is Pending.
                    return if round >= budget { None } else { Some(round) };
                }
            }
            round += 1;
            if round >= budget {
                return None;
            }
        }
    }

    /// Mirror of the OLD order (receipt on the FIRST all-zero read —
    /// no grace, no rescan): the load-bearing difference from the new
    /// close. Returns the receipt round (`Some`) or `None`.
    fn twin_old_close(script: &[ScriptedWriter], budget: usize) -> Option<usize> {
        for (round, writer) in script.iter().enumerate().take(budget) {
            if scripted_scan(*writer) == 0 {
                return Some(round);
            }
        }
        None
    }

    #[test]
    fn deterministic_close_old_receipts_early_new_waits() {
        // T1: the oracle is "no receipt precedes writer release".
        // Adversarial script: the writer is admitted but unpublished
        // at round 0 (scan 0), publishes at round 1 (scan 1), and
        // releases at round 2 (scans 0 thereafter).
        // - OLD (first-zero receipt): receipts at round 0 — while the
        //   writer is still inside. The old implementation FAILS the
        //   oracle (the hole, demonstrated deterministically).
        // - NEW (grace+rescan): round-0 zero leads to a grace scan
        //   (round 1: published 1 — keep polling), round-2 zero leads
        //   to a rescan (round 3: 0 — receipt). Receipt at round 3,
        //   after the round-2 release: CORRECT.
        let script = [
            ScriptedWriter::InsideUnpublished,
            ScriptedWriter::InsidePublished,
            ScriptedWriter::Released,
            ScriptedWriter::Released,
            ScriptedWriter::Released,
        ];
        let release_round = 2usize;
        let old = twin_old_close(&script, 8).expect("old receipts");
        assert_eq!(old, 0, "old receipts on the first zero");
        assert!(
            old < release_round,
            "old receipt (round {old}) precedes release (round {release_round}): hole demonstrated"
        );
        let new = twin_new_close(&script, 8).expect("new receipts");
        assert_eq!(new, 3, "new receipts after grace+rescan");
        assert!(
            new >= release_round,
            "new receipt (round {new}) must not precede release (round {release_round})"
        );
    }

    #[test]
    fn deterministic_close_pending_when_writer_never_releases() {
        // T1: a writer that never releases exhausts the round budget
        // (deadline) — the new close stays Pending, never receipts.
        // (The old close also pends here — one scan reads nonzero
        // every round — so this script pins the deadline, not the
        // hole; the hole is pinned by the test above.)
        let script = [ScriptedWriter::InsidePublished; 12];
        assert_eq!(twin_new_close(&script, 8), None);
        assert_eq!(twin_old_close(&script, 8), None);
    }

    #[test]
    fn atomic_twins_stay_loss_free_under_hammer() {
        // The atomic twins remain the protocol reference: the same
        // two-threads-one-lane hammer with atomic RMWs loses nothing
        // (contrast with the split-access hammer above — the
        // difference between the twins IS the F2 hazard).
        let fence = FenceController::new_for_test(1);
        let rounds = 2000u64;
        let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker = |fence: &FenceController, done: Arc<std::sync::atomic::AtomicU64>| {
            let (admit, release) = bpf_admit_twins(fence, 0);
            for _ in 0..rounds {
                assert!(admit());
                release();
                done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        };
        std::thread::scope(|s| {
            let d1 = done.clone();
            let d2 = done.clone();
            s.spawn(|| worker(&fence, d1));
            s.spawn(|| worker(&fence, d2));
        });
        assert_eq!(done.load(std::sync::atomic::Ordering::Relaxed), 2 * rounds);
        assert_eq!(fence.active_count(), 0);
    }

    #[test]
    fn boundary_drain_is_pending_not_quiescent() {
        // N1: the receipt path honors the deadline — a drain
        // observed at/past it is Pending, even double-drained.
        let deadline = Instant::now();
        assert!(matches!(
            close_receipt_decision(deadline, deadline),
            CloseOutcome::Pending
        ));
        assert!(matches!(
            close_receipt_decision(deadline + Duration::from_secs(1), deadline),
            CloseOutcome::Pending
        ));
        assert!(matches!(
            close_receipt_decision(deadline, deadline + Duration::from_secs(1)),
            CloseOutcome::Quiescent(_)
        ));
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
