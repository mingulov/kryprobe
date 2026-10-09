// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded resolver caches (frozen pins ADR-0012 §(d)): positive live
//! bindings, brief negative results, tombstones for ended workloads, pid
//! lifetime stability, refresh throttling, and explicit saturation/error
//! counters. Full maps refuse new inserts (never silent eviction); every
//! refusal is counted. Retained request history is a bounded ring.

use kryprobe_core::workload::{
    MAX_RESOLVER_CACHE_ENTRIES, MAX_RESOLVER_TOMBSTONES, RESOLVER_CACHE_TTL_NS,
    RESOLVER_MIN_REFRESH_INTERVAL_NS, RESOLVER_NEGATIVE_CACHE_TTL_NS,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Local TTL comparison against an explicitly passed pin: expired iff age
/// strictly exceeds the TTL; a backwards clock fails closed as expired.
/// Identical semantics to the frozen helper by construction, with a
/// cross-checked agreement oracle in tests (a Round-2 semantic change
/// trips the oracle instead of silently diverging).
fn entry_expired(observed_ns: u64, now_ns: u64, ttl_ns: u64) -> bool {
    if now_ns < observed_ns {
        return true;
    }
    now_ns - observed_ns > ttl_ns
}

/// Local deadline comparison against an explicitly passed pin: elapsed
/// iff the span strictly exceeds the timeout; a backwards clock fails
/// closed as elapsed. See [`entry_expired`] for the oracle discipline.
pub(crate) fn span_elapsed(start_ns: u64, now_ns: u64, timeout_ns: u64) -> bool {
    if now_ns < start_ns {
        return true;
    }
    now_ns - start_ns > timeout_ns
}

/// Helper-local pin: maximum tracked pid lifetimes (tgid → start-ticks).
pub const MAX_PID_LIFETIME_ENTRIES: usize = 1024;

/// Helper-local pin: maximum retained per-request outcome records.
pub const MAX_RETAINED_OUTCOMES: usize = 32;

/// Generate the saturating `inc_*` counter methods inside the
/// [`HelperCounters`] impl.
macro_rules! counter_inc_methods {
    ($($method:ident => $field:ident;)*) => {
        $(
            #[doc = concat!("Bump `", stringify!($field), "` (saturating).")]
            pub fn $method(&mut self) {
                Self::bump(&mut self.$field, &mut self.saturated);
            }
        )*
    };
}

/// Explicit saturation/error counters. All increments saturate with a
/// sticky flag rather than wrapping; the flag is part of the output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperCounters {
    /// Fresh positive-cache hits.
    pub positive_hits: u64,
    /// Positive-cache misses (absent or expired).
    pub positive_misses: u64,
    /// Fresh negative-cache hits (throttled re-scans).
    pub negative_hits: u64,
    /// Positive inserts accepted.
    pub inserts: u64,
    /// Positive inserts refused: cache full.
    pub insert_refused_full: u64,
    /// Negative inserts accepted.
    pub negative_inserts: u64,
    /// Negative inserts refused: cache full.
    pub negative_refused_full: u64,
    /// Tombstone inserts accepted.
    pub tombstone_inserts: u64,
    /// Tombstone inserts refused: store full.
    pub tombstone_refused_full: u64,
    /// Expired entries evicted on lookup.
    pub expired_evictions: u64,
    /// Pid lifetimes or objects changed under us.
    pub reuse_detected: u64,
    /// Scans skipped by the minimum refresh interval.
    pub refresh_throttled: u64,
    /// Keys left un-upgraded by the resolution deadline.
    pub deadline_trips: u64,
    /// Cgroup scans aborted at the directory budget.
    pub scan_budget_trips: u64,
    /// Symlink components refused during traversal.
    pub symlink_refused: u64,
    /// Permission denials observed.
    pub denied: u64,
    /// Non-host (relative/escaping/cross-device) paths refused.
    pub not_host_path: u64,
    /// Objects vanishing mid-traversal.
    pub gone_during_scan: u64,
    /// Pids whose hint no longer matches the captured cgroup (moved on).
    pub migration_skipped: u64,
    /// Pid lifetime records refused: table full.
    pub pid_lifetime_refused_full: u64,
    /// Whether any counter saturated (sticky).
    pub saturated: bool,
}

impl HelperCounters {
    /// Zeroed counters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            positive_hits: 0,
            positive_misses: 0,
            negative_hits: 0,
            inserts: 0,
            insert_refused_full: 0,
            negative_inserts: 0,
            negative_refused_full: 0,
            tombstone_inserts: 0,
            tombstone_refused_full: 0,
            expired_evictions: 0,
            reuse_detected: 0,
            refresh_throttled: 0,
            deadline_trips: 0,
            scan_budget_trips: 0,
            symlink_refused: 0,
            denied: 0,
            not_host_path: 0,
            gone_during_scan: 0,
            migration_skipped: 0,
            pid_lifetime_refused_full: 0,
            saturated: false,
        }
    }

    /// Saturating bump with sticky overflow flag.
    fn bump(slot: &mut u64, saturated: &mut bool) {
        let (next, overflow) = slot.overflowing_add(1);
        *slot = if overflow { u64::MAX } else { next };
        *saturated |= overflow;
    }

    counter_inc_methods! {
        inc_positive_hits => positive_hits;
        inc_positive_misses => positive_misses;
        inc_negative_hits => negative_hits;
        inc_inserts => inserts;
        inc_insert_refused_full => insert_refused_full;
        inc_negative_inserts => negative_inserts;
        inc_negative_refused_full => negative_refused_full;
        inc_tombstone_inserts => tombstone_inserts;
        inc_tombstone_refused_full => tombstone_refused_full;
        inc_expired_evictions => expired_evictions;
        inc_reuse_detected => reuse_detected;
        inc_refresh_throttled => refresh_throttled;
        inc_deadline_trips => deadline_trips;
        inc_scan_budget_trips => scan_budget_trips;
        inc_symlink_refused => symlink_refused;
        inc_denied => denied;
        inc_not_host_path => not_host_path;
        inc_gone_during_scan => gone_during_scan;
        inc_migration_skipped => migration_skipped;
        inc_pid_lifetime_refused_full => pid_lifetime_refused_full;
    }

    /// Fold a typed host-read failure into its counter. Terminal
    /// per-key outcomes (`GonePid`, `Unsupported`, `Invalid`) carry no
    /// scan counter: they surface as the key's own outcome.
    pub fn note_host_error(&mut self, error: &crate::host_reader::HostReadError) {
        use crate::host_reader::HostReadError as E;
        match error {
            E::GoneDuringScan => self.inc_gone_during_scan(),
            E::DeniedPid { .. } | E::DeniedCgroup { .. } => self.inc_denied(),
            E::NotHostPath => self.inc_not_host_path(),
            E::SymlinkRefused => self.inc_symlink_refused(),
            E::ReuseDetected => self.inc_reuse_detected(),
            E::BudgetExceeded => self.inc_scan_budget_trips(),
            E::GonePid { .. } | E::Unsupported | E::Invalid => {}
        }
    }
}

impl Default for HelperCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// One remembered live binding: the object identity plus when it was
/// observed (boot-ns, for TTL). Remembered liveness bounds re-scans;
/// promotion to `Verified` additionally requires an established workload
/// identity (R3 coherence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveBinding {
    /// Object device.
    pub dev: u64,
    /// Object inode.
    pub ino: u64,
    /// Observation time (boot-ns).
    pub observed_ns: u64,
}

/// One retained request outcome (bounded ring, counts only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeRecord {
    /// Request time (boot-ns).
    pub at_ns: u64,
    /// Verified/asserted associations.
    pub resolved: u64,
    /// Unusable associations.
    pub unresolved: u64,
    /// Refused keys.
    pub refused: u64,
}

/// Pid lifetime stability verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeVerdict {
    /// First observation of this tgid.
    FirstSeen,
    /// Same discriminator as before.
    Stable,
    /// Discriminator changed: the tgid was reused.
    Reused,
}

/// Bounded resolver cache bundle. All clocks are caller-supplied boot-ns
/// (deterministic under test, uptime-derived in production).
#[derive(Debug)]
pub struct ResolverCache {
    positive: HashMap<u64, LiveBinding>,
    negative: HashMap<u64, u64>,
    tombstones: HashMap<u64, u64>,
    pid_lifetimes: HashMap<u32, u64>,
    last_scan_ns: Option<u64>,
    history: VecDeque<OutcomeRecord>,
    counters: HelperCounters,
}

impl ResolverCache {
    /// Empty cache bundle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            positive: HashMap::new(),
            negative: HashMap::new(),
            tombstones: HashMap::new(),
            pid_lifetimes: HashMap::new(),
            last_scan_ns: None,
            history: VecDeque::new(),
            counters: HelperCounters::new(),
        }
    }

    /// Counter bundle (read/write for the resolver/host walk).
    pub fn counters(&mut self) -> &mut HelperCounters {
        &mut self.counters
    }

    /// Fresh live binding, if cached and unexpired. Expired entries evict
    /// on lookup (counted); a backwards clock fails closed as expired.
    pub fn lookup_positive(&mut self, cgroup: u64, now_ns: u64) -> Option<LiveBinding> {
        let Some(entry) = self.positive.get(&cgroup) else {
            self.counters.inc_positive_misses();
            return None;
        };
        let observed = entry.observed_ns;
        if entry_expired(observed, now_ns, RESOLVER_CACHE_TTL_NS) {
            self.positive.remove(&cgroup);
            self.counters.inc_expired_evictions();
            self.counters.inc_positive_misses();
            return None;
        }
        self.counters.inc_positive_hits();
        self.positive.get(&cgroup).copied()
    }

    /// Cache a live binding. A full cache refuses (counted, typed) rather
    /// than evicting; re-inserting a known cgroup refreshes in place.
    pub fn insert_positive(
        &mut self,
        cgroup: u64,
        binding: LiveBinding,
    ) -> Result<(), kryprobe_core::workload::MetadataUnavailable> {
        if !self.positive.contains_key(&cgroup) && self.positive.len() >= MAX_RESOLVER_CACHE_ENTRIES
        {
            self.counters.inc_insert_refused_full();
            return Err(kryprobe_core::workload::MetadataUnavailable::BudgetExceeded);
        }
        self.positive.insert(cgroup, binding);
        self.counters.inc_inserts();
        Ok(())
    }

    /// Whether a fresh negative result covers this cgroup (brief
    /// throttle so short-lived workloads do not cause continuous scans).
    pub fn lookup_negative(&mut self, cgroup: u64, now_ns: u64) -> bool {
        let Some(observed) = self.negative.get(&cgroup).copied() else {
            return false;
        };
        if entry_expired(observed, now_ns, RESOLVER_NEGATIVE_CACHE_TTL_NS) {
            self.negative.remove(&cgroup);
            self.counters.inc_expired_evictions();
            return false;
        }
        self.counters.inc_negative_hits();
        true
    }

    /// Cache a negative result (bounded like the positive cache).
    pub fn insert_negative(
        &mut self,
        cgroup: u64,
        now_ns: u64,
    ) -> Result<(), kryprobe_core::workload::MetadataUnavailable> {
        if !self.negative.contains_key(&cgroup) && self.negative.len() >= MAX_RESOLVER_CACHE_ENTRIES
        {
            self.counters.inc_negative_refused_full();
            return Err(kryprobe_core::workload::MetadataUnavailable::BudgetExceeded);
        }
        // The cache pin also bounds total entries; the guard above keeps
        // the negative map within [`MAX_RESOLVER_CACHE_ENTRIES`].
        debug_assert!(self.negative.len() <= MAX_RESOLVER_CACHE_ENTRIES);
        self.negative.insert(cgroup, now_ns);
        self.counters.inc_negative_inserts();
        Ok(())
    }

    /// Drop a negative entry (after pid reuse forces a re-scan).
    pub fn clear_negative(&mut self, cgroup: u64) {
        self.negative.remove(&cgroup);
    }

    /// Record an ended workload's tombstone (bounded by the frozen
    /// tombstone pin; full stores refuse typed and counted).
    pub fn insert_tombstone(
        &mut self,
        cgroup: u64,
        now_ns: u64,
    ) -> Result<(), kryprobe_core::workload::MetadataUnavailable> {
        if !self.tombstones.contains_key(&cgroup)
            && self.tombstones.len() >= MAX_RESOLVER_TOMBSTONES
        {
            self.counters.inc_tombstone_refused_full();
            return Err(kryprobe_core::workload::MetadataUnavailable::BudgetExceeded);
        }
        debug_assert!(self.tombstones.len() <= MAX_RESOLVER_TOMBSTONES);
        self.tombstones.insert(cgroup, now_ns);
        self.counters.inc_tombstone_inserts();
        Ok(())
    }

    /// Whether a tombstone covers this cgroup (ended workloads stay
    /// visibly ended for one positive TTL).
    pub fn lookup_tombstone(&mut self, cgroup: u64, now_ns: u64) -> bool {
        let Some(ended) = self.tombstones.get(&cgroup).copied() else {
            return false;
        };
        if entry_expired(ended, now_ns, RESOLVER_CACHE_TTL_NS) {
            self.tombstones.remove(&cgroup);
            self.counters.inc_expired_evictions();
            return false;
        }
        true
    }

    /// Note a pid lifetime observation: first sight, stability, or reuse.
    /// A full table records nothing new (counted) rather than evicting.
    pub fn note_pid_lifetime(&mut self, tgid: u32, start_ticks: u64) -> LifetimeVerdict {
        match self.pid_lifetimes.get(&tgid).copied() {
            None => {
                if self.pid_lifetimes.len() >= MAX_PID_LIFETIME_ENTRIES {
                    self.counters.inc_pid_lifetime_refused_full();
                    return LifetimeVerdict::FirstSeen;
                }
                self.pid_lifetimes.insert(tgid, start_ticks);
                LifetimeVerdict::FirstSeen
            }
            Some(previous) if previous == start_ticks => LifetimeVerdict::Stable,
            Some(_) => {
                self.pid_lifetimes.insert(tgid, start_ticks);
                self.counters.inc_reuse_detected();
                LifetimeVerdict::Reused
            }
        }
    }

    /// Global scan throttle: at most one full tree scan per minimum
    /// refresh interval. The first scan always proceeds; throttled calls
    /// count and return false. A backwards clock fails closed as elapsed
    /// (refresh proceeds — the safe direction for a throttle).
    pub fn note_scan(&mut self, now_ns: u64) -> bool {
        match self.last_scan_ns {
            None => {
                self.last_scan_ns = Some(now_ns);
                true
            }
            Some(last) => {
                if span_elapsed(last, now_ns, RESOLVER_MIN_REFRESH_INTERVAL_NS) {
                    self.last_scan_ns = Some(now_ns);
                    true
                } else {
                    self.counters.inc_refresh_throttled();
                    false
                }
            }
        }
    }

    /// Retain one request outcome; the ring holds at most
    /// [`MAX_RETAINED_OUTCOMES`] records.
    pub fn record_outcome(&mut self, record: OutcomeRecord) {
        self.history.push_back(record);
        while self.history.len() > MAX_RETAINED_OUTCOMES {
            self.history.pop_front();
        }
    }

    /// Retained outcome count (bounded by [`MAX_RETAINED_OUTCOMES`]).
    #[cfg(test)]
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Oldest retained outcome, if any.
    #[cfg(test)]
    #[must_use]
    pub fn oldest_outcome(&self) -> Option<OutcomeRecord> {
        self.history.front().copied()
    }
}

impl Default for ResolverCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_core::workload::MetadataUnavailable;

    fn binding(observed: u64) -> LiveBinding {
        LiveBinding {
            dev: 8,
            ino: 100,
            observed_ns: observed,
        }
    }

    #[test]
    fn positive_ttl_hits_misses_and_evicts() {
        let mut cache = ResolverCache::new();
        assert_eq!(cache.lookup_positive(7, 1000), None);
        assert_eq!(cache.counters.positive_misses, 1);
        cache.insert_positive(7, binding(1000)).expect("fits");
        assert_eq!(cache.lookup_positive(7, 1000 + 10), Some(binding(1000)));
        assert_eq!(cache.counters.positive_hits, 1);
        // Exactly at the TTL: still fresh (expiry is strictly-greater).
        assert!(
            cache
                .lookup_positive(7, 1000 + RESOLVER_CACHE_TTL_NS)
                .is_some()
        );
        // Past the TTL: evicted and counted.
        assert_eq!(
            cache.lookup_positive(7, 1000 + RESOLVER_CACHE_TTL_NS + 1),
            None
        );
        assert_eq!(cache.counters.expired_evictions, 1);
        // Backwards clock fails closed as expired.
        cache.insert_positive(7, binding(5000)).expect("fits");
        assert_eq!(cache.lookup_positive(7, 1000), None);
    }

    #[test]
    fn full_cache_refuses_with_counter() {
        let mut cache = ResolverCache::new();
        for cgroup in 0..MAX_RESOLVER_CACHE_ENTRIES as u64 {
            cache.insert_positive(cgroup, binding(0)).expect("fits");
        }
        assert_eq!(
            cache.insert_positive(u64::MAX, binding(0)),
            Err(MetadataUnavailable::BudgetExceeded)
        );
        assert_eq!(cache.counters.insert_refused_full, 1);
        // Refreshing a known cgroup still works when full.
        cache.insert_positive(0, binding(1)).expect("refresh fits");
        assert_eq!(cache.lookup_positive(0, 1).expect("hit").observed_ns, 1);
    }

    #[test]
    fn negative_cache_is_brief_and_bounded() {
        let mut cache = ResolverCache::new();
        assert!(!cache.lookup_negative(7, 1000));
        cache.insert_negative(7, 1000).expect("fits");
        assert!(cache.lookup_negative(7, 1000 + 10));
        assert_eq!(cache.counters.negative_hits, 1);
        assert!(!cache.lookup_negative(7, 1000 + RESOLVER_NEGATIVE_CACHE_TTL_NS + 1));
        for cgroup in 0..MAX_RESOLVER_CACHE_ENTRIES as u64 {
            let _ = cache.insert_negative(cgroup, 0);
        }
        assert_eq!(
            cache.insert_negative(u64::MAX, 0),
            Err(MetadataUnavailable::BudgetExceeded)
        );
        assert_eq!(cache.counters.negative_refused_full, 1);
    }

    #[test]
    fn tombstones_are_bounded() {
        let mut cache = ResolverCache::new();
        for cgroup in 0..MAX_RESOLVER_TOMBSTONES as u64 {
            cache.insert_tombstone(cgroup, 0).expect("fits");
        }
        assert_eq!(
            cache.insert_tombstone(u64::MAX, 0),
            Err(MetadataUnavailable::BudgetExceeded)
        );
        assert_eq!(cache.counters.tombstone_refused_full, 1);
        assert!(cache.lookup_tombstone(0, 10));
        assert!(!cache.lookup_tombstone(0, RESOLVER_CACHE_TTL_NS + 1));
    }

    #[test]
    fn pid_reuse_splits_lifetime() {
        let mut cache = ResolverCache::new();
        assert_eq!(
            cache.note_pid_lifetime(100, 777),
            LifetimeVerdict::FirstSeen
        );
        assert_eq!(cache.note_pid_lifetime(100, 777), LifetimeVerdict::Stable);
        assert_eq!(cache.note_pid_lifetime(100, 888), LifetimeVerdict::Reused);
        assert_eq!(cache.counters.reuse_detected, 1);
        assert_eq!(cache.note_pid_lifetime(100, 888), LifetimeVerdict::Stable);
        for tgid in 0..(MAX_PID_LIFETIME_ENTRIES - 1) as u32 {
            let _ = cache.note_pid_lifetime(10_000 + tgid, 1);
        }
        assert_eq!(
            cache.note_pid_lifetime(u32::MAX, 1),
            LifetimeVerdict::FirstSeen
        );
        assert_eq!(cache.counters.pid_lifetime_refused_full, 1);
    }

    #[test]
    fn scan_throttle_gates_refresh() {
        let mut cache = ResolverCache::new();
        assert!(cache.note_scan(1000));
        assert!(!cache.note_scan(1000 + 10));
        assert_eq!(cache.counters.refresh_throttled, 1);
        assert!(cache.note_scan(1000 + RESOLVER_MIN_REFRESH_INTERVAL_NS + 1));
        // Backwards clock: refresh proceeds (fail-closed for a throttle).
        assert!(cache.note_scan(500));
    }

    #[test]
    fn retained_history_is_a_bounded_ring() {
        let mut cache = ResolverCache::new();
        for i in 0..(MAX_RETAINED_OUTCOMES + 10) as u64 {
            cache.record_outcome(OutcomeRecord {
                at_ns: i,
                resolved: i,
                unresolved: 0,
                refused: 0,
            });
        }
        assert_eq!(cache.history_len(), MAX_RETAINED_OUTCOMES);
        assert_eq!(cache.oldest_outcome().expect("oldest").at_ns, 10);
    }

    #[test]
    fn local_comparisons_agree_with_frozen_helpers() {
        use kryprobe_core::workload::{
            cache_entry_expired, check_cache_budget, check_tombstone_budget, deadline_exceeded,
        };
        // Boundary sweep: exact, over-by-one, backwards, and extremes.
        for (start, now, span) in [
            (100u64, 100u64, 50u64),
            (100, 150, 50),
            (100, 151, 50),
            (200, 100, 50),
            (0, u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX, 0),
            (0, 0, 0),
            (5, 5, 0),
        ] {
            assert_eq!(
                entry_expired(start, now, span),
                cache_entry_expired(start, now, span),
                "ttl ({start},{now},{span})"
            );
            assert_eq!(
                span_elapsed(start, now, span),
                deadline_exceeded(start, now, span),
                "deadline ({start},{now},{span})"
            );
        }
        // Pre-insert fullness (`len >= MAX` refuses) agrees with the
        // frozen post-count guard (`len + 1` over budget refuses).
        for count in [0, 1, 255, 256, 257, 1024] {
            assert_eq!(
                count >= MAX_RESOLVER_CACHE_ENTRIES,
                check_cache_budget(count + 1).is_err(),
                "cache budget {count}"
            );
            assert_eq!(
                count >= MAX_RESOLVER_TOMBSTONES,
                check_tombstone_budget(count + 1).is_err(),
                "tombstone budget {count}"
            );
        }
    }

    #[test]
    fn counters_saturate_with_flag() {
        let mut counters = HelperCounters::new();
        counters.denied = u64::MAX;
        counters.inc_denied();
        assert_eq!(counters.denied, u64::MAX);
        assert!(counters.saturated);
        let line = serde_json::to_string(&counters).expect("JSON");
        assert!(line.contains("\"saturated\":true"), "{line}");
        assert!(!line.contains('/'), "counters carry no paths: {line}");
    }
}
