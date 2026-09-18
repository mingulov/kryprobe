// SPDX-License-Identifier: GPL-3.0-or-later
//! Cookie/index namespace: concurrent groups never conflate `COUNT[idx]`.
//!
//! Cookies are `(generation << 32) | index`; two groups sharing a
//! generation and indices would merge counts. The driver-owned
//! [`CookieAllocator`](kryprobe_core::attach::CookieAllocator) issues
//! disjoint index ranges per group and refuses exhaustion (fail closed,
//! never alias).

use kryprobe_core::attach::{COUNT_SLOTS, CookieAllocator, CookieExhausted, cookie_for};
use kryprobe_core::backend::BackendDriver;
use kryprobe_core::ids::PlanGeneration;
use std::collections::BTreeSet;

/// Two groups in one generation get disjoint, in-range, gen-stamped cookies.
#[test]
fn two_groups_get_disjoint_cookies() {
    let generation = PlanGeneration::new(1);
    let mut alloc = CookieAllocator::new(generation);
    let group_a = alloc.allocate(3).expect("3 of 64 slots fit");
    let group_b = alloc.allocate(2).expect("2 more slots fit");
    assert_eq!(group_a.generation(), generation);
    assert_eq!(group_b.generation(), generation);
    let cookies_a = group_a.cookies();
    let cookies_b = group_b.cookies();
    assert_eq!(cookies_a.len(), 3);
    assert_eq!(cookies_b.len(), 2);
    let seen: BTreeSet<u64> = cookies_a.iter().chain(&cookies_b).copied().collect();
    assert_eq!(seen.len(), 5, "ranges must be disjoint: {seen:?}");
    for cookie in &seen {
        assert_eq!(
            cookie >> 32,
            1,
            "generation stamped in high 32: {cookie:#x}"
        );
        assert!(
            (u64::from(COUNT_SLOTS)) > (cookie & 0xffff_ffff),
            "index in range: {cookie:#x}"
        );
    }
    assert_eq!(alloc.used(), 5);
    assert_eq!(alloc.remaining(), COUNT_SLOTS - 5);
}

/// Model of the BPF side: hits on distinct cookies accumulate in distinct
/// `COUNT` slots, so per-group counts stay exact under concurrency.
#[test]
fn per_group_counts_stay_separate() {
    let generation = PlanGeneration::new(7);
    let mut alloc = CookieAllocator::new(generation);
    let group_a = alloc.allocate(3).expect("fits");
    let group_b = alloc.allocate(2).expect("fits");
    // What the spine does per hit: `COUNT[cookie as u32] += 1` after the
    // generation gate passes.
    let mut count = [0u64; COUNT_SLOTS as usize];
    let hits_a = [11u64, 23, 5];
    let hits_b = [17u64, 29];
    for (cookie, hits) in group_a.cookies().iter().zip(hits_a.iter()) {
        assert_eq!(cookie >> 32, 7);
        for _ in 0..*hits {
            count[(cookie & 0xffff_ffff) as usize] += 1;
        }
    }
    for (cookie, hits) in group_b.cookies().iter().zip(hits_b.iter()) {
        for _ in 0..*hits {
            count[(cookie & 0xffff_ffff) as usize] += 1;
        }
    }
    let sum = |cookies: &[u64]| -> u64 {
        cookies
            .iter()
            .map(|cookie| count[(cookie & 0xffff_ffff) as usize])
            .sum()
    };
    assert_eq!(sum(&group_a.cookies()), hits_a.iter().sum::<u64>());
    assert_eq!(sum(&group_b.cookies()), hits_b.iter().sum::<u64>());
    assert_eq!(
        count.iter().sum::<u64>(),
        hits_a.iter().sum::<u64>() + hits_b.iter().sum::<u64>(),
        "no hits lost, none double-counted"
    );
}

/// Exhaustion refuses without issuing anything: no wrap, no alias, no
/// partial range. A failed request leaves the allocator unchanged.
#[test]
fn exhaustion_fails_closed_without_alias() {
    let generation = PlanGeneration::new(1);
    let mut alloc = CookieAllocator::new(generation);
    alloc.allocate(60).expect("60 of 64 fit");
    let err = alloc.allocate(5).expect_err("only 4 remain");
    assert_eq!(
        err,
        CookieExhausted {
            requested: 5,
            remaining: 4,
        }
    );
    assert_eq!(alloc.used(), 60, "failed request consumes nothing");
    alloc.allocate(4).expect("exact fit succeeds");
    assert_eq!(alloc.remaining(), 0);
    let err = alloc.allocate(1).expect_err("full space refuses");
    assert_eq!(err.remaining, 0);
    assert!(err.to_string().contains("exhausted"), "got {err}");
}

/// Empty ranges are refused: a group with no offsets has no cookies.
#[test]
fn zero_length_allocation_refused() {
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    let err = alloc.allocate(0).expect_err("empty range refused");
    assert_eq!(err.requested, 0);
    assert_eq!(alloc.used(), 0);
}

/// Generations partition the namespace: a fresh allocator for the next
/// generation reuses index space, and stale-generation cookies never
/// collide (high 32 bits differ; the BPF gate drops them).
#[test]
fn new_generation_reuses_index_space() {
    let first = CookieAllocator::new(PlanGeneration::new(1));
    let _full = {
        let mut first = first;
        first.allocate(64).expect("fills gen 1")
    };
    let mut second = CookieAllocator::new(PlanGeneration::new(2));
    let range = second.allocate(64).expect("gen 2 starts fresh");
    assert_eq!(range.base(), 0);
    assert_eq!(range.generation(), PlanGeneration::new(2));
    let cookies = range.cookies();
    assert_eq!(cookies.len(), 64);
    assert!(cookies.iter().all(|cookie| cookie >> 32 == 2));
    assert_eq!(cookie_for(PlanGeneration::new(1), 0), 0x0000_0001_0000_0000);
    assert_eq!(cookie_for(PlanGeneration::new(2), 0), 0x0000_0002_0000_0000);
}

/// X11 pin: a range stamps its ISSUING allocator's generation; no
/// caller-supplied stamp exists, so a wrong generation is
/// inexpressible (it would alias or mint gate-dropped cookies).
#[test]
fn range_stamps_issuing_generation_not_caller_choice() {
    let issuing = PlanGeneration::new(7);
    let mut alloc = CookieAllocator::new(issuing);
    let range = alloc.allocate(2).expect("fits");
    assert_eq!(range.generation(), issuing);
    assert_eq!(
        range.cookies(),
        vec![cookie_for(issuing, 0), cookie_for(issuing, 1)]
    );
    // A second allocator's range stamps its own issuance, never the
    // first's: same indices, disjoint cookies.
    let mut other = CookieAllocator::new(PlanGeneration::new(9));
    let other_range = other.allocate(2).expect("fits");
    assert_eq!(other_range.cookies()[0] >> 32, 9);
    assert_ne!(range.cookies()[0], other_range.cookies()[0]);
}

/// The driver owns the session allocator: ranges issued through the
/// driver are disjoint, carry the session generation, and exhaust.
#[test]
fn driver_owns_the_session_allocator() {
    let mut driver = BackendDriver::harness(); // session gen 1, 64 slots
    let group_a = driver.allocate_cookies(3).expect("fits");
    let group_b = driver.allocate_cookies(2).expect("fits");
    let generation = PlanGeneration::new(1);
    assert_eq!(group_a.generation(), generation);
    assert_eq!(group_b.generation(), generation);
    let seen: BTreeSet<u64> = group_a
        .cookies()
        .iter()
        .chain(&group_b.cookies())
        .copied()
        .collect();
    assert_eq!(seen.len(), 5, "driver-issued ranges are disjoint");
    driver.allocate_cookies(59).expect("exact fit");
    let err = driver
        .allocate_cookies(1)
        .expect_err("driver space exhausts");
    assert_eq!(err.remaining, 0);
}
