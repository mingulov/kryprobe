// SPDX-License-Identifier: GPL-3.0-or-later
//! Budget exhaustion tests: every counter fails typed and stays distinct.

use kryprobe_core::budget::{BudgetKind, BudgetManager};
use kryprobe_core::plan::PlanBudget;

const ALL_KINDS: [BudgetKind; 7] = [
    BudgetKind::Targets,
    BudgetKind::Objects,
    BudgetKind::Bytes,
    BudgetKind::Links,
    BudgetKind::StateEntries,
    BudgetKind::Queue,
    BudgetKind::Duration,
];

fn small_budget() -> PlanBudget {
    PlanBudget {
        max_targets: 2,
        max_objects: 2,
        max_bytes: 10,
        max_links: 2,
        max_state_entries: 4,
        max_queue: 4,
        max_duration_ns: 1000,
    }
}

fn limit_of(budget: &PlanBudget, kind: BudgetKind) -> u64 {
    match kind {
        BudgetKind::Targets => budget.max_targets,
        BudgetKind::Objects => budget.max_objects,
        BudgetKind::Bytes => budget.max_bytes,
        BudgetKind::Links => budget.max_links,
        BudgetKind::StateEntries => budget.max_state_entries,
        BudgetKind::Queue => budget.max_queue,
        BudgetKind::Duration => budget.max_duration_ns,
    }
}

#[test]
fn each_counter_charges_to_limit_then_exhausts_typed() {
    for kind in ALL_KINDS {
        let budget = small_budget();
        let mut mgr = BudgetManager::new(budget);
        let limit = limit_of(&budget, kind);
        assert!(mgr.charge(kind, limit).is_ok(), "{kind:?} full charge");
        assert_eq!(mgr.used(kind), limit);
        let err = mgr.charge(kind, 1).expect_err("must exhaust");
        assert_eq!(err.kind, kind, "omission must name its counter");
        assert_eq!(err.limit, limit);
        assert_eq!(mgr.used(kind), limit, "refused charge must not consume");
    }
}

#[test]
fn counters_are_distinct() {
    let mut mgr = BudgetManager::new(small_budget());
    assert!(mgr.charge(BudgetKind::Targets, 2).is_ok());
    assert!(mgr.charge(BudgetKind::Targets, 1).is_err());
    for kind in ALL_KINDS {
        if kind == BudgetKind::Targets {
            continue;
        }
        assert_eq!(mgr.used(kind), 0, "{kind:?} untouched by targets");
        assert!(mgr.charge(kind, 1).is_ok(), "{kind:?} still has room");
    }
}

#[test]
fn overflowing_charge_refuses_even_at_u64_max_limit() {
    let budget = PlanBudget {
        max_targets: u64::MAX,
        max_objects: u64::MAX,
        max_bytes: u64::MAX,
        max_links: u64::MAX,
        max_state_entries: u64::MAX,
        max_queue: u64::MAX,
        max_duration_ns: u64::MAX,
    };
    let mut mgr = BudgetManager::new(budget);
    assert!(mgr.charge(BudgetKind::Targets, u64::MAX).is_ok());
    assert_eq!(mgr.used(BudgetKind::Targets), u64::MAX);
    // `used + 1` overflows: must refuse (fail closed), never
    // saturate-pass against the `u64::MAX` ceiling.
    let err = mgr
        .charge(BudgetKind::Targets, 1)
        .expect_err("overflow must refuse");
    assert_eq!(err.limit, u64::MAX);
    assert_eq!(err.used, u64::MAX);
    assert_eq!(err.requested, 1);
    assert_eq!(
        mgr.used(BudgetKind::Targets),
        u64::MAX,
        "refused charge must not consume"
    );
    // A zero charge at the ceiling still passes: no overflow, nothing
    // consumed.
    assert!(mgr.charge(BudgetKind::Targets, 0).is_ok());
}

#[test]
fn zero_charge_is_free_but_never_exceeds() {
    let mut mgr = BudgetManager::new(small_budget());
    assert!(mgr.charge(BudgetKind::Bytes, 0).is_ok());
    assert_eq!(mgr.used(BudgetKind::Bytes), 0);
}
