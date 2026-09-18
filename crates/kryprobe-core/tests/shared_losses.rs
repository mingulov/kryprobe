// SPDX-License-Identifier: GPL-3.0-or-later
//! T6 concern #2: shared-layer losses (ring/queue/drain observed in
//! privilege land, outside any backend) feed the session total exactly
//! once, outside the per-backend sums.

use kryprobe_core::backend::{
    BackendDriver, BackendRegistry, DriverReport, RawEvent, SharedFeedError,
};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{CallKind, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{IntegritySummary, SharedLosses};
use kryprobe_core::synthetic::SyntheticBackend;

fn runtime() -> RuntimeCapabilities {
    RuntimeCapabilities {
        kernel_release: String::from("test"),
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf_present: false,
        userns: false,
        yama_scope: 0,
        caps: Vec::new(),
    }
}

/// Synthetic-only run: one event, zero backend-observed losses, nothing
/// skipped — so any nonzero session total comes from the shared feed alone.
fn synthetic_run() -> DriverReport {
    let mut registry = BackendRegistry::new();
    registry
        .register(Box::new(SyntheticBackend::new(Vec::new())))
        .expect("fresh registry accepts synthetic");
    let (header, payload) = SyntheticBackend::harness_event(
        EvidencePhase::Entered,
        OperationClass::Sign,
        CallKind::Operation,
        0,
        1_000_000,
    );
    let events = [RawEvent {
        header,
        payload: &payload,
    }];
    let mut driver = BackendDriver::harness();
    driver
        .run(&registry, &runtime(), &events)
        .expect("open gates + routed event runs clean")
}

#[test]
fn shared_losses_accrue_exactly_once_in_session_total() {
    let mut report = synthetic_run();
    assert!(report.skipped.is_empty());
    assert_eq!(report.skipped_drops(), 0);
    assert_eq!(report.summaries.len(), 1);
    assert_eq!(
        report.summaries[0].integrity,
        IntegritySummary::default(),
        "synthetic path observes no backend-local losses"
    );

    let fed = SharedLosses::new(11, 5);
    report
        .feed_shared_losses(fed)
        .expect("first shared feed is accepted");
    assert_eq!(report.shared_losses(), Some(fed));

    // The shared loss appears in the session total exactly once: present
    // (not dropped), single (not doubled to 22/10).
    let want = IntegritySummary {
        ring_reservation_failures: 11,
        user_queue_drops: 5,
        ..IntegritySummary::default()
    };
    assert_eq!(report.session_integrity_checked().expect("fed"), want);
    assert_eq!(report.session_integrity(), want);
    // The feed accrues outside the per-backend sums: backend summaries
    // are untouched, and skip-drop receipts stay disjoint (still zero).
    assert_eq!(report.summaries[0].integrity, IntegritySummary::default());
    assert!(report.skipped.is_empty());
    assert_eq!(report.skipped_drops(), 0);
}

#[test]
fn duplicate_shared_feed_refused_without_double_count() {
    let mut report = synthetic_run();
    let first = SharedLosses::new(11, 5);
    report
        .feed_shared_losses(first)
        .expect("first shared feed is accepted");
    let err = report
        .feed_shared_losses(SharedLosses::new(100, 100))
        .expect_err("second shared feed must refuse");
    assert_eq!(err, SharedFeedError::DuplicateFeed);
    assert_eq!(err.to_string(), "shared losses already fed");
    // The first feed stands: no accrual change, no double-count.
    assert_eq!(report.shared_losses(), Some(first));
    assert_eq!(
        report.session_integrity(),
        IntegritySummary {
            ring_reservation_failures: 11,
            user_queue_drops: 5,
            ..IntegritySummary::default()
        }
    );
}

#[test]
fn missing_shared_feed_fails_checked_total_but_not_lenient_rollup() {
    let report = synthetic_run();
    assert_eq!(report.shared_losses(), None);
    let err = report
        .session_integrity_checked()
        .expect_err("unfed report must fail the checked total");
    assert_eq!(err, SharedFeedError::MissingFeed);
    assert_eq!(err.to_string(), "shared losses not fed");
    // The lenient legacy path treats unfed as zero (harness/back-compat);
    // production reconciliation must use the checked total above.
    assert_eq!(report.session_integrity(), IntegritySummary::default());
}
