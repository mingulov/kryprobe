// SPDX-License-Identifier: GPL-3.0-or-later
//! kcrypto lifecycle reducer: edge ordering oracle.
//!
//! A terminal callback arriving before its return must complete the
//! request exactly once, with the callback's terminal status and the
//! submit→return duration — and a duplicate terminal after completion
//! must emit nothing.

use kryprobe_core::kcrypto::{
    CallbackDisposition, Edge, GapReason, LifecycleReducer, ReturnDisposition, Terminal,
};

#[test]
fn callback_before_return_completes_once() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: Some(7),
            ts_ns: 10
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Callback {
            id: 1,
            ts_ns: 20,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    let out = r.apply(Edge::Return {
        id: 1,
        ts_ns: 30,
        status: -115,
        disposition: ReturnDisposition::Queued,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].id, 1);
    assert_eq!(out[0].terminal, Terminal::Callback(0));
    assert_eq!(out[0].duration_ns, Some(10));
    assert!(
        r.apply(Edge::Callback {
            id: 1,
            ts_ns: 40,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    assert!(r.finish(50).is_empty());
}

#[test]
fn capacity_refusal_drops_overflow_submit() {
    let mut r = LifecycleReducer::new(1);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    // Live set is full: id 2 must not be admitted.
    assert!(
        r.apply(Edge::Submit {
            id: 2,
            tfm_id: None,
            ts_ns: 11
        })
        .is_empty()
    );
    // A refused id never completes: its terminal return is an orphan.
    assert!(
        r.apply(Edge::Return {
            id: 2,
            ts_ns: 30,
            status: 0,
            disposition: ReturnDisposition::Terminal,
        })
        .is_empty()
    );
    // The admitted id is unaffected and completes normally.
    let out = r.apply(Edge::Return {
        id: 1,
        ts_ns: 31,
        status: 0,
        disposition: ReturnDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].id, 1);
    assert_eq!(out[0].terminal, Terminal::Sync(0));
}

#[test]
fn capacity_freed_on_completion() {
    let mut r = LifecycleReducer::new(1);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    let out = r.apply(Edge::Return {
        id: 1,
        ts_ns: 20,
        status: 0,
        disposition: ReturnDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    // Live set is empty again: id 2 admits and completes.
    assert!(
        r.apply(Edge::Submit {
            id: 2,
            tfm_id: None,
            ts_ns: 30
        })
        .is_empty()
    );
    let out = r.apply(Edge::Return {
        id: 2,
        ts_ns: 40,
        status: 0,
        disposition: ReturnDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].id, 2);
}

#[test]
fn stats_count_admitted_and_emitted() {
    let mut r = LifecycleReducer::new(4);
    let fresh = r.stats();
    assert_eq!(fresh.admitted, 0);
    assert_eq!(fresh.emitted, 0);
    assert_eq!(fresh.unfinished, 0);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    let out = r.apply(Edge::Return {
        id: 1,
        ts_ns: 20,
        status: 0,
        disposition: ReturnDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    let s = r.stats();
    assert_eq!(s.admitted, 1);
    assert_eq!(s.emitted, 1);
    assert_eq!(s.unfinished, 0);
}

#[test]
fn stats_count_rejections() {
    let mut r = LifecycleReducer::new(1);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 11
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Submit {
            id: 2,
            tfm_id: None,
            ts_ns: 12
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Return {
            id: 9,
            ts_ns: 20,
            status: 0,
            disposition: ReturnDisposition::Terminal,
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Return {
            id: 1,
            ts_ns: 21,
            status: -1,
            disposition: ReturnDisposition::Unresolved,
        })
        .is_empty()
    );
    // Routine progress on a live id is observed but uncounted.
    assert!(
        r.apply(Edge::Callback {
            id: 1,
            ts_ns: 22,
            status: -115,
            disposition: CallbackDisposition::Progress,
        })
        .is_empty()
    );
    let s = r.stats();
    assert_eq!(s.admitted, 1);
    assert_eq!(s.duplicate, 1);
    assert_eq!(s.admission_failed, 1);
    assert_eq!(s.orphan, 1);
    assert_eq!(s.ambiguous, 1);
    assert_eq!(s.emitted, 0);
}

#[test]
fn gap_completes_live_id_as_unknown() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: Some(7),
            ts_ns: 10
        })
        .is_empty()
    );
    let out = r.apply(Edge::Gap {
        id: 1,
        reason: GapReason::TransportLoss,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].id, 1);
    assert_eq!(out[0].tfm_id, Some(7));
    assert_eq!(out[0].terminal, Terminal::Unknown);
    assert_eq!(out[0].duration_ns, None);
    assert_eq!(r.stats().emitted, 1);
}

#[test]
fn gap_with_retained_terminal_emits_it() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Callback {
            id: 1,
            ts_ns: 20,
            status: 5,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    // The return will never arrive, but terminal truth is retained:
    // the gap reconciles to the callback result, not Unknown.
    let out = r.apply(Edge::Gap {
        id: 1,
        reason: GapReason::MissingPhase,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].terminal, Terminal::Callback(5));
    assert_eq!(out[0].duration_ns, Some(10));
}

#[test]
fn edges_after_gap_completion_are_duplicates() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert_eq!(
        r.apply(Edge::Gap {
            id: 1,
            reason: GapReason::MissingPhase
        })
        .len(),
        1
    );
    // Late terminal: suppressed, counted duplicate.
    assert!(
        r.apply(Edge::Callback {
            id: 1,
            ts_ns: 30,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    // Repeat gap: same treatment.
    assert!(
        r.apply(Edge::Gap {
            id: 1,
            reason: GapReason::Deadline
        })
        .is_empty()
    );
    assert_eq!(r.stats().duplicate, 2);
    assert_eq!(r.stats().emitted, 1);
}

#[test]
fn gap_on_unknown_id_is_orphan() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Gap {
            id: 9,
            reason: GapReason::MissingPhase
        })
        .is_empty()
    );
    assert_eq!(r.stats().orphan, 1);
}

#[test]
fn finish_reconciles_pending_deterministically() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 3,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Callback {
            id: 3,
            ts_ns: 25,
            status: 7,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 12
        })
        .is_empty()
    );
    let out = r.finish(100);
    assert_eq!(out.len(), 2);
    // Deterministic id order regardless of arrival order.
    assert_eq!(out[0].id, 1);
    assert_eq!(out[0].terminal, Terminal::Unknown);
    assert_eq!(out[0].duration_ns, None);
    assert_eq!(out[1].id, 3);
    assert_eq!(out[1].terminal, Terminal::Callback(7));
    assert_eq!(out[1].duration_ns, Some(15));
    let s = r.stats();
    assert_eq!(s.emitted, 2);
    assert_eq!(s.unfinished, 1);
    // Drained ids are tombstoned: late edges are duplicates.
    assert!(
        r.apply(Edge::Callback {
            id: 3,
            ts_ns: 150,
            status: 7,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    assert_eq!(r.stats().duplicate, 1);
    // Second finish is a no-op.
    assert!(r.finish(200).is_empty());
}

#[test]
fn return_before_callback_completes_at_callback() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    // Queued return with no terminal yet: retained, silent.
    assert!(
        r.apply(Edge::Return {
            id: 1,
            ts_ns: 20,
            status: -115,
            disposition: ReturnDisposition::Queued,
        })
        .is_empty()
    );
    // Terminal callback joins the retained return: emits now with
    // submit-to-callback duration.
    let out = r.apply(Edge::Callback {
        id: 1,
        ts_ns: 30,
        status: 0,
        disposition: CallbackDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].terminal, Terminal::Callback(0));
    assert_eq!(out[0].duration_ns, Some(20));
    assert_eq!(r.stats().emitted, 1);
}

#[test]
fn conflicting_sync_return_keeps_first_terminal() {
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Callback {
            id: 1,
            ts_ns: 20,
            status: 5,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    // Sync return contradicts the retained callback terminal: the first
    // terminal wins and the conflict is counted ambiguous.
    let out = r.apply(Edge::Return {
        id: 1,
        ts_ns: 30,
        status: 0,
        disposition: ReturnDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].terminal, Terminal::Callback(5));
    assert_eq!(out[0].duration_ns, Some(10));
    assert_eq!(r.stats().ambiguous, 1);
    assert_eq!(r.stats().emitted, 1);
}

#[test]
fn tombstones_evict_oldest_beyond_capacity() {
    let mut r = LifecycleReducer::new(2);
    for (id, base) in [(1u64, 10u64), (2, 20), (3, 30)] {
        assert!(
            r.apply(Edge::Submit {
                id,
                tfm_id: None,
                ts_ns: base
            })
            .is_empty()
        );
        let out = r.apply(Edge::Return {
            id,
            ts_ns: base + 10,
            status: 0,
            disposition: ReturnDisposition::Terminal,
        });
        assert_eq!(out.len(), 1);
    }
    // Tombstones hold {2, 3}: id 3's late edge is still a duplicate.
    assert!(
        r.apply(Edge::Callback {
            id: 3,
            ts_ns: 45,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    assert_eq!(r.stats().duplicate, 1);
    // id 1 was evicted: resubmission starts an explicitly new lifecycle.
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 100
        })
        .is_empty()
    );
    let out = r.apply(Edge::Return {
        id: 1,
        ts_ns: 110,
        status: 0,
        disposition: ReturnDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].duration_ns, Some(10));
    assert_eq!(r.stats().admitted, 4);
    assert_eq!(r.stats().emitted, 4);
}

#[test]
fn q05_backlog_progress_then_terminal() {
    // Matrix Q05 pin: EBUSY-accepted backlog, EINPROGRESS progress
    // callbacks, then terminal success. Progress never completes;
    // exact terminal status retained; duration ends at terminal.
    let mut r = LifecycleReducer::new(4);
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 100
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Return {
            id: 1,
            ts_ns: 110,
            status: -16,
            disposition: ReturnDisposition::Queued,
        })
        .is_empty()
    );
    for ts in [120, 130] {
        assert!(
            r.apply(Edge::Callback {
                id: 1,
                ts_ns: ts,
                status: -115,
                disposition: CallbackDisposition::Progress,
            })
            .is_empty()
        );
    }
    let out = r.apply(Edge::Callback {
        id: 1,
        ts_ns: 140,
        status: 0,
        disposition: CallbackDisposition::Terminal,
    });
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].terminal, Terminal::Callback(0));
    assert_eq!(out[0].duration_ns, Some(40));
    assert_eq!(r.stats().emitted, 1);
}

#[test]
fn q08_terminal_at_most_once_across_paths() {
    // Matrix Q08 pin: every completion path emits exactly once;
    // repeats after completion are suppressed duplicates.
    let mut r = LifecycleReducer::new(8);
    // Path 1: sync return.
    assert!(
        r.apply(Edge::Submit {
            id: 1,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert_eq!(
        r.apply(Edge::Return {
            id: 1,
            ts_ns: 20,
            status: 0,
            disposition: ReturnDisposition::Terminal,
        })
        .len(),
        1
    );
    // Path 2: callback, then return.
    assert!(
        r.apply(Edge::Submit {
            id: 2,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Callback {
            id: 2,
            ts_ns: 20,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty()
    );
    assert_eq!(
        r.apply(Edge::Return {
            id: 2,
            ts_ns: 30,
            status: -115,
            disposition: ReturnDisposition::Queued,
        })
        .len(),
        1
    );
    // Path 3: return, then callback.
    assert!(
        r.apply(Edge::Submit {
            id: 3,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert!(
        r.apply(Edge::Return {
            id: 3,
            ts_ns: 20,
            status: -115,
            disposition: ReturnDisposition::Queued,
        })
        .is_empty()
    );
    assert_eq!(
        r.apply(Edge::Callback {
            id: 3,
            ts_ns: 30,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        })
        .len(),
        1
    );
    // Path 4: gap.
    assert!(
        r.apply(Edge::Submit {
            id: 4,
            tfm_id: None,
            ts_ns: 10
        })
        .is_empty()
    );
    assert_eq!(
        r.apply(Edge::Gap {
            id: 4,
            reason: GapReason::Deadline
        })
        .len(),
        1
    );
    assert_eq!(r.stats().emitted, 4);
    // Repeats on every path: suppressed, all duplicates.
    for id in [1u64, 2, 3, 4] {
        assert!(
            r.apply(Edge::Return {
                id,
                ts_ns: 100,
                status: 0,
                disposition: ReturnDisposition::Terminal,
            })
            .is_empty()
        );
        assert!(
            r.apply(Edge::Callback {
                id,
                ts_ns: 101,
                status: 0,
                disposition: CallbackDisposition::Terminal,
            })
            .is_empty()
        );
        assert!(
            r.apply(Edge::Gap {
                id,
                reason: GapReason::Deadline
            })
            .is_empty()
        );
    }
    assert_eq!(r.stats().duplicate, 12);
    assert_eq!(r.stats().emitted, 4);
}
