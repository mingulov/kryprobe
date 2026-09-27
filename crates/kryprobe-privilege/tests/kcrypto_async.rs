// SPDX-License-Identifier: GPL-3.0-or-later
//! P4 `kcrypto_async` suite (test plan P3–P6): qualified asynchronous
//! terminal completion, end to end through [`SensorCore`] (callback
//! decode → adapter identity relation → disposition feed → reducer →
//! ledger) plus the table-driven reducer characterization (Q03–Q08)
//! and the fixture-truth oracle with its guest cells.
//!
//! Contract pinned here (adapter contract v1,
//! `kcrypto_lifecycle/async_adapter.rs`): terminal truth comes ONLY
//! from adapter-fed dispositions; `-EINPROGRESS` returns queue,
//! `-EBUSY` queues iff the submit carried `MAY_BACKLOG`,
//! `-ENOSPC` is an exact immediate error (never rewritten);
//! `-EINPROGRESS` callbacks are progress (never terminal); early
//! callbacks retain truth for the joining return; storage reuse
//! stays distinct by invocation identity; ambiguous keys gap loud;
//! unqualified paths leave queued/unknown terminal with NO terminal
//! latency; at most one terminal record per invocation.

use kryprobe_core::kcrypto::{
    CallbackDisposition, Edge, GapReason, LifecycleFamily, LifecycleReducer, OpDirection,
    ReducerStats, RequestMeta, RequestRecord, ReturnDisposition, Terminal,
};
use kryprobe_privilege::kcrypto_lifecycle::async_adapter::{
    AsyncAdapter, CRYPTO_TFM_REQ_MAY_BACKLOG as MAY_BACKLOG, classify_callback, classify_return,
};

// ---------------------------------------------------------------------------
// Reducer characterization (Q03–Q08): table-driven, green day one.
// The T05/T06 reducer already implements async edge semantics; these
// cases PIN the contract the adapter feeds ("disposition feed only"
// needs NO reducer change — proven, not assumed).
// ---------------------------------------------------------------------------

/// Canonical submit metadata for reducer cases (the reducer carries
/// it opaquely; sensor tests pin its provenance).
fn meta() -> RequestMeta {
    RequestMeta {
        family: LifecycleFamily::Skcipher,
        direction: OpDirection::Encrypt,
        cryptlen: Some(16),
        req_flags: Some(0),
        epoch: Some(0),
    }
}

fn submit(id: u64, ts: u64) -> Edge {
    Edge::Submit {
        id,
        tfm_id: Some(1),
        ts_ns: ts,
        meta: meta(),
    }
}

fn ret(id: u64, ts: u64, status: i32, disposition: ReturnDisposition) -> Edge {
    Edge::Return {
        id,
        ts_ns: ts,
        status,
        disposition,
    }
}

fn cb(id: u64, ts: u64, status: i32, disposition: CallbackDisposition) -> Edge {
    Edge::Callback {
        id,
        ts_ns: ts,
        status,
        disposition,
    }
}

/// One table case: an edge script plus the exact expected outcome.
struct Case {
    name: &'static str,
    edges: Vec<Edge>,
    /// Expected emitted records, in emission order.
    want: Vec<RequestRecord>,
    /// Expected cumulative stats AFTER the script (finish NOT called
    /// unless the script ends with `Finish` — see `want_finish`).
    want_stats: ReducerStats,
    /// When true, `finish` is called after the script and must emit
    /// exactly `want_finish` (in ascending id order).
    want_finish: Vec<RequestRecord>,
}

fn record(id: u64, terminal: Terminal, duration_ns: Option<u64>) -> RequestRecord {
    RequestRecord {
        id,
        tfm_id: Some(1),
        terminal,
        duration_ns,
        meta: meta(),
    }
}

fn stats(
    admitted: u64,
    emitted: u64,
    orphan: u64,
    duplicate: u64,
    ambiguous: u64,
    admission_failed: u64,
    unfinished: u64,
) -> ReducerStats {
    ReducerStats {
        admitted,
        emitted,
        orphan,
        duplicate,
        ambiguous,
        admission_failed,
        unfinished,
    }
}

fn run_case(case: Case) {
    let mut r = LifecycleReducer::new(64);
    let mut got = Vec::new();
    for edge in case.edges {
        got.extend(r.apply(edge));
    }
    assert_eq!(got, case.want, "case {}: records", case.name);
    if case.want_finish.is_empty() {
        assert_eq!(r.stats(), case.want_stats, "case {}: stats", case.name);
    } else {
        let drained = r.finish(9999);
        assert_eq!(drained, case.want_finish, "case {}: finish", case.name);
        let mut want = case.want_stats;
        want.emitted += case.want_finish.len() as u64;
        want.unfinished += case
            .want_finish
            .iter()
            .filter(|rec| rec.terminal == Terminal::Unknown)
            .count() as u64;
        assert_eq!(r.stats(), want, "case {}: stats after finish", case.name);
    }
}

/// Q03–Q08 as one table: cross-CPU terminal (id/tfm/meta preserved —
/// the reducer never sees CPUs; sensor + live cells prove the
/// cross-CPU delivery), callback-before-return, callback-triggered
/// reuse, backlog progress, sync-on-async-capable, and the
/// missing/late/duplicate/conflicting/orphan terminal family.
#[test]
fn async_reducer_table_q03_q08() {
    let einprogress = -libc::EINPROGRESS;
    let ebusy = -libc::EBUSY;
    let enospc = -libc::ENOSPC;
    let cases = vec![
        // Q03: queued return, terminal callback on another CPU (the
        // edge stream carries no CPU — identity is the opaque id;
        // the sensor/live layers prove the CPUs differed).
        Case {
            name: "cross-cpu-terminal-keeps-submitter",
            edges: vec![
                submit(7, 100),
                ret(7, 110, einprogress, ReturnDisposition::Queued),
                cb(7, 150, 0, CallbackDisposition::Terminal),
            ],
            want: vec![record(7, Terminal::Callback(0), Some(50))],
            want_stats: stats(1, 1, 0, 0, 0, 0, 0),
            want_finish: vec![],
        },
        // Q04a: early terminal callback, joining return emits once.
        Case {
            name: "callback-before-return-emits-once",
            edges: vec![
                submit(1, 100),
                cb(1, 105, 0, CallbackDisposition::Terminal),
                ret(1, 110, einprogress, ReturnDisposition::Queued),
            ],
            want: vec![record(1, Terminal::Callback(0), Some(5))],
            want_stats: stats(1, 1, 0, 0, 0, 0, 0),
            want_finish: vec![],
        },
        // Q04b: callback-triggered reuse before unwind — the new
        // submit (fresh id, same storage — the reducer only sees
        // ids) never aliases the old return.
        Case {
            name: "callback-triggered-reuse-keeps-old-return",
            edges: vec![
                submit(1, 100),
                ret(1, 110, einprogress, ReturnDisposition::Queued),
                cb(1, 120, 0, CallbackDisposition::Terminal),
                submit(2, 125),
                ret(1, 130, einprogress, ReturnDisposition::Queued),
                ret(2, 140, 0, ReturnDisposition::Terminal),
            ],
            want: vec![
                record(1, Terminal::Callback(0), Some(20)),
                record(2, Terminal::Sync(0), Some(15)),
            ],
            // The post-completion Queued return for id 1 is a
            // suppressed duplicate (Callback truth already emitted).
            want_stats: stats(2, 2, 0, 1, 0, 0, 0),
            want_finish: vec![],
        },
        // Q05: backlog progress is observed, uncounted, never
        // terminal; the later terminal emits with the callback span.
        Case {
            name: "backlog-progress-is-not-terminal",
            edges: vec![
                submit(3, 100),
                ret(3, 105, ebusy, ReturnDisposition::Queued),
                cb(3, 110, einprogress, CallbackDisposition::Progress),
                cb(3, 120, einprogress, CallbackDisposition::Progress),
                cb(3, 150, 0, CallbackDisposition::Terminal),
            ],
            want: vec![record(3, Terminal::Callback(0), Some(50))],
            want_stats: stats(1, 1, 0, 0, 0, 0, 0),
            want_finish: vec![],
        },
        // Q05b: progress AFTER terminal truth is late traffic
        // (duplicate), whether or not the joining return arrived.
        Case {
            name: "progress-after-terminal-is-duplicate",
            edges: vec![
                submit(3, 100),
                cb(3, 105, 0, CallbackDisposition::Terminal),
                cb(3, 106, einprogress, CallbackDisposition::Progress),
                ret(3, 110, einprogress, ReturnDisposition::Queued),
                cb(3, 120, einprogress, CallbackDisposition::Progress),
            ],
            want: vec![record(3, Terminal::Callback(0), Some(5))],
            want_stats: stats(1, 1, 0, 2, 0, 0, 0),
            want_finish: vec![],
        },
        // Q06: sync completion on an async-capable driver (the
        // return classification, not the driver, decides).
        Case {
            name: "sync-completion-on-async-capable-driver",
            edges: vec![submit(4, 100), ret(4, 104, 0, ReturnDisposition::Terminal)],
            want: vec![record(4, Terminal::Sync(0), Some(4))],
            want_stats: stats(1, 1, 0, 0, 0, 0, 0),
            want_finish: vec![],
        },
        // Q06b: no-backlog ENOSPC is an exact immediate error.
        Case {
            name: "no-backlog-enospc-is-immediate-error",
            edges: vec![
                submit(4, 100),
                ret(4, 104, enospc, ReturnDisposition::Terminal),
            ],
            want: vec![record(4, Terminal::Sync(enospc), Some(4))],
            want_stats: stats(1, 1, 0, 0, 0, 0, 0),
            want_finish: vec![],
        },
        // Q07a: missing terminal — finish drains truthless.
        Case {
            name: "missing-terminal-drains-unknown",
            edges: vec![
                submit(5, 100),
                ret(5, 105, einprogress, ReturnDisposition::Queued),
            ],
            want: vec![],
            want_stats: stats(1, 0, 0, 0, 0, 0, 0),
            want_finish: vec![record(5, Terminal::Unknown, None)],
        },
        // Q07b: missing everything after submit (return lost too).
        Case {
            name: "missing-return-and-terminal-drains-unknown",
            edges: vec![submit(5, 100)],
            want: vec![],
            want_stats: stats(1, 0, 0, 0, 0, 0, 0),
            want_finish: vec![record(5, Terminal::Unknown, None)],
        },
        // Q07c: late duplicate terminal (same status) — duplicate.
        Case {
            name: "late-duplicate-terminal-is-duplicate",
            edges: vec![
                submit(6, 100),
                ret(6, 105, einprogress, ReturnDisposition::Queued),
                cb(6, 110, 0, CallbackDisposition::Terminal),
                cb(6, 900, 0, CallbackDisposition::Terminal),
            ],
            want: vec![record(6, Terminal::Callback(0), Some(10))],
            want_stats: stats(1, 1, 0, 1, 0, 0, 0),
            want_finish: vec![],
        },
        // Q07d: late conflicting terminal — ambiguous, first wins.
        Case {
            name: "late-conflicting-terminal-is-ambiguous",
            edges: vec![
                submit(6, 100),
                ret(6, 105, einprogress, ReturnDisposition::Queued),
                cb(6, 110, 0, CallbackDisposition::Terminal),
                cb(6, 900, -libc::EBADMSG, CallbackDisposition::Terminal),
            ],
            want: vec![record(6, Terminal::Callback(0), Some(10))],
            want_stats: stats(1, 1, 0, 0, 1, 0, 0),
            want_finish: vec![],
        },
        // Q07e: orphan terminal (never admitted) — orphan, silent.
        Case {
            name: "orphan-terminal-is-orphan",
            edges: vec![
                cb(77, 110, 0, CallbackDisposition::Terminal),
                ret(78, 110, 0, ReturnDisposition::Terminal),
            ],
            want: vec![],
            want_stats: stats(0, 0, 2, 0, 0, 0, 0),
            want_finish: vec![],
        },
        // Q07f: sync return contradicting retained callback truth —
        // first truth wins, conflict counted.
        Case {
            name: "sync-return-after-callback-truth-conflicts",
            edges: vec![
                submit(9, 100),
                cb(9, 105, 0, CallbackDisposition::Terminal),
                ret(9, 110, -libc::EIO, ReturnDisposition::Terminal),
            ],
            want: vec![record(9, Terminal::Callback(0), Some(5))],
            want_stats: stats(1, 1, 0, 0, 1, 0, 0),
            want_finish: vec![],
        },
        // Q08: unqualified adapter — Queued return, unresolvable
        // evidence, no terminal ever: Unknown with NO duration.
        Case {
            name: "unqualified-adapter-has-no-terminal-latency",
            edges: vec![
                submit(11, 100),
                ret(11, 105, ebusy, ReturnDisposition::Unresolved),
                cb(11, 120, 0, CallbackDisposition::Unresolved),
            ],
            want: vec![],
            want_stats: stats(1, 0, 0, 0, 2, 0, 0),
            want_finish: vec![record(11, Terminal::Unknown, None)],
        },
        // Q08b: gap-declared loss completes immediately with
        // retained truth when present.
        Case {
            name: "gap-completes-with-retained-truth",
            edges: vec![
                submit(12, 100),
                cb(12, 105, 0, CallbackDisposition::Terminal),
                Edge::Gap {
                    id: 12,
                    reason: GapReason::Deadline,
                },
            ],
            want: vec![record(12, Terminal::Callback(0), Some(5))],
            want_stats: stats(1, 1, 0, 0, 0, 0, 0),
            want_finish: vec![],
        },
        // Q08c: identity-ambiguous gap invalidates even retained
        // truth — Unknown, no duration, invalidation queryable.
        Case {
            name: "identity-gap-invalidates-retained-truth",
            edges: vec![
                submit(13, 100),
                cb(13, 105, 0, CallbackDisposition::Terminal),
                Edge::Gap {
                    id: 13,
                    reason: GapReason::IdentityAmbiguous,
                },
            ],
            want: vec![record(13, Terminal::Unknown, None)],
            want_stats: stats(1, 1, 0, 0, 1, 0, 0),
            want_finish: vec![],
        },
    ];
    for case in cases {
        run_case(case);
    }
    // The invalidation query pins alongside (not a table row — it
    // reads reducer state, not edges).
    let mut r = LifecycleReducer::new(4);
    for edge in [
        submit(13, 100),
        cb(13, 105, 0, CallbackDisposition::Terminal),
        Edge::Gap {
            id: 13,
            reason: GapReason::IdentityAmbiguous,
        },
    ] {
        r.apply(edge);
    }
    assert!(
        r.is_invalidated(13),
        "live identity gap flags the tombstone"
    );
    assert!(!r.is_invalidated(14), "never-admitted ids read clean");
}

// The 8 literal test-plan names, each pinning its headline behavior
// directly (the table above carries the exhaustive rows).

#[test]
fn terminal_before_return_emits_once() {
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(1, 100)).is_empty());
    assert!(
        r.apply(cb(1, 105, 0, CallbackDisposition::Terminal))
            .is_empty()
    );
    let done = r.apply(ret(1, 110, -libc::EINPROGRESS, ReturnDisposition::Queued));
    assert_eq!(done, vec![record(1, Terminal::Callback(0), Some(5))]);
    assert_eq!(r.stats().emitted, 1);
}

#[test]
fn callback_reuse_preserves_old_return() {
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(1, 100)).is_empty());
    assert!(
        r.apply(ret(1, 110, -libc::EINPROGRESS, ReturnDisposition::Queued))
            .is_empty()
    );
    let done = r.apply(cb(1, 120, 0, CallbackDisposition::Terminal));
    assert_eq!(done, vec![record(1, Terminal::Callback(0), Some(20))]);
    // New call reuses the storage (fresh id — the decoder mints it;
    // the old return still names id 1 and cannot alias id 2).
    assert!(r.apply(submit(2, 125)).is_empty());
    assert!(
        r.apply(ret(1, 130, -libc::EINPROGRESS, ReturnDisposition::Queued))
            .is_empty()
    );
    let done = r.apply(ret(2, 140, 0, ReturnDisposition::Terminal));
    assert_eq!(done, vec![record(2, Terminal::Sync(0), Some(15))]);
    assert_eq!(r.stats().duplicate, 1, "old post-completion return");
}

#[test]
fn cross_cpu_terminal_keeps_submitter() {
    // The reducer joins by opaque id alone — CPUs never appear. The
    // submitter's id, transform binding and metadata survive the
    // cross-CPU terminal intact (sensor + live cells prove the CPUs
    // actually differed; here the join key is pinned).
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(7, 100)).is_empty());
    assert!(
        r.apply(ret(7, 110, -libc::EINPROGRESS, ReturnDisposition::Queued))
            .is_empty()
    );
    let done = r.apply(cb(7, 150, 0, CallbackDisposition::Terminal));
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].id, 7);
    assert_eq!(done[0].tfm_id, Some(1));
    assert_eq!(done[0].meta, meta());
    assert_eq!(done[0].duration_ns, Some(50));
    assert!(done[0].evidence_valid());
}

#[test]
fn backlog_progress_is_not_terminal() {
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(3, 100)).is_empty());
    assert!(
        r.apply(ret(3, 105, -libc::EBUSY, ReturnDisposition::Queued))
            .is_empty()
    );
    assert!(
        r.apply(cb(
            3,
            110,
            -libc::EINPROGRESS,
            CallbackDisposition::Progress
        ))
        .is_empty()
    );
    assert_eq!(r.stats().emitted, 0, "progress never completes");
    let done = r.apply(cb(3, 150, 0, CallbackDisposition::Terminal));
    assert_eq!(done, vec![record(3, Terminal::Callback(0), Some(50))]);
}

#[test]
fn no_backlog_enospc_is_immediate_error() {
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(4, 100)).is_empty());
    let done = r.apply(ret(4, 104, -libc::ENOSPC, ReturnDisposition::Terminal));
    assert_eq!(
        done,
        vec![record(4, Terminal::Sync(-libc::ENOSPC), Some(4))]
    );
    assert_eq!(done[0].terminal, Terminal::Sync(-28), "exact native errno");
}

#[test]
fn async_capable_driver_may_complete_sync() {
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(4, 100)).is_empty());
    let done = r.apply(ret(4, 104, 0, ReturnDisposition::Terminal));
    assert_eq!(done, vec![record(4, Terminal::Sync(0), Some(4))]);
}

#[test]
fn duplicate_conflicting_orphan_late_callbacks_are_explicit() {
    let mut r = LifecycleReducer::new(8);
    // Orphan (never admitted).
    assert!(
        r.apply(cb(77, 110, 0, CallbackDisposition::Terminal))
            .is_empty()
    );
    assert_eq!(r.stats().orphan, 1);
    // Duplicate (same status) vs conflicting (other status).
    assert!(r.apply(submit(6, 100)).is_empty());
    assert!(
        r.apply(ret(6, 105, -libc::EINPROGRESS, ReturnDisposition::Queued))
            .is_empty()
    );
    assert_eq!(
        r.apply(cb(6, 110, 0, CallbackDisposition::Terminal)),
        vec![record(6, Terminal::Callback(0), Some(10))]
    );
    assert!(
        r.apply(cb(6, 900, 0, CallbackDisposition::Terminal))
            .is_empty()
    );
    assert_eq!(r.stats().duplicate, 1);
    assert!(
        r.apply(cb(6, 901, -libc::EIO, CallbackDisposition::Terminal))
            .is_empty()
    );
    assert_eq!(r.stats().ambiguous, 1);
    assert_eq!(r.stats().emitted, 1, "at most one terminal record");
}

#[test]
fn unqualified_adapter_has_no_terminal_latency() {
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(11, 100)).is_empty());
    assert!(
        r.apply(ret(11, 105, -libc::EBUSY, ReturnDisposition::Unresolved))
            .is_empty()
    );
    assert!(
        r.apply(cb(11, 120, 0, CallbackDisposition::Unresolved))
            .is_empty()
    );
    let drained = r.finish(9999);
    assert_eq!(drained, vec![record(11, Terminal::Unknown, None)]);
    assert_eq!(drained[0].duration_ns, None, "no terminal latency");
    assert!(!drained[0].evidence_valid());
    assert_eq!(r.stats().unfinished, 1);
}

// ---------------------------------------------------------------------------
// Adapter unit RED (contract §§4–8, 10): classification + identity
// relation. These FAIL (unimplemented shells) until the adapter logic
// lands.
// ---------------------------------------------------------------------------

#[test]
fn adapter_return_classification_table() {
    use ReturnDisposition::{Queued, Terminal, Unresolved};
    // (status, req_flags, want) — exact native errno preserved.
    let table: &[(i32, Option<u32>, ReturnDisposition)] = &[
        (-libc::EINPROGRESS, None, Queued),
        (-libc::EINPROGRESS, Some(0), Queued),
        (-libc::EBUSY, Some(MAY_BACKLOG), Queued),
        (-libc::EBUSY, Some(MAY_BACKLOG | 0x200), Queued),
        (-libc::EBUSY, Some(0), Unresolved),
        (-libc::EBUSY, None, Unresolved),
        (-libc::ENOSPC, None, Terminal),
        (-libc::ENOSPC, Some(0), Terminal),
        (-libc::ENOSPC, Some(MAY_BACKLOG), Terminal),
        (0, None, Terminal),
        (0, Some(MAY_BACKLOG), Terminal),
        (-libc::EINVAL, None, Terminal),
        (-libc::ENOKEY, Some(0), Terminal),
        (7, None, Terminal),
    ];
    for (status, flags, want) in table {
        assert_eq!(
            classify_return(*status, *flags),
            *want,
            "status {status} flags {flags:?}"
        );
    }
}

#[test]
fn adapter_callback_classification() {
    use CallbackDisposition::{Progress, Terminal};
    assert_eq!(classify_callback(-libc::EINPROGRESS), Progress);
    for status in [
        0,
        1,
        -libc::EIO,
        -libc::EBADMSG,
        -libc::ENOSPC,
        -libc::EBUSY,
    ] {
        assert_eq!(classify_callback(status), Terminal, "status {status}");
    }
}

#[test]
fn adapter_relation_join_and_retire() {
    let mut a = AsyncAdapter::new(8);
    // Cover from admission; early callback joins before any return.
    a.note_submit(0xAAA, 1, 100);
    let edges = a.resolve_callback(0xAAA, 105, 0);
    assert_eq!(
        edges,
        vec![Edge::Callback {
            id: 1,
            ts_ns: 105,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        }]
    );
    // Terminal callback retired the token: a late duplicate rejoins
    // the tombstone for reducer-side diagnosis (same id, no orphan).
    let edges = a.resolve_callback(0xAAA, 900, 0);
    assert_eq!(edges.len(), 1);
    assert!(matches!(edges[0], Edge::Callback { id: 1, .. }));
    assert_eq!(a.stats().callback_orphans, 0);
    // Unknown key: counted orphan, no edge.
    assert!(a.resolve_callback(0xBBB, 910, 0).is_empty());
    assert_eq!(a.stats().callback_orphans, 1);
}

#[test]
fn adapter_relation_progress_never_retires() {
    let mut a = AsyncAdapter::new(8);
    a.note_submit(0xAAA, 1, 100);
    // Progress joins (same id) but the token stays live: the later
    // terminal still joins live (not via tombstone).
    let edges = a.resolve_callback(0xAAA, 110, -libc::EINPROGRESS);
    assert_eq!(
        edges,
        vec![Edge::Callback {
            id: 1,
            ts_ns: 110,
            status: -libc::EINPROGRESS,
            disposition: CallbackDisposition::Progress,
        }]
    );
    let edges = a.resolve_callback(0xAAA, 150, 0);
    assert!(matches!(edges[0], Edge::Callback { id: 1, .. }));
    assert_eq!(a.stats().callback_orphans, 0);
}

#[test]
fn adapter_relation_ambiguous_key_gaps_all() {
    let mut a = AsyncAdapter::new(8);
    // Two live tokens under one key (storage reused while live):
    // the callback is genuinely unattributable — gap BOTH loud.
    a.note_submit(0xAAA, 1, 100);
    a.note_submit(0xAAA, 2, 101);
    let edges = a.resolve_callback(0xAAA, 120, 0);
    assert_eq!(edges.len(), 2, "one gap per live token");
    for edge in &edges {
        assert!(matches!(
            edge,
            Edge::Gap {
                reason: GapReason::IdentityAmbiguous,
                ..
            }
        ));
    }
    let mut ids: Vec<u64> = edges
        .iter()
        .map(|e| match e {
            Edge::Gap { id, .. } => *id,
            _ => unreachable!(),
        })
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2]);
    assert_eq!(a.stats().ambiguous_keys, 1);
    // Gapped tokens tombstone: a late callback rejoins the newest
    // for diagnosis instead of gapping again.
    let edges = a.resolve_callback(0xAAA, 900, 0);
    assert_eq!(edges.len(), 1);
    assert!(matches!(edges[0], Edge::Callback { id: 2, .. }));
    assert_eq!(a.stats().ambiguous_keys, 1, "no second gap storm");
}

#[test]
fn adapter_may_backlog_value_pins_kernel_truth() {
    // Edit tripwire for the contract constant (the VALUE's truth is
    // the kernel source citation + the live burst cell, which sets
    // this bit from real kernel headers end to end).
    assert_eq!(MAY_BACKLOG, 0x400);
}

#[test]
fn adapter_stale_callback_is_consumed_not_joined() {
    let mut a = AsyncAdapter::new(8);
    a.note_submit(0xAAA, 1, 100);
    // Scrambled timestamp (predates the submit): twin drift —
    // consumed, counted, never joined; cover kept for the real one.
    assert!(a.resolve_callback(0xAAA, 50, 0).is_empty());
    assert_eq!(a.stats().stale_callbacks, 1);
    assert_eq!(a.stats().callback_orphans, 0);
    let edges = a.resolve_callback(0xAAA, 150, 0);
    assert!(matches!(edges[0], Edge::Callback { id: 1, .. }));
    // Ties join (coarse-clock ambiguity, same as decoder returns).
    let mut b = AsyncAdapter::new(8);
    b.note_submit(0xAAA, 1, 100);
    assert!(!b.resolve_callback(0xAAA, 100, 0).is_empty());
    assert_eq!(b.stats().stale_callbacks, 0);
}

#[test]
fn adapter_gap_retires_to_tombstone() {
    let mut a = AsyncAdapter::new(8);
    a.note_submit(0xAAA, 1, 100);
    a.note_gap(0xAAA, 1);
    // The gapped token tombstones: late callbacks diagnose against
    // the gap completion (Unknown) as suppressed duplicates.
    let edges = a.resolve_callback(0xAAA, 900, 0);
    assert_eq!(edges.len(), 1);
    assert!(matches!(edges[0], Edge::Callback { id: 1, .. }));
    assert_eq!(a.stats().callback_orphans, 0);
}

#[test]
fn adapter_relation_exhaustion_refuses_cover() {
    let mut a = AsyncAdapter::new(2);
    a.note_submit(0xA01, 1, 100);
    a.note_submit(0xA02, 2, 100);
    // Live pool full: the third submit is admitted WITHOUT cover
    // (counted) — its callback arrives as an orphan, never a misjoin.
    a.note_submit(0xA03, 3, 100);
    assert_eq!(a.stats().cover_refused, 1);
    assert!(a.resolve_callback(0xA03, 100, 0).is_empty());
    assert_eq!(a.stats().callback_orphans, 1);
    // Covered tokens still join.
    assert!(!a.resolve_callback(0xA01, 100, 0).is_empty());
}

#[test]
fn adapter_relation_tombstones_evict_fifo() {
    let mut a = AsyncAdapter::new(2);
    // Fill live, retire both via terminal callbacks (→ tombstones).
    a.note_submit(0xA01, 1, 100);
    a.note_submit(0xA02, 2, 100);
    a.resolve_callback(0xA01, 100, 0);
    a.resolve_callback(0xA02, 100, 0);
    // Retire a third (live has room again): oldest tombstone evicts.
    a.note_submit(0xA03, 3, 100);
    a.resolve_callback(0xA03, 100, 0);
    assert_eq!(a.stats().tombstone_evictions, 1);
    // Evicted history reads orphan; retained tombstones rejoin.
    assert!(a.resolve_callback(0xA01, 900, 0).is_empty());
    assert_eq!(a.stats().callback_orphans, 1);
    assert!(!a.resolve_callback(0xA03, 900, 0).is_empty());
}

#[test]
fn adapter_sync_return_retires_without_disturbing() {
    let mut a = AsyncAdapter::new(8);
    // Sync nesting (same key, inner completes first): no callback
    // arrives, both tokens retire via sync returns, nothing gaps.
    a.note_submit(0xAAA, 1, 100);
    a.note_submit(0xAAA, 2, 101);
    a.note_sync_return(0xAAA, 2);
    a.note_sync_return(0xAAA, 1);
    assert_eq!(a.stats().ambiguous_keys, 0);
    assert_eq!(a.stats().callback_orphans, 0);
    // A late callback after both sync returns rejoins the newest
    // tombstone for diagnosis (never an orphan, never a misjoin).
    let edges = a.resolve_callback(0xAAA, 900, 0);
    assert_eq!(edges.len(), 1);
    assert!(matches!(edges[0], Edge::Callback { id: 1, .. }));
}

// ---------------------------------------------------------------------------
// Decode + sensor RED (contract §11): callback twin validation, the
// disposition feed, and the end-to-end async shapes. These FAIL on
// current code (kind 3 refuses as BadEdge; EBUSY never queues;
// callbacks never join) until the decode + sensor waves land.
// ---------------------------------------------------------------------------
//
// Local wire literals (contract §11 values; the behavioral tests
// below pin them against the ABI consts the moment those land — a
// divergence fails decode, loudly).
const SUBMIT: u8 = 1;
const RETURN: u8 = 2;
const CALLBACK: u8 = 3;
const ENC: u16 = 1;
const CB_CRYPTD: u16 = 3;
const CB_KXC: u16 = 4;

/// One 112-byte v6 `LEdge` submit/return (twin of the T08 builder).
#[allow(clippy::too_many_arguments)]
fn edge_v6(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    invoc: u64,
    tfm: u64,
    cryptlen: Option<u32>,
    req_flags: Option<u32>,
    drv: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 6;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    if edge == SUBMIT {
        let mut mflags = 0u16;
        if let Some(c) = cryptlen {
            out[28..32].copy_from_slice(&c.to_le_bytes());
            mflags |= 0x01;
        }
        if let Some(f) = req_flags {
            out[48..52].copy_from_slice(&f.to_le_bytes());
            mflags |= 0x02;
        }
        out[52] = 1;
        out[53] = site as u8;
        out[54..56].copy_from_slice(&mflags.to_le_bytes());
        let n = drv.len().min(55);
        out[56..56 + n].copy_from_slice(&drv[..n]);
    }
    out[32..40].copy_from_slice(&invoc.to_le_bytes());
    out[40..48].copy_from_slice(&tfm.to_le_bytes());
    out
}

/// One 112-byte v6 `LEdge` callback half (contract §11): key +
/// status + ts; invoc 0 (names no fsession invocation); zero
/// metadata/tfm/drv (submit owns those facts); flags 0.
fn cb_v6(site: u16, key: u64, ts_ns: u64, status: i32) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 6;
    out[3] = CALLBACK;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out
}

fn op_submit(key: u64, ts: u64, invoc: u64, frontend: u64, flags: Option<u32>) -> Vec<u8> {
    edge_v6(
        SUBMIT,
        ENC,
        key,
        ts,
        0,
        invoc,
        frontend,
        Some(16),
        flags,
        b"kxcipher-async",
    )
}

fn op_return(key: u64, ts: u64, invoc: u64, status: i32) -> Vec<u8> {
    edge_v6(RETURN, ENC, key, ts, status, invoc, 0, None, None, b"")
}

use kryprobe_privilege::kcrypto_lifecycle::decode::{DecodeDrop, LifecycleDecoder, decode_record};
use kryprobe_privilege::kcrypto_lifecycle::sensor::{EnrichmentStatus, SensorCore, SessionContext};

fn ctx() -> SessionContext {
    SessionContext {
        loss_baseline: [0; 5],
        agg_baseline: [0; 18],
        view_valid: true,
        miss_baseline: Vec::new(),
        enrichment: EnrichmentStatus::Available {
            entries: 0,
            truncated: false,
        },
    }
}

#[test]
fn decode_accepts_callback_halves() {
    // Both qualified sites validate with key + status + ts.
    for site in [CB_CRYPTD, CB_KXC] {
        let raw = decode_record(&cb_v6(site, 0xAAA, 150, 0)).expect("callback validates");
        assert_eq!(raw.edge, CALLBACK);
        assert_eq!(raw.site, site);
        assert_eq!(raw.key, 0xAAA);
        assert_eq!(raw.ts_ns, 150);
        assert_eq!(raw.status, 0);
        assert_eq!(raw.invoc, 0);
        assert!(!raw.tainted);
    }
    // Any status validates (classification is the adapter's job —
    // twin validation never judges errno values).
    for status in [-libc::EINPROGRESS, -libc::ENOSPC, 7, i32::MIN] {
        decode_record(&cb_v6(CB_CRYPTD, 0xAAA, 150, status)).expect("any status validates");
    }
}

#[test]
fn decode_refuses_callback_twin_drift() {
    // (mutator, want-drop) — every callback-half invariant pinned.
    let mut bad_site = cb_v6(ENC, 0xAAA, 150, 0);
    bad_site[3] = CALLBACK;
    let mut bad_invoc = cb_v6(CB_CRYPTD, 0xAAA, 150, 0);
    bad_invoc[32] = 9; // invoc != 0 names a phantom invocation
    let mut bad_flags = cb_v6(CB_CRYPTD, 0xAAA, 150, 0);
    bad_flags[6] = 1; // tainted: callbacks never taint (no cookie)
    let mut bad_meta = cb_v6(CB_CRYPTD, 0xAAA, 150, 0);
    bad_meta[28] = 3; // nonzero cryptlen without validity
    let mut bad_tfm = cb_v6(CB_CRYPTD, 0xAAA, 150, 0);
    bad_tfm[40] = 8; // return-side word discipline extended
    let mut bad_drv = cb_v6(CB_CRYPTD, 0xAAA, 150, 0);
    bad_drv[56] = b'x'; // callbacks carry no name
    let mut null_key = cb_v6(CB_CRYPTD, 0, 150, 0);
    null_key[8..16].copy_from_slice(&0u64.to_le_bytes());
    let table: &[(&[u8], DecodeDrop)] = &[
        (&bad_site, DecodeDrop::BadSite),
        (&bad_invoc, DecodeDrop::BadInvoc),
        (&bad_flags, DecodeDrop::BadFlags),
        (&bad_meta, DecodeDrop::BadMeta),
        (&bad_tfm, DecodeDrop::BadReturnTfm),
        (&bad_drv, DecodeDrop::BadDrv),
        (&null_key, DecodeDrop::NullKey),
    ];
    for (bytes, want) in table {
        assert_eq!(decode_record(bytes), Err(*want), "want {want:?}");
    }
}

#[test]
fn decode_callback_joins_token() {
    // Submit → queued return → callback: the callback edge names
    // the SAME opaque id (relation-joined, not invocation-joined).
    let mut d = LifecycleDecoder::new(8);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let sub = decode_record(&op_submit(0xAAA, 100, 0x4000, frontend, Some(0))).unwrap();
    let edges = d.join(sub);
    assert_eq!(edges.len(), 1);
    let id = match edges[0] {
        Edge::Submit { id, .. } => id,
        _ => panic!("want submit"),
    };
    let ret = decode_record(&op_return(0xAAA, 110, 0x4000, -libc::EINPROGRESS)).unwrap();
    let edges = d.join(ret);
    assert_eq!(edges.len(), 1);
    assert!(matches!(
        edges[0],
        Edge::Return {
            disposition: ReturnDisposition::Queued,
            ..
        }
    ));
    let cb = decode_record(&cb_v6(CB_CRYPTD, 0xAAA, 150, 0)).unwrap();
    let edges = d.join(cb);
    assert_eq!(
        edges,
        vec![Edge::Callback {
            id,
            ts_ns: 150,
            status: 0,
            disposition: CallbackDisposition::Terminal,
        }]
    );
}

#[test]
fn sensor_async_terminal_end_to_end() {
    let mut core = SensorCore::new(64, 64, 64, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(0)),
        op_return(0xAAA, 110, 0x4000, -libc::EINPROGRESS),
        cb_v6(CB_CRYPTD, 0xAAA, 150, 0),
    ];
    assert_eq!(core.ingest_records(&recs), 1, "one terminal record");
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].terminal, Terminal::Callback(0));
    assert_eq!(done[0].duration_ns, Some(50), "submit→callback span");
    assert_eq!(done[0].tfm_id, Some(1));
    assert_eq!(done[0].meta.cryptlen, Some(16));
    assert!(done[0].evidence_valid());
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.decode.admitted, 1);
    assert_eq!(ledger.decode.bad_records, 0);
    assert_eq!(ledger.reducer.emitted, 1);
}

#[test]
fn sensor_queued_without_callback_drains_unknown() {
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(0)),
        op_return(0xAAA, 110, 0x4000, -libc::EINPROGRESS),
    ];
    assert_eq!(core.ingest_records(&recs), 0, "nothing terminal yet");
    core.finish(9999);
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].terminal, Terminal::Unknown);
    assert_eq!(done[0].duration_ns, None, "no terminal latency");
    assert!(!done[0].evidence_valid());
}

#[test]
fn sensor_enospc_is_sync_terminal_exact() {
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    // No MAY_BACKLOG at submit + full queue: the driver answers
    // -ENOSPC immediately — terminal, exact, no callback follows.
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(0)),
        op_return(0xAAA, 104, 0x4000, -libc::ENOSPC),
    ];
    assert_eq!(core.ingest_records(&recs), 1);
    let done = core.take_completed();
    assert_eq!(done[0].terminal, Terminal::Sync(-libc::ENOSPC));
    assert_eq!(done[0].terminal, Terminal::Sync(-28), "never rewritten");
    assert_eq!(done[0].duration_ns, Some(4));
}

#[test]
fn sensor_ebusy_queues_only_with_backlog_consent() {
    let frontend = 0xFFFF_8880_0000_1000_u64;
    // WITH May-backlog: Queued (terminal via the later callback).
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(MAY_BACKLOG)),
        op_return(0xAAA, 105, 0x4000, -libc::EBUSY),
        cb_v6(CB_KXC, 0xAAA, 150, 0),
    ];
    assert_eq!(
        core.ingest_records(&recs),
        1,
        "backlog completes via callback"
    );
    let done = core.take_completed();
    assert_eq!(done[0].terminal, Terminal::Callback(0));
    // WITHOUT consent: Unresolved (loud, never completes).
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(0)),
        op_return(0xAAA, 105, 0x4000, -libc::EBUSY),
    ];
    assert_eq!(core.ingest_records(&recs), 0, "unresolved never completes");
    core.finish(9999);
    let done = core.take_completed();
    assert_eq!(done[0].terminal, Terminal::Unknown);
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(
        ledger.reducer.ambiguous, 1,
        "unresolvable evidence stays loud"
    );
    // Unknown flags (entry chase unreadable): consent never assumed.
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, None),
        op_return(0xAAA, 105, 0x4000, -libc::EBUSY),
    ];
    assert_eq!(core.ingest_records(&recs), 0);
}

#[test]
fn sensor_backlog_progress_shape() {
    // Burst shape (fixture depth-1, MAY_BACKLOG): submit 0 queues,
    // submits 1..3 backlog; progress callbacks never complete; each
    // terminal lands exactly once with its callback span.
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let mut recs = Vec::new();
    for (i, key) in [0xA0u64, 0xA1, 0xA2, 0xA3].iter().enumerate() {
        let invoc = 0x4000 + (i as u64) * 2;
        let want_ret = if i == 0 {
            -libc::EINPROGRESS
        } else {
            -libc::EBUSY
        };
        recs.push(op_submit(
            *key,
            100 + i as u64,
            invoc,
            frontend,
            Some(MAY_BACKLOG),
        ));
        recs.push(op_return(*key, 110 + i as u64, invoc, want_ret));
    }
    // Cryptd drain order: P1,T0,P2,T1,P3,T2,T3.
    let prog = |key: u64, ts: u64| cb_v6(CB_KXC, key, ts, -libc::EINPROGRESS);
    let term = |key: u64, ts: u64| cb_v6(CB_KXC, key, ts, 0);
    recs.push(prog(0xA1, 200));
    recs.push(term(0xA0, 201));
    recs.push(prog(0xA2, 202));
    recs.push(term(0xA1, 203));
    recs.push(prog(0xA3, 204));
    recs.push(term(0xA2, 205));
    recs.push(term(0xA3, 206));
    assert_eq!(core.ingest_records(&recs), 4, "four terminals, no more");
    let done = core.take_completed();
    assert_eq!(done.len(), 4);
    for r in &done {
        assert_eq!(r.terminal, Terminal::Callback(0));
        assert!(r.duration_ns.is_some(), "callback span present");
        assert!(r.evidence_valid());
    }
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.reducer.emitted, 4);
    assert_eq!(ledger.reducer.ambiguous, 0);
    assert_eq!(ledger.reducer.orphan, 0);
}

#[test]
fn sensor_callback_before_return_with_reuse() {
    // Early terminal, then storage reuse for a new call, then the
    // old return: the old return joins the OLD id (by invocation),
    // never the new call.
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(0)),
        cb_v6(CB_CRYPTD, 0xAAA, 105, 0),
        op_submit(0xAAA, 108, 0x4002, frontend, Some(0)),
        op_return(0xAAA, 110, 0x4000, -libc::EINPROGRESS),
        op_return(0xAAA, 120, 0x4002, 0),
    ];
    assert_eq!(core.ingest_records(&recs), 2);
    let done = core.take_completed();
    assert_eq!(done.len(), 2);
    // Old id: callback truth (span 5), NOT the new call's return.
    assert_eq!(done[0].terminal, Terminal::Callback(0));
    assert_eq!(done[0].duration_ns, Some(5));
    // New id: its own sync result (span 12).
    assert_eq!(done[1].terminal, Terminal::Sync(0));
    assert_eq!(done[1].duration_ns, Some(12));
    assert_ne!(done[0].id, done[1].id);
}

#[test]
fn sensor_sync_on_async_capable_driver() {
    // An async-capable driver (MAY_BACKLOG submit) may still answer
    // synchronously: the RETURN classification decides, not flags.
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(MAY_BACKLOG)),
        op_return(0xAAA, 104, 0x4000, 0),
    ];
    assert_eq!(core.ingest_records(&recs), 1);
    let done = core.take_completed();
    assert_eq!(done[0].terminal, Terminal::Sync(0));
    assert_eq!(
        done[0].meta.req_flags,
        Some(MAY_BACKLOG),
        "flags ride along"
    );
}

#[test]
fn sensor_unqualified_leaves_no_terminal_latency() {
    // AF_ALG-shaped traffic (unhooked completion): Queued return,
    // never a callback — Unknown with no duration, even though the
    // op really completed somewhere unobserved.
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let frontend = 0xFFFF_8880_0000_1000_u64;
    let recs = vec![
        op_submit(0xAAA, 100, 0x4000, frontend, Some(0)),
        op_return(0xAAA, 110, 0x4000, -libc::EINPROGRESS),
    ];
    assert_eq!(core.ingest_records(&recs), 0);
    core.finish(5000);
    let done = core.take_completed();
    assert_eq!(done[0].terminal, Terminal::Unknown);
    assert_eq!(done[0].duration_ns, None);
    // The submit's metadata still rides (observed fact, not truth).
    assert_eq!(done[0].meta.cryptlen, Some(16));
}

#[test]
fn adapter_note_submit_reports_cover_refusal() {
    // P4-N2 (adapter level): `note_submit` reports whether the
    // submit earned cover — the decoder retains contention for
    // refused submits so no later callback can misjoin.
    let mut a = AsyncAdapter::new(1);
    assert!(a.note_submit(0xC01, 1, 100));
    assert!(!a.note_submit(0xC01, 2, 200));
    assert_eq!(a.stats().cover_refused, 1);
}

#[test]
fn adapter_gap_key_invalidates_loud_or_orphans() {
    // P4-N2 (adapter level): `gap_key` gaps EVERY live token under
    // the key (counted ambiguity, edges for the reducer) — and
    // when no live token remains, the unattributable evidence reads
    // orphan (counted, never joined to a tombstone).
    let mut a = AsyncAdapter::new(2);
    a.note_submit(0xC02, 1, 100);
    let edges = a.gap_key(0xC02);
    assert_eq!(edges.len(), 1);
    assert!(
        matches!(
            edges[0],
            Edge::Gap {
                id: 1,
                reason: GapReason::IdentityAmbiguous
            }
        ),
        "contended key must gap its live token, got {:?}",
        edges[0]
    );
    assert_eq!(a.stats().ambiguous_keys, 1);
    assert!(a.gap_key(0xC02).is_empty());
    assert_eq!(a.stats().callback_orphans, 1);
}

#[test]
fn sensor_refused_same_key_reuse_cannot_complete_old_token() {
    // P4-N2 (sensor level): capacity 1; A submits/returns, its
    // terminal unobserved; the caller legally reuses the completed
    // storage for B (adapter cover refused — pool full); B's
    // callback must NEVER terminally complete A. A gaps loud
    // (Unknown, no span); B drains truthless; the refusal and the
    // ambiguity both count.
    let frontend = 0xFFFF_8880_0000_2000_u64;
    let mut core = SensorCore::new(1, 8, 8, 8, true);
    core.ingest_records(&[
        op_submit(0xBBB, 100, 0x5000, frontend, Some(0)),
        op_return(0xBBB, 110, 0x5000, -libc::EINPROGRESS),
        op_submit(0xBBB, 200, 0x5002, frontend, Some(0)),
        op_return(0xBBB, 210, 0x5002, -libc::EINPROGRESS),
        cb_v6(CB_CRYPTD, 0xBBB, 250, 0),
    ]);
    core.finish(5000);
    let done = core.take_completed();
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.adapter.cover_refused, 1);
    assert_eq!(ledger.adapter.ambiguous_keys, 1);
    assert!(
        !done.iter().any(|r| r.terminal == Terminal::Callback(0)),
        "B's callback must never supply a terminal result: {done:?}"
    );
    let old = done.iter().find(|r| r.id == 1).expect("A completes");
    assert_eq!(old.terminal, Terminal::Unknown);
    assert_eq!(old.duration_ns, None);
}

#[test]
fn sensor_refused_sync_reuse_clears_contention() {
    // P4-N2 (precision): a refused same-key submit that completes
    // SYNCHRONOUSLY never needs callback attribution — its return
    // clears the contention, so the old token's own callback still
    // joins cleanly (no gap, no ambiguity).
    let frontend = 0xFFFF_8880_0000_3000_u64;
    let mut core = SensorCore::new(1, 8, 8, 8, true);
    core.ingest_records(&[
        op_submit(0xCCC, 100, 0x6000, frontend, Some(0)),
        op_return(0xCCC, 110, 0x6000, -libc::EINPROGRESS),
        // Same storage, refused cover — but a sync result.
        op_submit(0xCCC, 200, 0x6002, frontend, Some(0)),
        op_return(0xCCC, 210, 0x6002, 0),
        // A's own terminal: joins (contention cleared).
        cb_v6(CB_CRYPTD, 0xCCC, 250, 0),
    ]);
    core.finish(5000);
    let done = core.take_completed();
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.adapter.cover_refused, 1);
    assert_eq!(ledger.adapter.ambiguous_keys, 0);
    let old = done.iter().find(|r| r.id == 1).expect("A completes");
    assert_eq!(old.terminal, Terminal::Callback(0));
    assert_eq!(old.duration_ns, Some(150));
}

#[test]
fn sensor_refusal_contention_overflow_invalidates_loud() {
    // P4-N2 (bound): refusal contention is decode-scale bounded —
    // past capacity the oldest contention is forgotten LOUD (its
    // key's live tokens gap immediately) instead of growing
    // without bound or misjoining silently.
    let frontend = 0xFFFF_8880_0000_4000_u64;
    let mut core = SensorCore::new(1, 8, 8, 8, true);
    core.ingest_records(&[
        // A covered (live pool full).
        op_submit(0xD01, 100, 0x7000, frontend, Some(0)),
        op_return(0xD01, 110, 0x7000, -libc::EINPROGRESS),
        // B refused (first contention).
        op_submit(0xD01, 200, 0x7002, frontend, Some(0)),
        op_return(0xD01, 210, 0x7002, -libc::EINPROGRESS),
        // C refused (overflow: B's contention forgotten loud —
        // A gaps NOW, at C's submit).
        op_submit(0xD02, 300, 0x7004, frontend, Some(0)),
        op_return(0xD02, 310, 0x7004, -libc::EINPROGRESS),
    ]);
    core.finish(5000);
    let done = core.take_completed();
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.adapter.cover_refused, 2);
    assert_eq!(ledger.adapter.ambiguous_keys, 1);
    let old = done.iter().find(|r| r.id == 1).expect("A completes");
    assert_eq!(old.terminal, Terminal::Unknown);
    assert_eq!(old.duration_ns, None);
}

#[test]
fn adapter_debug_redacts_pairing_keys() {
    // P4-N3: pairing keys render `<redacted>` at EVERY render —
    // live AND tombstoned — per the allowlist redaction rule.
    let key = 0xffff_8880_1234_5678_u64; // synthetic, never a real pointer
    let mut a = AsyncAdapter::new(2);
    a.note_submit(key, 1, 100);
    let live = format!("{a:?}");
    // Scan-visible renders (the P4r2 privacy scan re-checks these
    // lines independently: key absent, marker present).
    eprintln!("ADAPTER_RENDER live={live}");
    assert!(
        !live.contains(&key.to_string()),
        "live render leaks pairing key: {live}"
    );
    a.note_sync_return(key, 1);
    let dead = format!("{a:?}");
    eprintln!("ADAPTER_RENDER dead={dead}");
    eprintln!("ADAPTER_KEY {key}");
    assert!(
        !dead.contains(&key.to_string()),
        "tombstone render leaks pairing key: {dead}"
    );
    assert!(
        live.contains("<redacted>") && dead.contains("<redacted>"),
        "renders must carry the redaction marker: {live} / {dead}"
    );
}

#[test]
fn sensor_decoder_refusal_cannot_complete_old_token() {
    // P4R2-N1 (sensor level): capacity 1; A submits/returns, its
    // terminal unobserved; an unrelated D occupies the decoder;
    // the caller legally reuses A's completed storage for B and the
    // DECODER refuses B (full table — before adapter cover is even
    // attempted). The refused submit keeps contention, so B's
    // callback gaps A loud (Unknown, no span) instead of joining
    // the old covered token; D still completes exactly.
    let frontend = 0xFFFF_8880_0000_9000_u64;
    let mut core = SensorCore::new(1, 8, 8, 8, true);
    core.ingest_records(&[
        op_submit(0xE10, 100, 0x9000, frontend, Some(0)),
        op_return(0xE10, 110, 0x9000, -libc::EINPROGRESS),
        // Unrelated invocation occupies the decoder table.
        op_submit(0xE20, 180, 0x9002, frontend, Some(0)),
        // Legal reuse of A's storage; the full decoder refuses B.
        op_submit(0xE10, 200, 0x9004, frontend, Some(0)),
        op_return(0xE10, 210, 0x9004, -libc::EINPROGRESS),
        // B's real terminal: unattributable under contention.
        cb_v6(CB_CRYPTD, 0xE10, 250, 0),
        op_return(0xE20, 300, 0x9002, 0),
    ]);
    core.finish(5000);
    let done = core.take_completed();
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.decode.submit_refused, 1);
    assert_eq!(ledger.decode.bad_records, 0);
    assert_eq!(ledger.adapter.ambiguous_keys, 1);
    let old = done.iter().find(|r| r.id == 1).expect("A completes");
    assert_eq!(old.terminal, Terminal::Unknown);
    assert_eq!(old.duration_ns, None);
    let other = done.iter().find(|r| r.id == 2).expect("D completes");
    assert_eq!(other.terminal, Terminal::Sync(0));
    assert_eq!(other.duration_ns, Some(120));
}

#[test]
fn sensor_decoder_refusal_production_bounds_cannot_complete_old_token() {
    // P4R2-N1 at the production 4096/4096/4096 bounds (sensor
    // arm scale): the decoder still refuses the same-key reuse,
    // and the refused submit keeps contention — A gaps loud with
    // zero malformed records.
    let frontend = 0xFFFF_8880_0000_9100_u64;
    let mut core = SensorCore::new(4096, 4096, 4096, 8, true);
    core.ingest_records(&[
        op_submit(0xE10, 100, 0x9000, frontend, Some(0)),
        op_return(0xE10, 110, 0x9000, -libc::EINPROGRESS),
    ]);
    // A's terminal is unavailable. Fill the outstanding table
    // with distinct calls whose returns are not yet observed.
    for i in 0..4096_u64 {
        core.ingest_records(&[op_submit(
            0x20000 + 2 * i,
            120,
            0x40000 + 2 * i,
            frontend,
            Some(0),
        )]);
    }
    core.ingest_records(&[
        op_submit(0xE10, 200, 0x60000, frontend, Some(0)),
        op_return(0xE10, 210, 0x60000, -libc::EINPROGRESS),
        cb_v6(CB_CRYPTD, 0xE10, 250, 0),
    ]);
    core.finish(5000);
    let done = core.take_completed();
    let ledger = core.ledger([0; 5], [0; 18], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.decode.submit_refused, 1);
    assert_eq!(ledger.decode.bad_records, 0);
    assert_eq!(ledger.adapter.ambiguous_keys, 1);
    let old = done.iter().find(|r| r.id == 1).expect("A completes");
    assert_eq!(old.terminal, Terminal::Unknown);
    assert_eq!(old.duration_ns, None);
}
