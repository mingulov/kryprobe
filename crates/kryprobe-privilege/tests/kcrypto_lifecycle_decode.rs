// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 decode suite: raw `LEdge` bytes → T05 `Edge` events + join rules.
//!
//! Pins the v3 record twin (magic/version/edge/site/flags/aux/invoc/length),
//! the key→opaque-id join (fresh id per admission, bounded table),
//! return classification (sync-terminal vs queued), and the named loss
//! counters. BPF taints nested submits/returns (`LEDGE_TAINTED`) and the
//! decoder refuses them without disturbing the outstanding id — the
//! round-2 counterexample (reuse then late return joining the wrong
//! invocation) cannot complete. A same-key clean submit while an id is
//! outstanding means transport loss (the BPF slot empties only on a
//! return emit, so honest BPF never nests clean): the old id gaps
//! `IdentityAmbiguous` and the new submit admits fresh; its return
//! joins current (coarse-clock ties join — pinned).

use kryprobe_core::kcrypto::{Edge, GapReason, ReturnDisposition};
use kryprobe_privilege::kcrypto_lifecycle::decode::{
    DecodeDrop, DecodeStats, LifecycleDecoder, decode_record,
};

/// `LEDGE_TAINTED` flag bit (BPF nesting taint; mirrors the ABI const).
const TAINTED: u16 = 0x0001;

/// One 40-byte v3 `LEdge` (little-endian twin of the ABI struct).
fn edge_bytes_invoc(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    flags: u16,
    invoc: u64,
) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 3;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[6..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out[32..40].copy_from_slice(&invoc.to_le_bytes());
    out
}

/// Realistic default builder: same v3 record with a VALID
/// invocation (nonzero, poison-bit clear — the W2/W4 join tests
/// don't vary invocation, so equality holds; tests that do use
/// [`edge_bytes_invoc`] explicitly).
fn edge_bytes(edge: u8, site: u16, key: u64, ts_ns: u64, status: i32, flags: u16) -> [u8; 40] {
    edge_bytes_invoc(edge, site, key, ts_ns, status, flags, 0x4000)
}

#[test]
fn decode_record_accepts_valid_submit_and_return() {
    let raw = decode_record(&edge_bytes(1, 1, 0xabc, 100, 0, 0)).expect("valid submit parses");
    assert_eq!(
        (
            raw.edge, raw.site, raw.key, raw.ts_ns, raw.status, raw.invoc
        ),
        (1, 1, 0xabc, 100, 0, 0x4000)
    );
    let raw =
        decode_record(&edge_bytes_invoc(2, 1, 0xabc, 150, 0, 0, 0x4002)).expect("invoc parses");
    assert_eq!(raw.invoc, 0x4002);
    let raw = decode_record(&edge_bytes(2, 2, 0xdef, 200, -5, 0)).expect("valid return parses");
    assert_eq!(
        (raw.edge, raw.site, raw.key, raw.ts_ns, raw.status),
        (2, 2, 0xdef, 200, -5)
    );
}

#[test]
fn decode_record_rejects_twin_drift() {
    // Bad magic / version / edge / site / flags / aux each name their drop.
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[0] = 0;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMagic));
    // v1 AND v2 records refuse (fail closed across versions: an
    // old decoder would misread the longer v3 record, so versions
    // never mix).
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[2] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadVersion));
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[2] = 2;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadVersion));
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[2] = 4;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadVersion));
    assert_eq!(
        decode_record(&edge_bytes(3, 1, 9, 1, 0, 0)),
        Err(DecodeDrop::BadEdge)
    );
    assert_eq!(
        decode_record(&edge_bytes(1, 9, 9, 1, 0, 0)),
        Err(DecodeDrop::BadSite)
    );
    // Only the taint bit is defined; any other flag bit is drift.
    let tainted = decode_record(&edge_bytes(1, 1, 9, 1, 0, TAINTED)).expect("taint parses");
    assert!(tainted.tainted);
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[6] = 0x02;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadFlags));
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[28] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadAux));
    // Submit edges carry status 0 (ABI): a nonzero submit status is
    // twin drift, rejected — never silently discarded.
    assert_eq!(
        decode_record(&edge_bytes(1, 1, 9, 1, -5, 0)),
        Err(DecodeDrop::BadSubmitStatus)
    );
    // Returns keep their full i32 range.
    decode_record(&edge_bytes(2, 1, 9, 1, -5, 0)).expect("return status parses");
}

#[test]
fn decode_record_rejects_shape_and_null_key() {
    assert_eq!(decode_record(&[0u8; 39]), Err(DecodeDrop::BadLength));
    assert_eq!(decode_record(&[0u8; 41]), Err(DecodeDrop::BadLength));
    assert_eq!(
        decode_record(&edge_bytes(1, 1, 0, 1, 0, 0)),
        Err(DecodeDrop::NullKey)
    );
}

#[test]
fn feed_pairs_submit_with_sync_return() {
    let mut dec = LifecycleDecoder::new(16);
    let out = dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
    assert_eq!(out.len(), 1);
    let Edge::Submit { id, tfm_id, ts_ns } = out[0] else {
        panic!("submit must emit Submit, got {:?}", out[0]);
    };
    assert_eq!((id, tfm_id, ts_ns), (1, None, 100));
    let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, 0, 0));
    assert_eq!(out.len(), 1);
    assert!(matches!(
        out[0],
        Edge::Return {
            id: 1,
            ts_ns: 150,
            status: 0,
            disposition: ReturnDisposition::Terminal,
        }
    ));
    assert_eq!(
        dec.stats(),
        DecodeStats {
            admitted: 1,
            ..DecodeStats::default()
        }
    );
}

#[test]
fn feed_classifies_queued_vs_terminal_returns() {
    // -EINPROGRESS queues, -EBUSY is unresolved (never terminal);
    // every other status completes sync.
    for (status, terminal) in [
        (-115, false),
        (-16, false),
        (0, true),
        (-5, true),
        (1, true),
    ] {
        let mut dec = LifecycleDecoder::new(16);
        dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
        let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, status, 0));
        assert_eq!(out.len(), 1, "status {status}");
        let Edge::Return {
            disposition,
            status: got,
            ..
        } = out[0]
        else {
            panic!("status {status} must emit Return");
        };
        assert_eq!(got, status);
        assert_eq!(
            disposition == ReturnDisposition::Terminal,
            terminal,
            "status {status}"
        );
    }
}

#[test]
fn feed_return_without_submit_counts_unknown_key() {
    let mut dec = LifecycleDecoder::new(16);
    let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, 0, 0));
    assert!(out.is_empty(), "no phantom edges: {out:?}");
    assert_eq!(dec.stats().unknown_key_returns, 1);
    assert_eq!(dec.stats().admitted, 0);
}

#[test]
fn feed_reuse_while_outstanding_gaps_old_and_admits_fresh() {
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
    let out = dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, 0));
    assert_eq!(out.len(), 2);
    assert!(matches!(
        out[0],
        Edge::Gap {
            id: 1,
            reason: GapReason::IdentityAmbiguous,
        }
    ));
    assert!(matches!(
        out[1],
        Edge::Submit {
            id: 2,
            tfm_id: None,
            ts_ns: 200,
        }
    ));
    assert_eq!(dec.stats().gaps_synthesized, 1);
    assert_eq!(dec.stats().admitted, 2);
}

#[test]
fn feed_refuses_admission_at_capacity() {
    let mut dec = LifecycleDecoder::new(1);
    assert_eq!(dec.feed(&edge_bytes(1, 1, 0xaa, 100, 0, 0)).len(), 1);
    let out = dec.feed(&edge_bytes(1, 1, 0xbb, 110, 0, 0));
    assert!(out.is_empty(), "full table admits nothing: {out:?}");
    assert_eq!(dec.stats().submit_refused, 1);
    // The refused submit leaves no phantom: its return is unknown-key.
    let out = dec.feed(&edge_bytes(2, 1, 0xbb, 120, 0, 0));
    assert!(out.is_empty());
    assert_eq!(dec.stats().unknown_key_returns, 1);
    // And the admitted key still pairs.
    let out = dec.feed(&edge_bytes(2, 1, 0xaa, 130, 0, 0));
    assert_eq!(out.len(), 1);
}

#[test]
fn feed_bad_records_count_without_edges() {
    let mut dec = LifecycleDecoder::new(16);
    assert!(dec.feed(&[0u8; 31]).is_empty());
    assert!(dec.feed(&edge_bytes(9, 1, 1, 1, 0, 0)).is_empty());
    assert_eq!(dec.stats().bad_records, 2);
    assert_eq!(dec.stats().admitted, 0);
}

#[test]
fn f9_raw_edge_and_decoder_debug_redact_kernel_keys() {
    // Round-1 (sol-m9/astra-m9): pairing keys are kernel pointers and
    // must never render in diagnostics. Both the edge and the decoder
    // (whose table is keyed by raw addresses) redact them.
    let key = 0xdead_beef_1234_5678u64;
    let raw = decode_record(&edge_bytes(1, 1, key, 100, 0, 0)).expect("valid submit");
    let shown = format!("{raw:?}");
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(!shown.contains(&key.to_string()), "{shown}");
    let mut decoder = LifecycleDecoder::new(8);
    decoder.feed(&edge_bytes(1, 1, key, 100, 0, 0));
    let dshown = format!("{decoder:?}");
    assert!(dshown.contains("outstanding"), "{dshown}");
    assert!(!dshown.contains(&key.to_string()), "{dshown}");
}

#[test]
fn f4_ebusy_is_unresolved_einprogress_is_queued() {
    // Round-1 (sol-M4/astra-M4) + design:71: -EBUSY means accepted
    // backlog ONLY when the path/flags contract establishes it. Our
    // edge carries no flags, so -EBUSY is Unresolved (never
    // completes); only -EINPROGRESS claims Queued.
    for (status, want) in [
        (-115, ReturnDisposition::Queued),
        (-16, ReturnDisposition::Unresolved),
    ] {
        let mut dec = LifecycleDecoder::new(16);
        dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
        let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, status, 0));
        assert_eq!(out.len(), 1, "status {status}");
        let Edge::Return { disposition, .. } = out[0] else {
            panic!("status {status} must emit Return");
        };
        assert_eq!(disposition, want, "status {status}");
    }
}

#[test]
fn f3_late_pre_reuse_return_is_stale_not_joined() {
    // Round-1 (sol-M3/astra-M3): S1(t100), reuse S2(t200), then
    // R(t150): R predates S2, so it cannot be op2's (same-address
    // invocations never overlap in real time — a call's fexit runs
    // after its fentry on a monotonic clock). The stale return is
    // refused (counted, id2 stays outstanding); op2's own R(t250)
    // then completes id2 with ITS status.
    let mut dec = LifecycleDecoder::new(16);
    let s1 = dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
    assert!(matches!(s1[..], [Edge::Submit { id: 1, .. }]));
    let s2 = dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, 0));
    assert_eq!(s2.len(), 2);
    assert!(matches!(
        s2[0],
        Edge::Gap {
            id: 1,
            reason: GapReason::IdentityAmbiguous,
        }
    ));
    assert!(matches!(s2[1], Edge::Submit { id: 2, .. }));
    let stale = dec.feed(&edge_bytes(2, 1, 0xabc, 150, -5, 0));
    assert!(
        stale.is_empty(),
        "stale return must emit nothing: {stale:?}"
    );
    assert_eq!(dec.stats().stale_returns, 1);
    let done = dec.feed(&edge_bytes(2, 1, 0xabc, 250, 0, 0));
    assert_eq!(
        done,
        vec![Edge::Return {
            id: 2,
            ts_ns: 250,
            status: 0,
            disposition: ReturnDisposition::Terminal,
        }]
    );
}

#[test]
fn f3_return_at_same_tick_as_resubmit_joins() {
    // Transport-loss shape: S1(t100), R1 dropped by the ring, S2(t200)
    // gaps S1 `IdentityAmbiguous`, R2(t200) joins current — ties join
    // under a coarse clock (pinned). This is NOT the reuse case:
    // honest BPF taints nested submits (next test), so a clean
    // same-key submit while an id is outstanding proves the old
    // return never arrived.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
    dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, 0));
    let done = dec.feed(&edge_bytes(2, 1, 0xabc, 200, -5, 0));
    assert_eq!(
        done,
        vec![Edge::Return {
            id: 2,
            ts_ns: 200,
            status: -5,
            disposition: ReturnDisposition::Terminal,
        }]
    );
    assert_eq!(dec.stats().stale_returns, 0);
}

#[test]
fn w3_tainted_submit_gaps_outstanding_never_misattributes() {
    // Round-3 nesting killer (both exit orders): BPF taints the
    // nested submit AND poisons the slot, so the decoder gaps the
    // outstanding id FIRST — no future return can be attributed
    // (the first return could be either call's). Whatever exits
    // first, nothing trusted completes: every return refuses.
    // Both exit orders, both return flaggings: after the gap the id
    // is gone, so EVERY return refuses (unknown key) — the gap (not
    // the taint bit) is what protects the pairing. The all-clean
    // case is the strongest: even a clean first return cannot join.
    for second_flags in [TAINTED, 0] {
        let mut dec = LifecycleDecoder::new(16);
        dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
        let gap = dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, TAINTED));
        assert_eq!(
            gap,
            vec![Edge::Gap {
                id: 1,
                reason: GapReason::IdentityAmbiguous,
            }],
            "tainted submit gaps the disturbed id"
        );
        assert_eq!(dec.stats().submit_refused, 1);
        assert_eq!(dec.stats().admitted, 1, "no fresh id for taint");
        assert_eq!(dec.stats().gaps_synthesized, 1);
        let first = dec.feed(&edge_bytes(2, 1, 0xabc, 220, -5, 0));
        assert!(
            first.is_empty(),
            "first return refuses (unknown key): {first:?}"
        );
        let second = dec.feed(&edge_bytes(2, 1, 0xabc, 250, 0, second_flags));
        assert!(
            second.is_empty(),
            "second return refuses (unknown key): {second:?}"
        );
        assert_eq!(dec.stats().unknown_key_returns, 2);
    }
}

#[test]
fn w3_tainted_submit_without_outstanding_refuses_quietly() {
    // No outstanding id, nothing to poison: the refusal counts and
    // the table stays untouched (a later clean submit admits fresh).
    let mut dec = LifecycleDecoder::new(16);
    let refused = dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, TAINTED));
    assert!(refused.is_empty());
    assert_eq!(dec.stats().submit_refused, 1);
    assert_eq!(dec.stats().gaps_synthesized, 0);
    assert_eq!(dec.stats().admitted, 0);
    let admitted = dec.feed(&edge_bytes(1, 1, 0xabc, 300, 0, 0));
    assert!(
        matches!(admitted.as_slice(), [Edge::Submit { id: 1, .. }]),
        "clean submit admits fresh: {admitted:?}"
    );
}

#[test]
fn w2_tainted_return_never_joins_or_disturbs() {
    // A tainted return (slot was empty at BPF exit: pre-attach call
    // or NOSLOT drop) counts unknown-key and leaves
    // any outstanding id alone — a later clean return still joins.
    let mut dec = LifecycleDecoder::new(16);
    let unknown = dec.feed(&edge_bytes(2, 1, 0xabc, 150, 0, TAINTED));
    assert!(unknown.is_empty());
    assert_eq!(dec.stats().unknown_key_returns, 1);
    dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, 0));
    let tainted = dec.feed(&edge_bytes(2, 1, 0xabc, 210, -5, TAINTED));
    assert!(tainted.is_empty(), "tainted return emits nothing");
    assert_eq!(dec.stats().unknown_key_returns, 2);
    let done = dec.feed(&edge_bytes(2, 1, 0xabc, 220, 0, 0));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 1, .. }]),
        "outstanding undisturbed: {done:?}"
    );
}

#[test]
fn w2_site_mismatch_refuses_stale_and_keeps_outstanding() {
    // Submit site is stored; a return from the other site for the
    // same key cannot be this invocation's return (one call, one
    // function) — refused stale, outstanding kept for its real return.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
    let stale = dec.feed(&edge_bytes(2, 2, 0xabc, 150, 0, 0));
    assert!(stale.is_empty(), "cross-site return emits nothing");
    assert_eq!(dec.stats().stale_returns, 1);
    let done = dec.feed(&edge_bytes(2, 1, 0xabc, 200, 0, 0));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 1, .. }]),
        "outstanding undisturbed: {done:?}"
    );
}

#[test]
fn w4_invocation_mismatch_refuses_stale_and_keeps_outstanding() {
    // Round-4 (astra-M1): the join identity is the BPF invocation.
    // A same-key, same-site, later-timestamped return from a
    // DIFFERENT invocation (the lost-pair shape: A-submit
    // delivered, A-return + B-submit lost, B-return delivered)
    // refuses stale — never completes the outstanding id — and the
    // outstanding id is kept for its real return.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0x4000));
    let stale = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 250, -5, 0, 0x8000));
    assert!(stale.is_empty(), "cross-invocation return emits nothing");
    assert_eq!(dec.stats().stale_returns, 1);
    assert_eq!(dec.stats().unknown_key_returns, 0);
    let done = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 300, 0, 0, 0x4000));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 1, .. }]),
        "matching invocation still joins: {done:?}"
    );
}

#[test]
fn w4_nested_continuation_never_cross_joins() {
    // Round-4 (sol-M1): the three-call continuation
    // `A-sub → B-sub → B-ret → C-sub → A-ret → C-ret` as the fixed
    // BPF emits it — every edge after the nesting disturbance is
    // tainted with its own invocation. The tainted B-submit gaps A;
    // every later edge refuses; no id ever completes and no return
    // ever touches another call's id.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0x4000));
    let gap = dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 200, 0, TAINTED, 0x4002));
    assert_eq!(
        gap,
        vec![Edge::Gap {
            id: 1,
            reason: GapReason::IdentityAmbiguous,
        }],
        "tainted B-submit gaps A"
    );
    // B's return (tainted, own invocation): unknown key.
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 220, -5, TAINTED, 0x4002))
            .is_empty()
    );
    // C's submit while the slot is still disturbed: tainted, refused
    // quietly (nothing outstanding to gap).
    assert!(
        dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 230, 0, TAINTED, 0x4004))
            .is_empty()
    );
    assert_eq!(dec.stats().admitted, 1, "no fresh id for taint");
    // A's real return (tainted — the slot was disturbed): unknown.
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 250, 0, TAINTED, 0x4000))
            .is_empty()
    );
    // C's return (tainted): unknown.
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 260, 0, TAINTED, 0x4004))
            .is_empty()
    );
    assert_eq!(dec.stats().unknown_key_returns, 3);
    assert_eq!(dec.stats().gaps_synthesized, 1);
}

#[test]
fn w5_noslot_ghost_stream_refuses_everything_forever() {
    // Round-5 W5 (sticky quarantine): a NOSLOT-dropped submit leaves
    // a ghost — BPF quarantines the key STICKILY (never clears:
    // clearing misattributes shared ghosts, counting races), so the
    // ghost's return AND every later same-key edge arrive TAINTED
    // (never clean, never admitted, never joined). The decoder side
    // is the already-pinned taint rules; this pins the exact
    // quarantine-emitted shape end to end, INCLUDING that the key
    // never recovers (a later clean claim on the same key is the
    // round-5 misjoin shape — BPF must never emit it).
    let mut dec = LifecycleDecoder::new(16);
    // Ghost's return (submit was NOSLOT-dropped, return tainted):
    // unknown key, nothing disturbed.
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 150, -5, TAINTED, 0))
            .is_empty()
    );
    // Interleaved same-key submit during quarantine: tainted,
    // refused quietly (nothing outstanding to gap).
    assert!(
        dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 200, 0, TAINTED, 0x4002))
            .is_empty()
    );
    assert_eq!(dec.stats().submit_refused, 1);
    assert_eq!(dec.stats().admitted, 0);
    assert_eq!(dec.stats().unknown_key_returns, 1);
    // The quarantine sticks: later same-key edges stay tainted
    // (the ghost count never releases — round-5 Major 1).
    assert!(
        dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 300, 0, TAINTED, 0x8000))
            .is_empty()
    );
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 350, 0, TAINTED, 0))
            .is_empty()
    );
    assert_eq!(dec.stats().admitted, 0, "quarantined key never admits");
    // Other keys are unaffected (quarantine is per-key).
    let admitted = dec.feed(&edge_bytes_invoc(1, 1, 0xdef, 400, 0, 0, 0xC000));
    assert!(
        matches!(admitted.as_slice(), [Edge::Submit { id: 1, .. }]),
        "other keys admit fresh: {admitted:?}"
    );
    let done = dec.feed(&edge_bytes_invoc(2, 1, 0xdef, 450, 0, 0, 0xC000));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 1, .. }]),
        "other keys join normally: {done:?}"
    );
}

#[test]
fn w5_malformed_clean_invoc_refuses() {
    // Round-5 minor: honest BPF never emits a clean edge with
    // invoc 0 ("no invocation") or the poison bit set — both
    // refuse as twin drift, never join.
    assert_eq!(
        decode_record(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0)),
        Err(DecodeDrop::BadInvoc)
    );
    assert_eq!(
        decode_record(&edge_bytes_invoc(2, 1, 0xabc, 150, 0, 0, 0)),
        Err(DecodeDrop::BadInvoc)
    );
    assert_eq!(
        decode_record(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0x4001)),
        Err(DecodeDrop::BadInvoc)
    );
    // Tainted edges may carry either (slotless 0 / poisoned store):
    // the taint rules, not the twin check, govern them.
    decode_record(&edge_bytes_invoc(2, 1, 0xabc, 150, -5, TAINTED, 0))
        .expect("tainted zero parses");
    decode_record(&edge_bytes_invoc(2, 1, 0xabc, 150, -5, TAINTED, 0x4001))
        .expect("tainted poisoned parses");
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0));
    assert_eq!(dec.stats().bad_records, 1);
    assert_eq!(dec.stats().admitted, 0);
}

#[test]
fn w4_clean_reuse_after_loss_gaps_and_readmits() {
    // The sound remainder: a CLEAN same-key submit while an id is
    // outstanding proves the old invocation ended (the BPF slot
    // empties only on a return release) — the old id gaps and the
    // new invocation admits fresh, and only ITS return joins.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0x4000));
    let gap = dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 200, 0, 0, 0x8000));
    assert_eq!(
        gap.iter().filter(|e| matches!(e, Edge::Gap { .. })).count(),
        1,
        "old id gaps exactly once: {gap:?}"
    );
    assert!(
        matches!(
            gap.iter().find(|e| matches!(e, Edge::Submit { .. })),
            Some(Edge::Submit { id: 2, .. })
        ),
        "new invocation admits fresh: {gap:?}"
    );
    // The old invocation's return (were it delivered late) cannot
    // join the new id: invocation mismatch refuses stale.
    let stale = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 250, 0, 0, 0x4000));
    assert!(stale.is_empty(), "old return cannot join new id");
    assert_eq!(dec.stats().stale_returns, 1);
    let done = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 300, 0, 0, 0x8000));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 2, .. }]),
        "new invocation joins its own return: {done:?}"
    );
}
