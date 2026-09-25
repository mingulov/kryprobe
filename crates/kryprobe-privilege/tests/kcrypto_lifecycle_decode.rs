// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 decode suite: raw `LEdge` bytes → T05 `Edge` events + join rules.
//!
//! Pins the record twin (magic/version/edge/site/flags/aux/length),
//! the key→opaque-id join (fresh id per admission, bounded table),
//! return classification (sync-terminal vs queued), and the named loss
//! counters. Reuse-while-outstanding gaps the old id and admits fresh;
//! a late return for the old key joins the CURRENT id (known T06
//! limitation — T08 assigns BPF-side generations).

use kryprobe_core::kcrypto::{Edge, GapReason, ReturnDisposition};
use kryprobe_privilege::kcrypto_lifecycle::decode::{
    DecodeDrop, DecodeStats, LifecycleDecoder, decode_record,
};

/// One 32-byte `LEdge` (little-endian twin of the ABI struct).
fn edge_bytes(edge: u8, site: u16, key: u64, ts_ns: u64, status: i32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 1;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out
}

#[test]
fn decode_record_accepts_valid_submit_and_return() {
    let raw = decode_record(&edge_bytes(1, 1, 0xabc, 100, 0)).expect("valid submit parses");
    assert_eq!(
        (raw.edge, raw.site, raw.key, raw.ts_ns, raw.status),
        (1, 1, 0xabc, 100, 0)
    );
    let raw = decode_record(&edge_bytes(2, 2, 0xdef, 200, -5)).expect("valid return parses");
    assert_eq!(
        (raw.edge, raw.site, raw.key, raw.ts_ns, raw.status),
        (2, 2, 0xdef, 200, -5)
    );
}

#[test]
fn decode_record_rejects_twin_drift() {
    // Bad magic / version / edge / site / flags / aux each name their drop.
    let mut bad = edge_bytes(1, 1, 9, 1, 0);
    bad[0] = 0;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMagic));
    let mut bad = edge_bytes(1, 1, 9, 1, 0);
    bad[2] = 2;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadVersion));
    assert_eq!(
        decode_record(&edge_bytes(3, 1, 9, 1, 0)),
        Err(DecodeDrop::BadEdge)
    );
    assert_eq!(
        decode_record(&edge_bytes(1, 9, 9, 1, 0)),
        Err(DecodeDrop::BadSite)
    );
    let mut bad = edge_bytes(1, 1, 9, 1, 0);
    bad[6] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadFlags));
    let mut bad = edge_bytes(1, 1, 9, 1, 0);
    bad[28] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadAux));
}

#[test]
fn decode_record_rejects_shape_and_null_key() {
    assert_eq!(decode_record(&[0u8; 31]), Err(DecodeDrop::BadLength));
    assert_eq!(decode_record(&[0u8; 33]), Err(DecodeDrop::BadLength));
    assert_eq!(
        decode_record(&edge_bytes(1, 1, 0, 1, 0)),
        Err(DecodeDrop::NullKey)
    );
}

#[test]
fn feed_pairs_submit_with_sync_return() {
    let mut dec = LifecycleDecoder::new(16);
    let out = dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0));
    assert_eq!(out.len(), 1);
    let Edge::Submit { id, tfm_id, ts_ns } = out[0] else {
        panic!("submit must emit Submit, got {:?}", out[0]);
    };
    assert_eq!((id, tfm_id, ts_ns), (1, None, 100));
    let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, 0));
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
        dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0));
        let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, status));
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
    let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, 0));
    assert!(out.is_empty(), "no phantom edges: {out:?}");
    assert_eq!(dec.stats().unknown_key_returns, 1);
    assert_eq!(dec.stats().admitted, 0);
}

#[test]
fn feed_reuse_while_outstanding_gaps_old_and_admits_fresh() {
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0));
    let out = dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0));
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
    assert_eq!(dec.feed(&edge_bytes(1, 1, 0xaa, 100, 0)).len(), 1);
    let out = dec.feed(&edge_bytes(1, 1, 0xbb, 110, 0));
    assert!(out.is_empty(), "full table admits nothing: {out:?}");
    assert_eq!(dec.stats().submit_refused, 1);
    // The refused submit leaves no phantom: its return is unknown-key.
    let out = dec.feed(&edge_bytes(2, 1, 0xbb, 120, 0));
    assert!(out.is_empty());
    assert_eq!(dec.stats().unknown_key_returns, 1);
    // And the admitted key still pairs.
    let out = dec.feed(&edge_bytes(2, 1, 0xaa, 130, 0));
    assert_eq!(out.len(), 1);
}

#[test]
fn feed_bad_records_count_without_edges() {
    let mut dec = LifecycleDecoder::new(16);
    assert!(dec.feed(&[0u8; 31]).is_empty());
    assert!(dec.feed(&edge_bytes(9, 1, 1, 1, 0)).is_empty());
    assert_eq!(dec.stats().bad_records, 2);
    assert_eq!(dec.stats().admitted, 0);
}

#[test]
fn f9_raw_edge_and_decoder_debug_redact_kernel_keys() {
    // Round-1 (sol-m9/astra-m9): pairing keys are kernel pointers and
    // must never render in diagnostics. Both the edge and the decoder
    // (whose table is keyed by raw addresses) redact them.
    let key = 0xdead_beef_1234_5678u64;
    let raw = decode_record(&edge_bytes(1, 1, key, 100, 0)).expect("valid submit");
    let shown = format!("{raw:?}");
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(!shown.contains(&key.to_string()), "{shown}");
    let mut decoder = LifecycleDecoder::new(8);
    decoder.feed(&edge_bytes(1, 1, key, 100, 0));
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
        dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0));
        let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, status));
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
    let s1 = dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0));
    assert!(matches!(s1[..], [Edge::Submit { id: 1, .. }]));
    let s2 = dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0));
    assert_eq!(s2.len(), 2);
    assert!(matches!(
        s2[0],
        Edge::Gap {
            id: 1,
            reason: GapReason::IdentityAmbiguous,
        }
    ));
    assert!(matches!(s2[1], Edge::Submit { id: 2, .. }));
    let stale = dec.feed(&edge_bytes(2, 1, 0xabc, 150, -5));
    assert!(
        stale.is_empty(),
        "stale return must emit nothing: {stale:?}"
    );
    assert_eq!(dec.stats().stale_returns, 1);
    let done = dec.feed(&edge_bytes(2, 1, 0xabc, 250, 0));
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
    // Ties are ambiguous under a coarse clock: R(t200) against a
    // resubmit S2(t200) joins current (pinned; T08 generations
    // disambiguate).
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0));
    dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0));
    let done = dec.feed(&edge_bytes(2, 1, 0xabc, 200, -5));
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
