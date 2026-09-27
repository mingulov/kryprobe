// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 decode suite: raw `LEdge` bytes → T05 `Edge` events + join rules.
//!
//! Pins the v6 record twin (magic/version/edge/site/flags/meta/invoc/tfm/drv/length),
//! the invocation→opaque-id join (W8 fsession: fresh id per admission,
//! bounded table, nested same-key calls pair exactly by cookie id),
//! return classification (sync-terminal vs queued), and the named loss
//! counters. BPF taints what it cannot pair (`LEDGE_TAINTED` — entry
//! id-exhaustion, exits over a zero cookie) and tainted edges disturb
//! NOTHING (they name no invocation): the outstanding table is keyed
//! by invocation alone, so a same-key clean submit with a fresh
//! invocation admits alongside (nesting), while a same-invocation
//! resubmit (twin drift or replay — BPF ids are unique) gaps the old
//! id `IdentityAmbiguous` and admits fresh. Coarse-clock ties join.

use kryprobe_core::kcrypto::{Edge, GapReason, ReturnDisposition};
use kryprobe_privilege::kcrypto_lifecycle::decode::{
    DecodeDrop, DecodeStats, LifecycleDecoder, decode_record,
};

/// `LEDGE_TAINTED` flag bit (BPF nesting taint; mirrors the ABI const).
const TAINTED: u16 = 0x0001;

/// One 112-byte v6 `LEdge` (little-endian twin of the ABI struct).
fn edge_bytes_invoc(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    flags: u16,
    invoc: u64,
) -> [u8; 112] {
    edge_bytes_tfm(edge, site, key, ts_ns, status, flags, invoc, 0, b"")
}

/// Full builder with an explicit transform word (0 = unknown link —
/// the default; tests pinning first-seen pass a frontend here) and
/// driver name (submit edges only — returns carry tfm 0 + empty
/// name per the R2 twin). Metadata defaults to the unknown-chase
/// shape (validity clear, skcipher family, site-echoing direction);
/// tests pinning metadata use [`edge_v6`] explicitly.
#[allow(clippy::too_many_arguments)]
fn edge_bytes_tfm(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    flags: u16,
    invoc: u64,
    tfm: u64,
    drv: &[u8],
) -> [u8; 112] {
    let mut out = [0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 6;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[6..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out[32..40].copy_from_slice(&invoc.to_le_bytes());
    out[40..48].copy_from_slice(&tfm.to_le_bytes());
    if edge == 1 {
        out[52] = 1; // skcipher family
        out[53] = site as u8; // direction echoes the site
    }
    let n = drv.len().min(55);
    out[56..56 + n].copy_from_slice(&drv[..n]);
    out
}

/// Realistic default builder: same v6 record with a VALID
/// invocation (nonzero, reserved-bit clear — tests sharing one call
/// use the default 0x4000 so the join hits; tests with two live
/// calls pass distinct invocations via [`edge_bytes_invoc`]
/// explicitly, since the join keys by invocation alone).
fn edge_bytes(edge: u8, site: u16, key: u64, ts_ns: u64, status: i32, flags: u16) -> [u8; 112] {
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
    // v1..v5 records refuse (fail closed across versions: an old
    // decoder would misread the reshaped v6 record, so versions
    // never mix).
    for version in [1u8, 2, 3, 4, 5] {
        let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
        bad[2] = version;
        assert_eq!(
            decode_record(&bad),
            Err(DecodeDrop::BadVersion),
            "version {version} refuses"
        );
    }
    // P4 (adapter contract §11): kind 3 is the callback half now —
    // an op site on it is BadSite; unknown kinds still refuse BadEdge.
    assert_eq!(
        decode_record(&edge_bytes(9, 1, 9, 1, 0, 0)),
        Err(DecodeDrop::BadEdge)
    );
    assert_eq!(
        decode_record(&edge_bytes(3, 1, 9, 1, 0, 0)),
        Err(DecodeDrop::BadSite)
    );
    assert_eq!(
        decode_record(&edge_bytes(1, 9, 9, 1, 0, 0)),
        Err(DecodeDrop::BadSite)
    );
    // Only taint + truncated bits are defined; any other flag bit
    // is drift.
    let tainted = decode_record(&edge_bytes(1, 1, 9, 1, 0, TAINTED)).expect("taint parses");
    assert!(tainted.tainted);
    let clipped = decode_record(&edge_bytes(1, 1, 9, 1, 0, 0x0002)).expect("truncated parses");
    assert!(clipped.truncated);
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[6] = 0x04;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadFlags));
    let mut bad = edge_bytes(1, 1, 9, 1, 0, 0);
    bad[28] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
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
    assert_eq!(decode_record(&[0u8; 111]), Err(DecodeDrop::BadLength));
    assert_eq!(decode_record(&[0u8; 113]), Err(DecodeDrop::BadLength));
    // The v4 48-byte record refuses by length AND version (twin lock).
    assert_eq!(decode_record(&[0u8; 48]), Err(DecodeDrop::BadLength));
    assert_eq!(
        decode_record(&edge_bytes(1, 1, 0, 1, 0, 0)),
        Err(DecodeDrop::NullKey)
    );
}

#[test]
fn decode_record_carries_transform_word() {
    // T07.3: submit `tfm` admits any u64 — a frontend decodes
    // verbatim, 0 decodes as unknown (never refused either way: the
    // op joins by invocation with or without its transform).
    let raw = decode_record(&edge_bytes_tfm(1, 1, 0xabc, 100, 0, 0, 0x4000, 0xf00d, b""))
        .expect("tfm parses");
    assert_eq!(raw.tfm, 0xf00d);
    let raw = decode_record(&edge_bytes(1, 1, 0xabc, 100, 0, 0)).expect("zero tfm parses");
    assert_eq!(raw.tfm, 0);
    // `tfm` never disturbs the invocation join: the submit's word
    // pairs with the return's zero by invocation alone (R2).
    let mut dec = LifecycleDecoder::new(8);
    let submit = dec.feed(&edge_bytes_tfm(1, 1, 0xabc, 100, 0, 0, 0x4000, 0xf00d, b""));
    assert_eq!(submit.len(), 1);
    let ret = dec.feed(&edge_bytes_tfm(2, 1, 0xabc, 150, 0, 0, 0x4000, 0, b""));
    assert_eq!(ret.len(), 1, "submit word + return zero join");
}

#[test]
fn decode_record_v6_return_carries_no_chase() {
    // R2: honest BPF never chases at exit — a return-side transform
    // word or driver name is twin drift, refused loudly.
    let mut bad = edge_bytes(2, 1, 0xabc, 150, 0, 0);
    bad[40] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadReturnTfm));
    let mut bad = edge_bytes(2, 1, 0xabc, 150, 0, 0);
    bad[48] = b'x';
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    let mut bad = edge_bytes(2, 1, 0xabc, 150, 0, 0);
    bad[56] = b'x';
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadDrv));
}

#[test]
fn decode_record_v6_submit_carries_driver() {
    // T07-04/F05: the submit's driver word decodes verbatim (empty
    // when the chase was unreadable); a missing NUL or invalid
    // UTF-8 is drift.
    let raw = decode_record(&edge_bytes_tfm(
        1,
        1,
        0xabc,
        100,
        0,
        0,
        0x4000,
        0xf00d,
        b"aes-generic",
    ))
    .expect("driver parses");
    assert_eq!(raw.tfm, 0xf00d);
    assert_eq!(raw.drv, "aes-generic");
    let raw = decode_record(&edge_bytes(1, 1, 0xabc, 100, 0, 0)).expect("empty driver parses");
    assert!(raw.drv.is_empty());
    let mut bad = edge_bytes(1, 1, 0xabc, 100, 0, 0);
    bad[56..112].fill(b'x');
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadDrv));
    let mut bad = edge_bytes(1, 1, 0xabc, 100, 0, 0);
    bad[56] = 0xFF;
    bad[57] = 0;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadDrv));
}

#[test]
fn feed_pairs_submit_with_sync_return() {
    let mut dec = LifecycleDecoder::new(16);
    let out = dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
    assert_eq!(out.len(), 1);
    let Edge::Submit {
        id, tfm_id, ts_ns, ..
    } = out[0]
    else {
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
fn feed_return_without_submit_counts_unknown_invoc() {
    let mut dec = LifecycleDecoder::new(16);
    let out = dec.feed(&edge_bytes(2, 1, 0xabc, 150, 0, 0));
    assert!(out.is_empty(), "no phantom edges: {out:?}");
    assert_eq!(dec.stats().unknown_invoc_returns, 1);
    assert_eq!(dec.stats().admitted, 0);
}

#[test]
fn feed_resubmit_while_outstanding_gaps_old_and_admits_fresh() {
    // Same invocation submitted twice (BPF ids are unique — twin
    // drift or replay): the old id gaps `IdentityAmbiguous` and the
    // resubmit admits fresh under a new opaque id.
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
            ..
        }
    ));
    assert_eq!(dec.stats().gaps_synthesized, 1);
    assert_eq!(dec.stats().admitted, 2);
}

#[test]
fn feed_refuses_admission_at_capacity() {
    // Distinct invocations (a resubmit would gap-and-admit instead of
    // refusing — the join keys by invocation, not by key).
    let mut dec = LifecycleDecoder::new(1);
    assert_eq!(
        dec.feed(&edge_bytes_invoc(1, 1, 0xaa, 100, 0, 0, 0x4000))
            .len(),
        1
    );
    let out = dec.feed(&edge_bytes_invoc(1, 1, 0xbb, 110, 0, 0, 0x8000));
    assert!(out.is_empty(), "full table admits nothing: {out:?}");
    assert_eq!(dec.stats().submit_refused, 1);
    // The refused submit leaves no phantom: its return is unknown.
    let out = dec.feed(&edge_bytes_invoc(2, 1, 0xbb, 120, 0, 0, 0x8000));
    assert!(out.is_empty());
    assert_eq!(dec.stats().unknown_invoc_returns, 1);
    // And the admitted invocation still pairs.
    let out = dec.feed(&edge_bytes_invoc(2, 1, 0xaa, 130, 0, 0, 0x4000));
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
fn f3_late_pre_resubmit_return_is_stale_not_joined() {
    // Round-1 (sol-M3/astra-M3), W8 resubmit shape: S1(t100),
    // resubmit S2(t200, same invocation), then R(t150): R predates
    // S2, so it cannot be op2's (a call's exit runs after its entry
    // on a monotonic clock). The stale return is refused (counted,
    // id2 stays outstanding); op2's own R(t250) then completes id2
    // with ITS status.
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
    // Resubmit shape: S1(t100), R1 dropped by the ring, resubmit
    // S2(t200, same invocation) gaps S1 `IdentityAmbiguous`, R2(t200)
    // joins current — ties join under a coarse clock (pinned). Same
    // key with a FRESH invocation instead admits alongside (nesting
    // — see the W8 test below), never gaps.
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
fn w8_tainted_submit_disturbs_nothing_outstanding_joins() {
    // W8: per-call cookies isolate invocations, so a tainted submit
    // (honest BPF never emits one — NOSLOT drops silently — so this
    // is twin drift; it names no invocation) refuses WITHOUT touching
    // the table: no gap, and the outstanding id still joins its own
    // clean return. The loop covers both flaggings of the trailing
    // return: after the join the invocation is gone, so the second
    // return refuses (unknown invocation) either way.
    for second_flags in [TAINTED, 0] {
        let mut dec = LifecycleDecoder::new(16);
        dec.feed(&edge_bytes(1, 1, 0xabc, 100, 0, 0));
        let refused = dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, TAINTED));
        assert!(refused.is_empty(), "tainted submit emits nothing");
        assert_eq!(dec.stats().submit_refused, 1);
        assert_eq!(dec.stats().admitted, 1, "no fresh id for taint");
        assert_eq!(dec.stats().gaps_synthesized, 0, "nothing gapped");
        let done = dec.feed(&edge_bytes(2, 1, 0xabc, 220, -5, 0));
        assert!(
            matches!(done.as_slice(), [Edge::Return { id: 1, .. }]),
            "outstanding still joins: {done:?}"
        );
        let second = dec.feed(&edge_bytes(2, 1, 0xabc, 250, 0, second_flags));
        assert!(
            second.is_empty(),
            "second return refuses (unknown invocation): {second:?}"
        );
        assert_eq!(dec.stats().unknown_invoc_returns, 1);
    }
}

#[test]
fn w3_tainted_submit_without_outstanding_refuses_quietly() {
    // No outstanding id, nothing to gap: the refusal counts and
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
    // A tainted return (exit over a zero cookie: skipped entry or
    // pre-attach call) counts unknown-invocation and leaves any
    // outstanding id alone — a later clean return still joins.
    let mut dec = LifecycleDecoder::new(16);
    let unknown = dec.feed(&edge_bytes(2, 1, 0xabc, 150, 0, TAINTED));
    assert!(unknown.is_empty());
    assert_eq!(dec.stats().unknown_invoc_returns, 1);
    dec.feed(&edge_bytes(1, 1, 0xabc, 200, 0, 0));
    let tainted = dec.feed(&edge_bytes(2, 1, 0xabc, 210, -5, TAINTED));
    assert!(tainted.is_empty(), "tainted return emits nothing");
    assert_eq!(dec.stats().unknown_invoc_returns, 2);
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
fn w8_foreign_invocation_refuses_unknown_and_keeps_outstanding() {
    // W8 (round-4 astra-M1 shape, invoc-keyed): the join identity is
    // the BPF invocation. A same-key, same-site, later-timestamped
    // return from a DIFFERENT invocation (the lost-pair shape:
    // A-submit delivered, A-return + B-submit lost, B-return
    // delivered) names an invocation with no outstanding id —
    // refuses unknown, never completes the outstanding id — and the
    // outstanding id is kept for its real return.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0x4000));
    let unknown = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 250, -5, 0, 0x8000));
    assert!(unknown.is_empty(), "foreign invocation emits nothing");
    assert_eq!(dec.stats().unknown_invoc_returns, 1);
    assert_eq!(dec.stats().stale_returns, 0);
    let done = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 300, 0, 0, 0x4000));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 1, .. }]),
        "matching invocation still joins: {done:?}"
    );
}

#[test]
fn w8_nested_same_key_pairs_exactly() {
    // W8 (the DECISION decoder requirement): nested same-key calls —
    // `A-sub → B-sub → B-ret → A-ret`, all clean, distinct cookie
    // ids — admit alongside and pair EXACTLY (no gaps: a second
    // submit on the same key is a live second call, not proof the
    // first ended). A tainted return for a live invocation in the
    // middle refuses quietly WITHOUT disturbing it.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0x4000));
    let nested = dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 200, 0, 0, 0x4002));
    assert!(
        matches!(nested.as_slice(), [Edge::Submit { id: 2, .. }]),
        "nested submit admits alongside (no gap): {nested:?}"
    );
    assert_eq!(dec.stats().gaps_synthesized, 0);
    // Tainted return naming B's invocation: refused, B kept.
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 210, -5, TAINTED, 0x4002))
            .is_empty()
    );
    assert_eq!(dec.stats().unknown_invoc_returns, 1);
    let b_done = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 220, 0, 0, 0x4002));
    assert!(
        matches!(b_done.as_slice(), [Edge::Return { id: 2, .. }]),
        "inner call pairs exactly: {b_done:?}"
    );
    let a_done = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 250, -5, 0, 0x4000));
    assert!(
        matches!(a_done.as_slice(), [Edge::Return { id: 1, .. }]),
        "outer call pairs exactly: {a_done:?}"
    );
    assert_eq!(dec.stats().admitted, 2);
}

#[test]
fn w8_tainted_stream_disturbs_nothing_clean_recovers() {
    // W8 (no slots, no quarantine): tainted edges — NOSLOT-dropped
    // submits (invoc 0), exits over zero cookies — refuse quietly
    // and disturb nothing, WHILE a clean same-key call with a fresh
    // invocation admits alongside and pairs normally (the W5-forbidden
    // clean-claim shape is REQUIRED nesting behavior now).
    let mut dec = LifecycleDecoder::new(16);
    // Ghost's return (submit was NOSLOT-dropped, return tainted):
    // unknown invocation, nothing disturbed.
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 150, -5, TAINTED, 0))
            .is_empty()
    );
    // Interleaved tainted submit: refused quietly.
    assert!(
        dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 200, 0, TAINTED, 0x4002))
            .is_empty()
    );
    assert_eq!(dec.stats().submit_refused, 1);
    assert_eq!(dec.stats().admitted, 0);
    assert_eq!(dec.stats().unknown_invoc_returns, 1);
    // A clean same-key call admits alongside the taint and pairs.
    let admitted = dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 300, 0, 0, 0x8000));
    assert!(
        matches!(admitted.as_slice(), [Edge::Submit { id: 1, .. }]),
        "clean same-key admits alongside taint: {admitted:?}"
    );
    assert!(
        dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 350, 0, TAINTED, 0))
            .is_empty(),
        "tainted ghost return disturbs nothing"
    );
    let done = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 360, 0, 0, 0x8000));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 1, .. }]),
        "clean call joins normally: {done:?}"
    );
    // Other keys are unaffected.
    let admitted = dec.feed(&edge_bytes_invoc(1, 1, 0xdef, 400, 0, 0, 0xC000));
    assert!(
        matches!(admitted.as_slice(), [Edge::Submit { id: 2, .. }]),
        "other keys admit fresh: {admitted:?}"
    );
}

#[test]
fn w5_malformed_clean_invoc_refuses() {
    // Round-5 minor: honest BPF never emits a clean edge with
    // invoc 0 ("no invocation") or the reserved bit set — both
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
    // Tainted edges may carry either (slotless 0 / reserved-bit
    // set): the taint rules, not the twin check, govern them.
    decode_record(&edge_bytes_invoc(2, 1, 0xabc, 150, -5, TAINTED, 0))
        .expect("tainted zero parses");
    decode_record(&edge_bytes_invoc(2, 1, 0xabc, 150, -5, TAINTED, 0x4001))
        .expect("tainted reserved-bit parses");
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0));
    assert_eq!(dec.stats().bad_records, 1);
    assert_eq!(dec.stats().admitted, 0);
}

#[test]
fn w8_resubmit_gaps_and_readmits_return_joins_current() {
    // The W8 remainder: a same-INVOCATION resubmit (twin drift or
    // replay — BPF ids are unique) gaps the old id and admits fresh,
    // and only the current id joins that invocation's return. A
    // never-seen invocation's return refuses unknown.
    let mut dec = LifecycleDecoder::new(16);
    dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 100, 0, 0, 0x4000));
    let gap = dec.feed(&edge_bytes_invoc(1, 1, 0xabc, 200, 0, 0, 0x4000));
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
        "resubmit admits fresh: {gap:?}"
    );
    // A never-seen invocation cannot join: unknown, never stale.
    let unknown = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 250, 0, 0, 0x8000));
    assert!(unknown.is_empty(), "foreign return joins nothing");
    assert_eq!(dec.stats().unknown_invoc_returns, 1);
    assert_eq!(dec.stats().stale_returns, 0);
    let done = dec.feed(&edge_bytes_invoc(2, 1, 0xabc, 300, 0, 0, 0x4000));
    assert!(
        matches!(done.as_slice(), [Edge::Return { id: 2, .. }]),
        "current id joins its return: {done:?}"
    );
}

/// One 112-byte v6 `LEdge` (P3 twin: `cryptlen@28`, `req_flags@48`,
/// `fam@52`, `dir@53`, `mflags@54`, `drv@56` 55+NUL).
#[allow(clippy::too_many_arguments)]
fn edge_v6(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    invoc: u64,
    cryptlen: Option<u32>,
    req_flags: Option<u32>,
    drv: &[u8],
) -> [u8; 112] {
    let mut out = [0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 6;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    if edge == 1 {
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
    out
}

#[test]
fn v6_accepts_valid_submit_and_return_with_metadata() {
    let raw = decode_record(&edge_v6(
        1,
        1,
        0xabc,
        100,
        0,
        0x4000,
        Some(16),
        Some(0),
        b"drv",
    ))
    .expect("valid v6 submit parses");
    assert_eq!(
        (raw.edge, raw.site, raw.key, raw.ts_ns, raw.invoc),
        (1, 1, 0xabc, 100, 0x4000)
    );
    assert_eq!((raw.cryptlen, raw.req_flags), (Some(16), Some(0)));
    // Unknown chase (validity clear, value zero) decodes to None, never 0-as-data.
    let raw = decode_record(&edge_v6(1, 1, 0xabc, 100, 0, 0x4000, None, None, b""))
        .expect("unknown-chase submit parses");
    assert_eq!((raw.cryptlen, raw.req_flags), (None, None));
    let raw = decode_record(&edge_v6(2, 1, 0xabc, 150, -5, 0x4000, None, None, b""))
        .expect("valid v6 return parses");
    assert_eq!((raw.edge, raw.status), (2, -5));
    assert_eq!((raw.cryptlen, raw.req_flags), (None, None));
}

#[test]
fn v6_refuses_old_and_future_versions() {
    for version in [1u8, 2, 3, 4, 5, 7, 0xff] {
        let mut bad = edge_v6(1, 1, 9, 1, 0, 0x4000, Some(1), Some(0), b"");
        bad[2] = version;
        assert_eq!(
            decode_record(&bad),
            Err(DecodeDrop::BadVersion),
            "version {version} refuses"
        );
    }
}

#[test]
fn v6_return_side_metadata_refuses() {
    // R2 extended: returns carry all-zero metadata (never chased).
    let mut bad = edge_v6(2, 1, 9, 1, 0, 0x4000, None, None, b"");
    bad[28] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    let mut bad = edge_v6(2, 1, 9, 1, 0, 0x4000, None, None, b"");
    bad[48] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    let mut bad = edge_v6(2, 1, 9, 1, 0, 0x4000, None, None, b"");
    bad[52] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    let mut bad = edge_v6(2, 1, 9, 1, 0, 0x4000, None, None, b"");
    bad[54] = 1;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    let mut bad = edge_v6(2, 1, 9, 1, 0, 0x4000, None, None, b"");
    bad[56] = b'x';
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadDrv));
}

#[test]
fn v6_bad_meta_shapes_refuse() {
    // Defined mflags bits only.
    let mut bad = edge_v6(1, 1, 9, 1, 0, 0x4000, Some(1), Some(0), b"");
    bad[54] = 0x04;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    // Nonzero value without its validity bit is twin drift.
    let mut bad = edge_v6(1, 1, 9, 1, 0, 0x4000, None, Some(0), b"");
    bad[28] = 7;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    let mut bad = edge_v6(1, 1, 9, 1, 0, 0x4000, Some(1), None, b"");
    bad[48] = 7;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    // Family is skcipher-only; dir echoes the site.
    let mut bad = edge_v6(1, 1, 9, 1, 0, 0x4000, Some(1), Some(0), b"");
    bad[52] = 2;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    let mut bad = edge_v6(1, 1, 9, 1, 0, 0x4000, Some(1), Some(0), b"");
    bad[53] = 2;
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadMeta));
    // No NUL within the 56-byte driver word refuses.
    let mut bad = edge_v6(1, 1, 9, 1, 0, 0x4000, Some(1), Some(0), b"");
    bad[56..112].fill(b'x');
    assert_eq!(decode_record(&bad), Err(DecodeDrop::BadDrv));
}

#[test]
fn v6_join_with_tfm_binds_submit_lifetime() {
    use kryprobe_core::kcrypto::{LifecycleFamily, OpDirection};
    let mut dec = LifecycleDecoder::new(16);
    let raw = decode_record(&edge_v6(
        1,
        1,
        0xabc,
        100,
        0,
        0x4000,
        Some(16),
        Some(0),
        b"drv",
    ))
    .expect("valid v6 submit");
    let out = dec.join_with_tfm(raw, Some(7), Some(3));
    assert!(
        matches!(
            out.as_slice(),
            [Edge::Submit {
                id: 1,
                tfm_id: Some(7),
                ts_ns: 100,
                ..
            }]
        ),
        "binding rides the submit: {out:?}"
    );
    let Edge::Submit { meta, .. } = &out[0] else {
        panic!("submit edge: {out:?}");
    };
    assert_eq!(meta.family, LifecycleFamily::Skcipher);
    assert_eq!(meta.direction, OpDirection::Encrypt);
    assert_eq!(
        (meta.cryptlen, meta.req_flags, meta.epoch),
        (Some(16), Some(0), Some(3))
    );
    // The return joins the bound id; compat join stays unbound.
    let raw = decode_record(&edge_v6(2, 1, 0xabc, 150, 0, 0x4000, None, None, b""))
        .expect("valid v6 return");
    assert!(
        matches!(dec.join(raw).as_slice(), [Edge::Return { id: 1, .. }]),
        "return joins its submit"
    );
    let raw = decode_record(&edge_v6(1, 1, 0xabc, 200, 0, 0x4002, Some(8), Some(0), b""))
        .expect("valid v6 submit");
    let out = dec.join(raw);
    assert!(
        matches!(out.as_slice(), [Edge::Submit { tfm_id: None, .. }]),
        "compat join carries no binding: {out:?}"
    );
    let Edge::Submit { meta, .. } = &out[0] else {
        panic!("submit edge: {out:?}");
    };
    assert_eq!((meta.cryptlen, meta.epoch), (Some(8), None));
    // An epoch without a generation is not expressible: coerced to None,
    // and the invocation still admits (never destroyed by a caller slip).
    let raw = decode_record(&edge_v6(1, 1, 0xabc, 300, 0, 0x4004, Some(8), Some(0), b""))
        .expect("valid v6 submit");
    let out = dec.join_with_tfm(raw, None, Some(9));
    let Edge::Submit { meta, tfm_id, .. } = &out[0] else {
        panic!("submit edge: {out:?}");
    };
    assert_eq!((*tfm_id, meta.epoch), (None, None));
    assert_eq!(dec.stats().admitted, 3);
}
