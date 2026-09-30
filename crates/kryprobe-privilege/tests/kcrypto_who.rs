// SPDX-License-Identifier: GPL-3.0-or-later
//! K5 Task 4: who-row decode + stack symbolizer + latency surfacing.
//!
//! Unprivileged: the symbolizer is pure over fixture text, who decode is
//! pure over a hand-built [`WhoSnapshot`](kryprobe_privilege::kcrypto_backend::WhoSnapshot),
//! and the agg `key_hash`/`lat` pins decode a hand-encoded row through the
//! frozen [`Backend`](kryprobe_core::backend::Backend) trait.

use kryprobe_abi::kcrypto_agg::{
    KCTX_PROC, KFAM_SK, KOP_ENC, KRES_OK, KWhoKey, VParams, VWho, kh_of,
};
use kryprobe_core::backend::{Backend, DecodeContext};
use kryprobe_core::enums::EvidencePhase;
use kryprobe_core::evidence::{IntegritySummary, NativeObservation};
use kryprobe_core::ids::{IdIssuer, ObservationId, PlanGeneration, SessionId};
use kryprobe_privilege::kallsyms::{SymTable, read_kallsyms, symbolize, symbolize_with};
use kryprobe_privilege::kcrypto_backend::{KCryptoBackend, WhoSnapshot, observation_for_who};
use kryprobe_privilege::kcrypto_snapshot::{RowBytes, raw_event_for_agg};
use serde_json::Value;
use std::collections::BTreeSet;

/// Tiny map for unit symbolization (the brief's verbatim shape).
const TINY_MAP: &str = "ffffffff81000000 T _stext\n\
    ffffffff81001000 T hash_sendmsg\n\
    ffffffff81002000 T _etext\n";

/// Hand-written 6-line fixture (nearest-below pins + helper/type coverage).
const FIXTURE: &str = include_str!("data/kallsyms-sample.txt");

#[test]
fn k5_symbolize_nearest_below() {
    let map =
        "ffffffff81000000 T _stext\nffffffff81001000 T hash_sendmsg\nffffffff81002000 T _etext\n";
    let out = symbolize(&[0xffffffff81001500], map);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg"));
    let out = symbolize(&[0x10], "garbage\n");
    assert_eq!(out[0].sym, None);
    // IPs echo through; empty input yields empty output.
    let out = symbolize(&[0xffffffff81001500], map);
    assert_eq!(out[0].ip, 0xffffffff81001500);
    assert!(symbolize(&[], map).is_empty());
}

#[test]
fn k5_symbolize_fixture_file() {
    assert_eq!(FIXTURE.lines().count(), 6, "hand-written 6-line fixture");
    // Exact hit.
    let out = symbolize(&[0xffffffff81001000], FIXTURE);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg"));
    // Floor across a gap (local `t` type symbolizes like globals).
    let out = symbolize(&[0xffffffff81001800], FIXTURE);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg_helper"));
    // Below the first entry: no floor, `None`.
    let out = symbolize(&[0xffffffff80ffffff], FIXTURE);
    assert_eq!(out[0].sym, None);
    // Past the last entry: floor is the last symbol.
    let out = symbolize(&[0xffffffff81004099], FIXTURE);
    assert_eq!(out[0].sym.as_deref(), Some("crypto_alloc_tfm_node"));
}

#[test]
fn k5_symbolize_ignores_hidden_and_unparseable() {
    // `kptr_restrict` hides addresses as zero: zero entries must not
    // capture every IP (spec §2.2: hidden addrs -> `sym: null`).
    let hidden = "0000000000000000 T hidden_a\n0000000000000000 T hidden_b\n";
    let out = symbolize(&[0xffffffff81001500], hidden);
    assert_eq!(out[0].sym, None);
    // Mixed: the zero line is skipped, the real line still floors.
    let mixed =
        "0000000000000000 T hidden\nffffffff81001000 T hash_sendmsg\nnot-an-addr T bogus\nshort\n";
    let out = symbolize(&[0xffffffff81001500, 0x10], mixed);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg"));
    assert_eq!(out[1].sym, None);
    // Empty map: all `None`.
    let out = symbolize(&[0xffffffff81001500], "");
    assert_eq!(out[0].sym, None);
}

#[test]
fn k5_read_kallsyms_never_fails() {
    // Best-effort: a `String` on every machine (empty when unreadable),
    // never `Err`, never a panic; whatever it holds must symbolize cleanly.
    let text = read_kallsyms();
    let out = symbolize(&[0xffffffff81001500], &text);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ip, 0xffffffff81001500);
}

#[test]
fn sym_table_parse_once_shared_across_rows() {
    // 2B-C2: one parse per tick, shared across all who rows. Decoding two
    // rows against the same table must match, with the parse explicit and
    // singular at the call site (the tick used to re-parse + re-sort the
    // whole map for every who row).
    let table = SymTable::parse(TINY_MAP);
    let snap = who_snapshot(true, true);
    let first = observation_for_who(&snap, ObservationId::new(7), &table);
    let second = observation_for_who(&snap, ObservationId::new(8), &table);
    assert_eq!(first.backend_payload, second.backend_payload);
    let frames = first
        .backend_payload
        .get("stack")
        .and_then(|s| s.get("frames"))
        .and_then(Value::as_array)
        .expect("frames array");
    assert_eq!(
        frames[0].get("sym").and_then(Value::as_str),
        Some("hash_sendmsg")
    );
}

#[test]
fn symbolize_with_matches_symbolize() {
    // Refactor guard: the shared-table path must equal the legacy
    // per-call parse path on every input shape.
    let cases: [&[u64]; 3] = [&[0xffffffff81001500], &[0x10], &[]];
    for text in [TINY_MAP, FIXTURE, "garbage\n", ""] {
        let table = SymTable::parse(text);
        for ips in cases {
            assert_eq!(symbolize_with(ips, &table), symbolize(ips, text));
        }
    }
}

/// Hand-built `WhoSnapshot` with comm `python3`; the ok-flags shape the
/// DATA exactly as the BPF does when the chase is skipped: `parent_ok=false`
/// leaves `ppid`/`pcomm` zero, `params_ok=false` leaves `params` absent.
fn who_snapshot(parent_ok: bool, params_ok: bool) -> WhoSnapshot {
    let mut comm = [0u8; 16];
    comm[..7].copy_from_slice(b"python3");
    let mut pcomm = [0u8; 16];
    if parent_ok {
        pcomm[..4].copy_from_slice(b"bash");
    }
    WhoSnapshot {
        key: KWhoKey {
            kh: 0x8e83_4f55_dbe2_59a5,
            tgid: 4242,
            _pad: 0,
        },
        val: VWho {
            comm,
            tid: 4243,
            uid: 1000,
            cgroup: 0x9c,
            ppid: if parent_ok { 12 } else { 0 },
            pcomm,
            stack: 3,
            calls: 7,
            first_ns: 111,
            last_ns: 222,
        },
        stack_ips: vec![0xffffffff81001500],
        first_errno: None,
        params: params_ok.then_some(VParams {
            blocksize: 16,
            ivsize: 16,
            min_keysize: 16,
            max_keysize: 32,
        }),
    }
}

/// Decode the hand-built fixture (both ok-flags false: parent zeroed,
/// params absent).
fn decode_who_fixture(parent_ok: bool, params_ok: bool) -> NativeObservation {
    let table = SymTable::parse(TINY_MAP);
    observation_for_who(
        &who_snapshot(parent_ok, params_ok),
        ObservationId::new(1),
        &table,
    )
}

#[test]
fn k5_who_row_omits_unresolved() {
    let obs = decode_who_fixture(/* parent_ok=false, params_ok=false */ false, false);
    let p = &obs.backend_payload;
    assert!(p.get("ppid").is_none() && p.get("blocksize").is_none());
    assert_eq!(p.get("comm").and_then(Value::as_str), Some("python3"));
}

#[test]
fn k5_who_row_exact_keys_when_resolved() {
    let mut snap = who_snapshot(true, true);
    snap.first_errno = Some(-5);
    let table = SymTable::parse(TINY_MAP);
    let obs = observation_for_who(&snap, ObservationId::new(2), &table);
    assert_eq!(obs.phase, EvidencePhase::Discovered);
    let p = &obs.backend_payload;
    assert_eq!(p.get("row").and_then(Value::as_str), Some("who"));
    assert_eq!(
        p.get("key_hash").and_then(Value::as_u64),
        Some(0x8e83_4f55_dbe2_59a5)
    );
    assert_eq!(p.get("tgid").and_then(Value::as_u64), Some(4242));
    assert_eq!(p.get("tid").and_then(Value::as_u64), Some(4243));
    assert_eq!(p.get("comm").and_then(Value::as_str), Some("python3"));
    assert_eq!(p.get("uid").and_then(Value::as_u64), Some(1000));
    assert_eq!(p.get("cgroup").and_then(Value::as_u64), Some(0x9c));
    assert_eq!(p.get("ppid").and_then(Value::as_u64), Some(12));
    assert_eq!(p.get("pcomm").and_then(Value::as_str), Some("bash"));
    assert_eq!(p.get("calls").and_then(Value::as_u64), Some(7));
    assert_eq!(p.get("first_ns").and_then(Value::as_u64), Some(111));
    assert_eq!(p.get("last_ns").and_then(Value::as_u64), Some(222));
    assert_eq!(p.get("blocksize").and_then(Value::as_u64), Some(16));
    assert_eq!(p.get("ivsize").and_then(Value::as_u64), Some(16));
    assert_eq!(p.get("min_keysize").and_then(Value::as_u64), Some(16));
    assert_eq!(p.get("max_keysize").and_then(Value::as_u64), Some(32));
    assert_eq!(p.get("first_errno").and_then(Value::as_i64), Some(-5));
    // Stack: id echoes, frames symbolize through the map.
    assert_eq!(
        p.get("stack")
            .and_then(|s| s.get("id"))
            .and_then(Value::as_i64),
        Some(3)
    );
    let frames = p
        .get("stack")
        .and_then(|s| s.get("frames"))
        .and_then(Value::as_array)
        .expect("frames array");
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].get("ip").and_then(Value::as_u64),
        Some(0xffffffff81001500)
    );
    assert_eq!(
        frames[0].get("sym").and_then(Value::as_str),
        Some("hash_sendmsg")
    );
    // The full key set is exactly the brief's list (plus the `row` discriminator).
    let keys: BTreeSet<&str> = p
        .as_object()
        .expect("payload object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "row",
        "key_hash",
        "tgid",
        "tid",
        "comm",
        "uid",
        "cgroup",
        "ppid",
        "pcomm",
        "stack",
        "calls",
        "first_ns",
        "last_ns",
        "blocksize",
        "ivsize",
        "min_keysize",
        "max_keysize",
        "first_errno",
        "capture_profile",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
}

#[test]
fn k5_who_row_omit_key_set_when_unresolved() {
    let obs = decode_who_fixture(false, false);
    let keys: BTreeSet<&str> = obs
        .backend_payload
        .as_object()
        .expect("payload object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "row",
        "key_hash",
        "tgid",
        "tid",
        "comm",
        "uid",
        "cgroup",
        "stack",
        "calls",
        "first_ns",
        "last_ns",
        "capture_profile",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
    // The stack survives omission (id + frames are never gated).
    assert_eq!(
        obs.backend_payload
            .get("stack")
            .and_then(|s| s.get("frames"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn k5_who_row_first_errno_rule() {
    // Task 2 review M-1: render ONLY when < 0 and not -EINPROGRESS/-EBUSY.
    for (input, expected) in [
        (None, None),
        (Some(0), None),
        (Some(5), None),
        (Some(-115), None),
        (Some(-16), None),
        (Some(-5), Some(-5)),
        (Some(-22), Some(-22)),
    ] {
        let mut snap = who_snapshot(false, false);
        snap.first_errno = input;
        let table = SymTable::parse(TINY_MAP);
        let obs = observation_for_who(&snap, ObservationId::new(3), &table);
        assert_eq!(
            obs.backend_payload
                .get("first_errno")
                .and_then(Value::as_i64),
            expected,
            "first_errno render for input {input:?}"
        );
    }
}

#[test]
fn k5_who_row_negative_stack_id_renders_empty_frames() {
    // Task 4 review M1: a negative `stack` (raw helper errno) has no
    // KSTACK row, so `frames` is empty and `id` echoes the errno.
    let mut snap = who_snapshot(false, false);
    snap.val.stack = -14;
    snap.stack_ips = Vec::new();
    let table = SymTable::parse(TINY_MAP);
    let obs = observation_for_who(&snap, ObservationId::new(5), &table);
    let stack = obs.backend_payload.get("stack").expect("stack block");
    assert_eq!(stack.get("id").and_then(Value::as_i64), Some(-14));
    assert_eq!(
        stack.get("frames").and_then(Value::as_array).map(Vec::len),
        Some(0)
    );
}

#[test]
fn k5_who_row_frames_null_when_unresolvable() {
    let snap = who_snapshot(false, false);
    let table = SymTable::parse("garbage\n");
    let obs = observation_for_who(&snap, ObservationId::new(4), &table);
    let frames = obs
        .backend_payload
        .get("stack")
        .and_then(|s| s.get("frames"))
        .and_then(Value::as_array)
        .expect("frames array");
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].get("ip").and_then(Value::as_u64),
        Some(0xffffffff81001500),
        "raw ip kept"
    );
    assert!(
        frames[0].get("sym").is_some_and(Value::is_null),
        "unresolvable sym is null"
    );
}

/// Hand 382B agg payload: skcipher/encrypt/ok/proc, `t-alg`/`t-drv`,
/// nonzero latency buckets to pin passthrough.
fn agg_payload_with_lat(lat: [u64; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(382);
    out.push(0x01);
    out.push(1);
    out.extend_from_slice(&[KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC]);
    let mut alg = [0u8; 128];
    alg[..6].copy_from_slice(b"t-alg\0");
    out.extend_from_slice(&alg);
    let mut drv = [0u8; 128];
    drv[..6].copy_from_slice(b"t-drv\0");
    out.extend_from_slice(&drv);
    for word in [7u64, 224, 7, 0, 0, 100, 200] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for bucket in lat {
        out.extend_from_slice(&bucket.to_le_bytes());
    }
    assert_eq!(out.len(), 382);
    out
}

#[test]
fn k5_agg_row_gains_key_hash_and_lat() {
    let payload = agg_payload_with_lat([1, 2, 3, 4, 5, 6, 7, 8]);
    let backend = KCryptoBackend::new();
    let issuer = IdIssuer::default();
    let baseline = IntegritySummary::default();
    let ctx = DecodeContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        integrity: &baseline,
        id_issuer: &issuer,
    };
    let row = RowBytes::new(payload).expect("hand row");
    let obs = backend
        .decode(&ctx, raw_event_for_agg(&row))
        .expect("agg decodes");
    let p = &obs.backend_payload;
    assert_eq!(p.get("row").and_then(Value::as_str), Some("agg"));
    // `key_hash` is the shared FNV-1a row hash over the decoded row.
    let mut alg = [0u64; 16];
    alg[0] = u64::from_le_bytes(*b"t-alg\0\0\0");
    let mut drv = [0u64; 16];
    drv[0] = u64::from_le_bytes(*b"t-drv\0\0\0");
    assert_eq!(
        p.get("key_hash").and_then(Value::as_u64),
        Some(kh_of(KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC, &alg, &drv))
    );
    // `lat` passes the 8 buckets through verbatim.
    assert_eq!(
        p.get("lat"),
        Some(&serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8]))
    );
}

#[test]
fn who_row_render_scales_to_2048_rows() {
    // Audit #9/R1: per-tick who-row render cost must stay sane at row
    // scale. Generous wall bound (pure serde_json builds take ~ms) —
    // trips only on pathological blowup, never flakes.
    let table = SymTable::parse(TINY_MAP);
    let snap = who_snapshot(true, true);
    let first = observation_for_who(&snap, ObservationId::new(0), &table);
    assert!(first.backend_payload.is_object());
    let start = std::time::Instant::now();
    for i in 1..2048u64 {
        let obs = observation_for_who(&snap, ObservationId::new(i), &table);
        assert_eq!(obs.backend_payload, first.backend_payload);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "2048 who rows took {elapsed:?}"
    );
}
