// SPDX-License-Identifier: GPL-3.0-or-later
//! Payload-shape contract (1B-H3 structural): the kcrypto `BackendPayload`
//! vocabulary is machine-checked. Production `decode` output for every row
//! kind must carry exactly the pinned key sets (required always, optional
//! only when resolved), every consumer-read key must be emitted by the
//! producer (except `module`, which import-shaped observations carry and
//! kcrypto explicitly gates out via D4), and no emitted key may fall
//! outside the vocabulary — a producer typo or a renamed key fails here,
//! not silently in policy/render.

use kryprobe_abi::kcrypto_agg::{KCTX_PROC, KFAM_SK, KOP_ENC, KRES_OK};
use kryprobe_core::backend::{Backend, DecodeContext};
use kryprobe_core::evidence::payload_keys as K;
use kryprobe_core::ids::{IdIssuer, PlanGeneration, SessionId};

fn agg_row(calls: u64) -> kryprobe_privilege::kcrypto_snapshot::RowBytes {
    // 3A-M-T7: canonical builder (fills preserved from the old local copy).
    let out =
        kryprobe_testkit::kcrypto_rows::agg_row_bytes(kryprobe_testkit::kcrypto_rows::AggSpec {
            family: KFAM_SK,
            op: KOP_ENC,
            result: KRES_OK,
            ctx: KCTX_PROC,
            name: b"cbc(aes)",
            calls,
            bytes: 0,
            ok: 0,
        });
    kryprobe_privilege::kcrypto_snapshot::RowBytes::new(out).expect("hand row")
}

fn totals_row(calls: u64) -> kryprobe_privilege::kcrypto_snapshot::TotalsBytes {
    // 3A-M-T7: canonical builder (fills preserved from the old local copy).
    let out = kryprobe_testkit::kcrypto_rows::totals_row_bytes(calls, 0, 0);
    kryprobe_privilege::kcrypto_snapshot::TotalsBytes::new(out).expect("hand totals")
}

fn ident_row() -> kryprobe_privilege::kcrypto_snapshot::IdentBytes {
    // 3A-M-T7: canonical builder.
    let out = kryprobe_testkit::kcrypto_rows::ident_row_bytes();
    kryprobe_privilege::kcrypto_snapshot::IdentBytes::new(out).expect("hand ident")
}

fn decode(
    backend: &kryprobe_privilege::kcrypto_backend::KCryptoBackend,
    event: kryprobe_core::backend::RawEvent<'_>,
) -> kryprobe_core::evidence::NativeObservation {
    let issuer = IdIssuer::default();
    let integrity = kryprobe_core::evidence::IntegritySummary::default();
    let ctx = DecodeContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        integrity: &integrity,
        id_issuer: &issuer,
    };
    backend.decode(&ctx, event).expect("hand row decodes")
}

/// Sorted top-level keys of a payload.
fn keys(payload: &serde_json::Value) -> Vec<&str> {
    let mut keys: Vec<&str> = payload
        .as_object()
        .expect("payload is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

fn sorted<'a>(keys: &[&'a str]) -> Vec<&'a str> {
    let mut out = keys.to_vec();
    out.sort_unstable();
    out
}

#[test]
fn payload_contract_producer_emits_pinned_shapes() {
    let backend = kryprobe_privilege::kcrypto_backend::KCryptoBackend::new();
    // Agg/totals/ident through the production `decode` seam (hand row
    // bytes in, typed observations out — no privilege needed).
    let agg = agg_row(10);
    let agg_obs = decode(
        &backend,
        kryprobe_privilege::kcrypto_snapshot::raw_event_for_agg(&agg),
    );
    assert_eq!(
        keys(&agg_obs.backend_payload),
        sorted(K::AGG_KEYS),
        "agg emits exactly the pinned set"
    );
    let totals = totals_row(30);
    let totals_obs = decode(
        &backend,
        kryprobe_privilege::kcrypto_snapshot::raw_event_for_totals(&totals),
    );
    assert_eq!(
        keys(&totals_obs.backend_payload),
        sorted(K::TOTALS_KEYS),
        "totals emits exactly the pinned set"
    );
    let ident = ident_row();
    let ident_obs = decode(
        &backend,
        kryprobe_privilege::kcrypto_snapshot::raw_event_for_ident(&ident),
    );
    assert_eq!(
        keys(&ident_obs.backend_payload),
        sorted(K::IDENT_KEYS),
        "ident emits exactly the pinned set"
    );
    // Who rows, bare (nothing resolved) and full (parent + params +
    // errno resolved), through the production builder.
    let table = kryprobe_privilege::kallsyms::SymTable::parse("");
    let bare = kryprobe_privilege::kcrypto_backend::WhoSnapshot {
        key: Default::default(),
        val: Default::default(),
        stack_ips: Vec::new(),
        first_errno: None,
        params: None,
    };
    let bare_obs = kryprobe_privilege::kcrypto_backend::observation_for_who(
        &bare,
        kryprobe_core::ids::ObservationId::new(1),
        &table,
    );
    assert_eq!(
        keys(&bare_obs.backend_payload),
        sorted(K::WHO_KEYS),
        "bare who emits exactly the required set"
    );
    let full_val = kryprobe_abi::kcrypto_agg::VWho {
        ppid: 4242,
        ..Default::default()
    };
    let full = kryprobe_privilege::kcrypto_backend::WhoSnapshot {
        key: Default::default(),
        val: full_val,
        stack_ips: vec![0xffffffff81001500],
        first_errno: Some(-5),
        params: Some(kryprobe_abi::kcrypto_agg::VParams::default()),
    };
    let full_obs = kryprobe_privilege::kcrypto_backend::observation_for_who(
        &full,
        kryprobe_core::ids::ObservationId::new(2),
        &table,
    );
    let mut full_expected = K::WHO_KEYS.to_vec();
    full_expected.extend_from_slice(K::WHO_OPTIONAL_KEYS);
    assert_eq!(
        keys(&full_obs.backend_payload),
        sorted(&full_expected),
        "resolved who emits required + optional"
    );
    // Nested shapes are pinned too (consumers index into them).
    let counts = &agg_obs.backend_payload[K::COUNTS];
    assert_eq!(
        keys(counts),
        sorted(K::COUNT_KEYS),
        "counts block pins its four tallies"
    );
    let window = &agg_obs.backend_payload[K::WINDOW];
    assert_eq!(
        keys(window),
        sorted(K::WINDOW_KEYS),
        "window block pins first/last"
    );
}

#[test]
fn payload_contract_consumers_read_only_emitted_keys() {
    // Every key policy reads is emitted by the producer — except
    // `module`, which import-shaped observations carry and kcrypto
    // explicitly never emits (D4 backend gate).
    let mut emitted = K::AGG_KEYS.to_vec();
    emitted.extend_from_slice(K::TOTALS_KEYS);
    emitted.extend_from_slice(K::IDENT_KEYS);
    emitted.extend_from_slice(K::WHO_KEYS);
    emitted.extend_from_slice(K::WHO_OPTIONAL_KEYS);
    emitted.extend_from_slice(K::AGG_OPTIONAL_KEYS);
    for key in kryprobe_policy::eval::POLICY_READ_KEYS {
        if *key == K::MODULE {
            assert!(
                !emitted.contains(key),
                "kcrypto must never emit `module` (D4)"
            );
            continue;
        }
        assert!(
            emitted.contains(key),
            "policy reads `{key}`, producer never emits it"
        );
    }
    // Every key watch reads (top-level and nested) is emitted.
    for key in kryprobe_report::live_render::WATCH_READ_KEYS {
        assert!(
            emitted.contains(key) || K::COUNT_KEYS.contains(key),
            "watch reads `{key}`, producer never emits it"
        );
    }
    // No emitted key falls outside the vocabulary (a producer literal
    // bypassing the shared consts fails here).
    for key in &emitted {
        assert!(
            K::VOCAB.contains(key),
            "emitted key `{key}` is outside the vocabulary"
        );
    }
}
