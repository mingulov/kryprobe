// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 F8c: `request-lifecycle` registry backend (RED-first).
//!
//! The lifecycle sensor behind the frozen 7-method `Backend` trait:
//! detect/plan/configure/decode/finalize plus profile registration
//! (one `BackendId::KCrypto` slot — the second profile is a typed
//! `DuplicateBackend`, never a second capture).

use kryprobe_abi::{ABI_VERSION, BACKEND_KCRYPTO, EVENT_OBSERVATION, RawEventHeader};
use kryprobe_core::backend::{
    Backend, BackendPlan, DecodeContext, DetectContext, FinalizeContext, RawEvent,
};
use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
use kryprobe_core::error::BackendError;
use kryprobe_core::evidence::observation::NativeResult;
use kryprobe_core::evidence::{IntegritySummary, payload_keys as K};
use kryprobe_core::ids::{IdIssuer, PlanGeneration, SessionId};
use kryprobe_privilege::kcrypto_backend::{
    ProfileBackend, register_kcrypto, register_kcrypto_profile, register_kcrypto_shared,
};
use kryprobe_privilege::kcrypto_lifecycle::backend::{
    lifecycle_event, register_lifecycle, register_lifecycle_shared,
};
use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;

fn issuer() -> IdIssuer {
    IdIssuer::default()
}

fn decode_ctx<'a>(integrity: &'a IntegritySummary, issuer: &'a IdIssuer) -> DecodeContext<'a> {
    DecodeContext {
        session: SessionId::new(7),
        generation: PlanGeneration::new(1),
        integrity,
        id_issuer: issuer,
    }
}

fn runtime() -> kryprobe_core::capability::RuntimeCapabilities {
    kryprobe_core::capability::RuntimeCapabilities {
        kernel_release: "test".to_owned(),
        uprobe_multi: true,
        cookies: true,
        ringbuf: true,
        btf_present: true,
        userns: true,
        yama_scope: 0,
        caps: vec!["CAP_BPF".to_owned()],
    }
}

fn header_for(payload_len: usize) -> RawEventHeader {
    RawEventHeader {
        abi_version: ABI_VERSION,
        backend_id: BACKEND_KCRYPTO,
        event_kind: EVENT_OBSERVATION,
        flags: 0,
        total_len: (size_of::<RawEventHeader>() + payload_len) as u32,
        cpu: 0,
        session_cookie: 0,
        monotonic_ns: 0,
        tgid: 0,
        tid: 0,
        process_generation: 0,
        plan_generation: 0,
        reserved: 0,
    }
}

#[test]
fn f8c_capabilities_name_and_require_btf_ringbuf() {
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let caps = backend.capabilities();
    assert_eq!(caps.backend, BackendId::KCrypto);
    assert_eq!(caps.name, "kcrypto-lifecycle");
    assert!(caps.required.btf);
    assert!(caps.required.ringbuf);
}

#[test]
fn f8c_detect_finds_one_system_sensor() {
    // Unprivileged over host BTF (the VM lane proves guest BTF).
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let caps = runtime();
    let ctx = DetectContext {
        session: SessionId::new(7),
        runtime: &caps,
    };
    let instances = backend.detect(&ctx).expect("host BTF resolves");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].backend, BackendId::KCrypto);
}

#[test]
fn f8c_plan_requests_two_hooks_per_required_site() {
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let caps = runtime();
    let detect = DetectContext {
        session: SessionId::new(7),
        runtime: &caps,
    };
    let instance = &backend.detect(&detect).expect("detect")[0];
    let plan_ctx = kryprobe_core::backend::PlanContext {
        session: SessionId::new(7),
        runtime: &caps,
    };
    let plan: BackendPlan = backend
        .plan(
            &plan_ctx,
            instance,
            kryprobe_core::enums::CaptureMode::Trace,
        )
        .expect("plan");
    assert_eq!(plan.backend, BackendId::KCrypto);
    // Entry + return hook per required site, manifest-derived (new
    // sites extend the plan — never a hardcoded count again).
    assert_eq!(plan.probes.len(), 14, "7 sites × entry/return");
    assert_eq!(
        plan.probes.len(),
        kryprobe_privilege::kcrypto_lifecycle::profile::manifest(
            kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::RequestLifecycle
        )
        .required
        .len()
            * 2
    );
    assert!(plan.required.btf && plan.required.ringbuf);
}

#[test]
fn f8c_decode_sync_record_maps_completed() {
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let integrity = IntegritySummary::default();
    let issuer = issuer();
    let ctx = decode_ctx(&integrity, &issuer);
    // Sync completion, status 0, 50ns span.
    let payload =
        br#"{"request_id":1,"terminal":"sync","status":0,"duration_ns":"50","tfm_id":null}"#
            .to_vec();
    let header = header_for(payload.len());
    let obs = backend
        .decode(
            &ctx,
            RawEvent {
                header,
                payload: &payload,
            },
        )
        .expect("valid envelope");
    assert_eq!(obs.backend, BackendId::KCrypto);
    assert_eq!(obs.phase, EvidencePhase::Completed);
    assert_eq!(obs.call_kind, CallKind::Operation);
    assert_eq!(obs.operation_class, OperationClass::Unknown);
    assert_eq!(obs.native_result, NativeResult::KCrypto { status: 0 });
    assert_eq!(obs.started_ns, None);
    assert_eq!(obs.ended_ns, None);
    let p = &obs.backend_payload;
    assert_eq!(p[K::ROW], serde_json::json!("lifecycle"));
    assert_eq!(
        p[K::CAPTURE_PROFILE],
        serde_json::json!("request-lifecycle")
    );
    assert_eq!(p[K::ID], serde_json::json!("lc:1"));
    assert_eq!(p[K::TERMINAL], serde_json::json!("sync"));
    assert_eq!(p[K::STATUS], serde_json::json!(0));
    assert_eq!(p[K::DURATION_NS], serde_json::json!("50"));
    assert_eq!(p[K::EVIDENCE], serde_json::json!(true));
    // Exact key set (contract support; the payload_contract test pins it).
    let mut keys: Vec<&str> = p
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let mut want: Vec<&str> = K::LIFECYCLE_KEYS.to_vec();
    want.sort_unstable();
    assert_eq!(keys, want);
}

#[test]
fn f8c_decode_unknown_record_maps_entered_without_status() {
    // Unknown terminal: Entered phase (never Completed), NO status
    // (`KCryptoUnknown` — a zero placeholder would fabricate success
    // beside the payload's explicit `"status": null`).
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let integrity = IntegritySummary::default();
    let issuer = issuer();
    let ctx = decode_ctx(&integrity, &issuer);
    let payload =
        br#"{"request_id":9,"terminal":"unknown","status":null,"duration_ns":null,"tfm_id":null}"#
            .to_vec();
    let header = header_for(payload.len());
    let obs = backend
        .decode(
            &ctx,
            RawEvent {
                header,
                payload: &payload,
            },
        )
        .expect("valid envelope");
    assert_eq!(obs.phase, EvidencePhase::Entered);
    assert_eq!(obs.call_kind, CallKind::Unknown);
    assert_eq!(obs.native_result, NativeResult::KCryptoUnknown);
    let p = &obs.backend_payload;
    assert_eq!(p[K::TERMINAL], serde_json::json!("unknown"));
    assert_eq!(p[K::STATUS], serde_json::json!(null));
    assert_eq!(p[K::EVIDENCE], serde_json::json!(false));
    assert_eq!(
        p[K::COMPLETION_COVERAGE],
        serde_json::json!(K::COVERAGE_UNOBSERVED)
    );
}

#[test]
fn f8c_decode_rejects_malformed_envelopes() {
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let integrity = IntegritySummary::default();
    let issuer = issuer();
    let ctx = decode_ctx(&integrity, &issuer);
    for (name, payload) in [
        ("not-json", b"v1 row bytes".to_vec()),
        (
            "bad-terminal",
            br#"{"request_id":1,"terminal":"maybe","status":0,"duration_ns":"1","tfm_id":null}"#.to_vec(),
        ),
        (
            "status-without-terminal",
            br#"{"request_id":1,"terminal":"unknown","status":0,"duration_ns":null,"tfm_id":null}"#.to_vec(),
        ),
        (
            "terminal-without-status",
            br#"{"request_id":1,"terminal":"sync","status":null,"duration_ns":"1","tfm_id":null}"#.to_vec(),
        ),
        (
            "bad-duration",
            br#"{"request_id":1,"terminal":"sync","status":0,"duration_ns":"1x","tfm_id":null}"#.to_vec(),
        ),
        (
            "extra-key",
            br#"{"request_id":1,"terminal":"sync","status":0,"duration_ns":"1","tfm_id":null,"op":"encrypt"}"#.to_vec(),
        ),
        (
            "unknown-with-duration",
            br#"{"request_id":1,"terminal":"unknown","status":null,"duration_ns":"1","tfm_id":null}"#.to_vec(),
        ),
    ] {
        let header = header_for(payload.len());
        assert!(
            matches!(
                backend.decode(&ctx, RawEvent { header, payload: &payload }),
                Err(BackendError::CorruptInput(_))
            ),
            "{name} must be corrupt_input"
        );
    }
}

#[test]
fn f8c_decode_rejections_are_input_free() {
    // Rejection diagnostics name the rule, never the offered bytes
    // (T05 input-free precedent — rejected bytes could be key
    // material or buffer contents).
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let integrity = IntegritySummary::default();
    let issuer = issuer();
    let ctx = decode_ctx(&integrity, &issuer);
    for (sentinel, payload) in [
        (
            "SECRETKEY",
            br#"{"request_id":1,"terminal":"sync","status":0,"duration_ns":"1","tfm_id":null,"SECRETKEY":1}"#.to_vec(),
        ),
        (
            "not-a-duration-SECRET",
            br#"{"request_id":1,"terminal":"sync","status":0,"duration_ns":"not-a-duration-SECRET","tfm_id":null}"#.to_vec(),
        ),
        (
            "frobnicate-SECRET",
            br#"{"request_id":1,"terminal":"frobnicate-SECRET","status":0,"duration_ns":"1","tfm_id":null}"#.to_vec(),
        ),
    ] {
        let header = header_for(payload.len());
        let err = backend
            .decode(&ctx, RawEvent { header, payload: &payload })
            .expect_err("must reject");
        let text = format!("{err:?}");
        assert!(
            !text.contains(sentinel),
            "rejection leaks input {sentinel:?}: {text}"
        );
    }
}

#[test]
fn f8c_finalize_pre_configure_pins_zeros() {
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let coverage = kryprobe_core::evidence::CoverageSummary::not_run();
    let baseline = IntegritySummary::default();
    let ctx = FinalizeContext {
        session: SessionId::new(7),
        coverage: &coverage,
        integrity: &baseline,
    };
    let summary = backend.finalize(&ctx).expect("pre-configure finalize");
    assert_eq!(summary.backend, BackendId::KCrypto);
    assert_eq!(summary.observations, 0);
    assert_eq!(summary.integrity, IntegritySummary::default());
}

#[test]
fn w3_finalize_pre_configure_attests_noted_omissions() {
    // Round-3 M3: the live driver reports cap drops before finalize
    // even when the sensor lives outside the backend (scripted/canary
    // sessions) — a reported drop must read back as `budget_omissions`,
    // never as the pre-configure zero.
    use kryprobe_core::backend::Backend as _;
    let (backend, _shared) = register_lifecycle_shared_for_test();
    backend.note_output_omissions(7);
    let coverage = kryprobe_core::evidence::CoverageSummary::not_run();
    let baseline = IntegritySummary::default();
    let ctx = FinalizeContext {
        session: SessionId::new(7),
        coverage: &coverage,
        integrity: &baseline,
    };
    let summary = backend.finalize(&ctx).expect("pre-configure finalize");
    assert_eq!(summary.integrity.budget_omissions, 7);
    let mut rest = summary.integrity;
    rest.budget_omissions = 0;
    assert_eq!(rest, IntegritySummary::default());
}

#[test]
fn f8c_register_profile_selects_one_backend() {
    use kryprobe_core::backend::BackendRegistry;
    let mut registry = BackendRegistry::new();
    let ProfileBackend::RequestLifecycle(_shared) =
        register_kcrypto_profile(&mut registry, LifecycleProfile::RequestLifecycle)
            .expect("first registration")
    else {
        panic!("want lifecycle handle");
    };
    assert_eq!(
        registry
            .get(BackendId::KCrypto)
            .expect("registered")
            .capabilities()
            .name,
        "kcrypto-lifecycle"
    );
    // The second profile is a typed duplicate, never a second capture.
    assert!(register_kcrypto(&mut registry).is_err());
    assert!(register_lifecycle(&mut registry).is_err());
    let mut registry = BackendRegistry::new();
    let ProfileBackend::ApiReturns(_shared) =
        register_kcrypto_profile(&mut registry, LifecycleProfile::ApiReturns).expect("aggregate")
    else {
        panic!("want aggregate handle");
    };
    assert_eq!(
        registry
            .get(BackendId::KCrypto)
            .expect("registered")
            .capabilities()
            .name,
        "kcrypto"
    );
    assert!(register_kcrypto_shared(&mut registry).is_err());
    assert!(register_lifecycle_shared(&mut registry).is_err());
}

#[test]
fn f8c_lifecycle_event_builder_round_trips() {
    // The driver builds RawEvents from completed records through the
    // same constructor decode consumes (no second encoding).
    let record = kryprobe_core::kcrypto::RequestRecord {
        id: 3,
        tfm_id: None,
        terminal: kryprobe_core::kcrypto::Terminal::Callback(-5),
        duration_ns: Some(70),
        meta: kryprobe_core::kcrypto::RequestMeta {
            family: kryprobe_core::kcrypto::LifecycleFamily::Skcipher,
            direction: kryprobe_core::kcrypto::OpDirection::Encrypt,
            cryptlen: Some(16),
            req_flags: Some(0),
            epoch: Some(0),
        },
    };
    let (header, payload) = lifecycle_event(&record);
    assert_eq!(header.backend_id, BACKEND_KCRYPTO);
    assert_eq!(header.event_kind, EVENT_OBSERVATION);
    assert_eq!(header.flags, 0);
    assert_eq!(
        header.total_len as usize,
        size_of::<RawEventHeader>() + payload.len()
    );
    let (backend, _shared) = register_lifecycle_shared_for_test();
    let integrity = IntegritySummary::default();
    let issuer = issuer();
    let ctx = decode_ctx(&integrity, &issuer);
    let obs = backend
        .decode(
            &ctx,
            RawEvent {
                header,
                payload: &payload,
            },
        )
        .expect("built envelope decodes");
    assert_eq!(obs.phase, EvidencePhase::Completed);
    assert_eq!(obs.native_result, NativeResult::KCrypto { status: -5 });
    assert_eq!(
        obs.backend_payload[K::TERMINAL],
        serde_json::json!("callback")
    );
    assert_eq!(obs.backend_payload[K::DURATION_NS], serde_json::json!("70"));
}

/// Test-only shared registration (mirrors the CLI's real path).
fn register_lifecycle_shared_for_test() -> (
    kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend,
    kryprobe_privilege::kcrypto_lifecycle::backend::SharedLifecycleBackend,
) {
    use kryprobe_core::backend::BackendRegistry;
    let mut registry = BackendRegistry::new();
    let shared = register_lifecycle_shared(&mut registry).expect("register");
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    (backend, shared)
}
