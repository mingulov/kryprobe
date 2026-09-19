// SPDX-License-Identifier: GPL-3.0-or-later
//! K2 Task 2: KCryptoBackend through the frozen trait + driver e2e.
//!
//! Unprivileged tests (registration, capabilities, plan shape, the
//! exhaustive FAM x OP x RES x CTX decode table, canonical statuses,
//! totals/ident decode, corrupt rejection, unconfigured finalize, and a
//! BPF-gated driver `run`) run everywhere. The privileged e2e
//! (`driver_e2e_matches_fixture_truth`) is an `#[ignore]`d lane-style
//! test that returns early (honest skip) when not root or when BTF is
//! missing; it brings up the K1 configured sensor, drives the Task-1 P4
//! `alg_fixture` traffic, snapshots, and proves the full
//! `BackendDriver::run` pass decodes fixture truth exactly.
//!
//! Privileged hygiene mirrors `kcrypto_snapshot.rs`: suite lock (sensors
//! are system-wide), prebuilt-as-user binary under sudo, workspace
//! BPF-lane lock. The one unprivileged `configure` test skips when root
//! (under the lane every test runs as root, and `configure` attaches).

use kryprobe_abi::kcrypto_agg::{
    KCTL_IDENT, KCTL_OVERFLOW, KCTX_KTHREAD, KCTX_PROC, KCTX_SOFTIRQ, KCTX_UNKNOWN, KFAM_AEAD,
    KFAM_AHASH, KFAM_ANY, KFAM_SHASH, KFAM_SK, KIDN_DROPS, KOP_ALLOC, KOP_DEC, KOP_DESTROY,
    KOP_DIGEST, KOP_ENC, KOP_FINUP, KRES_ERR, KRES_OK, KRES_QUEUED, KRES_UNOBSERVED, VAgg,
    kcrypto_ident_hash, kctl_from_bytes, kctl_pack_head, kctl_pack_lens,
};
use kryprobe_core::backend::{
    Backend, BackendDriver, BackendRegistry, ConfigureContext, DecodeContext, DetectContext,
    FinalizeContext, PlanContext, RawEvent,
};
use kryprobe_core::budget::{BudgetKind, BudgetManager};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::error::BackendError;
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegritySummary, NativeObservation, NativeResult,
    ValidityInterval,
};
use kryprobe_core::ids::{IdIssuer, ObservationId, PlanGeneration, SessionId};
use kryprobe_core::plan::{CapabilityRequirements, PlanBudget};
use kryprobe_privilege::btf_resolve::{KCRYPTO_SYMBOLS, load_kcrypto_configured};
use kryprobe_privilege::kcrypto_backend::{KCRYPTO_CAPABILITIES, KCryptoBackend, register_kcrypto};
use kryprobe_privilege::kcrypto_snapshot::{
    IdentBytes, ParsedRow, RowBytes, SnapshotRows, TotalsBytes, parse_snapshot_row,
    raw_event_for_agg, raw_event_for_ident, raw_event_for_totals, snapshot_rows,
};
use kryprobe_privilege::mapops::map_lookup_bytes;
use kryprobe_testkit::alg_fixture;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Hand-built rows (parameterized head; names + class-consistent counters).
// ---------------------------------------------------------------------------

const TEST_ALG: &str = "t-alg";
const TEST_DRV: &str = "t-drv";

/// Class-consistent `VAgg` words for one result class: `calls` observations
/// land in exactly their class bucket (UNOBSERVED rows carry `calls` but no
/// class counts — the K1 void-return shape).
fn vagg_words_for(res: u8) -> [u64; 15] {
    let (ok, errors, queued) = match res {
        KRES_OK => (7, 0, 0),
        KRES_ERR => (0, 7, 0),
        KRES_QUEUED => (0, 0, 7),
        _ => (0, 0, 0),
    };
    [
        7, 224, ok, errors, queued, // calls, bytes, ok, errors, queued
        100, 200, // first_ns, last_ns
        0, 0, 0, 0, 0, 0, 0, 0, // lat[8] (C4: single edge, no durations)
    ]
}

fn vagg_bytes_for(res: u8) -> [u8; 120] {
    let mut out = [0u8; 120];
    for (i, w) in vagg_words_for(res).iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Hand-encoded `KAgg`: head + NUL-padded names (128B each).
fn kagg_bytes_for(fam: u8, op: u8, res: u8, ctx: u8, alg: &str, drv: &str) -> [u8; 260] {
    let mut out = [0u8; 260];
    out[0..4].copy_from_slice(&[fam, op, res, ctx]);
    out[4..4 + alg.len()].copy_from_slice(alg.as_bytes());
    out[132..132 + drv.len()].copy_from_slice(drv.as_bytes());
    out
}

/// Valid 382B agg payload for one head combo.
fn agg_payload_for(fam: u8, op: u8, res: u8, ctx: u8) -> Vec<u8> {
    agg_payload_named(fam, op, res, ctx, TEST_ALG, TEST_DRV)
}

fn agg_payload_named(fam: u8, op: u8, res: u8, ctx: u8, alg: &str, drv: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(382);
    out.push(0x01);
    out.push(1);
    out.extend_from_slice(&kagg_bytes_for(fam, op, res, ctx, alg, drv));
    out.extend_from_slice(&vagg_bytes_for(res));
    out
}

/// Valid 122B totals payload.
fn totals_payload_for(res: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(122);
    out.push(0x01);
    out.push(2);
    out.extend_from_slice(&vagg_bytes_for(res));
    out
}

/// Valid 50B ident payload for one head + hash.
fn ident_payload_for(kind: u8, key_hash: u64, fam: u8, op: u8, res: u8, ctx: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(50);
    out.push(0x01);
    out.push(3);
    out.push(kind);
    out.extend_from_slice(&[0u8; 7]); // _p[3] + pad to key_hash@8
    out.extend_from_slice(&key_hash.to_le_bytes());
    out.extend_from_slice(&kctl_pack_head(fam, op, res, ctx).to_le_bytes());
    out.extend_from_slice(
        &kctl_pack_lens(TEST_ALG.len() as u32, TEST_DRV.len() as u32).to_le_bytes(),
    );
    out.extend_from_slice(&150u64.to_le_bytes()); // val2: first-seen ns
    out.extend_from_slice(&0u64.to_le_bytes()); // val3: reserved
    out
}

// ---------------------------------------------------------------------------
// Context builders (frozen-trait shapes; no privilege needed).
// ---------------------------------------------------------------------------

fn decode_ctx<'a>(
    session: SessionId,
    generation: PlanGeneration,
    integrity: &'a IntegritySummary,
    issuer: &'a IdIssuer,
) -> DecodeContext<'a> {
    DecodeContext {
        session,
        generation,
        integrity,
        id_issuer: issuer,
    }
}

fn coverage_all(status: CoverageStatus) -> CoverageSummary {
    let dimension = || {
        DimensionCoverage::new(
            status,
            ValidityInterval {
                start_ns: 0,
                end_ns: None,
            },
        )
    };
    CoverageSummary {
        target_population: dimension(),
        object_discovery: dimension(),
        attachment: dimension(),
        aggregate_counts: dimension(),
        detailed_events: dimension(),
        attribution: dimension(),
        correlation: dimension(),
        completion: dimension(),
    }
}

fn runtime_with_btf(btf_present: bool) -> RuntimeCapabilities {
    RuntimeCapabilities {
        kernel_release: "test".to_owned(),
        uprobe_multi: true,
        cookies: true,
        ringbuf: true,
        btf_present,
        userns: true,
        yama_scope: 0,
        caps: vec!["CAP_BPF".to_owned()],
    }
}

fn open_budget() -> BudgetManager {
    BudgetManager::new(PlanBudget {
        max_targets: u64::MAX,
        max_objects: u64::MAX,
        max_bytes: u64::MAX,
        max_links: u64::MAX,
        max_state_entries: u64::MAX,
        max_queue: u64::MAX,
        max_duration_ns: u64::MAX,
    })
}

/// Decode one hand-built agg payload through a fresh backend.
fn decode_agg(fam: u8, op: u8, res: u8, ctx: u8) -> NativeObservation {
    decode_agg_named(fam, op, res, ctx, TEST_ALG, TEST_DRV)
}

fn decode_agg_named(fam: u8, op: u8, res: u8, ctx: u8, alg: &str, drv: &str) -> NativeObservation {
    let backend = KCryptoBackend::new();
    let row = RowBytes::new(agg_payload_named(fam, op, res, ctx, alg, drv)).expect("hand row");
    let event = raw_event_for_agg(&row);
    let issuer = IdIssuer::default();
    let integrity = IntegritySummary::default();
    let ctx = decode_ctx(
        SessionId::new(1),
        PlanGeneration::new(1),
        &integrity,
        &issuer,
    );
    let obs = backend.decode(&ctx, event).expect("hand row decodes");
    // `row`/`event` borrow discipline: the event borrows the owned row.
    assert_eq!(event.payload.len(), 382);
    obs
}

// ---------------------------------------------------------------------------
// Expected D8 mapping (frozen-rule replica: D8 tables + observe.rs outcome
// derivation — `crates/kryprobe-report/src/observe.rs`, `outcome_of` plus
// the phase match in `observation()`).
// ---------------------------------------------------------------------------

fn expected_symbol(fam: u8, op: u8) -> Option<&'static str> {
    match op {
        KOP_ALLOC => Some("crypto_alloc_tfm_node"),
        KOP_DESTROY => Some("crypto_destroy_tfm"),
        KOP_ENC if fam == KFAM_SK => Some("crypto_skcipher_encrypt"),
        KOP_DEC if fam == KFAM_SK => Some("crypto_skcipher_decrypt"),
        KOP_ENC if fam == KFAM_AEAD => Some("crypto_aead_encrypt"),
        KOP_DEC if fam == KFAM_AEAD => Some("crypto_aead_decrypt"),
        KOP_DIGEST if fam == KFAM_AHASH => Some("crypto_ahash_digest"),
        KOP_DIGEST if fam == KFAM_SHASH => Some("crypto_shash_digest"),
        KOP_FINUP if fam == KFAM_SHASH => Some("crypto_shash_finup"),
        _ => None,
    }
}

fn expected_call_phase(op: u8, res: u8, inventory: bool) -> (CallKind, EvidencePhase) {
    let completed = res == KRES_OK || res == KRES_ERR;
    let (call, phase) = match op {
        KOP_ALLOC => (CallKind::Initialization, EvidencePhase::Selected),
        KOP_ENC | KOP_DEC | KOP_DIGEST => (
            CallKind::Operation,
            if completed {
                EvidencePhase::Completed
            } else {
                EvidencePhase::Entered
            },
        ),
        KOP_FINUP => (
            CallKind::Finalization,
            if completed {
                EvidencePhase::Completed
            } else {
                EvidencePhase::Entered
            },
        ),
        KOP_DESTROY => (CallKind::Unknown, EvidencePhase::Returned),
        _ => (CallKind::Unknown, EvidencePhase::Entered),
    };
    if inventory {
        (call, EvidencePhase::Selected)
    } else {
        (call, phase)
    }
}

fn expected_status(res: u8) -> i32 {
    match res {
        KRES_OK => 0,
        KRES_ERR => -5,      // -EIO canonical
        KRES_QUEUED => -115, // -EINPROGRESS canonical
        _ => 0,
    }
}

/// Frozen report derivation replica: phase gates first, then the kcrypto
/// status arm of `outcome_of` (0 -> success, -115 -> pending, else failure).
fn expected_outcome(phase: EvidencePhase, status: i32) -> &'static str {
    match phase {
        EvidencePhase::Discovered | EvidencePhase::Selected => "not_applicable",
        EvidencePhase::Entered => "pending",
        EvidencePhase::Returned | EvidencePhase::Completed => {
            if status == 0 {
                "success"
            } else if status == -115 {
                "pending"
            } else {
                "failure"
            }
        }
        EvidencePhase::Succeeded => panic!("Succeeded never decodes"),
    }
}

fn expected_context(ctx: u8) -> &'static str {
    match ctx {
        KCTX_PROC => "process",
        KCTX_KTHREAD => "kthread",
        KCTX_SOFTIRQ => "softirq",
        _ => "unknown",
    }
}

fn expected_class(op: u8) -> OperationClass {
    match op {
        KOP_ENC => OperationClass::Encrypt,
        KOP_DEC => OperationClass::Decrypt,
        KOP_DIGEST | KOP_FINUP => OperationClass::Digest,
        KOP_ALLOC | KOP_DESTROY => OperationClass::KeyManagement,
        _ => OperationClass::Unknown,
    }
}

fn outcome_of_obs(obs: &NativeObservation) -> &'static str {
    let NativeResult::KCrypto { status } = obs.native_result else {
        panic!("kcrypto decode must emit KCrypto results");
    };
    expected_outcome(obs.phase, status)
}

// ---------------------------------------------------------------------------
// Registration + capabilities + detect + plan.
// ---------------------------------------------------------------------------

#[test]
fn capabilities_require_btf_only() {
    assert_eq!(KCRYPTO_CAPABILITIES.backend, BackendId::KCrypto);
    assert_eq!(KCRYPTO_CAPABILITIES.name, "kcrypto");
    assert_eq!(
        KCRYPTO_CAPABILITIES.required,
        CapabilityRequirements {
            uprobe_multi: false,
            cookies: false,
            ringbuf: false,
            btf: true,
        },
        "D2: btf gate only (ringbuf universal, uprobe_multi/cookies N/A to fexit)"
    );
    let backend = KCryptoBackend::new();
    assert_eq!(backend.id(), BackendId::KCrypto);
    assert!(backend.capabilities().required.btf);
}

fn btf_available() -> bool {
    std::fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

#[test]
fn register_kcrypto_detects_system_instance() {
    if !btf_available() {
        println!(
            "SKIP: register_kcrypto_detects_system_instance requires BTF (lane hosts have it)"
        );
        return;
    }
    let mut registry = BackendRegistry::new();
    register_kcrypto(&mut registry).expect("first registration ok");
    let backend = registry
        .get(BackendId::KCrypto)
        .expect("kcrypto registered");
    let runtime = runtime_with_btf(true);
    let ctx = DetectContext {
        session: SessionId::new(1),
        runtime: &runtime,
    };
    let instances = backend.detect(&ctx).expect("detect ok on BTF host");
    assert_eq!(instances.len(), 1, "D4: exactly one system instance");
    assert_eq!(instances[0].backend, BackendId::KCrypto);
    assert_eq!(instances[0].object, None);
    assert_eq!(
        instances[0].detail, "system kcrypto sensor (9 fexit points)",
        "D4 detail verbatim"
    );
}

#[test]
fn duplicate_registration_rejected() {
    let mut registry = BackendRegistry::new();
    register_kcrypto(&mut registry).expect("first registration ok");
    let err = register_kcrypto(&mut registry).expect_err("second registration refuses");
    assert_eq!(err.backend, BackendId::KCrypto);
    assert_eq!(registry.discover_all().len(), 1, "registry unchanged");
}

#[test]
fn plan_proposes_nine_ordinal_probes() {
    assert_eq!(KCRYPTO_SYMBOLS.len(), 9, "K1 pins 9 attach symbols");
    let backend = KCryptoBackend::new();
    let runtime = runtime_with_btf(true);
    let plan_ctx = PlanContext {
        session: SessionId::new(1),
        runtime: &runtime,
    };
    let instance = kryprobe_core::backend::DetectedInstance {
        backend: BackendId::KCrypto,
        object: None,
        detail: "system kcrypto sensor (9 fexit points)".to_owned(),
    };
    for mode in [
        kryprobe_core::enums::CaptureMode::Inventory,
        kryprobe_core::enums::CaptureMode::Profile,
        kryprobe_core::enums::CaptureMode::Trace,
    ] {
        let plan = backend.plan(&plan_ctx, &instance, mode).expect("plan ok");
        assert_eq!(plan.backend, BackendId::KCrypto);
        assert_eq!(plan.probes.len(), 9, "D3: 9 probes in {mode:?} mode");
        for (i, probe) in plan.probes.iter().enumerate() {
            assert_eq!(probe.file_offset, 0, "D3: kernel symbol, no file");
            assert_eq!(probe.cookie, 0, "D3: fexit ignores cookies");
            assert_eq!(probe.descriptor_id, i as u32, "D3: KCRYPTO_SYMBOLS ordinal");
        }
        assert_eq!(
            plan.required, KCRYPTO_CAPABILITIES.required,
            "plan echoes the static required gates"
        );
    }
}

// ---------------------------------------------------------------------------
// Decode: hand-worked spot cases (truth pins) + the exhaustive 480 table.
// ---------------------------------------------------------------------------

#[test]
fn decode_spot_cases_pin_d8_tables() {
    // (SK,ENC,OK,PROC): the canonical success row.
    let obs = decode_agg(KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC);
    assert_eq!(obs.backend, BackendId::KCrypto);
    assert_eq!(obs.call_kind, CallKind::Operation);
    assert_eq!(obs.phase, EvidencePhase::Completed);
    assert_eq!(obs.native_result, NativeResult::KCrypto { status: 0 });
    assert_eq!(outcome_of_obs(&obs), "success");
    assert_eq!(
        obs.native_name.as_ref().map(|n| n.as_str()),
        Some("crypto_skcipher_encrypt")
    );
    assert_eq!(obs.operation_class, OperationClass::Encrypt);
    assert_eq!(obs.backend_payload["context"], "process");
    assert!(obs.backend_payload.get("execution").is_none());
    assert_eq!(obs.target, None);
    assert_eq!(obs.object, None);
    assert_eq!(obs.implementation, None);
    assert_eq!(obs.started_ns, Some(100));
    assert_eq!(obs.ended_ns, Some(200));

    // (AEAD,DEC,ERR,KTHREAD): canonical -EIO failure.
    let obs = decode_agg(KFAM_AEAD, KOP_DEC, KRES_ERR, KCTX_KTHREAD);
    assert_eq!(
        (obs.call_kind, obs.phase),
        (CallKind::Operation, EvidencePhase::Completed)
    );
    assert_eq!(obs.native_result, NativeResult::KCrypto { status: -5 });
    assert_eq!(outcome_of_obs(&obs), "failure");
    assert_eq!(
        obs.native_name.as_ref().map(|n| n.as_str()),
        Some("crypto_aead_decrypt")
    );
    assert_eq!(obs.backend_payload["context"], "kthread");
    assert_eq!(
        obs.backend_payload["status_canonical"].as_bool(),
        Some(true)
    );

    // (SK,ENC,QUEUED,SOFTIRQ): canonical -EINPROGRESS pending.
    let obs = decode_agg(KFAM_SK, KOP_ENC, KRES_QUEUED, KCTX_SOFTIRQ);
    assert_eq!(
        (obs.call_kind, obs.phase),
        (CallKind::Operation, EvidencePhase::Entered)
    );
    assert_eq!(obs.native_result, NativeResult::KCrypto { status: -115 });
    assert_eq!(outcome_of_obs(&obs), "pending");
    assert_eq!(obs.backend_payload["context"], "softirq");

    // (SHASH,FINUP,OK,UNKNOWN): finalization call kind.
    let obs = decode_agg(KFAM_SHASH, KOP_FINUP, KRES_OK, KCTX_UNKNOWN);
    assert_eq!(
        (obs.call_kind, obs.phase),
        (CallKind::Finalization, EvidencePhase::Completed)
    );
    assert_eq!(
        obs.native_name.as_ref().map(|n| n.as_str()),
        Some("crypto_shash_finup")
    );
    assert_eq!(obs.operation_class, OperationClass::Digest);
    assert_eq!(obs.backend_payload["context"], "unknown");

    // (ANY,ALLOC,OK,PROC): inventory-only (D8).
    let obs = decode_agg(KFAM_ANY, KOP_ALLOC, KRES_OK, KCTX_PROC);
    assert_eq!(
        (obs.call_kind, obs.phase),
        (CallKind::Initialization, EvidencePhase::Selected)
    );
    assert_eq!(outcome_of_obs(&obs), "not_applicable");
    assert_eq!(
        obs.native_name.as_ref().map(|n| n.as_str()),
        Some("crypto_alloc_tfm_node")
    );
    assert_eq!(obs.backend_payload["execution"], "unsupported");

    // (ANY,ENC,OK,PROC): defensive ANY+exec (BPF never emits) — same
    // inventory treatment, never crash, never silent.
    let obs = decode_agg(KFAM_ANY, KOP_ENC, KRES_OK, KCTX_PROC);
    assert_eq!(
        (obs.call_kind, obs.phase),
        (CallKind::Operation, EvidencePhase::Selected)
    );
    assert_eq!(outcome_of_obs(&obs), "not_applicable");
    assert_eq!(obs.native_name, None, "unknown family: no symbol to name");
    assert_eq!(obs.backend_payload["execution"], "unsupported");

    // (AHASH,DIGEST,OK,PROC) + (SHASH,DIGEST,OK,PROC): hash symbols.
    let obs = decode_agg(KFAM_AHASH, KOP_DIGEST, KRES_OK, KCTX_PROC);
    assert_eq!(
        obs.native_name.as_ref().map(|n| n.as_str()),
        Some("crypto_ahash_digest")
    );
    let obs = decode_agg(KFAM_SHASH, KOP_DIGEST, KRES_OK, KCTX_PROC);
    assert_eq!(
        obs.native_name.as_ref().map(|n| n.as_str()),
        Some("crypto_shash_digest")
    );

    // Impossible-live combo (SK,DIGEST): normal op/res mapping, no symbol.
    let obs = decode_agg(KFAM_SK, KOP_DIGEST, KRES_OK, KCTX_PROC);
    assert_eq!(
        (obs.call_kind, obs.phase),
        (CallKind::Operation, EvidencePhase::Completed)
    );
    assert_eq!(obs.native_name, None);
    assert!(obs.backend_payload.get("execution").is_none());
}

/// Exhaustive FAM(5) x OP(6) x RES(4) x CTX(4) = 480 combos: every head
/// decodes (total function, never crash) with the D8-exact mapping.
#[test]
fn decode_cartesian_480_pins_full_contract() {
    let fams = [KFAM_ANY, KFAM_SK, KFAM_AEAD, KFAM_AHASH, KFAM_SHASH];
    let ops = [
        KOP_ALLOC,
        KOP_DESTROY,
        KOP_ENC,
        KOP_DEC,
        KOP_DIGEST,
        KOP_FINUP,
    ];
    let ress = [KRES_OK, KRES_ERR, KRES_QUEUED, KRES_UNOBSERVED];
    let ctxs = [KCTX_PROC, KCTX_KTHREAD, KCTX_SOFTIRQ, KCTX_UNKNOWN];
    let backend = KCryptoBackend::new();
    let issuer = IdIssuer::default();
    let integrity = IntegritySummary::default();
    let ctx = decode_ctx(
        SessionId::new(1),
        PlanGeneration::new(1),
        &integrity,
        &issuer,
    );
    let mut count = 0u32;
    for fam in fams {
        for op in ops {
            for res in ress {
                for ct in ctxs {
                    let row = RowBytes::new(agg_payload_for(fam, op, res, ct)).expect("hand row");
                    let event = raw_event_for_agg(&row);
                    let obs = backend.decode(&ctx, event).expect("every head decodes");
                    let inventory = fam == KFAM_ANY;
                    let (call, phase) = expected_call_phase(op, res, inventory);
                    let status = expected_status(res);
                    assert_eq!(
                        obs.backend,
                        BackendId::KCrypto,
                        "combo {fam}/{op}/{res}/{ct}"
                    );
                    assert_eq!(obs.call_kind, call, "combo {fam}/{op}/{res}/{ct}: call");
                    assert_eq!(obs.phase, phase, "combo {fam}/{op}/{res}/{ct}: phase");
                    assert_eq!(
                        obs.native_result,
                        NativeResult::KCrypto { status },
                        "combo {fam}/{op}/{res}/{ct}: status"
                    );
                    assert_eq!(
                        outcome_of_obs(&obs),
                        expected_outcome(phase, status),
                        "combo {fam}/{op}/{res}/{ct}: outcome"
                    );
                    assert_eq!(
                        obs.native_name.as_ref().map(|n| n.as_str()),
                        expected_symbol(fam, op),
                        "combo {fam}/{op}/{res}/{ct}: symbol"
                    );
                    assert_eq!(
                        obs.operation_class,
                        expected_class(op),
                        "combo {fam}/{op}/{res}/{ct}: class"
                    );
                    assert_eq!(
                        obs.backend_payload["context"],
                        expected_context(ct),
                        "combo {fam}/{op}/{res}/{ct}: context"
                    );
                    assert_eq!(
                        obs.backend_payload.get("execution").is_some(),
                        inventory,
                        "combo {fam}/{op}/{res}/{ct}: inventory flag"
                    );
                    if inventory {
                        assert_eq!(obs.backend_payload["execution"], "unsupported");
                    }
                    // Identity echo: names, counts, bytes, window, flag.
                    assert_eq!(obs.backend_payload["algorithm"], TEST_ALG);
                    assert_eq!(obs.backend_payload["driver"], TEST_DRV);
                    assert_eq!(obs.backend_payload["counts"]["calls"].as_u64(), Some(7));
                    assert_eq!(obs.backend_payload["bytes"].as_u64(), Some(224));
                    assert_eq!(
                        obs.backend_payload["window"]["first_ns"].as_u64(),
                        Some(100)
                    );
                    assert_eq!(obs.backend_payload["window"]["last_ns"].as_u64(), Some(200));
                    assert_eq!(
                        obs.backend_payload["status_canonical"].as_bool(),
                        Some(true)
                    );
                    // UNOBSERVED rows carry the payload note; others must not.
                    assert_eq!(
                        obs.backend_payload.get("result_note").is_some(),
                        res == KRES_UNOBSERVED,
                        "combo {fam}/{op}/{res}/{ct}: result note"
                    );
                    assert_eq!(obs.id, ObservationId::new(count as u64 + 1), "ids sequence");
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 480, "5 x 6 x 4 x 4 combos");
    // The backend counted every decode.
    let coverage = coverage_all(CoverageStatus::NotRun);
    let fin_ctx = FinalizeContext {
        session: SessionId::new(1),
        coverage: &coverage,
        integrity: &integrity,
    };
    let summary = backend
        .finalize(&fin_ctx)
        .expect("unconfigured finalize ok");
    assert_eq!(summary.observations, 480, "finalize echoes decoded");
}

#[test]
fn canonical_codes_pin_eio_einprogress() {
    assert_eq!(-libc_eio(), -5, "EIO pins 5 (Linux)");
    assert_eq!(-libc_einprogress(), -115, "EINPROGRESS pins 115 (Linux)");
    let err = decode_agg(KFAM_SK, KOP_ENC, KRES_ERR, KCTX_PROC);
    assert_eq!(err.native_result, NativeResult::KCrypto { status: -5 });
    assert_eq!(
        err.backend_payload["status_canonical"].as_bool(),
        Some(true)
    );
    let queued = decode_agg(KFAM_SK, KOP_ENC, KRES_QUEUED, KCTX_PROC);
    assert_eq!(queued.native_result, NativeResult::KCrypto { status: -115 });
    assert_eq!(
        queued.backend_payload["status_canonical"].as_bool(),
        Some(true)
    );
    // The flag rides every row: the sensor counts classes, never codes (D9).
    let ok = decode_agg(KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC);
    assert_eq!(ok.backend_payload["status_canonical"].as_bool(), Some(true));
}

/// `libc` errno values (the backend maps through these, not literals).
fn libc_eio() -> i32 {
    libc::EIO
}

fn libc_einprogress() -> i32 {
    libc::EINPROGRESS
}

#[test]
fn destroy_unobserved_arms_mapped_but_unreachable() {
    // DESTROY -> (unknown, Returned): mapped per D8, unreachable because
    // destroy rows never materialize (K1-proven void path).
    let obs = decode_agg(KFAM_ANY, KOP_DESTROY, KRES_OK, KCTX_PROC);
    assert_eq!(
        obs.native_name.as_ref().map(|n| n.as_str()),
        Some("crypto_destroy_tfm")
    );
    // ANY-fam inventory override still applies (Selected, not Returned).
    assert_eq!(obs.phase, EvidencePhase::Selected);
    let obs = decode_agg(KFAM_SK, KOP_DESTROY, KRES_OK, KCTX_PROC);
    assert_eq!(
        (obs.call_kind, obs.phase),
        (CallKind::Unknown, EvidencePhase::Returned)
    );
    // UNOBSERVED -> status 0 + payload note (unreachable: only the void
    // destroy path carries it, and that path emits no rows).
    let obs = decode_agg(KFAM_SK, KOP_DESTROY, KRES_UNOBSERVED, KCTX_PROC);
    assert_eq!(obs.native_result, NativeResult::KCrypto { status: 0 });
    assert_eq!(
        obs.backend_payload["result_note"],
        "unobserved: void return carries no result class (destroy path)"
    );
    // Reachable rows never carry the note.
    let obs = decode_agg(KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC);
    assert!(obs.backend_payload.get("result_note").is_none());
}

#[test]
fn decode_rejects_corrupt_without_counting() {
    let backend = KCryptoBackend::new();
    let issuer = IdIssuer::default();
    let integrity = IntegritySummary::default();
    let ctx = decode_ctx(
        SessionId::new(1),
        PlanGeneration::new(1),
        &integrity,
        &issuer,
    );
    let row = RowBytes::new(agg_payload_for(KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC)).expect("row");
    let good = raw_event_for_agg(&row);
    // Corrupt the version byte through a borrowed bad payload.
    let mut bad = good.payload.to_vec();
    bad[0] = 0x00;
    let bad_event = RawEvent {
        header: good.header,
        payload: &bad,
    };
    let err = backend
        .decode(&ctx, bad_event)
        .expect_err("bad version refuses");
    assert!(
        matches!(err, BackendError::CorruptInput(_)),
        "parse errors pass through, got {err:?}"
    );
    // The refused decode counted nothing and issued no id.
    assert_eq!(issuer.issue().expect("ids live"), ObservationId::new(1));
    let coverage = coverage_all(CoverageStatus::NotRun);
    let fin_ctx = FinalizeContext {
        session: SessionId::new(1),
        coverage: &coverage,
        integrity: &integrity,
    };
    assert_eq!(
        backend.finalize(&fin_ctx).expect("finalize").observations,
        0,
        "refused decodes never count"
    );
}

#[test]
fn totals_row_decodes_to_completed_aggregate() {
    let backend = KCryptoBackend::new();
    let totals = TotalsBytes::new(totals_payload_for(KRES_OK)).expect("totals");
    let event = raw_event_for_totals(&totals);
    let issuer = IdIssuer::default();
    let integrity = IntegritySummary::default();
    let ctx = decode_ctx(
        SessionId::new(1),
        PlanGeneration::new(1),
        &integrity,
        &issuer,
    );
    let obs = backend.decode(&ctx, event).expect("totals decodes");
    assert_eq!(obs.backend, BackendId::KCrypto);
    assert_eq!(obs.phase, EvidencePhase::Completed);
    assert_eq!(obs.call_kind, CallKind::Unknown);
    assert_eq!(obs.operation_class, OperationClass::Unknown);
    assert_eq!(obs.native_name, None);
    assert_eq!(obs.native_result, NativeResult::KCrypto { status: 0 });
    assert_eq!(outcome_of_obs(&obs), "success");
    assert_eq!(obs.backend_payload["row"], "totals");
    assert_eq!(obs.backend_payload["counts"]["calls"].as_u64(), Some(7));
    assert_eq!(obs.backend_payload["counts"]["ok"].as_u64(), Some(7));
    assert_eq!(obs.backend_payload["bytes"].as_u64(), Some(224));
    assert_eq!(
        obs.backend_payload["window"]["first_ns"].as_u64(),
        Some(100)
    );
    assert_eq!(obs.backend_payload["window"]["last_ns"].as_u64(), Some(200));
    assert_eq!(
        obs.backend_payload["status_canonical"].as_bool(),
        Some(true)
    );
    assert_eq!(obs.started_ns, Some(100));
    assert_eq!(obs.ended_ns, Some(200));
}

#[test]
fn ident_rows_decode_to_discovered_markers() {
    let backend = KCryptoBackend::new();
    let issuer = IdIssuer::default();
    let integrity = IntegritySummary::default();
    let ctx = decode_ctx(
        SessionId::new(1),
        PlanGeneration::new(1),
        &integrity,
        &issuer,
    );
    for (kind, kind_str) in [(KCTL_IDENT, "ident"), (KCTL_OVERFLOW, "overflow")] {
        let hash = 0x0102_0304_0506_0708u64;
        let ident = IdentBytes::new(ident_payload_for(
            kind, hash, KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC,
        ))
        .expect("ident");
        // The KCtl body parses (Task-1 codec shape).
        let kctl = kctl_from_bytes(&ident.0[2..]).expect("KCtl body");
        assert_eq!(kctl.kind, kind);
        let event = raw_event_for_ident(&ident);
        let obs = backend.decode(&ctx, event).expect("ident decodes");
        assert_eq!(obs.backend, BackendId::KCrypto);
        assert_eq!(obs.phase, EvidencePhase::Discovered, "first-seen = found");
        assert_eq!(outcome_of_obs(&obs), "not_applicable");
        assert_eq!(obs.call_kind, CallKind::Operation, "head-derived");
        assert_eq!(obs.operation_class, OperationClass::Encrypt);
        assert_eq!(
            obs.native_name.as_ref().map(|n| n.as_str()),
            Some("crypto_skcipher_encrypt")
        );
        assert_eq!(obs.backend_payload["row"], "ident");
        assert_eq!(obs.backend_payload["ident_kind"], kind_str);
        assert_eq!(obs.backend_payload["key_hash"].as_u64(), Some(hash));
        assert_eq!(obs.backend_payload["family"], "skcipher");
        assert_eq!(obs.backend_payload["op"], "encrypt");
        assert_eq!(obs.backend_payload["result"], "ok");
        assert_eq!(obs.backend_payload["context"], "process");
        assert_eq!(
            obs.backend_payload["name_lens"],
            serde_json_like(TEST_ALG.len() as u64, TEST_DRV.len() as u64)
        );
        assert_eq!(obs.backend_payload["first_seen_ns"].as_u64(), Some(150));
        assert_eq!(obs.started_ns, Some(150));
        assert_eq!(obs.ended_ns, None, "first-seen is an instant");
    }
}

/// The `name_lens` object the backend emits (`{"alg": N, "drv": M}`).
fn serde_json_like(alg: u64, drv: u64) -> serde_json::Value {
    serde_json::json!({"alg": alg, "drv": drv})
}

#[test]
fn finalize_unconfigured_counts_without_integrity() {
    // Pre-configure finalize observes no sensor: observations echo decoded,
    // integrity pins zero (documented; the priv e2e covers live integrity).
    let backend = KCryptoBackend::new();
    let issuer = IdIssuer::default();
    let integrity = IntegritySummary::default();
    let ctx = decode_ctx(
        SessionId::new(1),
        PlanGeneration::new(1),
        &integrity,
        &issuer,
    );
    for (op, res) in [(KOP_ENC, KRES_OK), (KOP_DEC, KRES_ERR)] {
        let row = RowBytes::new(agg_payload_for(KFAM_SK, op, res, KCTX_PROC)).expect("row");
        backend
            .decode(&ctx, raw_event_for_agg(&row))
            .expect("decode");
    }
    let coverage = coverage_all(CoverageStatus::Partial);
    // A nonzero ctx baseline must never echo (synthetic pattern).
    let baseline = IntegritySummary {
        ring_reservation_failures: 99,
        ..IntegritySummary::default()
    };
    let fin_ctx = FinalizeContext {
        session: SessionId::new(1),
        coverage: &coverage,
        integrity: &baseline,
    };
    let summary = backend.finalize(&fin_ctx).expect("finalize");
    assert_eq!(summary.backend, BackendId::KCrypto);
    assert_eq!(summary.observations, 2);
    assert_eq!(
        summary.integrity,
        IntegritySummary::default(),
        "never echo ctx"
    );
}

#[test]
fn driver_run_over_handfed_rows_green_unpriv() {
    // Full `driver.run` with the BTF gate unsatisfied: the backend skips
    // honestly (visible receipt, no attach, no budget) and the run is Ok.
    // `configure` never runs, so this is green unprivileged AND as root.
    let rows: Vec<RowBytes> = [KOP_ENC, KOP_DEC]
        .iter()
        .map(|op| RowBytes::new(agg_payload_for(KFAM_SK, *op, KRES_OK, KCTX_PROC)).expect("row"))
        .collect();
    let totals = TotalsBytes::new(totals_payload_for(KRES_OK)).expect("totals");
    let events: Vec<RawEvent<'_>> = rows
        .iter()
        .map(raw_event_for_agg)
        .chain(std::iter::once(raw_event_for_totals(&totals)))
        .collect();
    let mut registry = BackendRegistry::new();
    register_kcrypto(&mut registry).expect("register");
    let mut driver = BackendDriver::harness();
    let report = driver
        .run(&registry, &runtime_with_btf(false), &events)
        .expect("gated run is Ok");
    assert!(
        report.observations.is_empty(),
        "skipped backend decodes nothing"
    );
    assert!(report.plans.is_empty());
    assert!(report.summaries.is_empty());
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].backend, BackendId::KCrypto);
    assert_eq!(report.skipped[0].dropped_events, 3, "skip drops receipted");
    assert_eq!(report.skipped_drops(), 3);
}

fn is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn configure_fails_honestly_without_privilege() {
    if is_root() {
        println!("SKIP: configure_fails_honestly_without_privilege refuses to attach as root");
        return;
    }
    // Unprivileged `configure` loads nothing: it fails typed (Denied when
    // the BPF object is present but un-loadable, Unsupported when the
    // object itself is missing) — never panics, never half-charges.
    let backend = KCryptoBackend::new();
    let mut budget = open_budget();
    let mut ctx = ConfigureContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        budget: &mut budget,
    };
    let plan = kryprobe_core::backend::BackendPlan {
        backend: BackendId::KCrypto,
        probes: vec![],
        required: KCRYPTO_CAPABILITIES.required,
    };
    let err = backend
        .configure(&mut ctx, &plan)
        .expect_err("unpriv configure fails");
    assert!(
        matches!(err, BackendError::Denied(_) | BackendError::Unsupported(_)),
        "honest typed failure, got {err:?}"
    );
    assert_eq!(
        budget.used(BudgetKind::Links),
        0,
        "failed configure charges nothing"
    );
    assert_eq!(budget.used(BudgetKind::StateEntries), 0);
}

// ---------------------------------------------------------------------------
// Privileged scaffolding (lane_ready + suite lock + sensor: the
// kcrypto_snapshot idiom; P4 traffic counts identical to Task 1).
// ---------------------------------------------------------------------------

/// Workspace-relative path of the built kcrypto object.
fn kcrypto_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("kcrypto.bpf.o")
}

fn kcrypto_bytes() -> Vec<u8> {
    let path = kcrypto_object_path();
    assert!(
        path.is_file(),
        "missing BPF kcrypto object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
    std::fs::read(&path).expect("test fixture must be readable")
}

/// Privileged-gate: true when this test must run (root + BTF).
/// Callers `return` early on false (honest skip, prints why).
fn lane_ready(name: &str) -> bool {
    if !is_root() {
        println!("SKIP: {name} requires root (euid != 0)");
        return false;
    }
    if !btf_available() {
        println!("SKIP: {name} requires /sys/kernel/btf/vmlinux");
        return false;
    }
    true
}

/// Suite serialization lock: sensors are system-wide. The privileged e2e
/// holds this across its whole body (attach→detach). Poison-tolerant.
static SUITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn suite_guard() -> std::sync::MutexGuard<'static, ()> {
    SUITE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Sum decoded agg-observation counts matching (family, op, result, alg).
fn sum_obs(
    observations: &[NativeObservation],
    family: &str,
    op: &str,
    result: &str,
    alg: &str,
) -> (u64, u64, u64, u64, u64) {
    let mut out = (0, 0, 0, 0, 0);
    for obs in observations.iter().filter(|o| {
        o.backend_payload.get("row") == Some(&serde_json::json!("agg"))
            && o.backend_payload.get("family") == Some(&serde_json::json!(family))
            && o.backend_payload.get("op") == Some(&serde_json::json!(op))
            && o.backend_payload.get("result") == Some(&serde_json::json!(result))
            && o.backend_payload.get("algorithm") == Some(&serde_json::json!(alg))
    }) {
        let counts = &obs.backend_payload["counts"];
        out.0 += counts["calls"].as_u64().expect("calls u64");
        out.1 += obs.backend_payload["bytes"].as_u64().expect("bytes u64");
        out.2 += counts["ok"].as_u64().expect("ok u64");
        out.3 += counts["errors"].as_u64().expect("errors u64");
        out.4 += counts["queued"].as_u64().expect("queued u64");
    }
    out
}

fn words_for_name(name: &str) -> [u64; 16] {
    let mut bytes = [0u8; 128];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    let mut words = [0u64; 16];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("8B word"));
    }
    words
}

fn fam_num(family: &str) -> u8 {
    match family {
        "any" => KFAM_ANY,
        "skcipher" => KFAM_SK,
        "aead" => KFAM_AEAD,
        "ahash" => KFAM_AHASH,
        "shash" => KFAM_SHASH,
        other => panic!("unknown family {other:?}"),
    }
}

fn op_num(op: &str) -> u8 {
    match op {
        "alloc" => KOP_ALLOC,
        "destroy" => KOP_DESTROY,
        "encrypt" => KOP_ENC,
        "decrypt" => KOP_DEC,
        "digest" => KOP_DIGEST,
        "finup" => KOP_FINUP,
        other => panic!("unknown op {other:?}"),
    }
}

#[test]
#[ignore = "BPF lane: run under sudo with the lane lock"]
fn driver_e2e_matches_fixture_truth() {
    let _guard = suite_guard();
    if !lane_ready("driver_e2e_matches_fixture_truth") {
        return;
    }
    // The backend's `configure` loads its own sensor from this object
    // (direct-privileged, token None per D5); the env locator is exact.
    let object_path = kcrypto_object_path();
    assert!(object_path.is_file(), "BPF object must be prebuilt");
    // SAFETY: single-process test binary; only the backend's configure
    // reads this var, and only this suite-locked test triggers configure.
    unsafe {
        std::env::set_var(
            "KRYPROBE_BPF_DIR",
            object_path.as_os_str().to_string_lossy().into_owned(),
        );
    }
    let bytes = kcrypto_bytes();
    let (sensor, _points) = load_kcrypto_configured(&bytes, None)
        .unwrap_or_else(|err| panic!("bring-up failed: {err}"));
    // Task-1 P4 traffic, identical counts (lane-exclusive, fresh sensor).
    let sk = alg_fixture::skcipher_roundtrip("cbc(aes)", 20).expect("skcipher traffic");
    assert_eq!((sk.enc, sk.dec), (20, 20));
    let single = alg_fixture::hash_digest("sha512", 8).expect("hash traffic");
    assert_eq!((single.digests, single.digest_len), (8, 64));
    let multi = alg_fixture::hash_digest_multi("sha512", 4).expect("hashmulti traffic");
    assert_eq!(multi.digests, 4);
    let aead = alg_fixture::aead_roundtrip("gcm(aes)", 10).expect("aead traffic");
    assert_eq!((aead.enc, aead.dec), (10, 10));
    alg_fixture::aead_decrypt_bad_tag("gcm(aes)").expect("bad-tag decrypt must EBADMSG");

    // Snapshot, then drive the FULL lifecycle through `driver.run`
    // (registry + register_kcrypto + live-shape runtime caps). The owned
    // blobs outlive the run; events borrow them (D6).
    let snap: SnapshotRows = snapshot_rows(&sensor).expect("snapshot_rows");
    assert!(!snap.rows.is_empty(), "snapshot must carry agg rows");
    let mut events: Vec<RawEvent<'_>> = snap.rows.iter().map(raw_event_for_agg).collect();
    if let Some(totals) = snap.totals.as_ref() {
        events.push(raw_event_for_totals(totals));
    }
    for ident in &snap.idents {
        events.push(raw_event_for_ident(ident));
    }
    let mut registry = BackendRegistry::new();
    register_kcrypto(&mut registry).expect("register");
    let mut driver = BackendDriver::harness();
    let runtime = RuntimeCapabilities {
        kernel_release: "lane".to_owned(),
        uprobe_multi: true,
        cookies: true,
        ringbuf: true,
        btf_present: true,
        userns: true,
        yama_scope: 0,
        caps: vec!["CAP_BPF".to_owned(), "CAP_SYS_ADMIN".to_owned()],
    };
    let report = driver
        .run(&registry, &runtime, &events)
        .unwrap_or_else(|err| panic!("driver run failed: {err}"));
    assert!(report.skipped.is_empty(), "no skips on a healthy lane host");
    assert_eq!(report.plans.len(), 1, "one plan for one instance");
    assert_eq!(report.plans[0].probes.len(), 9);
    assert_eq!(report.summaries.len(), 1);
    let observations = &report.observations;
    assert_eq!(
        observations.len(),
        events.len(),
        "one observation per fed event ({} rows + totals + {} idents)",
        snap.rows.len(),
        snap.idents.len()
    );
    // Session IDs sequence from 1 in feed order (single backend).
    for (i, obs) in observations.iter().enumerate() {
        assert_eq!(obs.id, ObservationId::new(i as u64 + 1), "ids sequence");
        assert_eq!(obs.backend, BackendId::KCrypto);
    }

    // Fixture truth through DECODED observations (payload counts, P4):
    // skcipher roundtrip.
    assert_eq!(
        sum_obs(observations, "skcipher", "encrypt", "ok", "cbc(aes)"),
        (20, 20 * 32, 20, 0, 0)
    );
    assert_eq!(
        sum_obs(observations, "skcipher", "decrypt", "ok", "cbc(aes)"),
        (20, 20 * 32, 20, 0, 0)
    );
    assert_eq!(
        sum_obs(observations, "any", "alloc", "ok", "cbc(aes)").0,
        1,
        "one bind alloc"
    );
    // Hash: one ahash + one shash observation per single-shot op (64B
    // each), two finups per multi digest.
    assert_eq!(
        sum_obs(observations, "ahash", "digest", "ok", "sha512"),
        (8, 8 * 64, 8, 0, 0)
    );
    assert_eq!(
        sum_obs(observations, "shash", "digest", "ok", "sha512"),
        (8, 8 * 64, 8, 0, 0)
    );
    assert_eq!(
        sum_obs(observations, "shash", "finup", "ok", "sha512"),
        (8, 4 * 32, 8, 0, 0)
    );
    // AEAD: 10 clean + bad-tag setup enc + failed dec.
    assert_eq!(
        sum_obs(observations, "aead", "encrypt", "ok", "gcm(aes)"),
        (11, 11 * 32, 11, 0, 0)
    );
    assert_eq!(
        sum_obs(observations, "aead", "decrypt", "ok", "gcm(aes)"),
        (10, 10 * 48, 10, 0, 0)
    );
    assert_eq!(
        sum_obs(observations, "aead", "decrypt", "error", "gcm(aes)"),
        (1, 48, 0, 1, 0)
    );

    // Per-row shape: symbol set for known pairs, conservation, sane
    // windows, canonical flag, inventory marking on ANY rows only.
    for obs in observations
        .iter()
        .filter(|o| o.backend_payload.get("row") == Some(&serde_json::json!("agg")))
    {
        let counts = &obs.backend_payload["counts"];
        let (calls, ok, errors, queued) = (
            counts["calls"].as_u64().expect("calls"),
            counts["ok"].as_u64().expect("ok"),
            counts["errors"].as_u64().expect("errors"),
            counts["queued"].as_u64().expect("queued"),
        );
        assert_eq!(ok + errors + queued, calls, "conservation per row");
        let (first, last) = (
            obs.backend_payload["window"]["first_ns"]
                .as_u64()
                .expect("first"),
            obs.backend_payload["window"]["last_ns"]
                .as_u64()
                .expect("last"),
        );
        assert!(first <= last && last > 0, "sane window");
        assert_eq!(
            obs.backend_payload["status_canonical"].as_bool(),
            Some(true)
        );
        assert_eq!(obs.started_ns, Some(first));
        assert_eq!(obs.ended_ns, Some(last));
        let is_any = obs.backend_payload.get("family") == Some(&serde_json::json!("any"));
        assert_eq!(
            obs.backend_payload.get("execution").is_some(),
            is_any,
            "inventory marker iff ANY family"
        );
        assert_eq!(
            obs.native_name.as_ref().map(|n| n.as_str()),
            expected_symbol(
                fam_num(obs.backend_payload["family"].as_str().expect("family")),
                op_num(obs.backend_payload["op"].as_str().expect("op")),
            ),
            "symbol table exact"
        );
    }

    // Totals observation: KTOT preserved exactly (counts + bytes + window).
    let totals_obs: Vec<&NativeObservation> = observations
        .iter()
        .filter(|o| o.backend_payload.get("row") == Some(&serde_json::json!("totals")))
        .collect();
    assert_eq!(totals_obs.len(), 1, "exactly one totals observation");
    let tot = decode_snapshot_totals_via_parse(&snap);
    assert_eq!(
        totals_obs[0].backend_payload["counts"]["calls"].as_u64(),
        Some(tot.calls)
    );
    assert_eq!(
        totals_obs[0].backend_payload["bytes"].as_u64(),
        Some(tot.bytes)
    );
    assert_eq!(
        totals_obs[0].backend_payload["counts"]["ok"].as_u64(),
        Some(tot.ok)
    );
    assert_eq!(
        totals_obs[0].backend_payload["counts"]["errors"].as_u64(),
        Some(tot.errors)
    );
    assert_eq!(
        totals_obs[0].backend_payload["counts"]["queued"].as_u64(),
        Some(tot.queued)
    );
    // KTOT == sum(agg observations): healthy conservation end to end.
    let mut sum = (0u64, 0u64, 0u64, 0u64, 0u64);
    for obs in observations
        .iter()
        .filter(|o| o.backend_payload.get("row") == Some(&serde_json::json!("agg")))
    {
        sum.0 += obs.backend_payload["counts"]["calls"]
            .as_u64()
            .expect("calls");
        sum.1 += obs.backend_payload["bytes"].as_u64().expect("bytes");
        sum.2 += obs.backend_payload["counts"]["ok"].as_u64().expect("ok");
        sum.3 += obs.backend_payload["counts"]["errors"]
            .as_u64()
            .expect("errors");
        sum.4 += obs.backend_payload["counts"]["queued"]
            .as_u64()
            .expect("queued");
    }
    assert_eq!((tot.calls, tot.bytes, tot.ok, tot.errors, tot.queued), sum);

    // Idents join rows by hash with consistent head + window (C5 via decode).
    let ident_obs: Vec<&NativeObservation> = observations
        .iter()
        .filter(|o| o.backend_payload.get("row") == Some(&serde_json::json!("ident")))
        .collect();
    assert!(!ident_obs.is_empty(), "snapshot must carry IDENTs");
    for obs in &ident_obs {
        let key_hash = obs.backend_payload["key_hash"]
            .as_u64()
            .expect("key_hash u64");
        let fam = fam_num(obs.backend_payload["family"].as_str().expect("family"));
        let op = op_num(obs.backend_payload["op"].as_str().expect("op"));
        let joined: Vec<&NativeObservation> = observations
            .iter()
            .filter(|o| o.backend_payload.get("row") == Some(&serde_json::json!("agg")))
            .filter(|o| {
                let alg = words_for_name(o.backend_payload["algorithm"].as_str().expect("alg"));
                let drv = words_for_name(o.backend_payload["driver"].as_str().expect("drv"));
                kcrypto_ident_hash(fam, op, &alg, &drv) == key_hash
            })
            .collect();
        assert!(
            !joined.is_empty(),
            "IDENT {key_hash:016x} joins a decoded row"
        );
        let first_seen = obs.backend_payload["first_seen_ns"]
            .as_u64()
            .expect("first_seen");
        let first = joined
            .iter()
            .map(|o| {
                o.backend_payload["window"]["first_ns"]
                    .as_u64()
                    .expect("first")
            })
            .min()
            .expect("joined");
        let last = joined
            .iter()
            .map(|o| {
                o.backend_payload["window"]["last_ns"]
                    .as_u64()
                    .expect("last")
            })
            .max()
            .expect("joined");
        assert!(
            first <= first_seen && first_seen <= last,
            "IDENT inside gate window"
        );
    }

    // Finalize: observations == decoded; healthy integrity (drops 0, gap 0).
    let summary = &report.summaries[0];
    assert_eq!(summary.backend, BackendId::KCrypto);
    assert_eq!(summary.observations, observations.len() as u64);
    assert_eq!(
        summary.integrity,
        IntegritySummary::default(),
        "healthy lane: zero losses"
    );
    let drops = map_lookup_bytes(
        &sensor.loaded.maps.ident,
        &KIDN_DROPS.to_le_bytes(),
        1,
        "driver-twin/kidn-drops",
    )
    .map(|v| v[0])
    .unwrap_or(0);
    assert_eq!(drops, 0, "ring-reserve drops pin zero (independent read)");

    // K2 documents the shared-feed skip: the lenient total reads zero and
    // the checked total refuses (K3 feeds once per session).
    assert_eq!(
        report.session_integrity(),
        IntegritySummary::default(),
        "unfed lenient total pins zero"
    );
    assert!(
        report.session_integrity_checked().is_err(),
        "checked total refuses before the feed"
    );

    // Configure idempotency on the live backend: same generation is a
    // no-op (no re-charge); a new generation reloads and charges 9/5.
    let backend = registry.get(BackendId::KCrypto).expect("kcrypto live");
    let mut budget = open_budget();
    let mut ctx = ConfigureContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        budget: &mut budget,
    };
    backend
        .configure(&mut ctx, &report.plans[0])
        .expect("same-generation re-configure is a no-op");
    assert_eq!(budget.used(BudgetKind::Links), 0, "no-op charges nothing");
    assert_eq!(budget.used(BudgetKind::StateEntries), 0);
    let mut budget = open_budget();
    let mut ctx = ConfigureContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(2),
        budget: &mut budget,
    };
    backend
        .configure(&mut ctx, &report.plans[0])
        .expect("new-generation re-configure reloads");
    assert_eq!(budget.used(BudgetKind::Links), 9, "Links += attached_n");
    assert_eq!(
        budget.used(BudgetKind::StateEntries),
        5,
        "StateEntries += maps"
    );
}

/// Independent totals oracle: the Task-1 fallible entry over the snapshot
/// totals bytes (same bytes the driver decoded — guards the totals path).
fn decode_snapshot_totals_via_parse(snap: &SnapshotRows) -> VAgg {
    let totals = snap.totals.as_ref().expect("KTOT row present");
    match parse_snapshot_row(&totals.0).expect("totals parses") {
        ParsedRow::Totals { vagg } => vagg,
        _ => panic!("totals bytes decoded off-kind"),
    }
}
