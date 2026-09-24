// SPDX-License-Identifier: GPL-3.0-or-later
//! T02: kcrypto return/delivery evidence semantics (api-returns profile).
//!
//! S03/S04/O02 regression fixtures: a selected driver without driver-body
//! execution proof, no complete-delivery claim from internal
//! reconciliation, and representative status that never poses as an
//! exact native errno. Latency has no per-invocation claim: `lat`
//! passes through verbatim and nothing derives microseconds from it.

use kryprobe_abi::kcrypto_agg::{KCTX_PROC, KFAM_SK, KOP_ENC, KRES_ERR};
use kryprobe_core::backend::{Backend, DecodeContext};
use kryprobe_core::evidence::NativeResult;
use kryprobe_core::ids::{IdIssuer, PlanGeneration, SessionId};
use kryprobe_testkit::kcrypto_rows::{AggSpec, agg_row_bytes, totals_row_bytes};

fn decode_agg(bytes: Vec<u8>) -> kryprobe_core::evidence::NativeObservation {
    let backend = kryprobe_privilege::kcrypto_backend::KCryptoBackend::new();
    let row = kryprobe_privilege::kcrypto_snapshot::RowBytes::new(bytes).expect("hand row");
    let issuer = IdIssuer::default();
    let integrity = kryprobe_core::evidence::IntegritySummary::default();
    let ctx = DecodeContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        integrity: &integrity,
        id_issuer: &issuer,
    };
    backend
        .decode(
            &ctx,
            kryprobe_privilege::kcrypto_snapshot::raw_event_for_agg(&row),
        )
        .expect("hand row decodes")
}

fn decode_totals(calls: u64) -> kryprobe_core::evidence::NativeObservation {
    let backend = kryprobe_privilege::kcrypto_backend::KCryptoBackend::new();
    let totals =
        kryprobe_privilege::kcrypto_snapshot::TotalsBytes::new(totals_row_bytes(calls, 0, 0))
            .expect("hand totals");
    let issuer = IdIssuer::default();
    let integrity = kryprobe_core::evidence::IntegritySummary::default();
    let ctx = DecodeContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        integrity: &integrity,
        id_issuer: &issuer,
    };
    backend
        .decode(
            &ctx,
            kryprobe_privilege::kcrypto_snapshot::raw_event_for_totals(&totals),
        )
        .expect("hand totals decode")
}

/// S03: an error-class row (wrapper rejected before provider work, e.g.
/// ENOKEY) carries the selected driver but proves no driver-body
/// execution and counts zero successful work.
#[test]
fn s03_error_row_carries_driver_without_execution_proof() {
    let obs = decode_agg(agg_row_bytes(AggSpec {
        family: KFAM_SK,
        op: KOP_ENC,
        result: KRES_ERR,
        ctx: KCTX_PROC,
        name: b"cbc(aes)",
        drv: b"aesni-intel",
        calls: 5,
        bytes: 5120,
        ok: 0,
        errors: 5,
        queued: 0,
    }));
    let payload = &obs.backend_payload;
    assert_eq!(payload["driver"], "aesni-intel");
    assert_eq!(payload["result"], "error");
    assert_eq!(payload["counts"]["ok"], 0, "zero successful work");
    assert_eq!(payload["counts"]["errors"], 5);
    // Representative class status, never an exact native errno:
    assert!(
        matches!(obs.native_result, NativeResult::KCrypto { status } if status == -libc::EIO),
        "error class renders canonical EIO, got {:?}",
        obs.native_result
    );
    assert_eq!(payload["status_canonical"], true);
    assert!(
        obs.native_code.is_none(),
        "no exact native errno is carried"
    );
    // api-returns validity states (T02):
    assert_eq!(payload["capture_profile"], "api-returns");
    assert_eq!(payload["count_unit"], "api_invocation_return");
    assert_eq!(payload["completion_coverage"], "unobserved");
}

/// S04: reconciled totals (KTOT == sum(KAGG)) still carry no delivery
/// claim: counts are API-return units and completion is unobserved.
/// Session-level non-completeness rides coverage (live/policy tests).
#[test]
fn s04_reconciled_totals_carry_no_delivery_claim() {
    let totals = decode_totals(30);
    let payload = &totals.backend_payload;
    assert_eq!(payload["counts"]["calls"], 30);
    assert_eq!(payload["capture_profile"], "api-returns");
    assert_eq!(
        payload["count_unit"], "api_invocation_return",
        "totals count returns, not deliveries"
    );
    assert_eq!(payload["completion_coverage"], "unobserved");
    let agg = decode_agg(agg_row_bytes(AggSpec {
        family: KFAM_SK,
        op: KOP_ENC,
        result: KRES_ERR,
        ctx: KCTX_PROC,
        name: b"cbc(aes)",
        drv: b"aesni-intel",
        calls: 30,
        bytes: 0,
        ok: 0,
        errors: 30,
        queued: 0,
    }));
    assert_eq!(agg.backend_payload["completion_coverage"], "unobserved");
}

/// O02 (privilege leg): the aggregate representative status cannot
/// satisfy an exact-errno predicate — exact native errnos appear only
/// as `who` `first_errno`, never as the agg status.
#[test]
fn o02_representative_status_is_not_exact_errno() {
    let agg = decode_agg(agg_row_bytes(AggSpec {
        family: KFAM_SK,
        op: KOP_ENC,
        result: KRES_ERR,
        ctx: KCTX_PROC,
        name: b"cbc(aes)",
        drv: b"aesni-intel",
        calls: 1,
        bytes: 0,
        ok: 0,
        errors: 1,
        queued: 0,
    }));
    // Every error class renders the same canonical representative,
    // whatever the true kernel errno was (here: unknown, e.g. ENOKEY).
    assert!(
        matches!(agg.native_result, NativeResult::KCrypto { status } if status == -libc::EIO),
        "got {:?}",
        agg.native_result
    );
    assert!(agg.native_code.is_none());
    // The exact native errno rides only the who-row side channel:
    let table = kryprobe_privilege::kallsyms::SymTable::parse("");
    let who = kryprobe_privilege::kcrypto_backend::WhoSnapshot {
        key: Default::default(),
        val: Default::default(),
        stack_ips: Vec::new(),
        first_errno: Some(-libc::ENOKEY),
        params: None,
    };
    let who_obs = kryprobe_privilege::kcrypto_backend::observation_for_who(
        &who,
        kryprobe_core::ids::ObservationId::new(1),
        &table,
    );
    assert_eq!(who_obs.backend_payload["first_errno"], -libc::ENOKEY);
    assert_eq!(who_obs.backend_payload["capture_profile"], "api-returns");
}

/// Latency honesty: `lat` passes through verbatim (BPF writes zeros —
/// C4, no durations) and no per-invocation microsecond claim exists.
#[test]
fn lat_passthrough_carries_no_latency_claim() {
    let obs = decode_agg(agg_row_bytes(AggSpec {
        family: KFAM_SK,
        op: KOP_ENC,
        result: KRES_ERR,
        ctx: KCTX_PROC,
        name: b"cbc(aes)",
        drv: b"",
        calls: 2,
        bytes: 0,
        ok: 0,
        errors: 2,
        queued: 0,
    }));
    assert_eq!(
        obs.backend_payload["lat"],
        serde_json::json!([0, 0, 0, 0, 0, 0, 0, 0])
    );
    assert!(
        obs.backend_payload.get("latency_us").is_none(),
        "no microsecond latency is derived"
    );
}
