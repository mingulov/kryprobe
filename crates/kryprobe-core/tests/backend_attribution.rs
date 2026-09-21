// SPDX-License-Identifier: GPL-3.0-or-later
//! T6 per-backend attribution: summaries carry backend-scoped integrity,
//! and the session rollup is defined once (`IntegritySummary::rollup`).

use kryprobe_abi::{ABI_VERSION, EVENT_OBSERVATION, RawEventHeader};
use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendDriver, BackendPlan, BackendRegistry, BackendSummary,
    ConfigureContext, DecodeContext, DetectContext, DetectedInstance, DriverReport,
    FinalizeContext, PlanContext, RawEvent,
};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{
    BackendId, CallKind, CaptureMode, CoverageStatus, EvidencePhase, OperationClass,
};
use kryprobe_core::error::BackendError;
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegrityRef, IntegritySummary, NativeObservation,
    NativeResult, ValidityInterval,
};
use kryprobe_core::ids::SessionId;
use kryprobe_core::plan::CapabilityRequirements;
use kryprobe_core::synthetic::SyntheticBackend;
use kryprobe_testkit::assert_golden;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static P11_CAPS: BackendCapabilities = BackendCapabilities {
    backend: BackendId::P11,
    name: "lossy-stub",
    required: CapabilityRequirements {
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf: false,
    },
};

static OPENSSL_CAPS: BackendCapabilities = BackendCapabilities {
    backend: BackendId::OpenSsl,
    name: "lossy-stub",
    required: CapabilityRequirements {
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf: false,
    },
};

/// Test double reporting scripted backend-observed losses; decode counts honestly.
struct LossyStub {
    id: BackendId,
    caps: &'static BackendCapabilities,
    losses: IntegritySummary,
    decoded: AtomicUsize,
}

impl LossyStub {
    fn p11() -> Self {
        Self {
            id: BackendId::P11,
            caps: &P11_CAPS,
            losses: IntegritySummary {
                ring_reservation_failures: 3,
                unmatched_entries: 1,
                ..IntegritySummary::default()
            },
            decoded: AtomicUsize::new(0),
        }
    }

    fn openssl() -> Self {
        Self {
            id: BackendId::OpenSsl,
            caps: &OPENSSL_CAPS,
            losses: IntegritySummary {
                user_queue_drops: 7,
                budget_omissions: 2,
                ..IntegritySummary::default()
            },
            decoded: AtomicUsize::new(0),
        }
    }
}

impl Backend for LossyStub {
    fn id(&self) -> BackendId {
        self.id
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        self.caps
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        Ok(vec![DetectedInstance {
            backend: self.id,
            object: None,
            detail: String::from("lossy stub instance"),
        }])
    }

    fn plan(
        &self,
        _ctx: &PlanContext<'_>,
        _instance: &DetectedInstance,
        _mode: CaptureMode,
    ) -> Result<BackendPlan, BackendError> {
        Ok(BackendPlan {
            backend: self.id,
            probes: Vec::new(),
            required: CapabilityRequirements::default(),
        })
    }

    fn configure(
        &self,
        _ctx: &mut ConfigureContext<'_>,
        _plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn decode(
        &self,
        ctx: &DecodeContext<'_>,
        event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        self.decoded.fetch_add(1, Ordering::SeqCst);
        let native_result = match self.id {
            BackendId::P11 => NativeResult::P11 { rv: 0 },
            BackendId::OpenSsl => NativeResult::OpenSsl { code: 1 },
            BackendId::KCrypto | BackendId::Synthetic => NativeResult::Synthetic { code: 0 },
        };
        Ok(NativeObservation {
            id: ctx.id_issuer.issue().expect("test issues never exhaust"),
            backend: self.id,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Entered,
            call_kind: CallKind::Operation,
            operation_class: OperationClass::Sign,
            native_name: None,
            native_code: None,
            native_result,
            started_ns: Some(event.header.monotonic_ns),
            ended_ns: None,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::Value::Null,
        })
    }

    fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        // Backend-observed counters only; the session baseline in `ctx` is
        // assessment context, never echoed (echoing would double-count).
        Ok(BackendSummary {
            backend: self.id,
            observations: self.decoded.load(Ordering::SeqCst) as u64,
            integrity: self.losses,
        })
    }
}

fn runtime() -> RuntimeCapabilities {
    RuntimeCapabilities {
        kernel_release: String::from("test"),
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf_present: false,
        userns: false,
        yama_scope: 0,
        caps: Vec::new(),
    }
}

fn dim() -> DimensionCoverage {
    DimensionCoverage::new(
        CoverageStatus::CompleteForDeclaredBoundary,
        ValidityInterval {
            start_ns: 0,
            end_ns: None,
        },
    )
}

fn all_complete_coverage() -> CoverageSummary {
    CoverageSummary {
        target_population: dim(),
        object_discovery: dim(),
        attachment: dim(),
        aggregate_counts: dim(),
        detailed_events: dim(),
        attribution: dim(),
        correlation: dim(),
        completion: dim(),
    }
}

fn raw_parts(backend: BackendId, monotonic_ns: u64) -> (RawEventHeader, [u8; 8]) {
    (
        RawEventHeader {
            abi_version: ABI_VERSION,
            backend_id: backend.wire_id(),
            event_kind: EVENT_OBSERVATION,
            flags: 0,
            total_len: 64,
            cpu: 0,
            session_cookie: 0,
            monotonic_ns,
            tgid: 0,
            tid: 0,
            process_generation: 0,
            plan_generation: 1,
            reserved: 0,
        },
        [0_u8; 8],
    )
}

/// Three-backend driver run: synthetic (1 event) + p11 (2 events) + openssl
/// (1 event), in registration order.
fn attributed_run() -> DriverReport {
    let mut registry = BackendRegistry::new();
    registry
        .register(Box::new(SyntheticBackend::new(Vec::new())))
        .expect("fresh registry accepts synthetic");
    registry
        .register(Box::new(LossyStub::p11()))
        .expect("fresh registry accepts p11");
    registry
        .register(Box::new(LossyStub::openssl()))
        .expect("fresh registry accepts openssl");
    let (synth_header, synth_payload) = SyntheticBackend::harness_event(
        EvidencePhase::Entered,
        OperationClass::Sign,
        CallKind::Operation,
        0,
        1_000_000,
    );
    let (p11_header_a, p11_payload_a) = raw_parts(BackendId::P11, 2_000_000);
    let (p11_header_b, p11_payload_b) = raw_parts(BackendId::P11, 3_000_000);
    let (openssl_header, openssl_payload) = raw_parts(BackendId::OpenSsl, 4_000_000);
    let events = [
        RawEvent {
            header: synth_header,
            payload: &synth_payload,
        },
        RawEvent {
            header: p11_header_a,
            payload: &p11_payload_a,
        },
        RawEvent {
            header: p11_header_b,
            payload: &p11_payload_b,
        },
        RawEvent {
            header: openssl_header,
            payload: &openssl_payload,
        },
    ];
    let mut driver = BackendDriver::harness();
    driver
        .run(&registry, &runtime(), &events)
        .expect("open gates + routed events run clean")
}

fn golden_path() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("backend_attribution.golden.json")
}

fn attribution_json(report: &DriverReport) -> serde_json::Value {
    let summaries: Vec<serde_json::Value> = report
        .summaries()
        .iter()
        .map(|summary| {
            json!({
                "backend": format!("{:?}", summary.backend),
                "observations": summary.observations.to_string(),
                "integrity": serde_json::to_value(summary.integrity).expect("integrity serializes"),
            })
        })
        .collect();
    json!({
        "summaries": summaries,
        "session_integrity": serde_json::to_value(report.session_integrity()).expect("rollup serializes"),
    })
}

#[test]
fn synthetic_finalize_does_not_echo_session_integrity() {
    let backend = SyntheticBackend::new(Vec::new());
    let coverage = all_complete_coverage();
    let session_losses = IntegritySummary {
        ring_reservation_failures: 11,
        user_queue_drops: 5,
        ..IntegritySummary::default()
    };
    let summary = backend
        .finalize(&FinalizeContext {
            session: SessionId::new(1),
            coverage: &coverage,
            integrity: &session_losses,
        })
        .unwrap();
    assert_eq!(summary.backend, BackendId::Synthetic);
    // The synthetic driver path observes no backend-local losses: the
    // session baseline is assessment context, and echoing it here would
    // double-count under a two-backend rollup.
    assert_eq!(
        summary.integrity,
        IntegritySummary::default(),
        "finalize echoed session-wide integrity"
    );
}

#[test]
fn driver_run_scopes_integrity_per_backend_without_double_count() {
    let report = attributed_run();
    assert!(report.skipped().is_empty());
    assert_eq!(report.observations().len(), 4);
    let observed: Vec<BackendId> = report
        .observations()
        .iter()
        .map(|obs| obs.backend)
        .collect();
    assert_eq!(
        observed,
        vec![
            BackendId::Synthetic,
            BackendId::P11,
            BackendId::P11,
            BackendId::OpenSsl
        ]
    );
    assert_eq!(report.summaries().len(), 3);
    // Each summary carries only its own backend's losses (synthetic
    // observed none; the stubs report disjoint scripted counters).
    assert_eq!(report.summaries()[0].backend, BackendId::Synthetic);
    assert_eq!(report.summaries()[0].observations, 1);
    assert_eq!(report.summaries()[0].integrity, IntegritySummary::default());
    assert_eq!(report.summaries()[1].backend, BackendId::P11);
    assert_eq!(report.summaries()[1].observations, 2);
    assert_eq!(
        report.summaries()[1].integrity,
        IntegritySummary {
            ring_reservation_failures: 3,
            unmatched_entries: 1,
            ..IntegritySummary::default()
        }
    );
    assert_eq!(report.summaries()[2].backend, BackendId::OpenSsl);
    assert_eq!(report.summaries()[2].observations, 1);
    assert_eq!(
        report.summaries()[2].integrity,
        IntegritySummary {
            user_queue_drops: 7,
            budget_omissions: 2,
            ..IntegritySummary::default()
        }
    );
    // The session rollup is the exact sum: counted once, never doubled.
    let rolled = IntegritySummary {
        ring_reservation_failures: 3,
        user_queue_drops: 7,
        unmatched_entries: 1,
        budget_omissions: 2,
        ..IntegritySummary::default()
    };
    assert_eq!(report.session_integrity(), rolled);
    assert_eq!(
        IntegritySummary::rollup(report.summaries().iter().map(|summary| &summary.integrity)),
        rolled
    );
}

#[test]
fn attribution_channel_matches_golden() {
    let report = attributed_run();
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(&attribution_json(&report)).expect("golden serializes")
    );
    assert_golden(&golden_path(), text.as_bytes());
}

/// 1B-L4: reports assemble through checked transitions only — the
/// extend/take/push path round-trips a driven report intact.
#[test]
fn builder_transitions_roundtrip_driven_report() {
    let mut report = attributed_run();
    let mut rebuilt = DriverReport::default();
    rebuilt.extend_observations(report.take_observations());
    assert!(report.observations().is_empty());
    assert_eq!(rebuilt.observations().len(), 4);
    for summary in report.summaries().to_vec() {
        rebuilt.push_summary(summary);
    }
    assert_eq!(rebuilt.summaries().len(), 3);
    assert_eq!(rebuilt.summaries()[0].backend, BackendId::Synthetic);
}
