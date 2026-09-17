// SPDX-License-Identifier: GPL-3.0-or-later
//! 5d session test: a scripted synthetic session runs to FINALIZED and emits
//! golden JSONL record envelopes using schema-spelled values only.

use kryprobe_abi::{
    ABI_VERSION, BACKEND_P11, BACKEND_SYNTHETIC, EVENT_BARRIER, EVENT_OBSERVATION, RawEventHeader,
};
use kryprobe_core::backend::{
    Backend, ConfigureContext, DecodeContext, DetectContext, FinalizeContext, PlanContext, RawEvent,
};
use kryprobe_core::budget::{BudgetKind, BudgetManager};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::{
    BackendId, CallKind, CaptureMode, CoverageStatus, EvidencePhase, OperationClass,
};
use kryprobe_core::error::BackendError;
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegritySummary, NativeResult, ValidityInterval,
};
use kryprobe_core::ids::{ObservationId, PlanGeneration, SessionId};
use kryprobe_core::plan::{CapabilityRequirements, PlanBudget};
use kryprobe_core::session::{SessionController, SessionState};
use kryprobe_core::synthetic::{OpSpec, ScriptOp, SyntheticBackend};
use kryprobe_testkit::{assert_golden, check_stream};
use std::path::PathBuf;

fn script() -> Vec<ScriptOp> {
    let sign = OpSpec {
        class: OperationClass::Sign,
        call: CallKind::Operation,
    };
    let size = OpSpec {
        class: OperationClass::Encrypt,
        call: CallKind::SizeQuery,
    };
    let fail = OpSpec {
        class: OperationClass::Digest,
        call: CallKind::Operation,
    };
    vec![
        ScriptOp::Enter { op: sign },
        ScriptOp::Return { op: sign, code: 0 },
        ScriptOp::Enter { op: size },
        ScriptOp::Return { op: size, code: 0 },
        ScriptOp::Enter { op: fail },
        ScriptOp::Return { op: fail, code: -1 },
        ScriptOp::DropDetailed { count: 2 },
        ScriptOp::SpawnChild {
            parent: ObservationId::new(1),
        },
    ]
}

fn golden_path() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("synthetic_session.golden.jsonl")
}

fn records(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn field_of<'a>(records: &'a [serde_json::Value], id: &str, key: &str) -> Vec<&'a str> {
    records
        .iter()
        .filter(|record| record["payload"]["observation_id"] == id)
        .map(|record| record["payload"][key].as_str().unwrap())
        .collect()
}

#[test]
fn scripted_session_runs_to_finalized_with_golden_jsonl() {
    let backend = SyntheticBackend::new(script());
    let mut session = SessionController::new();
    for state in [
        SessionState::Qualified,
        SessionState::Discovering,
        SessionState::Attaching,
        SessionState::Observing,
    ] {
        session.transition(state).unwrap();
    }
    let run = backend.run_script(SessionId::new(7)).unwrap();
    for state in [
        SessionState::Quiescing,
        SessionState::Draining,
        SessionState::Finalized,
    ] {
        session.transition(state).unwrap();
    }
    assert_eq!(session.state(), SessionState::Finalized);

    let text = run.to_jsonl();
    let kinds: &[(&str, &[&str])] = &[
        (
            "synthetic_observation",
            &[
                "observation_id",
                "phase",
                "call_kind",
                "operation_class",
                "outcome",
                "native_result",
                "duration_ns",
            ],
        ),
        (
            "synthetic_relationship",
            &[
                "parent_observation_id",
                "child_observation_id",
                "relation",
                "anchor",
                "rule_id",
                "integrity",
            ],
        ),
    ];
    assert!(check_stream(&text, kinds).is_empty());
    assert_golden(&golden_path(), text.as_bytes());

    let records = records(&text);
    assert_eq!(records.len(), 19);
    assert!(
        !text.contains("succeeded") && !text.contains("SUCCEEDED"),
        "rust-only phase leaked onto the wire"
    );
    assert!(
        !text.contains("\"backend\""),
        "synthetic backend has no wire spelling"
    );
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["schema"], "kryprobe.event/v0");
        assert_eq!(record["session_id"], "session:7");
        assert_eq!(
            record["monotonic_ns"],
            (1_000_000 + index as u64 * 1_000).to_string()
        );
    }
    assert_eq!(
        field_of(&records, "observation:1", "phase"),
        [
            "discovered",
            "selected",
            "entered",
            "returned",
            "completed",
            "completed"
        ]
    );
    assert_eq!(field_of(&records, "observation:1", "outcome")[5], "success");
    assert_eq!(
        field_of(&records, "observation:2", "phase"),
        ["discovered", "selected", "entered", "returned"]
    );
    assert_eq!(field_of(&records, "observation:2", "outcome")[3], "success");
    assert_eq!(
        field_of(&records, "observation:3", "phase"),
        ["discovered", "selected", "entered", "returned", "completed"]
    );
    assert_eq!(field_of(&records, "observation:3", "outcome")[4], "failure");
    let relations: Vec<_> = records
        .iter()
        .filter(|record| record["kind"] == "synthetic_relationship")
        .collect();
    assert_eq!(relations.len(), 1);
    assert_eq!(
        relations[0]["payload"]["parent_observation_id"],
        "observation:1"
    );
    assert_eq!(
        relations[0]["payload"]["child_observation_id"],
        "observation:4"
    );
    assert_eq!(relations[0]["payload"]["relation"], "nested_within");
    assert_eq!(
        relations[0]["payload"]["anchor"],
        "verified_synchronous_nesting"
    );
    assert_eq!(run.relationships.len(), 1);
    assert_eq!(
        run.integrity,
        IntegritySummary {
            ring_reservation_failures: 2,
            unmatched_entries: 1,
            ..IntegritySummary::default()
        }
    );
    assert_eq!(run.aggregate_observations, 20);
}

#[test]
fn synthetic_backend_implements_all_seven_trait_methods() {
    let backend = SyntheticBackend::new(script());
    assert_eq!(backend.id(), BackendId::Synthetic);
    let caps = backend.capabilities();
    assert_eq!(caps.backend, BackendId::Synthetic);
    assert_eq!(caps.name, "synthetic");
    assert_eq!(caps.required, CapabilityRequirements::default());

    let session = SessionId::new(7);
    let generation = PlanGeneration::new(1);
    let runtime = sample_runtime();
    let found = backend
        .detect(&DetectContext {
            session,
            runtime: &runtime,
        })
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].backend, BackendId::Synthetic);
    let plan = backend
        .plan(
            &PlanContext {
                session,
                runtime: &runtime,
            },
            &found[0],
            CaptureMode::Trace,
        )
        .unwrap();
    assert_eq!(plan.backend, BackendId::Synthetic);
    assert_eq!(plan.probes.len(), 3);

    let mut budget = BudgetManager::new(sample_budget());
    let mut ctx = ConfigureContext {
        session,
        generation,
        budget: &mut budget,
    };
    backend.configure(&mut ctx, &plan).unwrap();
    assert_eq!(ctx.budget.used(BudgetKind::Links), 3);
    assert_eq!(ctx.budget.used(BudgetKind::StateEntries), 3);
    ctx.budget.charge(BudgetKind::Links, 61).unwrap();
    assert!(matches!(
        backend.configure(&mut ctx, &plan),
        Err(BackendError::Exhausted(_))
    ));

    let integrity = IntegritySummary::default();
    let ctx = DecodeContext {
        session,
        generation,
        integrity: &integrity,
    };
    let bytes = SyntheticBackend::encode_event(
        EvidencePhase::Entered,
        OperationClass::Encrypt,
        CallKind::SizeQuery,
        0,
    );
    let obs = backend
        .decode(
            &ctx,
            RawEvent {
                header: sample_header(),
                payload: &bytes,
            },
        )
        .unwrap();
    assert_eq!(obs.backend, BackendId::Synthetic);
    assert_eq!(obs.phase, EvidencePhase::Entered);
    assert_eq!(obs.operation_class, OperationClass::Encrypt);
    assert_eq!(obs.call_kind, CallKind::SizeQuery);
    assert_eq!(obs.native_result, NativeResult::Synthetic { code: 0 });
    assert!(matches!(
        backend.decode(
            &ctx,
            RawEvent {
                header: sample_header(),
                payload: &bytes[..7],
            }
        ),
        Err(BackendError::CorruptInput(_))
    ));
    let mut header = sample_header();
    header.backend_id = BACKEND_P11;
    assert!(matches!(
        backend.decode(
            &ctx,
            RawEvent {
                header,
                payload: &bytes
            }
        ),
        Err(BackendError::CorruptInput(_))
    ));
    header = sample_header();
    header.event_kind = EVENT_BARRIER;
    assert!(matches!(
        backend.decode(
            &ctx,
            RawEvent {
                header,
                payload: &bytes
            }
        ),
        Err(BackendError::Unsupported(_))
    ));

    let coverage = sample_coverage();
    let summary = backend
        .finalize(&FinalizeContext {
            session,
            coverage: &coverage,
            integrity: &integrity,
        })
        .unwrap();
    assert_eq!(summary.backend, BackendId::Synthetic);
    assert_eq!(summary.observations, 1);
    assert_eq!(summary.integrity, IntegritySummary::default());
}

#[test]
fn internal_ids_never_touch_the_wire() {
    assert_eq!(BackendId::Synthetic.wire_id(), BACKEND_SYNTHETIC);
    assert!(serde_json::to_string(&BackendId::Synthetic).is_err());
    assert!(serde_json::from_str::<BackendId>("\"synthetic\"").is_err());
    assert!(serde_json::to_string(&EvidencePhase::Succeeded).is_err());
    assert!(serde_json::from_str::<EvidencePhase>("\"succeeded\"").is_err());
    assert_eq!(serde_json::to_string(&BackendId::P11).unwrap(), "\"p11\"");
    assert_eq!(
        serde_json::to_string(&EvidencePhase::Completed).unwrap(),
        "\"completed\""
    );
}

fn sample_budget() -> PlanBudget {
    PlanBudget {
        max_targets: 8,
        max_objects: 16,
        max_bytes: 1 << 20,
        max_links: 64,
        max_state_entries: 64,
        max_queue: 512,
        max_duration_ns: 60_000_000_000,
    }
}

fn sample_runtime() -> RuntimeCapabilities {
    RuntimeCapabilities {
        kernel_release: "6.12.107+deb13-cloud-amd64".to_owned(),
        uprobe_multi: true,
        cookies: true,
        ringbuf: true,
        btf_present: false,
        userns: true,
        yama_scope: 1,
        caps: vec!["CAP_BPF".to_owned()],
    }
}

fn sample_header() -> RawEventHeader {
    RawEventHeader {
        abi_version: ABI_VERSION,
        backend_id: BACKEND_SYNTHETIC,
        event_kind: EVENT_OBSERVATION,
        flags: 0,
        total_len: 8,
        cpu: 0,
        session_cookie: 0,
        monotonic_ns: 1_000_000,
        tgid: 1,
        tid: 1,
        process_generation: 1,
        plan_generation: 1,
        reserved: 0,
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

fn sample_coverage() -> CoverageSummary {
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
