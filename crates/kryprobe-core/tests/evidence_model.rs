// SPDX-License-Identifier: GPL-3.0-or-later
//! 5c evidence-model tests: coverage pessimism, integrity zeros, ns-as-string.

use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    BackendPayload, CorrelationRef, CoverageSummary, DimensionCoverage, IntegrityRef,
    IntegritySummary, NativeObservation, NativeResult, OmissionId, SafeTextId, ValidityInterval,
};
use kryprobe_core::ids::ObservationId;

fn interval() -> ValidityInterval {
    ValidityInterval {
        start_ns: 1_000_000,
        end_ns: Some(2_000_000),
    }
}

fn complete_summary() -> CoverageSummary {
    let dim = || DimensionCoverage::new(CoverageStatus::CompleteForDeclaredBoundary, interval());
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

#[test]
fn coverage_all_complete_except_one_partial_renders_partial() {
    let mut summary = complete_summary();
    summary.detailed_events.status = CoverageStatus::Partial;
    assert_eq!(summary.overall(), CoverageStatus::Partial);
    assert_eq!(summary.weaker_dimensions(), vec!["detailed_events"]);
}

#[test]
fn coverage_all_complete_renders_complete_with_no_weaker_dimensions() {
    let summary = complete_summary();
    assert_eq!(
        summary.overall(),
        CoverageStatus::CompleteForDeclaredBoundary
    );
    assert!(summary.weaker_dimensions().is_empty());
}

#[test]
fn coverage_never_reports_optimistic_global_full() {
    // Every single non-complete dimension must surface; only all-complete
    // completes. Setting each dimension to Partial one at a time pins this.
    for index in 0..8 {
        let mut summary = complete_summary();
        let name = match index {
            0 => {
                summary.target_population.status = CoverageStatus::Partial;
                "target_population"
            }
            1 => {
                summary.object_discovery.status = CoverageStatus::Partial;
                "object_discovery"
            }
            2 => {
                summary.attachment.status = CoverageStatus::Partial;
                "attachment"
            }
            3 => {
                summary.aggregate_counts.status = CoverageStatus::Partial;
                "aggregate_counts"
            }
            4 => {
                summary.detailed_events.status = CoverageStatus::Partial;
                "detailed_events"
            }
            5 => {
                summary.attribution.status = CoverageStatus::Partial;
                "attribution"
            }
            6 => {
                summary.correlation.status = CoverageStatus::Partial;
                "correlation"
            }
            _ => {
                summary.completion.status = CoverageStatus::Partial;
                "completion"
            }
        };
        assert_eq!(summary.overall(), CoverageStatus::Partial, "dim {index}");
        assert_eq!(summary.weaker_dimensions(), vec![name], "dim {index}");
    }
    // A lone Unsupported dimension surfaces as Unsupported, never Complete.
    let mut summary = complete_summary();
    summary.attachment.status = CoverageStatus::Unsupported;
    assert_eq!(summary.overall(), CoverageStatus::Unsupported);
}

#[test]
fn integrity_default_is_all_zeros() {
    let summary = IntegritySummary::default();
    assert_eq!(summary.ring_reservation_failures, 0);
    assert_eq!(summary.user_queue_drops, 0);
    assert_eq!(summary.state_insert_failures, 0);
    assert_eq!(summary.state_evictions, 0);
    assert_eq!(summary.unmatched_entries, 0);
    assert_eq!(summary.unmatched_returns, 0);
    assert_eq!(summary.correlation_overflows, 0);
    assert_eq!(summary.unknown_generation_events, 0);
    assert_eq!(summary.budget_omissions, 0);
}

#[test]
fn integrity_counters_serialize_as_strings() {
    let summary = IntegritySummary {
        ring_reservation_failures: 3,
        ..IntegritySummary::default()
    };
    let text = serde_json::to_string(&summary).unwrap();
    assert!(
        text.contains("\"ring_reservation_failures\":\"3\""),
        "{text}"
    );
    assert!(text.contains("\"user_queue_drops\":\"0\""), "{text}");
    let back: IntegritySummary = serde_json::from_str(&text).unwrap();
    assert_eq!(back, summary);
}

fn sample_observation() -> NativeObservation {
    NativeObservation {
        id: ObservationId::new(1),
        backend: BackendId::P11,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Returned,
        call_kind: CallKind::Operation,
        operation_class: OperationClass::Sign,
        native_name: SafeTextId::new("C_Sign"),
        native_code: Some(0),
        native_result: NativeResult::P11 { rv: 0 },
        started_ns: Some(1_000_000),
        ended_ns: Some(1_002_000),
        correlation: Some(CorrelationRef::new(kryprobe_core::ids::CorrelationId::new(
            9,
        ))),
        integrity: IntegrityRef::new(4),
        backend_payload: BackendPayload::Null,
    }
}

#[test]
fn observation_ns_fields_serialize_as_strings() {
    let text = serde_json::to_string(&sample_observation()).unwrap();
    assert!(text.contains("\"started_ns\":\"1000000\""), "{text}");
    assert!(text.contains("\"ended_ns\":\"1002000\""), "{text}");
    let back: NativeObservation = serde_json::from_str(&text).unwrap();
    assert_eq!(back, sample_observation());
}

#[test]
fn omission_id_roundtrip() {
    let id: OmissionId = "omission:7".parse().unwrap();
    assert_eq!(id.to_string(), "omission:7");
    assert!("omission:".parse::<OmissionId>().is_err());
    assert!("target:7".parse::<OmissionId>().is_err());
}
