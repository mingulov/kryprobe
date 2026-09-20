// SPDX-License-Identifier: GPL-3.0-or-later
//! Live-render tests (moved with the tables from the CLI, 1B-H2/1B-M8).

use kryprobe_core::enums::CoverageStatus;
use kryprobe_core::evidence::{CoverageSummary, DimensionCoverage, ValidityInterval};
use kryprobe_report::live_render::trailer_dims;

fn complete_dim() -> DimensionCoverage {
    DimensionCoverage::new(
        CoverageStatus::CompleteForDeclaredBoundary,
        ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        },
    )
}

fn healthy_coverage() -> CoverageSummary {
    CoverageSummary {
        target_population: complete_dim(),
        object_discovery: complete_dim(),
        attachment: complete_dim(),
        aggregate_counts: complete_dim(),
        detailed_events: complete_dim(),
        attribution: complete_dim(),
        correlation: complete_dim(),
        completion: complete_dim(),
    }
}

#[test]
fn trailer_names_each_gap_in_kp2_order() {
    // Each dimension alone maps to its kp2 §8 token.
    let cases = [
        ("target_population", "operation"),
        ("object_discovery", "attach"),
        ("attachment", "attach"),
        ("aggregate_counts", "capture-integrity"),
        ("detailed_events", "capture-integrity"),
        ("attribution", "attribution"),
        ("correlation", "correlation"),
        ("completion", "completion"),
    ];
    for (field, token) in cases {
        let mut coverage = healthy_coverage();
        let dim = match field {
            "target_population" => &mut coverage.target_population,
            "object_discovery" => &mut coverage.object_discovery,
            "attachment" => &mut coverage.attachment,
            "aggregate_counts" => &mut coverage.aggregate_counts,
            "detailed_events" => &mut coverage.detailed_events,
            "attribution" => &mut coverage.attribution,
            "correlation" => &mut coverage.correlation,
            "completion" => &mut coverage.completion,
            _ => unreachable!("pinned field list"),
        };
        dim.status = CoverageStatus::Partial;
        assert_eq!(trailer_dims(&coverage), vec![token], "field {field}");
    }
    // Every non-complete status weakens (Unsupported/NotRun/Unknown
    // are gaps too, never COMPLETE).
    for status in [
        CoverageStatus::Partial,
        CoverageStatus::Unsupported,
        CoverageStatus::NotRun,
        CoverageStatus::Unknown,
    ] {
        let mut coverage = healthy_coverage();
        coverage.attachment.status = status;
        assert_eq!(
            trailer_dims(&coverage),
            vec!["attach"],
            "status {status:?} weakens"
        );
    }
    // Multi-gap order is the kp2 §8 order, deduped.
    let mut coverage = healthy_coverage();
    coverage.completion.status = CoverageStatus::Partial;
    coverage.attachment.status = CoverageStatus::Partial;
    coverage.aggregate_counts.status = CoverageStatus::Partial;
    coverage.correlation.status = CoverageStatus::Unknown;
    assert_eq!(
        trailer_dims(&coverage),
        vec!["attach", "capture-integrity", "completion", "correlation"]
    );
    // Contract held (incl. interval end) is COMPLETE.
    assert!(trailer_dims(&healthy_coverage()).is_empty());
}
