// SPDX-License-Identifier: GPL-3.0-or-later
//! Eight-dimension coverage table (see [`super::render_summary`]).

use super::{Rec, impact_rank, payload_str};

/// Coverage dimensions in `CoverageSummary` order.
const CORE_DIMS: [&str; 8] = [
    "target_population",
    "object_discovery",
    "attachment",
    "aggregate_counts",
    "detailed_events",
    "attribution",
    "correlation",
    "completion",
];

/// Coverage rows: one per core dimension plus a non-core footnote.
pub(super) fn coverage_table(records: &[Rec], interval: &str) -> Vec<String> {
    let mut lines = vec!["coverage:".to_owned()];
    for dim in CORE_DIMS {
        let gaps: Vec<&Rec> = records
            .iter()
            .filter(|rec| {
                rec.kind == "coverage_gap"
                    && payload_str(&rec.payload, "dimension").as_deref() == Some(dim)
            })
            .collect();
        if gaps.is_empty() {
            lines.push(format!(
                "  {dim}: complete; no gaps recorded during {interval}"
            ));
            continue;
        }
        let mut worst = "partial".to_owned();
        for gap in &gaps {
            let impact =
                payload_str(&gap.payload, "impact").unwrap_or_else(|| "unknown".to_owned());
            if impact_rank(&impact) > impact_rank(&worst) {
                worst = impact;
            }
        }
        let begins: Vec<u64> = gaps
            .iter()
            .filter_map(|gap| payload_str(&gap.payload, "begin_ns"))
            .filter_map(|text| text.parse().ok())
            .collect();
        let ends: Vec<u64> = gaps
            .iter()
            .filter_map(|gap| payload_str(&gap.payload, "end_ns"))
            .filter_map(|text| text.parse().ok())
            .collect();
        let gmin = begins.iter().min().copied().unwrap_or(0);
        let gmax = ends.iter().max().copied().unwrap_or(gmin);
        let plural = if gaps.len() == 1 { "" } else { "s" };
        lines.push(format!(
            "  {dim}: {worst}; {} gap{plural} during {gmin}..{gmax}ns",
            gaps.len()
        ));
    }
    let mut others: Vec<String> = records
        .iter()
        .filter(|rec| rec.kind == "coverage_gap")
        .filter_map(|rec| payload_str(&rec.payload, "dimension"))
        .filter(|dim| !CORE_DIMS.contains(&dim.as_str()))
        .collect();
    others.sort();
    others.dedup();
    if !others.is_empty() {
        lines.push(format!(
            "  plus gaps in other dimensions: {}",
            others.join(", ")
        ));
    }
    lines
}
