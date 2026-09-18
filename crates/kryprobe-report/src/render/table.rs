// SPDX-License-Identifier: GPL-3.0-or-later
//! Nine-dimension coverage table (see [`super::render_summary`]).

use super::Summary;

/// Coverage dimensions: the frozen schema `coverage_gap` dimension enum
/// in schema order (`schemas/event-v0.schema.json`). Shared vocabulary —
/// every schema-valid gap renders as its own row (see
/// `tests/coverage_dims.rs`); only non-schema spellings footnote.
pub(super) const SCHEMA_DIMS: [&str; 9] = [
    "target_enumeration",
    "executable_discovery",
    "attachment",
    "semantic_resolution",
    "attribution",
    "aggregate_counts",
    "event_transport",
    "correlation",
    "observation_continuity",
];

/// Coverage rows: one per schema dimension plus a non-schema footnote.
pub(super) fn coverage_table(summary: &Summary, interval: &str) -> Vec<String> {
    let mut lines = vec!["coverage:".to_owned()];
    for (dim, stat) in SCHEMA_DIMS.iter().zip(summary.gaps.iter()) {
        if stat.count == 0 {
            lines.push(format!(
                "  {dim}: complete; no gaps recorded during {interval}"
            ));
            continue;
        }
        let gmin = stat.gmin.unwrap_or(0);
        let gmax = stat.gmax.unwrap_or(gmin);
        let plural = if stat.count == 1 { "" } else { "s" };
        lines.push(format!(
            "  {dim}: {}; {} gap{plural} during {gmin}..{gmax}ns",
            stat.worst.as_deref().unwrap_or("partial"),
            stat.count
        ));
    }
    if !summary.others.is_empty() {
        lines.push(format!(
            "  plus gaps in other dimensions: {}",
            summary
                .others
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines
}
