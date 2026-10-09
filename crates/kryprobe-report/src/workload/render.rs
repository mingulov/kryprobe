// SPDX-License-Identifier: GPL-3.0-or-later
//! Report renderer (M1 Stage 2C): one human rendering consumed by both
//! live output and replay.
//!
//! Bounded: at most [`WORKLOAD_RENDER_MAX_ROWS`] detail rows and
//! [`WORKLOAD_RENDER_MAX_GROUPS`] group lines render; the rest collapse
//! into `+N more` trailers while every total still covers every row.
//! Deterministic: rows render in accounting-key order, groups in key
//! order. Unknown attribution renders as explicit `unknown` cells and an
//! explicit `unknown` group — never a host row, never blank. Ancestor
//! associations render as row context only: grouping counts each row
//! exactly once, so parent/child totals never add.

use super::codec::WorkloadWriteError;
use super::model::{GroupBy, WorkloadReport, WorkloadSelector};
use kryprobe_core::workload::{AttributionStatus, SnapshotConsistency};
use std::collections::BTreeMap;
use std::io::Write;

/// Max detail rows rendered; the rest collapse into a `+N more` trailer
/// (the totals below always cover every row — the cap bounds text, never
/// the counts).
pub const WORKLOAD_RENDER_MAX_ROWS: usize = 64;

/// Max group lines rendered; the rest collapse into a `+N more` trailer.
pub const WORKLOAD_RENDER_MAX_GROUPS: usize = 64;

/// One grouping bucket. There is deliberately no host bucket: rows whose
/// workload is unknown aggregate under [`GroupKey::Unknown`], never under
/// a fabricated host identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupKey {
    /// The whole observed population (`group_by: none` only).
    Observed,
    /// One captured cgroup id.
    Cgroup(u64),
    /// One resolved container identity.
    Container {
        /// Runtime instance identity.
        runtime: String,
        /// Full container id.
        id: String,
    },
    /// Rows with no groupable identity (unknown cgroup, or no resolved
    /// container under container grouping). Sorts last.
    Unknown,
}

impl WorkloadReport {
    /// Grouped call totals over this report's declared [`GroupBy`]: each
    /// row lands in exactly one group, so the groups always sum to the
    /// ledger's per-context sum (parent/child non-additivity holds by
    /// construction — ancestor associations never form groups). Groups
    /// sort by key with [`GroupKey::Unknown`] last.
    #[must_use]
    pub fn grouped_totals(&self) -> Vec<(GroupKey, u64)> {
        match self.group_by {
            GroupBy::None => vec![(GroupKey::Observed, self.ledger.per_context_sum)],
            GroupBy::Cgroup => {
                let mut groups: BTreeMap<u64, u64> = BTreeMap::new();
                let mut unknown: u64 = 0;
                for row in &self.rows {
                    if row.context.cgroup == 0 {
                        unknown = unknown
                            .checked_add(row.calls)
                            .expect("groups partition validated rows");
                    } else {
                        let total = groups.entry(row.context.cgroup).or_insert(0);
                        *total = total
                            .checked_add(row.calls)
                            .expect("groups partition validated rows");
                    }
                }
                let mut totals: Vec<(GroupKey, u64)> = groups
                    .into_iter()
                    .map(|(cgroup, calls)| (GroupKey::Cgroup(cgroup), calls))
                    .collect();
                if unknown > 0 {
                    totals.push((GroupKey::Unknown, unknown));
                }
                totals
            }
            GroupBy::Container => {
                let mut groups: BTreeMap<(String, String), u64> = BTreeMap::new();
                let mut unknown: u64 = 0;
                for row in &self.rows {
                    match row.workload.as_ref().and_then(|w| w.container.as_ref()) {
                        Some(container) => {
                            let total = groups
                                .entry((container.runtime.clone(), container.id.clone()))
                                .or_insert(0);
                            *total = total
                                .checked_add(row.calls)
                                .expect("groups partition validated rows");
                        }
                        None => {
                            unknown = unknown
                                .checked_add(row.calls)
                                .expect("groups partition validated rows");
                        }
                    }
                }
                let mut totals: Vec<(GroupKey, u64)> = groups
                    .into_iter()
                    .map(|((runtime, id), calls)| (GroupKey::Container { runtime, id }, calls))
                    .collect();
                if unknown > 0 {
                    totals.push((GroupKey::Unknown, unknown));
                }
                totals
            }
        }
    }

    /// Render this report as bounded deterministic human text (see the
    /// module docs for the bounding, ordering, and unknown-row rules).
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut text = String::new();
        let consistency = match self.interval.consistency {
            SnapshotConsistency::Quiescent => "quiescent",
            SnapshotConsistency::Unproven => "unproven",
        };
        text.push_str(&format!(
            "workload-report v2 session {} kernel {} interval {}..{}ns {} profile {}\n",
            crate::sanitize_cell(&self.session.session_id),
            crate::sanitize_cell(&self.session.kernel_identity),
            self.interval.start_ns,
            self.interval.end_ns,
            consistency,
            crate::sanitize_cell(&self.profile),
        ));
        text.push_str(&format!(
            "ledger: system={} per_context={} unknown={} refused={} gap={} saturated={}/{}\n",
            self.ledger.system_total,
            self.ledger.per_context_sum,
            self.ledger.unknown,
            self.ledger.refused_inserts,
            self.ledger.gap_unreconciled,
            self.ledger.system_saturated,
            self.ledger.per_context_saturated,
        ));
        if self.ledger.gap_unreconciled {
            text.push_str("ledger: gap unreconciled; no exact unknown established\n");
        }
        text.push_str(&format!(
            "partition: matched={} nonmatched={} unknown_match={} observed={}\n",
            self.partition.matched(),
            self.partition.nonmatched(),
            self.partition.unknown_match(),
            self.partition.observed(),
        ));
        let selector = match &self.selector {
            WorkloadSelector::None => "none".to_string(),
            WorkloadSelector::CgroupId(id) => format!("cgroup-id {id}"),
            WorkloadSelector::ContainerId { runtime, id, .. } => format!(
                "container-id {}:{}",
                crate::sanitize_cell(runtime),
                crate::sanitize_cell(id)
            ),
        };
        let (scope, group_by) = (
            match self.scope {
                super::model::ReportScope::Unscoped => "unscoped",
                super::model::ReportScope::Scoped => "scoped",
            },
            match self.group_by {
                GroupBy::None => "none",
                GroupBy::Cgroup => "cgroup",
                GroupBy::Container => "container",
            },
        );
        text.push_str(&format!(
            "selectors: {selector}; scope: system/{scope}; group_by: {group_by}\n"
        ));
        text.push_str(&format!("metadata: {}\n", render_metadata(&self.metadata)));
        text.push_str(&format!(
            "coverage: capture={} attribution={} metadata={} correlation={}\n",
            coverage_word(self.coverage.capture),
            coverage_word(self.coverage.attribution),
            coverage_word(self.coverage.metadata),
            coverage_word(self.coverage.correlation),
        ));
        text.push_str(&format!("rows ({}):\n", self.rows.len()));
        text.push_str(
            "KH CGROUP TGID UID START_NS KIND CALLS FAM OP RES CTX ALGORITHM DRIVER WORKLOAD STATUS ANCESTOR\n",
        );
        for row in self.rows.iter().take(WORKLOAD_RENDER_MAX_ROWS) {
            text.push_str(&format!(
                "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
                row.context.kh,
                row.context.cgroup,
                row.context.tgid,
                row.context.uid,
                row.context.start_ns,
                kind_word(row.context.execution_kind),
                row.calls,
                row.native.family,
                row.native.op,
                row.native.result,
                row.native.context,
                crate::sanitize_cell(&row.native.algorithm),
                crate::sanitize_cell(&row.native.driver),
                render_workload(row),
                render_status(row),
                render_ancestor(row),
            ));
        }
        if self.rows.len() > WORKLOAD_RENDER_MAX_ROWS {
            text.push_str(&format!(
                "+{} more\n",
                self.rows.len() - WORKLOAD_RENDER_MAX_ROWS
            ));
        }
        let groups = self.grouped_totals();
        text.push_str(&format!(
            "groups (group_by={group_by}, {}):\n",
            groups.len()
        ));
        for (key, calls) in groups.iter().take(WORKLOAD_RENDER_MAX_GROUPS) {
            text.push_str(&format!("{} calls={calls}\n", render_group(key)));
        }
        if groups.len() > WORKLOAD_RENDER_MAX_GROUPS {
            text.push_str(&format!(
                "+{} more\n",
                groups.len() - WORKLOAD_RENDER_MAX_GROUPS
            ));
        }
        text.push_str(&format!(
            "total: {} calls across {} rows\n",
            self.ledger.per_context_sum,
            self.rows.len(),
        ));
        text
    }

    /// Write [`render_text`](Self::render_text) to `writer`, then flush:
    /// every I/O failure surfaces as an I/O error with its kind intact
    /// (see [`WorkloadWriteError::Io`]). A returned `Err` means the
    /// output is NOT a clean terminal result.
    pub fn render_text_to(&self, mut writer: impl Write) -> Result<(), WorkloadWriteError> {
        let text = self.render_text();
        writer
            .write_all(text.as_bytes())
            .map_err(WorkloadWriteError::Io)?;
        writer.flush().map_err(WorkloadWriteError::Io)?;
        Ok(())
    }
}

fn kind_word(kind: kryprobe_core::workload::ExecutionKind) -> &'static str {
    match kind {
        kryprobe_core::workload::ExecutionKind::Proc => "proc",
        kryprobe_core::workload::ExecutionKind::Kthread => "kthread",
        kryprobe_core::workload::ExecutionKind::Softirq => "softirq",
        kryprobe_core::workload::ExecutionKind::Unknown => "unknown",
    }
}

fn coverage_word(level: super::model::CoverageLevel) -> &'static str {
    match level {
        super::model::CoverageLevel::Complete => "complete",
        super::model::CoverageLevel::Partial => "partial",
        super::model::CoverageLevel::Unavailable => "unavailable",
    }
}

fn render_metadata(metadata: &super::model::MetadataAvailability) -> String {
    match metadata {
        super::model::MetadataAvailability::Available => "available".to_string(),
        super::model::MetadataAvailability::Unavailable(reason) => format!(
            "unavailable ({})",
            match reason {
                kryprobe_core::workload::MetadataUnavailable::NoPrincipal => "no_principal",
                kryprobe_core::workload::MetadataUnavailable::HelperRefused => "helper_refused",
                kryprobe_core::workload::MetadataUnavailable::BudgetExceeded => "budget_exceeded",
                kryprobe_core::workload::MetadataUnavailable::UnsupportedEnvironment =>
                    "unsupported_environment",
                kryprobe_core::workload::MetadataUnavailable::ParseFailed => "parse_failed",
            }
        ),
    }
}

/// Primary workload associations for one row (container, pod, node — in
/// that deterministic order; the ancestor is row context and renders in
/// its own column). Empty means unknown: renders `unknown`, never blank
/// and never a fabricated host label.
fn render_workload(row: &super::model::ReportRow) -> String {
    let Some(workload) = &row.workload else {
        return "unknown".to_string();
    };
    let mut cells = Vec::new();
    if let Some(container) = &workload.container {
        cells.push(format!(
            "container:{}:{}",
            crate::sanitize_cell(&container.runtime),
            crate::sanitize_cell(&container.id)
        ));
    }
    if let Some(pod) = &workload.pod {
        cells.push(format!(
            "pod:{}:{}",
            crate::sanitize_cell(&pod.cluster),
            crate::sanitize_cell(&pod.uid)
        ));
    }
    if let Some(node) = &workload.node {
        cells.push(format!("node:{}", crate::sanitize_cell(node)));
    }
    if cells.is_empty() {
        "unknown".to_string()
    } else {
        cells.join(",")
    }
}

/// Association status word for one row; rows without a claim are
/// explicitly `unresolved` (unknown attribution survives rendering as
/// unknown — it never becomes a host row).
fn render_status(row: &super::model::ReportRow) -> &'static str {
    match row.evidence.as_ref().map(|e| e.status) {
        Some(AttributionStatus::Verified) => "verified",
        Some(AttributionStatus::Asserted) => "asserted",
        Some(AttributionStatus::Unresolved) | None => "unresolved",
        Some(AttributionStatus::Ambiguous) => "ambiguous",
        Some(AttributionStatus::Stale) => "stale",
        Some(AttributionStatus::Unsupported) => "unsupported",
    }
}

/// Ancestor-container context for one row (informational only — grouping
/// never counts it, so parent/child totals never add).
fn render_ancestor(row: &super::model::ReportRow) -> String {
    match row
        .workload
        .as_ref()
        .and_then(|w| w.ancestor_container.as_ref())
    {
        Some(ancestor) => format!(
            "container:{}:{}",
            crate::sanitize_cell(&ancestor.runtime),
            crate::sanitize_cell(&ancestor.id)
        ),
        None => "-".to_string(),
    }
}

fn render_group(key: &GroupKey) -> String {
    match key {
        GroupKey::Observed => "observed".to_string(),
        GroupKey::Cgroup(id) => format!("cgroup {id}"),
        GroupKey::Container { runtime, id } => format!(
            "container {}:{}",
            crate::sanitize_cell(runtime),
            crate::sanitize_cell(id)
        ),
        GroupKey::Unknown => "unknown".to_string(),
    }
}
