// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed workload report assembly, rendering, and offline replay (M1
//! Stage 2C): the ONE report API consumed by both live output and replay.
//!
//! - [`assemble`] builds a [`WorkloadReport`] from captured rows (live).
//! - [`report_from_bytes`] / [`report_from_reader`] rebuild the identical
//!   typed report from stored bytes (replay) with no host queries.
//! - [`WorkloadReport::render_text`] renders both paths identically:
//!   bounded, deterministically ordered, with unknown attribution kept as
//!   explicit unknown rows/groups (never host rows) and parent/child
//!   totals never added.
//! - [`render_legacy_v1`] is the minimal frozen-v1 behavior: stored
//!   partition plus limitations, or refusal.
//!
//! Every direction routes through the frozen Stage 2A contract (core
//! workload types, the v2/v1 validators) — never around it.

mod assemble;
mod codec;
mod legacy;
mod model;
mod render;

pub use assemble::assemble;
pub use codec::{WorkloadDecodeError, WorkloadWriteError, report_from_bytes, report_from_reader};
pub use legacy::{LegacyV1Error, render_legacy_v1};
pub use model::{
    AssemblyInput, CoverageLevel, GroupBy, MetadataAvailability, NativeIdentity, ReportCoverage,
    ReportInterval, ReportLedger, ReportRow, ReportRowInput, ReportScope, ReportSession,
    WorkloadBuildError, WorkloadReport, WorkloadSelector,
};
pub use render::{GroupKey, WORKLOAD_RENDER_MAX_GROUPS, WORKLOAD_RENDER_MAX_ROWS};
