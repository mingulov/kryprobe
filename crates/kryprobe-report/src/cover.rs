// SPDX-License-Identifier: GPL-3.0-or-later
//! Coverage records: `coverage_gap`.
//!
//! Complete dimensions have no gap to record ([`CoverageGap::from_dimension`]
//! returns `None`); every other status maps to its schema impact, with
//! `NotRun` reading as `unknown` (nothing observed, nothing claimed).

use crate::writer::{JsonlWriter, ReportError};
use kryprobe_core::enums::CoverageStatus;
use kryprobe_core::evidence::DimensionCoverage;
use serde::Serialize;

/// One recorded coverage gap (schema `coverage_gap` payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    /// Attributed target, or `None` for null.
    pub target: Option<String>,
    /// Backend spelling (schema `backend` enum).
    pub backend: String,
    /// Coverage dimension (schema `dimension` enum).
    pub dimension: String,
    /// Gap reason (schema `reason` enum).
    pub reason: String,
    /// Gap begin, monotonic nanoseconds.
    pub begin_ns: u64,
    /// Gap end, or `None` while open.
    pub end_ns: Option<u64>,
    /// Gap impact (schema `impact` enum).
    pub impact: String,
    /// Omitted event count, or `None` when uncounted.
    pub omitted_count: Option<u64>,
}

/// Caller context a dimension alone cannot supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapCtx {
    /// Coverage dimension (schema `dimension` enum).
    pub dimension: String,
    /// Attributed target, or `None` for null.
    pub target: Option<String>,
    /// Backend spelling (schema `backend` enum).
    pub backend: String,
    /// Gap reason (schema `reason` enum).
    pub reason: String,
    /// Omitted event count, or `None` when uncounted.
    pub omitted_count: Option<u64>,
}

impl CoverageGap {
    /// Builds the gap for a non-complete dimension, or `None` when the
    /// dimension is complete within its declared boundary.
    #[must_use]
    pub fn from_dimension(ctx: &GapCtx, dim: &DimensionCoverage) -> Option<Self> {
        let impact = match dim.status {
            CoverageStatus::CompleteForDeclaredBoundary => return None,
            CoverageStatus::Partial => "partial",
            CoverageStatus::Unsupported => "unsupported",
            CoverageStatus::NotRun | CoverageStatus::Unknown => "unknown",
        };
        Some(Self {
            target: ctx.target.clone(),
            backend: ctx.backend.clone(),
            dimension: ctx.dimension.clone(),
            reason: ctx.reason.clone(),
            begin_ns: dim.interval.start_ns,
            end_ns: dim.interval.end_ns,
            impact: impact.to_owned(),
            omitted_count: ctx.omitted_count,
        })
    }
}

#[derive(Serialize)]
struct GapPayload<'a> {
    target_id: Option<&'a str>,
    backend: &'a str,
    dimension: &'a str,
    reason: &'a str,
    begin_ns: String,
    end_ns: Option<String>,
    impact: &'a str,
    omitted_count: Option<String>,
}

impl JsonlWriter {
    /// Appends `coverage_gap`.
    pub fn coverage(&mut self, gap: &CoverageGap) -> Result<(), ReportError> {
        self.emit(
            "coverage_gap",
            GapPayload {
                target_id: gap.target.as_deref(),
                backend: &gap.backend,
                dimension: &gap.dimension,
                reason: &gap.reason,
                begin_ns: gap.begin_ns.to_string(),
                end_ns: gap.end_ns.map(|ns| ns.to_string()),
                impact: &gap.impact,
                omitted_count: gap.omitted_count.map(|n| n.to_string()),
            },
        )?;
        Ok(())
    }
}
