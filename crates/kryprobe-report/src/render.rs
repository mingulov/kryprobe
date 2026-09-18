// SPDX-License-Identifier: GPL-3.0-or-later
//! Text summary renderer with R-024 zero qualification.
//!
//! Every standalone `0` in the output rides a line carrying its interval
//! (`during …`) and coverage (`; <dimension>: <status>`) suffix; the
//! zero-wording test scans every rendered line for bare zeros.
//!
//! Both [`render_summary`] and [`render_summary_reader`] run the same
//! single-pass [`Summary`] accumulator; the reader form holds O(1) records
//! so million-event sessions render with bounded memory.

mod table;

use serde_json::Value;
use std::collections::BTreeSet;
use std::io::BufRead;

/// Evidence phases in ladder order.
const PHASES: [&str; 5] = ["discovered", "selected", "entered", "returned", "completed"];

/// One leniently parsed record (transient: never retained across lines).
pub(crate) struct Rec {
    kind: String,
    session: Option<String>,
    clock: Option<u64>,
    payload: Value,
}

fn parse_line(line: &str) -> Option<Rec> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    let object = value.as_object()?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let clock = object
        .get("monotonic_ns")
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<u64>().ok());
    Some(Rec {
        kind: kind.to_owned(),
        session: object
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        clock,
        payload: object.get("payload").cloned().unwrap_or(Value::Null),
    })
}

/// Running gap statistics for one schema coverage dimension.
#[derive(Default)]
pub(crate) struct DimStat {
    count: u64,
    worst: Option<String>,
    gmin: Option<u64>,
    gmax: Option<u64>,
}

/// Single-pass summary state: counts, clock bounds, and per-dimension gap
/// statistics. Memory is O(1) in the record count (plus one entry per
/// distinct non-schema dimension name, a fixed backend vocabulary).
#[derive(Default)]
pub(crate) struct Summary {
    records: u64,
    malformed: u64,
    session: Option<String>,
    min_clock: Option<u64>,
    max_clock: Option<u64>,
    phases: [u64; PHASES.len()],
    gaps: [DimStat; table::SCHEMA_DIMS.len()],
    others: BTreeSet<String>,
    snapshots: u64,
    worst_count: Option<String>,
    worst_event: Option<String>,
}

impl Summary {
    pub(crate) fn push_line(&mut self, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        let Some(rec) = parse_line(line) else {
            self.malformed += 1;
            return;
        };
        self.records += 1;
        if self.session.is_none() {
            self.session = rec.session.clone();
        }
        if let Some(clock) = rec.clock {
            self.min_clock = Some(self.min_clock.map_or(clock, |min| min.min(clock)));
            self.max_clock = Some(self.max_clock.map_or(clock, |max| max.max(clock)));
        }
        match rec.kind.as_str() {
            "operation_observation" => {
                if let Some(phase) = payload_str(&rec.payload, "phase")
                    && let Some(slot) = PHASES.iter().position(|want| *want == phase)
                {
                    self.phases[slot] += 1;
                }
            }
            "coverage_gap" => self.push_gap(&rec.payload),
            "aggregate_snapshot" => {
                self.snapshots += 1;
                let count = payload_str(&rec.payload, "count_integrity")
                    .unwrap_or_else(|| "unknown".to_owned());
                if self
                    .worst_count
                    .as_ref()
                    .is_none_or(|worst| count_rank(&count) > count_rank(worst))
                {
                    self.worst_count = Some(count);
                }
                let event = payload_str(&rec.payload, "event_integrity")
                    .unwrap_or_else(|| "unknown".to_owned());
                if self
                    .worst_event
                    .as_ref()
                    .is_none_or(|worst| event_rank(&event) > event_rank(worst))
                {
                    self.worst_event = Some(event);
                }
            }
            _ => {}
        }
    }

    fn push_gap(&mut self, payload: &Value) {
        // A gap without a string dimension is malformed input, counted
        // like any other malformed line — never silently dropped.
        let Some(dimension) = payload_str(payload, "dimension") else {
            self.malformed += 1;
            return;
        };
        let impact = payload_str(payload, "impact").unwrap_or_else(|| "unknown".to_owned());
        if let Some(slot) = table::SCHEMA_DIMS
            .iter()
            .position(|want| *want == dimension)
        {
            let stat = &mut self.gaps[slot];
            stat.count += 1;
            if stat
                .worst
                .as_ref()
                .is_none_or(|worst| impact_rank(&impact) > impact_rank(worst))
            {
                stat.worst = Some(impact);
            }
            if let Some(begin) = payload_str(payload, "begin_ns").and_then(|text| text.parse().ok())
            {
                stat.gmin = Some(stat.gmin.map_or(begin, |min: u64| min.min(begin)));
            }
            if let Some(end) = payload_str(payload, "end_ns").and_then(|text| text.parse().ok()) {
                stat.gmax = Some(stat.gmax.map_or(end, |max: u64| max.max(end)));
            }
        } else {
            self.others.insert(dimension);
        }
    }

    fn interval(&self) -> String {
        match (self.min_clock, self.max_clock) {
            (Some(min), Some(max)) => format!("{min}..{max}ns"),
            (None, _) | (_, None) => "an unknown interval".to_owned(),
        }
    }

    /// Weakest gap impact for schema dimension `dim`, or `complete`.
    fn dim_status(&self, dim: &str) -> &str {
        self.gaps
            .iter()
            .zip(table::SCHEMA_DIMS)
            .find(|(_, want)| *want == dim)
            .and_then(|(stat, _)| stat.worst.as_deref())
            .unwrap_or("complete")
    }

    pub(crate) fn finish(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        if self.records == 0 {
            lines.push("no records observed during an empty stream; coverage: unknown".to_owned());
        } else {
            let interval = self.interval();
            let session = self.session.as_deref().unwrap_or("unknown");
            lines.push(format!("session {}: {} records", session, self.records));
            for (phase, count) in PHASES.iter().zip(self.phases) {
                if count == 0 {
                    lines.push(format!(
                        "phase {phase}: no {phase}-phase operations observed during {interval}; event_transport: {}",
                        self.dim_status("event_transport")
                    ));
                } else {
                    lines.push(format!("phase {phase}: {count} observations"));
                }
            }
            lines.extend(table::coverage_table(self, &interval));
            if self.snapshots == 0 {
                lines.push(format!(
                    "integrity: no aggregate snapshots observed during {interval}; aggregate_counts: {}",
                    self.dim_status("aggregate_counts")
                ));
            } else {
                let plural = if self.snapshots == 1 { "" } else { "s" };
                lines.push(format!(
                    "integrity: {} snapshot{plural}; counts {}; events {}",
                    self.snapshots,
                    self.worst_count.as_deref().unwrap_or("qualified"),
                    self.worst_event.as_deref().unwrap_or("qualified"),
                ));
            }
        }
        if self.malformed > 0 {
            lines.push(format!("skipped {} malformed lines", self.malformed));
        }
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }
}

pub(crate) fn payload_str(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Severity rank: unknown spellings rank worst so they surface.
pub(crate) fn impact_rank(impact: &str) -> u8 {
    match impact {
        "partial" => 0,
        "unsupported" => 1,
        "refused" => 2,
        "unknown" => 3,
        _ => 4,
    }
}

fn count_rank(word: &str) -> u8 {
    match word {
        "qualified" => 0,
        "lower_bound" => 1,
        "estimated" => 2,
        "unknown" => 3,
        _ => 4,
    }
}

fn event_rank(word: &str) -> u8 {
    match word {
        "qualified" => 0,
        "partial" => 1,
        "not_requested" => 2,
        "unknown" => 3,
        _ => 4,
    }
}

/// Renders per-phase counts, the coverage table, and the integrity line.
#[must_use]
pub fn render_summary(stream: &str) -> String {
    let mut summary = Summary::default();
    for line in stream.lines() {
        summary.push_line(line);
    }
    summary.finish()
}

/// Streaming [`render_summary`]: same bytes, O(1) records in memory.
/// Stops fail-closed with the I/O error (including invalid UTF-8).
pub fn render_summary_reader(reader: impl BufRead) -> std::io::Result<String> {
    let mut summary = Summary::default();
    for line in reader.lines() {
        summary.push_line(&line?);
    }
    Ok(summary.finish())
}
