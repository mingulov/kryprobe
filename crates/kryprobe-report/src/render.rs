// SPDX-License-Identifier: GPL-3.0-or-later
//! Text summary renderer with R-024 zero qualification.
//!
//! Every standalone `0` in the output rides a line carrying its interval
//! (`during …`) and coverage (`; <dimension>: <status>`) suffix; the
//! zero-wording test scans every rendered line for bare zeros.

mod table;

use serde_json::Value;

/// Evidence phases in ladder order.
const PHASES: [&str; 5] = ["discovered", "selected", "entered", "returned", "completed"];

/// One leniently parsed record.
pub(crate) struct Rec {
    kind: String,
    session: Option<String>,
    clock: Option<u64>,
    payload: Value,
}

fn parse_stream(stream: &str) -> (Vec<Rec>, usize) {
    let mut records = Vec::new();
    let mut malformed = 0;
    for line in stream.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            malformed += 1;
            continue;
        };
        let Some(object) = value.as_object() else {
            malformed += 1;
            continue;
        };
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let clock = object
            .get("monotonic_ns")
            .and_then(Value::as_str)
            .and_then(|text| text.parse::<u64>().ok());
        records.push(Rec {
            kind: kind.to_owned(),
            session: object
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            clock,
            payload: object.get("payload").cloned().unwrap_or(Value::Null),
        });
    }
    (records, malformed)
}

fn interval_of(records: &[Rec]) -> String {
    let ticks: Vec<u64> = records.iter().filter_map(|rec| rec.clock).collect();
    match (ticks.iter().min(), ticks.iter().max()) {
        (Some(min), Some(max)) => format!("{min}..{max}ns"),
        (None, _) | (_, None) => "an unknown interval".to_owned(),
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

/// Weakest gap impact for `dim`, or `complete` when no gaps name it.
pub(crate) fn dim_status(records: &[Rec], dim: &str) -> String {
    let mut worst: Option<String> = None;
    for rec in records.iter().filter(|rec| rec.kind == "coverage_gap") {
        if payload_str(&rec.payload, "dimension").as_deref() != Some(dim) {
            continue;
        }
        let impact = payload_str(&rec.payload, "impact").unwrap_or_else(|| "unknown".to_owned());
        let replace = worst
            .as_ref()
            .is_none_or(|w| impact_rank(&impact) > impact_rank(w));
        if replace {
            worst = Some(impact);
        }
    }
    worst.unwrap_or_else(|| "complete".to_owned())
}

/// Renders per-phase counts, the coverage table, and the integrity line.
#[must_use]
pub fn render_summary(stream: &str) -> String {
    let (records, malformed) = parse_stream(stream);
    let mut lines: Vec<String> = Vec::new();
    if records.is_empty() {
        lines.push("no records observed during an empty stream; coverage: unknown".to_owned());
    } else {
        let interval = interval_of(&records);
        let session = records
            .iter()
            .find_map(|rec| rec.session.clone())
            .unwrap_or_else(|| "unknown".to_owned());
        lines.push(format!("session {}: {} records", session, records.len()));
        for phase in PHASES {
            let count = records
                .iter()
                .filter(|rec| {
                    rec.kind == "operation_observation"
                        && payload_str(&rec.payload, "phase").as_deref() == Some(phase)
                })
                .count();
            if count == 0 {
                lines.push(format!(
                    "phase {phase}: no {phase}-phase operations observed during {interval}; detailed_events: {}",
                    dim_status(&records, "detailed_events")
                ));
            } else {
                lines.push(format!("phase {phase}: {count} observations"));
            }
        }
        lines.extend(table::coverage_table(&records, &interval));
        let snapshots: Vec<&Rec> = records
            .iter()
            .filter(|rec| rec.kind == "aggregate_snapshot")
            .collect();
        if snapshots.is_empty() {
            lines.push(format!(
                "integrity: no aggregate snapshots observed during {interval}; aggregate_counts: {}",
                dim_status(&records, "aggregate_counts")
            ));
        } else {
            let mut worst_count = "qualified".to_owned();
            let mut worst_event = "qualified".to_owned();
            for snap in &snapshots {
                let count = payload_str(&snap.payload, "count_integrity")
                    .unwrap_or_else(|| "unknown".to_owned());
                if count_rank(&count) > count_rank(&worst_count) {
                    worst_count = count;
                }
                let event = payload_str(&snap.payload, "event_integrity")
                    .unwrap_or_else(|| "unknown".to_owned());
                if event_rank(&event) > event_rank(&worst_event) {
                    worst_event = event;
                }
            }
            let plural = if snapshots.len() == 1 { "" } else { "s" };
            lines.push(format!(
                "integrity: {} snapshot{plural}; counts {worst_count}; events {worst_event}",
                snapshots.len()
            ));
        }
    }
    if malformed > 0 {
        lines.push(format!("skipped {malformed} malformed lines"));
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}
