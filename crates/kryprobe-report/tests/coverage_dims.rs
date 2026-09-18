// SPDX-License-Identifier: GPL-3.0-or-later
//! T16 X3: the renderer covers exactly the frozen schema `coverage_gap`
//! dimension enum — every enum member renders as its own row, none
//! silently footnoted; unknown spellings still surface in the footnote.

use kryprobe_report::render_summary;

/// The frozen `coverage_gap` dimension enum, read from the schema file so
/// the pin tracks the contract (the schema itself is frozen: any edit
/// needs an ADR + version bump, and the freeze test pins its hash).
fn schema_gap_dimensions() -> Vec<String> {
    let schema = include_str!("../../../schemas/event-v0.schema.json");
    let parsed: serde_json::Value = serde_json::from_str(schema).expect("schema is JSON");
    let branches = parsed
        .get("oneOf")
        .and_then(serde_json::Value::as_array)
        .expect("schema has oneOf branches");
    let gap = branches
        .iter()
        .find(|branch| {
            branch
                .pointer("/properties/kind/const")
                .and_then(serde_json::Value::as_str)
                == Some("coverage_gap")
        })
        .expect("schema has a coverage_gap branch");
    gap.pointer("/properties/payload/properties/dimension/enum")
        .and_then(serde_json::Value::as_array)
        .expect("coverage_gap has a dimension enum")
        .iter()
        .map(|name| name.as_str().expect("enum member is a string").to_owned())
        .collect()
}

fn gap_record(id: usize, dimension: &str) -> String {
    serde_json::json!({
        "schema": "kryprobe.event/v0",
        "kind": "coverage_gap",
        "session_id": "session:dims",
        "record_id": format!("record:{id}"),
        "monotonic_ns": (1000 + id as u64).to_string(),
        "payload": {
            "dimension": dimension,
            "impact": "partial",
            "begin_ns": "1",
            "end_ns": "2",
        },
    })
    .to_string()
}

/// Coverage row names in render order (the `  {dim}:` lines under
/// `coverage:`, stopping before the footnote or the integrity line).
fn rendered_row_names(summary: &str) -> Vec<String> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in summary.lines() {
        if line == "coverage:" {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !line.starts_with("  ") || line.starts_with("  plus gaps") {
            break;
        }
        let name = line.trim_start().split(':').next().expect("row has a name");
        rows.push(name.to_owned());
    }
    rows
}

#[test]
fn rendered_rows_match_frozen_enum_exactly() {
    // Gapless stream: every dimension renders its `complete` row.
    let stream = serde_json::json!({
        "schema": "kryprobe.event/v0",
        "kind": "session_start",
        "session_id": "session:dims",
        "record_id": "record:0",
        "monotonic_ns": "0",
        "payload": {},
    })
    .to_string()
        + "\n";
    assert_eq!(
        rendered_row_names(&render_summary(&stream)),
        schema_gap_dimensions()
    );
}

#[test]
fn every_schema_dimension_renders_its_gap() {
    let dims = schema_gap_dimensions();
    assert!(!dims.is_empty(), "schema enum must be non-empty");
    let mut stream = String::new();
    for (id, dim) in dims.iter().enumerate() {
        stream.push_str(&gap_record(id, dim));
        stream.push('\n');
    }
    let summary = render_summary(&stream);
    for dim in &dims {
        let row = summary
            .lines()
            .find(|line| line.starts_with(&format!("  {dim}:")))
            .unwrap_or_else(|| panic!("schema dimension {dim} has no rendered row:\n{summary}"));
        assert!(
            row.contains("1 gap"),
            "row for {dim} must carry its gap: {row}"
        );
    }
    assert!(
        !summary.contains("plus gaps in other dimensions"),
        "schema-valid gaps must never be footnoted:\n{summary}"
    );
}

#[test]
fn unknown_dimension_still_footnoted() {
    // Non-schema spellings stay visible via the footnote (fail-closed:
    // reported, never dropped).
    let stream = gap_record(0, "custom_dim") + "\n";
    let summary = render_summary(&stream);
    assert!(
        summary.contains("plus gaps in other dimensions: custom_dim"),
        "unknown dimension must be footnoted:\n{summary}"
    );
}
