// SPDX-License-Identifier: GPL-3.0-or-later
//! T13: streaming render/validate are byte-identical to the batch pass.

use kryprobe_report::{
    MAX_VALIDATE_LINE_BYTES, ValidationFinding, render_summary, render_summary_reader,
    validate_and_render_file, validate_and_render_reader, validate_file, validate_reader,
    validate_str,
};
use std::io::BufReader;

fn schema_bytes() -> &'static [u8] {
    include_bytes!("../../../schemas/event-v0.schema.json")
}

fn render_streaming(text: &str) -> String {
    render_summary_reader(BufReader::new(text.as_bytes())).expect("streaming render reads &str")
}

fn validate_streaming(text: &str) -> Vec<ValidationFinding> {
    validate_reader(BufReader::new(text.as_bytes()), schema_bytes())
}

fn envelope(kind: &str, clock: &str, payload: serde_json::Value) -> String {
    serde_json::json!({
        "schema": "kryprobe.event/v0",
        "kind": kind,
        "session_id": "session:edge",
        "record_id": format!("record:{clock}"),
        "monotonic_ns": clock,
        "payload": payload,
    })
    .to_string()
}

/// Edge-case corpus: backwards clock, malformed lines, blanks, non-object,
/// missing clock/session, non-core dims, unknown impacts, worst integrities.
fn edge_stream() -> String {
    let mut lines = vec![
        envelope(
            "session_start",
            "0",
            serde_json::json!({"verdict": "observed"}),
        ),
        envelope(
            "operation_observation",
            "100",
            serde_json::json!({"phase": "completed"}),
        ),
        envelope(
            "operation_observation",
            "50",
            serde_json::json!({"phase": "completed"}),
        ),
        "{oops".to_owned(),
        String::new(),
        "   ".to_owned(),
        "[1,2]".to_owned(),
        envelope(
            "coverage_gap",
            "200",
            serde_json::json!({
                "dimension": "custom_dim",
                "impact": "weird",
                "begin_ns": "7",
                "end_ns": "9",
            }),
        ),
        envelope(
            "coverage_gap",
            "300",
            serde_json::json!({"dimension": "attachment"}),
        ),
        envelope(
            "aggregate_snapshot",
            "400",
            serde_json::json!({
                "count_integrity": "estimated",
                "event_integrity": "partial",
            }),
        ),
        envelope(
            "aggregate_snapshot",
            "500",
            serde_json::json!({
                "count_integrity": "unknown",
                "event_integrity": "unknown",
            }),
        ),
        serde_json::json!({
            "schema": "kryprobe.event/v0",
            "kind": "relationship",
            "record_id": "record:noclock",
            "payload": {},
        })
        .to_string(),
    ];
    lines.push("not json at all".to_owned());
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

#[test]
fn streaming_render_matches_batch_on_goldens() {
    let writer_golden = include_str!("goldens/writer_v0.jsonl");
    assert_eq!(
        render_streaming(writer_golden),
        render_summary(writer_golden)
    );
    let fixture = std::fs::read_to_string(fixture_path()).expect("pack fixture");
    assert_eq!(render_streaming(&fixture), render_summary(&fixture));
}

#[test]
fn streaming_render_matches_batch_on_edges() {
    for text in ["", "\n  \n", "not json\n", "{}\n", &edge_stream()] {
        assert_eq!(
            render_streaming(text),
            render_summary(text),
            "input: {text:?}"
        );
    }
    // No trailing newline must match too (final partial line).
    let edge = edge_stream();
    let untrimmed = edge.trim_end_matches('\n');
    assert_eq!(render_streaming(untrimmed), render_summary(untrimmed));
}

#[test]
fn gap_without_string_dimension_counts_malformed() {
    let stream = [
        envelope(
            "coverage_gap",
            "100",
            serde_json::json!({"impact": "partial"}),
        ),
        envelope(
            "coverage_gap",
            "200",
            serde_json::json!({"dimension": 7, "impact": "partial"}),
        ),
        envelope(
            "coverage_gap",
            "300",
            serde_json::json!({"dimension": "attachment", "impact": "partial"}),
        ),
    ]
    .join("\n")
        + "\n";
    // Missing dimension + non-string dimension: both counted, never
    // silently dropped; the well-formed gap renders normally.
    for text in [render_summary(&stream), render_streaming(&stream)] {
        assert!(
            text.contains("skipped 2 malformed lines"),
            "summary: {text}"
        );
        assert!(text.contains("3 records"), "summary: {text}");
        assert!(text.contains("attachment"), "summary: {text}");
    }
}

#[test]
fn streaming_validate_matches_batch() {
    let writer_golden = include_str!("goldens/writer_v0.jsonl");
    let fixture = std::fs::read_to_string(fixture_path()).expect("pack fixture");
    let tampered_schema = writer_golden.replacen("kryprobe.event/v0", "kryprobe.event/v9", 1);
    let tampered_key = writer_golden.replacen("\"payload\"", "\"dropped\"", 1);
    for text in [
        writer_golden,
        fixture.as_str(),
        "",
        "\n  \n",
        "not json\n",
        &edge_stream(),
        &tampered_schema,
        &tampered_key,
    ] {
        assert_eq!(
            validate_streaming(text),
            validate_str(text, schema_bytes()),
            "input: {text:?}"
        );
    }
}

#[test]
fn streaming_validate_matches_batch_on_drift() {
    let writer_golden = include_str!("goldens/writer_v0.jsonl");
    let edited = b"{\"edited\": true}";
    let streamed = validate_reader(BufReader::new(writer_golden.as_bytes()), edited);
    assert_eq!(streamed, validate_str(writer_golden, edited));
    assert!(
        streamed
            .iter()
            .any(|f| matches!(f, ValidationFinding::SchemaDrift { .. })),
        "drift must flag, got {streamed:?}"
    );
}

#[test]
fn validate_file_matches_batch_on_corpus() {
    let dir = std::env::temp_dir().join(format!("kryprobe-t13-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    for (name, text) in [
        (
            "writer.jsonl",
            include_str!("goldens/writer_v0.jsonl").to_owned(),
        ),
        ("edge.jsonl", edge_stream()),
        ("empty.jsonl", String::new()),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, &text).expect("write corpus");
        assert_eq!(
            validate_file(&path),
            validate_str(&text, schema_bytes()),
            "file: {name}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// T16 X1: the merged single pass feeds both consumers identically to
/// the two-pass sequence on every corpus input (clean, malformed, and
/// tampered). The summary is `Some` whenever the pass completes, even
/// with content findings — callers gate on findings first, as before.
#[test]
fn merged_pass_matches_two_pass_on_corpus() {
    let writer_golden = include_str!("goldens/writer_v0.jsonl");
    let fixture = std::fs::read_to_string(fixture_path()).expect("pack fixture");
    let tampered_schema = writer_golden.replacen("kryprobe.event/v0", "kryprobe.event/v9", 1);
    let tampered_key = writer_golden.replacen("\"payload\"", "\"dropped\"", 1);
    for text in [
        writer_golden,
        fixture.as_str(),
        "",
        "\n  \n",
        "not json\n",
        &edge_stream(),
        &tampered_schema,
        &tampered_key,
    ] {
        let (findings, summary) =
            validate_and_render_reader(BufReader::new(text.as_bytes()), schema_bytes());
        assert_eq!(findings, validate_streaming(text), "input: {text:?}");
        assert_eq!(
            summary.as_deref(),
            Some(render_summary(text).as_str()),
            "input: {text:?}"
        );
        // Byte-identical to the batch pass too (transitively via the
        // streaming identity tests above, pinned here end to end).
        assert_eq!(summary.as_deref(), Some(render_streaming(text).as_str()));
    }
}

#[test]
fn merged_pass_rejects_invalid_utf8_closed() {
    let (findings, summary) =
        validate_and_render_reader(BufReader::new(&b"{\xff\n"[..]), schema_bytes());
    assert!(
        matches!(findings.as_slice(), [ValidationFinding::Unreadable { .. }]),
        "invalid UTF-8 must fail closed, got {findings:?}"
    );
    assert!(summary.is_none(), "failed pass yields no summary");
}

#[test]
fn merged_file_matches_two_pass_on_corpus() {
    let dir = std::env::temp_dir().join(format!("kryprobe-t16x1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    for (name, text) in [
        (
            "writer.jsonl",
            include_str!("goldens/writer_v0.jsonl").to_owned(),
        ),
        ("edge.jsonl", edge_stream()),
        ("empty.jsonl", String::new()),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, &text).expect("write corpus");
        let (findings, summary) = validate_and_render_file(&path);
        assert_eq!(findings, validate_file(&path), "file: {name}");
        assert_eq!(
            summary.as_deref(),
            Some(render_summary(&text).as_str()),
            "file: {name}"
        );
    }
    let (findings, summary) = validate_and_render_file(&dir.join("missing.jsonl"));
    assert!(
        matches!(findings.as_slice(), [ValidationFinding::Unreadable { .. }]),
        "missing file must fail closed, got {findings:?}"
    );
    assert!(summary.is_none(), "failed pass yields no summary");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn streaming_validate_rejects_invalid_utf8_closed() {
    let findings = validate_reader(BufReader::new(&b"{\xff\n"[..]), schema_bytes());
    assert!(
        matches!(findings.as_slice(), [ValidationFinding::Unreadable { .. }]),
        "invalid UTF-8 must fail closed, got {findings:?}"
    );
}

#[test]
fn streaming_validate_rejects_overlong_line_closed() {
    // M-SEC-02: an unbounded line is a local memory-exhaustion vector.
    let mut big = vec![b'x'; MAX_VALIDATE_LINE_BYTES + 1];
    big.push(b'\n');
    let findings = validate_reader(BufReader::new(&big[..]), schema_bytes());
    assert!(
        matches!(findings.as_slice(), [ValidationFinding::Unreadable { .. }]),
        "overlong line must fail closed, got {findings:?}"
    );
}

#[test]
fn streaming_render_rejects_invalid_utf8() {
    let result = render_summary_reader(BufReader::new(&b"{\xff\n"[..]));
    assert!(result.is_err(), "invalid UTF-8 must error, got {result:?}");
}

#[test]
fn streaming_render_rejects_overlong_line() {
    // Same root as validate (M-SEC-02): the render loop shares the
    // bounded line reader.
    let mut big = vec![b'x'; MAX_VALIDATE_LINE_BYTES + 1];
    big.push(b'\n');
    let result = render_summary_reader(BufReader::new(&big[..]));
    assert!(result.is_err(), "overlong line must error");
}

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/session-v0.jsonl")
}

/// Soak scale: a quarter-million records (~30MB input), backend-era order
/// of magnitude. The bulk is minimal unknown-kind probes (envelope/clock
/// checks only); one thousand full observations plus gap/snapshot/start/end
/// records keep every summary and per-kind validation path warm. (A
/// one-million-record run verified the same flat growth; see the T13 task
/// report. The gate keeps the fast scale so `cargo test` stays usable.)
const SOAK_RECORDS: u64 = 250_000;
const SOAK_FULL_OBSERVATIONS: u64 = 1_000;
/// Streaming peak-growth cap: far below the soak input bytes (~30MB, over
/// 7x margin); the batch pass provably exceeds it (it holds the whole
/// input). Observed streaming growth is ~72KB, so the cap also carries
/// over 50x headroom above the implementation's real working set.
const SOAK_RSS_CAP_BYTES: u64 = 4 * 1024 * 1024;

fn soak_envelope(kind: &str, id: usize, clock: u64, payload: serde_json::Value) -> String {
    serde_json::json!({
        "schema": "kryprobe.event/v0",
        "kind": kind,
        "session_id": "session:soak",
        "record_id": format!("record:{id}"),
        "monotonic_ns": clock.to_string(),
        "payload": payload,
    })
    .to_string()
}

fn soak_observation(clock: u64) -> String {
    const PHASES: [&str; 5] = ["discovered", "selected", "entered", "returned", "completed"];
    soak_envelope(
        "operation_observation",
        clock as usize,
        clock,
        serde_json::json!({
            "observation_id": "o",
            "target_id": "t",
            "implementation_id": "i",
            "backend": "b",
            "boundary": "y",
            "phase": PHASES[clock as usize % PHASES.len()],
            "call_kind": "c",
            "operation_class": "s",
            "outcome": "u",
            "native_namespace": "n",
            "native_operation": "C",
            "native_result": "r",
            "algorithm": "a",
            "duration_ns": "1",
        }),
    )
}

/// Minimal bulk record: unknown kind, so only envelope/shape/clock checks
/// apply. `format!`, not `serde_json`, keeps debug-mode generation fast.
fn soak_probe(clock: u64) -> String {
    format!(
        "{{\"schema\":\"kryprobe.event/v0\",\"kind\":\"p\",\"session_id\":\"s:x\",\
         \"record_id\":\"r:{clock}\",\"monotonic_ns\":\"{clock}\",\"payload\":{{}}}}"
    )
}

/// Process peak RSS (VmHWM) in bytes; `None` off Linux (cap skipped there).
fn peak_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Scratch dir removed on drop, so a failed soak leaves no litter.
struct SoakDir(std::path::PathBuf);

impl Drop for SoakDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

#[test]
fn soak_large_stream_is_bounded_and_identical() {
    use std::io::{BufWriter, Write};
    // Workspace target dir, not /tmp: the soak input is tens of MB and
    // shared tmpfs mounts routinely carry tight quotas.
    let dir = SoakDir(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("t13-soak-{}", std::process::id())),
    );
    std::fs::create_dir_all(&dir.0).expect("soak dir");
    let path = dir.0.join("soak.jsonl");
    // Generate incrementally: the input itself never sits in memory whole.
    let input_bytes = {
        let file = std::fs::File::create(&path).expect("soak file");
        let mut out = BufWriter::new(file);
        let mut bytes = 0u64;
        let mut emit = |line: String| {
            bytes += (line.len() + 1) as u64;
            writeln!(out, "{line}").expect("soak write");
        };
        emit(soak_envelope(
            "session_start",
            0,
            0,
            serde_json::json!({
                "target_selector": "t",
                "capture_mode": "c",
                "requested_backends": [],
                "contract_version": "v",
                "qualification_id": "q",
            }),
        ));
        for clock in 1..=SOAK_FULL_OBSERVATIONS {
            emit(soak_observation(clock));
        }
        let gap_clock = SOAK_FULL_OBSERVATIONS + 1;
        emit(soak_envelope(
            "coverage_gap",
            gap_clock as usize,
            gap_clock,
            serde_json::json!({
                "target_id": "t",
                "backend": "b",
                "dimension": "attachment",
                "reason": "r",
                "begin_ns": "1",
                "end_ns": "2",
                "impact": "partial",
                "omitted_count": "0",
            }),
        ));
        let snap_clock = SOAK_FULL_OBSERVATIONS + 2;
        emit(soak_envelope(
            "aggregate_snapshot",
            snap_clock as usize,
            snap_clock,
            serde_json::json!({
                "target_id": "t",
                "backend": "b",
                "implementation_id": "i",
                "unit": "u",
                "count": "1",
                "count_integrity": "qualified",
                "begin_ns": "1",
                "end_ns": "2",
                "final": true,
                "barrier_status": "s",
                "event_integrity": "qualified",
            }),
        ));
        for clock in SOAK_FULL_OBSERVATIONS + 3..SOAK_RECORDS - 1 {
            emit(soak_probe(clock));
        }
        let end_clock = SOAK_RECORDS - 1;
        emit(soak_envelope(
            "session_end",
            end_clock as usize,
            end_clock,
            serde_json::json!({
                "verdict": "v",
                "final_barrier": "f",
                "unresolved_gap_ids": [],
                "child_exit_code": 0,
                "child_signal": 0,
            }),
        ));
        out.flush().expect("soak flush");
        bytes
    };
    assert!(
        input_bytes > SOAK_RSS_CAP_BYTES * 4,
        "soak input ({input_bytes}B) must dwarf the cap ({SOAK_RSS_CAP_BYTES}B)"
    );
    // Stream every pass under the RSS probe; the batch pass runs after so
    // its whole-input allocation cannot pollute the measurement.
    let before = peak_rss_bytes();
    let streamed_summary =
        render_summary_reader(BufReader::new(std::fs::File::open(&path).expect("open")))
            .expect("streaming render of soak");
    let streamed_findings = validate_file(&path);
    // T16 X1: the merged single pass rides the same soak — bounded and
    // identical at scale.
    let (merged_findings, merged_summary) = validate_and_render_file(&path);
    let after = peak_rss_bytes();
    assert!(
        streamed_findings.is_empty(),
        "soak stream must validate clean, got {:?}",
        &streamed_findings[..streamed_findings.len().min(4)]
    );
    assert!(
        merged_findings.is_empty(),
        "merged soak pass must validate clean, got {:?}",
        &merged_findings[..merged_findings.len().min(4)]
    );
    assert_eq!(
        merged_summary.as_deref(),
        Some(streamed_summary.as_str()),
        "merged soak summary must match the streaming pass"
    );
    if let (Some(before), Some(after)) = (before, after) {
        let growth = after.saturating_sub(before);
        eprintln!(
            "soak: input {input_bytes}B, streaming peak growth {growth}B (cap {SOAK_RSS_CAP_BYTES}B)"
        );
        assert!(
            growth < SOAK_RSS_CAP_BYTES,
            "streaming peak growth ({growth}B) must stay under the cap ({SOAK_RSS_CAP_BYTES}B)"
        );
    }
    // Byte-identical to the batch pass at soak scale. No batch-validate
    // leg: both validate forms share one line-validator core, and the
    // corpus tests above already prove their findings identical — the
    // streaming clean-assert here is the soak-scale validation proof.
    let text = std::fs::read_to_string(&path).expect("soak read");
    assert_eq!(streamed_summary, render_summary(&text));
    drop(dir);
}
