// SPDX-License-Identifier: GPL-3.0-or-later
//! `report`: validate a stream, then render its summary (exit 0 or 2);
//! plus `report --system`: one live capture rendered human or JSON
//! (exit 0 complete, 3 partial, 4 unusable, 1 internal).

use crate::args::{FilterArgs, ReportFormat};
use crate::live::{DEFAULT_TICK_MS, LiveConfig, LiveError, LiveOutcome, run_live_capture};
use crate::request_filter::{
    EVIDENCE_VERSION, apply_request_filter, context_filter, push_filter_counters,
};
use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;
use kryprobe_privilege::kcrypto_lifecycle::sensor::EnrichmentStatus;
use kryprobe_report::{
    KCRYPTO_LIFECYCLE_SESSION_V1, ReportError, SessionWriteError, SessionWriter,
    lifecycle_v1_payload, validate_and_render_file, write_str_atomic,
};
use std::io::Write;
use std::path::Path;

/// Default live window when `--duration` is absent (brief-exact).
const DEFAULT_REPORT_SECS: u64 = 60;

/// Runs `report`: findings (or an unreadable file) exit 2 with detail.
///
/// One streaming pass feeds both validation and rendering, so
/// million-record sessions render with bounded memory and the summary
/// always describes exactly the bytes validated (no TOCTOU window).
pub fn run(file: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (findings, summary) = validate_and_render_file(file);
    if !findings.is_empty() {
        let _ = writeln!(
            stderr,
            "report: {} finding(s) in {}:",
            findings.len(),
            file.display()
        );
        for finding in &findings {
            let _ = writeln!(stderr, "  {finding}");
        }
        return 2;
    }
    match summary {
        Some(summary) => {
            let _ = write!(stdout, "{summary}");
            0
        }
        // Unreachable in practice (`None` always rides an `Unreadable`
        // finding, handled above); fail closed without rendering.
        None => {
            let _ = writeln!(
                stderr,
                "report: cannot render {}: incomplete pass",
                file.display()
            );
            2
        }
    }
}

/// Renders one outcome as a single JSON doc plus a trailing newline:
/// brief-exact keys in brief order (`observations`, `coverage`,
/// `integrity`, `enrichment`, `verdict`), with the `doctor`-shaped
/// verdict `{status, missing}`. Serialized straight into one growing buffer
/// (M7: a `json!` map would sort the keys, and four `to_string`s plus
/// `format!` would peak at ~2× the doc size); byte-identical to the
/// piece-assembled form.
///
/// 1A-L15: the hand-placed braces stay by design — a `preserve_order`
/// `Map` would need the same 2× peak the streaming form avoids. The
/// `report_live.json` byte-exact golden plus the parse/key-order
/// tests fail on any unbalanced edit, so the braces are pinned
/// without a serializer.
///
/// 1A-M4: serialization failure is a defect `Err` (the caller exits
/// 1), never a panic — a future unserializable graph shape must not
/// turn a clean report (exit 0) into exit 101. Unreachable today
/// (the graph holds no floats or exotic map keys and `Vec` writes
/// never fail); the branches exist so the contract holds tomorrow.
pub fn render_report_json(outcome: &LiveOutcome) -> Result<String, String> {
    let missing = kryprobe_report::live_render::trailer_dims(&outcome.coverage);
    let status = if !outcome.interrupted && missing.is_empty() {
        "complete"
    } else {
        "partial"
    };
    // Lifecycle rows project to the standalone payload-v1 object
    // (validated, fail-closed): the report carries exactly the six
    // schema keys, never the live dispatch envelope.
    let mut observations = outcome.observations.clone();
    for obs in &mut observations {
        if let Some(projected) = kryprobe_report::lifecycle_v1_payload(obs) {
            obs.backend_payload = projected?;
        }
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(b"{\"observations\":");
    serde_json::to_writer(&mut buf, &observations)
        .map_err(|err| format!("defect: observations do not serialize: {err}"))?;
    buf.extend_from_slice(b",\"coverage\":");
    serde_json::to_writer(&mut buf, &outcome.coverage)
        .map_err(|err| format!("defect: coverage does not serialize: {err}"))?;
    buf.extend_from_slice(b",\"integrity\":");
    serde_json::to_writer(&mut buf, &outcome.integrity)
        .map_err(|err| format!("defect: integrity does not serialize: {err}"))?;
    // T07-R2-09: the ledger's enrichment verdict rides the JSON
    // report — available/unavailable/not-attempted, never dropped.
    buf.extend_from_slice(b",\"enrichment\":");
    match &outcome.enrichment {
        None => buf.extend_from_slice(b"null"),
        Some(EnrichmentStatus::Available { entries, truncated }) => {
            buf.extend_from_slice(b"{\"status\":\"available\",\"entries\":");
            buf.extend_from_slice(entries.to_string().as_bytes());
            buf.extend_from_slice(b",\"truncated\":");
            buf.extend_from_slice(truncated.to_string().as_bytes());
            buf.extend_from_slice(b"}");
        }
        Some(EnrichmentStatus::Unavailable { reason }) => {
            buf.extend_from_slice(b"{\"status\":\"unavailable\",\"reason\":");
            serde_json::to_writer(&mut buf, reason)
                .map_err(|err| format!("defect: enrichment does not serialize: {err}"))?;
            buf.extend_from_slice(b"}");
        }
    }
    buf.extend_from_slice(b",\"verdict\":{\"status\":\"");
    buf.extend_from_slice(status.as_bytes());
    buf.extend_from_slice(b"\",\"missing\":");
    serde_json::to_writer(&mut buf, &missing)
        .map_err(|err| format!("defect: verdict dims do not serialize: {err}"))?;
    buf.extend_from_slice(b"}}\n");
    String::from_utf8(buf).map_err(|err| format!("defect: report JSON is not UTF-8: {err}"))
}

/// Live window: explicit `--duration` or the 60s default.
fn report_window_secs(duration: Option<u64>) -> u64 {
    duration.unwrap_or(DEFAULT_REPORT_SECS)
}

/// Envelope filter populations (P6-N3): the session-envelope
/// coverage record's `unknown`/`filtered` under an active filter
/// (the CLI computes them from the filtered view; the exporter
/// stamps them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeFilter {
    /// Unknown population: lifecycle rows with an unknown terminal
    /// OR an unknown filter verdict (exact union — a row in both
    /// counts once).
    pub unknown: u64,
    /// Filtered population: requests failing a constraint on a
    /// known field (hidden from the rendered rows).
    pub filtered: u64,
}

/// Renders one lifecycle outcome as a versioned session-envelope
/// stream (T11/P6: start/config, validated observations, coverage,
/// terminal receipt — the validated replacement for the refused
/// lifecycle JSONL). Every row MUST project to payload-v1 (a
/// non-lifecycle row or an invalid projection refuses LOUD, never a
/// silent skip); the coverage record carries the outcome's exact
/// populations plus per-stage loss; the receipt is `clean` only when
/// the window was uninterrupted, the coverage contract held, and no
/// loss or unfinished work was counted. Without a filter the
/// coverage `unknown` is the driver's unknown-terminal count and
/// `filtered` is 0; under a filter both ride the envelope tallies.
///
/// Serialization failure is a defect `Err` (the caller exits 1),
/// never a panic — same contract as [`render_report_json`].
pub fn render_lifecycle_session(
    outcome: &LiveOutcome,
    profile: LifecycleProfile,
) -> Result<String, ReportError> {
    render_lifecycle_session_with_id(
        outcome,
        profile,
        &kryprobe_report::live_render::mint_live_session_id(),
        None,
    )
}

/// Session-envelope export under a caller-chosen session id: the
/// production path ([`render_lifecycle_session`]) mints a run-unique
/// id per export (P6-N4); tests and goldens pin a fixed id here so
/// the golden bytes stay deterministic while production never
/// repeats an identity. `envelope_filter` carries the filter
/// tallies when a CLI filter is active (`None` keeps the unfiltered
/// populations).
pub fn render_lifecycle_session_with_id(
    outcome: &LiveOutcome,
    profile: LifecycleProfile,
    session_id: &str,
    envelope_filter: Option<EnvelopeFilter>,
) -> Result<String, ReportError> {
    let totals = outcome
        .lifecycle_totals
        .as_ref()
        .ok_or(ReportError::MissingLifecycleTotals)?;
    let session = |err: SessionWriteError| match err {
        SessionWriteError::SerializeFailed { kind, detail } => {
            ReportError::SerializeFailed { kind, detail }
        }
        // Unreachable by construction: the call sequence below is
        // fixed (one start, observations, one coverage, one
        // receipt) and every projection pre-validates — but a
        // corrupt future must fail LOUD, never emit a torn stream.
        other => ReportError::SerializeFailed {
            kind: "session",
            detail: other.to_string(),
        },
    };
    let mut writer = SessionWriter::new(session_id);
    writer
        .session_start(
            profile.as_str(),
            EVIDENCE_VERSION,
            KCRYPTO_LIFECYCLE_SESSION_V1,
        )
        .map_err(session)?;
    for obs in &outcome.observations {
        let projected = match lifecycle_v1_payload(obs) {
            Some(Ok(record)) => record,
            Some(Err(defect)) => {
                return Err(ReportError::UnprojectableRow { detail: defect });
            }
            None => {
                return Err(ReportError::UnprojectableRow {
                    detail: "not a lifecycle row".to_owned(),
                });
            }
        };
        writer.observation(&projected).map_err(session)?;
    }
    // P6-N3: without a filter the unknown population is the
    // driver's own unknown-terminal count and `filtered` is honestly
    // 0; under a filter both ride the envelope tallies (exact union
    // + exact filtered-out count from the filtered view).
    let (unknown, filtered) = match envelope_filter {
        Some(counts) => (counts.unknown, counts.filtered),
        None => (totals.unknown_terminals, 0),
    };
    writer
        .coverage(
            totals.admitted,
            totals.emitted,
            totals.unfinished,
            totals.loss_stages(),
            unknown,
            filtered,
        )
        .map_err(session)?;
    let clean = !outcome.interrupted
        && kryprobe_report::live_render::trailer_dims(&outcome.coverage).is_empty()
        && totals.loss_total() == 0
        && totals.unfinished == 0;
    if clean {
        writer
            .receipt(true, totals.admitted, totals.emitted, totals.unfinished)
            .map_err(session)?;
    } else {
        writer
            .receipt_partial(
                totals.admitted,
                totals.emitted,
                totals.unfinished,
                totals.loss_stages(),
            )
            .map_err(session)?;
    }
    Ok(writer.into_string())
}

/// Finishes a live capture: human tables, the JSON doc, or the
/// validated JSONL stream to `--out` (atomic) or stdout — the frozen
/// event-v0 envelope for aggregate outcomes, the versioned
/// lifecycle session envelope for lifecycle outcomes (the outcome
/// selects the envelope, never the caller); 0 when the coverage
/// contract held, 3 on gaps, 4/1 on [`LiveError`] via
/// [`LiveError::exit_code`], 1 when a JSONL export refuses a
/// non-wire-spellable row. An active CLI filter applies
/// post-ingestion first (P6-N3): filtered-out rows hide from every
/// format, tallies ride coverage + the FILTER line + the envelope.
fn finish_report_live(
    result: Result<LiveOutcome, LiveError>,
    format: ReportFormat,
    out: Option<&Path>,
    filter: &FilterArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let mut outcome = match result {
        Ok(outcome) => outcome,
        Err(err) => {
            let _ = writeln!(stderr, "report: {err}");
            return err.exit_code();
        }
    };
    // P6-N3: post-ingestion filter (inactive filters skip entirely —
    // unfiltered sessions keep their exact existing bytes).
    let mut filter_counts = None;
    let mut envelope_filter = None;
    if filter.is_active() {
        let view = apply_request_filter(
            &outcome.observations,
            &context_filter(filter),
            EVIDENCE_VERSION,
            KCRYPTO_LIFECYCLE_SESSION_V1,
        );
        outcome.observations = view.observations;
        push_filter_counters(&mut outcome.coverage, &view.tally);
        filter_counts = Some(kryprobe_report::live_render::FilterCounts {
            admitted: view.tally.admitted,
            filtered: view.tally.filtered_out,
            unknown: view.tally.unknown,
        });
        envelope_filter = Some(EnvelopeFilter {
            unknown: view.unknown_union,
            filtered: view.tally.filtered_out,
        });
    }
    // 4B-M5: an interrupted window is partial evidence even when
    // every measured dimension held.
    if outcome.interrupted {
        let _ = writeln!(stderr, "report: interrupted by SIGINT — partial window");
    }
    let code = if !outcome.interrupted
        && kryprobe_report::live_render::trailer_dims(&outcome.coverage).is_empty()
    {
        0
    } else {
        3
    };
    let text = match format {
        ReportFormat::Human => {
            let mut text = kryprobe_report::live_render::render_watch_tables_filtered(
                &outcome.observations,
                &outcome.coverage,
                filter_counts,
            );
            // T07-R2-09: the enrichment verdict trailers the human
            // report (same line as `watch` — one shared renderer).
            text.push_str(&crate::live::render_enrichment_line(&outcome.enrichment));
            text
        }
        ReportFormat::Json => match render_report_json(&outcome) {
            Ok(text) => text,
            Err(err) => {
                let _ = writeln!(stderr, "report: cannot render JSON: {err}");
                return 1;
            }
        },
        ReportFormat::Jsonl => {
            // T11/P6: lifecycle outcomes export the versioned
            // session envelope (validated observations + coverage
            // + receipt); aggregate outcomes keep the frozen
            // event-v0 stream, byte-untouched.
            let text = if outcome.lifecycle_totals.is_some() {
                render_lifecycle_session_with_id(
                    &outcome,
                    LifecycleProfile::RequestLifecycle,
                    &kryprobe_report::live_render::mint_live_session_id(),
                    envelope_filter,
                )
            } else {
                kryprobe_report::live_render::render_live_jsonl(
                    &outcome.observations,
                    &outcome.coverage,
                    outcome.interrupted,
                )
            };
            match text {
                Ok(text) => text,
                Err(err) => {
                    let _ = writeln!(stderr, "report: cannot export JSONL: {err}");
                    return 1;
                }
            }
        }
    };
    match out {
        Some(path) => match write_str_atomic(path, &text) {
            Ok(()) => {
                let _ = writeln!(stderr, "wrote {}", path.display());
                code
            }
            Err(err) => {
                let _ = writeln!(stderr, "report: cannot write {}: {err}", path.display());
                1
            }
        },
        None => {
            let _ = write!(stdout, "{text}");
            code
        }
    }
}

/// Runs `report --system`: one bounded capture (default 60s), rendered
/// human (same tables as `watch`, plus the verdict exit) or JSON.
#[allow(clippy::too_many_arguments)]
pub fn run_report_live(
    source: &str,
    duration: Option<u64>,
    format: ReportFormat,
    out: Option<&Path>,
    token: Option<&Path>,
    profile: LifecycleProfile,
    filter: &FilterArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // T11/P6: the versioned-envelope ADR decided — lifecycle
    // outcomes export the session envelope (validated observations
    // + coverage + receipt), so jsonl + request-lifecycle runs the
    // capture instead of refusing. The frozen event-v0 envelope
    // still carries no lifecycle payload and stays byte-untouched;
    // the outcome selects the envelope at render time.
    // 4B-M5: SIGINT finalizes and renders the partial window (exit 3),
    // with a per-tick stderr progress line while the capture runs.
    let cfg = LiveConfig {
        source: source.to_owned(),
        duration_secs: Some(report_window_secs(duration)),
        tick_ms: DEFAULT_TICK_MS,
        token: token.map(Path::to_owned),
        // 4B-M4: machine formats get the structured stderr audit
        // trail (object load + attach); human mode stays silent.
        json_audit: !matches!(format, ReportFormat::Human),
        profile,
    };
    finish_report_live(
        run_live_capture(&cfg, &crate::runtime_facts::live_runtime()),
        format,
        out,
        filter,
        stdout,
        stderr,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_watch::fixtures::*;
    use kryprobe_testkit::assert_golden;
    use std::path::PathBuf;

    fn golden(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens")
            .join(name)
    }

    #[test]
    fn json_golden_pins_doc() {
        assert_golden(
            &golden("report_live.json"),
            render_report_json(&json_fixture())
                .expect("fixture renders")
                .as_bytes(),
        );
    }

    #[test]
    fn json_hostile_payload_renders_without_panic() {
        // 1A-M4/3A-L-T2: hostile-but-valid payloads render through
        // the Result shapes (the Err branches exist so a future
        // unserializable graph shape degrades to exit 1, never a
        // panic-shaped exit 101).
        let mut outcome = json_fixture();
        let first = outcome
            .observations
            .first_mut()
            .expect("fixture carries an observation");
        first.backend_payload = serde_json::json!({
            "deep": {"a": [1, {"b": "x".repeat(4096)}]},
            "many": (0..512).map(|i| format!("k{i}")).collect::<Vec<_>>(),
        });
        let text = render_report_json(&outcome).expect("hostile payload renders");
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("hostile json parses");
        assert_eq!(doc["verdict"]["status"], "complete");
    }

    #[test]
    fn json_keys_exact_and_verdict_tracks_gaps() {
        let text = render_report_json(&json_fixture()).expect("fixture renders");
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("report json parses");
        let mut keys: Vec<&str> = doc
            .as_object()
            .expect("top-level object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "coverage",
                "enrichment",
                "integrity",
                "observations",
                "verdict"
            ]
        );
        assert!(text.starts_with("{\"observations\":"), "brief key order");
        // T07-R2-09: enrichment rides between integrity and
        // verdict; the aggregate fixture never snapshots (null).
        assert!(
            text.contains(",\"enrichment\":null,\"verdict\":"),
            "enrichment key placement: {text}"
        );
        assert_eq!(doc["verdict"]["status"], "complete");
        assert_eq!(doc["verdict"]["missing"], serde_json::json!([]));

        let partial = render_report_json(&partial_fixture()).expect("fixture renders");
        let doc: serde_json::Value =
            serde_json::from_str(partial.trim_end()).expect("partial json parses");
        assert_eq!(doc["verdict"]["status"], "partial");
        assert_eq!(
            doc["verdict"]["missing"],
            serde_json::json!(["attach", "capture-integrity"])
        );
    }

    #[test]
    fn json_and_human_carry_enrichment_verdict() {
        // T07-R2-09: every enrichment arm reaches BOTH user
        // surfaces — the JSON key and the human trailer line — so
        // an unreadable `/proc/crypto` never looks like available
        // enrichment.
        let mut outcome = json_fixture();
        outcome.enrichment = Some(EnrichmentStatus::Available {
            entries: 41,
            truncated: true,
        });
        let text = render_report_json(&outcome).expect("available renders");
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("available json parses");
        assert_eq!(
            doc["enrichment"],
            serde_json::json!({"status": "available", "entries": 41, "truncated": true})
        );
        assert_eq!(
            crate::live::render_enrichment_line(&outcome.enrichment),
            "enrichment: available (entries=41, truncated=true)\n"
        );
        outcome.enrichment = Some(EnrichmentStatus::Unavailable {
            reason: "os error 2".to_owned(),
        });
        let text = render_report_json(&outcome).expect("unavailable renders");
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("unavailable json parses");
        assert_eq!(
            doc["enrichment"],
            serde_json::json!({"status": "unavailable", "reason": "os error 2"})
        );
        assert_eq!(
            crate::live::render_enrichment_line(&outcome.enrichment),
            "enrichment: unavailable (reason: os error 2)\n"
        );
        outcome.enrichment = None;
        let text = render_report_json(&outcome).expect("none renders");
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("none json parses");
        assert!(doc["enrichment"].is_null(), "not-attempted is null");
        assert_eq!(
            crate::live::render_enrichment_line(&outcome.enrichment),
            "enrichment: not attempted (profile snapshots no registry)\n"
        );
    }

    #[test]
    fn window_defaults_to_60s() {
        assert_eq!(report_window_secs(None), 60);
        assert_eq!(report_window_secs(Some(2)), 2);
    }

    #[test]
    fn json_lifecycle_rows_carry_v1_payloads() {
        // Report JSON projects lifecycle rows to the standalone
        // payload-v1 object: `schema` present, exactly six keys, and
        // the validator accepts every projected payload.
        use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
        use kryprobe_core::evidence::{IntegrityRef, NativeObservation, NativeResult};
        use kryprobe_core::ids::ObservationId;
        let obs = NativeObservation {
            id: ObservationId::new(1),
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Completed,
            call_kind: CallKind::Operation,
            operation_class: OperationClass::Unknown,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns: None,
            ended_ns: None,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "lifecycle",
                "capture_profile": "request-lifecycle",
                "id": "lc:1",
                "tfm_id": null,
                "terminal": "sync",
                "status": 0,
                "duration_ns": "50",
                "evidence": true,
                "count_unit": "request_lifecycle",
                "completion_coverage": "observed",
            }),
        };
        let mut outcome = json_fixture();
        outcome.observations.push(obs);
        let text = render_report_json(&outcome).expect("fixture renders");
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("report json parses");
        let rows = doc["observations"].as_array().expect("observations array");
        let payload = &rows[rows.len() - 1]["backend_payload"];
        let mut keys: Vec<&str> = payload
            .as_object()
            .expect("payload object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "duration_ns",
                "request_id",
                "schema",
                "status",
                "terminal",
                "tfm_id"
            ]
        );
        assert_eq!(payload["schema"], "kryprobe.kcrypto.lifecycle/v1");
        assert!(
            kryprobe_report::validate_lifecycle_v1(payload).is_empty(),
            "projected payload validates"
        );
    }

    /// Lifecycle outcome fixture: one sync + one unknown row, exact
    /// reducer totals, healthy coverage (mirrors
    /// `tests/goldens/lifecycle_session.jsonl`).
    fn lifecycle_fixture() -> LiveOutcome {
        use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
        use kryprobe_core::evidence::{IntegrityRef, NativeObservation, NativeResult};
        use kryprobe_core::ids::ObservationId;
        let row = |id: u64,
                   terminal: &str,
                   status: serde_json::Value,
                   duration: serde_json::Value| {
            NativeObservation {
                id: ObservationId::new(id),
                backend: BackendId::KCrypto,
                target: None,
                object: None,
                implementation: None,
                phase: EvidencePhase::Completed,
                call_kind: CallKind::Operation,
                operation_class: OperationClass::Unknown,
                native_name: None,
                native_code: None,
                native_result: NativeResult::KCrypto { status: 0 },
                started_ns: None,
                ended_ns: None,
                correlation: None,
                integrity: IntegrityRef::new(0),
                backend_payload: serde_json::json!({
                    "row": "lifecycle",
                    "capture_profile": "request-lifecycle",
                    "id": format!("lc:{id}"),
                    "tfm_id": null,
                    "terminal": terminal,
                    "status": status,
                    "duration_ns": duration,
                    "evidence": terminal != "unknown",
                    "count_unit": "request_lifecycle",
                    "completion_coverage": if terminal == "unknown" { "unobserved" } else { "observed" },
                }),
            }
        };
        let mut outcome = outcome_with(
            vec![
                row(1, "sync", serde_json::json!(0), serde_json::json!("50")),
                row(
                    2,
                    "unknown",
                    serde_json::json!(null),
                    serde_json::json!(null),
                ),
            ],
            healthy_coverage(2),
        );
        outcome.lifecycle_totals = Some(crate::live::LifecycleTotals {
            admitted: 2,
            emitted: 2,
            unfinished: 1,
            unknown_terminals: 1,
            ..Default::default()
        });
        outcome
    }

    #[test]
    fn jsonl_lifecycle_runs_capture_and_exports_session() {
        // T11/P6 contract flip (approved): jsonl + request-lifecycle
        // runs the capture (no pre-capture refusal) and exports the
        // versioned session envelope. The bogus source proves the
        // capture runs (exit 4 naming the source, like human).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_report_live(
            "bogus-source",
            Some(0),
            ReportFormat::Jsonl,
            None,
            None,
            LifecycleProfile::RequestLifecycle,
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 4);
        let detail = String::from_utf8(stderr).expect("stderr is UTF-8");
        assert!(
            detail.contains("bogus-source"),
            "capture names the source: {detail}"
        );
    }

    #[test]
    fn jsonl_lifecycle_session_validates_clean() {
        // The exported session stream validates clean under the
        // session validator: start, both observations, coverage,
        // receipt — with the unfinished row forcing a partial
        // receipt (never a clean claim over unfinished work).
        let text =
            render_lifecycle_session(&lifecycle_fixture(), LifecycleProfile::RequestLifecycle)
                .expect("fixture exports");
        assert!(
            kryprobe_report::validate_lifecycle_session(&text).is_empty(),
            "session validates clean:\n{text}"
        );
        assert!(
            text.contains("\"verdict\":\"partial\""),
            "unfinished work forces partial:\n{text}"
        );
        assert!(
            text.contains("\"unfinished\":1"),
            "unfinished population rides the receipt:\n{text}"
        );
        // A non-lifecycle row in a lifecycle export refuses LOUD
        // (exit 1 at the CLI), never a silent skip.
        let mut mixed = lifecycle_fixture();
        mixed
            .observations
            .push(json_fixture().observations[0].clone());
        let err = render_lifecycle_session(&mixed, LifecycleProfile::RequestLifecycle)
            .expect_err("mixed rows must refuse");
        assert!(
            matches!(err, kryprobe_report::ReportError::UnprojectableRow { .. }),
            "typed refusal: {err}"
        );
    }

    #[test]
    fn session_golden_pins_stream() {
        // P6-N4: the golden keeps its fixed `live:run` id via direct
        // writer-path construction (fixed id passed in) while the
        // production exporter mints run-unique ids.
        assert_golden(
            &golden("lifecycle_session.jsonl"),
            render_lifecycle_session_with_id(
                &lifecycle_fixture(),
                LifecycleProfile::RequestLifecycle,
                kryprobe_report::live_render::LIVE_SESSION_ID,
                None,
            )
            .expect("fixture exports")
            .as_bytes(),
        );
    }

    fn export_session_id(text: &str) -> String {
        let start: serde_json::Value =
            serde_json::from_str(text.lines().next().expect("export opens with start"))
                .expect("start parses");
        start
            .get("session")
            .and_then(serde_json::Value::as_str)
            .expect("start carries session")
            .to_owned()
    }

    #[test]
    fn live_exports_mint_run_unique_sessions() {
        // P6-N4 RED: every live export mints its own session id
        // (constant `live:run` let a cross-kernel observation splice
        // validate). Two exports must differ.
        let first =
            render_lifecycle_session(&lifecycle_fixture(), LifecycleProfile::RequestLifecycle)
                .expect("first exports");
        let second =
            render_lifecycle_session(&lifecycle_fixture(), LifecycleProfile::RequestLifecycle)
                .expect("second exports");
        assert_ne!(
            export_session_id(&first),
            export_session_id(&second),
            "live exports must not share a session id"
        );
    }

    #[test]
    fn cross_run_observation_splice_refuses() {
        // P6-N4 RED: an observation spliced from another run's
        // export (same seq, foreign session) refuses on the session
        // constancy check — run identity defeats the splice.
        let first =
            render_lifecycle_session(&lifecycle_fixture(), LifecycleProfile::RequestLifecycle)
                .expect("first exports");
        let second =
            render_lifecycle_session(&lifecycle_fixture(), LifecycleProfile::RequestLifecycle)
                .expect("second exports");
        let mut first_lines: Vec<&str> = first.lines().collect();
        let second_lines: Vec<&str> = second.lines().collect();
        assert!(first_lines.len() > 2 && second_lines.len() > 2);
        first_lines[1] = second_lines[1];
        let spliced = first_lines.join("\n") + "\n";
        assert!(
            !kryprobe_report::validate_lifecycle_session(&spliced).is_empty(),
            "cross-run splice must refuse"
        );
    }

    #[test]
    fn finish_exits_complete_partial_and_errors() {
        // Complete → 0 with the trailer on stdout.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Human,
            None,
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        let human = String::from_utf8(stdout).expect("utf-8");
        assert!(human.contains("COMPLETE\n"), "human trailer kept");
        // T07-R2-09: the enrichment verdict trailers the tables
        // (aggregate fixture: honestly not attempted).
        assert!(
            human.ends_with("enrichment: not attempted (profile snapshots no registry)\n"),
            "enrichment trailer: {human}"
        );
        // Gaps → 3 (findings stand: the tables still render).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(partial_fixture()),
            ReportFormat::Human,
            None,
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
        assert!(
            String::from_utf8(stdout)
                .expect("utf-8")
                .contains("PARTIAL: attach,capture-integrity")
        );
        // JSON to stdout → 0 with the doc.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Json,
            None,
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(
            String::from_utf8(stdout)
                .expect("utf-8")
                .starts_with("{\"observations\":")
        );
        // Failures name themselves: Unusable → 4, Internal → 1.
        for (err, code) in [
            (LiveError::Unusable("gate".to_owned()), 4),
            (LiveError::Internal("boom".to_owned()), 1),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            assert_eq!(
                finish_report_live(
                    Err(err),
                    ReportFormat::Human,
                    None,
                    &FilterArgs::default(),
                    &mut stdout,
                    &mut stderr
                ),
                code
            );
            assert!(stdout.is_empty());
            assert!(
                String::from_utf8(stderr)
                    .expect("utf-8")
                    .contains("report:")
            );
        }
    }

    #[test]
    fn finish_out_writes_atomically_and_reports_failure() {
        let scratch = kryprobe_testkit::TempDir::named("k3-2-out").expect("scratch dir");
        let file = scratch.path().join("report.json");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Json,
            Some(&file),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(stdout.is_empty(), "file mode prints no stdout");
        assert!(
            String::from_utf8(stderr).expect("utf-8").contains("wrote "),
            "write receipt"
        );
        assert_eq!(
            std::fs::read(&file).expect("read out file"),
            render_report_json(&json_fixture())
                .expect("fixture renders")
                .as_bytes()
        );
        // Human honors `--out` through the same branch.
        let human = scratch.path().join("report.txt");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Human,
            Some(&human),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(stdout.is_empty(), "file mode prints no stdout");
        let mut human_text = kryprobe_report::live_render::render_watch_tables(
            &json_fixture().observations,
            &json_fixture().coverage,
        );
        human_text.push_str(&crate::live::render_enrichment_line(
            &json_fixture().enrichment,
        ));
        assert_eq!(
            std::fs::read(&human).expect("read human out file"),
            human_text.as_bytes()
        );
        // Unwritable destination fails closed (exit 1, nothing on stdout).
        let missing = scratch.path().join("no-such-dir").join("report.json");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Json,
            Some(&missing),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("cannot write")
        );
    }

    #[test]
    fn finish_interrupted_forces_partial_everywhere() {
        // 4B-M5: a SIGINT-cut window exits 3 with partial status in
        // every format, even when every measured dimension held.
        let mut outcome = json_fixture();
        outcome.interrupted = true;
        for format in [ReportFormat::Human, ReportFormat::Json, ReportFormat::Jsonl] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = finish_report_live(
                Ok(outcome.clone()),
                format,
                None,
                &FilterArgs::default(),
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(code, 3, "interrupted exits 3 in {format:?}");
            assert!(
                String::from_utf8(stderr)
                    .expect("utf-8")
                    .contains("interrupted by SIGINT"),
                "interruption named in {format:?}"
            );
        }
        assert!(
            render_report_json(&outcome)
                .expect("fixture renders")
                .contains("\"status\":\"partial\""),
            "JSON status flips to partial"
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        finish_report_live(
            Ok(outcome),
            ReportFormat::Jsonl,
            None,
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert!(
            String::from_utf8(stdout)
                .expect("utf-8")
                .contains("\"PARTIAL\""),
            "JSONL verdict flips to PARTIAL"
        );
    }

    #[test]
    fn finish_jsonl_emits_validated_stream() {
        const KINDS: &[(&str, &[&str])] = &[
            ("session_start", &["target_selector", "capture_mode"]),
            ("operation_observation", &["observation_id", "backend"]),
            ("session_end", &["verdict"]),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Jsonl,
            None,
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(stdout).expect("utf-8");
        assert_eq!(kryprobe_report::check_stream(&text, KINDS), Vec::new());
        assert!(text.contains("\"session_start\""));
        assert!(text.contains("\"session_end\""));
    }

    #[test]
    fn finish_json_with_filter_carries_tallies_and_hides() {
        // P6-N3: the JSON report carries the filtered view — the
        // mismatched who row hides from observations, exact tallies
        // ride the attribution counters. Fixture: 1 agg + 1 who (tid
        // 4243); the stranger pid filters the who row out.
        let filter = FilterArgs {
            pid: Some(999),
            uid: None,
            comm: None,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Json,
            None,
            &filter,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        let doc: serde_json::Value =
            serde_json::from_str(String::from_utf8(stdout).expect("utf-8").trim_end())
                .expect("json parses");
        let rows = doc["observations"].as_array().expect("observations");
        assert_eq!(rows.len(), 1, "agg passes, who hides: {doc}");
        assert_eq!(rows[0]["backend_payload"]["row"], "agg");
        let counters = doc["coverage"]["attribution"]["counters"]
            .as_array()
            .expect("attribution counters");
        let value = |name: &str| {
            counters
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("counter {name}: {counters:?}"))["value"]
                .clone()
        };
        assert_eq!(value("filter_admitted"), serde_json::json!("0"));
        assert_eq!(value("filter_filtered"), serde_json::json!("1"));
        assert_eq!(value("filter_unknown"), serde_json::json!("0"));
    }

    #[test]
    fn lifecycle_export_with_filter_carries_envelope_tallies() {
        // P6-N3: under a filter the envelope coverage record rides
        // the exact tallies (union unknown + filtered-out) instead
        // of the unfiltered populations.
        let text = render_lifecycle_session_with_id(
            &lifecycle_fixture(),
            LifecycleProfile::RequestLifecycle,
            "session:filtered",
            Some(EnvelopeFilter {
                unknown: 2,
                filtered: 1,
            }),
        )
        .expect("filtered export");
        let coverage = text
            .lines()
            .find(|line| line.contains("\"kind\":\"coverage\""))
            .expect("coverage record");
        let record: serde_json::Value = serde_json::from_str(coverage).expect("coverage parses");
        assert_eq!(record["unknown"], 2);
        assert_eq!(record["filtered"], 1);
        assert!(
            kryprobe_report::validate_lifecycle_session(&text).is_empty(),
            "filtered export validates:\n{text}"
        );
    }

    #[test]
    fn lifecycle_finish_with_filter_unions_unknown() {
        // P6-N3 end to end: the lifecycle fixture (one sync + one
        // unknown row) under a pid filter exports unknown=2 (both
        // verdict-unknown, one also terminal-unknown — counted once)
        // and filtered=0, and every row still renders.
        let filter = FilterArgs {
            pid: Some(101),
            uid: None,
            comm: None,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(lifecycle_fixture()),
            ReportFormat::Jsonl,
            None,
            &filter,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(stdout).expect("utf-8");
        let observations = text
            .lines()
            .filter(|line| line.contains("\"kind\":\"observation\""))
            .count();
        assert_eq!(observations, 2, "lifecycle never gates rows:\n{text}");
        let coverage = text
            .lines()
            .find(|line| line.contains("\"kind\":\"coverage\""))
            .expect("coverage record");
        let record: serde_json::Value = serde_json::from_str(coverage).expect("coverage parses");
        assert_eq!(record["unknown"], 2, "exact union:\n{text}");
        assert_eq!(record["filtered"], 0, "nothing known-mismatched:\n{text}");
    }
}
