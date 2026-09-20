// SPDX-License-Identifier: GPL-3.0-or-later
//! `report`: validate a stream, then render its summary (exit 0 or 2);
//! plus `report --system`: one live capture rendered human or JSON
//! (exit 0 complete, 3 partial, 4 unusable, 1 internal).

use crate::args::ReportFormat;
use crate::live::{DEFAULT_TICK_MS, LiveConfig, LiveError, LiveOutcome, run_live_capture};
use kryprobe_report::{validate_and_render_file, write_str_atomic};
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
/// `integrity`, `verdict`), with the `doctor`-shaped verdict
/// `{status, missing}`. Serialized straight into one growing buffer
/// (M7: a `json!` map would sort the keys, and four `to_string`s plus
/// `format!` would peak at ~2× the doc size); byte-identical to the
/// piece-assembled form.
#[must_use]
pub fn render_report_json(outcome: &LiveOutcome) -> String {
    let missing = kryprobe_report::live_render::trailer_dims(&outcome.coverage);
    let status = if missing.is_empty() {
        "complete"
    } else {
        "partial"
    };
    // Live kcrypto rows always serialize (real decodes never emit the
    // synthetic backend/result or the `Succeeded` phase); a failure is a
    // caller defect and fails loud, never a partial doc. `Vec` writes
    // never fail, so the `expect`s below are unreachable in practice.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"{\"observations\":");
    serde_json::to_writer(&mut buf, &outcome.observations).expect("live observations serialize");
    buf.extend_from_slice(b",\"coverage\":");
    serde_json::to_writer(&mut buf, &outcome.coverage).expect("live coverage serializes");
    buf.extend_from_slice(b",\"integrity\":");
    serde_json::to_writer(&mut buf, &outcome.integrity).expect("live integrity serializes");
    buf.extend_from_slice(b",\"verdict\":{\"status\":\"");
    buf.extend_from_slice(status.as_bytes());
    buf.extend_from_slice(b"\",\"missing\":");
    serde_json::to_writer(&mut buf, &missing).expect("verdict dims serialize");
    buf.extend_from_slice(b"}}\n");
    String::from_utf8(buf).expect("report JSON is UTF-8")
}

/// Live window: explicit `--duration` or the 60s default.
fn report_window_secs(duration: Option<u64>) -> u64 {
    duration.unwrap_or(DEFAULT_REPORT_SECS)
}

/// Finishes a live capture: human tables, the JSON doc, or the
/// validated event-v0 JSONL stream to `--out` (atomic) or stdout; 0
/// when the coverage contract held, 3 on gaps, 4/1 on [`LiveError`]
/// via [`LiveError::exit_code`], 1 when the JSONL export refuses a
/// non-wire-spellable row.
fn finish_report_live(
    result: Result<LiveOutcome, LiveError>,
    format: ReportFormat,
    out: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(err) => {
            let _ = writeln!(stderr, "report: {err}");
            return err.exit_code();
        }
    };
    let code = if kryprobe_report::live_render::trailer_dims(&outcome.coverage).is_empty() {
        0
    } else {
        3
    };
    let text = match format {
        ReportFormat::Human => kryprobe_report::live_render::render_watch_tables(
            &outcome.observations,
            &outcome.coverage,
        ),
        ReportFormat::Json => render_report_json(&outcome),
        ReportFormat::Jsonl => {
            match kryprobe_report::live_render::render_live_jsonl(
                &outcome.observations,
                &outcome.coverage,
            ) {
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
pub fn run_report_live(
    source: &str,
    duration: Option<u64>,
    format: ReportFormat,
    out: Option<&Path>,
    token: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // Ctrl-C keeps the default disposition and terminates the process:
    // no trailer, no finalize (Task 1 installs no SIGINT handler —
    // std-only). Graceful-shutdown-on-SIGINT is future work.
    let cfg = LiveConfig {
        source: source.to_owned(),
        duration_secs: Some(report_window_secs(duration)),
        tick_ms: DEFAULT_TICK_MS,
        token: token.map(Path::to_owned),
    };
    finish_report_live(
        run_live_capture(&cfg, &crate::runtime_facts::live_runtime()),
        format,
        out,
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
            render_report_json(&json_fixture()).as_bytes(),
        );
    }

    #[test]
    fn json_keys_exact_and_verdict_tracks_gaps() {
        let text = render_report_json(&json_fixture());
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("report json parses");
        let mut keys: Vec<&str> = doc
            .as_object()
            .expect("top-level object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["coverage", "integrity", "observations", "verdict"]);
        assert!(text.starts_with("{\"observations\":"), "brief key order");
        assert_eq!(doc["verdict"]["status"], "complete");
        assert_eq!(doc["verdict"]["missing"], serde_json::json!([]));

        let partial = render_report_json(&partial_fixture());
        let doc: serde_json::Value =
            serde_json::from_str(partial.trim_end()).expect("partial json parses");
        assert_eq!(doc["verdict"]["status"], "partial");
        assert_eq!(
            doc["verdict"]["missing"],
            serde_json::json!(["attach", "capture-integrity"])
        );
    }

    #[test]
    fn window_defaults_to_60s() {
        assert_eq!(report_window_secs(None), 60);
        assert_eq!(report_window_secs(Some(2)), 2);
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
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(
            String::from_utf8(stdout)
                .expect("utf-8")
                .ends_with("COMPLETE\n"),
            "human trailer"
        );
        // Gaps → 3 (findings stand: the tables still render).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(partial_fixture()),
            ReportFormat::Human,
            None,
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
        let dir = std::env::temp_dir().join(format!("kryprobe-k3-2-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let file = dir.join("report.json");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Json,
            Some(&file),
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
            render_report_json(&json_fixture()).as_bytes()
        );
        // Human honors `--out` through the same branch.
        let human = dir.join("report.txt");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Human,
            Some(&human),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(stdout.is_empty(), "file mode prints no stdout");
        assert_eq!(
            std::fs::read(&human).expect("read human out file"),
            kryprobe_report::live_render::render_watch_tables(
                &json_fixture().observations,
                &json_fixture().coverage,
            )
            .as_bytes()
        );
        // Unwritable destination fails closed (exit 1, nothing on stdout).
        let missing = dir.join("no-such-dir").join("report.json");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_report_live(
            Ok(json_fixture()),
            ReportFormat::Json,
            Some(&missing),
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
        std::fs::remove_dir_all(&dir).ok();
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
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(stdout).expect("utf-8");
        assert_eq!(kryprobe_report::check_stream(&text, KINDS), Vec::new());
        assert!(text.contains("\"session_start\""));
        assert!(text.contains("\"session_end\""));
    }
}
