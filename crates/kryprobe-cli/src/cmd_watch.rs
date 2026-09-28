// SPDX-License-Identifier: GPL-3.0-or-later
//! `watch --system`: one live capture rendered as aggregated human tables.
//!
//! One blocking [`run_live_capture`](crate::live::run_live_capture) per
//! invocation, then one render: the per-tick snapshots repeat agg/totals
//! rows with cumulative counters, so the table keeps the latest
//! observation per full row key and sums across result classes and
//! contexts. `report --system` (human) renders these same tables via
//! [`render_watch_tables`](kryprobe_report::live_render::render_watch_tables);
//! only the exit code differs (watch exits 0 on any completed capture,
//! report exits 0/3 on the verdict). The tables themselves live in
//! `kryprobe-report` (1B-H2/1B-M8); this module is dispatch + runtime
//! facts + test fixtures.

use crate::args::FilterArgs;
use crate::live::{
    DEFAULT_TICK_MS, LiveConfig, LiveError, LiveOutcome, emit_stdout_text, run_live_capture,
};
use crate::request_filter::{
    EVIDENCE_VERSION, apply_request_filter, context_filter, push_filter_counters,
};
use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;
use std::io::Write;
use std::path::Path;

/// Finishes a capture: tables to stdout (exit 0, or 3 when the window
/// was SIGINT-cut) or the named failure to stderr (`Unusable` → 4,
/// `Internal` → 1 via [`LiveError::exit_code`]). An active CLI filter
/// applies post-ingestion first (P6-N3): filtered-out rows hide,
/// tallies ride coverage + the FILTER line.
fn finish_watch(
    result: Result<LiveOutcome, LiveError>,
    filter: &FilterArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match result {
        Ok(mut outcome) => {
            // P6-N3: post-ingestion filter (inactive filters skip
            // entirely — unfiltered sessions keep exact bytes).
            let mut filter_counts = None;
            if filter.is_active() {
                let view = apply_request_filter(
                    &outcome.observations,
                    &context_filter(filter),
                    EVIDENCE_VERSION,
                    kryprobe_report::KCRYPTO_LIFECYCLE_SESSION_V1,
                );
                outcome.observations = view.observations;
                push_filter_counters(&mut outcome.coverage, &view.tally);
                filter_counts = Some(kryprobe_report::live_render::FilterCounts {
                    admitted: view.tally.admitted,
                    filtered: view.tally.filtered_out,
                    unknown: view.tally.unknown,
                });
            }
            // One emit (P7/T12): the tables + enrichment line
            // finalize together — a torn stream reports 1, never a
            // silent capture code. Bytes identical to the two-write
            // form on success.
            let mut text = kryprobe_report::live_render::render_watch_tables_filtered(
                &outcome.observations,
                &outcome.coverage,
                filter_counts,
            );
            text.push_str(&crate::live::render_enrichment_line(&outcome.enrichment));
            // 4B-M5: an interrupted window is partial evidence even
            // when every measured dimension held — exit 3, with the
            // tables above as the preserved evidence.
            let code = if outcome.interrupted {
                let _ = writeln!(stderr, "watch: interrupted by SIGINT — partial window");
                3
            } else {
                0
            };
            emit_stdout_text(stdout, stderr, "watch", &text, code)
        }
        Err(err) => {
            let _ = writeln!(stderr, "watch: {err}");
            err.exit_code()
        }
    }
}

/// Runs `watch --system`: one capture (`None` runs until stdin closes),
/// then the aggregated tables to stdout.
pub fn run_watch(
    source: &str,
    duration: Option<u64>,
    token: Option<&Path>,
    profile: LifecycleProfile,
    filter: &FilterArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // 4B-M5: SIGINT finalizes and renders the partial window (exit 3),
    // with a per-tick stderr progress line while the capture runs.
    let cfg = LiveConfig {
        source: source.to_owned(),
        duration_secs: duration,
        tick_ms: DEFAULT_TICK_MS,
        token: token.map(Path::to_owned),
        json_audit: false,
        profile,
    };
    finish_watch(
        run_live_capture(&cfg, &crate::runtime_facts::live_runtime()),
        filter,
        stdout,
        stderr,
    )
}

/// Hand-fed `LiveOutcome` fixtures shared by this crate's unit tests
/// (`observation_for_agg`-shaped payloads; the e2e markers keep their own
/// mirror copy since integration tests link the non-test lib).
#[cfg(test)]
pub(crate) mod fixtures {
    use kryprobe_core::backend::BackendSummary;
    use kryprobe_core::enums::{
        BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass,
    };
    use kryprobe_core::evidence::{
        CoverageSummary, DimensionCounter, DimensionCoverage, IntegrityRef, IntegritySummary,
        NativeObservation, NativeResult, ValidityInterval,
    };
    use kryprobe_core::ids::ObservationId;

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn agg_obs(
        id: u64,
        family: &str,
        op: &str,
        result: &str,
        algorithm: &str,
        driver: &str,
        context: &str,
        calls: u64,
        bytes: u64,
        ok: u64,
        errors: u64,
        queued: u64,
    ) -> NativeObservation {
        let class = match op {
            "encrypt" => OperationClass::Encrypt,
            "decrypt" => OperationClass::Decrypt,
            "digest" | "finup" => OperationClass::Digest,
            _ => OperationClass::Unknown,
        };
        NativeObservation {
            id: ObservationId::new(id),
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Completed,
            call_kind: CallKind::Operation,
            operation_class: class,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns: Some(100),
            ended_ns: Some(200),
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "agg",
                "family": family,
                "op": op,
                "result": result,
                "algorithm": algorithm,
                "driver": driver,
                "context": context,
                "counts": {"calls": calls, "ok": ok, "errors": errors, "queued": queued},
                "bytes": bytes,
                "window": {"first_ns": 100, "last_ns": 200},
                "status_canonical": true,
                "capture_profile": "api-returns",
                "count_unit": "api_invocation_return",
                "completion_coverage": "unobserved",
            }),
        }
    }

    pub(crate) fn totals_obs(
        id: u64,
        calls: u64,
        bytes: u64,
        ok: u64,
        errors: u64,
        queued: u64,
    ) -> NativeObservation {
        NativeObservation {
            id: ObservationId::new(id),
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Completed,
            call_kind: CallKind::Unknown,
            operation_class: OperationClass::Unknown,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns: Some(100),
            ended_ns: Some(200),
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "totals",
                "counts": {"calls": calls, "ok": ok, "errors": errors, "queued": queued},
                "bytes": bytes,
                "window": {"first_ns": 100, "last_ns": 200},
                "status_canonical": true,
                "capture_profile": "api-returns",
                "count_unit": "api_invocation_return",
                "completion_coverage": "unobserved",
            }),
        }
    }

    pub(crate) fn ident_obs(id: u64) -> NativeObservation {
        NativeObservation {
            id: ObservationId::new(id),
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Discovered,
            call_kind: CallKind::Operation,
            operation_class: OperationClass::Encrypt,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns: Some(100),
            ended_ns: None,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "ident",
                "ident_kind": "ident",
                "key_hash": 1234,
                "family": "skcipher",
                "op": "encrypt",
                "result": "ok",
                "context": "process",
                "name_lens": {"alg": 8, "drv": 5},
                "first_seen_ns": 100,
                "capture_profile": "api-returns",
            }),
        }
    }

    /// One `row="who"` observation in the Task 4 resolved shape
    /// (parent + params + one symbolized frame + first_errno).
    pub(crate) fn who_obs(
        id: u64,
        kh: u64,
        tgid: u64,
        comm: &str,
        uid: u64,
        calls: u64,
    ) -> NativeObservation {
        NativeObservation {
            id: ObservationId::new(id),
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Discovered,
            call_kind: CallKind::Unknown,
            operation_class: OperationClass::Unknown,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns: Some(100),
            ended_ns: Some(200),
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "who",
                "key_hash": kh,
                "tgid": tgid,
                "tid": tgid + 1,
                "comm": comm,
                "uid": uid,
                "cgroup": 156,
                "ppid": 12,
                "pcomm": "bash",
                "stack": {"id": 3, "frames": [{"ip": 0xffffffff81001500u64, "sym": "hash_sendmsg"}]},
                "calls": calls,
                "first_ns": 100,
                "last_ns": 200,
                "blocksize": 16,
                "ivsize": 16,
                "min_keysize": 16,
                "max_keysize": 32,
                "first_errno": -5,
                "capture_profile": "api-returns",
            }),
        }
    }

    fn dim(status: CoverageStatus, counters: Vec<(&str, u64)>) -> DimensionCoverage {
        let mut dim = DimensionCoverage::new(
            status,
            ValidityInterval {
                start_ns: 100,
                end_ns: Some(200),
            },
        );
        for (name, value) in counters {
            dim.counters.push(DimensionCounter {
                name: name.to_owned(),
                value,
            });
        }
        dim
    }

    pub(crate) fn complete_dim() -> DimensionCoverage {
        dim(CoverageStatus::CompleteForDeclaredBoundary, Vec::new())
    }

    pub(crate) fn healthy_coverage(decoded: u64) -> CoverageSummary {
        CoverageSummary {
            target_population: complete_dim(),
            object_discovery: complete_dim(),
            attachment: dim(
                CoverageStatus::CompleteForDeclaredBoundary,
                vec![("probes_attached", 9), ("probes_expected", 9)],
            ),
            aggregate_counts: dim(
                CoverageStatus::CompleteForDeclaredBoundary,
                vec![("ktot_gap", 0)],
            ),
            detailed_events: dim(
                CoverageStatus::CompleteForDeclaredBoundary,
                vec![("ring_drops", 0), ("overflow_identities", 0)],
            ),
            attribution: complete_dim(),
            correlation: complete_dim(),
            completion: dim(
                CoverageStatus::CompleteForDeclaredBoundary,
                vec![("observations_decoded", decoded)],
            ),
        }
    }

    pub(crate) fn gapped_coverage() -> CoverageSummary {
        CoverageSummary {
            target_population: complete_dim(),
            object_discovery: complete_dim(),
            attachment: dim(
                CoverageStatus::Partial,
                vec![("probes_attached", 8), ("probes_expected", 9)],
            ),
            aggregate_counts: dim(CoverageStatus::Partial, vec![("ktot_gap", 7)]),
            detailed_events: dim(
                CoverageStatus::CompleteForDeclaredBoundary,
                vec![("ring_drops", 0), ("overflow_identities", 0)],
            ),
            attribution: complete_dim(),
            correlation: complete_dim(),
            completion: dim(
                CoverageStatus::CompleteForDeclaredBoundary,
                vec![("observations_decoded", 2)],
            ),
        }
    }

    pub(crate) fn outcome_with(
        observations: Vec<NativeObservation>,
        coverage: CoverageSummary,
    ) -> crate::live::LiveOutcome {
        let decoded = observations.len() as u64;
        crate::live::LiveOutcome {
            observations,
            summary: BackendSummary {
                backend: BackendId::KCrypto,
                observations: decoded,
                integrity: IntegritySummary::default(),
            },
            coverage,
            integrity: IntegritySummary::default(),
            terminal_state: kryprobe_core::session::SessionState::Finalized,
            interrupted: false,
            // Aggregate-profile fixture: no registry snapshot.
            enrichment: None,
            // Aggregate-profile fixture: no lifecycle reducer.
            lifecycle_totals: None,
        }
    }

    /// Two-tick cumulative session (mirrors `tests/goldens/watch.txt`).
    pub(crate) fn watch_fixture() -> crate::live::LiveOutcome {
        let observations = vec![
            agg_obs(
                1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 10, 1000, 10, 0, 0,
            ),
            agg_obs(
                2, "aead", "decrypt", "error", "gcm(aes)", "aesni", "process", 1, 64, 0, 1, 0,
            ),
            totals_obs(3, 11, 1064, 10, 1, 0),
            agg_obs(
                4, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 25, 2500, 25, 0, 0,
            ),
            agg_obs(
                5, "aead", "decrypt", "error", "gcm(aes)", "aesni", "process", 2, 128, 0, 2, 0,
            ),
            agg_obs(
                6, "aead", "decrypt", "ok", "gcm(aes)", "aesni", "process", 5, 320, 5, 0, 0,
            ),
            totals_obs(7, 32, 2948, 30, 2, 0),
            ident_obs(8),
            who_obs(9, 0xc1, 4242, "python3", 1000, 7),
            who_obs(10, 0xc2, 12, "bash", 0, 3),
        ];
        outcome_with(observations, healthy_coverage(10))
    }

    /// Single-tick gapped session (mirrors `tests/goldens/report_partial.txt`).
    pub(crate) fn partial_fixture() -> crate::live::LiveOutcome {
        let observations = vec![
            agg_obs(
                1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 3, 300, 3, 0, 0,
            ),
            totals_obs(2, 10, 1000, 10, 0, 0),
        ];
        outcome_with(observations, gapped_coverage())
    }

    /// Minimal healthy session (mirrors `tests/goldens/report_live.json`).
    pub(crate) fn json_fixture() -> crate::live::LiveOutcome {
        let observations = vec![
            agg_obs(
                1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 3, 300, 3, 0, 0,
            ),
            who_obs(2, 0xc1, 4242, "python3", 1000, 7),
        ];
        outcome_with(observations, healthy_coverage(2))
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use kryprobe_report::live_render::render_watch_tables;
    use kryprobe_testkit::assert_golden;
    use std::path::PathBuf;

    fn golden(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens")
            .join(name)
    }

    /// Renders a hand-fed outcome through the report tables (1B-H2).
    fn render(fixture: &crate::live::LiveOutcome) -> String {
        render_watch_tables(&fixture.observations, &fixture.coverage)
    }

    #[test]
    fn watch_golden_pins_complete_render() {
        assert_golden(&golden("watch.txt"), render(&watch_fixture()).as_bytes());
    }

    #[test]
    fn partial_golden_pins_gap_trailer() {
        // Report human renders these same tables; the golden pins the
        // PARTIAL trailer over the gapped fixture.
        assert_golden(
            &golden("report_partial.txt"),
            render(&partial_fixture()).as_bytes(),
        );
    }

    #[test]
    fn latest_wins_per_row_key() {
        // Same full key twice (cumulative ticks): the table keeps 25,
        // never the 35 a naive sum would claim.
        let observations = vec![
            agg_obs(
                1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 10, 100, 10, 0, 0,
            ),
            agg_obs(
                2, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 25, 250, 25, 0, 0,
            ),
            totals_obs(3, 25, 250, 25, 0, 0),
        ];
        let text = render(&outcome_with(observations, healthy_coverage(3)));
        assert!(
            text.contains("skcipher encrypt cbc(aes) aesni 25 250 25 0 0\n"),
            "{text:?}"
        );
    }

    #[test]
    fn totals_absent_falls_back_to_column_sums() {
        // No totals carrier: TOTAL sums the rendered rows (the coverage
        // trailer separately attests the missing baseline).
        let observations = vec![
            agg_obs(
                1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 10, 100, 10, 0, 0,
            ),
            agg_obs(
                2, "aead", "decrypt", "ok", "gcm(aes)", "aesni", "process", 5, 50, 5, 0, 0,
            ),
        ];
        let text = render(&outcome_with(observations, healthy_coverage(2)));
        assert!(text.contains("TOTAL - - - 15 150 15 0 0\n"), "{text:?}");
    }

    #[test]
    fn blank_cells_render_unknown() {
        // Missing/empty names render `unknown` (C10), never blank, never
        // fabricated.
        let mut obs = agg_obs(
            1, "skcipher", "encrypt", "ok", "", "aesni", "process", 3, 30, 3, 0, 0,
        );
        obs.backend_payload
            .as_object_mut()
            .expect("payload object")
            .remove("driver");
        let text = render(&outcome_with(vec![obs], healthy_coverage(1)));
        assert!(
            text.contains("skcipher encrypt unknown unknown 3 30 3 0 0\n"),
            "{text:?}"
        );
    }

    #[test]
    fn hostile_cells_render_sanitized() {
        // L-SEC-01/M-T3: kernel-sourced strings (`comm`, names) can
        // carry control bytes (`PR_SET_NAME`, hostile modules) — tables
        // must neutralize them (no escapes, no row splits).
        let who = who_obs(1, 0xc1, 4242, "py\x1b[2Jth\non3", 1000, 7);
        let agg = agg_obs(
            2,
            "skcipher",
            "encrypt",
            "ok",
            "cbc\x07(aes)",
            "aesni",
            "process",
            3,
            30,
            3,
            0,
            0,
        );
        let text = render(&outcome_with(vec![who, agg], healthy_coverage(2)));
        assert!(!text.contains('\x1b'), "no escapes: {text:?}");
        assert!(text.contains("py?[2Jth?on3"), "sanitized comm: {text:?}");
        assert!(text.contains("cbc?(aes)"), "sanitized algorithm: {text:?}");
        for fragment in text.split('\n') {
            assert!(
                !fragment.chars().any(|c| c.is_control()),
                "no control chars in row: {fragment:?}"
            );
        }
    }

    #[test]
    fn finish_maps_outcome_and_errors() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_watch(
            Ok(watch_fixture()),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(
            String::from_utf8(stdout)
                .expect("utf-8")
                .contains("COMPLETE")
        );

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_watch(
            Err(LiveError::Unusable("btf gate".to_owned())),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 4);
        assert!(stdout.is_empty());
        let stderr = String::from_utf8(stderr).expect("utf-8");
        assert!(
            stderr.contains("watch:") && stderr.contains("btf gate"),
            "{stderr}"
        );

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_watch(
            Err(LiveError::Internal("boom".to_owned())),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr).expect("utf-8").contains("boom"),
            "internal reason surfaces"
        );
    }

    /// P7/T12: the emit seam owns stdout finalization — a broken
    /// pipe reports 1 with the explicit status, never the capture
    /// code over a torn stream.
    #[test]
    fn finish_broken_stdout_reports_terminal_failure() {
        struct BrokenPipe;
        impl std::io::Write for BrokenPipe {
            fn write(&mut self, _chunk: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "EPIPE"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut stdout = BrokenPipe;
        let mut stderr = Vec::new();
        let code = finish_watch(
            Ok(watch_fixture()),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1, "torn stream never reports the capture code");
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("watch: cannot write stdout"),
            "explicit terminal output status"
        );
    }

    #[test]
    fn finish_interrupted_renders_tables_and_exits_3() {
        // 4B-M5: SIGINT-cut windows keep their evidence (tables print)
        // but exit 3 with the interruption named on stderr.
        let mut outcome = watch_fixture();
        outcome.interrupted = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_watch(
            Ok(outcome),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
        assert!(
            String::from_utf8(stdout)
                .expect("utf-8")
                .contains("COMPLETE"),
            "evidence still renders"
        );
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("interrupted by SIGINT"),
            "interruption named"
        );
    }

    #[test]
    fn finish_with_pid_filter_hides_mismatch_and_tallies() {
        // P6-N3: the production watch path applies the submitter
        // filter post-ingestion — the mismatched who row hides, the
        // FILTER line tallies exactly. Fixture tids: 4243 (python3)
        // and 13 (bash).
        let filter = FilterArgs {
            pid: Some(4243),
            uid: None,
            comm: None,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_watch(Ok(watch_fixture()), &filter, &mut stdout, &mut stderr);
        assert_eq!(code, 0);
        let text = String::from_utf8(stdout).expect("utf-8");
        assert!(
            text.contains("FILTER admitted=1 filtered=1 unknown=0"),
            "exact FILTER line:\n{text}"
        );
        assert!(text.contains("python3"), "admitted row renders:\n{text}");
        assert!(
            !text.contains("bash"),
            "filtered-out row hides (comm + pcomm):\n{text}"
        );
    }

    #[test]
    fn finish_without_filter_renders_everything() {
        // Inactive filter: no FILTER line, both who rows render.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_watch(
            Ok(watch_fixture()),
            &FilterArgs::default(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(stdout).expect("utf-8");
        assert!(
            !text.contains("FILTER admitted="),
            "no FILTER line:\n{text}"
        );
        assert!(
            text.contains("python3") && text.contains("bash"),
            "both rows:\n{text}"
        );
    }
}
