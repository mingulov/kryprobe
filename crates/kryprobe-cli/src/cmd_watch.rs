// SPDX-License-Identifier: GPL-3.0-or-later
//! `watch --system`: one live capture rendered as aggregated human tables.
//!
//! One blocking [`run_live_capture`](crate::live::run_live_capture) per
//! invocation, then one render: the per-tick snapshots repeat agg/totals
//! rows with cumulative counters, so the table keeps the latest
//! observation per full row key and sums across result classes and
//! contexts. `report --system` (human) renders these same tables via
//! [`render_watch_tables`]; only the exit code differs (watch exits 0 on
//! any completed capture, report exits 0/3 on the verdict).

use crate::live::{DEFAULT_TICK_MS, LiveConfig, LiveError, LiveOutcome, run_live_capture};
use kryprobe_core::capability::RuntimeCapabilities;
use kryprobe_core::enums::CoverageStatus;
use kryprobe_core::evidence::{CoverageSummary, NativeObservation};
use kryprobe_privilege::probe::{
    ProbeOutcome, attach_cookies, btf_present, cap_names, ringbuf_create, uprobe_multi_link_self,
    userns_create,
};
use std::collections::BTreeMap;
use std::io::Write;

/// Exact table header (brief-exact column set).
const HEADER: &str = "FAMILY OP ALGORITHM DRIVER CALLS BYTES OK QUEUED ERRORS";

/// Accumulated counters for one rendered row.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Acc {
    calls: u64,
    bytes: u64,
    ok: u64,
    queued: u64,
    errors: u64,
}

impl Acc {
    /// Field-wise saturating sum (counters never wrap, never panic).
    fn add(&mut self, other: Acc) {
        self.calls = self.calls.saturating_add(other.calls);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.ok = self.ok.saturating_add(other.ok);
        self.queued = self.queued.saturating_add(other.queued);
        self.errors = self.errors.saturating_add(other.errors);
    }
}

/// Raw payload string (empty when missing or not a string).
fn raw<'a>(payload: &'a serde_json::Value, key: &str) -> &'a str {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

/// Rendered cell: missing or empty renders `unknown` (C10 — zeros and
/// unknowns render as unknown, never fabricated).
fn show(cell: &str) -> &str {
    if cell.is_empty() { "unknown" } else { cell }
}

/// One `counts` sub-counter (0 when the shape is absent — real decodes
/// always carry it; only hand-fed shapes can miss it).
fn count(payload: &serde_json::Value, key: &str) -> u64 {
    payload
        .get("counts")
        .and_then(|counts| counts.get(key))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn acc_of(obs: &NativeObservation) -> Acc {
    let payload = &obs.backend_payload;
    Acc {
        calls: count(payload, "calls"),
        bytes: payload
            .get("bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        ok: count(payload, "ok"),
        queued: count(payload, "queued"),
        errors: count(payload, "errors"),
    }
}

/// Full row key: the KAGG identity the payload mirrors
/// (family, op, result, algorithm, driver, context).
fn row_key(obs: &NativeObservation) -> (&str, &str, &str, &str, &str, &str) {
    let payload = &obs.backend_payload;
    (
        raw(payload, "family"),
        raw(payload, "op"),
        raw(payload, "result"),
        raw(payload, "algorithm"),
        raw(payload, "driver"),
        raw(payload, "context"),
    )
}

/// kp2 §8 trailer dimensions in kp2 order: `attach` (attachment,
/// object_discovery), `operation` (target_population — the observed op
/// surface), `capture-integrity` (aggregate_counts, detailed_events),
/// `completion` (completion — the closed window attests temporal
/// coverage, so `temporal` is never emitted alone), `attribution`
/// (attribution), `correlation` (passthrough — no kp2 §8 counterpart).
/// Empty ⟺ every dimension complete (interval end with the contract held
/// is COMPLETE, never PARTIAL).
#[must_use]
pub fn trailer_dims(coverage: &CoverageSummary) -> Vec<&'static str> {
    let weak = |status: CoverageStatus| status != CoverageStatus::CompleteForDeclaredBoundary;
    let mut dims = Vec::new();
    if weak(coverage.attachment.status) || weak(coverage.object_discovery.status) {
        dims.push("attach");
    }
    if weak(coverage.target_population.status) {
        dims.push("operation");
    }
    if weak(coverage.aggregate_counts.status) || weak(coverage.detailed_events.status) {
        dims.push("capture-integrity");
    }
    if weak(coverage.completion.status) {
        dims.push("completion");
    }
    if weak(coverage.attribution.status) {
        dims.push("attribution");
    }
    if weak(coverage.correlation.status) {
        dims.push("correlation");
    }
    dims
}

/// Renders one outcome: header + one row per
/// (family, op, algorithm, driver) + `TOTAL` + the `COMPLETE` /
/// `PARTIAL: <dims>` trailer. Latest wins per full row key (cumulative
/// snapshots), then classes/contexts sum; idents never render as rows;
/// `TOTAL` comes from the latest totals carrier (column sums when totals
/// are absent — the coverage trailer separately attests the gap).
#[must_use]
pub fn render_watch_tables(outcome: &LiveOutcome) -> String {
    let mut latest: BTreeMap<(&str, &str, &str, &str, &str, &str), Acc> = BTreeMap::new();
    for obs in &outcome.observations {
        if obs
            .backend_payload
            .get("row")
            .and_then(serde_json::Value::as_str)
            != Some("agg")
        {
            continue;
        }
        latest.insert(row_key(obs), acc_of(obs));
    }
    let mut rows: BTreeMap<(&str, &str, &str, &str), Acc> = BTreeMap::new();
    for ((family, op, _, algorithm, driver, _), acc) in latest {
        rows.entry((family, op, algorithm, driver))
            .or_default()
            .add(acc);
    }
    let mut text = String::from(HEADER);
    text.push('\n');
    for ((family, op, algorithm, driver), acc) in &rows {
        text.push_str(&format!(
            "{} {} {} {} {} {} {} {} {}\n",
            show(family),
            show(op),
            show(algorithm),
            show(driver),
            acc.calls,
            acc.bytes,
            acc.ok,
            acc.queued,
            acc.errors
        ));
    }
    let totals = outcome
        .observations
        .iter()
        .rev()
        .find(|obs| {
            obs.backend_payload
                .get("row")
                .and_then(serde_json::Value::as_str)
                == Some("totals")
        })
        .map(acc_of)
        .unwrap_or_else(|| {
            rows.values().fold(Acc::default(), |mut total, acc| {
                total.add(*acc);
                total
            })
        });
    text.push_str(&format!(
        "TOTAL - - - {} {} {} {} {}\n",
        totals.calls, totals.bytes, totals.ok, totals.queued, totals.errors
    ));
    let dims = trailer_dims(&outcome.coverage);
    if dims.is_empty() {
        text.push_str("COMPLETE\n");
    } else {
        text.push_str(&format!("PARTIAL: {}\n", dims.join(",")));
    }
    text
}

/// Kernel release context (`/proc` read; `unknown` when unreadable —
/// informational only, never a gate).
fn os_release() -> String {
    let text = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    if text.is_empty() {
        String::from("unknown")
    } else {
        text
    }
}

/// Yama scope context (informational only, never a gate; 0 when
/// unreadable — mirrors the fail-soft context reads).
fn yama_scope() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Effective caps from CapEff (mirrors the `cmd_doctor` helper, which is
/// outside this task's file budget so it cannot be shared).
fn effective_caps() -> Vec<String> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:")
            && let Ok(bits) = u64::from_str_radix(hex.trim(), 16)
        {
            return cap_names(bits);
        }
    }
    Vec::new()
}

/// Live host facts for the session gate: gate bools from the committed
/// privilege probes (`Pass` ⟺ present — probe details are human verdicts,
/// never parsed back), context from direct `/proc` reads. std-only
/// (ADR-0002 Rule B: no `libc::` in the CLI crate).
pub(crate) fn live_runtime() -> RuntimeCapabilities {
    let pass = |outcome: ProbeOutcome| matches!(outcome, ProbeOutcome::Pass { .. });
    RuntimeCapabilities {
        kernel_release: os_release(),
        uprobe_multi: pass(uprobe_multi_link_self()),
        cookies: pass(attach_cookies()),
        ringbuf: pass(ringbuf_create()),
        btf_present: pass(btf_present()),
        userns: pass(userns_create()),
        yama_scope: yama_scope(),
        caps: effective_caps(),
    }
}

/// Finishes a capture: tables to stdout (exit 0) or the named failure to
/// stderr (`Unusable` → 4, `Internal` → 1 via [`LiveError::exit_code`]).
fn finish_watch(
    result: Result<LiveOutcome, LiveError>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match result {
        Ok(outcome) => {
            let _ = write!(stdout, "{}", render_watch_tables(&outcome));
            0
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
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // Ctrl-C keeps the default disposition and terminates the process:
    // no trailer, no finalize (Task 1 installs no SIGINT handler —
    // std-only). Graceful-shutdown-on-SIGINT is future work.
    let cfg = LiveConfig {
        source: source.to_owned(),
        duration_secs: duration,
        tick_ms: DEFAULT_TICK_MS,
    };
    finish_watch(run_live_capture(&cfg, &live_runtime()), stdout, stderr)
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
        ];
        outcome_with(observations, healthy_coverage(8))
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
        let observations = vec![agg_obs(
            1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 3, 300, 3, 0, 0,
        )];
        outcome_with(observations, healthy_coverage(1))
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use kryprobe_testkit::assert_golden;
    use std::path::PathBuf;

    fn golden(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/goldens")
            .join(name)
    }

    #[test]
    fn watch_golden_pins_complete_render() {
        assert_golden(
            &golden("watch.txt"),
            render_watch_tables(&watch_fixture()).as_bytes(),
        );
    }

    #[test]
    fn partial_golden_pins_gap_trailer() {
        // Report human renders these same tables; the golden pins the
        // PARTIAL trailer over the gapped fixture.
        assert_golden(
            &golden("report_partial.txt"),
            render_watch_tables(&partial_fixture()).as_bytes(),
        );
    }

    #[test]
    fn trailer_names_each_gap_in_kp2_order() {
        // Each dimension alone maps to its kp2 §8 token.
        let cases = [
            ("target_population", "operation"),
            ("object_discovery", "attach"),
            ("attachment", "attach"),
            ("aggregate_counts", "capture-integrity"),
            ("detailed_events", "capture-integrity"),
            ("attribution", "attribution"),
            ("correlation", "correlation"),
            ("completion", "completion"),
        ];
        for (field, token) in cases {
            let mut coverage = healthy_coverage(1);
            let dim = match field {
                "target_population" => &mut coverage.target_population,
                "object_discovery" => &mut coverage.object_discovery,
                "attachment" => &mut coverage.attachment,
                "aggregate_counts" => &mut coverage.aggregate_counts,
                "detailed_events" => &mut coverage.detailed_events,
                "attribution" => &mut coverage.attribution,
                "correlation" => &mut coverage.correlation,
                "completion" => &mut coverage.completion,
                _ => unreachable!("pinned field list"),
            };
            dim.status = CoverageStatus::Partial;
            assert_eq!(trailer_dims(&coverage), vec![token], "field {field}");
        }
        // Every non-complete status weakens (Unsupported/NotRun/Unknown
        // are gaps too, never COMPLETE).
        for status in [
            CoverageStatus::Partial,
            CoverageStatus::Unsupported,
            CoverageStatus::NotRun,
            CoverageStatus::Unknown,
        ] {
            let mut coverage = healthy_coverage(1);
            coverage.attachment.status = status;
            assert_eq!(
                trailer_dims(&coverage),
                vec!["attach"],
                "status {status:?} weakens"
            );
        }
        // Multi-gap order is the kp2 §8 order, deduped.
        let mut coverage = healthy_coverage(1);
        coverage.completion.status = CoverageStatus::Partial;
        coverage.attachment.status = CoverageStatus::Partial;
        coverage.aggregate_counts.status = CoverageStatus::Partial;
        coverage.correlation.status = CoverageStatus::Unknown;
        assert_eq!(
            trailer_dims(&coverage),
            vec!["attach", "capture-integrity", "completion", "correlation"]
        );
        // Contract held (incl. interval end) is COMPLETE.
        assert!(trailer_dims(&healthy_coverage(1)).is_empty());
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
        let text = render_watch_tables(&outcome_with(observations, healthy_coverage(3)));
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
        let text = render_watch_tables(&outcome_with(observations, healthy_coverage(2)));
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
        let text = render_watch_tables(&outcome_with(vec![obs], healthy_coverage(1)));
        assert!(
            text.contains("skcipher encrypt unknown unknown 3 30 3 0 0\n"),
            "{text:?}"
        );
    }

    #[test]
    fn finish_maps_outcome_and_errors() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_watch(Ok(watch_fixture()), &mut stdout, &mut stderr);
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

    #[test]
    fn live_runtime_reports_without_privilege() {
        // Shape smoke: always runs, release never empty.
        let runtime = live_runtime();
        assert!(!runtime.kernel_release.is_empty());
    }
}
