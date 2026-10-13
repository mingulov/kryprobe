// SPDX-License-Identifier: GPL-3.0-or-later
//! `check --system`: one live capture evaluated against an explicit
//! policy (exit 10 violation, 0 clean, 3 inconclusive, 4 unusable,
//! 2 bad policy/args, 1 internal).
//!
//! The policy file reads and parses BEFORE capture: bad policy is a
//! usage error (exit 2) even on an unusable lane. The human verdict
//! line goes to stdout; the violation detail (algorithm/driver/
//! context/evidence, kp2 §13 row 12) and gap dims go to stderr.

use crate::live::{DEFAULT_TICK_MS, LiveConfig, LiveError, LiveOutcome, run_live_capture};
use crate::workload::{
    WorkloadFinishOpts, finish_workload_report, observations_for_rows, precheck_metadata_file,
};
use kryprobe_policy::workload::{CaptureIntegrity, ScopedRow, ScopedVerdict, evaluate_scoped};
use kryprobe_policy::{Policy, evaluate, parse_policy};
use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;
use kryprobe_report::workload::GroupBy;
use std::io::{Read, Write};
use std::path::Path;

/// Default live window when `--duration` is absent (report idiom).
const DEFAULT_CHECK_SECS: u64 = 60;

/// Live window: explicit `--duration` or the 60s default.
fn check_window_secs(duration: Option<u64>) -> u64 {
    duration.unwrap_or(DEFAULT_CHECK_SECS)
}

/// Maximum policy file accepted (M-SEC-02): unbounded reads are a
/// local memory-exhaustion vector (the policy crate caps again at
/// parse; both agree on 64 KiB).
const MAX_POLICY_FILE_BYTES: usize = 64 * 1024;

/// Reads a policy file with a hard cap (the token-worker `take(+1)`
/// probe idiom): over-cap refuses with a size error, never parses.
fn read_policy_capped(policy: &Path) -> Result<String, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(policy)
        .and_then(|f| {
            f.take(MAX_POLICY_FILE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| ())
        })
        .map_err(|err| format!("check: cannot read policy {}: {err}", policy.display()))?;
    if bytes.len() > MAX_POLICY_FILE_BYTES {
        return Err(format!(
            "check: policy {} too large ({} bytes, max {MAX_POLICY_FILE_BYTES})",
            policy.display(),
            bytes.len()
        ));
    }
    String::from_utf8(bytes)
        .map_err(|err| format!("check: cannot read policy {}: {err}", policy.display()))
}

/// Finishes a capture against a parsed policy: the verdict line to
/// stdout, detail to stderr; 10/0/3 on the verdict, 4/1 on
/// [`LiveError`] via [`LiveError::exit_code`]. The verdict mapping
/// itself lives in [`crate::verdict`] (1B-M8).
fn finish_check(
    result: Result<LiveOutcome, LiveError>,
    policy: &Policy,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(err) => {
            let _ = writeln!(stderr, "check: {err}");
            return err.exit_code();
        }
    };
    let rendered = crate::verdict::render_check_verdict(
        evaluate(policy, &outcome.observations, &outcome.coverage),
        &outcome.coverage,
    );
    let _ = write!(stdout, "{}", rendered.stdout);
    let _ = write!(stderr, "{}", rendered.stderr);
    // 4B-M5: an interrupted window is partial evidence — exit 3 —
    // unless the verdict already fired (10 wins: a violation on a
    // cut-short window is still a violation).
    if outcome.interrupted && rendered.code == 0 {
        let _ = writeln!(stderr, "check: interrupted by SIGINT — partial window");
        3
    } else {
        rendered.code
    }
}

/// Runs `check --system`: parse the policy (exit 2 on any rejection),
/// then one bounded capture (default 60s) evaluated once — or the
/// cgroup-scoped verdict over the typed workload report when
/// `--filter-cgroup-id` selects a scope.
#[allow(clippy::too_many_arguments)]
pub fn run(
    source: &str,
    duration: Option<u64>,
    policy: &Path,
    token: Option<&Path>,
    profile: LifecycleProfile,
    filter_cgroup_id: Option<u64>,
    workload_metadata: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // 4B-M5: SIGINT finalizes and evaluates the partial window (exit 3
    // unless the verdict fired), with a per-tick stderr progress line.
    let text = match read_policy_capped(policy) {
        Ok(text) => text,
        Err(detail) => {
            let _ = writeln!(stderr, "{detail}");
            return 2;
        }
    };
    let policy = match parse_policy(&text) {
        Ok(policy) => policy,
        Err(err) => {
            let _ = writeln!(stderr, "check: invalid policy {}: {err}", policy.display());
            return 2;
        }
    };
    // The argument layer refuses metadata without a scope; direct
    // callers get the same refusal (never a silent downgrade).
    if workload_metadata.is_some() && filter_cgroup_id.is_none() {
        let _ = writeln!(
            stderr,
            "check: --workload-metadata needs --filter-cgroup-id (system-wide checks take no metadata)"
        );
        return 2;
    }
    if let Some(path) = workload_metadata
        && let Err(code) = precheck_metadata_file("check", path, stderr)
    {
        return code;
    }
    let cfg = LiveConfig {
        source: source.to_owned(),
        duration_secs: Some(check_window_secs(duration)),
        tick_ms: DEFAULT_TICK_MS,
        token: token.map(Path::to_owned),
        json_audit: false,
        profile,
        workload: filter_cgroup_id.is_some(),
    };
    let outcome = run_live_capture(&cfg, &crate::runtime_facts::live_runtime());
    match filter_cgroup_id {
        Some(id) => {
            let opts = WorkloadFinishOpts {
                group_by: GroupBy::None,
                filter_cgroup_id: Some(id),
                metadata_file: workload_metadata.map(Path::to_owned),
                profile: profile.as_str().to_owned(),
            };
            finish_check_scoped(outcome, &policy, id, &opts, stdout, stderr)
        }
        None => finish_check(outcome, &policy, stdout, stderr),
    }
}

/// Finishes a cgroup-scoped check: serve metadata (bounded,
/// post-capture), assemble the typed report, evaluate the policy over
/// exactly the report rows (one population, two views), render the
/// scoped verdict. The stdout verdict mirrors the system-wide shape;
/// the exact scoped partition always rides stderr (a clean verdict
/// over an empty selection must say so).
fn finish_check_scoped(
    result: Result<LiveOutcome, LiveError>,
    policy: &Policy,
    filter_cgroup_id: u64,
    opts: &WorkloadFinishOpts,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(err) => {
            let _ = writeln!(stderr, "check: {err}");
            return err.exit_code();
        }
    };
    let finished = match finish_workload_report(&outcome, opts) {
        Ok(finished) => finished,
        Err(err) => {
            let _ = writeln!(stderr, "check: {err}");
            return 1;
        }
    };
    // The capture ran (LiveError mapped above), so integrity reads
    // the report ledger: an unreconciled gap voids clean, a proven
    // ledger keeps it.
    let integrity = if finished.report.ledger.gap_unreconciled {
        CaptureIntegrity::Partial
    } else {
        CaptureIntegrity::Complete
    };
    // The assembly above already validated this same id (a 0
    // refuses there first), so this construction cannot fail after a
    // successful finish — the arm is defensive (direct-API contract
    // violations are internal; the argument layer owns exit 2).
    let selector = match kryprobe_policy::workload::WorkloadSelector::cgroup(filter_cgroup_id) {
        Ok(selector) => selector,
        Err(err) => {
            let _ = writeln!(stderr, "check: {err}");
            return 1;
        }
    };
    let observations = match observations_for_rows(&finished.rows, &outcome.observations) {
        Ok(observations) => observations,
        Err(err) => {
            let _ = writeln!(stderr, "check: {err}");
            return 1;
        }
    };
    let scoped: Vec<ScopedRow<'_>> = finished
        .rows
        .iter()
        .zip(observations.iter())
        .map(|(row, observation)| ScopedRow {
            calls: row.calls,
            context: row.context,
            identity: row.identity.clone(),
            evidence: row.evidence.clone(),
            observation,
        })
        .collect();
    let verdict = match evaluate_scoped(policy, &selector, &scoped, integrity) {
        Ok(verdict) => verdict,
        Err(err) => {
            let _ = writeln!(stderr, "check: {err}");
            return err.exit_intent();
        }
    };
    render_scoped_verdict(&verdict, outcome.interrupted, stdout, stderr)
}

/// Renders one scoped verdict: the stdout line mirrors the
/// system-wide shape (VIOLATION/CLEAN/INCONCLUSIVE), the violation
/// detail and the exact scoped partition ride stderr. An interrupted
/// window keeps a confirmed violation (10) and degrades anything
/// else to 3 — a cut window never cleans.
fn render_scoped_verdict(
    verdict: &ScopedVerdict<'_>,
    interrupted: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let partition = match verdict {
        ScopedVerdict::Violation { partition, .. }
        | ScopedVerdict::Clean { partition }
        | ScopedVerdict::Inconclusive { partition, .. } => partition,
    };
    let partition_line = format!(
        "check: scoped partition matched={} nonmatched={} unknown_match={}",
        partition.matched(),
        partition.nonmatched(),
        partition.unknown_match()
    );
    match verdict {
        ScopedVerdict::Violation {
            rule,
            obs_ids,
            algorithm,
            driver,
            context,
            evidence,
            ..
        } => {
            let ids = obs_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                stdout,
                "VIOLATION rule={rule} observations={}",
                obs_ids.len()
            );
            let _ = writeln!(
                stderr,
                "check: violation rule={rule} matched={} algorithm={algorithm} driver={driver} context={context} evidence=obs[{ids}]",
                obs_ids.len()
            );
            if let Some(first) = evidence.first() {
                let _ = writeln!(stderr, "check: evidence: {}", first.backend_payload);
            }
            let _ = writeln!(stderr, "{partition_line}");
            10
        }
        ScopedVerdict::Clean { .. } => {
            if interrupted {
                let _ = writeln!(stderr, "check: interrupted by SIGINT — partial window");
                let _ = writeln!(stdout, "INCONCLUSIVE missing=interrupted-window");
                let _ = writeln!(stderr, "{partition_line}");
                3
            } else {
                let _ = writeln!(stdout, "CLEAN");
                let _ = writeln!(stderr, "{partition_line}");
                0
            }
        }
        ScopedVerdict::Inconclusive { missing, .. } => {
            let _ = writeln!(stdout, "INCONCLUSIVE missing={}", missing.join(","));
            let _ = writeln!(stderr, "check: inconclusive: {}", missing.join(","));
            let _ = writeln!(stderr, "{partition_line}");
            3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_watch::fixtures::*;

    fn deny_md5() -> Policy {
        parse_policy(
            "version: 1\nrules:\n  - id: no-kernel-md5\n    source: kernel-crypto\n    match:\n      stage: executed\n      algorithm: md5\n    decision: deny\n",
        )
        .expect("deny-md5 parses")
    }

    fn clean_policy() -> Policy {
        parse_policy(
            "version: 1\nrules:\n  - id: no-such-alg\n    source: kernel-crypto\n    match:\n      stage: executed\n      algorithm: no-such-alg-zzz\n    decision: deny\n",
        )
        .expect("clean policy parses")
    }

    fn md5_outcome() -> LiveOutcome {
        outcome_with(
            vec![
                agg_obs(
                    1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 3, 300, 3, 0, 0,
                ),
                agg_obs(
                    2,
                    "shash",
                    "digest",
                    "ok",
                    "md5",
                    "md5-generic",
                    "kthread",
                    20,
                    320,
                    20,
                    0,
                    0,
                ),
                totals_obs(3, 23, 620, 23, 0, 0),
            ],
            healthy_coverage(3),
        )
    }

    #[test]
    fn policy_read_refuses_oversize() {
        // M-SEC-02: unbounded policy reads are a local
        // memory-exhaustion vector — over 64 KiB refuses with a size
        // error, never parses.
        let scratch = kryprobe_testkit::TempDir::named("k4-oversize").expect("scratch dir");
        let file = scratch.path().join("huge.yaml");
        std::fs::write(&file, "x".repeat(64 * 1024 + 1)).expect("write input");
        let err = read_policy_capped(&file).expect_err("oversize refused");
        assert!(err.contains("too large"), "size error, got: {err}");
    }

    #[test]
    fn check_window_defaults_to_60s() {
        assert_eq!(check_window_secs(None), 60);
        assert_eq!(check_window_secs(Some(2)), 2);
    }

    #[test]
    fn check_finish_violation_exit10() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check(Ok(md5_outcome()), &deny_md5(), &mut stdout, &mut stderr);
        assert_eq!(code, 10);
        let stdout = String::from_utf8(stdout).expect("utf-8");
        assert_eq!(stdout, "VIOLATION rule=no-kernel-md5 observations=1\n");
        let stderr = String::from_utf8(stderr).expect("utf-8");
        // kp2 §13 row 12: the detail names algorithm/driver/context/evidence.
        for marker in [
            "algorithm='md5'",
            "driver='md5-generic'",
            "context='kthread'",
            "evidence=obs[observation:2]",
        ] {
            assert!(stderr.contains(marker), "missing {marker}: {stderr}");
        }
        // Lossless evidence: the second line is the matched observation.
        let evidence = stderr
            .lines()
            .find(|line| line.starts_with("check: evidence: "))
            .expect("evidence line");
        let doc: serde_json::Value =
            serde_json::from_str(evidence.strip_prefix("check: evidence: ").expect("prefix"))
                .expect("evidence json parses");
        assert_eq!(doc["backend_payload"]["algorithm"], "md5");
        assert_eq!(doc["id"], "observation:2");
    }

    #[test]
    fn check_finish_clean_exit0() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check(Ok(md5_outcome()), &clean_policy(), &mut stdout, &mut stderr);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8(stdout).expect("utf-8"), "CLEAN\n");
        assert!(stderr.is_empty(), "clean stays quiet");
    }

    #[test]
    fn check_finish_inconclusive_exit3() {
        // Forced gap: gapped coverage + a matching-nothing policy.
        let outcome = outcome_with(
            vec![
                agg_obs(
                    1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 3, 300, 3, 0, 0,
                ),
                totals_obs(2, 10, 1000, 10, 0, 0),
            ],
            gapped_coverage(),
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check(Ok(outcome), &clean_policy(), &mut stdout, &mut stderr);
        assert_eq!(code, 3);
        assert_eq!(
            String::from_utf8(stdout).expect("utf-8"),
            "INCONCLUSIVE missing=attach,capture-integrity\n"
        );
        let stderr = String::from_utf8(stderr).expect("utf-8");
        assert!(
            stderr.contains("attach,capture-integrity"),
            "gap dims named: {stderr}"
        );
    }

    #[test]
    fn check_finish_violation_stands_over_gaps() {
        // Findings stand: a deny match exits 10 even when other
        // coverage is partial (engine verdict, CLI mapping).
        let mut outcome = md5_outcome();
        outcome.coverage = gapped_coverage();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check(Ok(outcome), &deny_md5(), &mut stdout, &mut stderr);
        assert_eq!(code, 10);
    }

    #[test]
    fn check_finish_interrupted_clean_becomes_3_violation_stands() {
        // 4B-M5: an interrupted clean verdict degrades to 3, but a
        // violation on a cut-short window is still a violation (10).
        let mut clean = md5_outcome();
        clean.interrupted = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check(Ok(clean), &clean_policy(), &mut stdout, &mut stderr);
        assert_eq!(code, 3);
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("interrupted by SIGINT")
        );

        let mut violated = md5_outcome();
        violated.interrupted = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check(Ok(violated), &deny_md5(), &mut stdout, &mut stderr);
        assert_eq!(code, 10);
    }

    #[test]
    fn check_finish_errors_map_4_and_1() {
        for (err, code) in [
            (LiveError::Unusable("gate".to_owned()), 4),
            (LiveError::Internal("boom".to_owned()), 1),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            assert_eq!(
                finish_check(Err(err), &clean_policy(), &mut stdout, &mut stderr),
                code
            );
            assert!(stdout.is_empty());
            assert!(String::from_utf8(stderr).expect("utf-8").contains("check:"));
        }
    }

    fn scoped_opts(filter_cgroup_id: u64) -> WorkloadFinishOpts {
        WorkloadFinishOpts {
            group_by: GroupBy::None,
            filter_cgroup_id: Some(filter_cgroup_id),
            metadata_file: None,
            profile: "api-returns".to_owned(),
        }
    }

    #[test]
    fn scoped_violation_stands_despite_gaps() {
        // M1: the md5 row at cgroup 43 definitely matches the
        // deny rule — exit 10 even though the ledger is gapped
        // (spec §5.6: a proven matching violation stands).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(workload_outcome()),
            &deny_md5(),
            43,
            &scoped_opts(43),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 10);
        assert_eq!(
            String::from_utf8(stdout).expect("utf-8"),
            "VIOLATION rule=no-kernel-md5 observations=1\n"
        );
        let err_text = String::from_utf8(stderr).expect("utf-8");
        assert!(
            err_text.contains("algorithm=md5") && err_text.contains("evidence=obs["),
            "violation detail: {err_text:?}"
        );
        assert!(
            err_text.contains("scoped partition matched=10 nonmatched=20 unknown_match=0"),
            "exact partition: {err_text:?}"
        );
    }

    #[test]
    fn scoped_violation_renders_row_scoped_evidence() {
        // SEM04 render pin: one aggregate template (calls=100,
        // bytes=409600) shared by two contexts; the deny rule matches
        // algorithm + uid 1234, so only the 5-call row convicts — and
        // the printed evidence shows that row's 5 calls with its event
        // context, never the system-wide counts under uid 1234.
        use crate::workload::JoinedRow;
        use kryprobe_core::workload::{ContextIdentity, ExecutionKind, MetadataUnavailable};
        let mut template = agg_obs(
            1, "skcipher", "encrypt", "ok", "cbc(aes)", "aesni", "process", 100, 409600, 100, 0, 2,
        );
        template.backend_payload["key_hash"] = serde_json::json!(7u64);
        let row = |cgroup: u64, tgid: u32, uid: u32, calls: u64| JoinedRow {
            context: ContextIdentity::new(7, cgroup, tgid, uid, 555, ExecutionKind::Proc),
            calls,
            native: workload_native("cbc(aes)", Some("aesni")),
        };
        let mut outcome = outcome_with(vec![template], healthy_coverage(1));
        outcome.workload_capture = Some(workload_capture(
            vec![row(42, 1000, 1234, 5), row(43, 1001, 1000, 95)],
            100,
        ));
        outcome.workload_preflight = Some(workload_preflight_unavailable(
            MetadataUnavailable::NoPrincipal,
        ));
        let policy = parse_policy(
            "version: 1\nrules:\n  - id: no-uid-cbc\n    source: kernel-crypto\n    match:\n      stage: executed\n      algorithm: cbc(aes)\n      uid: 1234\n    decision: deny\n",
        )
        .expect("deny parses");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(outcome),
            &policy,
            42,
            &scoped_opts(42),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 10);
        assert_eq!(
            String::from_utf8(stdout).expect("utf-8"),
            "VIOLATION rule=no-uid-cbc observations=1\n"
        );
        let err_text = String::from_utf8(stderr).expect("utf-8");
        assert!(
            err_text.contains("scoped partition matched=5 nonmatched=95 unknown_match=0"),
            "exact partition: {err_text:?}"
        );
        let evidence = err_text
            .lines()
            .find(|line| line.starts_with("check: evidence: "))
            .expect("evidence line");
        let doc: serde_json::Value =
            serde_json::from_str(evidence.strip_prefix("check: evidence: ").expect("prefix"))
                .expect("evidence json parses");
        assert_eq!(doc["counts"]["calls"], serde_json::json!(5), "{doc}");
        assert_eq!(doc["uid"], serde_json::json!(1234), "{doc}");
        assert_eq!(doc["event"]["cgroup"], serde_json::json!(42), "{doc}");
        assert_eq!(doc["evidence_scope"], serde_json::json!("row"), "{doc}");
        for key in ["bytes", "lat", "window", "ok", "errors", "queued"] {
            assert!(doc.get(key).is_none(), "system-only `{key}` omitted: {doc}");
        }
    }

    #[test]
    fn scoped_unknown_match_voids_clean() {
        // M1: 5 calls sit at cgroup 0 (unknown whether they belong
        // to cgroup 43) — no violation, but clean is unproven (3).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(workload_outcome_with_unknown()),
            &clean_policy(),
            43,
            &scoped_opts(43),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
        let out_text = String::from_utf8(stdout).expect("utf-8");
        assert!(
            out_text.contains("unknown-match") && out_text.contains("capture-gap"),
            "missing names both gaps: {out_text:?}"
        );
        let err_text = String::from_utf8(stderr).expect("utf-8");
        assert!(
            err_text.contains("scoped partition matched=10 nonmatched=20 unknown_match=5"),
            "exact partition: {err_text:?}"
        );
    }

    #[test]
    fn scoped_gap_without_violation_is_inconclusive() {
        // M1: no deny matches, but the unreconciled ledger gap could
        // hide the cgroup's calls — clean is unproven (3).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(workload_outcome()),
            &clean_policy(),
            43,
            &scoped_opts(43),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
        assert_eq!(
            String::from_utf8(stdout).expect("utf-8"),
            "INCONCLUSIVE missing=capture-gap\n"
        );
    }

    #[test]
    fn scoped_clean_over_empty_selection_says_so() {
        // M1: cgroup 99 captures nothing and no deny matches — the
        // verdict still cannot be clean (capture gap), and the
        // partition line shows the empty selection.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(workload_outcome()),
            &clean_policy(),
            99,
            &scoped_opts(99),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
        let err_text = String::from_utf8(stderr).expect("utf-8");
        assert!(
            err_text.contains("scoped partition matched=0 nonmatched=30 unknown_match=0"),
            "empty selection visible: {err_text:?}"
        );
    }

    #[test]
    fn scoped_interrupted_keeps_violation_degrades_rest() {
        // A confirmed violation stands on a cut window (10);
        // anything else degrades to 3 (a cut window never cleans).
        let mut violated = workload_outcome();
        violated.interrupted = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(violated),
            &deny_md5(),
            43,
            &scoped_opts(43),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 10);

        let mut inconclusive = workload_outcome();
        inconclusive.interrupted = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(inconclusive),
            &clean_policy(),
            43,
            &scoped_opts(43),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
    }

    #[test]
    fn scoped_render_shapes_mirror_system_wide() {
        use kryprobe_core::workload::ScopePartition;
        use kryprobe_policy::workload::ScopedVerdict;
        // Direct render tests (live scoped checks always carry the
        // ledger gap, so Clean only renders here — the shape still
        // pins byte-exact for the day the fence proves out).
        let partition = ScopePartition::from_counts(10, 20, 0).expect("partition");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = render_scoped_verdict(
            &ScopedVerdict::Clean { partition },
            false,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8(stdout).expect("utf-8"), "CLEAN\n");
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("scoped partition matched=10 nonmatched=20 unknown_match=0")
        );
        // Interrupted clean degrades (a cut window never cleans).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = render_scoped_verdict(
            &ScopedVerdict::Clean { partition },
            true,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 3);
        assert_eq!(
            String::from_utf8(stdout).expect("utf-8"),
            "INCONCLUSIVE missing=interrupted-window\n"
        );
    }

    #[test]
    fn scoped_refusals_map_2_and_1() {
        // Direct-API refusals (the argument layer owns exit 2 for
        // these): cgroup 0 is not selectable (internal here — the
        // assembly refuses it first), a missing capture is internal
        // (1), metadata without a scope is usage (2).
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(workload_outcome()),
            &deny_md5(),
            0,
            &scoped_opts(0),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = finish_check_scoped(
            Ok(md5_outcome()),
            &deny_md5(),
            43,
            &scoped_opts(43),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);

        let scratch = kryprobe_testkit::TempDir::named("check-meta-scope").expect("scratch");
        let policy_path = scratch.path().join("p.yaml");
        std::fs::write(&policy_path, "version: 1\nrules: []\n").expect("policy");
        let meta_path = scratch.path().join("m.json");
        std::fs::write(&meta_path, "{}").expect("metadata");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            "kernel-crypto",
            Some(60),
            &policy_path,
            None,
            kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
            None,
            Some(&meta_path),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 2);
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("--workload-metadata needs --filter-cgroup-id")
        );
    }
}
