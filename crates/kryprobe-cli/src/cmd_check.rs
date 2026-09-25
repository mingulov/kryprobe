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
use kryprobe_policy::{Policy, evaluate, parse_policy};
use kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile;
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
/// then one bounded capture (default 60s) evaluated once.
pub fn run(
    source: &str,
    duration: Option<u64>,
    policy: &Path,
    token: Option<&Path>,
    profile: LifecycleProfile,
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
    let cfg = LiveConfig {
        source: source.to_owned(),
        duration_secs: Some(check_window_secs(duration)),
        tick_ms: DEFAULT_TICK_MS,
        token: token.map(Path::to_owned),
        json_audit: false,
        profile,
    };
    finish_check(
        run_live_capture(&cfg, &crate::runtime_facts::live_runtime()),
        &policy,
        stdout,
        stderr,
    )
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
}
