// SPDX-License-Identifier: GPL-3.0-or-later
//! P6/T11 views suite: task-lifetime contexts, filters, aggregates,
//! lifecycle session streaming, and subcommand help.
//!
//! RED-first: these tests name the P6 contract (task record items 2–6,
//! tests plan `kcrypto_views` row). Unprivileged and hermetic, except
//! `proc_start_marker_reads_own_lifetime`, which reads only the test's
//! own `/proc/self` (no fixture, no VM).

use kryprobe_cli::args::{ArgsError, parse};
use kryprobe_privilege::kcrypto_context::{
    CompletionContext, ExecutionKind, ExecutionContext, FilterVerdict, Histogram, LifetimeVerdict,
    OriginClaim, RequestContext, StackMarker, SubmitterContext, TaskLifetime, UnknownPolicy,
    apply_filter, read_start_marker,
};
use kryprobe_report::{SessionWriter, validate_lifecycle_session};

fn argv(words: &[&str]) -> Vec<String> {
    std::iter::once("kryprobe")
        .chain(words.iter().copied())
        .map(str::to_owned)
        .collect()
}

/// Runs `kryprobe …` through the library shell, capturing both streams.
fn run(words: &[&str]) -> (i32, String, String) {
    let argv = argv(words);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = kryprobe_cli::run(&argv, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).expect("stdout utf-8"),
        String::from_utf8(stderr).expect("stderr utf-8"),
    )
}

fn lifetime(pid: u32, marker: Option<u64>) -> TaskLifetime {
    TaskLifetime {
        pid,
        tgid: pid,
        start_marker: marker,
    }
}

fn submitter(pid: u32, marker: Option<u64>) -> SubmitterContext {
    SubmitterContext {
        lifetime: lifetime(pid, marker),
        comm: Some("fixture".to_owned()),
        uid: Some(1000),
        cgroup: Some(7),
        ppid: Some(1),
        stack: StackMarker::Full,
    }
}

fn admitted_request() -> RequestContext {
    RequestContext {
        request_id: "req:1".to_owned(),
        submitter: Some(submitter(100, Some(50_000))),
        execution: ExecutionContext {
            kind: ExecutionKind::Process(lifetime(100, Some(50_000))),
        },
        completion: None,
        evidence_version: "evidence:p6-test".to_owned(),
        rule_version: "rule:p6-test".to_owned(),
        consumer_label: None,
    }
}

// ---------------------------------------------------------------------------
// C01: PID reuse is a new task lifetime.
// ---------------------------------------------------------------------------

#[test]
fn pid_reuse_is_a_new_task_lifetime() {
    // Same pid + same start marker: the same lifetime.
    let a = lifetime(100, Some(50_000));
    let b = lifetime(100, Some(50_000));
    assert_eq!(a.verdict_against(&b), LifetimeVerdict::Same);
    // Same pid + different start marker: reuse — a NEW lifetime, never
    // joined with the old one.
    let c = lifetime(100, Some(77_000));
    assert_eq!(a.verdict_against(&c), LifetimeVerdict::Reused);
    // Either marker missing: unqualified — never Same, never Reused,
    // always explicit Unknown.
    let d = lifetime(100, None);
    assert_eq!(a.verdict_against(&d), LifetimeVerdict::Unknown);
    assert_eq!(d.verdict_against(&d), LifetimeVerdict::Unknown);
    // Different pids never join, even with equal markers.
    let e = lifetime(101, Some(50_000));
    assert_eq!(a.verdict_against(&e), LifetimeVerdict::Unknown);
}

#[test]
fn proc_start_marker_reads_own_lifetime() {
    // The marker read is best-effort over /proc: our own pid has a
    // start time; a dead pid has none (never a panic, never a guess).
    let own = std::process::id();
    let marker = read_start_marker(own);
    assert!(
        marker.is_some_and(|m| m > 0),
        "own pid must have a nonzero start marker"
    );
    assert_eq!(read_start_marker(u32::MAX), None, "dead pid stays None");
}

// ---------------------------------------------------------------------------
// C02: rename/uid/cgroup change marks drift; the lifetime still keys on
// pid + start marker, never on the mutable fields.
// ---------------------------------------------------------------------------

#[test]
fn rename_uid_cgroup_change_marks_lifetime_drift() {
    let before = submitter(100, Some(50_000));
    let mut after = before.clone();
    after.comm = Some("renamed".to_owned());
    after.uid = Some(0);
    after.cgroup = Some(9);
    // Mutable fields moved but the lifetime key is unchanged: Same
    // lifetime WITH drift flags — the join holds, the change is loud.
    let drift = before.drift_against(&after);
    assert!(drift.same_lifetime, "pid+marker still join");
    assert!(drift.comm_changed, "rename is visible");
    assert!(drift.uid_changed, "uid change is visible");
    assert!(drift.cgroup_changed, "cgroup change is visible");
    // And the reverse: identical snapshots show no drift.
    let calm = before.drift_against(&before);
    assert!(calm.same_lifetime);
    assert!(!calm.comm_changed && !calm.uid_changed && !calm.cgroup_changed);
}

// ---------------------------------------------------------------------------
// C03: softirq on the interrupted task never names a user origin.
// ---------------------------------------------------------------------------

#[test]
fn softirq_is_not_interrupted_user_origin() {
    let interrupted = lifetime(100, Some(50_000));
    let exec = ExecutionContext {
        kind: ExecutionKind::SoftIrq {
            interrupted: Some(interrupted),
        },
    };
    // The interrupted task is recorded as context, but the origin claim
    // stays unavailable: softirq is not user origin.
    assert_eq!(exec.origin(), OriginClaim::Unavailable);
    assert!(
        exec.interrupted_task().is_some(),
        "interrupted task stays visible as context, not as origin"
    );
    // A plain process execution names its own lifetime as origin.
    let proc = ExecutionContext {
        kind: ExecutionKind::Process(lifetime(100, Some(50_000))),
    };
    assert_eq!(
        proc.origin(),
        OriginClaim::Proved(lifetime(100, Some(50_000)))
    );
}

// ---------------------------------------------------------------------------
// C04: worker submitter — worker PID/stack alone cannot establish the
// original user causality.
// ---------------------------------------------------------------------------

#[test]
fn worker_execution_needs_proved_handoff_for_origin() {
    // A worker execution with no handoff edge: origin unavailable.
    let lone = ExecutionContext {
        kind: ExecutionKind::Worker {
            worker: lifetime(7, Some(11)),
            handoff: None,
        },
    };
    assert_eq!(lone.origin(), OriginClaim::Unavailable);
    // The same worker WITH a proved handoff edge names the origin.
    let handed = ExecutionContext {
        kind: ExecutionKind::Worker {
            worker: lifetime(7, Some(11)),
            handoff: Some(lifetime(100, Some(50_000))),
        },
    };
    assert_eq!(
        handed.origin(),
        OriginClaim::Proved(lifetime(100, Some(50_000)))
    );
}

// ---------------------------------------------------------------------------
// O01: missing vs sampled stacks stay explicit.
// ---------------------------------------------------------------------------

#[test]
fn missing_and_sampled_stacks_stay_explicit() {
    let mut missing = submitter(100, Some(50_000));
    missing.stack = StackMarker::Missing;
    assert!(!missing.stack.has_frames(), "missing stack has no frames");
    assert_eq!(missing.stack.label(), "missing");

    let mut sampled = submitter(100, Some(50_000));
    sampled.stack = StackMarker::Sampled;
    assert!(
        sampled.stack.has_frames(),
        "sampled stack may carry frames"
    );
    assert_eq!(sampled.stack.label(), "sampled");
    assert_ne!(
        missing.stack.label(),
        sampled.stack.label(),
        "missing and sampled never collapse"
    );

    let full = submitter(100, Some(50_000));
    assert_eq!(full.stack.label(), "full");
}

// ---------------------------------------------------------------------------
// O02: completion on another worker under a submitter PID filter — the
// admitted completion follows its request.
// ---------------------------------------------------------------------------

#[test]
fn worker_completion_survives_submitter_filter() {
    let mut req = admitted_request();
    // Completion lands on another worker (pid 7), not the submitter.
    req.completion = Some(CompletionContext {
        landed: ExecutionContext {
            kind: ExecutionKind::Worker {
                worker: lifetime(7, Some(11)),
                handoff: Some(lifetime(100, Some(50_000))),
            },
        },
        follows_request: true,
    });
    // A submitter-pid filter naming the ORIGINAL submitter admits the
    // request; the completion follows even though pid 7 itself would
    // fail the filter.
    let filter = kryprobe_privilege::kcrypto_context::ContextFilter {
        submitter_pid: Some(100),
        unknown_policy: UnknownPolicy::Exclude,
        ..Default::default()
    };
    let verdict = apply_filter(&req, &filter);
    assert_eq!(
        verdict,
        FilterVerdict::Admitted,
        "admitted completion follows its request"
    );
    // Control: a filter naming nobody involved filters the request out.
    let other = kryprobe_privilege::kcrypto_context::ContextFilter {
        submitter_pid: Some(4242),
        unknown_policy: UnknownPolicy::Exclude,
        ..Default::default()
    };
    assert_eq!(apply_filter(&req, &other), FilterVerdict::FilteredOut);
}

// ---------------------------------------------------------------------------
// Unknown populations: never silently dropped.
// ---------------------------------------------------------------------------

#[test]
fn unknown_consumer_is_not_dropped_silently() {
    // A request whose submitter is entirely unknown, under a filter
    // that excludes unknowns: verdict Unknown (counted, visible), never
    // a silent drop and never Admitted-by-default.
    let mut req = admitted_request();
    req.submitter = None;
    let filter = kryprobe_privilege::kcrypto_context::ContextFilter {
        submitter_pid: Some(100),
        unknown_policy: UnknownPolicy::Exclude,
        ..Default::default()
    };
    assert_eq!(apply_filter(&req, &filter), FilterVerdict::Unknown);
    // Under the include-unknowns policy the same request is admitted —
    // the policy is explicit, per filter, never a global default smuggle.
    let include = kryprobe_privilege::kcrypto_context::ContextFilter {
        submitter_pid: Some(100),
        unknown_policy: UnknownPolicy::Include,
        ..Default::default()
    };
    assert_eq!(apply_filter(&req, &include), FilterVerdict::Admitted);
    // Filtered and unknown populations stay separate tallies.
    let mut tally = kryprobe_privilege::kcrypto_context::FilterTally::default();
    tally.record(FilterVerdict::Admitted);
    tally.record(FilterVerdict::FilteredOut);
    tally.record(FilterVerdict::Unknown);
    assert_eq!((tally.admitted, tally.filtered_out, tally.unknown), (1, 1, 1));
    assert_eq!(tally.total(), 3, "every verdict is accounted");
}

// ---------------------------------------------------------------------------
// Aggregates are independent of sampled details.
// ---------------------------------------------------------------------------

#[test]
fn sampled_detail_keeps_exact_aggregate_population() {
    // 10 observations enter the aggregate; only 3 detail rows render.
    let mut hist = Histogram::new("submit_bytes", "bytes", vec![64, 4096, 65536]);
    for _ in 0..10 {
        hist.observe(16);
    }
    assert_eq!(hist.samples(), 10, "aggregate sees the full population");
    let rendered = hist.render_with_cap(3);
    assert!(
        rendered.contains("samples=10"),
        "render names the exact population: {rendered}"
    );
    assert!(
        rendered.contains("details=3"),
        "render names the sampled detail count: {rendered}"
    );
    assert!(
        rendered.contains("mode=sampled"),
        "auto-aggregation announces its mode change: {rendered}"
    );
    // Uncapped render carries no mode-change announcement.
    let full = hist.render_with_cap(10);
    assert!(
        !full.contains("mode=sampled"),
        "no announcement without sampling: {full}"
    );
    // Named population, units, bounds, and counts all render.
    assert!(rendered.contains("submit_bytes"), "population name: {rendered}");
    assert!(rendered.contains("bytes"), "units: {rendered}");
}

// ---------------------------------------------------------------------------
// Streaming: unknown versions refuse; missing trailers cannot be clean.
// ---------------------------------------------------------------------------

fn session_fixture() -> String {
    let mut writer = SessionWriter::new("session:views");
    writer
        .session_start("request-lifecycle", "evidence:v1", "rule:v1")
        .expect("start emits");
    writer
        .observation(&serde_json::json!({
            "schema": "kryprobe.kcrypto.lifecycle/v1",
            "request_id": "fixture:req-1",
            "tfm_id": null,
            "terminal": "sync",
            "status": 0,
            "duration_ns": "120",
        }))
        .expect("valid observation emits");
    writer
        .receipt(true, 1, 1, 0)
        .expect("receipt emits");
    writer.into_string()
}

#[test]
fn unknown_stream_version_refuses() {
    // Control: the well-formed fixture validates clean.
    assert!(
        validate_lifecycle_session(&session_fixture()).is_empty(),
        "fixture must validate clean"
    );
    // A foreign-version record anywhere refuses the WHOLE stream.
    let evil = session_fixture().replacen(
        "kryprobe.kcrypto.lifecycle-session/v1",
        "kryprobe.kcrypto.lifecycle-session/v9",
        1,
    );
    let findings = validate_lifecycle_session(&evil);
    assert!(
        !findings.is_empty(),
        "foreign stream version must refuse, not parse"
    );
    // An embedded observation with a foreign payload version is a
    // stream defect too, not a silent skip.
    let evil_payload = session_fixture().replacen(
        "kryprobe.kcrypto.lifecycle/v1",
        "kryprobe.kcrypto.lifecycle/v9",
        1,
    );
    assert!(
        !validate_lifecycle_session(&evil_payload).is_empty(),
        "foreign payload version inside the envelope must refuse"
    );
}

#[test]
fn missing_terminal_trailer_cannot_be_clean() {
    // Strip the receipt: the stream is truncated — findings are nonempty
    // and no clean verdict is reachable.
    let mut lines: Vec<&str> = session_fixture().lines().collect();
    assert!(lines.len() >= 2, "fixture needs start + receipt");
    lines.pop();
    let truncated = lines.join("\n") + "\n";
    let findings = validate_lifecycle_session(&truncated);
    assert!(
        !findings.is_empty(),
        "receiptless stream must carry findings"
    );
    assert!(
        findings.iter().any(|f| f.is_missing_receipt()),
        "one finding names the missing terminal trailer: {findings:?}"
    );
}

// ---------------------------------------------------------------------------
// Help: the discovery path works and names the profile floor.
// ---------------------------------------------------------------------------

#[test]
fn subcommand_help_succeeds_and_names_profile_floor() {
    for sub in ["watch", "report"] {
        let (code, stdout, _) = run(&[sub, "--help"]);
        assert_eq!(code, 0, "{sub} --help must succeed, not usage-error");
        assert!(
            stdout.contains("api-returns") && stdout.contains("request-lifecycle"),
            "{sub} --help names both profiles: {stdout}"
        );
        assert!(
            stdout.contains("7.0"),
            "{sub} --help names the kernel floor: {stdout}"
        );
    }
    // `--help` after flags still wins (early exit, no capture).
    let (code, stdout, _) = run(&["watch", "--system", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("api-returns"), "flag-order help: {stdout}");
    // Control: the global parser still rejects real usage errors.
    assert!(matches!(
        parse(&argv(&["watch", "--bogus"])),
        Err(ArgsError::Usage(_))
    ));
}
