// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 3 public CLI tests: usage exits before capture, frozen
//! fixture replay, and helper-serve finishes through the public API.
//!
//! Live capture (real BPF plus the installed helper) is Stage 4
//! installed acceptance — NOT_RUN here (no lease, host gates only).
//! These tests pin everything around it: argument refusals exit 2
//! without touching privilege, stored bytes replay identically, and
//! the post-capture finish serves fixture helpers through the real
//! confinement boundary (spawn, attest, bind, fold) or degrades to
//! raw-ID rows plus typed unavailability — never an error.

use kryprobe_cli::live::LiveOutcome;
use kryprobe_cli::workload::{
    JoinedRow, WorkloadCapture, WorkloadFinishOpts, finish_workload_report,
};
use kryprobe_core::evidence::NativeObservation;
use std::os::unix::fs::PermissionsExt;

/// One CLI invocation through the public entry point.
fn run_cli(words: &[&str]) -> (i32, String, String) {
    let argv: Vec<String> = words.iter().map(ToString::to_string).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = kryprobe_cli::run(&argv, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).expect("utf-8 stdout"),
        String::from_utf8(stderr).expect("utf-8 stderr"),
    )
}

/// Usage refusals exit 2 naming the rule — before any capture (these
/// run unprivileged: a capture attempt would fail 4, never 2).
#[test]
fn workload_usage_refusals_exit_before_capture() {
    for (words, needle) in [
        (
            vec![
                "kryprobe",
                "watch",
                "--system",
                "--kcrypto-profile",
                "request-lifecycle",
                "--group-by",
                "cgroup",
            ],
            "api-returns",
        ),
        (
            vec![
                "kryprobe",
                "report",
                "--system",
                "--format",
                "json",
                "--group-by",
                "cgroup",
            ],
            "human or --format workload-json",
        ),
        (
            vec![
                "kryprobe",
                "check",
                "--system",
                "--policy",
                "p.yaml",
                "--group-by",
                "cgroup",
            ],
            "not supported",
        ),
        (
            vec!["kryprobe", "watch", "--system", "--filter-cgroup-id", "0"],
            "refuses 0",
        ),
        (
            vec!["kryprobe", "report", "--system", "--filter-pod", "web"],
            "until M2",
        ),
        (
            vec![
                "kryprobe",
                "check",
                "--system",
                "--policy",
                "p.yaml",
                "--cgroup-id",
                "5",
            ],
            "--filter-cgroup-id",
        ),
    ] {
        let (code, _, stderr) = run_cli(&words);
        assert_eq!(code, 2, "args {words:?} exit 2");
        assert!(
            stderr.contains(needle),
            "args {words:?} name the rule: {stderr:?}"
        );
    }
    // The metadata precheck stats (never reads) before capture: a
    // missing file is a usage error without privilege.
    let (code, _, stderr) = run_cli(&[
        "kryprobe",
        "watch",
        "--system",
        "--workload-metadata",
        "/definitely-absent-k3-meta.json",
    ]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("cannot use workload metadata"),
        "{stderr:?}"
    );
}

/// Frozen v2 fixtures replay through `report FILE` with exits on the
/// stored evidence: asserted-metadata is complete (0), partial
/// capture gaps (3), raw ids carry unavailable dimensions (3).
#[test]
fn frozen_fixtures_replay_with_stored_exits() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../kryprobe-report/tests/fixtures/workload-v2");
    for (name, code_want) in [
        ("asserted-metadata.json", 0),
        ("partial-capture.json", 3),
        ("complete-raw-ids.json", 3),
    ] {
        let path = dir.join(name);
        assert!(path.is_file(), "frozen fixture ships: {}", path.display());
        let (code, stdout, _) = run_cli(&["kryprobe", "report", &path.display().to_string()]);
        assert_eq!(code, code_want, "{name} exits on stored evidence");
        assert!(
            stdout.contains("workload-report v2 session"),
            "{name} renders typed text"
        );
    }
    // Replay-after-exit pin: the asserted fixture renders its STORED
    // rows with no helper and no host queries (the workloads are
    // long gone — replay reads bytes, never /proc).
    let path = dir.join("asserted-metadata.json");
    let (code, stdout, _) = run_cli(&["kryprobe", "report", &path.display().to_string()]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("docker") || stdout.contains("container"),
        "asserted identities render from stored bytes:\n{stdout}"
    );
}

/// A missing file keeps the legacy path (unreadable finding, exit 2 —
/// the workload dispatch never disturbs it).
#[test]
fn missing_file_keeps_legacy_unreadable() {
    let (code, _, stderr) = run_cli(&["kryprobe", "report", "/definitely-absent-k3.json"]);
    assert_eq!(code, 2);
    assert!(!stderr.contains("workload-report-v2"), "{stderr:?}");
}

fn joined_row(kh: u64, cgroup: u64, tgid: u32, calls: u64, algorithm: &str) -> JoinedRow {
    JoinedRow {
        context: kryprobe_core::workload::ContextIdentity::new(
            kh,
            cgroup,
            tgid,
            1000,
            555,
            kryprobe_core::workload::ExecutionKind::Proc,
        ),
        calls,
        native: kryprobe_report::workload::NativeIdentity::new(1, 2, 0, 0, algorithm, None),
    }
}

fn agg_observation(id: u64, kh: u64, algorithm: &str) -> NativeObservation {
    use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
    NativeObservation {
        id: kryprobe_core::ids::ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase: EvidencePhase::Completed,
        call_kind: CallKind::Operation,
        operation_class: OperationClass::Encrypt,
        native_name: None,
        native_code: None,
        native_result: kryprobe_core::evidence::NativeResult::KCrypto { status: 0 },
        started_ns: Some(100),
        ended_ns: Some(200),
        correlation: None,
        integrity: kryprobe_core::evidence::IntegrityRef::new(0),
        backend_payload: serde_json::json!({
            "row": "agg",
            "family": "skcipher",
            "op": "encrypt",
            "result": "ok",
            "algorithm": algorithm,
            "driver": "aesni",
            "context": "process",
            "key_hash": kh,
            "capture_profile": "api-returns",
        }),
    }
}

/// One public finish outcome: joined capture + observations + a
/// caller-supplied preflight (unavailable fixtures never serve;
/// launchable ones serve the fixture helper through real
/// confinement).
fn finish_outcome(
    preflight: kryprobe_privilege::workload_launch::WorkloadPreflight,
) -> LiveOutcome {
    LiveOutcome {
        observations: vec![agg_observation(1, 7, "cbc(aes)")],
        summary: kryprobe_core::backend::BackendSummary {
            backend: kryprobe_core::enums::BackendId::KCrypto,
            observations: 1,
            integrity: kryprobe_core::evidence::IntegritySummary::default(),
        },
        coverage: kryprobe_core::evidence::CoverageSummary::not_run(),
        integrity: kryprobe_core::evidence::IntegritySummary::default(),
        terminal_state: kryprobe_core::session::SessionState::Finalized,
        interrupted: false,
        enrichment: None,
        lifecycle_totals: None,
        stop: None,
        workload_preflight: Some(preflight),
        workload_terminal: None,
        workload_capture: Some(WorkloadCapture {
            rows: vec![joined_row(7, 42, 100, 20, "cbc(aes)")],
            system_total: 20,
            system_saturated: false,
            refused_inserts: 0,
            interval_start_ns: 100,
            interval_end_ns: 1000,
        }),
        workload_misses: None,
    }
}

fn launchable_preflight(
    helper: &std::path::Path,
) -> kryprobe_privilege::workload_launch::WorkloadPreflight {
    kryprobe_privilege::workload_launch::WorkloadPreflight {
        helper: Some(helper.to_path_buf()),
        helper_identity: Some(
            kryprobe_privilege::workload_launch::pin_helper(helper)
                .expect("fixture pins")
                .identity,
        ),
        principal: Some(
            kryprobe_privilege::workload_launch::current_principal().expect("test principal"),
        ),
        kernel_scope: Some("test-scope".to_string()),
        unavailable: None,
    }
}

fn finish_opts() -> WorkloadFinishOpts {
    WorkloadFinishOpts {
        group_by: kryprobe_report::workload::GroupBy::Cgroup,
        filter_cgroup_id: None,
        metadata_file: None,
        profile: "api-returns".to_string(),
    }
}

/// Built launch fixture binary (`kryprobe-privilege` Cargo example,
/// next to this test executable's `deps` dir). The example location
/// is the test-only gate (default `cargo build` never produces it,
/// default `cargo install` never ships it — only explicit
/// `--example` selection builds it). Every all-target `cargo test`
/// builds it
/// (including the `xtask check` gate); focused `--test` runs must
/// build it first (`cargo build -p kryprobe-privilege --example
/// kryprobe_launch_fixture`) — the assert says so loudly.
fn fixture_binary_path() -> std::path::PathBuf {
    let test_exe = std::env::current_exe().expect("test exe");
    let bin = test_exe
        .parent()
        .expect("deps dir")
        .parent()
        .expect("profile dir")
        .join("examples")
        .join("kryprobe_launch_fixture");
    assert!(
        bin.is_file(),
        "fixture binary built at {} (run all-target `cargo test --workspace`)",
        bin.display()
    );
    // Layout pin: the Cargo test-only gate IS this directory — a
    // fixture resolving anywhere else (e.g. back in the profile dir
    // as a `src/bin` target) would ship with normal builds.
    assert_eq!(
        bin.parent().and_then(|dir| dir.file_name()),
        Some(std::ffi::OsStr::new("examples")),
        "fixture resolves from Cargo examples (test-only)"
    );
    bin
}

/// Stage the fixture binary at `dir/name` with its stem sidecar.
/// The launcher verifies the real confinement of every fixture
/// serve below (same shape as the launch-module fixtures).
fn stage_fixture(
    dir: &std::path::Path,
    name: &str,
    sidecar: serde_json::Value,
) -> std::path::PathBuf {
    let dst = dir.join(name);
    std::fs::copy(fixture_binary_path(), &dst).expect("fixture staged");
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let stem = std::path::Path::new(name)
        .file_stem()
        .expect("stem")
        .to_string_lossy()
        .into_owned();
    std::fs::write(
        dir.join(format!("{stem}.fixture.json")),
        serde_json::to_string(&sidecar).expect("sidecar"),
    )
    .expect("sidecar written");
    dst
}

/// Wrong-kernel metadata at CLI level: the helper answers (transport
/// fine), but the snapshot kernel differs — the key refuses typed,
/// the row stays unresolved, metadata coverage reads partial.
#[test]
fn wrong_kernel_folds_to_partial_metadata() {
    let scratch = kryprobe_testkit::TempDir::named("cli-wrong-kernel").expect("scratch");
    // The request key is fixed by the finish fixture (single row:
    // cgroup 42, tgid 100, start 555, scope test-scope); only the
    // minted session varies, so the fixture substitutes it in.
    std::fs::write(
        scratch.path().join("resp.json"),
        "{\"session_id\":\"00000000000000000000000000000000\",\
         \"kernel_identity\":{\"known\":\"other-scope\"},\"associations\":[],\
         \"errors\":[{\"key\":{\"kernel_scope\":\"test-scope\",\"cgroup\":42,\
         \"tgid\":100,\"start_ns\":555},\"code\":\"kernel_mismatch\",\
         \"detail\":\"kernel_differs\"}],\"status\":\"complete\",\
         \"chunk\":{\"index\":0,\"total\":1},\
         \"counters\":{\"resolved\":0,\"unresolved\":0,\"refused\":1}}",
    )
    .expect("template written");
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"canned": "resp.json"}),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(finished.rows.len(), 1);
    assert_eq!(
        finished.rows[0].evidence.status,
        kryprobe_core::workload::AttributionStatus::Unresolved
    );
    assert_eq!(
        finished.report.metadata,
        kryprobe_report::workload::MetadataAvailability::Available
    );
    assert_eq!(
        finished.report.coverage.metadata,
        kryprobe_report::workload::CoverageLevel::Partial
    );
}

/// Ordinary-user metadata success at CLI level: a covering file
/// binding asserts through the served fixture — identity established,
/// attribution complete.
#[test]
fn asserted_metadata_resolves_through_serve() {
    use kryprobe_core::workload::{
        AttributionStatus, BindingProvenance, ContainerRef, KernelIdentity, METHOD_METADATA_FILE,
        MetadataEntry, MetadataSnapshot, SnapshotInterval, SnapshotRequest, ValidityInterval,
        WorkloadOrigin,
    };
    let scratch = kryprobe_testkit::TempDir::named("cli-asserted").expect("scratch");
    // Canned response via the frozen pure resolver (covering
    // validity → Asserted); the fixture substitutes the minted
    // session. Placeholder session is valid 32-hex (binds after
    // substitution).
    let request = SnapshotRequest {
        session_id: "00000000000000000000000000000000".to_string(),
        keys: vec![kryprobe_core::workload::SnapshotKey {
            kernel_scope: "test-scope".to_string(),
            cgroup: 42,
            tgid: 100,
            start_ns: 555,
        }],
        capture_interval: Some(SnapshotInterval {
            start_ns: 100,
            end_ns: 1000,
        }),
    };
    let snapshot = MetadataSnapshot {
        collector: "cli-test".to_string(),
        snapshot_interval: SnapshotInterval {
            start_ns: 100,
            end_ns: 1000,
        },
        kernel_identity: KernelIdentity::Known("test-scope".to_string()),
        entries: vec![MetadataEntry {
            container: Some(ContainerRef {
                runtime: "docker://host-a".to_string(),
                id: "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57".to_string(),
                lifetime: None,
            }),
            pod: None,
            cluster: None,
            node: None,
            ancestor_container: None,
            display_name: None,
            cgroup_id: Some(42),
            binding: BindingProvenance {
                method: METHOD_METADATA_FILE.to_string(),
                source: WorkloadOrigin::OperatorMetadataFile,
                status: AttributionStatus::Asserted,
                validity: Some(ValidityInterval::monotonic(50, 2000)),
            },
        }],
    };
    let response = kryprobe_core::workload::resolve(&request, &snapshot).expect("resolves");
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Asserted
    );
    let canned = kryprobe_core::workload::encode_response(&response).expect("encodes");
    let canned_path = scratch.path().join("canned.json");
    std::fs::write(&canned_path, &canned).expect("canned");
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"canned": "canned.json"}),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(finished.rows.len(), 1);
    assert!(finished.rows[0].identity.is_resolved());
    assert_eq!(
        finished.rows[0].evidence.status,
        AttributionStatus::Asserted
    );
    assert_eq!(
        finished.report.coverage.attribution,
        kryprobe_report::workload::CoverageLevel::Complete
    );
    assert_eq!(
        finished.report.coverage.metadata,
        kryprobe_report::workload::CoverageLevel::Complete
    );
    let text = finished.report.render_text();
    assert!(
        text.contains("docker"),
        "asserted identity renders:\n{text}"
    );
}

/// Stale metadata at CLI level: a non-covering validity keeps the
/// working identity but marks the row stale (counted unresolved).
#[test]
fn stale_metadata_keeps_identity_marks_row() {
    use kryprobe_core::workload::{
        AttributionStatus, BindingProvenance, ContainerRef, KernelIdentity, METHOD_METADATA_FILE,
        MetadataEntry, MetadataSnapshot, SnapshotInterval, SnapshotRequest, ValidityInterval,
        WorkloadOrigin,
    };
    let scratch = kryprobe_testkit::TempDir::named("cli-stale").expect("scratch");
    let request = SnapshotRequest {
        session_id: "00000000000000000000000000000000".to_string(),
        keys: vec![kryprobe_core::workload::SnapshotKey {
            kernel_scope: "test-scope".to_string(),
            cgroup: 42,
            tgid: 100,
            start_ns: 555,
        }],
        capture_interval: Some(SnapshotInterval {
            start_ns: 100,
            end_ns: 1000,
        }),
    };
    let snapshot = MetadataSnapshot {
        collector: "cli-test".to_string(),
        snapshot_interval: SnapshotInterval {
            start_ns: 100,
            end_ns: 1000,
        },
        kernel_identity: KernelIdentity::Known("test-scope".to_string()),
        entries: vec![MetadataEntry {
            container: Some(ContainerRef {
                runtime: "docker://host-a".to_string(),
                id: "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57".to_string(),
                lifetime: None,
            }),
            pod: None,
            cluster: None,
            node: None,
            ancestor_container: None,
            display_name: None,
            cgroup_id: Some(42),
            binding: BindingProvenance {
                method: METHOD_METADATA_FILE.to_string(),
                source: WorkloadOrigin::OperatorMetadataFile,
                status: AttributionStatus::Asserted,
                validity: Some(ValidityInterval::monotonic(100, 500)),
            },
        }],
    };
    let response = kryprobe_core::workload::resolve(&request, &snapshot).expect("resolves");
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Stale
    );
    let canned = kryprobe_core::workload::encode_response(&response).expect("encodes");
    let canned_path = scratch.path().join("canned.json");
    std::fs::write(&canned_path, &canned).expect("canned");
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"canned": "canned.json"}),
    );
    // Counted-unresolved (ADR-0012): the producer counts the
    // stale row unresolved, never resolved.
    assert_eq!(response.counters.resolved, 0);
    assert_eq!(response.counters.unresolved, 1);
    assert_eq!(response.counters.refused, 0);
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(finished.rows.len(), 1);
    assert!(finished.rows[0].identity.is_resolved());
    assert_eq!(finished.rows[0].evidence.status, AttributionStatus::Stale);
    // C2 oracle: stale identity is KEPT but never qualifies as
    // complete attribution — the report reads PARTIAL.
    assert_eq!(
        finished.report.coverage.attribution,
        kryprobe_report::workload::CoverageLevel::Partial,
        "stale bindings report PARTIAL attribution"
    );
}

/// C3 oracle: a workload crossing the 4 KiB request byte budget
/// resolves via multiple bounded requests — never a whole-batch
/// refusal. The fixture echoes every chunk's keys as unresolved
/// (binding to any chunk) and counts serves.
#[test]
fn byte_budget_splits_snapshot_requests() {
    use kryprobe_core::workload::{SnapshotInterval, SnapshotKey, SnapshotRequest, encode_request};
    let scratch = kryprobe_testkit::TempDir::named("cli-byte-split").expect("scratch");
    // 120 distinct triples: under the 256-count cap, over the byte
    // budget as one request.
    let keys: Vec<SnapshotKey> = (0..120u64)
        .map(|i| SnapshotKey {
            kernel_scope: "test-scope".to_string(),
            cgroup: 1000 + i,
            tgid: 2000 + i as u32,
            start_ns: 555,
        })
        .collect();
    // Prove the workload crosses the budget as ONE request (the old
    // code built exactly this shape and refused the whole batch).
    let single = SnapshotRequest {
        session_id: "0123456789abcdef0123456789abcdef".to_string(),
        keys,
        capture_interval: Some(SnapshotInterval {
            start_ns: 100,
            end_ns: 1000,
        }),
    };
    assert_eq!(
        encode_request(&single),
        Err(kryprobe_core::workload::MetadataUnavailable::BudgetExceeded),
        "one request would cross the byte budget"
    );
    let rows: Vec<JoinedRow> = single
        .keys
        .iter()
        .enumerate()
        .map(|(n, key)| joined_row(n as u64, key.cgroup, key.tgid, 1, "cbc(aes)"))
        .collect();
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"echo_unresolved": true, "count": "count"}),
    );
    let mut outcome = finish_outcome(launchable_preflight(&helper));
    outcome.workload_capture = Some(WorkloadCapture {
        rows,
        system_total: 120,
        system_saturated: false,
        refused_inserts: 0,
        interval_start_ns: 100,
        interval_end_ns: 1000,
    });
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    // Resolved (multi-request), not whole-batch refused.
    assert_eq!(
        finished.report.metadata,
        kryprobe_report::workload::MetadataAvailability::Available,
        "byte-crossing workload resolves"
    );
    let serves = std::fs::read_to_string(scratch.path().join("count"))
        .expect("serves counted")
        .lines()
        .count();
    assert!(serves > 1, "more than one bounded request served: {serves}");
    // Every chunk's answers combined: all 120 rows, echoed
    // unresolved, metadata complete, attribution partial.
    assert_eq!(finished.rows.len(), 120);
    assert!(
        finished.rows.iter().all(
            |row| row.evidence.status == kryprobe_core::workload::AttributionStatus::Unresolved
        ),
        "echo answers every row unresolved"
    );
    assert_eq!(
        finished.report.coverage.metadata,
        kryprobe_report::workload::CoverageLevel::Complete
    );
    assert_eq!(
        finished.report.coverage.attribution,
        kryprobe_report::workload::CoverageLevel::Partial
    );
}

/// C5 oracle (Codex C2): zero captured keys split into zero
/// requests — the finish preserves the frozen empty-request refusal
/// (`SnapshotRequest::validate`: empty keys → `ParseFailed`) instead
/// of answering `Available` with COMPLETE coverage. No helper
/// invocation serves nothing.
/// (RED pre-fix: `answered = true` + `Available` + COMPLETE.)
#[test]
fn empty_capture_finish_preserves_empty_request_refusal() {
    let scratch = kryprobe_testkit::TempDir::named("cli-empty-capture").expect("scratch");
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"echo_unresolved": true, "count": "count"}),
    );
    let mut outcome = finish_outcome(launchable_preflight(&helper));
    outcome.workload_capture = Some(WorkloadCapture {
        rows: vec![],
        system_total: 0,
        system_saturated: false,
        refused_inserts: 0,
        interval_start_ns: 100,
        interval_end_ns: 1000,
    });
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(
        finished.report.metadata,
        kryprobe_report::workload::MetadataAvailability::Unavailable(
            kryprobe_core::workload::MetadataUnavailable::ParseFailed
        ),
        "empty capture refuses like the frozen empty request"
    );
    assert_eq!(
        finished.report.coverage.metadata,
        kryprobe_report::workload::CoverageLevel::Unavailable,
        "no-answer state, never COMPLETE coverage"
    );
    assert!(
        !scratch.path().join("count").exists(),
        "zero requests serve zero invocations"
    );
}

/// C4 oracle: the human workload report carries the terminal
/// miss telemetry — per-program join detail, per-operation run
/// qualification, and unavailable reasons — or explicit
/// unavailability. Global misses never touch context rows.
/// (RED shown pre-fix as `..._v1`: the report carried neither.)
#[test]
fn workload_report_carries_miss_telemetry() {
    use kryprobe_privilege::kcrypto_backend::{AggProgMissDelta, MissTerminal};
    let preflight = kryprobe_privilege::workload_launch::WorkloadPreflight {
        helper: None,
        helper_identity: None,
        principal: None,
        kernel_scope: Some("test-scope".to_string()),
        unavailable: Some(kryprobe_core::workload::MetadataUnavailable::HelperRefused),
    };
    let mut outcome = finish_outcome(preflight);
    // Capture with program misses: one qualified program, one
    // stats-gated (run unqualified, never zero-filled).
    outcome.workload_misses = Some(MissTerminal::Available(vec![
        AggProgMissDelta {
            section: "fexit/kcrypto_sendmsg".to_owned(),
            program_id: 12,
            miss_baseline: 50,
            miss_current: 60,
            miss_delta: 10,
            run_delta: None,
        },
        AggProgMissDelta {
            section: "fexit/kcrypto_recvmsg".to_owned(),
            program_id: 11,
            miss_baseline: 100,
            miss_current: 115,
            miss_delta: 15,
            run_delta: Some(12),
        },
    ]));
    let finished =
        kryprobe_cli::workload::finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    // Stable section/program-ID join, absolute endpoints, delta,
    // and per-operation run qualification — sorted for determinism.
    assert!(text.contains("misses: 2 program(s)"), "got:\n{text}");
    let recv = "fexit/kcrypto_recvmsg id=11 baseline=100 current=115 delta=15 run=12";
    let send = "fexit/kcrypto_sendmsg id=12 baseline=50 current=60 delta=10 run=unavailable";
    assert!(text.contains(recv), "qualified program line, got:\n{text}");
    assert!(
        text.contains(send),
        "stats-gated program line, got:\n{text}"
    );
    assert!(
        text.find(recv) < text.find(send),
        "sorted by (section, program ID), got:\n{text}"
    );
    // Never assigned to contexts: the frozen report text (rows +
    // ledger) carries no miss data.
    assert!(
        !finished.report.render_text().contains("misses:"),
        "rows/ledger untouched by global misses"
    );
    // Explicit unavailability carries the reason verbatim.
    outcome.workload_misses = Some(MissTerminal::Unavailable {
        reason: "miss join refused: redeploy".to_owned(),
    });
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains("misses: unavailable (miss join refused: redeploy)"),
        "unavailable reason, got:\n{text}"
    );
    // Never silently absent.
    outcome.workload_misses = None;
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains("misses: unavailable (not collected)"),
        "explicit not-collected, got:\n{text}"
    );
}

/// Helper crash at CLI level: the serve retries, then the finish
/// degrades to raw-ID rows plus typed unavailability — data, never
/// an error (enrichment cannot stall capture).
#[test]
fn helper_crash_degrades_to_raw_ids() {
    let scratch = kryprobe_testkit::TempDir::named("cli-crash").expect("scratch");
    let helper = stage_fixture(scratch.path(), "helper", serde_json::json!({"crash": true}));
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes anyway");
    assert_eq!(
        finished.report.metadata,
        kryprobe_report::workload::MetadataAvailability::Unavailable(
            kryprobe_core::workload::MetadataUnavailable::HelperRefused
        )
    );
    assert_eq!(
        finished.rows[0].evidence.status,
        kryprobe_core::workload::AttributionStatus::Unresolved
    );
    assert_eq!(
        finished.report.coverage.metadata,
        kryprobe_report::workload::CoverageLevel::Unavailable
    );
}
