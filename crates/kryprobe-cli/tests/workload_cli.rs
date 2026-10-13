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
/// default `cargo install` never ships it — explicit selection
/// (`--example`/`--examples`/`--all-targets`) can also build it).
/// Every all-target `cargo test`
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

// ---------------------------------------------------------------------------
// F04 shared replay invariants (SEM01/SEM02)
// ---------------------------------------------------------------------------

fn f04_fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../kryprobe-report/tests/fixtures/workload-v2")
}

fn f04_fixture_value(name: &str) -> serde_json::Value {
    let bytes = std::fs::read(f04_fixture_dir().join(name)).expect("frozen fixture ships");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

fn f04_stage(name: &str, value: &serde_json::Value) -> (kryprobe_testkit::TempDir, String) {
    let scratch = kryprobe_testkit::TempDir::named(name).expect("scratch");
    let path = scratch.path().join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec(value).expect("encodes")).expect("staged");
    let display = path.display().to_string();
    (scratch, display)
}

/// SEM01 at the public surface: selector-contradictory scoped
/// partitions refuse through `report FILE` (exit 2, nothing renders);
/// the derived buckets replay with exits on the stored evidence.
#[test]
fn scoped_partition_conservation_is_not_selection() {
    // Case 1: selector 999 claims 50/0/0 although rows derive 0/40/10.
    let mut hostile = f04_fixture_value("unknown-match.json");
    hostile["selectors"]["cgroup_id"] = serde_json::json!("999");
    hostile["partition"]["matched"] = serde_json::json!("50");
    hostile["partition"]["nonmatched"] = serde_json::json!("0");
    hostile["partition"]["unknown_match"] = serde_json::json!("0");
    let (_scratch, path) = f04_stage("cli-f04-partition-hostile", &hostile);
    let (code, stdout, stderr) = run_cli(&["kryprobe", "report", &path]);
    assert_eq!(code, 2, "partition-hostile refuses: {stdout}{stderr}");
    assert!(
        !stdout.contains("matched=50"),
        "nothing renders on refusal: {stdout}"
    );
    // The derived 0/40/10 replays (exit 3 on the stored partial
    // attribution, like the frozen fixture it mutates).
    let mut derived = f04_fixture_value("unknown-match.json");
    derived["selectors"]["cgroup_id"] = serde_json::json!("999");
    derived["partition"]["matched"] = serde_json::json!("0");
    derived["partition"]["nonmatched"] = serde_json::json!("40");
    derived["partition"]["unknown_match"] = serde_json::json!("10");
    let (_scratch, path) = f04_stage("cli-f04-partition-derived", &derived);
    let (code, stdout, _) = run_cli(&["kryprobe", "report", &path]);
    assert_eq!(code, 3, "derived 0/40/10 replays");
    assert!(stdout.contains("matched=0"), "derived renders:\n{stdout}");
    // Case 2: selector 43812 with stored 0/50/0 refuses; the frozen
    // 20/20/10 replays (positive control).
    let mut hostile2 = f04_fixture_value("unknown-match.json");
    hostile2["partition"]["matched"] = serde_json::json!("0");
    hostile2["partition"]["nonmatched"] = serde_json::json!("50");
    hostile2["partition"]["unknown_match"] = serde_json::json!("0");
    let (_scratch, path) = f04_stage("cli-f04-partition-hostile2", &hostile2);
    let (code, _, _) = run_cli(&["kryprobe", "report", &path]);
    assert_eq!(code, 2, "selector-43812 0/50/0 refuses");
    let frozen = f04_fixture_dir().join("unknown-match.json");
    let (code, stdout, _) = run_cli(&["kryprobe", "report", &frozen.display().to_string()]);
    assert_eq!(code, 3, "frozen 20/20/10 replays");
    assert!(stdout.contains("matched=20"), "frozen renders:\n{stdout}");
}

/// SEM02 across every ingress: resolved cgroup-zero refuses under
/// verified/asserted/stale through observation, snapshot, assembly,
/// decode, and `report FILE`; unresolved cgroup-zero passes each.
#[test]
fn cgroup_zero_identity_refuses_every_ingress() {
    use kryprobe_core::workload::{
        AttributionEvidence, AttributionStatus, ChunkInfo, ContextIdentity, CountOperand,
        ExecutionKind, KernelIdentity, Relationship, ResolvedAssociation, ResponseStatus,
        SnapshotCounters, SnapshotKey, SnapshotResponse, ValidityInterval, WorkloadIdentity,
        WorkloadObservation,
    };
    const ID_A: &str = "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57";
    const RUNTIME: &str = "docker://host-a";
    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    let usable = |status: AttributionStatus| match status {
        AttributionStatus::Verified => AttributionEvidence::verified_kernel_capture(
            Relationship::HookContext,
            ValidityInterval::monotonic(100, 1000),
        ),
        AttributionStatus::Asserted => AttributionEvidence::asserted_metadata(
            Relationship::HookContext,
            kryprobe_core::workload::METHOD_METADATA_FILE,
            Some(ValidityInterval::monotonic(100, 1000)),
        ),
        _ => AttributionEvidence::new(
            Relationship::HookContext,
            kryprobe_core::workload::METHOD_METADATA_FILE,
            kryprobe_core::workload::WorkloadOrigin::OperatorMetadataFile,
            AttributionStatus::Stale,
            Some(ValidityInterval::monotonic(100, 1000)),
        ),
    };
    let wire_status = |status: AttributionStatus| match status {
        AttributionStatus::Verified => "verified",
        AttributionStatus::Asserted => "asserted",
        _ => "stale",
    };
    for status in [
        AttributionStatus::Verified,
        AttributionStatus::Asserted,
        AttributionStatus::Stale,
    ] {
        let tag = wire_status(status);
        let identity = WorkloadIdentity::container(RUNTIME, ID_A, Some("lifetime-a"));
        let evidence = usable(status);
        assert!(evidence.validate().is_ok(), "usable evidence coheres");
        // Ingress 1: shared observation validation.
        let observation = WorkloadObservation {
            context: ContextIdentity::new(7, 0, 1000, 1000, 555, ExecutionKind::Proc),
            identity: identity.clone(),
            evidence: evidence.clone(),
        };
        assert!(
            observation.validate().is_err(),
            "observation refuses resolved cgroup-zero under {tag}"
        );
        // Ingress 2: snapshot response validation (positive pin: the
        // pre-existing rule every other ingress must match).
        let response = SnapshotResponse {
            session_id: SESSION.to_string(),
            kernel_identity: KernelIdentity::Known("kernel-A/boot-A".to_string()),
            associations: vec![ResolvedAssociation {
                key: SnapshotKey {
                    kernel_scope: "kernel-A/boot-A".to_string(),
                    cgroup: 0,
                    tgid: 1000,
                    start_ns: 555,
                },
                identity: identity.clone(),
                evidence: evidence.clone(),
            }],
            errors: vec![],
            status: ResponseStatus::Complete,
            chunk: ChunkInfo::single(),
            counters: if status == AttributionStatus::Stale {
                SnapshotCounters {
                    resolved: 0,
                    unresolved: 1,
                    refused: 0,
                }
            } else {
                SnapshotCounters {
                    resolved: 1,
                    unresolved: 0,
                    refused: 0,
                }
            },
        };
        assert!(
            response.validate().is_err(),
            "snapshot refuses resolved cgroup-zero under {tag}"
        );
        // Ingress 3: typed report assembly.
        let input = kryprobe_report::workload::AssemblyInput {
            session_id: SESSION.to_string(),
            kernel_identity: "7.0.0-38-generic/boot-A".to_string(),
            interval_start_ns: 100,
            interval_end_ns: 1000,
            consistency: kryprobe_core::workload::SnapshotConsistency::Quiescent,
            profile: "api-returns".to_string(),
            system_total: CountOperand {
                value: 50,
                saturated: false,
                population: "global".to_string(),
            },
            per_context_saturated: false,
            refused_inserts: 0,
            rows: vec![kryprobe_report::workload::ReportRowInput {
                context: ContextIdentity::new(7, 0, 1000, 1000, 555, ExecutionKind::Proc),
                calls: 50,
                native: kryprobe_report::workload::NativeIdentity::new(
                    1,
                    2,
                    0,
                    0,
                    "cbc(aes)",
                    Some("cbc-aes-aesni"),
                ),
                identity: identity.clone(),
                evidence: evidence.clone(),
            }],
            partition: kryprobe_core::workload::ScopePartition::from_counts(50, 0, 0)
                .expect("valid"),
            selector: kryprobe_report::workload::WorkloadSelector::None,
            group_by: kryprobe_report::workload::GroupBy::None,
            metadata: kryprobe_report::workload::MetadataAvailability::Available,
            coverage: kryprobe_report::workload::ReportCoverage {
                capture: kryprobe_report::workload::CoverageLevel::Complete,
                attribution: kryprobe_report::workload::CoverageLevel::Complete,
                metadata: kryprobe_report::workload::CoverageLevel::Complete,
                correlation: kryprobe_report::workload::CoverageLevel::Complete,
            },
        };
        assert!(
            kryprobe_report::workload::assemble(input).is_err(),
            "assembly refuses resolved cgroup-zero under {tag}"
        );
        // Ingresses 4+5: replay decode and `report FILE`.
        let mut hostile = f04_fixture_value("asserted-metadata.json");
        hostile["contexts"][0]["cgroup_id"] = serde_json::json!("0");
        hostile["contexts"][0]["attribution"]["status"] = serde_json::json!(tag);
        if status == AttributionStatus::Verified {
            hostile["contexts"][0]["attribution"]["method"] = serde_json::json!("captured_cgroup");
            hostile["contexts"][0]["attribution"]["source"] = serde_json::json!("kernel_capture");
        }
        let bytes = serde_json::to_vec(&hostile).expect("encodes");
        assert!(
            kryprobe_report::workload::report_from_bytes(&bytes).is_err(),
            "decode refuses resolved cgroup-zero under {tag}"
        );
        let (_scratch, path) = f04_stage(&format!("cli-f04-cgroup-zero-{tag}"), &hostile);
        let (code, stdout, _) = run_cli(&["kryprobe", "report", &path]);
        assert_eq!(code, 2, "replay refuses resolved cgroup-zero under {tag}");
        assert!(stdout.is_empty(), "nothing renders on refusal: {stdout}");
    }
    // Positive controls: unresolved cgroup-zero passes every typed
    // ingress and replays; the frozen asserted fixture is untouched.
    let unresolved = WorkloadObservation {
        context: ContextIdentity::new(7, 0, 1000, 1000, 555, ExecutionKind::Proc),
        identity: WorkloadIdentity::none(),
        evidence: AttributionEvidence::unresolved(Relationship::HookContext),
    };
    assert!(unresolved.validate().is_ok());
    let raw = std::fs::read(f04_fixture_dir().join("unknown-context.json")).expect("ships");
    kryprobe_report::workload::report_from_bytes(&raw).expect("unresolved cgroup-zero decodes");
    let path = f04_fixture_dir().join("unknown-context.json");
    let (code, _, _) = run_cli(&["kryprobe", "report", &path.display().to_string()]);
    assert_eq!(code, 3, "unresolved cgroup-zero replays");
    let path = f04_fixture_dir().join("asserted-metadata.json");
    let (code, _, _) = run_cli(&["kryprobe", "report", &path.display().to_string()]);
    assert_eq!(code, 0, "asserted fixture keeps replaying");
}

// ---------------------------------------------------------------------------
// F05 scoped policy evidence (SEM04)
// ---------------------------------------------------------------------------

/// Production-shaped aggregate template: one `kh` with system-wide
/// tallies (`calls=100`, `bytes=409600`) shared by two contexts.
fn f05_template() -> NativeObservation {
    use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
    NativeObservation {
        id: kryprobe_core::ids::ObservationId::new(1),
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
            "key_hash": 7,
            "family": "skcipher",
            "op": "encrypt",
            "result": "ok",
            "algorithm": "cbc(aes)",
            "driver": "aesni",
            "context": "process",
            "counts": {"calls": 100, "ok": 100, "errors": 0, "queued": 2},
            "bytes": 409600,
            "lat": [1, 2, 3],
            "window": {"first_ns": 100, "last_ns": 200},
            "status_canonical": true,
            "capture_profile": "api-returns",
            "count_unit": "api_invocation_return",
            "completion_coverage": "unobserved",
        }),
    }
}

fn f05_row(
    cgroup: u64,
    tgid: u32,
    uid: u32,
    calls: u64,
) -> kryprobe_report::workload::ReportRowInput {
    kryprobe_report::workload::ReportRowInput {
        context: kryprobe_core::workload::ContextIdentity::new(
            7,
            cgroup,
            tgid,
            uid,
            555,
            kryprobe_core::workload::ExecutionKind::Proc,
        ),
        calls,
        native: kryprobe_report::workload::NativeIdentity::new(
            1,
            2,
            0,
            0,
            "cbc(aes)",
            Some("aesni"),
        ),
        identity: kryprobe_core::workload::WorkloadIdentity::none(),
        evidence: kryprobe_core::workload::AttributionEvidence::unresolved(
            kryprobe_core::workload::Relationship::HookContext,
        ),
    }
}

/// SEM04: a deny verdict on a selected row attributes that row's
/// quantities. Two contexts share one `kh` (system `calls=100`,
/// `bytes=409600`); the selected row carries `calls=5` under
/// `uid=1234`. The deny rule matches algorithm + UID, so the
/// violation evidence must show 5 calls with the row's event
/// context — never the system-wide 100/409600 stamped `uid=1234`.
/// (RED pre-fix: evidence `counts.calls` is 100 with system bytes.)
#[test]
fn scoped_violation_evidence_uses_row_population() {
    use kryprobe_policy::workload::{CaptureIntegrity, ScopedRow, ScopedVerdict};
    let rows = vec![f05_row(42, 1000, 1234, 5), f05_row(43, 1001, 1000, 95)];
    let template = f05_template();
    let projected =
        kryprobe_cli::workload::observations_for_rows(&rows, &[template]).expect("projects");
    assert_eq!(projected.len(), 2);
    let policy = kryprobe_policy::parse_policy(
        "version: 1\nrules:\n  - id: no-uid-cbc\n    source: kernel-crypto\n    match:\n      stage: executed\n      algorithm: cbc(aes)\n      uid: 1234\n    decision: deny\n",
    )
    .expect("deny parses");
    let selector = kryprobe_policy::workload::WorkloadSelector::cgroup(42).expect("selector");
    let scoped: Vec<ScopedRow<'_>> = rows
        .iter()
        .zip(projected.iter())
        .map(|(row, observation)| ScopedRow {
            calls: row.calls,
            context: row.context,
            identity: row.identity.clone(),
            evidence: row.evidence.clone(),
            observation,
        })
        .collect();
    let verdict = kryprobe_policy::workload::evaluate_scoped(
        &policy,
        &selector,
        &scoped,
        CaptureIntegrity::Complete,
    )
    .expect("evaluates");
    let ScopedVerdict::Violation {
        partition,
        evidence,
        obs_ids,
        ..
    } = &verdict
    else {
        panic!("deny on the selected row violates: {verdict:?}");
    };
    assert_eq!(verdict.exit_intent(), 10);
    assert_eq!(partition.matched(), 5);
    assert_eq!(partition.nonmatched(), 95);
    assert_eq!(partition.unknown_match(), 0);
    // Only the uid-1234 row matches: one finding, one observation.
    assert_eq!(evidence.len(), 1);
    assert_eq!(obs_ids.len(), 1);
    let payload = &evidence[0].backend_payload;
    // The row's population: 5 calls, never the system 100.
    assert_eq!(
        payload["counts"]["calls"],
        serde_json::json!(5),
        "{payload}"
    );
    // The row's event context rides the evidence.
    assert_eq!(payload["uid"], serde_json::json!(1234), "{payload}");
    assert_eq!(
        payload["event"]["cgroup"],
        serde_json::json!(42),
        "{payload}"
    );
    assert_eq!(
        payload["event"]["tgid"],
        serde_json::json!(1000),
        "{payload}"
    );
    assert_eq!(
        payload["event"]["start_ns"],
        serde_json::json!(555),
        "{payload}"
    );
    assert_eq!(
        payload["event"]["uid"],
        serde_json::json!(1234),
        "{payload}"
    );
    // Explicitly scoped, with the system template kept as separately
    // labeled evidence — never merged into the row's quantities.
    assert_eq!(
        payload["evidence_scope"],
        serde_json::json!("row"),
        "{payload}"
    );
    assert_eq!(
        payload["aggregate_obs"],
        serde_json::json!("observation:1"),
        "{payload}"
    );
    // System-only quantities stay out: no bytes/latency/window and no
    // result tallies beyond the row's own calls.
    for key in ["bytes", "lat", "window", "ok", "errors", "queued"] {
        assert!(
            payload.get(key).is_none(),
            "system-only `{key}` omitted: {payload}"
        );
    }
    assert!(
        payload["counts"].get("ok").is_none(),
        "system ok omitted: {payload}"
    );
    // Native tuple and capture labels survive the projection.
    for (key, want) in [
        ("row", "agg"),
        ("family", "skcipher"),
        ("op", "encrypt"),
        ("result", "ok"),
        ("algorithm", "cbc(aes)"),
        ("driver", "aesni"),
        ("context", "process"),
        ("capture_profile", "api-returns"),
        ("count_unit", "api_invocation_return"),
        ("completion_coverage", "unobserved"),
    ] {
        assert_eq!(payload[key], serde_json::json!(want), "{payload}");
    }
    assert_eq!(payload["key_hash"], serde_json::json!(7), "{payload}");
    // System window timestamps are not row facts.
    assert_eq!(evidence[0].started_ns, None);
    assert_eq!(evidence[0].ended_ns, None);
    // The sibling row projects its own 95 calls under its own uid —
    // quantities differ per row from the one shared template.
    assert_eq!(
        projected[1].backend_payload["counts"]["calls"],
        serde_json::json!(95)
    );
    assert_eq!(projected[1].backend_payload["uid"], serde_json::json!(1000));
    assert_eq!(
        projected[1].backend_payload["event"]["cgroup"],
        serde_json::json!(43)
    );
    // Fresh positional session-scoped ids number the projection in
    // row order.
    assert_eq!(projected[0].id, kryprobe_core::ids::ObservationId::new(1));
    assert_eq!(projected[1].id, kryprobe_core::ids::ObservationId::new(2));
}

/// F07 RED: canned helper valid unresolved response plus
/// `denied=1`/`migration_skipped=1` — the public completion must
/// surface the approved counters. Pre-fix the launcher discards the
/// counters line, so the observation assertion fails.
#[test]
fn helper_denied_and_migration_counters_surface_in_completion() {
    use kryprobe_core::workload::{
        AttributionStatus, KernelIdentity, MetadataSnapshot, SnapshotInterval, SnapshotKey,
        SnapshotRequest,
    };
    let scratch = kryprobe_testkit::TempDir::named("cli-helper-diag").expect("scratch");
    // Canned response via the frozen pure resolver (empty entries:
    // the key stays Unresolved — still bound). Placeholder session
    // is valid 32-hex (binds after fixture substitution).
    let request = SnapshotRequest {
        session_id: "00000000000000000000000000000000".to_string(),
        keys: vec![SnapshotKey {
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
        entries: Vec::new(),
    };
    let response = kryprobe_core::workload::resolve(&request, &snapshot).expect("resolves");
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Unresolved
    );
    let canned = kryprobe_core::workload::encode_response(&response).expect("encodes");
    std::fs::write(scratch.path().join("canned.json"), &canned).expect("canned");
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({
            "canned": "canned.json",
            "counters": {
                "positive_hits": 0, "positive_misses": 1, "negative_hits": 0,
                "inserts": 0, "insert_refused_full": 0,
                "negative_inserts": 0, "negative_refused_full": 0,
                "tombstone_inserts": 0, "tombstone_refused_full": 0,
                "expired_evictions": 0, "reuse_detected": 0,
                "refresh_throttled": 0, "deadline_trips": 0,
                "scan_budget_trips": 0, "symlink_refused": 0,
                "denied": 1, "not_host_path": 0, "gone_during_scan": 0,
                "migration_skipped": 1, "pid_lifetime_refused_full": 0,
                "saturated": false,
            },
        }),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    // Positive control: the valid response keeps its meaning.
    assert_eq!(finished.rows.len(), 1);
    assert_eq!(
        finished.rows[0].evidence.status,
        AttributionStatus::Unresolved
    );
    // The typed aggregate carries the approved counters.
    let diagnostics = finished.diagnostics.as_ref().expect("diagnostics measured");
    assert_eq!(diagnostics.denied, 1);
    assert_eq!(diagnostics.migration_skipped, 1);
    assert_eq!(diagnostics.positive_misses, 1);
    assert!(!diagnostics.saturated);
    // The approved counters surface on the public completion.
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains("denied=1"),
        "completion surfaces denied=1:\n{text}"
    );
    assert!(
        text.contains("migration_skipped=1"),
        "completion surfaces migration_skipped=1:\n{text}"
    );
    assert!(
        text.contains("helper-diagnostics: positive_hits="),
        "completion carries the diagnostics section:\n{text}"
    );
}

/// F07 shared canned bytes: a valid unresolved response for the
/// finish fixture key (cgroup 42, tgid 100, start 555), via the
/// frozen pure resolver with empty entries.
fn f07_unresolved_canned(dir: &std::path::Path) {
    use kryprobe_core::workload::{
        KernelIdentity, MetadataSnapshot, SnapshotInterval, SnapshotKey, SnapshotRequest,
    };
    let request = SnapshotRequest {
        session_id: "00000000000000000000000000000000".to_string(),
        keys: vec![SnapshotKey {
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
        entries: Vec::new(),
    };
    let response = kryprobe_core::workload::resolve(&request, &snapshot).expect("resolves");
    let canned = kryprobe_core::workload::encode_response(&response).expect("encodes");
    std::fs::write(dir.join("canned.json"), &canned).expect("canned");
}

/// F07 shared golden counters: every approved field present.
fn f07_counters() -> serde_json::Value {
    serde_json::json!({
        "positive_hits": 0, "positive_misses": 1, "negative_hits": 0,
        "inserts": 0, "insert_refused_full": 0,
        "negative_inserts": 0, "negative_refused_full": 0,
        "tombstone_inserts": 0, "tombstone_refused_full": 0,
        "expired_evictions": 0, "reuse_detected": 0,
        "refresh_throttled": 0, "deadline_trips": 0,
        "scan_budget_trips": 0, "symlink_refused": 0,
        "denied": 1, "not_host_path": 0, "gone_during_scan": 0,
        "migration_skipped": 1, "pid_lifetime_refused_full": 0,
        "saturated": false,
    })
}

/// Malformed diagnostics at CLI level: the valid response keeps its
/// meaning while the completion marks diagnostics unavailable —
/// never echoing the raw line — and the unresolved row keeps its
/// numeric context.
#[test]
fn malformed_helper_diagnostics_keep_response_mark_unavailable() {
    use kryprobe_core::workload::AttributionStatus;
    let scratch = kryprobe_testkit::TempDir::named("cli-diag-malformed").expect("scratch");
    f07_unresolved_canned(scratch.path());
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"canned": "canned.json", "counters_line": "GARBAGE-COUNT\x00ERS{"}),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(finished.rows.len(), 1);
    assert_eq!(
        finished.rows[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert_eq!(finished.diagnostics, None);
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains("helper-diagnostics: unavailable"),
        "completion marks diagnostics unavailable:\n{text}"
    );
    assert!(
        !text.contains("GARBAGE-COUNT"),
        "raw record never echoes:\n{text}"
    );
    assert!(
        text.contains("7 42 100 1000 555 proc 20"),
        "unavailable row keeps numeric context:\n{text}"
    );
}

/// Unknown counters at CLI level: not approved fields, so the
/// aggregate marks unavailable while the response stays valid.
#[test]
fn unknown_helper_counter_marks_unavailable() {
    use kryprobe_core::workload::AttributionStatus;
    let scratch = kryprobe_testkit::TempDir::named("cli-diag-unknown").expect("scratch");
    f07_unresolved_canned(scratch.path());
    let mut counters = f07_counters();
    counters["mystery_counter"] = serde_json::json!(9);
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"canned": "canned.json", "counters": counters}),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(
        finished.rows[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert_eq!(finished.diagnostics, None);
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains("helper-diagnostics: unavailable"),
        "completion marks diagnostics unavailable:\n{text}"
    );
    assert!(
        !text.contains("mystery_counter"),
        "unknown field never surfaces:\n{text}"
    );
}

/// Forged private paths at CLI level: a path string smuggled into
/// the counters record is not a measurement, and the forged string
/// never reaches CLI output.
#[test]
fn forged_helper_path_never_reaches_cli_output() {
    use kryprobe_core::workload::AttributionStatus;
    let scratch = kryprobe_testkit::TempDir::named("cli-diag-forged").expect("scratch");
    f07_unresolved_canned(scratch.path());
    let mut counters = f07_counters();
    counters["denied"] = serde_json::json!("/proc/self/root/etc/shadow-f07");
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"canned": "canned.json", "counters": counters}),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(
        finished.rows[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert_eq!(finished.diagnostics, None);
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains("helper-diagnostics: unavailable"),
        "completion marks diagnostics unavailable:\n{text}"
    );
    assert!(
        !text.contains("shadow-f07"),
        "forged path never reaches output:\n{text}"
    );
    assert!(
        text.contains("7 42 100 1000 555 proc 20"),
        "unavailable row keeps numeric context:\n{text}"
    );
}

/// Absent diagnostics at CLI level: the echo helper emits no record,
/// so the completion marks unavailable while rows keep numerics.
#[test]
fn absent_helper_diagnostics_mark_unavailable() {
    use kryprobe_core::workload::AttributionStatus;
    let scratch = kryprobe_testkit::TempDir::named("cli-diag-absent").expect("scratch");
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({"echo_unresolved": true}),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(
        finished.rows[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert_eq!(finished.diagnostics, None);
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains("helper-diagnostics: unavailable"),
        "completion marks diagnostics unavailable:\n{text}"
    );
    assert!(
        text.contains("7 42 100 1000 555 proc 20"),
        "unavailable row keeps numeric context:\n{text}"
    );
}

/// Multi-chunk aggregation at CLI level: every chunk's `denied=1`
/// folds into the completion aggregate (checked sum over serves).
#[test]
fn helper_diagnostics_aggregate_across_chunks() {
    use kryprobe_core::workload::SnapshotKey;
    let scratch = kryprobe_testkit::TempDir::named("cli-diag-chunks").expect("scratch");
    // 120 distinct triples: under the count cap, over the byte
    // budget as one request (proven split shape).
    let keys: Vec<SnapshotKey> = (0..120u64)
        .map(|i| SnapshotKey {
            kernel_scope: "test-scope".to_string(),
            cgroup: 1000 + i,
            tgid: 2000 + i as u32,
            start_ns: 555,
        })
        .collect();
    let rows: Vec<JoinedRow> = keys
        .iter()
        .enumerate()
        .map(|(n, key)| joined_row(n as u64, key.cgroup, key.tgid, 1, "cbc(aes)"))
        .collect();
    let helper = stage_fixture(
        scratch.path(),
        "helper",
        serde_json::json!({
            "echo_unresolved": true,
            "count": "count",
            "counters": f07_counters(),
        }),
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
    let serves = std::fs::read_to_string(scratch.path().join("count"))
        .expect("serves counted")
        .lines()
        .count() as u64;
    assert!(serves > 1, "more than one bounded request served: {serves}");
    assert_eq!(finished.rows.len(), 120);
    // Each chunk measured denied=1: the aggregate sums the serves.
    let diagnostics = finished.diagnostics.as_ref().expect("diagnostics measured");
    assert_eq!(diagnostics.denied, serves);
    assert_eq!(diagnostics.migration_skipped, serves);
    assert!(!diagnostics.saturated);
    let text = kryprobe_cli::workload::render_workload_text(&outcome, &finished);
    assert!(
        text.contains(&format!("denied={serves}")),
        "completion surfaces the aggregate:\n{text}"
    );
}
