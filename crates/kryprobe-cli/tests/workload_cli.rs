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
    }
}

fn launchable_preflight(
    helper: &std::path::Path,
) -> kryprobe_privilege::workload_launch::WorkloadPreflight {
    kryprobe_privilege::workload_launch::WorkloadPreflight {
        helper: Some(helper.to_path_buf()),
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

fn fixture_script(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("fixture written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// Honest attestation snippet (same shape as the launch-module
/// fixtures): the launcher verifies the real confinement of every
/// fixture serve below.
const HONEST_ATTEST: &str = r#"
honest_attestation() {
    uid=$(awk '/^Uid:/{print $2}' /proc/self/status)
    euid=$(awk '/^Uid:/{print $3}' /proc/self/status)
    gid=$(awk '/^Gid:/{print $2}' /proc/self/status)
    egid=$(awk '/^Gid:/{print $3}' /proc/self/status)
    caps="1"
    if [ "$(awk '/^CapEff:/{print $2}' /proc/self/status)" = "0000000000000000" ] \
        && [ "$(awk '/^CapPrm:/{print $2}' /proc/self/status)" = "0000000000000000" ] \
        && [ "$(awk '/^CapInh:/{print $2}' /proc/self/status)" = "0000000000000000" ] \
        && [ "$(awk '/^CapAmb:/{print $2}' /proc/self/status)" = "0000000000000000" ]; then
        caps="0"
    fi
    if [ "$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status)" = "1" ]; then nnp="true"; else nnp="false"; fi
    fds=$(ls /proc/self/fd | sort -n | sed '$d' | paste -sd, -)
    printf '{"attestation":{"uid":%s,"euid":%s,"gid":%s,"egid":%s,"caps":{"eff":"%s","prm":"%s","inh":"%s","amb":"%s"},"no_new_privs":%s,"fds":[%s]}}\n' \
        "$uid" "$euid" "$gid" "$egid" "$caps" "$caps" "$caps" "$caps" "$nnp" "$fds"
}
"#;

/// Wrong-kernel metadata at CLI level: the helper answers (transport
/// fine), but the snapshot kernel differs — the key refuses typed,
/// the row stays unresolved, metadata coverage reads partial.
#[test]
fn wrong_kernel_folds_to_partial_metadata() {
    let scratch = kryprobe_testkit::TempDir::named("cli-wrong-kernel").expect("scratch");
    // The request key is fixed by the finish fixture (single row:
    // cgroup 42, tgid 100, start 555, scope test-scope); only the
    // minted session varies, so the fixture substitutes it in.
    let helper = fixture_script(
        scratch.path(),
        "helper",
        &format!(
            "#!/bin/sh\nset -eu\n{HONEST_ATTEST}\n\
             req=$(cat)\n\
             session=$(printf '%s' \"$req\" | sed -n 's/.*\"session_id\":\"\\([0-9a-f]*\\)\".*/\\1/p')\n\
             honest_attestation >&2\n\
             printf '{{\"session_id\":\"%s\",\"kernel_identity\":{{\"known\":\"other-scope\"}},\
\"associations\":[],\
\"errors\":[{{\"key\":{{\"kernel_scope\":\"test-scope\",\"cgroup\":42,\"tgid\":100,\"start_ns\":555}},\
\"code\":\"kernel_mismatch\",\"detail\":\"kernel_differs\"}}],\
\"status\":\"complete\",\"chunk\":{{\"index\":0,\"total\":1}},\
\"counters\":{{\"resolved\":0,\"unresolved\":0,\"refused\":1}}}}' \"$session\"\n"
        ),
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
    let helper = fixture_script(
        scratch.path(),
        "helper",
        &format!(
            "#!/bin/sh\nset -eu\n{HONEST_ATTEST}\n\
             req=$(cat)\n\
             session=$(printf '%s' \"$req\" | sed -n 's/.*\"session_id\":\"\\([0-9a-f]*\\)\".*/\\1/p')\n\
             honest_attestation >&2\n\
             sed \"s/00000000000000000000000000000000/$session/\" '{canned}'\n",
            canned = canned_path.display(),
        ),
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
    let helper = fixture_script(
        scratch.path(),
        "helper",
        &format!(
            "#!/bin/sh\nset -eu\n{HONEST_ATTEST}\n\
             req=$(cat)\n\
             session=$(printf '%s' \"$req\" | sed -n 's/.*\"session_id\":\"\\([0-9a-f]*\\)\".*/\\1/p')\n\
             honest_attestation >&2\n\
             sed \"s/00000000000000000000000000000000/$session/\" '{canned}'\n",
            canned = canned_path.display(),
        ),
    );
    let outcome = finish_outcome(launchable_preflight(&helper));
    let finished = finish_workload_report(&outcome, &finish_opts()).expect("finishes");
    assert_eq!(finished.rows.len(), 1);
    assert!(finished.rows[0].identity.is_resolved());
    assert_eq!(finished.rows[0].evidence.status, AttributionStatus::Stale);
}

/// Helper crash at CLI level: the serve retries, then the finish
/// degrades to raw-ID rows plus typed unavailability — data, never
/// an error (enrichment cannot stall capture).
#[test]
fn helper_crash_degrades_to_raw_ids() {
    let scratch = kryprobe_testkit::TempDir::named("cli-crash").expect("scratch");
    let helper = fixture_script(scratch.path(), "helper", "#!/bin/sh\nset -eu\nkill -9 $$\n");
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
