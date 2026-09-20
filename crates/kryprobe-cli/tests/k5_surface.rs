// SPDX-License-Identifier: GPL-3.0-or-later
//! K5 Task 5: CLI surface integration tests (WHO block, policy keys,
//! token verb, doctor probe). Hermetic and unprivileged unless noted;
//! the one root-only mint leg uses a `--bin` temp copy (never the
//! default exe target) plus a temp `--receipt`.

use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegrityRef, NativeObservation, NativeResult,
    ValidityInterval,
};
use kryprobe_core::ids::ObservationId;

// ---------------------------------------------------------------------------
// Policy keys (K5: `comm` glob + `uid` u32).
// ---------------------------------------------------------------------------

#[test]
fn k5_policy_uid_key() {
    assert!(
        kryprobe_policy::parse_rule(
            "id: x\nsource: kernel-crypto\nmatch: {uid: 1000}\ndecision: deny"
        )
        .is_ok()
    );
    assert!(
        kryprobe_policy::parse_rule(
            "id: x\nsource: kernel-crypto\nmatch: {uid: root}\ndecision: deny"
        )
        .is_err()
    );
}

/// One `row="who"` observation with the given identity (hand-shaped
/// Task 4 payload subset: the WHO/policy surface reads only these keys).
fn who_obs(id: u64, comm: &str, uid: u64, tgid: u64, kh: u64, calls: u64) -> NativeObservation {
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
            "stack": {"id": 3, "frames": []},
            "calls": calls,
            "first_ns": 100,
            "last_ns": 200,
        }),
    }
}

fn complete_coverage() -> CoverageSummary {
    let dim = || {
        DimensionCoverage::new(
            CoverageStatus::CompleteForDeclaredBoundary,
            ValidityInterval {
                start_ns: 100,
                end_ns: Some(200),
            },
        )
    };
    CoverageSummary {
        target_population: dim(),
        object_discovery: dim(),
        attachment: dim(),
        aggregate_counts: dim(),
        detailed_events: dim(),
        attribution: dim(),
        correlation: dim(),
        completion: dim(),
    }
}

#[test]
fn k5_policy_comm_glob_matches_who_rows() {
    let policy = kryprobe_policy::parse_policy(
        "version: 1\nrules:\n  - id: no-python\n    source: kernel-crypto\n    match: {comm: 'py*'}\n    decision: deny\n",
    )
    .expect("comm glob parses");
    let obs = vec![
        who_obs(1, "python3", 1000, 100, 11, 7),
        who_obs(2, "nginx", 1000, 200, 22, 9),
    ];
    match kryprobe_policy::evaluate(&policy, &obs, &complete_coverage()) {
        kryprobe_policy::PolicyVerdict::Violation { rule, obs_ids, .. } => {
            assert_eq!(rule, "no-python");
            assert_eq!(obs_ids, vec![ObservationId::new(1)]);
        }
        other => panic!("expected comm violation, got {other:?}"),
    }
}

#[test]
fn k5_policy_uid_exact_matches_who_rows() {
    let policy = kryprobe_policy::parse_policy(
        "version: 1\nrules:\n  - id: no-root\n    source: kernel-crypto\n    match: {uid: 0}\n    decision: deny\n",
    )
    .expect("uid rule parses");
    let obs = vec![
        who_obs(1, "python3", 1000, 100, 11, 7),
        who_obs(2, "cron", 0, 300, 33, 5),
    ];
    match kryprobe_policy::evaluate(&policy, &obs, &complete_coverage()) {
        kryprobe_policy::PolicyVerdict::Violation { rule, obs_ids, .. } => {
            assert_eq!(rule, "no-root");
            assert_eq!(obs_ids, vec![ObservationId::new(2)]);
        }
        other => panic!("expected uid violation, got {other:?}"),
    }
    // A uid that matches nothing on complete coverage is CLEAN (the key
    // constrains; it does not poison).
    let policy = kryprobe_policy::parse_policy(
        "version: 1\nrules:\n  - id: no-nobody\n    source: kernel-crypto\n    match: {uid: 65534}\n    decision: deny\n",
    )
    .expect("uid rule parses");
    assert_eq!(
        kryprobe_policy::evaluate(&policy, &obs, &complete_coverage()),
        kryprobe_policy::PolicyVerdict::Clean
    );
}

// ---------------------------------------------------------------------------
// WHO block render (K5: `KH TGID COMM UID CALLS`, top 32 by calls).
// ---------------------------------------------------------------------------

/// `n` distinct who rows (one id each; calls 1..=n so row `i` sorts
/// above every lower row).
fn who_fixture(n: u64) -> Vec<NativeObservation> {
    (1..=n)
        .map(|i| {
            who_obs(
                i,
                &format!("proc{i}"),
                1000 + (i % 3),
                1000 + i,
                0x1000 + i,
                i,
            )
        })
        .collect()
}

#[test]
fn k5_who_block_renders_top32() {
    let text = kryprobe_cli::cmd_watch::render_who_block(&who_fixture(40));
    assert_eq!(text.lines().count(), 1 + 32 + 1); // header + rows + "+N more"
    assert!(text.contains("+8 more"));
}

#[test]
fn k5_who_block_empty_renders_none() {
    assert_eq!(
        kryprobe_cli::cmd_watch::render_who_block(&[]),
        "WHO: none\n"
    );
    // Non-who rows do not feed the block either.
    let mut agg = who_obs(1, "x", 0, 1, 1, 1);
    agg.backend_payload["row"] = serde_json::json!("agg");
    assert_eq!(
        kryprobe_cli::cmd_watch::render_who_block(&[agg]),
        "WHO: none\n"
    );
}

#[test]
fn k5_who_block_sorts_calls_desc_latest_wins() {
    // Two ticks of the same (kh, tgid): the later cumulative row wins
    // (7, never 5+7); rows sort by calls desc.
    let rows = vec![
        who_obs(1, "old", 1000, 100, 0xaaaa, 5),
        who_obs(2, "small", 1000, 200, 0xbbbb, 3),
        who_obs(3, "new", 1000, 100, 0xaaaa, 7),
    ];
    let text = kryprobe_cli::cmd_watch::render_who_block(&rows);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "KH TGID COMM UID CALLS");
    assert_eq!(lines.len(), 3, "header + 2 rows, no trailer:\n{text}");
    assert!(
        lines[1].contains(" 100 ") && lines[1].ends_with(" 7"),
        "{text:?}"
    );
    assert!(lines[1].contains("new"), "{text:?}");
    assert!(
        lines[2].contains("small") && lines[2].ends_with(" 3"),
        "{text:?}"
    );
}

// ---------------------------------------------------------------------------
// File-capability xattr encode (K5: setcap fallback for `token mint`).
// ---------------------------------------------------------------------------

#[test]
fn k5_cap_xattr_golden() {
    // VERIFIED bytes: `setcap cap_bpf,cap_perfmon+ep` on a scratch copy
    // yields exactly this `security.capability` value on this host, and
    // writing these bytes back round-trips through `getcap` (see the
    // Task 5 report for the exact commands).
    let got = kryprobe_cli::cmd_token::encode_capability_xattr(&[38, 39]);
    assert_eq!(
        got,
        [
            0x01, 0x00, 0x00, 0x02, // magic_etc (rev + EFFECTIVE)
            0x00, 0x00, 0x00, 0x00, // data[0].permitted
            0x00, 0x00, 0x00, 0x00, // data[0].inheritable
            0xC0, 0x00, 0x00, 0x00, // data[1].permitted (bits 38, 39)
            0x00, 0x00, 0x00, 0x00, // data[1].inheritable
        ]
    );
}

#[test]
fn k5_cap_xattr_low_cap_matches_ping() {
    // Second empirical pin: `/usr/bin/ping` (`cap_net_raw=ep`, cap 13)
    // reads back exactly these bytes on this host.
    let got = kryprobe_cli::cmd_token::encode_capability_xattr(&[13]);
    assert_eq!(
        got,
        [
            0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    );
    // Empty set: magic only, no permitted bits.
    let got = kryprobe_cli::cmd_token::encode_capability_xattr(&[]);
    assert_eq!(&got[..4], &[0x01, 0x00, 0x00, 0x02]);
    assert!(got[4..].iter().all(|b| *b == 0));
}

// ---------------------------------------------------------------------------
// CLI driver + live no-mechanism pre-flight (K5: exit 4 names `token mint`).
// ---------------------------------------------------------------------------

/// Runs the CLI library in-process, capturing stdout/stderr.
fn run_cli(argv: &[&str]) -> (i32, String, String) {
    let argv: Vec<String> = argv.iter().map(|word| (*word).to_owned()).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = kryprobe_cli::run(&argv, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).expect("stdout utf-8"),
        String::from_utf8(stderr).expect("stderr utf-8"),
    )
}

fn is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

/// Serializes the pre-flight legs: they read (and one writes)
/// `KRYPROBE_TOKEN`, which is process-global.
static K5_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn k5_env_guard() -> std::sync::MutexGuard<'static, ()> {
    K5_ENV_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn restore_token_env(prior: Option<std::ffi::OsString>) {
    match prior {
        // SAFETY: held under K5_ENV_LOCK.
        Some(value) => unsafe { std::env::set_var("KRYPROBE_TOKEN", value) },
        None => unsafe { std::env::remove_var("KRYPROBE_TOKEN") },
    }
}

/// Pre-flight test env: a scratch garbage object behind tier-1
/// `KRYPROBE_BPF_DIR` (locates + reads, never loads — the pre-flight
/// refuses first) plus the requested `KRYPROBE_TOKEN` state. Returns
/// both priors + the scratch dir; the caller restores via
/// [`k5_restore_env`]. Call only under [`k5_env_guard`].
fn k5_preflight_env(
    token_env: Option<&str>,
) -> (
    Option<std::ffi::OsString>,
    Option<std::ffi::OsString>,
    std::path::PathBuf,
) {
    let dir = std::env::temp_dir().join(format!("kryprobe-k5-preflight-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    std::fs::write(dir.join("garbage.o"), b"k5-garbage-object").expect("write garbage object");
    let bpf_prior = std::env::var_os("KRYPROBE_BPF_DIR");
    // SAFETY: held under K5_ENV_LOCK; restored before the guard drops.
    unsafe { std::env::set_var("KRYPROBE_BPF_DIR", dir.join("garbage.o")) };
    let token_prior = std::env::var_os("KRYPROBE_TOKEN");
    match token_env {
        // SAFETY: held under K5_ENV_LOCK; restored before the guard drops.
        Some(value) => unsafe { std::env::set_var("KRYPROBE_TOKEN", value) },
        None => unsafe { std::env::remove_var("KRYPROBE_TOKEN") },
    }
    (bpf_prior, token_prior, dir)
}

fn k5_restore_env(
    bpf_prior: Option<std::ffi::OsString>,
    token_prior: Option<std::ffi::OsString>,
    dir: &std::path::Path,
) {
    match bpf_prior {
        // SAFETY: held under K5_ENV_LOCK.
        Some(value) => unsafe { std::env::set_var("KRYPROBE_BPF_DIR", value) },
        None => unsafe { std::env::remove_var("KRYPROBE_BPF_DIR") },
    }
    restore_token_env(token_prior);
    std::fs::remove_dir_all(dir).ok();
}

static K5_FAKE_CAPS: kryprobe_core::backend::BackendCapabilities =
    kryprobe_core::backend::BackendCapabilities {
        backend: kryprobe_core::enums::BackendId::KCrypto,
        name: "k5-fake-kcrypto",
        required: kryprobe_core::plan::CapabilityRequirements {
            uprobe_multi: false,
            cookies: false,
            ringbuf: false,
            btf: false,
        },
    };

/// Fake kcrypto-id backend that sails through detect/plan/configure so
/// the run reaches BPF bring-up (where the no-mechanism pre-flight
/// refuses unprivileged runs before any attach).
struct K5Fake;

impl kryprobe_core::backend::Backend for K5Fake {
    fn id(&self) -> kryprobe_core::enums::BackendId {
        kryprobe_core::enums::BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static kryprobe_core::backend::BackendCapabilities {
        &K5_FAKE_CAPS
    }

    fn detect(
        &self,
        _ctx: &kryprobe_core::backend::DetectContext<'_>,
    ) -> Result<Vec<kryprobe_core::backend::DetectedInstance>, kryprobe_core::error::BackendError>
    {
        Ok(vec![kryprobe_core::backend::DetectedInstance {
            backend: kryprobe_core::enums::BackendId::KCrypto,
            object: None,
            detail: "k5 fake instance".to_owned(),
        }])
    }

    fn plan(
        &self,
        _ctx: &kryprobe_core::backend::PlanContext<'_>,
        _instance: &kryprobe_core::backend::DetectedInstance,
        _mode: kryprobe_core::enums::CaptureMode,
    ) -> Result<kryprobe_core::backend::BackendPlan, kryprobe_core::error::BackendError> {
        Ok(kryprobe_core::backend::BackendPlan {
            backend: kryprobe_core::enums::BackendId::KCrypto,
            probes: Vec::new(),
            required: K5_FAKE_CAPS.required,
        })
    }

    fn configure(
        &self,
        _ctx: &mut kryprobe_core::backend::ConfigureContext<'_>,
        _plan: &kryprobe_core::backend::BackendPlan,
    ) -> Result<(), kryprobe_core::error::BackendError> {
        Ok(())
    }

    fn decode(
        &self,
        _ctx: &kryprobe_core::backend::DecodeContext<'_>,
        _event: kryprobe_core::backend::RawEvent<'_>,
    ) -> Result<kryprobe_core::evidence::NativeObservation, kryprobe_core::error::BackendError>
    {
        panic!("k5 fake decode must not run: pre-flight refuses first");
    }

    fn finalize(
        &self,
        _ctx: &kryprobe_core::backend::FinalizeContext<'_>,
    ) -> Result<kryprobe_core::backend::BackendSummary, kryprobe_core::error::BackendError> {
        panic!("k5 fake finalize must not run: pre-flight refuses first");
    }
}

fn k5_registry() -> kryprobe_core::backend::BackendRegistry {
    let mut registry = kryprobe_core::backend::BackendRegistry::new();
    registry.register(Box::new(K5Fake)).expect("fake registers");
    registry
}

fn k5_open_runtime() -> kryprobe_core::capability::RuntimeCapabilities {
    kryprobe_core::capability::RuntimeCapabilities {
        kernel_release: "test".to_owned(),
        uprobe_multi: true,
        cookies: true,
        ringbuf: true,
        btf_present: true,
        userns: true,
        yama_scope: 0,
        caps: Vec::new(),
    }
}

#[test]
fn k5_live_no_mechanism_names_mint() {
    if is_root() {
        println!("SKIP: k5_live_no_mechanism_names_mint needs unprivileged euid");
        return;
    }
    let _guard = k5_env_guard();
    let (bpf_prior, token_prior, dir) = k5_preflight_env(None);
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(0),
        tick_ms: 1000,
        token: None,
    };
    let err = kryprobe_cli::live::run_live_capture_with_registry(
        &cfg,
        &k5_open_runtime(),
        &k5_registry(),
    )
    .expect_err("unpriv + no token must refuse");
    k5_restore_env(bpf_prior, token_prior, &dir);
    match err {
        kryprobe_cli::live::LiveError::Unusable(reason) => {
            assert!(
                reason.contains("kryprobe token mint"),
                "names the remedy, got: {reason}"
            );
            assert!(
                reason.contains("/sys/fs/bpf/kryprobe/token"),
                "names the default pin, got: {reason}"
            );
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Doctor `token_delegated` probe (K5: pass|skipped|denied, never gates).
// ---------------------------------------------------------------------------

#[test]
fn k5_doctor_reports_token_delegated() {
    let (code, stdout, _) = run_cli(&["kryprobe", "doctor"]);
    assert_eq!(code, 0);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("probe token_delegated:"))
        .expect("token_delegated row");
    assert!(
        line.contains("pass:") || line.contains("skipped:") || line.contains("denied:"),
        "probe outcome shape: {line}"
    );
}

#[test]
fn k5_doctor_json_includes_token_delegated() {
    let (code, stdout, _) = run_cli(&["kryprobe", "doctor", "--json"]);
    assert_eq!(code, 0);
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("doctor json parses");
    let probes = doc["probes"].as_array().expect("probes array");
    let probe = probes
        .iter()
        .find(|probe| probe["name"] == "token_delegated")
        .expect("token_delegated probe");
    let outcome = probe["outcome"].as_str().expect("outcome str");
    assert!(
        ["pass", "skipped", "denied"].contains(&outcome),
        "bad outcome {outcome}"
    );
}

#[test]
fn k5_doctor_token_delegated_matrix() {
    use kryprobe_cli::cmd_doctor::token_delegated_outcome;
    use kryprobe_cli::cmd_token::PinState;
    use kryprobe_privilege::ProbeOutcome;
    let bpf_caps = vec!["CAP_BPF".to_owned()];
    // Usable pin passes even without caps.
    assert!(matches!(
        token_delegated_outcome(&PinState::Usable, &[]),
        ProbeOutcome::Pass { .. }
    ));
    // Effective cap_bpf passes without any pin.
    assert!(matches!(
        token_delegated_outcome(&PinState::Absent, &bpf_caps),
        ProbeOutcome::Pass { .. }
    ));
    // Present-but-unusable pin without caps is denied (names why).
    let denied_stage =
        match token_delegated_outcome(&PinState::PresentUnusable("errno 22".to_owned()), &[]) {
            ProbeOutcome::Denied { stage, .. } => stage,
            _ => panic!("expected denied"),
        };
    assert!(denied_stage.contains("errno 22"), "{denied_stage}");
    // Neither mechanism is a skip, never a denial.
    assert!(matches!(
        token_delegated_outcome(&PinState::Absent, &[]),
        ProbeOutcome::Skipped { .. }
    ));
}

// ---------------------------------------------------------------------------
// `token status` (K5: never privileged, never crashes).
// ---------------------------------------------------------------------------

#[test]
fn k5_token_status_reports_caps_and_pin() {
    // The test binary carries no file caps and no pin exists on this
    // box: both lines render their honest negative, exit 0.
    let (code, stdout, _) = run_cli(&["kryprobe", "token", "status"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "caps + pin lines: {stdout:?}");
    assert_eq!(lines[0], "caps: none not-effective");
    assert_eq!(lines[1], "pin: absent unreadable");
}

#[test]
fn k5_token_status_default_bin_is_current_exe() {
    // `--bin` pointing at our own exe renders byte-identical output to
    // the default (pins the default-target rule without privilege).
    let exe = std::env::current_exe().expect("current exe");
    let (_, default_out, _) = run_cli(&["kryprobe", "token", "status"]);
    let (code, explicit_out, _) = run_cli(&[
        "kryprobe",
        "token",
        "status",
        "--bin",
        exe.to_str().expect("utf-8 exe"),
    ]);
    assert_eq!(code, 0);
    assert_eq!(explicit_out, default_out);
}

#[test]
fn k5_token_status_missing_bin_reports_unreadable() {
    let (code, stdout, _) = run_cli(&[
        "kryprobe",
        "token",
        "status",
        "--bin",
        "/nonexistent-k5-zzz",
    ]);
    assert_eq!(code, 0, "missing xattr/file reports, never crashes");
    assert!(
        stdout.contains("caps: unreadable ("),
        "reason carried: {stdout:?}"
    );
    assert!(
        stdout.contains("pin: "),
        "pin line still present: {stdout:?}"
    );
}

#[test]
fn k5_cap_xattr_decode_roundtrip() {
    use kryprobe_cli::cmd_token::{decode_capability_xattr, encode_capability_xattr};
    // Encode/decode round-trip, effective flag preserved.
    assert_eq!(
        decode_capability_xattr(&encode_capability_xattr(&[38, 39])),
        Some((vec![38, 39], true))
    );
    // Ping-shaped bytes decode to cap 13.
    assert_eq!(
        decode_capability_xattr(&encode_capability_xattr(&[13])),
        Some((vec![13], true))
    );
    // 12-byte rev-1 shape decodes its single pair.
    let rev1 = [
        0x01, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(decode_capability_xattr(&rev1), Some((vec![13], true)));
    // Corrupt shapes are `None` (callers report, never crash).
    assert_eq!(decode_capability_xattr(&[]), None);
    assert_eq!(decode_capability_xattr(&[0u8; 7]), None);
    let mut bad_magic = encode_capability_xattr(&[13]);
    bad_magic[3] = 0x09;
    assert_eq!(decode_capability_xattr(&bad_magic), None);
}

#[test]
fn k5_cap_display_name_pins_verified_positions() {
    // Header-verified positions (`capsh --decode` cross-checked): the
    // broadcast/admin/perfmon/bpf/restore slots that neighbor tables
    // misplace, plus the numeric fallback past the table.
    use kryprobe_cli::cmd_token::cap_display_name;
    assert_eq!(cap_display_name(11), "cap_net_broadcast");
    assert_eq!(cap_display_name(13), "cap_net_raw");
    assert_eq!(cap_display_name(21), "cap_sys_admin");
    assert_eq!(cap_display_name(38), "cap_perfmon");
    assert_eq!(cap_display_name(39), "cap_bpf");
    assert_eq!(cap_display_name(40), "cap_checkpoint_restore");
    assert_eq!(cap_display_name(63), "cap_63");
}

// ---------------------------------------------------------------------------
// `token mint` (K5: root setcap one-shot + receipt).
// ---------------------------------------------------------------------------

#[test]
fn k5_token_mint_unpriv_refuses_exit4() {
    if is_root() {
        println!("SKIP: k5_token_mint_unpriv_refuses_exit4 needs unprivileged euid");
        return;
    }
    let (code, stdout, stderr) =
        run_cli(&["kryprobe", "token", "mint", "--bin", "/tmp/k5-mint-refuse"]);
    assert_eq!(code, 4);
    assert!(stdout.is_empty(), "refusal prints no stdout: {stdout:?}");
    assert!(stderr.contains("root"), "names the need: {stderr:?}");
}

#[test]
fn k5_token_mint_roundtrip_as_root() {
    if !is_root() {
        println!("SKIP: k5_token_mint_roundtrip_as_root needs root");
        return;
    }
    let dir = std::env::temp_dir().join(format!("kryprobe-k5-mint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let bin = dir.join("mint-copy");
    std::fs::copy("/bin/true", &bin).expect("copy scratch binary");
    let receipt = dir.join("receipt.json");
    let bin_str = bin.to_str().expect("utf-8 bin").to_owned();
    let receipt_str = receipt.to_str().expect("utf-8 receipt").to_owned();

    // Mint: exit 0, stdout is exactly one JSON object, nothing else.
    let (code, stdout, stderr) = run_cli(&[
        "kryprobe",
        "token",
        "mint",
        "--bin",
        &bin_str,
        "--receipt",
        &receipt_str,
    ]);
    assert_eq!(code, 0, "stderr: {stderr:?}");
    assert_eq!(stdout.lines().count(), 1, "one JSON object: {stdout:?}");
    assert!(!stderr.is_empty(), "human hints ride stderr");
    let doc: serde_json::Value = serde_json::from_str(stdout.trim_end()).expect("receipt parses");
    assert_eq!(doc["mechanism"], "setcap");
    assert_eq!(doc["binary"], bin_str);
    assert_eq!(doc["caps"], serde_json::json!(["cap_bpf", "cap_perfmon"]));
    assert_eq!(doc["effective"], true);
    assert!(!doc["kernel"].as_str().unwrap_or("").is_empty());
    assert!(doc["time"].as_str().unwrap_or("").ends_with('Z'));
    // The file copy is byte-identical to stdout.
    assert_eq!(
        std::fs::read_to_string(&receipt).expect("read receipt"),
        stdout
    );
    // `status` on the minted copy sees the grant.
    let (code, stdout, _) = run_cli(&["kryprobe", "token", "status", "--bin", &bin_str]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("caps: cap_perfmon,cap_bpf effective"),
        "grant visible: {stdout:?}"
    );
    // Re-mint over the existing receipt without `--force` refuses (exit 2).
    let (code, _, stderr) = run_cli(&[
        "kryprobe",
        "token",
        "mint",
        "--bin",
        &bin_str,
        "--receipt",
        &receipt_str,
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--force"), "names the override: {stderr:?}");
    // `--force` overwrites.
    let (code, _, _) = run_cli(&[
        "kryprobe",
        "token",
        "mint",
        "--bin",
        &bin_str,
        "--receipt",
        &receipt_str,
        "--force",
    ]);
    assert_eq!(code, 0);
    // Missing `--bin` target is invalid input (exit 2), not a crash.
    let missing = dir.join("nope");
    let (code, _, _) = run_cli(&[
        "kryprobe",
        "token",
        "mint",
        "--bin",
        missing.to_str().expect("utf-8"),
    ]);
    assert_eq!(code, 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn k5_receipt_json_shape() {
    let doc: serde_json::Value =
        serde_json::from_str(&kryprobe_cli::cmd_token::mint_receipt_json("b", "k", "t"))
            .expect("receipt parses");
    assert_eq!(doc["mechanism"], "setcap");
    assert_eq!(doc["binary"], "b");
    assert_eq!(doc["caps"], serde_json::json!(["cap_bpf", "cap_perfmon"]));
    assert_eq!(doc["effective"], true);
    assert_eq!(doc["kernel"], "k");
    assert_eq!(doc["time"], "t");
}

#[test]
fn k5_format_unix_utc_pins_shape() {
    use kryprobe_cli::cmd_token::format_unix_utc;
    assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(format_unix_utc(2_147_483_647), "2038-01-19T03:14:07Z");
    let now = kryprobe_cli::cmd_token::utc_now_string();
    assert_eq!(now.len(), 20, "RFC3339 UTC shape: {now}");
    assert!(now.ends_with('Z') && now.starts_with("20"), "{now}");
}

// ---------------------------------------------------------------------------
// Token discovery order + no-mechanism reason (K5: `--token` > env > pin).
// ---------------------------------------------------------------------------

#[test]
fn k5_token_candidates_order() {
    use kryprobe_cli::cmd_token::token_candidates;
    use std::path::PathBuf;
    let pin = PathBuf::from("/sys/fs/bpf/kryprobe/token");
    assert_eq!(
        token_candidates(Some(PathBuf::from("e").as_path()), Some("v")),
        vec![PathBuf::from("e"), PathBuf::from("v"), pin.clone()]
    );
    assert_eq!(token_candidates(None, None), vec![pin.clone()]);
    assert_eq!(
        token_candidates(Some(PathBuf::from("e").as_path()), None),
        vec![PathBuf::from("e"), pin.clone()]
    );
}

#[test]
fn k5_no_mechanism_reason_names_mint() {
    use kryprobe_cli::cmd_token::no_mechanism_reason;
    use std::path::PathBuf;
    let bare = no_mechanism_reason(None);
    assert!(
        bare.contains(
            "no BPF capability: run 'kryprobe token mint' once as root, or supply --token"
        ),
        "ruling sentence: {bare}"
    );
    assert!(bare.contains("/sys/fs/bpf/kryprobe/token"), "{bare}");
    let explicit = no_mechanism_reason(Some(PathBuf::from("/tmp/k5-tok-zzz").as_path()));
    assert!(explicit.contains("/tmp/k5-tok-zzz"), "{explicit}");
}

#[test]
fn k5_live_config_default_has_no_token() {
    assert_eq!(kryprobe_cli::live::LiveConfig::default().token, None);
}

#[test]
fn k5_live_explicit_token_named_when_unusable() {
    if is_root() {
        println!("SKIP: k5_live_explicit_token_named_when_unusable needs unprivileged euid");
        return;
    }
    let _guard = k5_env_guard();
    let (bpf_prior, token_prior, dir) = k5_preflight_env(None);
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(0),
        tick_ms: 1000,
        token: Some(std::path::PathBuf::from("/nonexistent-k5-token-zzz")),
    };
    let err = kryprobe_cli::live::run_live_capture_with_registry(
        &cfg,
        &k5_open_runtime(),
        &k5_registry(),
    )
    .expect_err("unusable explicit token must refuse");
    k5_restore_env(bpf_prior, token_prior, &dir);
    match err {
        kryprobe_cli::live::LiveError::Unusable(reason) => {
            assert!(reason.contains("kryprobe token mint"), "{reason}");
            assert!(reason.contains("/nonexistent-k5-token-zzz"), "{reason}");
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}

#[test]
fn k5_live_env_token_consulted() {
    if is_root() {
        println!("SKIP: k5_live_env_token_consulted needs unprivileged euid");
        return;
    }
    let _guard = k5_env_guard();
    let (bpf_prior, token_prior, dir) = k5_preflight_env(Some("/nonexistent-k5-env-token"));
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(0),
        tick_ms: 1000,
        token: None,
    };
    let err = kryprobe_cli::live::run_live_capture_with_registry(
        &cfg,
        &k5_open_runtime(),
        &k5_registry(),
    )
    .expect_err("unusable env token must refuse");
    k5_restore_env(bpf_prior, token_prior, &dir);
    match err {
        kryprobe_cli::live::LiveError::Unusable(reason) => {
            assert!(reason.contains("kryprobe token mint"), "{reason}");
            assert!(reason.contains("KRYPROBE_TOKEN"), "{reason}");
            assert!(reason.contains("/nonexistent-k5-env-token"), "{reason}");
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}
