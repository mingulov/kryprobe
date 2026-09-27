// SPDX-License-Identifier: GPL-3.0-or-later
//! K3 Task 1: live capture session + consolidated locator tests.
//!
//! Locator legs pin the D2 3-tier order (`KRYPROBE_BPF_DIR` file-or-dir →
//! exe-dir bundled → CWD dev object) with exact per-candidate fs errors.
//! Live legs drive `run_live_capture` (fake registries unprivileged, real
//! backend under the BPF lane lock for the privileged proof).

use std::path::PathBuf;

/// Serializes every test that mutates or depends on `KRYPROBE_BPF_DIR`
/// (process-global; parallel tests would race).
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Exact `ENOENT` render on this platform (Linux-only repo).
fn enoent_text() -> String {
    std::io::Error::from_raw_os_error(libc::ENOENT).to_string()
}

/// Unique scratch dir per test (no shared state; removed on drop,
/// including on failure).
fn scratch(name: &str) -> kryprobe_testkit::TempDir {
    kryprobe_testkit::TempDir::named(&format!("k3-1-{name}")).expect("scratch dir")
}

fn set_bpf_dir(value: &std::ffi::OsStr) {
    // SAFETY: held under ENV_LOCK; restored before the guard drops.
    unsafe { std::env::set_var("KRYPROBE_BPF_DIR", value) };
}

fn remove_bpf_dir() {
    // SAFETY: held under ENV_LOCK; restored before the guard drops.
    unsafe { std::env::remove_var("KRYPROBE_BPF_DIR") };
}

/// Tier-2 candidate for this test binary (the exe-dir probe).
fn exe_tier_candidate() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    exe.parent()
        .expect("exe parent")
        .join("kryprobe-bpf")
        .join("kcrypto.bpf.o")
}

#[test]
fn locator_env_file_wins_live() {
    let _guard = env_guard();
    let prior = std::env::var_os("KRYPROBE_BPF_DIR");
    let scratch = scratch("locator-file");
    let dir = scratch.path();
    let file = dir.join("custom.o");
    std::fs::write(&file, b"fake-object").expect("write tmp object");
    set_bpf_dir(file.as_os_str());
    let (found, bytes) =
        kryprobe_privilege::locate_kcrypto_object_bytes().expect("env file locates");
    assert_eq!(found, file, "tier 1: env file tried as-is");
    assert_eq!(bytes, b"fake-object", "single read returns the bytes");
    match prior {
        Some(value) => set_bpf_dir(&value),
        None => remove_bpf_dir(),
    }
}

#[test]
fn locator_env_dir_joins_live() {
    let _guard = env_guard();
    let prior = std::env::var_os("KRYPROBE_BPF_DIR");
    let scratch = scratch("locator-dir");
    let dir = scratch.path();
    let object = dir.join("kcrypto.bpf.o");
    std::fs::write(&object, b"fake-object").expect("write tmp object");
    set_bpf_dir(dir.as_os_str());
    let (found, bytes) =
        kryprobe_privilege::locate_kcrypto_object_bytes().expect("env dir locates");
    assert_eq!(found, object, "tier 1: env dir joined with kcrypto.bpf.o");
    assert_eq!(bytes, b"fake-object", "single read returns the bytes");
    match prior {
        Some(value) => set_bpf_dir(&value),
        None => remove_bpf_dir(),
    }
}

#[test]
fn locator_miss_or_dev_fallback_pins_order() {
    let _guard = env_guard();
    let prior = std::env::var_os("KRYPROBE_BPF_DIR");
    // Absent env path: tier 1 must miss; tiers 2 (exe-dir) and 3 (CWD dev)
    // then decide the outcome. The dev tier may legitimately hit on trees
    // with a prebuilt object, so both arms assert exact order evidence.
    // Absent child of a guard dir (never created).
    let absent_scratch = scratch("absent");
    let absent = absent_scratch.path().join("absent");
    set_bpf_dir(absent.as_os_str());
    let tier1 = absent.join("kcrypto.bpf.o");
    let tier2 = exe_tier_candidate();
    let tier3 = PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o");
    match kryprobe_privilege::locate_kcrypto_object_bytes() {
        // Either later tier may rescue the env miss (G9: the lane stages
        // the exe tier, so tier 2 hits on lane-run trees; tier 3 hits on
        // trees with a prebuilt dev object). The miss of tier 1 + the
        // try order stay pinned by the Err arm and the pure-candidates
        // unit test.
        Ok((path, _)) => assert!(
            path == tier2 || path == tier3,
            "a later tier rescues the env miss (tier 1 missed): {}",
            path.display()
        ),
        Err(err) => {
            assert_eq!(err.env_dir.as_deref(), absent.to_str());
            let tried: Vec<PathBuf> = err
                .misses
                .iter()
                .map(|miss| miss.candidate.clone())
                .collect();
            assert_eq!(
                tried,
                vec![tier1, tier2, tier3],
                "3-tier try order with exact candidates"
            );
            for miss in &err.misses {
                assert_eq!(
                    miss.error,
                    enoent_text(),
                    "exact fs error for {}",
                    miss.candidate.display()
                );
            }
            let text = err.to_string();
            assert!(
                text.starts_with("object missing (tried KRYPROBE_BPF_DIR="),
                "K2 wrapper vocabulary preserved: {text}"
            );
        }
    }
    match prior {
        Some(value) => set_bpf_dir(&value),
        None => remove_bpf_dir(),
    }
}

#[test]
fn live_gate_fail_names_gate() {
    // No caps: the static btf gate fails before detect/configure (no
    // attach possible in any environment, as root or not).
    let mut registry = kryprobe_core::backend::BackendRegistry::new();
    kryprobe_privilege::kcrypto_backend::register_kcrypto(&mut registry).expect("register");
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(0),
        tick_ms: 1000,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let runtime = kryprobe_core::capability::RuntimeCapabilities {
        kernel_release: "test".to_owned(),
        uprobe_multi: false,
        cookies: false,
        ringbuf: false,
        btf_present: false,
        userns: false,
        yama_scope: 0,
        caps: Vec::new(),
    };
    let err = kryprobe_cli::live::run_live_capture_with_registry(&cfg, &runtime, &registry)
        .expect_err("gate must fail");
    match err {
        kryprobe_cli::live::LiveError::Unusable(reason) => {
            assert!(reason.contains("btf"), "gate named, got: {reason}");
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}

#[test]
fn live_detect_empty_is_honest() {
    let registry = fake_registry(0);
    let (cfg, runtime) = open_session();
    let err = kryprobe_cli::live::run_live_capture_with_registry(&cfg, &runtime, &registry)
        .expect_err("empty detect must fail");
    match err {
        kryprobe_cli::live::LiveError::Unusable(reason) => {
            assert!(
                reason.contains("no instances"),
                "honest empty, got: {reason}"
            );
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}

#[test]
fn live_missing_backend_is_unusable() {
    let registry = kryprobe_core::backend::BackendRegistry::new();
    let (cfg, runtime) = open_session();
    let err = kryprobe_cli::live::run_live_capture_with_registry(&cfg, &runtime, &registry)
        .expect_err("missing backend must fail");
    assert_eq!(
        err,
        kryprobe_cli::live::LiveError::Unusable("kcrypto backend not registered".to_owned())
    );
}

#[test]
fn live_bad_source_rejected() {
    let registry = fake_registry(1);
    let (mut cfg, runtime) = open_session();
    cfg.source = "openssl".to_owned();
    let err = kryprobe_cli::live::run_live_capture_with_registry(&cfg, &runtime, &registry)
        .expect_err("bad source must fail");
    match err {
        kryprobe_cli::live::LiveError::Unusable(reason) => {
            assert!(
                reason.contains("kernel-crypto"),
                "names the live source, got: {reason}"
            );
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}

#[test]
fn live_registry_injection_dispatches_on_profile() {
    // The injection seam dispatches exactly like the production entry:
    // a request-lifecycle config refuses typed (no concrete backend
    // handle exists here) — it must never silently run aggregate.
    let registry = fake_registry(1);
    let (mut cfg, runtime) = open_session();
    cfg.profile =
        kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::RequestLifecycle;
    let err = kryprobe_cli::live::run_live_capture_with_registry(&cfg, &runtime, &registry)
        .expect_err("lifecycle over injection must fail");
    match err {
        kryprobe_cli::live::LiveError::Unusable(reason) => {
            assert!(
                reason.contains("concrete backend"),
                "names the missing handle, got: {reason}"
            );
        }
        other => panic!("expected Unusable, got {other:?}"),
    }
}

#[test]
fn live_shared_feed_exactly_once() {
    use kryprobe_core::backend::{DriverReport, SharedFeedError};
    use kryprobe_core::evidence::SharedLosses;
    let mut report = DriverReport::default();
    let first = SharedLosses::new(11, 0);
    report
        .feed_shared_losses(first)
        .expect("first feed accepted");
    let err = report
        .feed_shared_losses(SharedLosses::new(100, 100))
        .expect_err("second feed refuses");
    assert_eq!(err, SharedFeedError::DuplicateFeed);
    assert_eq!(report.shared_losses(), Some(first), "first feed stands");
}

#[test]
fn live_config_default_tick_is_1000ms() {
    let cfg = kryprobe_cli::live::LiveConfig::default();
    assert_eq!(cfg.tick_ms, 1000);
}

fn fake_registry(instances: usize) -> kryprobe_core::backend::BackendRegistry {
    let mut registry = kryprobe_core::backend::BackendRegistry::new();
    registry
        .register(Box::new(FakeBackend { instances }))
        .expect("fake registers");
    registry
}

/// Open-gates session inputs (all caps present; the fake stops the run
/// before any attach regardless).
fn open_session() -> (
    kryprobe_cli::live::LiveConfig,
    kryprobe_core::capability::RuntimeCapabilities,
) {
    (
        kryprobe_cli::live::LiveConfig {
            source: "kernel-crypto".to_owned(),
            duration_secs: Some(0),
            tick_ms: 1000,
            token: None,
            json_audit: false,
            profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
        },
        kryprobe_core::capability::RuntimeCapabilities {
            kernel_release: "test".to_owned(),
            uprobe_multi: true,
            cookies: true,
            ringbuf: true,
            btf_present: true,
            userns: true,
            yama_scope: 0,
            caps: vec!["CAP_BPF".to_owned()],
        },
    )
}

static FAKE_OPEN_CAPS: kryprobe_core::backend::BackendCapabilities =
    kryprobe_core::backend::BackendCapabilities {
        backend: kryprobe_core::enums::BackendId::KCrypto,
        name: "fake-kcrypto",
        required: kryprobe_core::plan::CapabilityRequirements {
            uprobe_multi: false,
            cookies: false,
            ringbuf: false,
            btf: false,
        },
    };

/// Fake kcrypto-id backend: scripted detect, fail-closed configure,
/// loud decode/finalize. The remaining fake legs stop before `configure`
/// (source/detect arms), so `configure` never runs — it refuses loudly
/// if the session ever overruns the scripted stop.
struct FakeBackend {
    instances: usize,
}

impl kryprobe_core::backend::Backend for FakeBackend {
    fn id(&self) -> kryprobe_core::enums::BackendId {
        kryprobe_core::enums::BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static kryprobe_core::backend::BackendCapabilities {
        &FAKE_OPEN_CAPS
    }

    fn detect(
        &self,
        _ctx: &kryprobe_core::backend::DetectContext<'_>,
    ) -> Result<Vec<kryprobe_core::backend::DetectedInstance>, kryprobe_core::error::BackendError>
    {
        Ok((0..self.instances)
            .map(|_| kryprobe_core::backend::DetectedInstance {
                backend: kryprobe_core::enums::BackendId::KCrypto,
                object: None,
                detail: "fake instance".to_owned(),
            })
            .collect())
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
            required: FAKE_OPEN_CAPS.required,
        })
    }

    fn configure(
        &self,
        _ctx: &mut kryprobe_core::backend::ConfigureContext<'_>,
        _plan: &kryprobe_core::backend::BackendPlan,
    ) -> Result<(), kryprobe_core::error::BackendError> {
        Err(kryprobe_core::error::BackendError::Denied(
            kryprobe_core::error::DeniedReason::with_detail("fake_denied", "scripted"),
        ))
    }

    fn decode(
        &self,
        _ctx: &kryprobe_core::backend::DecodeContext<'_>,
        _event: kryprobe_core::backend::RawEvent<'_>,
    ) -> Result<kryprobe_core::evidence::NativeObservation, kryprobe_core::error::BackendError>
    {
        panic!("fake decode must not run: configure is scripted to fail");
    }

    fn finalize(
        &self,
        _ctx: &kryprobe_core::backend::FinalizeContext<'_>,
    ) -> Result<kryprobe_core::backend::BackendSummary, kryprobe_core::error::BackendError> {
        panic!("fake finalize must not run: configure is scripted to fail");
    }
}

fn is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

fn btf_available() -> bool {
    std::fs::metadata("/sys/kernel/btf/vmlinux").is_ok()
}

/// Privileged-gate: true when this test must run (root + BTF).
/// Callers `return` early on false (honest skip, prints why).
fn lane_ready(name: &str) -> bool {
    if !is_root() {
        println!("SKIP: {name} requires root (euid != 0)");
        return false;
    }
    if !btf_available() {
        println!("SKIP: {name} requires /sys/kernel/btf/vmlinux");
        return false;
    }
    true
}

/// Suite serialization lock: sensors are system-wide. The privileged proof
/// holds this across its whole body (attach→detach). Poison-tolerant.
static SUITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn suite_guard() -> std::sync::MutexGuard<'static, ()> {
    SUITE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Workspace-relative path of the built kcrypto object.
fn kcrypto_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/kryprobe-bpf/kcrypto.bpf.o")
}

/// A `bpftool link show` block header: `<id>:` followed by the link
/// kind, e.g. `15125: tracing  prog 18393` (K4 evidence
/// `evidence/k4-1/s1-mon.d/link-*.txt`).
fn is_link_header(line: &str) -> bool {
    let mut parts = line.splitn(2, ':');
    matches!(parts.next(), Some(id) if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_some()
}

/// Count TRUE `trace_fexit` links in `bpftool link show` output.
///
/// Each link is a block (a `<id>:` header plus continuation lines); only
/// blocks carrying `attach_type trace_fexit` count. Foreign links
/// (`raw_tracepoint`/`perf_event`, 1–2 lines each) and transient
/// `Error: ...` lines are ignored, and empty output yields 0. Counting
/// raw lines instead passes the gate mid-ramp (3 lines per tracing
/// link), which flaked exactness assertions — see K4 T1 root cause.
fn count_trace_fexit_links(output: &str) -> usize {
    let mut count = 0;
    let mut in_block = false;
    let mut block_has_fexit = false;
    for line in output.lines() {
        if is_link_header(line) {
            in_block = true;
            block_has_fexit = false;
        } else if in_block && !block_has_fexit && line.contains("attach_type trace_fexit") {
            block_has_fexit = true;
            count += 1;
        }
    }
    count
}

/// Tracing-link count via bpftool (lane-only helper; the test runs as
/// root so no sudo indirection is needed). `None` when bpftool itself
/// errors (transient during attach storms — the caller retries; the
/// overall timeout keeps a broken bpftool loud).
fn link_count_or_none() -> Option<usize> {
    let output = std::process::Command::new("bpftool")
        .args(["link", "show"])
        .output()
        .or_else(|_| {
            std::process::Command::new("/usr/sbin/bpftool")
                .args(["link", "show"])
                .output()
        })
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(count_trace_fexit_links(&text))
}

#[test]
fn link_parser_empty_case() {
    // `link-0.txt`: zero bytes before attach.
    assert_eq!(count_trace_fexit_links(""), 0);
    assert_eq!(count_trace_fexit_links("\n"), 0);
}

#[test]
fn link_parser_midramp_with_error_case() {
    // Verbatim `s1-mon.d/link-21.txt` (modulo trailing spaces): 3
    // tracing links plus a transient per-id error line → 3, not 10.
    let sample = "15125: tracing  prog 18393\n\
        \tprog_type tracing  attach_type trace_fexit\n\
        \ttarget_obj_id 1  target_btf_id 105300\n\
        15126: tracing  prog 18394\n\
        \tprog_type tracing  attach_type trace_fexit\n\
        \ttarget_obj_id 1  target_btf_id 105301\n\
        15127: tracing  prog 18395\n\
        \tprog_type tracing  attach_type trace_fexit\n\
        \ttarget_obj_id 1  target_btf_id 105317\n\
        Error: can't get link by id (15128): Resource temporarily unavailable\n";
    assert_eq!(count_trace_fexit_links(sample), 3);
}

#[test]
fn link_parser_foreign_only_case() {
    // Verbatim shapes from `s3-late-module-load.txt` (1-line
    // raw_tracepoint/perf_event) and `s4-two-implementations.txt`
    // (2-line perf_event + uprobe/uretprobe continuation): no fexit → 0.
    let sample = "15407: raw_tracepoint  prog 18717\n\
        15408: raw_tracepoint  prog 18718\n\
        15410: perf_event  prog 18716\n\
        15826: perf_event  prog 18715\n\
        \tuprobe /proc/self/fd/18+0x27a60\n\
        15827: perf_event  prog 18715\n\
        \turetprobe /proc/self/fd/58+0x315f0  cookie 413\n";
    assert_eq!(count_trace_fexit_links(sample), 0);
}

#[test]
fn link_parser_full_session_case() {
    // One fully attached session holds 9 trace_fexit links (single sensor,
    // H1(b); was 18 across the twins); the `n >= 9` gate below pins
    // that unit. Foreign links interleaved must not inflate the count.
    let mut sample = String::from("15407: raw_tracepoint  prog 18717\n");
    for id in 15125..15125 + 9 {
        sample.push_str(&format!(
            "{id}: tracing  prog {}\n\tprog_type tracing  attach_type trace_fexit\n\ttarget_obj_id 1  target_btf_id 105300\n",
            18393 + (id - 15125)
        ));
    }
    sample.push_str("15826: perf_event  prog 18715\n\tuprobe /proc/self/fd/18+0x27a60\n");
    assert_eq!(count_trace_fexit_links(&sample), 9);
}

fn lane_runtime() -> kryprobe_core::capability::RuntimeCapabilities {
    kryprobe_core::capability::RuntimeCapabilities {
        kernel_release: "lane".to_owned(),
        uprobe_multi: true,
        cookies: true,
        ringbuf: true,
        btf_present: true,
        userns: true,
        yama_scope: 0,
        caps: vec!["CAP_BPF".to_owned(), "CAP_SYS_ADMIN".to_owned()],
    }
}

fn row_kind(obs: &kryprobe_core::evidence::NativeObservation) -> &str {
    obs.backend_payload
        .get("row")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?")
}

/// Compact per-(row,family,op,result,algorithm) call sums for failure
/// messages (only rendered on failure).
fn breakdown(observations: &[kryprobe_core::evidence::NativeObservation]) -> String {
    let mut sums: std::collections::BTreeMap<(String, String, String, String, String), u64> =
        std::collections::BTreeMap::new();
    for obs in observations {
        let key = (
            row_kind(obs).to_owned(),
            obs.backend_payload
                .get("family")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_owned(),
            obs.backend_payload
                .get("op")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_owned(),
            obs.backend_payload
                .get("result")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_owned(),
            obs.backend_payload
                .get("algorithm")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_owned(),
        );
        let calls = obs.backend_payload["counts"]["calls"].as_u64().unwrap_or(0);
        *sums.entry(key).or_default() += calls;
    }
    format!("{sums:?}")
}

/// Sum `counts.calls` over agg observations matching
/// (family, op, result, algorithm).
fn sum_obs(
    observations: &[kryprobe_core::evidence::NativeObservation],
    family: &str,
    op: &str,
    result: &str,
    alg: &str,
) -> u64 {
    observations
        .iter()
        .filter(|o| row_kind(o) == "agg")
        .filter(|o| {
            o.backend_payload
                .get("family")
                .and_then(serde_json::Value::as_str)
                == Some(family)
        })
        .filter(|o| {
            o.backend_payload
                .get("op")
                .and_then(serde_json::Value::as_str)
                == Some(op)
        })
        .filter(|o| {
            o.backend_payload
                .get("result")
                .and_then(serde_json::Value::as_str)
                == Some(result)
        })
        .filter(|o| {
            o.backend_payload
                .get("algorithm")
                .and_then(serde_json::Value::as_str)
                == Some(alg)
        })
        .map(|o| {
            o.backend_payload["counts"]["calls"]
                .as_u64()
                .expect("calls")
        })
        .sum()
}

#[test]
#[ignore = "BPF lane: run under sudo with the lane lock + lease"]
fn live_capture_proves_session() {
    let _suite = suite_guard();
    if !lane_ready("live_capture_proves_session") {
        return;
    }
    let _env = env_guard();
    let prior = std::env::var_os("KRYPROBE_BPF_DIR");
    // Both the backend's `configure` and the session sensor resolve the
    // object through the consolidated locator; elevated runs refuse the
    // env tier, so the lane-staged exe tier serves (the env set below is
    // belt-and-braces for manual non-lane runs).
    let object_path = kcrypto_object_path();
    assert!(
        object_path.is_file(),
        "BPF object must be prebuilt: {}",
        object_path.display()
    );
    set_bpf_dir(object_path.as_os_str());

    // Mid-session traffic burst (positive control): gated on the
    // session sensor fully attached (9 true `trace_fexit` links — one
    // session per K4 graded gates) — deterministic, no sleep-guessing
    // against BPF load times — and done well before the window closes.
    // Synchronously prepare before run_live_capture can attach. The
    // worker only clones/finalizes the retained operation after readiness.
    let prepared = kryprobe_testkit::alg_fixture::PreparedHashFinups::new("sha512")
        .expect("prepare hash prefix before attachment");
    let traffic = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            if link_count_or_none().is_some_and(|n| n >= 9) {
                break;
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(60),
                "sensors attach within 60s (links: {:?})",
                link_count_or_none()
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let gate_wait = start.elapsed();
        let sk =
            kryprobe_testkit::alg_fixture::skcipher_roundtrip("cbc(aes)", 20).expect("skcipher");
        let single = kryprobe_testkit::alg_fixture::hash_digest("sha512", 8).expect("hash");
        let multi = prepared
            .finish(4)
            .expect("cloned finups and digest goldens");
        let aead = kryprobe_testkit::alg_fixture::aead_roundtrip("gcm(aes)", 10).expect("aead");
        kryprobe_testkit::alg_fixture::aead_decrypt_bad_tag("gcm(aes)")
            .expect("bad-tag decrypt must EBADMSG");
        (sk, single, multi, aead, gate_wait)
    });

    // Main run: 8s window, 1s ticks → 9 ticks (opening + mids + closing).
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(8),
        tick_ms: 1000,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let outcome = kryprobe_cli::live::run_live_capture(&cfg, &lane_runtime())
        .unwrap_or_else(|err| panic!("live capture failed: {err}"));

    let (sk, single, multi, aead, gate_wait) = traffic.join().expect("traffic joins");
    println!("live proof: attach gate passed after {gate_wait:?}");
    assert_eq!((sk.enc, sk.dec), (20, 20), "skcipher positive control");
    assert_eq!((single.digests, single.digest_len), (8, 64), "hash control");
    assert_eq!(
        (multi.digests, multi.digest_len),
        (4, 64),
        "cloned finup control"
    );
    assert_eq!((aead.enc, aead.dec), (10, 10), "aead control");

    // Observations decode; ids are unique and positive. (G9: NOT
    // 1..N — G2 latest-per-key eviction consumes issuer ids for rows
    // that later ticks overwrite, so survivors are a sparse
    // subsequence; H2 pins latest-wins at first-seen slots.)
    assert!(!outcome.observations.is_empty(), "session decodes rows");
    let mut seen = std::collections::HashSet::new();
    for obs in &outcome.observations {
        assert!(obs.id.get() > 0, "positive ids");
        assert!(seen.insert(obs.id.get()), "ids unique across session");
        assert_eq!(obs.backend, kryprobe_core::enums::BackendId::KCrypto);
    }
    // Finalize counts decodes, observations carry latest-per-key survivors
    // (documented in live.rs): strictly more decodes than survivors —
    // the totals key repeats every tick, so eviction always engages.
    assert!(
        outcome.summary.observations > outcome.observations.len() as u64,
        "finalize(decodes) > emitted(survivors): {} vs {}",
        outcome.summary.observations,
        outcome.observations.len()
    );
    assert_eq!(
        outcome.summary.backend,
        kryprobe_core::enums::BackendId::KCrypto
    );

    // Latest-wins: one totals row (single Totals key across all ticks, last
    // tick wins). Cross-tick conservation sums are meaningless post-eviction,
    // so the totals row asserts presence plus traffic flow instead.
    let totals: Vec<_> = outcome
        .observations
        .iter()
        .filter(|o| row_kind(o) == "totals")
        .collect();
    assert_eq!(totals.len(), 1, "latest-wins: exactly one totals row");
    assert!(
        totals[0].backend_payload["counts"]["calls"]
            .as_u64()
            .expect("calls")
            >= 1,
        "KTOT observed traffic"
    );

    // Fixture truth present (lower bounds: ambient traffic may add rows,
    // never remove the driven ones).
    // skcipher bounds are 18, not 20 (G9 kworker-miss finding: cbc(aes)
    // is cryptd-async here and ~1% of kworker completions never reach
    // BPF — see the driver test comment + evidence/review-remain/
    // g9-kworker-miss/). Sync families below stay at full fixture
    // counts (no kworker leg, exact every run).
    assert!(
        sum_obs(
            &outcome.observations,
            "skcipher",
            "encrypt",
            "ok",
            "cbc(aes)"
        ) >= 18,
        "skcipher encrypt rows decode; breakdown: {}",
        breakdown(&outcome.observations)
    );
    assert!(
        sum_obs(
            &outcome.observations,
            "skcipher",
            "decrypt",
            "ok",
            "cbc(aes)"
        ) >= 18,
        "skcipher decrypt rows decode"
    );
    assert!(
        sum_obs(&outcome.observations, "ahash", "digest", "ok", "sha512") >= 8,
        "ahash digest rows decode"
    );
    assert!(
        sum_obs(&outcome.observations, "shash", "digest", "ok", "sha512") >= 8,
        "shash digest rows decode"
    );
    assert_eq!(
        sum_obs(&outcome.observations, "shash", "finup", "ok", "sha512"),
        4,
        "one shash finup per prepared clone"
    );
    let finups: Vec<_> = outcome
        .observations
        .iter()
        .filter(|o| {
            row_kind(o) == "agg"
                && o.backend_payload["family"] == "shash"
                && o.backend_payload["op"] == "finup"
                && o.backend_payload["algorithm"] == "sha512"
        })
        .collect();
    assert_eq!(
        finups
            .iter()
            .map(|o| o.backend_payload["bytes"].as_u64().expect("bytes"))
            .sum::<u64>(),
        4 * 16,
        "only final-argument bytes, not full input"
    );
    for row in finups {
        assert_eq!(row.backend_payload["counts"]["errors"], 0);
        assert_eq!(row.backend_payload["counts"]["queued"], 0);
        let callers: Vec<_> = outcome
            .observations
            .iter()
            .filter(|o| {
                row_kind(o) == "who"
                    && o.backend_payload["key_hash"] == row.backend_payload["key_hash"]
            })
            .collect();
        assert!(
            callers
                .iter()
                .all(|o| o.backend_payload["tgid"] == std::process::id()),
            "foreign finup cannot satisfy the fixture"
        );
        assert_eq!(
            callers
                .iter()
                .map(|o| o.backend_payload["calls"].as_u64().expect("caller calls"))
                .sum::<u64>(),
            row.backend_payload["counts"]["calls"]
                .as_u64()
                .expect("calls"),
            "finup caller counts reconcile"
        );
    }
    assert!(
        sum_obs(&outcome.observations, "aead", "encrypt", "ok", "gcm(aes)") >= 10,
        "aead encrypt rows decode"
    );
    assert!(
        sum_obs(&outcome.observations, "aead", "decrypt", "ok", "gcm(aes)") >= 10,
        "aead decrypt rows decode"
    );
    assert!(
        sum_obs(
            &outcome.observations,
            "aead",
            "decrypt",
            "error",
            "gcm(aes)"
        ) >= 1,
        "bad-tag error row decodes"
    );

    // Idents: drained exactly once each across all ticks (no per-tick
    // finalize loss — M1 — and no duplication); healthy drain, no overflow.
    let idents: Vec<_> = outcome
        .observations
        .iter()
        .filter(|o| row_kind(o) == "ident")
        .collect();
    assert!(!idents.is_empty(), "fixture traffic yields idents");
    assert!(
        idents.iter().all(|o| {
            o.backend_payload
                .get("ident_kind")
                .and_then(serde_json::Value::as_str)
                != Some("overflow")
        }),
        "healthy drain has no OVERFLOW records"
    );
    let mut seen: std::collections::HashMap<(u64, String), usize> =
        std::collections::HashMap::new();
    for obs in &idents {
        let hash = obs.backend_payload["key_hash"].as_u64().expect("key_hash");
        let kind = obs.backend_payload["ident_kind"]
            .as_str()
            .expect("ident_kind")
            .to_owned();
        *seen.entry((hash, kind)).or_default() += 1;
    }
    for (key, count) in &seen {
        assert_eq!(*count, 1, "ident {key:?} drained exactly once");
    }

    // Healthy lane: zero losses everywhere, coverage COMPLETE.
    assert_eq!(
        outcome.summary.integrity,
        kryprobe_core::evidence::IntegritySummary::default(),
        "healthy lane: zero backend losses"
    );
    assert_eq!(
        outcome.integrity,
        kryprobe_core::evidence::IntegritySummary::default(),
        "healthy lane: zero session losses"
    );
    assert_eq!(
        outcome.coverage.overall(),
        kryprobe_core::enums::CoverageStatus::Unknown,
        "healthy lane: delivery/completion unmeasured (weaker: {:?})",
        outcome.coverage.weaker_dimensions()
    );
    assert_eq!(
        outcome.coverage.weaker_dimensions(),
        vec!["aggregate_counts", "detailed_events", "completion"],
        "T02: reconciled session still leaves delivery/completion unknown"
    );

    // Zero window: exactly the opening tick (ids still sequence).
    let cfg0 = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(0),
        tick_ms: 1000,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let outcome0 = kryprobe_cli::live::run_live_capture(&cfg0, &lane_runtime())
        .unwrap_or_else(|err| panic!("zero-window capture failed: {err}"));
    assert_eq!(
        outcome0
            .observations
            .iter()
            .filter(|o| row_kind(o) == "totals")
            .count(),
        1,
        "Some(0) takes exactly the opening tick"
    );
    for (i, obs) in outcome0.observations.iter().enumerate() {
        assert_eq!(obs.id.get(), i as u64 + 1, "zero-window ids sequence");
    }
    assert_eq!(
        outcome0.summary.observations,
        outcome0.observations.len() as u64,
        "zero-window finalize==decoded"
    );

    match prior {
        Some(value) => set_bpf_dir(&value),
        None => remove_bpf_dir(),
    }
}

#[test]
fn locator_candidates_pin_three_tier_order() {
    use kryprobe_privilege::kcrypto_backend::kcrypto_object_candidates;
    // Env file tried as-is, then exe tier, then dev tier.
    let cand_scratch = scratch("cand");
    let file = cand_scratch.path().join("cand.o");
    std::fs::write(&file, b"x").expect("candidate probe file");
    let exe = PathBuf::from("/exe/dir");
    assert_eq!(
        kcrypto_object_candidates(file.to_str(), Some(exe.as_path()), false),
        vec![
            file.clone(),
            PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o"),
            PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
        ]
    );
    // Env dir joined; unknown exe dir skips tier 2 (never fabricated).
    let dir = cand_scratch.path().join("cand-dir");
    assert_eq!(
        kcrypto_object_candidates(dir.to_str(), None, false),
        vec![
            dir.join("kcrypto.bpf.o"),
            PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
        ]
    );
    // Unset env: exe tier first, dev last.
    assert_eq!(
        kcrypto_object_candidates(None, Some(exe.as_path()), false),
        vec![
            PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o"),
            PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
        ]
    );
}

/// 1B-H4: a controller walked through bring-up to `Attaching` — the
/// state `drive_session` requires on entry (production reaches it via
/// gate → detect → plan → configure in `run_live_session`).
fn attached_controller() -> kryprobe_core::session::SessionController {
    use kryprobe_core::session::SessionState as S;
    let mut controller = kryprobe_core::session::SessionController::new();
    for state in [S::Qualified, S::Discovering, S::Attaching] {
        controller.transition(state).expect("bring-up hop legal");
    }
    controller
}

/// P0-4 (3A-C-T2): scripted sensor serving canned ticks through the
/// `SessionSensor` seam — the live success path without privilege.
struct ScriptedSensor {
    script: Vec<kryprobe_privilege::kcrypto_snapshot::SnapshotRows>,
    who: kryprobe_privilege::kcrypto_backend::WhoSnapshot,
    drop_sites: [u64; 8],
    barriers: std::sync::Mutex<Vec<u64>>,
    tables: std::sync::atomic::AtomicU64,
    finished: std::sync::atomic::AtomicBool,
}

impl kryprobe_cli::live::SessionSensor for ScriptedSensor {
    fn snapshot_tick(
        &mut self,
        barrier_id: u64,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<kryprobe_privilege::kcrypto_snapshot::SnapshotRows, kryprobe_cli::live::LiveError>
    {
        self.barriers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(barrier_id);
        let idx = (barrier_id - 1) as usize;
        if idx + 1 >= self.script.len() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(self.script[idx.min(self.script.len() - 1)].clone())
    }

    fn kallsyms_text(&mut self) -> String {
        self.tables
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        String::new()
    }

    fn snapshot_who(
        &mut self,
    ) -> Result<
        (Vec<kryprobe_privilege::kcrypto_backend::WhoSnapshot>, u64),
        kryprobe_cli::live::LiveError,
    > {
        // Three same-key rows per tick: latest-per-key still dedups to
        // one who observation, but a per-row kallsyms parse (2B-C2)
        // would cost 3 parses per tick instead of 1 — the H-T3(1)
        // parse-count leg below discriminates exactly that.
        Ok((
            vec![self.who.clone(), self.who.clone(), self.who.clone()],
            0,
        ))
    }

    fn drop_sites(&mut self) -> Result<[u64; 8], kryprobe_cli::live::LiveError> {
        Ok(self.drop_sites)
    }

    fn finish(&mut self) {
        self.finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Success-path fake backend: scripted detect/plan/configure, counting
/// decode over production `observation_for_who`, scripted finalize.
struct SuccessBackend {
    decodes: std::sync::atomic::AtomicU64,
    finalized: std::sync::atomic::AtomicBool,
    /// Parsed ONCE at construction (empty fixture text): decode must
    /// not parse per call, or the H-T3(1) parse-count leg below would
    /// count fake-backend parses alongside tick parses.
    table: kryprobe_privilege::kallsyms::SymTable<'static>,
}

impl kryprobe_core::backend::Backend for SuccessBackend {
    fn id(&self) -> kryprobe_core::enums::BackendId {
        kryprobe_core::enums::BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static kryprobe_core::backend::BackendCapabilities {
        &FAKE_OPEN_CAPS
    }

    fn detect(
        &self,
        _ctx: &kryprobe_core::backend::DetectContext<'_>,
    ) -> Result<Vec<kryprobe_core::backend::DetectedInstance>, kryprobe_core::error::BackendError>
    {
        Ok(vec![kryprobe_core::backend::DetectedInstance {
            backend: kryprobe_core::enums::BackendId::KCrypto,
            object: None,
            detail: "success fake".to_owned(),
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
            required: FAKE_OPEN_CAPS.required,
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
        ctx: &kryprobe_core::backend::DecodeContext<'_>,
        _event: kryprobe_core::backend::RawEvent<'_>,
    ) -> Result<kryprobe_core::evidence::NativeObservation, kryprobe_core::error::BackendError>
    {
        let id = ctx.id_issuer.issue().map_err(|_| {
            kryprobe_core::error::BackendError::Internal(kryprobe_core::error::InternalError::new(
                "scripted_id_exhausted",
            ))
        })?;
        self.decodes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(kryprobe_privilege::kcrypto_backend::observation_for_who(
            &kryprobe_privilege::kcrypto_backend::WhoSnapshot {
                key: Default::default(),
                val: Default::default(),
                stack_ips: Vec::new(),
                first_errno: None,
                params: None,
            },
            id,
            &self.table,
        ))
    }

    fn finalize(
        &self,
        _ctx: &kryprobe_core::backend::FinalizeContext<'_>,
    ) -> Result<kryprobe_core::backend::BackendSummary, kryprobe_core::error::BackendError> {
        self.finalized
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(kryprobe_core::backend::BackendSummary {
            backend: kryprobe_core::enums::BackendId::KCrypto,
            observations: self.decodes.load(std::sync::atomic::Ordering::Relaxed),
            integrity: kryprobe_core::evidence::IntegritySummary::default(),
        })
    }
}

fn script_agg_as(calls: u64, name8: &[u8; 8]) -> kryprobe_privilege::kcrypto_snapshot::RowBytes {
    // 3A-M-T7: canonical builder (fills preserved from the old local copy).
    let out =
        kryprobe_testkit::kcrypto_rows::agg_row_bytes(kryprobe_testkit::kcrypto_rows::AggSpec {
            family: kryprobe_abi::kcrypto_agg::KFAM_SK,
            op: kryprobe_abi::kcrypto_agg::KOP_ENC,
            result: kryprobe_abi::kcrypto_agg::KRES_OK,
            ctx: kryprobe_abi::kcrypto_agg::KCTX_PROC,
            name: name8.as_slice(),
            drv: b"",
            calls,
            bytes: 0,
            ok: 0,
            errors: 0,
            queued: 0,
        });
    kryprobe_privilege::kcrypto_snapshot::RowBytes::new(out).expect("hand row")
}

fn script_totals(calls: u64) -> kryprobe_privilege::kcrypto_snapshot::TotalsBytes {
    // 3A-M-T7: canonical builder (fills preserved from the old local copy).
    let out = kryprobe_testkit::kcrypto_rows::totals_row_bytes(calls, 0, 0);
    kryprobe_privilege::kcrypto_snapshot::TotalsBytes::new(out).expect("hand totals")
}

fn script_ident() -> kryprobe_privilege::kcrypto_snapshot::IdentBytes {
    // 3A-M-T7: canonical builder.
    let out = kryprobe_testkit::kcrypto_rows::ident_row_bytes();
    kryprobe_privilege::kcrypto_snapshot::IdentBytes::new(out).expect("hand ident")
}

#[test]
fn live_success_path_scripted_sensor_three_ticks() {
    // P0-4: N ticks → decode → coverage → finalize, unprivileged.
    // 3 ticks × (2 distinct agg + totals + ident + who), latest-per-key:
    // 2 agg + totals + who + 3 idents = 7 observations; decode serves
    // agg/totals/ident every tick (12 calls).
    // H-T3(1): guard BEFORE construction — the fake backend parses its
    // table once at construction, and that parse must not land in a
    // concurrent test's count window.
    let _suite = suite_guard();
    let mut controller = attached_controller();
    let tick = |wall: u64| kryprobe_privilege::kcrypto_snapshot::SnapshotRows {
        rows: vec![
            script_agg_as(10, b"cbc(aes)"),
            script_agg_as(20, b"gcm(aes)"),
        ],
        totals: Some(script_totals(30)),
        idents: vec![script_ident()],
        overflow_identities: 0,
        drops: 7,
        monotonic_ns: wall,
    };
    let sensor = ScriptedSensor {
        script: vec![tick(100), tick(200), tick(300)],
        who: kryprobe_privilege::kcrypto_backend::WhoSnapshot {
            key: Default::default(),
            val: Default::default(),
            stack_ips: Vec::new(),
            first_errno: None,
            params: None,
        },
        drop_sites: [0; 8],
        barriers: std::sync::Mutex::new(Vec::new()),
        tables: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicBool::new(false),
    };
    let backend = SuccessBackend {
        decodes: std::sync::atomic::AtomicU64::new(0),
        finalized: std::sync::atomic::AtomicBool::new(false),
        table: kryprobe_privilege::kallsyms::SymTable::parse(""),
    };
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(60),
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = sensor;
    // The delta below counts REAL `SymTable::parse` calls — 1 per
    // tick, not 1 per who row (guard held since test start).
    let parses_before = kryprobe_privilege::kallsyms::parse_calls();
    let outcome = kryprobe_cli::live::drive_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        9,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        None,
        &mut controller,
        None,
    )
    .expect("scripted session drives green");
    // Row counts: latest-per-key (2 agg + totals + who) + every
    // disjoint ident (3).
    assert_eq!(outcome.observations.len(), 7, "4 keys + 3 idents");
    assert_eq!(
        backend.decodes.load(std::sync::atomic::Ordering::Relaxed),
        12,
        "decode serves agg+totals+ident (who bypasses decode)"
    );
    // Barrier cadence: exactly 3 ticks, sequential ids from 1.
    assert_eq!(
        sensor
            .barriers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone(),
        vec![1, 2, 3]
    );
    // Kallsyms seam: one table per tick (C2 counting leg, H-T3).
    assert_eq!(sensor.tables.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(
        kryprobe_privilege::kallsyms::parse_calls() - parses_before,
        3,
        "one real parse per tick across 3 who rows per tick (C2)"
    );
    // 1B-H4: the governed session ends Finalized, observably.
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
    assert_eq!(
        controller.state(),
        kryprobe_core::session::SessionState::Finalized
    );
    // Drops accounting: scripted session drops ride the coverage.
    let ring = outcome
        .coverage
        .detailed_events
        .counters
        .iter()
        .find(|c| c.name == "ring_drops")
        .expect("ring_drops counter")
        .value;
    assert_eq!(ring, 7);
    // Interval walls come from the snapshots (first → closing).
    // Completion carries the decoded magnitude plus the T02 unobserved
    // reason (api-returns never observes terminal completion).
    let completion_names: Vec<&str> = outcome
        .coverage
        .completion
        .counters
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(
        completion_names,
        vec!["observations_decoded", "uncovered:completion_unobserved"]
    );
    // Exactly-once feed + finalize: Ok outcome proves the shared feed
    // ran once (double-feed errors) and finalize filed its summary.
    assert!(
        backend.finalized.load(std::sync::atomic::Ordering::Relaxed),
        "finalize ran once"
    );
    assert!(
        sensor.finished.load(std::sync::atomic::Ordering::Relaxed),
        "sensor finish ran once"
    );
}

/// M-T4: sensor serving unbounded identical ticks — the session
/// ends only when the shared stop flag fires, so a stop-ignoring
/// driver would hang this test instead of passing it.
struct MidStopSensor {
    tick: kryprobe_privilege::kcrypto_snapshot::SnapshotRows,
    ticks: std::sync::Arc<std::sync::atomic::AtomicU64>,
    finished: std::sync::atomic::AtomicBool,
}

impl kryprobe_cli::live::SessionSensor for MidStopSensor {
    fn snapshot_tick(
        &mut self,
        _barrier_id: u64,
        _stop: &std::sync::atomic::AtomicBool,
    ) -> Result<kryprobe_privilege::kcrypto_snapshot::SnapshotRows, kryprobe_cli::live::LiveError>
    {
        self.ticks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.tick.clone())
    }

    fn kallsyms_text(&mut self) -> String {
        String::new()
    }

    fn snapshot_who(
        &mut self,
    ) -> Result<
        (Vec<kryprobe_privilege::kcrypto_backend::WhoSnapshot>, u64),
        kryprobe_cli::live::LiveError,
    > {
        Ok((Vec::new(), 0))
    }

    fn drop_sites(&mut self) -> Result<[u64; 8], kryprobe_cli::live::LiveError> {
        Ok([0; 8])
    }

    fn finish(&mut self) {
        self.finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn live_stop_mid_run_tears_down_cleanly() {
    // M-T4: a second thread sets the shared stop flag after the 3rd
    // tick starts; the driver must end the session (Ok, Finalized,
    // exactly-once finalize + sensor finish), not hang or error.
    let _suite = suite_guard();
    let mut controller = attached_controller();
    let tick = kryprobe_privilege::kcrypto_snapshot::SnapshotRows {
        rows: vec![script_agg_as(10, b"cbc(aes)")],
        totals: Some(script_totals(10)),
        idents: vec![script_ident()],
        overflow_identities: 0,
        drops: 0,
        monotonic_ns: 100,
    };
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut sensor = MidStopSensor {
        tick,
        ticks: ticks.clone(),
        finished: std::sync::atomic::AtomicBool::new(false),
    };
    let backend = SuccessBackend {
        decodes: std::sync::atomic::AtomicU64::new(0),
        finalized: std::sync::atomic::AtomicBool::new(false),
        table: kryprobe_privilege::kallsyms::SymTable::parse(""),
    };
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(3600),
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| {
            while ticks.load(std::sync::atomic::Ordering::Relaxed) < 3 {
                std::thread::yield_now();
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        kryprobe_cli::live::drive_session(
            &cfg,
            &backend,
            &mut sensor,
            &stop,
            9,
            kryprobe_core::ids::SessionId::new(1),
            kryprobe_core::ids::PlanGeneration::new(1),
            &kryprobe_core::ids::IdIssuer::default(),
            None,
            &mut controller,
            None,
        )
    })
    .expect("stopped session drives green");
    let served = sensor.ticks.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        (3..=6).contains(&served),
        "stop lands mid-run, promptly ({served} ticks)"
    );
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
    assert!(
        backend.finalized.load(std::sync::atomic::Ordering::Relaxed),
        "finalize ran once"
    );
    assert!(
        sensor.finished.load(std::sync::atomic::Ordering::Relaxed),
        "sensor finish ran once"
    );
}

#[test]
fn live_sigint_ends_window_with_interrupted_outcome() {
    // 4B-M5: a recorded SIGINT ends the window like a stop, but the
    // outcome carries `interrupted` so finishes render partial + exit 3.
    // Serialized (suite guard): SIGINT_SEEN is process-global.
    let _suite = suite_guard();
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut controller = attached_controller();
    let tick = kryprobe_privilege::kcrypto_snapshot::SnapshotRows {
        rows: vec![script_agg_as(10, b"cbc(aes)")],
        totals: Some(script_totals(10)),
        idents: vec![script_ident()],
        overflow_identities: 0,
        drops: 0,
        monotonic_ns: 100,
    };
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut sensor = MidStopSensor {
        tick,
        ticks: ticks.clone(),
        finished: std::sync::atomic::AtomicBool::new(false),
    };
    let backend = SuccessBackend {
        decodes: std::sync::atomic::AtomicU64::new(0),
        finalized: std::sync::atomic::AtomicBool::new(false),
        table: kryprobe_privilege::kallsyms::SymTable::parse(""),
    };
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: None,
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| {
            while ticks.load(std::sync::atomic::Ordering::Relaxed) < 3 {
                std::thread::yield_now();
            }
            kryprobe_privilege::host::SIGINT_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        kryprobe_cli::live::drive_session(
            &cfg,
            &backend,
            &mut sensor,
            &stop,
            9,
            kryprobe_core::ids::SessionId::new(1),
            kryprobe_core::ids::PlanGeneration::new(1),
            &kryprobe_core::ids::IdIssuer::default(),
            None,
            &mut controller,
            None,
        )
    })
    .expect("interrupted session drives green");
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(outcome.interrupted, "outcome carries interrupted");
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
    assert!(
        backend.finalized.load(std::sync::atomic::Ordering::Relaxed),
        "finalize ran once"
    );
}

#[test]
fn live_progress_hook_sees_every_tick() {
    // 4B-M5: the progress hook fires once per tick with (tick, rows, drops).
    let _suite = suite_guard();
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut controller = attached_controller();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let progress = {
        let seen = std::sync::Arc::clone(&seen);
        move |tick: u64, rows: u64, drops: u64| {
            seen.lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((tick, rows, drops));
        }
    };
    let tick = |wall: u64| kryprobe_privilege::kcrypto_snapshot::SnapshotRows {
        rows: vec![script_agg_as(10, b"cbc(aes)")],
        totals: Some(script_totals(10)),
        idents: vec![script_ident()],
        overflow_identities: 0,
        drops: 0,
        monotonic_ns: wall,
    };
    let mut sensor = ScriptedSensor {
        script: vec![tick(100), tick(200)],
        who: kryprobe_privilege::kcrypto_backend::WhoSnapshot {
            key: Default::default(),
            val: Default::default(),
            stack_ips: Vec::new(),
            first_errno: None,
            params: None,
        },
        drop_sites: [0; 8],
        barriers: std::sync::Mutex::new(Vec::new()),
        tables: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicBool::new(false),
    };
    let backend = SuccessBackend {
        decodes: std::sync::atomic::AtomicU64::new(0),
        finalized: std::sync::atomic::AtomicBool::new(false),
        table: kryprobe_privilege::kallsyms::SymTable::parse(""),
    };
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(60),
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let outcome = kryprobe_cli::live::drive_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        9,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        None,
        &mut controller,
        Some(&progress),
    )
    .expect("scripted session drives green");
    assert!(!outcome.interrupted);
    let seen = seen.lock().unwrap_or_else(|poison| poison.into_inner());
    assert_eq!(seen.len(), 2, "one progress call per tick");
    assert_eq!(seen[0].0, 1);
    assert_eq!(seen[1].0, 2);
    assert!(
        seen.iter().all(|(_, rows, _)| *rows == 2),
        "agg + ident rows"
    );
}

#[test]
fn live_observations_bounded_by_row_keys_not_ticks() {
    // H2/H-T3(2): 5 identical ticks accumulate latest-per-key (2 agg +
    // totals + who = 4) plus every disjoint ident (5) — 9 total, not
    // 5x5=25. Memory is O(keys + idents), never O(ticks x rows).
    // H-T3(1): guard before construction (see the 3-tick test).
    let _suite = suite_guard();
    let mut controller = attached_controller();
    let tick = |wall: u64| kryprobe_privilege::kcrypto_snapshot::SnapshotRows {
        rows: vec![
            script_agg_as(10, b"cbc(aes)"),
            script_agg_as(20, b"gcm(aes)"),
        ],
        totals: Some(script_totals(30)),
        idents: vec![script_ident()],
        overflow_identities: 0,
        drops: 7,
        monotonic_ns: wall,
    };
    let mut sensor = ScriptedSensor {
        script: vec![tick(100), tick(200), tick(300), tick(400), tick(500)],
        who: kryprobe_privilege::kcrypto_backend::WhoSnapshot {
            key: Default::default(),
            val: Default::default(),
            stack_ips: Vec::new(),
            first_errno: None,
            params: None,
        },
        drop_sites: [0; 8],
        barriers: std::sync::Mutex::new(Vec::new()),
        tables: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicBool::new(false),
    };
    let backend = SuccessBackend {
        decodes: std::sync::atomic::AtomicU64::new(0),
        finalized: std::sync::atomic::AtomicBool::new(false),
        table: kryprobe_privilege::kallsyms::SymTable::parse(""),
    };
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(60),
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let parses_before = kryprobe_privilege::kallsyms::parse_calls();
    let outcome = kryprobe_cli::live::drive_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        9,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        None,
        &mut controller,
        None,
    )
    .expect("scripted session drives green");
    assert_eq!(
        sensor
            .barriers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len(),
        5,
        "all 5 ticks ran"
    );
    assert_eq!(
        outcome.observations.len(),
        9,
        "latest-per-key (4) + all idents (5), not 25"
    );
    // Decode still runs per row per tick (latest counters need fresh
    // decodes); only accumulation is bounded.
    assert_eq!(
        backend.decodes.load(std::sync::atomic::Ordering::Relaxed),
        20,
        "5 ticks x (2 agg + totals + ident)"
    );
    assert_eq!(
        kryprobe_privilege::kallsyms::parse_calls() - parses_before,
        5,
        "one real parse per tick across 3 who rows per tick (C2)"
    );
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
}

#[test]
fn live_corrupt_snapshot_row_fails_closed() {
    // H3: the in-loop single parse is also the corruption gate — a
    // garbage row fails the tick typed (`Internal`), never panics and
    // never decodes half a row.
    // H-T3(1): guard before construction (see the 3-tick test).
    let _suite = suite_guard();
    let mut controller = attached_controller();
    let mut bad = vec![0u8; 382];
    bad[0] = 0x01;
    bad[1] = 9; // no such row kind
    let tick = kryprobe_privilege::kcrypto_snapshot::SnapshotRows {
        rows: vec![kryprobe_privilege::kcrypto_snapshot::RowBytes::new(bad).expect("382B")],
        totals: None,
        idents: Vec::new(),
        overflow_identities: 0,
        drops: 0,
        monotonic_ns: 100,
    };
    let mut sensor = ScriptedSensor {
        script: vec![tick],
        who: kryprobe_privilege::kcrypto_backend::WhoSnapshot {
            key: Default::default(),
            val: Default::default(),
            stack_ips: Vec::new(),
            first_errno: None,
            params: None,
        },
        drop_sites: [0; 8],
        barriers: std::sync::Mutex::new(Vec::new()),
        tables: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicBool::new(false),
    };
    let backend = SuccessBackend {
        decodes: std::sync::atomic::AtomicU64::new(0),
        finalized: std::sync::atomic::AtomicBool::new(false),
        table: kryprobe_privilege::kallsyms::SymTable::parse(""),
    };
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(60),
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    // The corrupt row fails before the who/kallsyms stage — the
    // session must parse zero tables, not one-per-row-then-fail.
    let parses_before = kryprobe_privilege::kallsyms::parse_calls();
    let err = kryprobe_cli::live::drive_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        9,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        None,
        &mut controller,
        None,
    )
    .expect_err("corrupt row must fail the session");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("live parse agg"),
        "names the failing stage: {msg}"
    );
    assert_eq!(
        backend.decodes.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "nothing decodes past a corrupt row"
    );
    assert_eq!(
        kryprobe_privilege::kallsyms::parse_calls() - parses_before,
        0,
        "corrupt tick parses no kallsyms table"
    );
    // 1B-H4: the failure parks the machine in FailedPartial (the
    // session still fails closed — the escape records, not recovers).
    assert_eq!(
        controller.state(),
        kryprobe_core::session::SessionState::FailedPartial
    );
}

/// 3A-M-T6: fake backend whose decode fails — drives the live session
/// into the `FailedPartial` escape without privilege.
struct FailingBackend;

impl kryprobe_core::backend::Backend for FailingBackend {
    fn id(&self) -> kryprobe_core::enums::BackendId {
        kryprobe_core::enums::BackendId::KCrypto
    }

    fn capabilities(&self) -> &'static kryprobe_core::backend::BackendCapabilities {
        &FAKE_OPEN_CAPS
    }

    fn detect(
        &self,
        _ctx: &kryprobe_core::backend::DetectContext<'_>,
    ) -> Result<Vec<kryprobe_core::backend::DetectedInstance>, kryprobe_core::error::BackendError>
    {
        Ok(vec![kryprobe_core::backend::DetectedInstance {
            backend: kryprobe_core::enums::BackendId::KCrypto,
            object: None,
            detail: "failing fake".to_owned(),
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
            required: FAKE_OPEN_CAPS.required,
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
        Err(kryprobe_core::error::BackendError::Internal(
            kryprobe_core::error::InternalError::new("scripted_decode_failed"),
        ))
    }

    fn finalize(
        &self,
        _ctx: &kryprobe_core::backend::FinalizeContext<'_>,
    ) -> Result<kryprobe_core::backend::BackendSummary, kryprobe_core::error::BackendError> {
        Ok(kryprobe_core::backend::BackendSummary {
            backend: kryprobe_core::enums::BackendId::KCrypto,
            observations: 0,
            integrity: kryprobe_core::evidence::IntegritySummary::default(),
        })
    }
}

#[test]
fn live_backend_failure_runs_failed_partial_recovery() {
    // 3A-M-T6 (1B-H4): a backend decode failure fails the session AND
    // parks the machine in `FailedPartial`; the recovery edge
    // `FailedPartial -> Finalized` stays legal (a future consumer may
    // still finalize partial results — today the escape only records).
    let _suite = suite_guard();
    let mut controller = attached_controller();
    let tick = kryprobe_privilege::kcrypto_snapshot::SnapshotRows {
        rows: vec![script_agg_as(10, b"cbc(aes)")],
        totals: None,
        idents: Vec::new(),
        overflow_identities: 0,
        drops: 0,
        monotonic_ns: 100,
    };
    let mut sensor = ScriptedSensor {
        script: vec![tick],
        who: kryprobe_privilege::kcrypto_backend::WhoSnapshot {
            key: Default::default(),
            val: Default::default(),
            stack_ips: Vec::new(),
            first_errno: None,
            params: None,
        },
        drop_sites: [0; 8],
        barriers: std::sync::Mutex::new(Vec::new()),
        tables: std::sync::atomic::AtomicU64::new(0),
        finished: std::sync::atomic::AtomicBool::new(false),
    };
    let backend = FailingBackend;
    let cfg = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(60),
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::ApiReturns,
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let err = kryprobe_cli::live::drive_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        9,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        None,
        &mut controller,
        None,
    )
    .expect_err("failing decode must fail the session");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("live decode agg"),
        "names the failing stage: {msg}"
    );
    assert_eq!(
        controller.state(),
        kryprobe_core::session::SessionState::FailedPartial
    );
    assert!(
        controller
            .transition(kryprobe_core::session::SessionState::Finalized)
            .is_ok(),
        "FailedPartial -> Finalized recovery edge stays legal"
    );
}

/// T06 item 4: scripted lifecycle sensor serving canned per-tick
/// completions through the `LifecycleSessionSensor` seam — the
/// request-lifecycle success path without privilege. The stop flag is
/// shared with the driver (the seam itself owns no stop): the last
/// scripted tick latches it, so the session ends after its Nth tick.
struct ScriptedLifecycleSensor<'a> {
    ticks: Vec<Vec<kryprobe_core::kcrypto::RequestRecord>>,
    finish_records: Vec<kryprobe_core::kcrypto::RequestRecord>,
    finish_staged: bool,
    ledger: kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleLedger,
    now: u64,
    drains: std::sync::atomic::AtomicU64,
    taken: std::sync::atomic::AtomicU64,
    closed: std::sync::atomic::AtomicBool,
    quiets: std::sync::atomic::AtomicU64,
    quiet_backlog: u64,
    stop: &'a std::sync::atomic::AtomicBool,
}

impl kryprobe_cli::live::LifecycleSessionSensor for ScriptedLifecycleSensor<'_> {
    fn wait_for_activity(
        &mut self,
        _max_wait: std::time::Duration,
        _pending_writer: bool,
    ) -> Result<(), kryprobe_cli::live::LiveError> {
        Ok(()) // The next scripted drain is already available.
    }

    fn drain_tick(
        &mut self,
        _max_records: usize,
    ) -> Result<
        kryprobe_privilege::kcrypto_lifecycle::sensor::DrainOutcome,
        kryprobe_cli::live::LiveError,
    > {
        let call = self
            .drains
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if call + 1 >= self.ticks.len() as u64 {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let completed = self.ticks[(call as usize).min(self.ticks.len() - 1)].len();
        Ok(
            kryprobe_privilege::kcrypto_lifecycle::sensor::DrainOutcome {
                records: completed,
                completed,
                busy: false,
            },
        )
    }

    fn take_completed(
        &mut self,
    ) -> Result<Vec<kryprobe_core::kcrypto::RequestRecord>, kryprobe_cli::live::LiveError> {
        // Retention drains once: the Nth take surfaces the Nth
        // scripted tick; takes past the script (the closing take)
        // surface nothing new — until `finish_stop` stages the
        // reconciled records, which the next take surfaces (the
        // production retain-then-take protocol).
        if self.finish_staged {
            self.finish_staged = false;
            return Ok(self.finish_records.clone());
        }
        let call = self
            .taken
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if call >= self.ticks.len() as u64 {
            return Ok(Vec::new());
        }
        Ok(self.ticks[call as usize].clone())
    }

    fn verify_identity(&self) -> Result<(), kryprobe_cli::live::LiveError> {
        // Scripted sensor: identity is trivially valid (no kernel
        // objects to re-verify).
        Ok(())
    }

    fn close_input(&mut self) -> Result<(), kryprobe_cli::live::LiveError> {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn drain_quiet(
        &mut self,
    ) -> Result<
        kryprobe_privilege::kcrypto_lifecycle::sensor::QuietOutcome,
        kryprobe_cli::live::LiveError,
    > {
        self.quiets
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(
            kryprobe_privilege::kcrypto_lifecycle::sensor::QuietOutcome {
                rounds: 1,
                records: 0,
                quiet: self.quiet_backlog == 0,
                backlog_bytes: self.quiet_backlog,
            },
        )
    }

    fn finish_stop(&mut self, stop_ns: u64) -> Result<(), kryprobe_cli::live::LiveError> {
        assert_eq!(stop_ns, self.now, "finish stamps the closing wall");
        self.finish_staged = true;
        Ok(())
    }

    fn ledger(
        &self,
    ) -> Result<
        kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleLedger,
        kryprobe_cli::live::LiveError,
    > {
        Ok(self.ledger.clone())
    }

    fn now_ns(&self) -> Result<u64, kryprobe_cli::live::LiveError> {
        Ok(self.now)
    }
}

fn lifecycle_record(
    id: u64,
    terminal: kryprobe_core::kcrypto::Terminal,
) -> kryprobe_core::kcrypto::RequestRecord {
    // Mirrors the reducer contract: grounded terminals carry the
    // submit-to-terminal span; Unknown carries no duration (T05
    // rejects unknown+duration — a span without endpoints would be
    // fabricated timing).
    let duration_ns = if terminal == kryprobe_core::kcrypto::Terminal::Unknown {
        None
    } else {
        Some(1000 + id)
    };
    kryprobe_core::kcrypto::RequestRecord {
        id,
        tfm_id: None,
        terminal,
        duration_ns,
        meta: kryprobe_core::kcrypto::RequestMeta {
            family: kryprobe_core::kcrypto::LifecycleFamily::Skcipher,
            direction: kryprobe_core::kcrypto::OpDirection::Encrypt,
            cryptlen: Some(16),
            req_flags: Some(0),
            epoch: Some(0),
            aead: None,
        },
    }
}

fn lifecycle_test_ledger(
    admitted: u64,
    emitted: u64,
    unfinished: u64,
) -> kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleLedger {
    kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleLedger {
        completed: Vec::new(),
        edge_hits: [
            2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        adapter: kryprobe_privilege::kcrypto_lifecycle::async_adapter::AdapterStats::default(),
        decode: kryprobe_privilege::kcrypto_lifecycle::decode::DecodeStats {
            admitted,
            ..kryprobe_privilege::kcrypto_lifecycle::decode::DecodeStats::default()
        },
        reducer: kryprobe_core::kcrypto::ReducerStats {
            admitted,
            emitted,
            unfinished,
            ..kryprobe_core::kcrypto::ReducerStats::default()
        },
        kernel_loss: [0; 5],
        agg_accepted: [
            2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        retained_dropped: 0,
        view_valid: true,
        loss_baseline: [0; 5],
        agg_baseline: [0; 22],
        prog_misses: Vec::new(),
        miss_current: Vec::new(),
        tfm_stats: kryprobe_privilege::kcrypto_lifecycle::tfm::TfmStats::default(),
        generations: Vec::new(),
        enrichment: kryprobe_privilege::kcrypto_lifecycle::sensor::EnrichmentStatus::Available {
            entries: 0,
            truncated: false,
        },
    }
}

fn lifecycle_live_config() -> kryprobe_cli::live::LiveConfig {
    kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: None,
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::RequestLifecycle,
    }
}

#[test]
fn live_lifecycle_scripted_session_drives_green() {
    // T06 item 4: two scripted ticks (grounded sync + callback) plus
    // one truthless finish record decode through the REAL lifecycle
    // backend into three kept observations; the machine finalizes;
    // the shared feed adds nothing (no double count); completion
    // flips on the unfinished record while delivery dimensions stay
    // Unknown.
    use kryprobe_core::kcrypto::Terminal;
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = ScriptedLifecycleSensor {
        ticks: vec![
            vec![lifecycle_record(1, Terminal::Sync(0))],
            vec![lifecycle_record(2, Terminal::Callback(-5))],
        ],
        finish_records: vec![lifecycle_record(3, Terminal::Unknown)],
        finish_staged: false,
        ledger: lifecycle_test_ledger(3, 3, 1),
        now: 555,
        drains: std::sync::atomic::AtomicU64::new(0),
        taken: std::sync::atomic::AtomicU64::new(0),
        closed: std::sync::atomic::AtomicBool::new(false),
        quiets: std::sync::atomic::AtomicU64::new(0),
        quiet_backlog: 0,
        stop: &stop,
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let cfg = lifecycle_live_config();
    // Fully-attached scripted session: the attached count tracks the
    // manifest's program boundary (P4 adds the two fentry callbacks,
    // 7 -> 9) so attachment stays Complete.
    let attached_points = kryprobe_privilege::kcrypto_lifecycle::profile::max_programs(
        &kryprobe_privilege::kcrypto_lifecycle::profile::manifest(
            kryprobe_privilege::kcrypto_lifecycle::profile::LifecycleProfile::RequestLifecycle,
        ),
    );
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        attached_points,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("scripted lifecycle session drives green");
    assert_eq!(outcome.observations.len(), 3, "every completion kept");
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
    assert_eq!(outcome.summary.observations, 3, "decode counts all three");
    // Same profile/decoder: every observation carries the lifecycle
    // envelope (row + capture profile + terminal triple).
    for observation in &outcome.observations {
        assert_eq!(
            observation.backend_payload["row"], "lifecycle",
            "lifecycle row: {}",
            observation.backend_payload
        );
        assert_eq!(
            observation.backend_payload["capture_profile"], "request-lifecycle",
            "lifecycle profile: {}",
            observation.backend_payload
        );
    }
    assert_eq!(
        outcome.observations[0].backend_payload["terminal"],
        serde_json::json!("sync")
    );
    assert_eq!(
        outcome.observations[0].backend_payload["status"],
        serde_json::json!(0)
    );
    assert_eq!(
        outcome.observations[1].backend_payload["terminal"],
        serde_json::json!("callback")
    );
    assert_eq!(
        outcome.observations[2].backend_payload["terminal"],
        serde_json::json!("unknown")
    );
    assert!(
        outcome.observations[2].backend_payload["status"].is_null(),
        "unknown terminal carries no trusted status: {}",
        outcome.observations[2].backend_payload
    );
    // Empty shared feed: session integrity equals the summary
    // integrity exactly (a second accrual would double).
    assert_eq!(
        outcome.integrity, outcome.summary.integrity,
        "no double count through the shared feed"
    );
    // Coverage: unfinished flips completion; delivery stays Unknown.
    assert_eq!(
        outcome.coverage.completion.status,
        kryprobe_core::enums::CoverageStatus::Partial
    );
    assert_eq!(
        outcome.coverage.aggregate_counts.status,
        kryprobe_core::enums::CoverageStatus::Unknown
    );
    assert_eq!(
        outcome.coverage.detailed_events.status,
        kryprobe_core::enums::CoverageStatus::Unknown
    );
    assert_eq!(
        outcome.coverage.attachment.status,
        kryprobe_core::enums::CoverageStatus::CompleteForDeclaredBoundary
    );
    // Ring-clock interval: both walls are the scripted now.
    assert_eq!(outcome.coverage.completion.interval.start_ns, 555);
    assert_eq!(outcome.coverage.completion.interval.end_ns, Some(555));
    // Two loop ticks (the close drains quiet, not ticked).
    assert_eq!(
        sensor.drains.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "2 loop ticks"
    );
    // Detach-then-drain ran exactly once at close.
    assert!(
        sensor.closed.load(std::sync::atomic::Ordering::Relaxed),
        "input closed at close"
    );
    assert_eq!(
        sensor.quiets.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "one quiet drain at close"
    );
}

#[test]
fn live_lifecycle_observation_cap_truncates_deterministically() {
    // Round-2 (sol-M2/astra-M4, C12): past 100K decoded records the
    // session stops early with exactly the cap kept, an explicit
    // truncation counter, and `Partial` completion — bounded
    // memory, valid kept evidence, loud stop.
    use kryprobe_core::kcrypto::Terminal;
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let flood: Vec<kryprobe_core::kcrypto::RequestRecord> = (0..100_001)
        .map(|id| lifecycle_record(id, Terminal::Sync(0)))
        .collect();
    let mut sensor = ScriptedLifecycleSensor {
        ticks: vec![flood],
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(100_001, 100_001, 0),
        now: 999,
        drains: std::sync::atomic::AtomicU64::new(0),
        taken: std::sync::atomic::AtomicU64::new(0),
        closed: std::sync::atomic::AtomicBool::new(false),
        quiets: std::sync::atomic::AtomicU64::new(0),
        quiet_backlog: 0,
        stop: &stop,
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let cfg = lifecycle_live_config();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("truncated session still finalizes");
    assert_eq!(outcome.observations.len(), 100_000, "cap kept exactly");
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
    assert_eq!(
        outcome.coverage.completion.status,
        kryprobe_core::enums::CoverageStatus::Partial,
        "truncation flips completion"
    );
    assert!(
        outcome
            .coverage
            .completion
            .counters
            .iter()
            .any(|c| c.name == "observations_truncated" && c.value == 1),
        "truncation counter present: {:?}",
        outcome.coverage.completion.counters
    );
    // Round-3 (sol/astra-M3): the dropped record is COUNTED in
    // session integrity (`budget_omissions`), never silently
    // omitted — memory bounded AND output loss accounted.
    assert_eq!(
        outcome.integrity.budget_omissions, 1,
        "one cap drop attested: {:?}",
        outcome.integrity
    );
}

#[test]
fn live_lifecycle_close_backlog_flips_transport() {
    // Round-2 (sol-M2/astra-M3): a nonzero quiet-verdict backlog
    // reaches coverage and flips `detailed_events` — teardown
    // backlog is reported evidence, never vanishing state.
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = ScriptedLifecycleSensor {
        ticks: vec![Vec::new()],
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(0, 0, 0),
        now: 111,
        drains: std::sync::atomic::AtomicU64::new(0),
        taken: std::sync::atomic::AtomicU64::new(0),
        closed: std::sync::atomic::AtomicBool::new(false),
        quiets: std::sync::atomic::AtomicU64::new(0),
        quiet_backlog: 80,
        stop: &stop,
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let cfg = lifecycle_live_config();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("backlogged close still finalizes");
    assert_eq!(
        outcome.coverage.detailed_events.status,
        kryprobe_core::enums::CoverageStatus::Partial,
        "backlog flips transport"
    );
    assert!(
        outcome
            .coverage
            .detailed_events
            .counters
            .iter()
            .any(|c| c.name == "close_backlog_bytes" && c.value == 80),
        "backlog counter present: {:?}",
        outcome.coverage.detailed_events.counters
    );
    assert_eq!(
        outcome.coverage.completion.status,
        kryprobe_core::enums::CoverageStatus::Partial,
        "M2 provisional-hold: close backlog voids exact completion"
    );
}

#[test]
fn live_lifecycle_registry_backend_drives_same_decoder() {
    // T06 item 4 core: the backend reached through the REAL registry
    // (registered via `register_lifecycle_shared`) decodes and
    // finalizes through the live driver — registry and live entry
    // points choose the same profile/decoder, pinned without
    // privilege (no configure/attach runs here).
    let mut registry = kryprobe_core::backend::BackendRegistry::new();
    kryprobe_privilege::kcrypto_lifecycle::backend::register_lifecycle_shared(&mut registry)
        .expect("lifecycle registers once");
    let backend = registry
        .get(kryprobe_core::enums::BackendId::KCrypto)
        .expect("registered backend resolves");
    assert_eq!(backend.capabilities().name, "kcrypto-lifecycle");
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = ScriptedLifecycleSensor {
        ticks: vec![Vec::new()],
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(0, 0, 0),
        now: 777,
        drains: std::sync::atomic::AtomicU64::new(0),
        taken: std::sync::atomic::AtomicU64::new(0),
        closed: std::sync::atomic::AtomicBool::new(false),
        quiets: std::sync::atomic::AtomicU64::new(0),
        quiet_backlog: 0,
        stop: &stop,
    };
    let cfg = lifecycle_live_config();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("registry backend drives through the live driver");
    assert!(outcome.observations.is_empty(), "no completions, no rows");
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
    assert_eq!(
        outcome.coverage.completion.status,
        kryprobe_core::enums::CoverageStatus::CompleteForDeclaredBoundary,
        "nothing unfinished completes"
    );
}

#[test]
fn live_lifecycle_unconfigured_sensor_refuses_typed() {
    // The production sensor over an unconfigured backend refuses on
    // the first tick with a typed `Internal` naming the lifecycle
    // stage (the `session_sensor` precedent); the machine parks in
    // `FailedPartial` (best-effort — the original error wins).
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let mut production = kryprobe_cli::live::RealLifecycleSensor::new(&backend);
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let cfg = lifecycle_live_config();
    let err = kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        &backend,
        &mut production,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect_err("unconfigured sensor must refuse");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("lifecycle"),
        "names the lifecycle stage: {msg}"
    );
    assert!(
        matches!(err, kryprobe_cli::live::LiveError::Internal(_)),
        "driver defect maps Internal: {msg}"
    );
    assert_eq!(
        controller.state(),
        kryprobe_core::session::SessionState::FailedPartial
    );
}

/// Scripted drain outcomes for sustained-drain tests (T07-R3-05):
/// `drain_tick` serves one scripted `(records, busy)` outcome per
/// call, `take_completed` serves one scripted batch per take; past
/// either script, drains go quiet and takes go empty. Sets the
/// shared stop flag once `stop_after_drains` drains have run
/// (`u64::MAX` disables — the session's own deadline/cap ends it).
struct BurstLifecycleSensor<'a> {
    drains: Vec<(usize, bool)>,
    takes: Vec<Vec<kryprobe_core::kcrypto::RequestRecord>>,
    finish_records: Vec<kryprobe_core::kcrypto::RequestRecord>,
    finish_staged: bool,
    ledger: kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleLedger,
    now: u64,
    drain_calls: std::sync::atomic::AtomicU64,
    take_calls: std::sync::atomic::AtomicU64,
    stop_after_drains: u64,
    stop: &'a std::sync::atomic::AtomicBool,
    quiet_gate: Option<(
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
    delivered: Option<std::sync::mpsc::SyncSender<()>>,
    stop_on_wait: bool,
}

impl kryprobe_cli::live::LifecycleSessionSensor for BurstLifecycleSensor<'_> {
    fn wait_for_activity(
        &mut self,
        max_wait: std::time::Duration,
        pending_writer: bool,
    ) -> Result<(), kryprobe_cli::live::LiveError> {
        if self.stop_on_wait {
            assert!(
                pending_writer,
                "busy head needs a retry yield, not readable-fd spinning"
            );
            assert!(
                max_wait <= std::time::Duration::from_millis(50),
                "cancellation remains bounded"
            );
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(()) // The producer gate has already made the next batch ready.
    }

    fn drain_tick(
        &mut self,
        _max_records: usize,
    ) -> Result<
        kryprobe_privilege::kcrypto_lifecycle::sensor::DrainOutcome,
        kryprobe_cli::live::LiveError,
    > {
        let call = self
            .drain_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if call + 1 >= self.stop_after_drains {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let (records, busy) = self
            .drains
            .get(call as usize)
            .copied()
            .unwrap_or((0, false));
        if records == 0 && !busy {
            if let Some((quiet, resume)) = self.quiet_gate.take() {
                quiet.send(()).expect("announce quiet snapshot");
                resume.recv().expect("producer releases snapshot");
            }
        } else if records > 0
            && let Some(delivered) = self.delivered.take()
        {
            delivered.send(()).expect("announce drain after idle");
        }
        Ok(
            kryprobe_privilege::kcrypto_lifecycle::sensor::DrainOutcome {
                records,
                completed: records,
                busy,
            },
        )
    }

    fn take_completed(
        &mut self,
    ) -> Result<Vec<kryprobe_core::kcrypto::RequestRecord>, kryprobe_cli::live::LiveError> {
        if self.finish_staged {
            self.finish_staged = false;
            return Ok(self.finish_records.clone());
        }
        let call = self
            .take_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.takes.get(call as usize).cloned().unwrap_or_default())
    }

    fn verify_identity(&self) -> Result<(), kryprobe_cli::live::LiveError> {
        Ok(())
    }

    fn close_input(&mut self) -> Result<(), kryprobe_cli::live::LiveError> {
        Ok(())
    }

    fn drain_quiet(
        &mut self,
    ) -> Result<
        kryprobe_privilege::kcrypto_lifecycle::sensor::QuietOutcome,
        kryprobe_cli::live::LiveError,
    > {
        Ok(
            kryprobe_privilege::kcrypto_lifecycle::sensor::QuietOutcome {
                rounds: 1,
                records: 0,
                quiet: true,
                backlog_bytes: 0,
            },
        )
    }

    fn finish_stop(&mut self, stop_ns: u64) -> Result<(), kryprobe_cli::live::LiveError> {
        assert_eq!(stop_ns, self.now, "finish stamps the closing wall");
        self.finish_staged = true;
        Ok(())
    }

    fn ledger(
        &self,
    ) -> Result<
        kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleLedger,
        kryprobe_cli::live::LiveError,
    > {
        Ok(self.ledger.clone())
    }

    fn now_ns(&self) -> Result<u64, kryprobe_cli::live::LiveError> {
        Ok(self.now)
    }
}

#[test]
fn live_lifecycle_tick_drains_to_quiet() {
    // T07-R3-05: one tick sustains three drain rounds (busy, busy,
    // quiet) — the burst collapses into a SINGLE window (one
    // progress call with the summed rows/records), not three
    // sleep-separated ticks that let the ring drop mid-burst.
    use kryprobe_core::kcrypto::Terminal;
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = BurstLifecycleSensor {
        drains: vec![(5, false), (3, false), (0, false)],
        takes: vec![
            vec![lifecycle_record(1, Terminal::Sync(0))],
            vec![lifecycle_record(2, Terminal::Sync(0))],
            Vec::new(),
        ],
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(2, 2, 0),
        now: 555,
        drain_calls: std::sync::atomic::AtomicU64::new(0),
        take_calls: std::sync::atomic::AtomicU64::new(0),
        stop_after_drains: 3,
        stop: &stop,
        quiet_gate: None,
        delivered: None,
        stop_on_wait: false,
    };
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let progress = {
        let seen = std::sync::Arc::clone(&seen);
        move |tick: u64, rows: u64, drops: u64| {
            seen.lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((tick, rows, drops));
        }
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let cfg = lifecycle_live_config();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        Some(&progress),
    )
    .expect("sustained session drives green");
    assert_eq!(
        sensor
            .drain_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        3,
        "three rounds drained"
    );
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "one window for the burst: {seen:?}");
    assert_eq!(seen[0], (1, 2, 8), "rows and drops summed: {seen:?}");
    assert_eq!(outcome.observations.len(), 2, "every completion kept");
    assert_eq!(outcome.summary.observations, 2);
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
}

#[test]
fn live_lifecycle_drain_round_cap_bounds_flood() {
    // T07-R3-05: an endless busy producer cannot starve the window
    // — the per-tick round cap bounds the sustained loop (the
    // first window drains exactly 8 rounds), the window still
    // elapses (progress flows), and the stop flag ends the session
    // on the next round.
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = BurstLifecycleSensor {
        drains: vec![(10, false); 20],
        takes: Vec::new(),
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(0, 0, 0),
        now: 555,
        drain_calls: std::sync::atomic::AtomicU64::new(0),
        take_calls: std::sync::atomic::AtomicU64::new(0),
        stop_after_drains: 9,
        stop: &stop,
        quiet_gate: None,
        delivered: None,
        stop_on_wait: false,
    };
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let progress = {
        let seen = std::sync::Arc::clone(&seen);
        move |tick: u64, rows: u64, drops: u64| {
            seen.lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((tick, rows, drops));
        }
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let cfg = lifecycle_live_config();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        Some(&progress),
    )
    .expect("capped session drives green");
    assert_eq!(
        sensor
            .drain_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        9,
        "8 capped rounds + 1 stop round"
    );
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "windows elapse under flood: {seen:?}");
    assert_eq!(seen[0], (1, 0, 80), "first window capped at 8×10: {seen:?}");
    assert!(outcome.observations.is_empty());
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
}

#[test]
fn live_lifecycle_idle_burst_does_not_wait_for_display_tick() {
    // Catch a driver that sleeps for the display cadence after an empty
    // ring snapshot. Channels place the burst after that snapshot; no
    // sleep guesses where the producer and consumer are. The receive
    // timeout is a deadlock/response guard, not the synchronization.
    use std::sync::{atomic::AtomicBool, mpsc::sync_channel};
    use std::time::Duration;
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let stop = AtomicBool::new(false);
    let (quiet_tx, quiet_rx) = sync_channel(1);
    let (resume_tx, resume_rx) = sync_channel(1);
    let (delivered_tx, delivered_rx) = sync_channel(1);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut sensor = BurstLifecycleSensor {
                drains: vec![(0, false), (1, false)],
                takes: vec![
                    Vec::new(),
                    vec![lifecycle_record(
                        1,
                        kryprobe_core::kcrypto::Terminal::Sync(0),
                    )],
                ],
                finish_records: Vec::new(),
                finish_staged: false,
                ledger: lifecycle_test_ledger(1, 1, 0),
                now: 555,
                drain_calls: std::sync::atomic::AtomicU64::new(0),
                take_calls: std::sync::atomic::AtomicU64::new(0),
                stop_after_drains: 2,
                stop: &stop,
                quiet_gate: Some((quiet_tx, resume_rx)),
                delivered: Some(delivered_tx),
                stop_on_wait: false,
            };
            let mut cfg = lifecycle_live_config();
            cfg.tick_ms = 30_000;
            let mut controller = attached_controller();
            kryprobe_cli::live::drive_lifecycle_session(
                &cfg,
                &kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new(),
                &mut sensor,
                &stop,
                7,
                kryprobe_core::ids::SessionId::new(1),
                kryprobe_core::ids::PlanGeneration::new(1),
                &kryprobe_core::ids::IdIssuer::default(),
                &mut controller,
                None,
            )
        });
        let quiet = quiet_rx.recv_timeout(Duration::from_secs(2));
        let released = resume_tx.send(());
        let responsive = delivered_rx.recv_timeout(Duration::from_secs(2));
        // Always stop and join, including the failing old implementation.
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let outcome = worker
            .join()
            .expect("session worker")
            .expect("session result");
        assert!(quiet.is_ok(), "initial quiet snapshot reached: {quiet:?}");
        assert!(released.is_ok(), "producer released the snapshot");
        assert!(
            responsive.is_ok(),
            "ready burst waited for the display tick: {responsive:?}"
        );
        assert_eq!(outcome.observations.len(), 1, "owned completion preserved");
    });
}
#[test]
fn live_lifecycle_display_cadence_is_independent_of_drain_windows() {
    // A backlog requires three service windows, all before the next
    // display tick. Only the initial update and final pending totals
    // should reach the output callback.
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = BurstLifecycleSensor {
        drains: vec![(10, false); 17],
        takes: Vec::new(),
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(0, 0, 0),
        now: 555,
        drain_calls: std::sync::atomic::AtomicU64::new(0),
        take_calls: std::sync::atomic::AtomicU64::new(0),
        stop_after_drains: 17,
        stop: &stop,
        quiet_gate: None,
        delivered: None,
        stop_on_wait: false,
    };
    let mut cfg = lifecycle_live_config();
    cfg.tick_ms = 30_000;
    let mut controller = attached_controller();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let report = {
        let seen = std::sync::Arc::clone(&seen);
        move |tick, rows, records| seen.lock().unwrap().push((tick, rows, records))
    };
    kryprobe_cli::live::drive_lifecycle_session(
        &cfg,
        &kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new(),
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        Some(&report),
    )
    .expect("session");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(1, 0, 80), (2, 0, 90)],
        "busy drains must not turn display updates into a hot output loop"
    );
}

#[test]
fn live_lifecycle_busy_without_progress_services_wait_and_stop() {
    // A pending producer can leave the oldest record busy. A bounded
    // drain cap alone still spins between windows unless zero-progress
    // windows yield. Cancellation arrives at that wait boundary.
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = BurstLifecycleSensor {
        drains: vec![(0, true); 17],
        takes: Vec::new(),
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(0, 0, 0),
        now: 555,
        drain_calls: std::sync::atomic::AtomicU64::new(0),
        take_calls: std::sync::atomic::AtomicU64::new(0),
        stop_after_drains: 17, // watchdog bounds the broken spin path
        stop: &stop,
        quiet_gate: None,
        delivered: None,
        stop_on_wait: true,
    };
    let mut controller = attached_controller();
    kryprobe_cli::live::drive_lifecycle_session(
        &lifecycle_live_config(),
        &kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new(),
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("session");
    assert!(
        sensor
            .drain_calls
            .load(std::sync::atomic::Ordering::Relaxed)
            <= 9,
        "busy record spun through multiple windows instead of yielding"
    );
}

#[test]
fn sustained_backlog_services_stop() {
    // P2/K05: records keep flowing (sustained backlog); stop must be
    // serviced inside the same window — the round cap and quiet are
    // bounds, not prerequisites. Stop latched at round 5 of 8 ends
    // the session at exactly 5 drains; every completion is kept.
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    use kryprobe_core::kcrypto::Terminal;
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = BurstLifecycleSensor {
        drains: vec![(10, false); 8],
        takes: (1..=5)
            .map(|id| vec![lifecycle_record(id, Terminal::Sync(0))])
            .collect(),
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(5, 5, 0),
        now: 555,
        drain_calls: std::sync::atomic::AtomicU64::new(0),
        take_calls: std::sync::atomic::AtomicU64::new(0),
        stop_after_drains: 5,
        stop: &stop,
        quiet_gate: None,
        delivered: None,
        stop_on_wait: false,
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &lifecycle_live_config(),
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("stopped session still finalizes");
    assert_eq!(
        sensor
            .drain_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        5,
        "stop waited for quiet/round cap instead of ending the window"
    );
    assert_eq!(outcome.observations.len(), 5, "every completion kept");
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
}

#[test]
fn busy_record_yields_without_spin() {
    // P2/K05: a busy head with zero progress yields through
    // `wait_for_activity` (pending-writer retry, bounded wait —
    // asserted inside the fake) instead of spinning windows.
    // Cancellation latched at that single wait ends the session:
    // exactly 8 capped rounds + 1 stop round proves one yield.
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = BurstLifecycleSensor {
        drains: vec![(0, true); 17],
        takes: Vec::new(),
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(0, 0, 0),
        now: 555,
        drain_calls: std::sync::atomic::AtomicU64::new(0),
        take_calls: std::sync::atomic::AtomicU64::new(0),
        stop_after_drains: 17, // watchdog bounds the broken spin path
        stop: &stop,
        quiet_gate: None,
        delivered: None,
        stop_on_wait: true,
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &lifecycle_live_config(),
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("yielded session still finalizes");
    assert_eq!(
        sensor
            .drain_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        9,
        "busy record spun past one window instead of yielding once"
    );
    assert!(outcome.observations.is_empty());
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
}

#[test]
fn observation_cap_counts_omissions() {
    // P2/K05: cap truncation counts EVERY dropped record across
    // batches — loop batches plus stop-time reconciliation — not a
    // bare flag. 60K + 60K loop records with a 10-record finish tail
    // keeps exactly 100K and attests 20,010 omissions in both the
    // coverage counter and session integrity (the existing
    // single-drop test cannot tell a flag from a count).
    use kryprobe_core::kcrypto::Terminal;
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let batch = |base: u64| {
        (base..base + 60_000)
            .map(|id| lifecycle_record(id, Terminal::Sync(0)))
            .collect::<Vec<_>>()
    };
    let mut sensor = BurstLifecycleSensor {
        drains: vec![(60_000, false), (60_000, false)],
        takes: vec![batch(0), batch(60_000)],
        finish_records: (120_000..120_010)
            .map(|id| lifecycle_record(id, Terminal::Sync(0)))
            .collect(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(120_010, 120_010, 0),
        now: 999,
        drain_calls: std::sync::atomic::AtomicU64::new(0),
        take_calls: std::sync::atomic::AtomicU64::new(0),
        stop_after_drains: u64::MAX, // the cap itself must stop the loop
        stop: &stop,
        quiet_gate: None,
        delivered: None,
        stop_on_wait: false,
    };
    let backend = kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new();
    let outcome = kryprobe_cli::live::drive_lifecycle_session(
        &lifecycle_live_config(),
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("truncated session still finalizes");
    assert_eq!(
        sensor
            .drain_calls
            .load(std::sync::atomic::Ordering::Relaxed),
        2,
        "cap must stop the loop after the second batch"
    );
    assert_eq!(outcome.observations.len(), 100_000, "cap kept exactly");
    assert_eq!(
        outcome.integrity.budget_omissions, 20_010,
        "every dropped record attested: {:?}",
        outcome.integrity
    );
    assert!(
        outcome
            .coverage
            .completion
            .counters
            .iter()
            .any(|c| c.name == "observations_truncated" && c.value == 20_010),
        "truncation count (not flag) present: {:?}",
        outcome.coverage.completion.counters
    );
    assert_eq!(
        outcome.coverage.completion.status,
        kryprobe_core::enums::CoverageStatus::Partial,
        "truncation flips completion"
    );
    assert_eq!(
        outcome.terminal_state,
        kryprobe_core::session::SessionState::Finalized
    );
}

/// P2/K05: lifecycle backend whose terminal accounting fails — the
/// final-output seam. Decodes delegate to the real backend; only
/// `finalize` (end-of-session facts) reports a defect.
struct FinalizeFailingBackend {
    inner: kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend,
}

impl kryprobe_core::backend::Backend for FinalizeFailingBackend {
    fn id(&self) -> kryprobe_core::enums::BackendId {
        self.inner.id()
    }

    fn capabilities(&self) -> &'static kryprobe_core::backend::BackendCapabilities {
        self.inner.capabilities()
    }

    fn detect(
        &self,
        ctx: &kryprobe_core::backend::DetectContext<'_>,
    ) -> Result<Vec<kryprobe_core::backend::DetectedInstance>, kryprobe_core::error::BackendError>
    {
        self.inner.detect(ctx)
    }

    fn plan(
        &self,
        ctx: &kryprobe_core::backend::PlanContext<'_>,
        instance: &kryprobe_core::backend::DetectedInstance,
        mode: kryprobe_core::enums::CaptureMode,
    ) -> Result<kryprobe_core::backend::BackendPlan, kryprobe_core::error::BackendError> {
        self.inner.plan(ctx, instance, mode)
    }

    fn configure(
        &self,
        ctx: &mut kryprobe_core::backend::ConfigureContext<'_>,
        plan: &kryprobe_core::backend::BackendPlan,
    ) -> Result<(), kryprobe_core::error::BackendError> {
        self.inner.configure(ctx, plan)
    }

    fn decode(
        &self,
        ctx: &kryprobe_core::backend::DecodeContext<'_>,
        event: kryprobe_core::backend::RawEvent<'_>,
    ) -> Result<kryprobe_core::evidence::NativeObservation, kryprobe_core::error::BackendError>
    {
        self.inner.decode(ctx, event)
    }

    fn finalize(
        &self,
        _ctx: &kryprobe_core::backend::FinalizeContext<'_>,
    ) -> Result<kryprobe_core::backend::BackendSummary, kryprobe_core::error::BackendError> {
        Err(kryprobe_core::error::BackendError::Internal(
            kryprobe_core::error::InternalError::new("p2_probe_finalize_failed"),
        ))
    }

    fn note_output_omissions(&self, omitted: u64) {
        self.inner.note_output_omissions(omitted);
    }
}

#[test]
fn backend_finalize_failure_parks_failed_partial() {
    // P2/K05 (P2r/C5 renamed: this covers backend finalization, not
    // the final-output seams — a terminal-accounting (finalize)
    // failure cannot yield a clean session): the driver surfaces the
    // error and parks the machine in `FailedPartial`, never
    // `Finalized`.
    kryprobe_privilege::host::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    let mut controller = attached_controller();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut sensor = ScriptedLifecycleSensor {
        ticks: vec![Vec::new()],
        finish_records: Vec::new(),
        finish_staged: false,
        ledger: lifecycle_test_ledger(0, 0, 0),
        now: 555,
        drains: std::sync::atomic::AtomicU64::new(0),
        taken: std::sync::atomic::AtomicU64::new(0),
        closed: std::sync::atomic::AtomicBool::new(false),
        quiets: std::sync::atomic::AtomicU64::new(0),
        quiet_backlog: 0,
        stop: &stop,
    };
    let backend = FinalizeFailingBackend {
        inner: kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend::new(),
    };
    let err = kryprobe_cli::live::drive_lifecycle_session(
        &lifecycle_live_config(),
        &backend,
        &mut sensor,
        &stop,
        7,
        kryprobe_core::ids::SessionId::new(1),
        kryprobe_core::ids::PlanGeneration::new(1),
        &kryprobe_core::ids::IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect_err("finalize failure must surface, not pass clean");
    assert!(
        matches!(err, kryprobe_cli::live::LiveError::Internal(_)),
        "defect-class finalize failure stays Internal: {err:?}"
    );
    assert_eq!(
        controller.state(),
        kryprobe_core::session::SessionState::FailedPartial,
        "failed session parks FailedPartial, never Finalized"
    );
}

#[test]
fn selftest_out_write_failure_cannot_be_clean() {
    // P2r/C5: the reached `--out` final-write seam through `run()`.
    // `selftest synthetic` is deterministic and needs no privilege;
    // an unwritable `--out` (missing parent dir, so the atomic
    // tmp+rename cannot land) must exit not-clean with the path on
    // stderr. Positive control first: the same command to a good
    // writer exits 0, proving validation passed and only the write
    // failed below.
    let argv_ok: Vec<String> = ["kryprobe", "selftest", "synthetic"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = kryprobe_cli::run(&argv_ok, &mut stdout, &mut stderr);
    assert_eq!(
        code,
        0,
        "control run must exit clean: stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(!stdout.is_empty(), "control run must emit JSONL");
    let dir = scratch("out-fail");
    let bad = dir.path().join("no-such-dir").join("synth.jsonl");
    let argv_bad: Vec<String> = [
        "kryprobe",
        "selftest",
        "synthetic",
        "--out",
        bad.to_str().expect("utf-8 scratch path"),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = kryprobe_cli::run(&argv_bad, &mut stdout, &mut stderr);
    assert_ne!(code, 0, "failed --out write must not exit clean");
    let stderr_text = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        stderr_text.contains("cannot write") && stderr_text.contains("no-such-dir"),
        "stderr names the failed write: {stderr_text}"
    );
    assert!(stdout.is_empty(), "file run writes no stdout");
}

#[test]
fn report_live_unwritable_out_reaches_live_handler() {
    // P2r2/R2(a): the run()-level proof on the LIVE report path
    // (ReportLive argv -> cmd_report::run_report_live, not the
    // selftest writer). The jsonl + request-lifecycle pre-gate refuses
    // BEFORE any capture, so this runs deterministically on every
    // host — a kernel-crypto capture would need privilege and would
    // execute a real window where available. Control first: a good
    // --out still refuses (exit 1, no file written — refusal precedes
    // any write); then the unwritable --out reaches the same live
    // refusal, never a selftest verdict.
    //
    // Residual, stated not claimed: the --out write-failure branch
    // itself (cmd_report.rs finish) needs a completed capture to
    // reach at run() level (privilege); it stays covered by the
    // direct unit test. This test pins the live dispatch, the --out
    // plumbing, and the refusal-before-write order.
    let dir = scratch("report-live-out");
    let good = dir.path().join("report.jsonl");
    let argv_good: Vec<String> = [
        "kryprobe",
        "report",
        "--system",
        "--format",
        "jsonl",
        "--kcrypto-profile",
        "request-lifecycle",
        "--out",
        good.to_str().expect("utf-8 scratch path"),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = kryprobe_cli::run(&argv_good, &mut stdout, &mut stderr);
    assert_eq!(
        code,
        1,
        "live pre-gate refuses: stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let text = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        text.contains("cannot export request-lifecycle rows"),
        "live refusal named: {text}"
    );
    assert!(
        text.contains("report:"),
        "verdict comes from the live report handler: {text}"
    );
    assert!(stdout.is_empty(), "no capture output past the gate");
    assert!(!good.exists(), "refusal precedes any --out write");
    // Fault: unwritable --out (missing parent dir) reaches the same
    // live refusal — the failure mode is the gate's, not a write's.
    let bad = dir.path().join("no-such-dir").join("report.jsonl");
    let argv_bad: Vec<String> = [
        "kryprobe",
        "report",
        "--system",
        "--format",
        "jsonl",
        "--kcrypto-profile",
        "request-lifecycle",
        "--out",
        bad.to_str().expect("utf-8 scratch path"),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = kryprobe_cli::run(&argv_bad, &mut stdout, &mut stderr);
    assert_eq!(
        code,
        1,
        "unwritable --out keeps the live refusal: stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let text = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        text.contains("cannot export request-lifecycle rows"),
        "live refusal named: {text}"
    );
    assert!(
        !text.contains("cannot write"),
        "no write attempted past the gate: {text}"
    );
    assert!(
        !text.contains("selftest"),
        "verdict is the live handler's, not selftest's: {text}"
    );
    assert!(stdout.is_empty());
}

#[test]
fn stdout_flush_failure_cannot_be_clean() {
    // P2r/C5: the reached stdout write-failure seam end to end: the
    // real binary with stdout wired to /dev/full (every write fails
    // ENOSPC) must exit not-clean with the stdout note on stderr.
    // Positive control first: piped stdout exits 0, proving the
    // command itself is clean in this environment.
    //
    // P2r2/R2(b): this test fails at WRITE time, so it cannot see a
    // flush-only failure (Astra's flush-removal mutation stayed
    // green). Flush-only sensitivity lives in the main.rs unit test
    // `flush_only_failure_is_not_clean`, which drives the factored
    // main tail with an injected writer.
    let bin = env!("CARGO_BIN_EXE_kryprobe");
    let control = std::process::Command::new(bin)
        .args(["selftest", "synthetic"])
        .output()
        .expect("spawn control");
    assert!(
        control.status.success(),
        "control run must exit clean: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(!control.stdout.is_empty(), "control run must emit JSONL");
    let full = std::fs::File::create("/dev/full").expect("open /dev/full");
    let out = std::process::Command::new(bin)
        .args(["selftest", "synthetic"])
        .stdout(std::process::Stdio::from(full))
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn /dev/full run");
    assert!(
        !out.status.success(),
        "failed stdout flush must not exit clean"
    );
    let stderr_text = String::from_utf8(out.stderr).expect("stderr utf-8");
    assert!(
        stderr_text.contains("stdout"),
        "stderr names stdout: {stderr_text}"
    );
}
