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

/// Unique scratch dir per test (no shared state; removed on success).
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kryprobe-k3-1-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
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
    let dir = scratch("locator-file");
    let file = dir.join("custom.o");
    std::fs::write(&file, b"fake-object").expect("write tmp object");
    set_bpf_dir(file.as_os_str());
    let found = kryprobe_privilege::locate_kcrypto_object().expect("env file locates");
    assert_eq!(found, file, "tier 1: env file tried as-is");
    match prior {
        Some(value) => set_bpf_dir(&value),
        None => remove_bpf_dir(),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn locator_env_dir_joins_live() {
    let _guard = env_guard();
    let prior = std::env::var_os("KRYPROBE_BPF_DIR");
    let dir = scratch("locator-dir");
    let object = dir.join("kcrypto.bpf.o");
    std::fs::write(&object, b"fake-object").expect("write tmp object");
    set_bpf_dir(dir.as_os_str());
    let found = kryprobe_privilege::locate_kcrypto_object().expect("env dir locates");
    assert_eq!(found, object, "tier 1: env dir joined with kcrypto.bpf.o");
    match prior {
        Some(value) => set_bpf_dir(&value),
        None => remove_bpf_dir(),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn locator_miss_or_dev_fallback_pins_order() {
    let _guard = env_guard();
    let prior = std::env::var_os("KRYPROBE_BPF_DIR");
    // Absent env path: tier 1 must miss; tiers 2 (exe-dir) and 3 (CWD dev)
    // then decide the outcome. The dev tier may legitimately hit on trees
    // with a prebuilt object, so both arms assert exact order evidence.
    let absent = std::env::temp_dir().join(format!("kryprobe-k3-1-absent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&absent);
    let _ = std::fs::remove_file(&absent);
    set_bpf_dir(absent.as_os_str());
    let tier1 = absent.join("kcrypto.bpf.o");
    let tier2 = exe_tier_candidate();
    let tier3 = PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o");
    match kryprobe_privilege::locate_kcrypto_object() {
        Ok(path) => assert_eq!(
            path, tier3,
            "only the dev fallback may rescue an env+exe miss (tiers 1-2 missed)"
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
    Some(
        String::from_utf8(output.stdout)
            .ok()?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
    )
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
    // object through the consolidated locator; the env tier is exact.
    let object_path = kcrypto_object_path();
    assert!(
        object_path.is_file(),
        "BPF object must be prebuilt: {}",
        object_path.display()
    );
    set_bpf_dir(object_path.as_os_str());

    // Mid-session traffic burst (positive control): gated on both
    // sensors fully attached (9+9 tracing links) — deterministic, no
    // sleep-guessing against BPF load times — and done well before the
    // window closes.
    let traffic = std::thread::spawn(|| {
        let start = std::time::Instant::now();
        loop {
            if link_count_or_none().is_some_and(|n| n >= 18) {
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
        let multi =
            kryprobe_testkit::alg_fixture::hash_digest_multi("sha512", 4).expect("hashmulti");
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
    };
    let outcome = kryprobe_cli::live::run_live_capture(&cfg, &lane_runtime())
        .unwrap_or_else(|err| panic!("live capture failed: {err}"));

    let (sk, single, multi, aead, gate_wait) = traffic.join().expect("traffic joins");
    println!("live proof: attach gate passed after {gate_wait:?}");
    assert_eq!((sk.enc, sk.dec), (20, 20), "skcipher positive control");
    assert_eq!((single.digests, single.digest_len), (8, 64), "hash control");
    assert_eq!(multi.digests, 4, "hashmulti control");
    assert_eq!((aead.enc, aead.dec), (10, 10), "aead control");

    // Observations decode; ids sequence from 1 in decode order.
    assert!(!outcome.observations.is_empty(), "session decodes rows");
    for (i, obs) in outcome.observations.iter().enumerate() {
        assert_eq!(obs.id.get(), i as u64 + 1, "ids sequence from 1");
        assert_eq!(obs.backend, kryprobe_core::enums::BackendId::KCrypto);
    }
    // Finalize == decoded (nothing deduped, nothing lost).
    assert_eq!(
        outcome.summary.observations,
        outcome.observations.len() as u64,
        "finalize==decoded"
    );
    assert_eq!(
        outcome.summary.backend,
        kryprobe_core::enums::BackendId::KCrypto
    );

    // Tick count: one totals row per tick (9 ticks ran, closing included).
    let totals: Vec<_> = outcome
        .observations
        .iter()
        .filter(|o| row_kind(o) == "totals")
        .collect();
    assert_eq!(totals.len(), 9, "one totals row per tick");

    // Totals conserved: per-tick KTOT == Σagg sums to global equality
    // (ambient-proof: summation preserves the per-tick conservation).
    let tot_calls: u64 = totals
        .iter()
        .map(|o| {
            o.backend_payload["counts"]["calls"]
                .as_u64()
                .expect("calls")
        })
        .sum();
    let agg_calls: u64 = outcome
        .observations
        .iter()
        .filter(|o| row_kind(o) == "agg")
        .map(|o| {
            o.backend_payload["counts"]["calls"]
                .as_u64()
                .expect("calls")
        })
        .sum();
    assert_eq!(tot_calls, agg_calls, "KTOT == Σagg across all ticks");
    let tot_bytes: u64 = totals
        .iter()
        .map(|o| o.backend_payload["bytes"].as_u64().expect("bytes"))
        .sum();
    let agg_bytes: u64 = outcome
        .observations
        .iter()
        .filter(|o| row_kind(o) == "agg")
        .map(|o| o.backend_payload["bytes"].as_u64().expect("bytes"))
        .sum();
    assert_eq!(tot_bytes, agg_bytes, "bytes conserved too");

    // Fixture truth present (lower bounds: ambient traffic may add rows,
    // never remove the driven ones).
    assert!(
        sum_obs(
            &outcome.observations,
            "skcipher",
            "encrypt",
            "ok",
            "cbc(aes)"
        ) >= 20,
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
        ) >= 20,
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
    assert!(
        sum_obs(&outcome.observations, "shash", "finup", "ok", "sha512") >= 8,
        "shash finup rows decode"
    );
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
        kryprobe_core::enums::CoverageStatus::CompleteForDeclaredBoundary,
        "healthy lane: coverage COMPLETE (weaker: {:?})",
        outcome.coverage.weaker_dimensions()
    );

    // Zero window: exactly the opening tick (ids still sequence).
    let cfg0 = kryprobe_cli::live::LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: Some(0),
        tick_ms: 1000,
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
    let file = std::env::temp_dir().join("kryprobe-k3-1-cand.o");
    std::fs::write(&file, b"x").expect("candidate probe file");
    let exe = PathBuf::from("/exe/dir");
    assert_eq!(
        kcrypto_object_candidates(file.to_str(), Some(exe.as_path())),
        vec![
            file.clone(),
            PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o"),
            PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
        ]
    );
    std::fs::remove_file(&file).ok();
    // Env dir joined; unknown exe dir skips tier 2 (never fabricated).
    let dir = PathBuf::from("/tmp/kryprobe-k3-1-cand-dir");
    assert_eq!(
        kcrypto_object_candidates(dir.to_str(), None),
        vec![
            dir.join("kcrypto.bpf.o"),
            PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
        ]
    );
    // Unset env: exe tier first, dev last.
    assert_eq!(
        kcrypto_object_candidates(None, Some(exe.as_path())),
        vec![
            PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o"),
            PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o"),
        ]
    );
}
