// SPDX-License-Identifier: GPL-3.0-or-later
//! Release-consumer honesty: the staging and installer scripts verify
//! what they consume. Real scripts, owned temp dirs only — no global
//! install, no capabilities. Artifact cases build (or reuse a scratch
//! copy of) a pinned stage from `build-release.sh`, mutate one axis,
//! and assert refusal before touching the destination. Doctor protocol
//! fixtures cover the installer's final verification predicate separately.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const PAYLOAD: [&str; 3] = [
    "bin/kryprobe",
    "bin/kryprobe-bpf/kcrypto.bpf.o",
    "bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn run(cmd: &mut Command) -> std::process::Output {
    cmd.output().expect("spawn")
}

fn sha256_file(path: &Path) -> String {
    let out = run(Command::new("sha256sum").arg(path));
    assert!(
        out.status.success(),
        "sha256sum works: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .split_whitespace()
        .next()
        .expect("digest field")
        .to_owned()
}

/// `doctor --versions --json` of a binary from a neutral CWD with dev
/// object overrides removed, so the exe-bundled tier is the only tier
/// that can resolve.
fn installed_versions(binary: &Path, cwd: &Path) -> serde_json::Value {
    let out = run(Command::new(binary)
        .args(["doctor", "--versions", "--json"])
        .current_dir(cwd)
        .env_remove("KRYPROBE_BPF_DIR")
        .env_remove("KRYPROBE_BPF_OBJ"));
    assert!(
        out.status.success(),
        "doctor --versions exits 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&String::from_utf8(out.stdout).expect("utf-8")).expect("json")
}

/// Cargo target dir the ambient build uses (honors an explicit
/// `CARGO_TARGET_DIR`, resolved against the workspace root like Cargo
/// resolves it against its invocation CWD).
fn ambient_target_dir(root: &Path) -> PathBuf {
    match std::env::var("CARGO_TARGET_DIR") {
        Ok(dir) if !dir.is_empty() => {
            let dir = PathBuf::from(dir);
            if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            }
        }
        _ => root.join("target"),
    }
}

/// A pinned stage built by the real script, with its manifest pin.
fn build_pinned_stage(scratch: &Path, name: &str) -> (PathBuf, String) {
    let root = workspace_root();
    let stage = scratch.join(name);
    let out = run(Command::new("sh")
        .arg(root.join("packaging/build-release.sh"))
        .args(["--dest"])
        .arg(&stage));
    assert!(
        out.status.success(),
        "build-release.sh exits 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(stage.join("manifest.json")).expect("manifest written"),
    )
    .expect("manifest json");
    assert_eq!(manifest["pins_enforced"], true);
    assert_eq!(manifest["profile_pins_enforced"], true);
    assert_eq!(manifest["kryprobe_release_manifest"], 2);
    assert_eq!(manifest["objects"].as_array().expect("objects").len(), 2);
    let pin = manifest["pin_digests"][0]
        .as_str()
        .expect("one pin")
        .to_owned();
    (stage, pin)
}

fn install_stage(stage: &Path, destdir: &Path) -> std::process::Output {
    let root = workspace_root();
    run(Command::new("sh")
        .arg(root.join("packaging/install.sh"))
        .args(["--stage"])
        .arg(stage)
        .args(["--destdir"])
        .arg(destdir)
        .arg("--no-mint"))
}

/// Recompute `sha256sums.txt` over the payload paths currently in the
/// stage (what a careful-but-unpinned packager would ship).
fn rewrite_checksums(stage: &Path, paths: &[&str]) {
    let mut text = String::new();
    for name in paths {
        text.push_str(&format!("{}  {name}\n", sha256_file(&stage.join(name))));
    }
    std::fs::write(stage.join("sha256sums.txt"), text).expect("checksums");
}

/// Rewrite `manifest.json` for the files currently staged: a fully
/// self-consistent stage, so refusal must come from pin enforcement,
/// never from manifest mismatch. Template mirrors
/// `build-release.sh` (drift fails the test loudly, never silently).
fn rewrite_manifest(stage: &Path) {
    let bin = sha256_file(&stage.join("bin/kryprobe"));
    let obj = sha256_file(&stage.join("bin/kryprobe-bpf/kcrypto.bpf.o"));
    let lifecycle = sha256_file(&stage.join("bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o"));
    let manifest = format!(
        "{{\"kryprobe_release_manifest\":2,\"binary\":{{\"path\":\"bin/kryprobe\",\"sha256\":\"{bin}\"}},\"objects\":[{{\"name\":\"kcrypto.bpf.o\",\"path\":\"bin/kryprobe-bpf/kcrypto.bpf.o\",\"sha256\":\"{obj}\"}},{{\"name\":\"kcrypto-lifecycle.bpf.o\",\"path\":\"bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o\",\"sha256\":\"{lifecycle}\"}}],\"pins_enforced\":true,\"profile_pins_enforced\":true,\"pin_digests\":[\"{obj}\",\"{lifecycle}\"]}}\n"
    );
    std::fs::write(stage.join("manifest.json"), manifest).expect("manifest");
}

const PASSING_DOCTOR: &str = "probe cap_state: pass: CapEff CAP_BPF, CAP_PERFMON\n\
probe kcrypto_object: pass: /fixture/bin/kryprobe-bpf/kcrypto.bpf.o\n\
probe kcrypto_attach: pass: 9/9 attached\n";

/// Exercise the real installer through its live verification branch without
/// granting capabilities or loading BPF. Only the binary's external protocol
/// and `id -u` are fixtures; copying, hashing, validation and exit handling run
/// unchanged. These tests do not establish installed capture readiness.
fn install_doctor_fixture(doctor: &[u8], status: u8, skip: Option<&str>) -> std::process::Output {
    let scratch = kryprobe_testkit::TempDir::named("installer-doctor").expect("scratch");
    let stage = scratch.path().join("stage");
    copy_file_assert_bytes(&stage.join(PAYLOAD[1]), b"aggregate protocol fixture\n");
    copy_file_assert_bytes(&stage.join(PAYLOAD[2]), b"lifecycle protocol fixture\n");
    let binary = stage.join(PAYLOAD[0]);
    std::fs::write(
        &binary,
        r#"#!/bin/sh
set -eu
if [ "$#" -eq 3 ] && [ "$1" = doctor ] && [ "$2" = --versions ] && [ "$3" = --json ]; then
    objects="$(dirname -- "$0")/kryprobe-bpf"
    aggregate=$(sha256sum "$objects/kcrypto.bpf.o")
    lifecycle=$(sha256sum "$objects/kcrypto-lifecycle.bpf.o")
    printf '{"pins_enforced":true,"profile_pins_enforced":true,"kcrypto":{"path":"%s/kcrypto.bpf.o","sha256":"%s"},"kcrypto_lifecycle":{"path":"%s/kcrypto-lifecycle.bpf.o","sha256":"%s"}}\n' "$objects" "${aggregate%% *}" "$objects" "${lifecycle%% *}"
elif [ "$#" -eq 4 ] && [ "$1" = token ] && [ "$3" = --bin ] && [ "$4" = "$0" ]; then
    case "$2" in mint|status) : ;; *) exit 98 ;; esac
elif [ "$#" -eq 1 ] && [ "$1" = doctor ]; then
    cat "$KRYPROBE_TEST_DOCTOR_OUT"
    printf '%s\n' 'doctor diagnostic on stderr' >&2
    exit "$KRYPROBE_TEST_DOCTOR_STATUS"
else
    echo 'unexpected protocol fixture invocation' >&2
    exit 99
fi
"#,
    )
    .expect("protocol fixture");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    rewrite_checksums(&stage, &PAYLOAD);
    rewrite_manifest(&stage);
    let tools = scratch.path().join("tools");
    let id = tools.join("id");
    copy_file_assert_bytes(
        &id,
        b"#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = -u ] || exit 97\nprintf '%s\\n' 0\n",
    );
    std::fs::set_permissions(&id, std::fs::Permissions::from_mode(0o755)).expect("chmod id");
    let doctor_file = scratch.path().join("doctor.stdout");
    std::fs::write(&doctor_file, doctor).expect("doctor output fixture");
    let tmp = scratch.path().join("tmp");
    std::fs::create_dir(&tmp).expect("private tmp");
    let mut path = vec![tools];
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").expect("PATH"),
    ));
    let mut cmd = Command::new("sh");
    cmd.arg(workspace_root().join("packaging/install.sh"))
        .arg("--stage")
        .arg(&stage)
        .arg("--prefix")
        .arg(scratch.path().join("installed"))
        .env("PATH", std::env::join_paths(path).expect("fixture PATH"))
        .env("TMPDIR", &tmp)
        .env("KRYPROBE_TEST_DOCTOR_OUT", doctor_file)
        .env("KRYPROBE_TEST_DOCTOR_STATUS", status.to_string());
    match skip {
        Some("no-mint") => {
            cmd.arg("--no-mint");
        }
        Some("destdir") => {
            cmd.arg("--destdir").arg(scratch.path().join("destdir"));
        }
        None => {}
        Some(_) => panic!("unknown skip fixture"),
    }
    let out = run(&mut cmd);
    assert_eq!(std::fs::read_dir(tmp).expect("private tmp").count(), 0);
    out
}

#[test]
fn installer_verifies_all_selected_passing_rows() {
    // Unselected degradation, including lifecycle floor refusal, must not
    // become a blanket failure of aggregate installation verification.
    let doctor = format!(
        "{PASSING_DOCTOR}probe kcrypto_lifecycle: skipped: kernel floor unsupported\n\
         probe unrelated: failed: detail names cap_state and kcrypto_attach\n\
         coverage-profile: kernel-crypto-v1\nverdict: ready\n"
    );
    let out = install_doctor_fixture(doctor.as_bytes(), 0, None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ install verified"));
    assert!(
        stdout.contains(&doctor),
        "doctor diagnostics must be retained"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("doctor diagnostic on stderr"));
}

#[test]
fn installer_refuses_each_nonpassing_selected_outcome() {
    for row in PASSING_DOCTOR.lines() {
        let name = row
            .strip_prefix("probe ")
            .unwrap()
            .split(':')
            .next()
            .unwrap();
        for outcome in [
            "denied: attach (errno 1)",
            "skipped: unavailable",
            "failed: 8/9 attached",
        ] {
            let doctor = PASSING_DOCTOR.replace(row, &format!("probe {name}: {outcome}"));
            let out = install_doctor_fixture(doctor.as_bytes(), 0, None);
            assert!(!out.status.success(), "{name}: {outcome} must be refused");
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(!stdout.contains("+ install verified"));
            assert!(stdout.contains(&doctor), "nonpassing diagnostics retained");
        }
    }
}

#[test]
fn installer_preserves_doctor_failure_status_and_diagnostics() {
    for doctor in [PASSING_DOCTOR, "doctor aborted before producing rows\n"] {
        let out = install_doctor_fixture(doctor.as_bytes(), 7, None);
        assert_eq!(
            out.status.code(),
            Some(7),
            "doctor status must not be hidden"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("+ install verified"));
        assert!(stdout.contains(doctor));
        assert!(String::from_utf8_lossy(&out.stderr).contains("doctor diagnostic on stderr"));
    }
}

#[test]
fn installer_requires_one_well_formed_row_per_selected_predicate() {
    for row in PASSING_DOCTOR.lines() {
        let name = row
            .strip_prefix("probe ")
            .unwrap()
            .split(':')
            .next()
            .unwrap();
        let without = PASSING_DOCTOR.replace(&format!("{row}\n"), "");
        for (case, doctor) in [
            ("missing", without.clone()),
            ("duplicate", format!("{PASSING_DOCTOR}{row}\n")),
            (
                "contradictory",
                format!("{PASSING_DOCTOR}probe {name}: failed: unavailable\n"),
            ),
            (
                "missing delimiter",
                format!("{without}probe {name} pass: fixture\n"),
            ),
            ("missing detail", format!("{without}probe {name}: pass:\n")),
            (
                "unknown outcome",
                format!("{without}probe {name}: passing: fixture\n"),
            ),
            (
                "unrelated substring",
                format!("{without}probe unrelated: pass: probe {name}: pass: fixture\n"),
            ),
            (
                "malformed duplicate",
                format!("{PASSING_DOCTOR}probe {name} pass: fixture\n"),
            ),
            (
                "NUL in outcome",
                format!("{without}probe {name}: pa\0ss: fixture\n"),
            ),
        ] {
            let out = install_doctor_fixture(doctor.as_bytes(), 0, None);
            assert!(!out.status.success(), "{name}: {case} must be refused");
            assert!(!String::from_utf8_lossy(&out.stdout).contains("+ install verified"));
        }
    }
}

#[test]
fn installer_skipped_verification_never_claims_capture_verified() {
    for skip in ["no-mint", "destdir"] {
        let out = install_doctor_fixture(b"doctor must not run\n", 7, Some(skip));
        assert!(
            out.status.success(),
            "{skip}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("+ install verified"));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("doctor diagnostic on stderr"));
    }
}

/// Seed every destination file with sentinel bytes so
/// the test can prove a refused install changed nothing.
fn seed_destination(destdir: &Path) -> [Vec<u8>; 3] {
    PAYLOAD.map(|path| {
        let marker = format!("sentinel-{path}-not-overwritten").into_bytes();
        copy_file_assert_bytes(&destdir.join("usr/local").join(path), &marker);
        marker
    })
}

fn copy_file_assert_bytes(dst: &Path, bytes: &[u8]) {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(dst, bytes).expect("write");
}

fn assert_destination_unchanged(destdir: &Path, markers: &[Vec<u8>; 3]) {
    for (path, marker) in PAYLOAD.iter().zip(markers) {
        let bytes = std::fs::read(destdir.join("usr/local").join(path)).expect("seeded file");
        assert_eq!(&bytes, marker, "refused install leaves {path} alone");
    }
}

/// Valid pinned stage installs; the installed pair is the staged pair
/// and the installed binary enforces the installed object's pin.
#[test]
fn installer_accepts_valid_pinned_stage() {
    let scratch = kryprobe_testkit::TempDir::named("installer-valid").expect("scratch");
    let (stage, pin) = build_pinned_stage(scratch.path(), "pkg");
    let destdir = scratch.path().join("installed");
    let out = install_stage(&stage, &destdir);
    assert!(
        out.status.success(),
        "valid stage installs: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bin = destdir.join("usr/local/bin/kryprobe");
    let obj = destdir.join("usr/local/bin/kryprobe-bpf/kcrypto.bpf.o");
    let lifecycle = destdir.join("usr/local/bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o");
    assert!(
        lifecycle.is_file(),
        "installed package must contain the request-lifecycle object"
    );
    assert_eq!(
        sha256_file(&bin),
        sha256_file(&stage.join("bin/kryprobe")),
        "installed binary is the staged binary"
    );
    assert_eq!(
        sha256_file(&obj),
        sha256_file(&stage.join("bin/kryprobe-bpf/kcrypto.bpf.o")),
        "installed object is the staged object"
    );
    assert_eq!(
        sha256_file(&lifecycle),
        sha256_file(&stage.join("bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o")),
        "installed lifecycle object is the staged object"
    );
    let neutral = scratch.path().join("neutral");
    std::fs::create_dir_all(&neutral).expect("neutral cwd");
    let versions = installed_versions(&bin, &neutral);
    assert_eq!(versions["pins_enforced"], true);
    assert_eq!(versions["profile_pins_enforced"], true);
    assert_eq!(versions["kcrypto"]["sha256"], pin.as_str());
    assert_eq!(
        versions["kcrypto"]["path"],
        obj.to_str().expect("utf-8 path")
    );
    assert_eq!(
        versions["kcrypto_lifecycle"]["path"],
        lifecycle.to_str().expect("utf-8 path")
    );
    assert_eq!(
        versions["kcrypto_lifecycle"]["sha256"],
        sha256_file(&lifecycle)
    );
}

/// Wrong-family object bytes under the kcrypto name in a fully
/// self-consistent stage (checksums and manifest regenerated): only
/// the staged binary's pin check can refuse — the pinned binary
/// trusts its baked digest, not these bytes. Dest unchanged.
#[test]
fn installer_refuses_rehashed_wrong_object() {
    let scratch = kryprobe_testkit::TempDir::named("installer-object").expect("scratch");
    let root = workspace_root();
    let (stage, _pin) = build_pinned_stage(scratch.path(), "pkg");
    std::fs::copy(
        root.join("target/kryprobe-bpf/spine.bpf.o"),
        stage.join("bin/kryprobe-bpf/kcrypto.bpf.o"),
    )
    .expect("wrong-family object");
    rewrite_checksums(&stage, &PAYLOAD);
    rewrite_manifest(&stage);
    let destdir = scratch.path().join("installed");
    let markers = seed_destination(&destdir);
    let out = install_stage(&stage, &destdir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "wrong object must be refused, stderr: {stderr}"
    );
    assert!(
        stderr.contains("does not trust the staged object"),
        "refusal comes from pin enforcement: {stderr}"
    );
    assert_destination_unchanged(&destdir, &markers);
}

/// The lifecycle object is mandatory, and its name is part of its
/// trusted identity. Recomputing all packaging metadata must not make
/// changed bytes or two swapped (individually trusted) objects valid.
#[test]
fn installer_refuses_lifecycle_damage_and_profile_swaps() {
    let scratch = kryprobe_testkit::TempDir::named("installer-profiles").expect("scratch");
    let (original, _) = build_pinned_stage(scratch.path(), "original");
    for (variant, reason) in [
        ("missing", "stage lacks"),
        ("modified", "does not trust the staged lifecycle object"),
        ("swapped", "does not trust the staged object"),
        ("omitted-checksum", "do not match the payload files"),
        ("manifest-nul", "is not manifest v2"),
    ] {
        let stage = scratch.path().join(variant);
        std::fs::create_dir_all(stage.join("bin/kryprobe-bpf")).expect("mkdir");
        for path in PAYLOAD
            .into_iter()
            .chain(["manifest.json", "sha256sums.txt"])
        {
            std::fs::copy(original.join(path), stage.join(path)).expect("copy stage");
        }
        let object = stage.join(PAYLOAD[1]);
        let lifecycle = stage.join(PAYLOAD[2]);
        match variant {
            "missing" => std::fs::remove_file(&lifecycle).expect("remove lifecycle"),
            "modified" => {
                let mut bytes = std::fs::read(&lifecycle).expect("lifecycle");
                bytes[100] ^= 1;
                std::fs::write(&lifecycle, bytes).expect("change lifecycle");
                rewrite_checksums(&stage, &PAYLOAD);
                rewrite_manifest(&stage);
            }
            "swapped" => {
                let aggregate_bytes = std::fs::read(&object).expect("aggregate");
                std::fs::copy(&lifecycle, &object).expect("swap aggregate");
                std::fs::write(&lifecycle, aggregate_bytes).expect("swap lifecycle");
                rewrite_checksums(&stage, &PAYLOAD);
                rewrite_manifest(&stage);
            }
            "omitted-checksum" => rewrite_checksums(&stage, &PAYLOAD[..2]),
            "manifest-nul" => {
                let mut bytes = std::fs::read(stage.join("manifest.json")).expect("manifest");
                bytes.push(0);
                std::fs::write(stage.join("manifest.json"), bytes).expect("append NUL");
            }
            _ => unreachable!(),
        }
        let destdir = scratch.path().join(format!("installed-{variant}"));
        let markers = seed_destination(&destdir);
        let out = install_stage(&stage, &destdir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{variant} must be refused: {stderr}");
        assert!(stderr.contains(reason), "{variant} refusal: {stderr}");
        assert_destination_unchanged(&destdir, &markers);
    }
}

/// Unpinned dev binary in a fully self-consistent stage (checksums
/// and manifest regenerated): only the staged binary's pin check can
/// refuse — the binary reports `pins_enforced:false`. Dest unchanged.
#[test]
fn installer_refuses_unpinned_binary() {
    let scratch = kryprobe_testkit::TempDir::named("installer-binary").expect("scratch");
    let root = workspace_root();
    let out = run(Command::new(env!("CARGO"))
        .args(["build", "--locked", "-p", "kryprobe-cli"])
        .current_dir(&root)
        .env_remove("KRYPROBE_PIN_DIGESTS")
        .env_remove("KRYPROBE_PIN_OBJECTS")
        .env_remove("KRYPROBE_REQUIRE_PINS"));
    assert!(
        out.status.success(),
        "debug binary builds: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let debug_bin = ambient_target_dir(&root).join("debug/kryprobe");
    assert!(debug_bin.is_file(), "debug binary exists");
    let neutral = scratch.path().join("neutral");
    std::fs::create_dir_all(&neutral).expect("neutral cwd");
    assert_eq!(
        installed_versions(&debug_bin, &neutral)["pins_enforced"],
        false,
        "test premise: debug binary is unpinned"
    );
    let (stage, _pin) = build_pinned_stage(scratch.path(), "pkg");
    std::fs::copy(&debug_bin, stage.join("bin/kryprobe")).expect("unpinned binary");
    rewrite_checksums(&stage, &PAYLOAD);
    rewrite_manifest(&stage);
    let destdir = scratch.path().join("installed");
    let markers = seed_destination(&destdir);
    let out = install_stage(&stage, &destdir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "unpinned binary must be refused, stderr: {stderr}"
    );
    assert!(
        stderr.contains("is not pin-enforced"),
        "refusal comes from pin enforcement: {stderr}"
    );
    assert_destination_unchanged(&destdir, &markers);
}

/// Checksum list that omits the binary: consistency data must cover
/// exactly the shipped payload — refuse even though the pair itself
/// is pinned and valid, dest unchanged.
#[test]
fn installer_refuses_omitted_binary_checksum() {
    let scratch = kryprobe_testkit::TempDir::named("installer-checksums").expect("scratch");
    let (stage, _pin) = build_pinned_stage(scratch.path(), "pkg");
    rewrite_checksums(&stage, &["bin/kryprobe-bpf/kcrypto.bpf.o"]);
    let destdir = scratch.path().join("installed");
    let markers = seed_destination(&destdir);
    let out = install_stage(&stage, &destdir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "omitted binary checksum must be refused, stderr: {stderr}"
    );
    assert!(
        stderr.contains("do not match the payload files"),
        "refusal comes from checksum cover: {stderr}"
    );
    assert_destination_unchanged(&destdir, &markers);
}

/// Non-JSON manifest containing the old `"pins_enforced":true`
/// fragment: not a versioned manifest — refuse even though the
/// binary/object pair itself is valid, dest unchanged.
#[test]
fn installer_refuses_invalid_manifest() {
    let scratch = kryprobe_testkit::TempDir::named("installer-manifest").expect("scratch");
    let (stage, _pin) = build_pinned_stage(scratch.path(), "pkg");
    std::fs::write(
        stage.join("manifest.json"),
        "not JSON at all; marker \"pins_enforced\":true is enough\n",
    )
    .expect("invalid manifest");
    let destdir = scratch.path().join("installed");
    let markers = seed_destination(&destdir);
    let out = install_stage(&stage, &destdir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "invalid manifest must be refused, stderr: {stderr}"
    );
    assert!(
        stderr.contains("is not manifest v2"),
        "refusal comes from manifest validation: {stderr}"
    );
    assert_destination_unchanged(&destdir, &markers);
}

/// Well-shaped manifest whose binary digest no longer matches the
/// staged binary: the manifest must bind the files being copied —
/// refuse, dest unchanged.
#[test]
fn installer_refuses_manifest_digest_mismatch() {
    let scratch = kryprobe_testkit::TempDir::named("installer-digest").expect("scratch");
    let (stage, _pin) = build_pinned_stage(scratch.path(), "pkg");
    let manifest = std::fs::read_to_string(stage.join("manifest.json")).expect("manifest");
    let tampered = manifest.replacen(
        &sha256_file(&stage.join("bin/kryprobe")),
        &"0".repeat(64),
        1,
    );
    assert_ne!(tampered, manifest, "digest actually replaced");
    std::fs::write(stage.join("manifest.json"), tampered).expect("tampered manifest");
    let destdir = scratch.path().join("installed");
    let markers = seed_destination(&destdir);
    let out = install_stage(&stage, &destdir);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "manifest digest mismatch must be refused, stderr: {stderr}"
    );
    assert!(
        stderr.contains("is not manifest v2"),
        "refusal comes from manifest validation: {stderr}"
    );
    assert_destination_unchanged(&destdir, &markers);
}

/// A `--cargo` wrapper applying a host-only strip setting to real
/// `build` invocations (differentiates same-source builds without
/// touching source); `xtask` invocations pass through untouched.
fn write_strip_wrapper(path: &Path) {
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\nset -eu\nif [ \"$1\" = build ]; then\n    export CARGO_PROFILE_RELEASE_STRIP=symbols\nfi\nexec {} \"$@\"\n",
            env!("CARGO")
        ),
    )
    .expect("wrapper");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// A custom `CARGO_TARGET_DIR` build stages the executable from that
/// build — not a distinguishable prior binary sitting in the default
/// target. The strip setting differentiates the two real builds
/// without touching source; the default target is left alone.
#[test]
fn build_release_stages_actual_target_dir_build() {
    let scratch = kryprobe_testkit::TempDir::named("target-dir-stage").expect("scratch");
    let root = workspace_root();
    let script = root.join("packaging/build-release.sh");
    let default_bin = ambient_target_dir(&root).join("release/kryprobe");

    // Prior distinguishable binary in the default target.
    let (_prior_stage, _prior_pin) = build_pinned_stage(scratch.path(), "prior-pkg");
    let prior_hash = sha256_file(&default_bin);

    // Same source, isolated target dir, host-only strip setting.
    let wrapper = scratch.path().join("cargo-stripped.sh");
    write_strip_wrapper(&wrapper);
    let isolated = scratch.path().join("isolated-target");
    let stage = scratch.path().join("pkg");
    let out = run(Command::new("sh")
        .arg(&script)
        .args(["--dest"])
        .arg(&stage)
        .args(["--cargo"])
        .arg(&wrapper)
        .env("CARGO_TARGET_DIR", &isolated));
    assert!(
        out.status.success(),
        "isolated-target build stages: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let new_hash = sha256_file(&isolated.join("release/kryprobe"));
    let staged_hash = sha256_file(&stage.join("bin/kryprobe"));
    assert_ne!(
        new_hash, prior_hash,
        "strip setting distinguishes the new build"
    );
    assert_eq!(
        staged_hash, new_hash,
        "stage contains the actual new build, not the prior binary"
    );
    assert_eq!(
        sha256_file(&default_bin),
        prior_hash,
        "default target left alone"
    );
}

/// A relative `CARGO_TARGET_DIR` resolves against the workspace root
/// (Cargo's own rule at its invocation directory): the stage carries
/// that build's executable, not the default-target binary.
#[test]
fn build_release_stages_relative_target_dir_build() {
    let scratch = kryprobe_testkit::TempDir::named("target-dir-relative").expect("scratch");
    let root = workspace_root();
    let script = root.join("packaging/build-release.sh");
    let default_bin = ambient_target_dir(&root).join("release/kryprobe");

    // Prior distinguishable binary in the default target.
    let (_prior_stage, _prior_pin) = build_pinned_stage(scratch.path(), "prior-pkg");
    let prior_hash = sha256_file(&default_bin);

    // Same source, process-unique relative target dir, strip setting.
    let rel = format!("target-isolated-rel-{}", std::process::id());
    assert!(!Path::new(&rel).is_absolute(), "test premise: relative dir");
    let _ = std::fs::remove_dir_all(root.join(&rel));
    let wrapper = scratch.path().join("cargo-stripped.sh");
    write_strip_wrapper(&wrapper);
    let stage = scratch.path().join("pkg");
    let out = run(Command::new("sh")
        .arg(&script)
        .args(["--dest"])
        .arg(&stage)
        .args(["--cargo"])
        .arg(&wrapper)
        .env("CARGO_TARGET_DIR", &rel));
    assert!(
        out.status.success(),
        "relative-target build stages: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let new_hash = sha256_file(&root.join(&rel).join("release/kryprobe"));
    let staged_hash = sha256_file(&stage.join("bin/kryprobe"));
    assert_ne!(
        new_hash, prior_hash,
        "strip setting distinguishes the new build"
    );
    assert_eq!(
        staged_hash, new_hash,
        "stage contains the relative-target build"
    );
    std::fs::remove_dir_all(root.join(&rel)).expect("cleanup");
}

/// A cold target dir (never built — no prebuilt binary to lean on)
/// still stages: the script builds from scratch. A private scratch
/// target dir proves the precondition; tests never mutate the shared
/// ambient/default target dirs (concurrent script runs and sibling
/// hashes race on them).
#[test]
fn build_release_builds_cold_target_dir() {
    let scratch = kryprobe_testkit::TempDir::named("target-dir-cold").expect("scratch");
    let script = workspace_root().join("packaging/build-release.sh");
    let isolated = scratch.path().join("cold-target");
    assert!(!isolated.exists(), "target dir starts cold");
    let stage = scratch.path().join("pkg");
    let out = run(Command::new("sh")
        .arg(&script)
        .args(["--dest"])
        .arg(&stage)
        .env("CARGO_TARGET_DIR", &isolated));
    assert!(
        out.status.success(),
        "cold-target build stages: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        sha256_file(&stage.join("bin/kryprobe")),
        sha256_file(&isolated.join("release/kryprobe")),
        "stage contains the cold build"
    );
}

/// `--dest` accepts relative and absolute directories: both stage a
/// pin-enforced release. The relative form is resolved against the
/// caller's directory before the script changes directory.
#[test]
fn build_release_accepts_relative_and_absolute_dest() {
    let scratch = kryprobe_testkit::TempDir::named("dest-paths").expect("scratch");
    let script = workspace_root().join("packaging/build-release.sh");
    let out = run(Command::new("sh")
        .arg(&script)
        .args(["--dest", "rel-pkg"])
        .current_dir(scratch.path()));
    assert!(
        out.status.success(),
        "relative --dest stages: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let abs = scratch.path().join("abs-pkg");
    assert!(abs.is_absolute(), "test premise: absolute control");
    let out = run(Command::new("sh").arg(&script).args(["--dest"]).arg(&abs));
    assert!(
        out.status.success(),
        "absolute --dest stages: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for stage in [scratch.path().join("rel-pkg"), abs] {
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(stage.join("manifest.json")).expect("manifest written"),
        )
        .expect("manifest json");
        assert_eq!(manifest["pins_enforced"], true);
    }
}

#[test]
fn build_release_refuses_nonempty_destination_without_clobbering() {
    let scratch = kryprobe_testkit::TempDir::named("stage-no-clobber").expect("scratch");
    let marker = scratch.path().join("keep");
    std::fs::write(&marker, "previous release").expect("sentinel");
    let out = run(Command::new("sh")
        .arg(workspace_root().join("packaging/build-release.sh"))
        .arg("--dest")
        .arg(scratch.path()));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing non-empty dest"));
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "previous release");
}
