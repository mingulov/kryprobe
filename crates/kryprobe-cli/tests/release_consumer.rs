// SPDX-License-Identifier: GPL-3.0-or-later
//! Release-consumer honesty: the staging and installer scripts verify
//! what they consume. Real scripts, owned temp dirs only — no global
//! install, no capabilities. Each case builds (or reuses a scratch
//! copy of) a pinned stage from `build-release.sh`, mutates one axis,
//! and asserts the consumer refuses before touching the destination.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Seed a destination with sentinel bytes; returns the marker pair so
/// the test can prove a refused install changed nothing.
fn seed_dest_pair(destdir: &Path) -> (Vec<u8>, Vec<u8>) {
    let bin = destdir.join("usr/local/bin/kryprobe");
    let obj = destdir.join("usr/local/bin/kryprobe-bpf/kcrypto.bpf.o");
    let bin_marker = b"sentinel-binary-not-overwritten".to_vec();
    let obj_marker = b"sentinel-object-not-overwritten".to_vec();
    copy_file_assert_bytes(&bin, &bin_marker);
    copy_file_assert_bytes(&obj, &obj_marker);
    (bin_marker, obj_marker)
}

fn copy_file_assert_bytes(dst: &Path, bytes: &[u8]) {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(dst, bytes).expect("write");
}

fn assert_dest_pair_unchanged(destdir: &Path, markers: &(Vec<u8>, Vec<u8>)) {
    let bin = std::fs::read(destdir.join("usr/local/bin/kryprobe")).expect("seeded bin");
    let obj = std::fs::read(destdir.join("usr/local/bin/kryprobe-bpf/kcrypto.bpf.o"))
        .expect("seeded obj");
    assert_eq!(bin, markers.0, "refused install leaves dest binary alone");
    assert_eq!(obj, markers.1, "refused install leaves dest object alone");
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
    let neutral = scratch.path().join("neutral");
    std::fs::create_dir_all(&neutral).expect("neutral cwd");
    let versions = installed_versions(&bin, &neutral);
    assert_eq!(versions["pins_enforced"], true);
    assert_eq!(versions["kcrypto"]["sha256"], pin.as_str());
    assert_eq!(
        versions["kcrypto"]["path"],
        obj.to_str().expect("utf-8 path")
    );
}

/// Wrong-family object bytes under the kcrypto name with regenerated
/// checksums: the manifest still pins the original digest and the
/// pinned binary trusts only that digest — refuse, dest unchanged.
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
    rewrite_checksums(&stage, &["bin/kryprobe", "bin/kryprobe-bpf/kcrypto.bpf.o"]);
    let destdir = scratch.path().join("installed");
    let markers = seed_dest_pair(&destdir);
    let out = install_stage(&stage, &destdir);
    assert!(
        !out.status.success(),
        "wrong object must be refused, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_dest_pair_unchanged(&destdir, &markers);
}

/// Unpinned dev binary with regenerated checksums and the old
/// manifest: the binary reports `pins_enforced:false` — refuse, dest
/// unchanged.
#[test]
fn installer_refuses_unpinned_binary() {
    let scratch = kryprobe_testkit::TempDir::named("installer-binary").expect("scratch");
    let root = workspace_root();
    let out = run(Command::new(env!("CARGO"))
        .args(["build", "--locked", "-p", "kryprobe-cli"])
        .current_dir(&root));
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
    rewrite_checksums(&stage, &["bin/kryprobe", "bin/kryprobe-bpf/kcrypto.bpf.o"]);
    let destdir = scratch.path().join("installed");
    let markers = seed_dest_pair(&destdir);
    let out = install_stage(&stage, &destdir);
    assert!(
        !out.status.success(),
        "unpinned binary must be refused, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_dest_pair_unchanged(&destdir, &markers);
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
    let markers = seed_dest_pair(&destdir);
    let out = install_stage(&stage, &destdir);
    assert!(
        !out.status.success(),
        "omitted binary checksum must be refused, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_dest_pair_unchanged(&destdir, &markers);
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
    let markers = seed_dest_pair(&destdir);
    let out = install_stage(&stage, &destdir);
    assert!(
        !out.status.success(),
        "invalid manifest must be refused, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_dest_pair_unchanged(&destdir, &markers);
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
    let markers = seed_dest_pair(&destdir);
    let out = install_stage(&stage, &destdir);
    assert!(
        !out.status.success(),
        "manifest digest mismatch must be refused, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_dest_pair_unchanged(&destdir, &markers);
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
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nset -eu\nif [ \"$1\" = build ]; then\n    export CARGO_PROFILE_RELEASE_STRIP=symbols\nfi\nexec {} \"$@\"\n",
            env!("CARGO")
        ),
    )
    .expect("wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("chmod");
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
