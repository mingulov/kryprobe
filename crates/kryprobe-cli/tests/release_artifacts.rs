// SPDX-License-Identifier: GPL-3.0-or-later
//! S05: staged release package binds one binary to exactly the BPF
//! objects it allows (T03). Correct object accepted; missing,
//! modified, and stale-from-another-build objects refused before
//! load; empty required pins fail the build. Owned temp dirs only —
//! no global install, no capabilities.

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

/// `doctor --versions --json` of a staged binary from a neutral CWD
/// with dev object overrides removed, so the exe-bundled tier is the
/// only tier that can resolve.
fn staged_versions(binary: &Path, cwd: &Path) -> serde_json::Value {
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

fn copy_file(src: &Path, dst: &Path) {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::copy(src, dst).expect("copy");
}

/// S05 matrix: one pinned release stage, four object variants. The
/// release binary is built once by the packaging script; each variant
/// re-stages that same immutable binary with a different object.
#[test]
fn s05_staged_package_binds_binary_to_object() {
    let root = workspace_root();
    let script = root.join("packaging/build-release.sh");
    let kcrypto = root.join("target/kryprobe-bpf/kcrypto.bpf.o");
    let spine = root.join("target/kryprobe-bpf/spine.bpf.o");
    assert!(
        kcrypto.is_file() && spine.is_file(),
        "prebuilt BPF objects required (run `cargo xtask build --bpf` first)"
    );
    let scratch = kryprobe_testkit::TempDir::named("s05-stage").expect("scratch");
    let stage = scratch.path().join("pkg");

    // Two-phase release build + atomic stage + manifest + verify.
    let out = run(Command::new("sh").arg(&script).args(["--dest"]).arg(&stage));
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

    let binary = stage.join("bin/kryprobe");
    let object = stage.join("bin/kryprobe-bpf/kcrypto.bpf.o");
    let neutral = scratch.path().join("neutral");
    std::fs::create_dir_all(&neutral).expect("neutral cwd");

    // Correct object: accepted, identity is the staged path + pin.
    let versions = staged_versions(&binary, &neutral);
    assert_eq!(versions["pins_enforced"], true);
    assert_eq!(versions["kcrypto"]["sha256"], pin.as_str());
    assert_eq!(
        versions["kcrypto"]["path"],
        object.to_str().expect("utf-8 path")
    );

    // Missing object: refused before load (null identity, pins hold).
    let missing = scratch.path().join("missing");
    copy_file(&binary, &missing.join("bin/kryprobe"));
    let versions = staged_versions(&missing.join("bin/kryprobe"), &neutral);
    assert_eq!(versions["pins_enforced"], true);
    assert!(
        versions["kcrypto"].is_null(),
        "missing object has no identity: {versions}"
    );

    // One-byte-modified object: digest mismatch, refused before load.
    let modified = scratch.path().join("modified");
    copy_file(&binary, &modified.join("bin/kryprobe"));
    let tampered = modified.join("bin/kryprobe-bpf/kcrypto.bpf.o");
    copy_file(&object, &tampered);
    let mut bytes = std::fs::read(&tampered).expect("read");
    bytes[100] ^= 0x01;
    std::fs::write(&tampered, &bytes).expect("write");
    let versions = staged_versions(&modified.join("bin/kryprobe"), &neutral);
    assert_eq!(versions["pins_enforced"], true);
    assert!(
        versions["kcrypto"].is_null(),
        "modified object has no identity: {versions}"
    );

    // Stale object from another build: genuine artifact bytes (the
    // spine object) under the kcrypto name — wrong identity, refused.
    let stale = scratch.path().join("stale");
    copy_file(&binary, &stale.join("bin/kryprobe"));
    copy_file(&spine, &stale.join("bin/kryprobe-bpf/kcrypto.bpf.o"));
    let versions = staged_versions(&stale.join("bin/kryprobe"), &neutral);
    assert_eq!(versions["pins_enforced"], true);
    assert!(
        versions["kcrypto"].is_null(),
        "stale object has no identity: {versions}"
    );
}

/// S05: `KRYPROBE_REQUIRE_PINS=1` with an empty pin set fails the
/// build instead of shipping a silently unpinned binary.
#[test]
fn s05_empty_required_pins_fail_the_build() {
    let root = workspace_root();
    let cargo = env!("CARGO");
    let out = run(Command::new(cargo)
        .args(["build", "--locked", "-p", "kryprobe-privilege"])
        .current_dir(&root)
        .env("KRYPROBE_REQUIRE_PINS", "1")
        .env_remove("KRYPROBE_PIN_DIGESTS"));
    assert!(
        !out.status.success(),
        "required-but-empty pins must fail the build"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to bake an unpinned binary"),
        "fail-closed reason named: {stderr}"
    );
}
