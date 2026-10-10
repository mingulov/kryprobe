// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 3 installer tests: the dev flow installs the helper
//! sibling from the caller's Cargo target dir, without caps, into an
//! isolated destination — and refuses loudly when a named source is
//! missing.
//!
//! The script under test is byte-copied into a scratch "repo" so
//! ROOT resolution (from `$0`) lands on a fake tree: stub binaries,
//! stub BPF objects, and a DESTDIR that stages instead of granting
//! caps (no root, no live system touched). BPF objects stay at the
//! xtask lane path — they are stubs here because this lane never
//! builds BPF (host gates only).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Byte-copy of `packaging/install.sh` at test time (the copy is
/// what runs, so ROOT points at the fake tree).
fn script_source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/install.sh")
}

struct FakeTree {
    _scratch: kryprobe_testkit::TempDir,
    root: PathBuf,
}

impl FakeTree {
    /// `bins`: directory (relative to the fake root) holding stub
    /// `kryprobe` + `kryprobe-workload-helper`; the xtask-lane BPF
    /// stubs always live at `<root>/target/kryprobe-bpf/`.
    fn new(bins: &str, bin_bytes: &[u8], helper_bytes: &[u8]) -> Self {
        let scratch = kryprobe_testkit::TempDir::named("k3-install").expect("scratch");
        let root = scratch.path().to_path_buf();
        let script_dst = root.join("packaging/install.sh");
        std::fs::create_dir_all(script_dst.parent().expect("pkg dir")).expect("pkg dir");
        let source = script_source();
        assert!(source.is_file(), "ships: {}", source.display());
        std::fs::copy(&source, &script_dst).expect("stage script");
        let bin_dir = root.join(bins);
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        std::fs::write(bin_dir.join("kryprobe"), bin_bytes).expect("stub bin");
        std::fs::write(bin_dir.join("kryprobe-workload-helper"), helper_bytes)
            .expect("stub helper");
        let obj_dir = root.join("target/kryprobe-bpf");
        std::fs::create_dir_all(&obj_dir).expect("obj dir");
        std::fs::write(obj_dir.join("kcrypto.bpf.o"), b"fake-kcrypto-object\n").expect("stub o");
        std::fs::write(
            obj_dir.join("kcrypto-lifecycle.bpf.o"),
            b"fake-lifecycle-object\n",
        )
        .expect("stub lo");
        Self {
            _scratch: scratch,
            root,
        }
    }

    fn script(&self) -> PathBuf {
        self.root.join("packaging/install.sh")
    }

    /// DESTDIR staging install: copies files, then exits 0 before
    /// any cap grant (no root needed).
    fn install(&self, target_dir: Option<&str>, cwd: Option<&Path>) -> std::process::Output {
        let destdir = self.root.join("dest");
        let mut cmd = Command::new("sh");
        cmd.arg(self.script())
            .arg("--destdir")
            .arg(&destdir)
            .arg("--prefix")
            .arg("/t")
            .arg("--no-mint");
        match target_dir {
            Some(dir) => {
                cmd.env("CARGO_TARGET_DIR", dir);
            }
            None => {
                cmd.env_remove("CARGO_TARGET_DIR");
            }
        }
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.output().expect("runs")
    }

    fn dest(&self) -> PathBuf {
        self.root.join("dest/t")
    }

    /// Build a fake release stage under `root/name`: stub objects, a
    /// stub `kryprobe` answering `doctor --versions --json` with the
    /// measured pins, byte-exact manifest v2, and the checksum list.
    /// Returns the stage directory.
    fn stage(&self, name: &str) -> PathBuf {
        let stage = self.root.join(name);
        let obj_dir = stage.join("bin/kryprobe-bpf");
        std::fs::create_dir_all(&obj_dir).expect("stage dirs");
        let obj = obj_dir.join("kcrypto.bpf.o");
        let lifecycle = obj_dir.join("kcrypto-lifecycle.bpf.o");
        std::fs::write(&obj, b"fake-stage-kcrypto-object\n").expect("stage o");
        std::fs::write(&lifecycle, b"fake-stage-lifecycle-object\n").expect("stage lo");
        let obj_digest = sha256_of(&obj);
        let lifecycle_digest = sha256_of(&lifecycle);
        // Stub binary: executable, CWD-independent, enforcing the
        // staged objects' pins (same predicate build-release.sh and
        // install.sh verify — absolute staged paths).
        let doctor = format!(
            "{{\"pins_enforced\":true,\"profile_pins_enforced\":true,\
             \"objects\":[{{\"sha256\":\"{obj_digest}\",\"path\":\"{obj}\"}},\
             {{\"sha256\":\"{lifecycle_digest}\",\"path\":\"{lifecycle}\"}}]}}",
            obj = obj.display(),
            lifecycle = lifecycle.display(),
        );
        let bin = stage.join("bin/kryprobe");
        std::fs::write(&bin, format!("#!/bin/sh\nprintf '%s\\n' '{doctor}'\n")).expect("stage bin");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let bin_digest = sha256_of(&bin);
        // Byte-exact manifest v2 + trailing newline (template owned
        // by build-release.sh; mirrored here).
        std::fs::write(
            stage.join("manifest.json"),
            format!(
                "{{\"kryprobe_release_manifest\":2,\
                 \"binary\":{{\"path\":\"bin/kryprobe\",\"sha256\":\"{bin_digest}\"}},\
                 \"objects\":[{{\"name\":\"kcrypto.bpf.o\",\
                 \"path\":\"bin/kryprobe-bpf/kcrypto.bpf.o\",\
                 \"sha256\":\"{obj_digest}\"}},\
                 {{\"name\":\"kcrypto-lifecycle.bpf.o\",\
                 \"path\":\"bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o\",\
                 \"sha256\":\"{lifecycle_digest}\"}}],\
                 \"pins_enforced\":true,\"profile_pins_enforced\":true,\
                 \"pin_digests\":[\"{obj_digest}\",\"{lifecycle_digest}\"]}}\n"
            ),
        )
        .expect("stage manifest");
        std::fs::write(
            stage.join("sha256sums.txt"),
            format!(
                "{bin_digest}  bin/kryprobe\n\
                 {obj_digest}  bin/kryprobe-bpf/kcrypto.bpf.o\n\
                 {lifecycle_digest}  bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o\n"
            ),
        )
        .expect("stage sums");
        stage
    }

    /// DESTDIR staging install from a release stage (verified first,
    /// `--no-mint` so no cap grant runs).
    fn install_stage(&self, stage: &Path) -> std::process::Output {
        let destdir = self.root.join("dest");
        Command::new("sh")
            .arg(self.script())
            .arg("--destdir")
            .arg(&destdir)
            .arg("--prefix")
            .arg("/t")
            .arg("--no-mint")
            .arg("--stage")
            .arg(stage)
            .output()
            .expect("runs")
    }
}

fn sha256_of(path: &Path) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum runs");
    assert!(out.status.success(), "sha256sum exits 0");
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .split_whitespace()
        .next()
        .expect("digest")
        .to_owned()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("installed")
        .permissions()
        .mode()
        & 0o777
}

/// Isolated-target install: stub bins come ONLY from the caller's
/// CARGO_TARGET_DIR (never the default), the helper lands alongside
/// kryprobe at 0755 with no caps granted, objects at 0644.
#[test]
fn dev_install_uses_isolated_target_and_ships_helper() {
    let tree = FakeTree::new(
        "cargo-target/debug",
        b"fake-kryprobe-isolated\n",
        b"fake-helper-isolated\n",
    );
    let target = tree.root.join("cargo-target");
    // The default target dir holds nothing installable: any byte
    // from there would prove the wrong resolution.
    assert!(!tree.root.join("target/debug/kryprobe").exists());
    let out = tree.install(Some(&target.display().to_string()), None);
    assert!(
        out.status.success(),
        "exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dest = tree.dest();
    assert_eq!(
        std::fs::read(dest.join("bin/kryprobe")).expect("bin"),
        b"fake-kryprobe-isolated\n"
    );
    assert_eq!(
        std::fs::read(dest.join("bin/kryprobe-workload-helper")).expect("helper"),
        b"fake-helper-isolated\n"
    );
    assert_eq!(mode_of(&dest.join("bin/kryprobe")), 0o755);
    assert_eq!(mode_of(&dest.join("bin/kryprobe-workload-helper")), 0o755);
    assert_eq!(mode_of(&dest.join("bin/kryprobe-bpf/kcrypto.bpf.o")), 0o644);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("kryprobe-workload-helper (no caps)"),
        "install announces the cap-free helper:\n{stdout}"
    );
}

/// Cargo semantics: a relative CARGO_TARGET_DIR resolves against the
/// CWD, not the repo.
#[test]
fn relative_target_dir_resolves_against_cwd() {
    let tree = FakeTree::new(
        "cargo-target/debug",
        b"fake-kryprobe-relative\n",
        b"fake-helper-relative\n",
    );
    let out = tree.install(Some("cargo-target"), Some(&tree.root));
    assert!(
        out.status.success(),
        "exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(tree.dest().join("bin/kryprobe")).expect("bin"),
        b"fake-kryprobe-relative\n"
    );
}

/// Unset CARGO_TARGET_DIR keeps the historical default
/// (`$ROOT/target`), preferring release bins when present.
#[test]
fn unset_target_dir_keeps_default_with_release_preference() {
    let tree = FakeTree::new(
        "target/debug",
        b"fake-kryprobe-debug\n",
        b"fake-helper-debug\n",
    );
    let release = tree.root.join("target/release");
    std::fs::create_dir_all(&release).expect("release dir");
    std::fs::write(release.join("kryprobe"), b"fake-kryprobe-release\n").expect("rel bin");
    std::fs::write(
        release.join("kryprobe-workload-helper"),
        b"fake-helper-release\n",
    )
    .expect("rel helper");
    let out = tree.install(None, None);
    assert!(
        out.status.success(),
        "exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(tree.dest().join("bin/kryprobe")).expect("bin"),
        b"fake-kryprobe-release\n"
    );
    assert_eq!(
        std::fs::read(tree.dest().join("bin/kryprobe-workload-helper")).expect("helper"),
        b"fake-helper-release\n"
    );
}

/// A named-but-missing helper refuses (exit 1) instead of shipping
/// a kryprobe whose metadata lookups would silently degrade.
#[test]
fn missing_helper_refuses_before_copy() {
    let tree = FakeTree::new("cargo-target/debug", b"fake-kryprobe\n", b"fake-helper\n");
    std::fs::remove_file(
        tree.root
            .join("cargo-target/debug/kryprobe-workload-helper"),
    )
    .expect("drop helper");
    let target = tree.root.join("cargo-target");
    let out = tree.install(Some(&target.display().to_string()), None);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kryprobe-workload-helper"),
        "names the missing helper: {stderr:?}"
    );
    assert!(
        !tree.dest().join("bin/kryprobe").exists(),
        "refusal copies nothing"
    );
}

/// Structural pin on the no-caps invariant: the only cap grant in
/// the script targets the kryprobe binary — the helper is never
/// minted, so it can never carry ambient authority into the
/// confined child.
#[test]
fn script_mints_only_the_kryprobe_binary() {
    let text = std::fs::read_to_string(script_source()).expect("script reads");
    // Real invocations only: comments document the invariant and
    // echo lines print hints — neither grants a capability.
    let mints: Vec<&str> = text
        .lines()
        .filter(|line| {
            line.contains("token mint")
                && !line.trim_start().starts_with('#')
                && !line.contains("echo")
        })
        .collect();
    assert_eq!(mints.len(), 1, "exactly one mint site: {mints:?}");
    assert!(
        mints[0].contains("--bin \"$BIN_DST\"") && !mints[0].contains("HELPER"),
        "the mint site grants the kryprobe binary only: {}",
        mints[0]
    );
}

/// M2: a fresh `--stage` install copies no helper (pinned actual
/// behavior — metadata lookups then refuse `HelperRefused`).
#[test]
fn stage_fresh_install_ships_no_helper() {
    let tree = FakeTree::new("cargo-target/debug", b"unused\n", b"unused\n");
    let stage = tree.stage("stage");
    let out = tree.install_stage(&stage);
    assert!(
        out.status.success(),
        "exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dest = tree.dest();
    assert!(dest.join("bin/kryprobe").is_file(), "binary installs");
    assert!(
        dest.join("bin/kryprobe-bpf/kcrypto.bpf.o").is_file(),
        "objects install"
    );
    assert!(
        !dest.join("bin/kryprobe-workload-helper").exists(),
        "fresh stage ships no helper"
    );
}

/// M2: `--stage` over an installed sibling preserves it
/// byte-identical — its revision keeps serving (NOT a refusal).
#[test]
fn stage_upgrade_preserves_sibling_byte_identical() {
    let tree = FakeTree::new("cargo-target/debug", b"unused\n", b"unused\n");
    let stage = tree.stage("stage");
    let sibling = tree.dest().join("bin/kryprobe-workload-helper");
    std::fs::create_dir_all(sibling.parent().expect("bin dir")).expect("bin dir");
    std::fs::write(&sibling, b"old-helper-revision-1\n").expect("old sibling");
    std::fs::set_permissions(&sibling, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let out = tree.install_stage(&stage);
    assert!(
        out.status.success(),
        "exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let dest = tree.dest();
    assert!(dest.join("bin/kryprobe").is_file(), "binary updates");
    assert_eq!(
        std::fs::read(&sibling).expect("sibling reads"),
        b"old-helper-revision-1\n",
        "sibling preserved byte-identical"
    );
    assert_eq!(mode_of(&sibling), 0o755, "sibling mode preserved");
}

/// M2: the installer help pins fresh-vs-upgrade helper behavior
/// (the old text claimed `HelperRefused` unconditionally, which is
/// false over an installed sibling).
#[test]
fn stage_help_pins_fresh_vs_upgrade_helper_behavior() {
    let out = Command::new("sh")
        .arg(script_source())
        .arg("--help")
        .output()
        .expect("help runs");
    assert!(out.status.success(), "help exits 0");
    let help = String::from_utf8(out.stdout).expect("utf-8 help");
    assert!(
        help.contains("fresh install") && help.contains("no helper"),
        "fresh wording:\n{help}"
    );
    assert!(
        help.contains("preserved") && help.contains("byte-identical"),
        "upgrade wording:\n{help}"
    );
}
