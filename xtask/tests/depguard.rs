// SPDX-License-Identifier: GPL-3.0-or-later
//! Dependency-direction guard (1B-M4): `kryprobe-testkit` is dev-only —
//! no production crate may carry it under `[dependencies]`. A production
//! edge reintroduced here fails the gate, not review attention.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// True when `manifest` names `dep` under `[dependencies]` (a simple
/// section scan — these manifests keep one dep per line).
fn has_normal_dep(manifest: &Path, dep: &str) -> bool {
    let text = std::fs::read_to_string(manifest).expect("manifest reads");
    let mut in_normal_deps = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_normal_deps = line == "[dependencies]";
            continue;
        }
        if in_normal_deps && line.starts_with(dep) {
            return true;
        }
    }
    false
}

#[test]
fn testkit_is_dev_only_everywhere() {
    let root = workspace_root();
    for krate in [
        "kryprobe-abi",
        "kryprobe-core",
        "kryprobe-policy",
        "kryprobe-privilege",
        "kryprobe-report",
        "kryprobe-cli",
    ] {
        let manifest = root.join("crates").join(krate).join("Cargo.toml");
        assert!(
            !has_normal_dep(&manifest, "kryprobe-testkit"),
            "{krate} must not depend on testkit in production (1B-M4)"
        );
    }
}
