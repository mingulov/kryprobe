// SPDX-License-Identifier: GPL-3.0-or-later
//! Manifest-hygiene gate (BP-L4): shared `[package]` metadata lives
//! in `[workspace.package]` and every workspace member inherits it,
//! so version/edition/license/rust-version cannot drift per crate.
//! The BPF crates are workspace-excluded (separate `[workspace]`-less
//! builds under the pinned nightly) and cannot inherit — they pin
//! the same version explicitly, which this gate compares.

use std::path::{Path, PathBuf};

/// Member manifests that must inherit every [`INHERITED_KEYS`] entry.
const HOST_MANIFESTS: &[&str] = &[
    "xtask/Cargo.toml",
    "crates/kryprobe-abi/Cargo.toml",
    "crates/kryprobe-testkit/Cargo.toml",
    "crates/kryprobe-core/Cargo.toml",
    "crates/kryprobe-privilege/Cargo.toml",
    "crates/kryprobe-report/Cargo.toml",
    "crates/kryprobe-policy/Cargo.toml",
    "crates/kryprobe-cli/Cargo.toml",
];

/// `[package]` keys owned by `[workspace.package]`.
const INHERITED_KEYS: &[&str] = &["version", "edition", "license", "rust-version"];

/// Excluded-from-workspace manifests whose explicit `version` must
/// equal the workspace version.
const BPF_MANIFESTS: &[&str] = &[
    "crates/bpf-spine/Cargo.toml",
    "crates/bpf-kcrypto/Cargo.toml",
];

/// Non-comment, non-empty manifest lines (TOML `#` comments only).
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && *line != "[package]")
}

/// `[workspace.package]`-owned keys missing their
/// `<key>.workspace = true` inheritance line.
pub(crate) fn missing_inheritance(text: &str) -> Vec<&'static str> {
    INHERITED_KEYS
        .iter()
        .copied()
        .filter(|key| {
            let want = format!("{key}.workspace = true");
            !code_lines(text).any(|line| line == want)
        })
        .collect()
}

/// First `version = "x"` value in `text` (the `[package]` stanza for
/// member manifests, which declare no other `version` first).
pub(crate) fn manifest_version(text: &str) -> Option<String> {
    code_lines(text).find_map(|line| {
        line.strip_prefix("version = ")
            .and_then(|rest| rest.strip_prefix('"')?.strip_suffix('"'))
            .map(str::to_owned)
    })
}

/// The `[workspace.package]` version from the root manifest.
pub(crate) fn workspace_version(root_text: &str) -> Option<String> {
    let mut in_section = false;
    for line in code_lines(root_text) {
        if line.starts_with('[') {
            in_section = line == "[workspace.package]";
            continue;
        }
        if in_section && let Some(rest) = line.strip_prefix("version = ") {
            return rest
                .strip_prefix('"')
                .and_then(|quoted| quoted.strip_suffix('"'))
                .map(str::to_owned);
        }
    }
    None
}

/// Walk up to the workspace root (holds `crates/kryprobe-privilege/`).
fn workspace_root() -> Option<PathBuf> {
    crate::root::climb_to("crates/kryprobe-privilege")
}

/// Scan the manifests; nonempty means the gate fails.
pub(crate) fn find_violations(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for rel in HOST_MANIFESTS {
        let path = root.join(rel);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for key in missing_inheritance(&text) {
            out.push(format!(
                "{rel}: `{key}` not inherited from [workspace.package]"
            ));
        }
    }
    let root_text = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    match workspace_version(&root_text) {
        Some(version) => {
            for rel in BPF_MANIFESTS {
                let path = root.join(rel);
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                match manifest_version(&text) {
                    Some(got) if got == version => {}
                    Some(got) => out.push(format!(
                        "{rel}: version {got} != workspace version {version}"
                    )),
                    None => out.push(format!("{rel}: no explicit version found")),
                }
            }
        }
        None => out.push("Cargo.toml: no [workspace.package] version".to_owned()),
    }
    out.sort();
    out
}

/// xtask `check` step: 0 when the manifests hold, 1 with details otherwise.
pub(crate) fn check_manifests() -> i32 {
    let Some(root) = workspace_root() else {
        eprintln!(
            "xtask check: cannot find workspace root (no crates/kryprobe-privilege above here)"
        );
        return 1;
    };
    let violations = find_violations(&root);
    if violations.is_empty() {
        println!("+ manifest: workspace inheritance holds");
        return 0;
    }
    eprintln!("xtask check: manifest-hygiene violations (BP-L4):");
    for v in &violations {
        eprintln!("  {v}");
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_OK: &str = r#"
[package]
name = "kryprobe-core"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
"#;

    #[test]
    fn clean_host_manifest_passes() {
        assert!(missing_inheritance(HOST_OK).is_empty());
    }

    #[test]
    fn literal_host_values_are_flagged() {
        let text = HOST_OK.replace("edition.workspace = true", "edition = \"2024\"");
        assert_eq!(missing_inheritance(&text), vec!["edition"]);
    }

    #[test]
    fn commented_inheritance_does_not_count() {
        let text = HOST_OK.replace("license.workspace = true", "# license.workspace = true");
        assert_eq!(missing_inheritance(&text), vec!["license"]);
    }

    #[test]
    fn workspace_version_reads_the_package_section() {
        let text = "[workspace]\nresolver = \"2\"\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n";
        assert_eq!(workspace_version(text).as_deref(), Some("0.1.0"));
        assert_eq!(workspace_version("[workspace]\n"), None);
    }

    #[test]
    fn bpf_version_mismatch_is_a_violation() {
        let scratch = kryprobe_testkit::TempDir::named("manifest-gate").expect("scratch dir");
        let dir = scratch.path();
        std::fs::create_dir_all(dir.join("crates/bpf-spine")).unwrap();
        std::fs::create_dir_all(dir.join("crates/bpf-kcrypto")).unwrap();
        std::fs::create_dir_all(dir.join("xtask")).unwrap();
        for rel in HOST_MANIFESTS {
            let path = dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, HOST_OK).unwrap();
        }
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\n[workspace.package]\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("crates/bpf-spine/Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("crates/bpf-kcrypto/Cargo.toml"),
            "[package]\nname = \"y\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();
        let violations = find_violations(dir);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("bpf-kcrypto"), "{violations:?}");
    }

    /// The gate must hold on the real tree (BP-L4 migrated).
    #[test]
    fn real_manifests_hold() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .canonicalize()
            .unwrap();
        assert!(find_violations(&root).is_empty());
    }
}
