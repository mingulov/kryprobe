// SPDX-License-Identifier: GPL-3.0-or-later
//! Lane-addressability guard (3A-L-T1): every `#[ignore]`d test names
//! the BPF lane that runs it, and every test addressable via
//! `cargo xtask test bpf` lives in a suite the lane actually runs —
//! ignored tests rot silently otherwise. The pinned total fails the
//! gate on accidental ignore add/remove (bump deliberately with the
//! new test's lane reason).

use std::path::{Path, PathBuf};

/// Pinned ignored-test total: bump only when a lane test is added or
/// removed, with its `BPF lane:` reason in place (37 at P3r:
/// +`guest_sync_meta_matches_fixture_truth`,
/// +`guest_below_floor_refuses_typed`,
/// +`guest_enokey_leaves_provider_unentered` — all vng-lane,
/// staged-guest only; the sudo-lane EXPECTED inventory enrolls the
/// suite with OTHER_LANE routing under its explicit lane decision).
const PINNED_IGNORED: usize = 37;

/// Reason prefix every ignored test must carry.
const LANE_PREFIX: &str = "BPF lane: ";

/// Reason spelling for tests the xtask lane runs itself (as opposed
/// to manual sudo + lock/lease lanes).
const XTASK_REASON: &str = "BPF lane: run with `cargo xtask test bpf`";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("workspace root resolves")
}

/// The `#[ignore...]` reason on `line`, or `None` for non-attribute
/// lines (doc comments mentioning `#[ignore]` are not attributes).
fn ignore_reason(line: &str) -> Option<Option<String>> {
    let trimmed = line.trim();
    if trimmed.starts_with("//!") || trimmed.starts_with("//") {
        return None;
    }
    let rest = trimmed.strip_prefix("#[ignore")?;
    if rest.trim() == "]" {
        return Some(None);
    }
    let rest = rest.trim().strip_prefix('=')?.trim();
    let reason = rest
        .strip_prefix('"')?
        .strip_suffix(']')?
        .strip_suffix('"')?;
    Some(Some(reason.to_owned()))
}

/// `(package, suite)` pairs from the `test_bpf` runner table in
/// `xtask/src/bpf/mod.rs` (lines shaped `("pkg", "suite"),`).
fn lane_suites(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim().strip_suffix(',')?.trim();
            let (pkg, suite) = line.strip_prefix("(\"")?.split_once("\", \"")?;
            let suite = suite.strip_suffix("\")")?;
            if !pkg.contains(' ') && !suite.contains(' ') {
                Some((pkg.to_owned(), suite.to_owned()))
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn ignore_attributes_parse() {
    assert_eq!(ignore_reason("#[test]"), None);
    assert_eq!(
        ignore_reason("//! The roundtrip test is `#[ignore]`d (needs privilege)"),
        None
    );
    assert_eq!(
        ignore_reason("#[ignore = \"BPF lane: run with `cargo xtask test bpf`\"]"),
        Some(Some(XTASK_REASON.to_owned()))
    );
    // Bare `#[ignore]` (no reason) is a parse failure, not silent: the
    // workspace scan below reports it as an empty reason.
    assert_eq!(ignore_reason("#[ignore]"), Some(None));
}

#[test]
fn lane_table_parses() {
    let text = "        (\"kryprobe-privilege\", \"bpf_pipeline\"),\n        (\"kryprobe-cli\", \"cli_bpf_e2e\"),\n";
    assert_eq!(
        lane_suites(text),
        vec![
            ("kryprobe-privilege".to_owned(), "bpf_pipeline".to_owned()),
            ("kryprobe-cli".to_owned(), "cli_bpf_e2e".to_owned()),
        ]
    );
    assert!(lane_suites("fn test_bpf() -> i32 {\n").is_empty());
}

#[test]
fn every_ignored_test_is_lane_addressable() {
    let root = workspace_root();
    let lane_src =
        std::fs::read_to_string(root.join("xtask/src/bpf/mod.rs")).expect("lane source reads");
    let suites = lane_suites(&lane_src);
    assert!(!suites.is_empty(), "lane table must parse non-empty");
    let mut total = 0usize;
    let mut failures = Vec::new();
    for krate in [
        "kryprobe-abi",
        "kryprobe-core",
        "kryprobe-policy",
        "kryprobe-privilege",
        "kryprobe-report",
        "kryprobe-cli",
    ] {
        let tests_dir = root.join("crates").join(krate).join("tests");
        let Ok(entries) = std::fs::read_dir(&tests_dir) else {
            continue;
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("test file reads");
            let suite = path
                .file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned();
            for (index, line) in text.lines().enumerate() {
                let Some(reason) = ignore_reason(line) else {
                    continue;
                };
                total += 1;
                let what = format!("{}:{}: {}", path.display(), index + 1, line.trim());
                match reason {
                    None => failures.push(format!("bare #[ignore] without lane reason: {what}")),
                    Some(reason) if !reason.starts_with(LANE_PREFIX) => {
                        failures.push(format!("non-lane ignore reason: {what}"));
                    }
                    Some(reason) if reason == XTASK_REASON => {
                        if !suites.iter().any(|(p, s)| p == krate && *s == suite) {
                            failures.push(format!(
                                "xtask-reason test outside the lane suite list: {what}"
                            ));
                        }
                    }
                    Some(_) => {}
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "lane-addressability failures:\n{}",
        failures.join("\n")
    );
    assert_eq!(
        total, PINNED_IGNORED,
        "ignored-test total drifted (accidental #[ignore] add/remove?)"
    );
}
