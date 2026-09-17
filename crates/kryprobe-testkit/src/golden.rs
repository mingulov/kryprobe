// SPDX-License-Identifier: GPL-3.0-or-later
//! Byte-exact golden files with rewrite-that-still-fails update semantics.

use std::env;
use std::fs;
use std::path::Path;

/// Env var that turns a golden mismatch into rewrite-and-still-fail.
///
/// Only the exact value `"1"` enables update mode.
pub const UPDATE_ENV_VAR: &str = "KRYPROBE_UPDATE_GOLDENS";

/// Asserts `actual` is byte-identical to the file at `path`, panicking on mismatch.
///
/// When `KRYPROBE_UPDATE_GOLDENS=1`, a mismatch rewrites the file with
/// `actual`, prints `GOLDEN-UPDATED <path>` to stderr, and still panics, so
/// golden updates never pass silently; re-run the test to confirm green.
/// A missing golden file counts as a mismatch. The parent directory must exist.
pub fn assert_golden(path: &Path, actual: &[u8]) {
    let expected = match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => panic!("golden {}: cannot read file: {err}", path.display()),
    };
    if expected.as_deref() == Some(actual) {
        return;
    }
    if update_mode() {
        match fs::write(path, actual) {
            Ok(()) => {}
            Err(err) => panic!("golden {}: cannot rewrite file: {err}", path.display()),
        }
        eprintln!("GOLDEN-UPDATED {}", path.display());
    }
    fail_mismatch(path, expected.as_deref(), actual);
}

fn update_mode() -> bool {
    env::var(UPDATE_ENV_VAR).is_ok_and(|value| value == "1")
}

fn fail_mismatch(path: &Path, expected: Option<&[u8]>, actual: &[u8]) -> ! {
    let hint = "run with KRYPROBE_UPDATE_GOLDENS=1 to rewrite, then re-run";
    match expected {
        None => panic!(
            "golden {}: mismatch, file missing ({} actual bytes); {hint}",
            path.display(),
            actual.len()
        ),
        Some(want) => match first_diff(want, actual) {
            Some(offset) => panic!(
                "golden {}: mismatch at byte {offset} (want {} bytes, got {}); {hint}",
                path.display(),
                want.len(),
                actual.len()
            ),
            None => panic!(
                "golden {}: mismatch (want {} bytes, got {}); {hint}",
                path.display(),
                want.len(),
                actual.len()
            ),
        },
    }
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    let common = a.len().min(b.len());
    for (offset, pair) in a.iter().zip(b.iter()).enumerate().take(common) {
        if pair.0 != pair.1 {
            return Some(offset);
        }
    }
    if a.len() == b.len() {
        return None;
    }
    Some(common)
}
