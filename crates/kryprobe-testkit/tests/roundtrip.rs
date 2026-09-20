// SPDX-License-Identifier: GPL-3.0-or-later
//! Round-trip tests: goldens and ABI event bytes (the clock and JSONL
//! checks moved to their production crates with the code, 1B-M4).

use std::path::{Path, PathBuf};

use kryprobe_testkit::assert_golden;

/// Serializes every `assert_golden` call (which reads process env) with the
/// `set_var`/`remove_var` in the update test, so no two threads touch the
/// environment concurrently.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn locked_assert_golden(path: &Path, actual: &[u8]) {
    let _guard = lock_env();
    assert_golden(path, actual);
}

fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kryprobe-testkit-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[test]
fn golden_match_passes_on_identical_bytes() {
    let path = scratch_dir("match").join("golden.bin");
    std::fs::write(&path, b"exact-bytes").expect("write golden");
    locked_assert_golden(&path, b"exact-bytes");
}

#[test]
#[should_panic(expected = "mismatch")]
fn golden_mismatch_fails() {
    let path = scratch_dir("mismatch").join("golden.bin");
    std::fs::write(&path, b"expected-bytes").expect("write golden");
    locked_assert_golden(&path, b"different-bytes");
}

#[test]
fn golden_update_rewrites_and_still_fails() {
    let path = scratch_dir("update").join("golden.bin");
    std::fs::write(&path, b"stale-bytes").expect("write golden");
    let _guard = lock_env();
    // SAFETY: `ENV_LOCK` is held, and every other environment access in this
    // test binary (all `assert_golden` reads) goes through the same lock.
    unsafe {
        std::env::set_var("KRYPROBE_UPDATE_GOLDENS", "1");
    }
    let result = std::panic::catch_unwind(|| assert_golden(&path, b"fresh-bytes"));
    // SAFETY: same lock still held; no other thread can observe the update.
    unsafe {
        std::env::remove_var("KRYPROBE_UPDATE_GOLDENS");
    }
    let err = result.expect_err("update mode must still fail the test");
    let message = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|text| (*text).to_string()))
        .expect("panic payload is a string");
    assert!(
        message.contains("mismatch"),
        "update panic must name the mismatch, got: {message}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read rewritten golden"),
        b"fresh-bytes"
    );
}

#[test]
fn golden_mismatch_without_update_mode_leaves_file_untouched() {
    let path = scratch_dir("no-update").join("golden.bin");
    std::fs::write(&path, b"stale-bytes").expect("write golden");
    let _guard = lock_env();
    // Force update mode off even if the outer environment enables it, so
    // this negative control always exercises the no-rewrite path.
    let saved = std::env::var("KRYPROBE_UPDATE_GOLDENS").ok();
    // SAFETY: `ENV_LOCK` is held; see the update test.
    unsafe {
        std::env::remove_var("KRYPROBE_UPDATE_GOLDENS");
    }
    let result = std::panic::catch_unwind(|| assert_golden(&path, b"fresh-bytes"));
    // SAFETY: same lock still held; the saved value (if any) is restored.
    unsafe {
        if let Some(value) = saved {
            std::env::set_var("KRYPROBE_UPDATE_GOLDENS", value);
        }
    }
    assert!(result.is_err(), "mismatch must still fail the test");
    assert_eq!(
        std::fs::read(&path).expect("read untouched golden"),
        b"stale-bytes"
    );
}

#[test]
fn abi_event_bytes_split_and_match_golden() {
    use kryprobe_abi::{ABI_VERSION, split_header};

    /// 8-aligned scratch: `split_header` requires an 8-aligned buffer.
    #[repr(C, align(8))]
    struct Scratch([u8; 128]);

    let payload = b"synthetic-event-payload";
    let total = 56 + payload.len();
    let mut scratch = Scratch([0u8; 128]);
    scratch.0[0..2].copy_from_slice(&ABI_VERSION.to_le_bytes());
    scratch.0[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    scratch.0[56..total].copy_from_slice(payload);
    let (_header, body) = split_header(&scratch.0[..total]).expect("valid header splits");
    assert_eq!(body, payload);

    let path = scratch_dir("abi").join("event.bin");
    std::fs::write(&path, payload).expect("write golden");
    locked_assert_golden(&path, body);
}
