// SPDX-License-Identifier: GPL-3.0-or-later
//! Round-trip tests: manual clock, goldens, JSONL checks, ABI event bytes.

use std::path::{Path, PathBuf};

use kryprobe_testkit::{ManualClock, StreamFinding, assert_golden, check_stream};

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

/// Caller-supplied kind table: testkit has no backend knowledge, so the
/// required payload keys per kind come from here.
const SYNTH_KINDS: &[(&str, &[&str])] = &[
    ("session_start", &["target_selector", "capture_mode"]),
    ("operation_observation", &["observation_id", "backend"]),
    ("session_end", &["verdict"]),
];

fn scratch_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kryprobe-testkit-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn record(kind: &str, record_id: &str, mono: &str, payload: &str) -> String {
    format!(
        "{{\"schema\":\"kryprobe.event/v0\",\"kind\":\"{kind}\",\
         \"session_id\":\"test:session\",\"record_id\":\"{record_id}\",\
         \"monotonic_ns\":\"{mono}\",\"payload\":{payload}}}"
    )
}

#[test]
fn manual_clock_starts_at_given_value_and_advances_monotonically() {
    let mut clock = ManualClock::new(1_000_000);
    assert_eq!(clock.now(), 1_000_000);
    assert_eq!(clock.advance(500), 1_000_500);
    assert_eq!(clock.now(), 1_000_500);
    assert_eq!(clock.advance(0), 1_000_500);
    assert!(clock.now() >= 1_000_500);
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
    assert!(result.is_err(), "update mode must still fail the test");
    assert_eq!(
        std::fs::read(&path).expect("read rewritten golden"),
        b"fresh-bytes"
    );
}

#[test]
fn check_stream_accepts_valid_three_record_stream() {
    let text = [
        record(
            "session_start",
            "test:r1",
            "1000000",
            "{\"target_selector\":\"pid\",\"capture_mode\":\"trace\"}",
        ),
        record(
            "operation_observation",
            "test:r2",
            "1000500",
            "{\"observation_id\":\"test:o1\",\"backend\":\"p11\"}",
        ),
        record(
            "session_end",
            "test:r3",
            "1001000",
            "{\"verdict\":\"OBSERVED\"}",
        ),
    ]
    .join("\n");
    assert_eq!(check_stream(&text, SYNTH_KINDS), Vec::new());
}

#[test]
fn check_stream_reports_missing_key() {
    let text = "{\"schema\":\"kryprobe.event/v0\",\"kind\":\"session_end\",\
        \"record_id\":\"test:r\",\"monotonic_ns\":\"7\",\
        \"payload\":{\"verdict\":\"OBSERVED\"}}";
    assert_eq!(
        check_stream(text, SYNTH_KINDS),
        vec![StreamFinding::MissingKey {
            line: 1,
            key: "session_id".to_string(),
        }]
    );
}

#[test]
fn check_stream_reports_missing_payload_key() {
    let text = record("session_end", "test:r", "7", "{}");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::MissingKey {
            line: 1,
            key: "payload.verdict".to_string(),
        }]
    );
}

#[test]
fn check_stream_reports_bad_shape() {
    let text = record("session_end", "test:r", "07", "{\"verdict\":\"OBSERVED\"}");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::BadShape {
            line: 1,
            key: "monotonic_ns".to_string(),
            value: "07".to_string(),
        }]
    );
}

#[test]
fn check_stream_reports_clock_went_backwards() {
    let text = [
        record(
            "session_start",
            "test:r1",
            "100",
            "{\"target_selector\":\"pid\",\"capture_mode\":\"trace\"}",
        ),
        record("session_end", "test:r2", "50", "{\"verdict\":\"OBSERVED\"}"),
    ]
    .join("\n");
    assert_eq!(
        check_stream(&text, SYNTH_KINDS),
        vec![StreamFinding::ClockWentBackwards {
            line: 2,
            previous: "100".to_string(),
            current: "50".to_string(),
        }]
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
