// SPDX-License-Identifier: GPL-3.0-or-later
//! Runner accounting must remain in the ordinary host gate.

#[test]
fn privileged_runner_rejects_stale_empty_skipped_and_timed_out_evidence() {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/test_sudo_lane.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg("-v")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("Python runner tests spawn");
    assert!(
        output.status.success(),
        "runner regressions: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
