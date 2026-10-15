// SPDX-License-Identifier: GPL-3.0-or-later
//! Spawn-hygiene regression: fds the test process inherited (CI runner
//! log pipes sit at high non-CLOEXEC numbers) must not reach the
//! helper, whose stdio-only attestation refuses them. GH host-gate run
//! 38811851719 went red on exactly this: every i02 helper spawn
//! refused with single-line `{"error":"helper_refused"}`.

#[path = "support/mod.rs"]
mod support;

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// Serializes the two tests: one scrubs CLOEXEC process-wide, the other
/// needs its dirty fds untouched between setup and spawn.
static SPAWN_GUARD: Mutex<()> = Mutex::new(());

/// Two held-open files with CLOEXEC forcibly cleared, mimicking
/// inherited runner pipes. Panics unless the fds are REALLY non-CLOEXEC
/// (a vacuous setup would pass without proving anything).
struct DirtyFds {
    _a: File,
    _b: File,
}

fn clear_cloexec(fd: std::os::unix::io::RawFd) {
    // SAFETY: fcntl F_SETFD on a live owned fd; no memory effects.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    assert_eq!(rc, 0, "test setup can clear CLOEXEC");
    // SAFETY: F_GETFD only reads flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert_eq!(
        flags & libc::FD_CLOEXEC,
        0,
        "test setup fds are really non-CLOEXEC"
    );
}

fn hold_dirty_fds() -> DirtyFds {
    let a = File::open("/dev/null").expect("open /dev/null");
    let b = File::open("/dev/null").expect("open /dev/null");
    clear_cloexec(a.as_raw_fd());
    clear_cloexec(b.as_raw_fd());
    DirtyFds { _a: a, _b: b }
}

fn helper_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_kryprobe-workload-helper"))
}

#[test]
fn scrubbed_spawn_serves_despite_dirty_parent() {
    let _guard = SPAWN_GUARD.lock().expect("guard");
    let _dirty = hold_dirty_fds();
    support::scrub_inherited_fds();
    let output = Command::new(helper_bin())
        .arg("--attest")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("helper spawns");
    assert_eq!(output.status.code(), Some(0), "scrubbed spawn serves");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"attestation\""),
        "attestation line on stdout: {stdout}"
    );
}

#[test]
fn unscrubbed_spawn_inherits_fds_and_refuses() {
    let _guard = SPAWN_GUARD.lock().expect("guard");
    let _dirty = hold_dirty_fds();
    // NO scrub here: this control pins the hazard the other test fixes.
    let output = Command::new(helper_bin())
        .arg("--attest")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("helper spawns");
    assert_eq!(output.status.code(), Some(1), "unscrubbed spawn refuses");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim(),
        r#"{"error":"helper_refused"}"#,
        "single-line refusal, no attestation: {stderr:?}"
    );
}
