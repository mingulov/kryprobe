// SPDX-License-Identifier: GPL-3.0-or-later
//! `inspect`: one process snapshot, human or JSON.

use kryprobe_core::authority::TargetInspectionAuthority;
use kryprobe_privilege::{InspectError, LocalPrivilegedAuthority, TargetSnapshot};
use std::io::Write;

fn human(snapshot: &TargetSnapshot) -> String {
    format!(
        "pid: {}\nstarttime: {}\nexe_dev: {}\nexe_ino: {}\nexe_size: {}\nmaps_lines: {}\nmaps_first_dev: {}\nyama_scope: {}\ncaps: {}\n",
        snapshot.pid,
        snapshot.starttime,
        snapshot.exe_dev,
        snapshot.exe_ino,
        snapshot.exe_size,
        snapshot.maps_lines,
        snapshot.maps_first_dev,
        snapshot.yama_scope,
        snapshot.caps
    )
}

fn json(snapshot: &TargetSnapshot) -> serde_json::Value {
    serde_json::json!({
        "pid": snapshot.pid,
        "starttime": snapshot.starttime,
        "exe_dev": snapshot.exe_dev,
        "exe_ino": snapshot.exe_ino,
        "exe_size": snapshot.exe_size,
        "maps_lines": snapshot.maps_lines,
        "maps_first_dev": snapshot.maps_first_dev,
        "yama_scope": snapshot.yama_scope,
        "caps": snapshot.caps,
    })
}

/// Runs `inspect`: 0 on success, 1 when gone, 4 when denied a stage.
pub fn run(pid: u32, json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    match LocalPrivilegedAuthority.inspect(pid) {
        Ok(snapshot) => {
            if json {
                let _ = writeln!(stdout, "{}", self::json(&snapshot));
            } else {
                let _ = write!(stdout, "{}", human(&snapshot));
            }
            0
        }
        Err(InspectError::TargetGone) => {
            let _ = writeln!(stderr, "inspect: target gone (pid {pid})");
            1
        }
        Err(InspectError::Denied { stage }) => {
            let _ = writeln!(stderr, "inspect: Denied{{{stage}}} (needs capability)");
            4
        }
    }
}
