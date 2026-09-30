// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded target inspection: the ONLY inspection path (SECURITY §3.3).
//!
//! `inspect_pid` pins the target with pidfd + `/proc/<pid>/stat` starttime,
//! then takes bounded reads of exe link metadata, maps line count + first
//! device, plus Yama scope and CapEff context notes.
//!
//! Micro-borrow note: pidfd+starttime pin + ENOENT-only exit proof follows
//! the p11scope `process.rs` / osslscope `pin.rs` patterns, reimplemented
//! here (no code copied).

use crate::fd::OwnedFd;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

/// Maximum bytes read from any single `/proc` file (bounded reads only).
const READ_CAP: u64 = 64 * 1024;

/// Sentinel for an unreadable Yama scope (context note, never gating).
const YAMA_UNKNOWN: u32 = u32::MAX;

/// Minimal process/object state needed to derive or verify a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSnapshot {
    /// Inspected process ID.
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat` (starttime, clock ticks).
    pub starttime: u64,
    /// Device of the `/proc/<pid>/exe` symlink.
    pub exe_dev: u64,
    /// Inode of the `/proc/<pid>/exe` symlink.
    pub exe_ino: u64,
    /// Size of the `/proc/<pid>/exe` symlink.
    pub exe_size: u64,
    /// Lines seen within the bounded maps read.
    pub maps_lines: u64,
    /// Device field (`08:01` shape) of the first maps line, if any.
    pub maps_first_dev: String,
    /// Yama ptrace scope, or `u32::MAX` when unreadable.
    pub yama_scope: u32,
    /// `CapEff` hex value, or `"unknown"` when unreadable.
    pub caps: String,
}

/// Inspection failure: the target is gone, or a stage was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectError {
    /// pidfd open and `/proc` reads agree the target no longer exists.
    TargetGone,
    /// A named stage was refused by permissions.
    Denied {
        /// Stage that hit EACCES/EPERM (e.g. `"maps"`).
        stage: String,
    },
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetGone => write!(f, "target gone"),
            Self::Denied { stage } => write!(f, "denied at stage: {stage}"),
        }
    }
}

impl std::error::Error for InspectError {}

/// Map an I/O failure: ESRCH/ENOENT → gone, EACCES/EPERM → denied stage.
fn map_io(stage: &'static str, err: std::io::Error) -> InspectError {
    match err.raw_os_error() {
        Some(code) if code == libc::ESRCH || code == libc::ENOENT => InspectError::TargetGone,
        Some(code) if code == libc::EACCES || code == libc::EPERM => InspectError::Denied {
            stage: stage.to_owned(),
        },
        _ => match err.kind() {
            std::io::ErrorKind::NotFound => InspectError::TargetGone,
            _ => InspectError::Denied {
                stage: stage.to_owned(),
            },
        },
    }
}

/// Read one `/proc` file with a hard byte cap.
fn read_capped(path: &str, stage: &'static str) -> Result<String, InspectError> {
    let file = std::fs::File::open(path).map_err(|err| map_io(stage, err))?;
    let mut text = String::new();
    file.take(READ_CAP)
        .read_to_string(&mut text)
        .map_err(|err| map_io(stage, err))?;
    Ok(text)
}

/// Parse field 22 (starttime) from `/proc/<pid>/stat` text.
fn parse_starttime(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(19)?.parse::<u64>().ok()
}

/// Device field of the first maps line (`""` when there is none).
fn parse_first_dev(maps: &str) -> String {
    match maps.lines().next() {
        Some(line) => match line.split_whitespace().nth(3) {
            Some(dev) => dev.to_owned(),
            None => String::new(),
        },
        None => String::new(),
    }
}

/// `CapEff` hex value from `/proc/<pid>/status` text.
fn cap_eff(status: &str) -> String {
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("CapEff:") {
            return value.trim().to_owned();
        }
    }
    "unknown".to_owned()
}

/// Inspect one process with bounded reads (SECURITY §3.3).
///
/// Opens a pidfd to pin the target, then reads starttime, exe link
/// metadata, and a bounded maps prefix. ESRCH/ENOENT (including a
/// pidfd_open miss or an unreadable stat) map to
/// [`InspectError::TargetGone`]; EACCES/EPERM map to
/// [`InspectError::Denied`] naming the stage. Yama/CapEff are context
/// notes only and never fail the snapshot.
///
/// Crate-private: the only external entry is the inspection facet
/// (`TargetInspectionAuthority::inspect` on `LocalPrivilegedAuthority`).
pub(crate) fn inspect_pid(pid: u32) -> Result<TargetSnapshot, InspectError> {
    // No live pid exceeds i32::MAX (Linux pid_max <= 2^22); anything above
    // is gone by construction. Reject before the narrowing cast so the
    // fail-closed verdict never depends on negative-pid errno mapping.
    if pid > i32::MAX as u32 {
        return Err(InspectError::TargetGone);
    }
    // Raw syscall: this libc exposes SYS_pidfd_open but no pidfd_open wrapper.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as i32, 0) } as i32;
    if raw < 0 {
        let code = std::io::Error::last_os_error().raw_os_error();
        match code {
            Some(c) if c == libc::ESRCH || c == libc::ENOENT || c == libc::EINVAL => {
                return Err(InspectError::TargetGone);
            }
            _ => {
                return Err(InspectError::Denied {
                    stage: "pidfd_open".to_owned(),
                });
            }
        }
    }
    // SAFETY: pidfd_open returned an open fd; this guard is its sole owner.
    // Held to end of scope so the pid cannot be recycled mid-snapshot.
    let _pin = unsafe { OwnedFd::from_raw_fd(raw) };

    let stat_path = format!("/proc/{pid}/stat");
    let stat = read_capped(&stat_path, "stat")?;
    let starttime = match parse_starttime(&stat) {
        Some(value) => value,
        None => return Err(InspectError::TargetGone),
    };

    let exe_path = format!("/proc/{pid}/exe");
    let exe_meta = std::fs::symlink_metadata(&exe_path).map_err(|err| map_io("exe", err))?;

    let maps_path = format!("/proc/{pid}/maps");
    let maps = read_capped(&maps_path, "maps")?;
    let maps_lines = maps.lines().count() as u64;
    let maps_first_dev = parse_first_dev(&maps);

    let yama_scope = match read_capped("/proc/sys/kernel/yama/ptrace_scope", "yama") {
        Ok(text) => match text.trim().parse::<u32>() {
            Ok(value) => value,
            Err(_) => YAMA_UNKNOWN,
        },
        Err(_) => YAMA_UNKNOWN,
    };
    let status_path = format!("/proc/{pid}/status");
    let caps = match read_capped(&status_path, "status") {
        Ok(text) => cap_eff(&text),
        Err(_) => "unknown".to_owned(),
    };

    Ok(TargetSnapshot {
        pid,
        starttime,
        exe_dev: exe_meta.dev(),
        exe_ino: exe_meta.ino(),
        exe_size: exe_meta.size(),
        maps_lines,
        maps_first_dev,
        yama_scope,
        caps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pids above i32::MAX fail closed without reaching the syscall.
    #[test]
    fn huge_pid_is_target_gone() {
        assert_eq!(
            inspect_pid(i32::MAX as u32 + 1),
            Err(InspectError::TargetGone)
        );
        assert_eq!(inspect_pid(u32::MAX), Err(InspectError::TargetGone));
    }
}
