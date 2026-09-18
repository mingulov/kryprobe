// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw map element ops: u64 lookup/update + percpu sums (T7c2).

use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{bpf, last_errno};
use std::os::raw::c_void;

const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;

/// `BPF_MAP_*_ELEM` attr: map_fd, key, value, flags (32 bytes, UAPI order).
#[repr(C)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Map element failure: stage + errno, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapOpsError {
    LookupFailed { stage: String, errno: i32 },
    UpdateFailed { stage: String, errno: i32 },
}

impl std::fmt::Display for MapOpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LookupFailed { stage, errno } => {
                write!(f, "map lookup failed at {stage}: errno {errno}")
            }
            Self::UpdateFailed { stage, errno } => {
                write!(f, "map update failed at {stage}: errno {errno}")
            }
        }
    }
}

impl std::error::Error for MapOpsError {}

/// Update one u64 element (`BPF_ANY`).
pub fn map_update(map: &OwnedFd, key: u32, value: u64, stage: &str) -> Result<(), MapOpsError> {
    let key = key as u64;
    let mut value = value;
    let mut attr = ElemAttr {
        map_fd: map.as_raw_fd() as u32,
        _pad: 0,
        key: (&raw const key) as u64,
        value: (&raw mut value) as u64,
        flags: 0,
    };
    // SAFETY: attr + key/value pointees outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_MAP_UPDATE_ELEM,
            (&raw mut attr).cast::<c_void>(),
            size_of::<ElemAttr>() as u32,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(MapOpsError::UpdateFailed {
            stage: stage.to_owned(),
            errno: last_errno(),
        })
    }
}

/// Look up one u64 element.
pub fn map_lookup(map: &OwnedFd, key: u32, stage: &str) -> Result<u64, MapOpsError> {
    let key = key as u64;
    let mut value = 0u64;
    let mut attr = ElemAttr {
        map_fd: map.as_raw_fd() as u32,
        _pad: 0,
        key: (&raw const key) as u64,
        value: (&raw mut value) as u64,
        flags: 0,
    };
    // SAFETY: attr + key/value pointees outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            (&raw mut attr).cast::<c_void>(),
            size_of::<ElemAttr>() as u32,
        )
    };
    if ret == 0 {
        Ok(value)
    } else {
        Err(MapOpsError::LookupFailed {
            stage: stage.to_owned(),
            errno: last_errno(),
        })
    }
}

/// Online CPU count (≥1; `max(1)` fallback documented).
pub fn online_cpus() -> u32 {
    // SAFETY: sysconf takes no pointers; an error return folds into the max(1) fallback.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n < 1 { 1 } else { n as u32 }
}

/// Upper bound for a sane possible-CPU count parsed from sysfs.
///
/// Real `CONFIG_NR_CPUS` tops out at 8192; anything above this from a
/// text file is corruption, and sizing a `Vec<u64>` from it could OOM.
/// Such input is rejected (`None`) so the caller falls back to the
/// `sysconf` count, which is kernel-measured rather than parsed.
const MAX_SANE_CPUS: u32 = 65_536;

/// Parse a Linux CPU list (e.g. `"0-3,8-11\n"`) into a CPU count.
///
/// Fail-closed: any malformed, overflowing, oversized, or absurd input
/// yields `None` (the caller falls back to a safe over-estimate). Never
/// panics. Overlaps can only over-count, which is the safe direction
/// for buffer sizing.
fn possible_cpus_from_str(text: &str) -> Option<u32> {
    if text.len() > 64 * 1024 {
        return None;
    }
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut total: u32 = 0;
    for item in text.split(',') {
        let item = item.trim();
        let (lo, hi) = match item.split_once('-') {
            None => {
                let cpu: u32 = item.parse().ok()?;
                (cpu, cpu)
            }
            Some((lo, hi)) => {
                if hi.contains('-') {
                    return None;
                }
                let lo: u32 = lo.trim().parse().ok()?;
                let hi: u32 = hi.trim().parse().ok()?;
                if lo > hi {
                    return None;
                }
                (lo, hi)
            }
        };
        total = total.checked_add((hi - lo).checked_add(1)?)?;
        if total > MAX_SANE_CPUS {
            return None;
        }
    }
    if total == 0 { None } else { Some(total) }
}

/// `sysconf` fallback for the possible-CPU count: `max(CONF, online)`.
///
/// Used only when `/sys/devices/system/cpu/possible` is unreadable or
/// unparseable. Takes the maximum of the available signals so the buffer
/// errs toward larger (safe direction), never smaller. Always ≥1 since
/// `online_cpus()` is.
fn fallback_possible_cpus() -> u32 {
    // SAFETY: sysconf takes no pointers; an error return folds into the max(1) fallback.
    let conf = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    let conf = if conf < 1 { 1 } else { conf as u32 };
    conf.max(online_cpus())
}

/// Possible CPU count for percpu-map buffer sizing (≥1).
///
/// The kernel writes `num_possible_cpus()` lanes on percpu map lookup,
/// which exceeds the online count whenever any CPU is offline — sizing
/// from `online_cpus()` lets the kernel overwrite adjacent heap. This
/// reads the possible set from `/sys/devices/system/cpu/possible` (the
/// same source libbpf's `libbpf_num_possible_cpus` uses) rather than
/// `_SC_NPROCESSORS_CONF`, so the count matches the kernel's lane count
/// by construction instead of by POSIX-semantics assumption, and so the
/// parser stays a pure, deterministically unit-testable function.
/// The parsed value is clamped to `max(parsed, online)`: a
/// parseable-but-stale sysfs file must never shrink the buffer below a
/// trusted signal. Unreadable/unparseable input falls back to
/// `fallback_possible_cpus` (safe/larger direction).
pub fn possible_cpus() -> u32 {
    if let Ok(text) = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        && let Some(n) = possible_cpus_from_str(&text)
    {
        return n.max(online_cpus());
    }
    fallback_possible_cpus()
}

/// Look up one percpu element and sum all CPU lanes (saturating).
///
/// Buffer is sized by [`possible_cpus`], not [`online_cpus`]: the kernel
/// writes possible-CPUs worth of lanes on percpu lookup.
pub fn map_lookup_percpu_sum(map: &OwnedFd, key: u32, stage: &str) -> Result<u64, MapOpsError> {
    let key = key as u64;
    let mut values = vec![0u64; possible_cpus() as usize];
    let mut attr = ElemAttr {
        map_fd: map.as_raw_fd() as u32,
        _pad: 0,
        key: (&raw const key) as u64,
        value: values.as_mut_ptr() as u64,
        flags: 0,
    };
    // SAFETY: attr + key/value pointees outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            (&raw mut attr).cast::<c_void>(),
            size_of::<ElemAttr>() as u32,
        )
    };
    if ret == 0 {
        Ok(values.iter().fold(0u64, |a, v| a.saturating_add(*v)))
    } else {
        Err(MapOpsError::LookupFailed {
            stage: stage.to_owned(),
            errno: last_errno(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd::OwnedFd;

    /// Never a real fd: syscalls fail EBADF before use; close(-1) is a
    /// harmless no-op on drop.
    fn bad_fd() -> OwnedFd {
        // SAFETY: never dereferenced; the bpf() call fails first.
        unsafe { OwnedFd::from_raw_fd(-1) }
    }

    #[test]
    fn bad_fd_update_reports_stage_and_errno() {
        let fd = bad_fd();
        let err = map_update(&fd, 0, 0, "unit/probe").unwrap_err();
        assert!(
            matches!(err, MapOpsError::UpdateFailed { ref stage, errno } if stage == "unit/probe" && errno == libc::EBADF),
            "got {err}"
        );
    }

    #[test]
    fn bad_fd_lookup_reports_stage_and_errno() {
        let fd = bad_fd();
        let err = map_lookup(&fd, 0, "unit/probe").unwrap_err();
        assert!(
            matches!(err, MapOpsError::LookupFailed { ref stage, errno } if stage == "unit/probe" && errno == libc::EBADF),
            "got {err}"
        );
    }

    #[test]
    fn online_cpus_is_sane() {
        assert!(online_cpus() >= 1);
    }

    #[test]
    fn possible_cpu_list_counts_lanes() {
        for (text, want) in [
            ("0\n", 1),
            ("0-11\n", 12),
            ("0-3,8-11", 8),
            ("0,2", 2),
            ("  0-1 , 4  \n", 3),
            ("7-7", 1),
        ] {
            assert_eq!(possible_cpus_from_str(text), Some(want), "input {text:?}");
        }
    }

    #[test]
    fn possible_cpu_list_rejects_hostile_input() {
        for text in [
            "",
            "   \n",
            "garbage",
            "0,,1",
            ",0",
            "0,",
            "-1",
            "0-",
            "-0",
            "3-0",
            "1-2-3",
            "0x10",
            "0-99999999999",
            "0-100000",
        ] {
            assert_eq!(possible_cpus_from_str(text), None, "input {text:?}");
        }
        assert_eq!(possible_cpus_from_str(&"0,".repeat(40_000)), None);
    }

    #[test]
    fn possible_ge_online_invariant() {
        let possible = possible_cpus();
        assert!(possible >= 1);
        assert!(
            possible >= online_cpus(),
            "possible {possible} < online {}",
            online_cpus()
        );
    }

    #[test]
    fn possible_fallback_is_safe_direction() {
        let fallback = fallback_possible_cpus();
        assert!(fallback >= 1);
        assert!(
            fallback >= online_cpus(),
            "fallback {fallback} < online {}",
            online_cpus()
        );
    }
}
