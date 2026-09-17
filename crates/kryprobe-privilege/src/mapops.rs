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

/// Online CPU count for percpu lookups (≥1; `max(1)` fallback documented).
pub fn online_cpus() -> u32 {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n < 1 { 1 } else { n as u32 }
}

/// Look up one percpu element and sum all CPU lanes (saturating).
pub fn map_lookup_percpu_sum(map: &OwnedFd, key: u32, stage: &str) -> Result<u64, MapOpsError> {
    let key = key as u64;
    let mut values = vec![0u64; online_cpus() as usize];
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
}
