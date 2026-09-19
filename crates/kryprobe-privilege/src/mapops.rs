// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw map element ops: u64 lookup/update + percpu sums (T7c2).

use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{bpf, last_errno};
use std::os::raw::c_void;

const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// `BPF_MAP_GET_NEXT_KEY` command id (UAPI `linux/bpf.h` `bpf_cmd`).
const BPF_MAP_GET_NEXT_KEY: u32 = 4;

/// `BPF_MAP_*_ELEM` attr: map_fd, key, value, flags (32 bytes, UAPI order).
#[repr(C)]
struct ElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// `BPF_MAP_GET_NEXT_KEY` attr: map_fd, key, next_key (24 bytes, UAPI
/// order). A null `key` starts the iteration; `ENOENT` ends it.
#[repr(C)]
struct NextKeyAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    next_key: u64,
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

/// `_SC_NPROCESSORS_CONF` (≥1; `max(1)` fallback documented).
fn conf_cpus() -> u32 {
    // SAFETY: sysconf takes no pointers; an error return folds into the max(1) fallback.
    let conf = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    if conf < 1 { 1 } else { conf as u32 }
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
/// `max(conf, online)` (safe/larger direction).
pub fn possible_cpus() -> u32 {
    let text = std::fs::read_to_string("/sys/devices/system/cpu/possible").ok();
    possible_cpus_from_topology(text.as_deref(), conf_cpus(), online_cpus())
}

/// [`possible_cpus`] over an injected CPU topology (test seam).
///
/// `possible_text` is the raw `/sys/devices/system/cpu/possible` content
/// (`None` = unreadable file); `conf`/`online` are the two `sysconf`
/// signals. The offline-CPU path (possible > online) is unproducible on
/// an all-online host and offlining live CPUs is out of scope, so tests
/// drive this seam with a synthetic possible≠online mismatch instead.
/// [`possible_cpus`] is this function applied to the real host reads —
/// no behavior change on the real path.
fn possible_cpus_from_topology(possible_text: Option<&str>, conf: u32, online: u32) -> u32 {
    if let Some(text) = possible_text
        && let Some(parsed) = possible_cpus_from_str(text)
    {
        return parsed.max(online);
    }
    conf.max(online)
}

/// Update one element with raw key/value bytes (`BPF_ANY`, K1 Task 2:
/// kcrypto `KCFG` init + dump-test setup).
pub fn map_update_bytes(
    map: &OwnedFd,
    key: &[u8],
    value: &[u8],
    stage: &str,
) -> Result<(), MapOpsError> {
    let mut attr = ElemAttr {
        map_fd: map.as_raw_fd() as u32,
        _pad: 0,
        key: key.as_ptr() as u64,
        value: value.as_ptr() as u64,
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

/// Look up one element with raw key bytes into exactly `value_len`
/// bytes (K1 Task 2: kcrypto map dumps).
///
/// The caller must pass the map's exact value size (percpu maps:
/// `value_size * possible_cpus()` — the kernel writes all possible
/// lanes; an undersized buffer is a kernel heap overwrite, same trust
/// model as [`map_lookup_percpu_sum`]).
pub fn map_lookup_bytes(
    map: &OwnedFd,
    key: &[u8],
    value_len: usize,
    stage: &str,
) -> Result<Vec<u8>, MapOpsError> {
    let mut value = vec![0u8; value_len.max(1)];
    value.truncate(value_len);
    // `truncate` to the requested length keeps capacity; an empty
    // request still hands the kernel a live (1-byte) buffer — the
    // lookup then fails honestly (`E2BIG`/length) instead of faulting
    // on a dangling pointer.
    let mut attr = ElemAttr {
        map_fd: map.as_raw_fd() as u32,
        _pad: 0,
        key: key.as_ptr() as u64,
        value: value.as_mut_ptr() as u64,
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
        value.resize(value_len, 0);
        Ok(value)
    } else {
        Err(MapOpsError::LookupFailed {
            stage: stage.to_owned(),
            errno: last_errno(),
        })
    }
}

/// Iterate keys: `None` starts at the first key, `Some(prev)` steps.
/// `Ok(None)` is end-of-iteration (`ENOENT`); any other errno is
/// [`MapOpsError::LookupFailed`]. `key_len` must be the map's exact key
/// size (K1 Task 2: `KAGG`/`KIDN` dumps).
pub fn map_get_next_key(
    map: &OwnedFd,
    key: Option<&[u8]>,
    key_len: usize,
    stage: &str,
) -> Result<Option<Vec<u8>>, MapOpsError> {
    let mut next = vec![0u8; key_len.max(1)];
    next.truncate(key_len);
    let mut attr = NextKeyAttr {
        map_fd: map.as_raw_fd() as u32,
        _pad: 0,
        key: key.map(|k| k.as_ptr() as u64).unwrap_or(0),
        next_key: next.as_mut_ptr() as u64,
    };
    // SAFETY: attr + key/next pointees outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_MAP_GET_NEXT_KEY,
            (&raw mut attr).cast::<c_void>(),
            size_of::<NextKeyAttr>() as u32,
        )
    };
    if ret == 0 {
        next.resize(key_len, 0);
        Ok(Some(next))
    } else {
        let errno = last_errno();
        if errno == libc::ENOENT {
            Ok(None)
        } else {
            Err(MapOpsError::LookupFailed {
                stage: stage.to_owned(),
                errno,
            })
        }
    }
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
    fn bad_fd_byte_ops_report_stage_and_errno() {
        // The K1 Task-2 byte primitives fail honestly (EBADF before any
        // length check) on a bad fd; GET_NEXT_KEY maps only ENOENT to
        // end-of-iteration, never other errnos.
        let fd = bad_fd();
        let err = map_update_bytes(&fd, &[0u8; 4], &[0u8; 8], "unit/update").unwrap_err();
        assert!(
            matches!(err, MapOpsError::UpdateFailed { ref stage, errno } if stage == "unit/update" && errno == libc::EBADF),
            "got {err}"
        );
        let err = map_lookup_bytes(&fd, &[0u8; 4], 8, "unit/lookup").unwrap_err();
        assert!(
            matches!(err, MapOpsError::LookupFailed { ref stage, errno } if stage == "unit/lookup" && errno == libc::EBADF),
            "got {err}"
        );
        let err = map_get_next_key(&fd, None, 4, "unit/next").unwrap_err();
        assert!(
            matches!(err, MapOpsError::LookupFailed { ref stage, errno } if stage == "unit/next" && errno == libc::EBADF),
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
        // Unreadable/unparseable possible set falls back to max(conf,
        // online) — the safe (larger) direction on every input shape.
        for (possible_text, conf, online) in [
            (None, 8, 4),
            (None, 2, 4),
            (Some("garbage"), 8, 4),
            (Some(""), 8, 4),
            (Some("0-100000"), 8, 4),
        ] {
            let fallback = possible_cpus_from_topology(possible_text, conf, online);
            assert_eq!(fallback, conf.max(online), "input {possible_text:?}");
            assert!(fallback >= 1);
        }
    }

    #[test]
    fn offline_cpu_mismatch_sizes_by_possible() {
        // Synthetic possible≠online mismatch: 8 possible lanes with only
        // 4 online (half the CPUs offline) must still size 8 lanes — the
        // kernel writes all possible lanes on percpu lookup regardless
        // of which are online. Unproducible on an all-online host, so it
        // runs through the injected-topology seam.
        assert_eq!(
            possible_cpus_from_topology(Some("0-7\n"), 8, 4),
            8,
            "offline CPUs must not shrink the percpu buffer"
        );
        assert_eq!(
            possible_cpus_from_topology(Some("0-3,8-11"), 12, 4),
            8,
            "disjoint possible set still sizes by possible"
        );
    }

    #[test]
    fn stale_possible_never_shrinks_below_online() {
        // A parseable-but-stale sysfs file (fewer lanes than are
        // online) clamps up to the trusted online signal.
        assert_eq!(possible_cpus_from_topology(Some("0-1\n"), 4, 4), 4);
        assert_eq!(possible_cpus_from_topology(Some("0\n"), 16, 16), 16);
    }

    #[test]
    fn seam_matches_real_path_on_host_topology() {
        // The seam is a refactor, not a behavior change: applied to the
        // real host reads it must equal `possible_cpus()`.
        let text = std::fs::read_to_string("/sys/devices/system/cpu/possible").ok();
        assert_eq!(
            possible_cpus_from_topology(text.as_deref(), conf_cpus(), online_cpus()),
            possible_cpus()
        );
    }
}
