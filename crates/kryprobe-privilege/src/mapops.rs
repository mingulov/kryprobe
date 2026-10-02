// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw map element ops: u64 lookup/update + percpu sums (T7c2).

use crate::fd::OwnedFd;
#[cfg(not(test))]
use crate::probe::bpf_sys::bpf;
use crate::probe::bpf_sys::last_errno;
use core::ffi::c_void;
#[cfg(test)]
use topology_tests::bpf;

#[cfg(test)]
pub(crate) mod topology_tests;

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
    /// Element lookup failed.
    LookupFailed {
        /// Lookup stage that failed.
        stage: String,
        /// Kernel or local validation errno.
        errno: i32,
    },
    /// Element update failed.
    UpdateFailed {
        /// Update stage that failed.
        stage: String,
        /// Kernel errno.
        errno: i32,
    },
    /// Full read-back verification failed: the map does not contain
    /// the bytes just written (T06 LCFG gate — unwritten/zeroed configs
    /// fail closed here instead of arming a disarmed sensor). The
    /// detail names the exact refusal (length/magic/version/flags/
    /// reserved); the read-back buffer always holds the map's full
    /// value size (a short buffer would be a kernel overwrite — the
    /// `u64` [`map_lookup`] helper is 8-byte values only).
    ConfigRejected {
        /// Verification stage that failed.
        stage: String,
        /// Exact refusal detail.
        detail: String,
    },
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
            Self::ConfigRejected { stage, detail } => {
                write!(f, "map config rejected at {stage}: {detail}")
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
///
/// The destination is exactly 8 bytes: callers must only use this for
/// maps with `value_size == 8` (wider values need [`map_lookup_bytes`]
/// with the map's exact value size — the kernel writes the full value
/// size and a short buffer is a stack overwrite).
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

/// Resource bound for CPU ids and lane counts accepted from sysfs.
/// Larger topologies refuse capture instead of guessing a smaller count.
const MAX_SANE_CPUS: u32 = 65_536;
const MAX_CPU_LIST_BYTES: usize = 64 * 1024;

/// Parse a Linux CPU list (e.g. `"0-3,8-11\n"`) into a CPU count.
///
/// Fail-closed: any malformed, overflowing, oversized, or absurd input
/// yields `None`. Ranges must be ordered and non-overlapping, like the
/// kernel's cpulist output. Never substitute a smaller topology signal.
fn possible_cpus_from_str(text: &str) -> Option<u32> {
    if text.len() > MAX_CPU_LIST_BYTES {
        return None;
    }
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut total: u32 = 0;
    let mut previous = None;
    for item in text.split(',') {
        let item = item.trim();
        if !item
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b.is_ascii_whitespace())
        {
            return None;
        }
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
        if hi >= MAX_SANE_CPUS || previous.is_some_and(|last| lo <= last) {
            return None;
        }
        previous = Some(hi);
        total = total.checked_add((hi - lo).checked_add(1)?)?;
        if total > MAX_SANE_CPUS {
            return None;
        }
    }
    if total == 0 { None } else { Some(total) }
}

/// Validated possible CPU count for percpu-map buffer sizing (≥1).
///
/// The kernel writes `num_possible_cpus()` lanes on percpu map lookup,
/// which exceeds the online count whenever any CPU is offline — sizing
/// from `online_cpus()` lets the kernel overwrite adjacent heap. This
/// reads the possible set from `/sys/devices/system/cpu/possible` (the
/// same source libbpf's `libbpf_num_possible_cpus` uses) rather than
/// `_SC_NPROCESSORS_CONF`, so the count matches the kernel's lane count
/// by construction. Missing, malformed, or contradictory topology
/// returns a typed refusal; configured/online/affinity counts cannot
/// establish a safe fallback bound. Online count only detects a
/// contradiction, never supplies a replacement count.
///
/// Cached process-wide, including refusals: Linux fixes cpu_possible_mask
/// during boot; CPU online/offline changes do not change its lanes.
/// See <https://docs.kernel.org/core-api/cpu_hotplug.html#cpu-maps>.
/// A lookup supplies no userspace buffer length: decoder length checks
/// cannot detect or prevent a kernel overwrite from an undersized buffer.
pub fn possible_cpus() -> Result<u32, MapOpsError> {
    #[cfg(test)]
    if let Some((text, online)) = topology_tests::topology() {
        return possible_cpus_from_topology(text, online);
    }
    static CACHED: std::sync::OnceLock<Result<u32, MapOpsError>> = std::sync::OnceLock::new();
    CACHED.get_or_init(possible_cpus_uncached).clone()
}

/// Uncached, bounded sysfs read plus an online-count consistency check.
fn possible_cpus_uncached() -> Result<u32, MapOpsError> {
    use std::io::Read;
    let text = std::fs::File::open("/sys/devices/system/cpu/possible")
        .and_then(|file| {
            let mut text = String::new();
            file.take((MAX_CPU_LIST_BYTES + 1) as u64)
                .read_to_string(&mut text)?;
            Ok(text)
        })
        .ok();
    possible_cpus_from_topology(text.as_deref(), online_cpus())
}

fn possible_cpus_from_topology(
    possible_text: Option<&str>,
    online: u32,
) -> Result<u32, MapOpsError> {
    let refusal = |errno| MapOpsError::LookupFailed {
        stage: "percpu/possible-cpus".to_owned(),
        errno,
    };
    let text = possible_text.ok_or_else(|| refusal(libc::ENODATA))?;
    possible_cpus_from_str(text)
        .filter(|count| *count >= online)
        .ok_or_else(|| refusal(libc::EINVAL))
}

/// Trusted lane count and kernel-aligned byte length, checked before allocation.
pub(crate) fn percpu_buffer_len(value_size: usize) -> Result<(usize, usize), MapOpsError> {
    let ncpu = possible_cpus()? as usize;
    let value_len = value_size
        .checked_add(7)
        .map(|size| size & !7)
        .and_then(|stride| stride.checked_mul(ncpu))
        .filter(|len| *len > 0)
        .ok_or_else(|| MapOpsError::LookupFailed {
            stage: "percpu/value-size".to_owned(),
            errno: libc::EOVERFLOW,
        })?;
    Ok((ncpu, value_len))
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
/// # Safety
///
/// The caller must pass the map's exact value size (percpu maps:
/// `round_up(value_size, 8) * possible_cpus()?` — the kernel writes all
/// possible lanes, including offline CPUs). A topology refusal must
/// propagate before lookup. An undersized buffer is a kernel heap overwrite (L-SEC-02);
/// every call site documents its size provenance. Same trust model as
/// [`map_lookup_percpu_sum`].
pub unsafe fn map_lookup_bytes(
    map: &OwnedFd,
    key: &[u8],
    value_len: usize,
    stage: &str,
) -> Result<Vec<u8>, MapOpsError> {
    let mut value = vec![0u8; value_len.max(1)];
    value.truncate(value_len);
    // `truncate` to the requested length keeps capacity; an empty
    // request still hands the kernel a live (1-byte) buffer — it only
    // avoids faulting on misuse (all callers pass exact sizes; the
    // lookup takes no userspace value length, so no `E2BIG` exists
    // on this path — the kernel writes the full value size).
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
/// [`MapOpsError::LookupFailed`].
///
/// # Safety
///
/// `key_len` must be the map's exact key size (same L-SEC-02 rationale
/// as [`map_lookup_bytes`]: the kernel writes `key_len` bytes).
pub unsafe fn map_get_next_key(
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
    let (ncpu, _) = percpu_buffer_len(size_of::<u64>())?;
    let key = key as u64;
    let mut values = vec![0u64; ncpu];
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
        // SAFETY: bad fd fails EBADF before any kernel write; the
        // length is never trusted on the error path (M-T5: the sizing
        // contract is probed by compilation — every production caller
        // documents exact-size provenance — plus this fail-safe read).
        let err = unsafe { map_lookup_bytes(&fd, &[0u8; 4], 8, "unit/lookup") }.unwrap_err();
        assert!(
            matches!(err, MapOpsError::LookupFailed { ref stage, errno } if stage == "unit/lookup" && errno == libc::EBADF),
            "got {err}"
        );
        // SAFETY: bad fd fails EBADF before any kernel write (same
        // M-T5 rationale as the lookup above).
        let err = unsafe { map_get_next_key(&fd, None, 4, "unit/next") }.unwrap_err();
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
    fn possible_cpus_cached_matches_live_read() {
        // M1: the cached value is exactly the live read (stable
        // across calls — one sysfs read per process, not per tick).
        let live = possible_cpus_uncached();
        assert!(live.as_ref().is_ok_and(|count| *count >= 1));
        assert_eq!(possible_cpus(), live);
        assert_eq!(possible_cpus(), live);
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
            "+1",
            "0,0",
            "0-3,2-4",
            "4,0-3",
            "65536",
        ] {
            assert_eq!(possible_cpus_from_str(text), None, "input {text:?}");
        }
        assert_eq!(possible_cpus_from_str(&"0,".repeat(40_000)), None);
    }

    #[test]
    fn possible_ge_online_invariant() {
        let possible = possible_cpus().unwrap();
        assert!(possible >= 1);
        assert!(
            possible >= online_cpus(),
            "possible {possible} < online {}",
            online_cpus()
        );
    }

    #[test]
    fn unavailable_or_invalid_possible_topology_refuses() {
        for (text, errno) in [
            (None, libc::ENODATA),
            (Some("garbage"), libc::EINVAL),
            (Some(""), libc::EINVAL),
            (Some("0-100000"), libc::EINVAL),
        ] {
            assert_eq!(
                possible_cpus_from_topology(text, 4),
                Err(MapOpsError::LookupFailed {
                    stage: "percpu/possible-cpus".to_owned(),
                    errno,
                }),
            );
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
            possible_cpus_from_topology(Some("0-7\n"), 4),
            Ok(8),
            "offline CPUs must not shrink the percpu buffer"
        );
        assert_eq!(
            possible_cpus_from_topology(Some("0-3,8-11"), 4),
            Ok(8),
            "disjoint possible set still sizes by possible"
        );
    }

    #[test]
    fn contradictory_possible_topology_refuses() {
        for (text, online) in [("0-1\n", 4), ("0\n", 16)] {
            assert!(possible_cpus_from_topology(Some(text), online).is_err());
        }
    }

    #[test]
    fn seam_matches_real_path_on_host_topology() {
        // The seam is a refactor, not a behavior change: applied to the
        // real host reads it must equal `possible_cpus()`.
        let text = std::fs::read_to_string("/sys/devices/system/cpu/possible").ok();
        assert_eq!(
            possible_cpus_from_topology(text.as_deref(), online_cpus()),
            possible_cpus()
        );
    }
}
