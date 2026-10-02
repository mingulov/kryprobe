// SPDX-License-Identifier: GPL-3.0-or-later
//! Safe topology fault injection: real callers, invalid map fds, no kernel writes.

use super::*;
use std::cell::Cell;

type Topology = (Option<&'static str>, u32);

thread_local! {
    static TOPOLOGY: Cell<Option<Topology>> = const { Cell::new(None) };
    static BPF_CALLS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn topology() -> Option<Topology> {
    TOPOLOGY.get()
}

// Observe the real syscall boundary; never emulate a successful lookup.
pub(super) unsafe fn bpf(cmd: u32, attr: *mut c_void, size: u32) -> core::ffi::c_long {
    BPF_CALLS.set(BPF_CALLS.get() + 1);
    unsafe { crate::probe::bpf_sys::bpf(cmd, attr, size) }
}

pub(crate) fn with_topology<T>(text: Option<&'static str>, run: impl FnOnce() -> T) -> (T, usize) {
    struct Restore(Option<Topology>, usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            TOPOLOGY.set(self.0);
            BPF_CALLS.set(self.1);
        }
    }
    let _restore = Restore(TOPOLOGY.replace(Some((text, 4))), BPF_CALLS.replace(0));
    let result = run();
    (result, BPF_CALLS.get())
}

pub(crate) fn bad_fd() -> OwnedFd {
    // SAFETY: -1 never owns a resource; every syscall fails before copying.
    unsafe { OwnedFd::from_raw_fd(-1) }
}

pub(crate) fn sensor() -> crate::btf_resolve::ConfiguredKcrypto {
    use crate::bpfloader::{KcryptoMaps, LoadedKcrypto};
    crate::btf_resolve::ConfiguredKcrypto {
        loaded: LoadedKcrypto {
            maps: KcryptoMaps {
                config: bad_fd(),
                agg: bad_fd(),
                total: bad_fd(),
                ident: bad_fd(),
                ring: bad_fd(),
                who: bad_fd(),
                stack: bad_fd(),
                err: bad_fd(),
                params: bad_fd(),
                drops: bad_fd(),
            },
            progs: Vec::new(),
        },
        links: Vec::new(),
    }
}

pub(crate) fn spine() -> crate::bpfloader::LoadedSpine {
    use crate::bpfloader::{LoadedSpine, SpineMaps, SpineProgs};
    LoadedSpine {
        maps: SpineMaps {
            config: bad_fd(),
            start: bad_fd(),
            count: bad_fd(),
            events: bad_fd(),
            loss: bad_fd(),
        },
        progs: SpineProgs {
            entry: bad_fd(),
            ret: bad_fd(),
        },
    }
}

pub(crate) fn assert_refused<T: std::fmt::Debug>(
    result: Result<T, MapOpsError>,
    calls: usize,
    errno: i32,
) {
    assert_eq!(
        result.unwrap_err(),
        MapOpsError::LookupFailed {
            stage: "percpu/possible-cpus".to_owned(),
            errno,
        }
    );
    assert_eq!(
        calls, 0,
        "untrusted topology must refuse before any BPF call"
    );
}

#[test]
fn unavailable_topology_refuses_scalar_lookup_before_bpf() {
    let (result, calls) = with_topology(None, || map_lookup_percpu_sum(&bad_fd(), 0, "unit/count"));
    assert_refused(result, calls, libc::ENODATA);
}

#[test]
fn malformed_topology_refuses_scalar_lookup_before_bpf() {
    for text in [
        "", "garbage", "0-100000", "0-1", "0,0", "0-3,2-4", "+1", "65536",
    ] {
        let (result, calls) = with_topology(Some(text), || {
            map_lookup_percpu_sum(&bad_fd(), 0, "unit/count")
        });
        assert_refused(result, calls, libc::EINVAL);
    }
}

#[test]
fn offline_possible_lanes_are_sized_and_folded() {
    let (result, calls) = with_topology(Some("0-3,8-11"), || {
        assert_eq!(
            percpu_buffer_len(9),
            Ok((8, 128)),
            "each lane rounds up to eight bytes"
        );
        assert_eq!(percpu_buffer_len(80), Ok((8, 640)));
        assert_eq!(percpu_buffer_len(120), Ok((8, 960)));
        let (ncpu, value_len) = percpu_buffer_len(8).unwrap();
        assert_eq!((ncpu, value_len), (8, 64));
        // The final four lanes are offline. Their saved counts still contribute.
        let raw: Vec<u8> = [1u64, 2, 3, 4, 10, 20, 30, 40]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        crate::kcrypto_backend::fold_drop_lanes(&raw, ncpu)
    });
    assert_eq!(result, Some(110));
    assert_eq!(calls, 0);
}

#[test]
fn percpu_allocation_size_refuses_overflow() {
    for value_size in [0, usize::MAX, usize::MAX / 8 + 1] {
        let (result, calls) = with_topology(Some("0-7"), || percpu_buffer_len(value_size));
        assert_eq!(
            result.unwrap_err(),
            MapOpsError::LookupFailed {
                stage: "percpu/value-size".to_owned(),
                errno: libc::EOVERFLOW,
            }
        );
        assert_eq!(calls, 0);
    }
}

#[test]
fn valid_topology_reaches_real_lookup_error() {
    let (result, calls) = with_topology(Some("0-7"), || {
        map_lookup_percpu_sum(&bad_fd(), 0, "unit/count")
    });
    assert_eq!(
        result,
        Err(MapOpsError::LookupFailed {
            stage: "unit/count".to_owned(),
            errno: libc::EBADF,
        })
    );
    assert_eq!(calls, 1, "valid topology must reach the real syscall");
}

#[test]
fn unavailable_topology_refuses_snapshot_callers_before_bpf() {
    let sensor = sensor();
    let (result, calls) = with_topology(None, || crate::kcrypto_snapshot::snapshot_rows(&sensor));
    assert_refused(result, calls, libc::ENODATA);
}

#[test]
fn unavailable_topology_refuses_who_snapshot_before_bpf() {
    use crate::kcrypto_backend::{SnapshotError, snapshot_who};
    let sensor = sensor();
    let (result, calls) = with_topology(None, || snapshot_who(&sensor));
    assert_refused(
        result.map_err(|SnapshotError::Map(err)| err),
        calls,
        libc::ENODATA,
    );
}

#[test]
fn unavailable_topology_refuses_drop_snapshot_before_bpf() {
    use crate::kcrypto_backend::{SnapshotError, snapshot_drops};
    let sensor = sensor();
    let (result, calls) = with_topology(None, || snapshot_drops(&sensor));
    assert_refused(
        result.map_err(|SnapshotError::Map(err)| err),
        calls,
        libc::ENODATA,
    );
}
