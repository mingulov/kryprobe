// SPDX-License-Identifier: GPL-3.0-or-later
//! Root-side token minting over a private bpffs mount (T8, T17 split flow).
//!
//! Follows the kernel selftests/bpf `token` flow: `fsopen("bpf")`,
//! four `delegate_*` strings, `FSCONFIG_CMD_CREATE`, `fsmount`,
//! `openat` of the mount root, then `BPF_TOKEN_CREATE` on that
//! directory fd. Syscall numbers come from libc; the `linux/mount.h`
//! command constants are spelled out (verified).
//!
//! T17: the kernel refuses `BPF_TOKEN_CREATE` from the initial user
//! namespace, so the fsopen/mint halves run in a child userns (see
//! [`super::userns`]); this module keeps the delegate strings plus the
//! parent-side configure-and-mount half ([`instantiate_bpffs`]).

use super::{TokenAxes, TokenError, TokenHandle};
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{bpf, fd_or_errno, last_errno};
use std::os::fd::RawFd;
use std::os::raw::{c_long, c_void};

/// `linux/mount.h`: set a string mount parameter.
const FSCONFIG_SET_STRING: c_long = 1;
/// `linux/mount.h`: create (or reuse) the superblock.
const FSCONFIG_CMD_CREATE: c_long = 6;
/// `linux/mount.h`: close-on-exec mount fd.
const FSMOUNT_CLOEXEC: c_long = 1;
/// `linux/mount.h`: close-on-exec fs-context fd (the sole `fsopen`
/// flag; unknown flags are `EINVAL`). Present since `fsopen` itself
/// (5.1), so safe on every kernel this product supports (6.12+).
const FSOPEN_CLOEXEC: c_long = 1;

/// Smoke-lane delegation: trailing atoms use the kernel's lowercase
/// enum-name suffixes (`map_create`, `array`, `kprobe`, `trace_uprobe_multi`).
/// `percpu_array`/`ringbuf` follow the same rule (T12 root run confirms).
const DELEGATES: [(&[u8], &[u8]); 4] = [
    (b"delegate_cmds\0", b"map_create:prog_load\0"),
    (b"delegate_maps\0", b"array:percpu_array:ringbuf\0"),
    (b"delegate_progs\0", b"kprobe\0"),
    (b"delegate_attachs\0", b"trace_uprobe_multi\0"),
];

fn syscall_fd(stage: &'static str, ret: c_long) -> Result<OwnedFd, TokenError> {
    fd_or_errno(ret).map_err(|errno| TokenError::Denied { stage, errno })
}

/// Opens the `bpf` fs context for the split flow. Child-safe
/// (syscall + fd check only, no allocation): called from the
/// post-fork mint child, which must fsopen inside the new userns.
/// Lives here (not in `super::userns`) so the raw entry point stays
/// in the ADR-0002 allowlisted token mount flow.
pub(crate) fn fsopen_bpf() -> Result<OwnedFd, TokenError> {
    // SAFETY: fsopen("bpf", FSOPEN_CLOEXEC) takes no out-params.
    // CLOEXEC (spawn discipline): the sole caller is the post-fork
    // mint child, which never execs — the flag only hardens.
    syscall_fd("fsopen", unsafe {
        libc::syscall(libc::SYS_fsopen, c"bpf".as_ptr(), FSOPEN_CLOEXEC)
    })
}

/// Parent-side half of the split flow: configures the fs context
/// the mint child opened, creates and mounts the bpffs instance, and
/// returns its root dir fd for the child's `BPF_TOKEN_CREATE`.
///
/// The `fs` context MUST come from the mint userns (see
/// [`super::userns`]): `fsopen` pins superblock ownership to the
/// opener's namespace, and an init-ns context would EPERM the mint.
pub(crate) fn instantiate_bpffs(fs: &OwnedFd) -> Result<OwnedFd, TokenError> {
    for (key, value) in DELEGATES {
        // SAFETY: NUL-terminated key/value, copied in synchronously.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                c_long::from(fs.as_raw_fd()),
                FSCONFIG_SET_STRING,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        };
        if rc != 0 {
            return Err(TokenError::Denied {
                stage: "fsconfig",
                errno: last_errno(),
            });
        }
    }
    // SAFETY: CREATE takes no key/value pointers.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            c_long::from(fs.as_raw_fd()),
            FSCONFIG_CMD_CREATE,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(TokenError::Denied {
            stage: "fsconfig-create",
            errno: last_errno(),
        });
    }
    // SAFETY: fsmount takes fds/flags only.
    let mnt = syscall_fd("fsmount", unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            c_long::from(fs.as_raw_fd()),
            FSMOUNT_CLOEXEC,
            0,
        )
    })?;
    // `BPF_TOKEN_CREATE` wants a directory fd on the bpffs instance,
    // not the mount fd itself (which it rejects with EBADF).
    // SAFETY: "." is NUL-terminated; O_DIRECTORY pins a directory.
    syscall_fd("open-mount-root", unsafe {
        libc::openat(
            mnt.as_raw_fd(),
            c".".as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
        )
    } as c_long)
}

/// A minted smoke-lane token plus its pinned mint namespace: the
/// worker joins `ns` before loading (token USE is bound to the mint
/// ns). Both fds close with this value; `ns` must outlive the worker.
#[derive(Debug)]
pub struct MintedToken {
    handle: TokenHandle,
    ns: OwnedFd,
}

impl MintedToken {
    /// The verified token handle (axes-checked at mint time).
    pub fn handle(&self) -> &TokenHandle {
        &self.handle
    }

    /// Raw fd of the pinned mint userns (for the worker spawn).
    pub fn ns_fd(&self) -> RawFd {
        self.ns.as_raw_fd()
    }
}

/// Mints the smoke-lane token; verifies live axes before returning.
///
/// The `BPF_TOKEN_CREATE` syscall executes in a child user namespace
/// (see [`super::userns`]): the kernel refuses it from the initial
/// namespace with EOPNOTSUPP by design. The ordering pin below fails
/// closed if the mint ever runs in the caller's own namespace.
pub fn mint_smoke_token() -> Result<MintedToken, TokenError> {
    let output = super::userns::mint_token_via_userns()?;
    if output.obs.mint_userns == 0 || output.obs.mint_userns == output.obs.caller_userns {
        return Err(TokenError::Denied {
            stage: "userns-order",
            errno: libc::EPROTO,
        });
    }
    let handle = TokenHandle::verified(output.token, TokenAxes::smoke_expected())?;
    Ok(MintedToken {
        handle,
        ns: output.ns,
    })
}

/// `BPF_*_GET_*_ID` attr: `{start,next,open_flags,fd_token}` (16 bytes,
/// per `linux/bpf.h`'s anonymous `BPF_*_GET_*_ID` struct).
#[repr(C)]
struct IdScanAttr {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
    fd_by_id_token: i32,
}

const _: () = assert!(size_of::<IdScanAttr>() == 16);

const BPF_PROG_GET_NEXT_ID: u32 = 11;
const BPF_MAP_GET_NEXT_ID: u32 = 12;

/// Upper bound on ids collected per `GET_NEXT_ID` sweep (B6):
/// ordinary hosts hold dozens; a host churning out ever-larger ids
/// aborts with [`TokenError::ScanAborted`] instead of looping forever.
/// Fail-closed (never a silent truncation).
const MAX_IDS_PER_SCAN: usize = 65_536;

/// Live `(map_ids, prog_ids)` for the T8 leak assertion (sorted ascending).
///
/// Each sweep is bounded ([`MAX_IDS_PER_SCAN`]) and requires monotonic
/// ids: a bound hit or a non-monotonic step (id reuse under host churn)
/// aborts with [`TokenError::ScanAborted`], never a partial list that
/// would read as false-clean.
pub fn live_bpf_ids() -> Result<(Vec<u32>, Vec<u32>), TokenError> {
    fn scan(cmd: u32, stage: &'static str) -> Result<Vec<u32>, TokenError> {
        let mut ids = Vec::new();
        let mut start = 0u32;
        loop {
            // Root scans carry no token: the fd field must be 0 (a
            // -1 here is EINVAL: the kernel only accepts a nonzero fd
            // with `BPF_F_TOKEN_FD` in `open_flags`).
            let mut attr = IdScanAttr {
                start_id: start,
                next_id: 0,
                open_flags: 0,
                fd_by_id_token: 0,
            };
            // SAFETY: `attr` is a live stack struct; size matches its type.
            let rc = unsafe {
                bpf(
                    cmd,
                    (&raw mut attr).cast::<c_void>(),
                    size_of::<IdScanAttr>() as u32,
                )
            };
            if rc != 0 {
                let errno = last_errno();
                if errno == libc::ENOENT {
                    return Ok(ids);
                }
                return Err(TokenError::Denied { stage, errno });
            }
            if attr.next_id == 0 || attr.next_id <= start {
                return Err(TokenError::ScanAborted {
                    stage,
                    reason: "ids went non-monotonic under host churn",
                });
            }
            if ids.len() >= MAX_IDS_PER_SCAN {
                return Err(TokenError::ScanAborted {
                    stage,
                    reason: "id bound exceeded (see MAX_IDS_PER_SCAN)",
                });
            }
            start = attr.next_id;
            ids.push(start);
        }
    }
    Ok((
        scan(BPF_MAP_GET_NEXT_ID, "id-scan-map")?,
        scan(BPF_PROG_GET_NEXT_ID, "id-scan-prog")?,
    ))
}

/// Ids present in `after` but absent from `before` (B6 extras-only leak
/// comparison), in ascending order. Both slices are sorted ascending
/// (see [`live_bpf_ids`]).
///
/// Host REMOVALS (ambient ids torn down mid-roundtrip) are ordinary
/// churn, never leaks; host ADDITIONS still report. The smoke lane is
/// therefore serial: no concurrent BPF loads during the roundtrip (see
/// [`super::smoke`] and `docs/commands.md`).
pub(crate) fn extra_ids(before: &[u32], after: &[u32]) -> Vec<u32> {
    after
        .iter()
        .filter(|id| before.binary_search(id).is_err())
        .copied()
        .collect()
}

/// Settle interval between leak-scan polls (see [`settle_bpf_ids`]).
const SETTLE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);
/// Max settle polls before the leak comparison runs anyway (2s cap).
const SETTLE_POLLS: u32 = 100;

/// Re-scans live BPF ids until no extras remain vs `want_*` or the
/// settle window lapses; returns the final scan for the caller's
/// extras-only comparison (see [`extra_ids`]).
///
/// WHY: map ids linger briefly after the worker exits (the dying prog
/// struct holds the last map refs until RCU teardown — measured: 5
/// extra ids at exit, gone <50ms later), so an immediate rescan would
/// cry leak on a clean roundtrip. A REAL leak persists past the 2s
/// window and still fails the comparison. Host removals converge at
/// once (never leaks); host additions keep the window open and then
/// report. Parent-side only (sleeps).
pub fn settle_bpf_ids(
    want_maps: &[u32],
    want_progs: &[u32],
) -> Result<(Vec<u32>, Vec<u32>), TokenError> {
    let mut current = live_bpf_ids()?;
    for _ in 0..SETTLE_POLLS {
        if extra_ids(want_maps, &current.0).is_empty()
            && extra_ids(want_progs, &current.1).is_empty()
        {
            return Ok(current);
        }
        std::thread::sleep(SETTLE_INTERVAL);
        current = live_bpf_ids()?;
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `FSOPEN_CLOEXEC` value this module passes is accepted by
    /// the kernel and takes effect. Where `fsopen` succeeds the
    /// CLOEXEC bit is asserted directly; where the host denies contexts
    /// (this host denies even tmpfs unprivileged: measured EPERM), a
    /// differential pins the value instead: a bogus flag must draw
    /// `EINVAL` (proving flag validation runs before the denial), while
    /// ours must not be `EINVAL`. A host that denies before validating
    /// flags skips honestly (the value is then unverifiable here).
    #[test]
    fn fsopen_cloexec_flag_accepted_case() {
        // SAFETY: fsopen takes no out-params; the fd is owned below
        // on the success path only.
        let ret = unsafe { libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), FSOPEN_CLOEXEC) };
        if ret >= 0 {
            // SAFETY: freshly returned owned fd.
            let fs = unsafe { OwnedFd::from_raw_fd(ret as RawFd) };
            assert!(
                crate::fd::cloexec_flag_set(fs.as_raw_fd()),
                "FSOPEN_CLOEXEC must take effect"
            );
            return;
        }
        let errno = last_errno();
        // SAFETY: bogus-flag probe; the fd is closed below on the
        // unexpected success path.
        let bogus = unsafe { libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), 0x4000) };
        if bogus >= 0 {
            println!("SKIP: host accepts wider fsopen flags; differential inconclusive");
            if let Ok(fd) = RawFd::try_from(bogus) {
                // SAFETY: freshly returned owned fd; closed immediately.
                unsafe {
                    libc::close(fd);
                }
            }
            return;
        }
        if last_errno() != libc::EINVAL {
            println!("SKIP: host denies fsopen before validating flags");
            return;
        }
        assert_ne!(
            errno,
            libc::EINVAL,
            "kernel rejected FSOPEN_CLOEXEC (wrong constant?)"
        );
        println!("SKIP: fsopen denied (errno {errno}); flag value accepted (not EINVAL)");
    }

    /// The bpf fs context opens CLOEXEC (spawn discipline): the
    /// child's copy must never survive an exec. Root-only (`fsopen`
    /// of bpf denies unprivileged with EPERM: measured).
    #[test]
    fn fsopen_bpf_is_cloexec_case() {
        // SAFETY: idempotent getter.
        if unsafe { libc::geteuid() } != 0 {
            println!("SKIP: bpf fsopen needs euid == 0");
            return;
        }
        let fs = fsopen_bpf().expect("root fsopen");
        assert!(
            crate::fd::cloexec_flag_set(fs.as_raw_fd()),
            "fs context fd must be CLOEXEC"
        );
    }

    /// A bad fs fd denies at the first `fsconfig` (unprivileged-safe:
    /// no mount is reachable from fd -1).
    #[test]
    fn instantiate_rejects_bad_fd_case() {
        // SAFETY: -1 is never dereferenced; `fsconfig` fails first,
        // and `Drop` skips negative fds.
        let bad = unsafe { OwnedFd::from_raw_fd(-1) };
        let err = instantiate_bpffs(&bad).unwrap_err();
        assert!(
            matches!(err, TokenError::Denied { .. }),
            "bad fs fd must deny, got {err}"
        );
    }

    /// Guards the NUL-termination contract the raw `fsconfig` syscalls
    /// rely on (key/value are passed as bare pointers).
    #[test]
    fn delegates_nul_terminated_case() {
        for (key, value) in DELEGATES {
            assert_eq!(key.last(), Some(&0), "delegate key NUL");
            assert_eq!(value.last(), Some(&0), "delegate value NUL");
        }
    }

    /// Extras-only leak comparison (B6): host removals are ordinary
    /// churn, host additions (ours or a concurrent loader's) report.
    #[test]
    fn extra_ids_cases() {
        assert!(extra_ids(&[], &[]).is_empty());
        assert!(extra_ids(&[1, 2, 3], &[1, 2, 3]).is_empty());
        // Host teardown mid-roundtrip: removals never cry leak.
        assert!(extra_ids(&[1, 2, 3], &[1, 3]).is_empty());
        assert!(extra_ids(&[1, 2, 3], &[]).is_empty());
        // Leftovers report, in ascending order.
        assert_eq!(extra_ids(&[1, 3], &[1, 2, 3]), vec![2]);
        assert_eq!(extra_ids(&[], &[9]), vec![9]);
    }

    /// Live scan or `None` when the host denies id scans (the
    /// settle tests need no privilege assertions of their own).
    fn live_or_skip() -> Option<(Vec<u32>, Vec<u32>)> {
        match live_bpf_ids() {
            Ok(ids) => Some(ids),
            Err(TokenError::Denied { errno, stage }) => {
                println!("SKIP: id scans denied at {stage} (errno {errno})");
                None
            }
            Err(err) => panic!("scan failed dishonestly: {err}"),
        }
    }

    /// Settle converges at once when the live sets already match.
    #[test]
    fn settle_converged_case() {
        let Some((maps, progs)) = live_or_skip() else {
            return;
        };
        let (settled_maps, settled_progs) =
            settle_bpf_ids(&maps, &progs).expect("settle converged");
        assert_eq!(settled_maps, maps, "maps must match at once");
        assert_eq!(settled_progs, progs, "progs must match at once");
    }

    /// Settle does NOT invent convergence: against an impossible want
    /// it lapses the window and returns the live (mismatching) sets.
    /// Skips on hosts with no ambient BPF objects (want `[]` is live).
    #[test]
    fn settle_timeout_case() {
        let Some((maps, progs)) = live_or_skip() else {
            return;
        };
        if maps.is_empty() && progs.is_empty() {
            println!("SKIP: no ambient BPF objects to mismatch against");
            return;
        }
        let (settled_maps, settled_progs) = settle_bpf_ids(&[], &[]).expect("settle lapses");
        assert!(
            !settled_maps.is_empty() || !settled_progs.is_empty(),
            "lapsed settle must report the live sets, not the want"
        );
    }
}
