// SPDX-License-Identifier: GPL-3.0-or-later
//! Host identity and errno classifiers (1B-M7).
//!
//! The CLI renders host facts but must not name errnos or call `libc`
//! itself (ADR-0002 Rule B): euid checks and errno classification live
//! here behind typed/plain-bool APIs, and only real syscall errnos flow
//! back to renderers — nothing here invents one.

/// True when the process runs as root (euid 0).
#[must_use]
pub fn euid_is_root() -> bool {
    // SAFETY: idempotent getter.
    unsafe { libc::geteuid() == 0 }
}

/// Set when SIGINT arrives after [`install_sigint_flag`] (4B-M5): the
/// live tick loop polls this alongside the session stop flag, so an
/// interrupted capture finalizes and renders partial (exit 3) instead
/// of dying mid-capture with no evidence.
pub static SIGINT_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Records SIGINT arrival in [`SIGINT_SEEN`]: the only async-signal
/// work is one relaxed atomic store, which is signal-safe.
extern "C" fn sigint_flag(_sig: libc::c_int) {
    SIGINT_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Installs the SIGINT recorder ([`SIGINT_SEEN`]) with `SA_RESTART`
/// (in-flight syscalls resume; the tick loop observes the flag at
/// its next poll) and clears any stale arrival. Idempotent.
/// The CLI owns no `libc` (ADR-0002 Rule B) — signal handling lives
/// here behind this plain call.
pub fn install_sigint_flag() -> std::io::Result<()> {
    // SAFETY: zeroed `sigaction` (empty mask) + a signal-safe handler;
    // `sigaction` with valid args reports failure via its return.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sigint_flag as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// `CLOCK_MONOTONIC` now in nanoseconds (unprivileged; the ring-clock
/// domain — lifecycle session walls and the `finish` stop stamp).
/// The CLI owns no `libc` (ADR-0002 Rule B), so the syscall lives
/// here behind this plain call; the single unsafe site for both this
/// and the snapshot walls.
pub fn monotonic_ns() -> std::io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer; `CLOCK_MONOTONIC` is always supported.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((ts.tv_sec.max(0) as u64) * 1_000_000_000 + (ts.tv_nsec.max(0) as u64))
}

/// True for missing-path errnos (`ENOENT`/`ENOTDIR`): bad input paths.
#[must_use]
pub fn errno_is_missing(errno: i32) -> bool {
    errno == libc::ENOENT || errno == libc::ENOTDIR
}

/// True for refusal errnos (`EPERM`/`EACCES`/`EOPNOTSUPP`/`ENOTSUP`):
/// the kernel or filesystem refused the operation.
#[must_use]
pub fn errno_is_refused(errno: i32) -> bool {
    [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP, libc::ENOTSUP].contains(&errno)
}

/// True when an xattr read found no value (`ENODATA`): absent attribute.
#[must_use]
pub fn errno_is_absent_xattr(errno: i32) -> bool {
    errno == libc::ENODATA
}

/// Poll slice for interruptible fd writes (P7-N1): a stalled sink
/// re-checks the SIGINT witness this often, so a fresh SIGINT aborts
/// within ~50 ms instead of hanging a blocked `write_all` under
/// `SA_RESTART`.
const INTERRUPT_POLL_MS: i32 = 50;

/// An fd writer that never blocks past one poll slice without
/// consulting the SIGINT witness (P7-N1: a fresh SIGINT during a
/// blocked terminal emit aborts promptly with the torn-stream
/// status instead of hanging in `write_all` under `SA_RESTART` —
/// task item 3 "responsive stop", item 2 stop/reap ≤ 10 s).
///
/// Construction records the fd's file-status flags and sets
/// `O_NONBLOCK`; `Drop` restores the recorded flags. Each `write`
/// attempts the fd directly (fast path — no flag consult, so a
/// stale witness never fails a writable sink); only a stalled sink
/// (`EAGAIN`, zero progress, `EINTR`) enters the poll loop, where
/// every wake re-checks [`SIGINT_SEEN`] and reports a fresh arrival
/// as [`ErrorKind::Interrupted`](std::io::ErrorKind::Interrupted) —
/// the emit seam maps witness-set `Interrupted` to the torn-stream
/// abort and retries anything else. Bytes accepted on success are
/// identical to a blocking write (no v0 byte change).
///
/// The fd must stay open for `self`'s lifetime; flag changes are
/// process-visible, so this is single-writer emit-window use (the
/// CLI's terminal stdout emission — its only stdout writer).
/// `flush` is a no-op (unbuffered — every accepted byte reached the
/// fd).
#[derive(Debug)]
pub struct InterruptibleWriter {
    fd: std::os::fd::RawFd,
    saved_flags: libc::c_int,
}

impl InterruptibleWriter {
    /// Wraps `fd` for interruptible emission (sets `O_NONBLOCK`,
    /// restored on drop). Fails closed when the fd's flags cannot
    /// be read or set.
    pub fn new(fd: std::os::fd::RawFd) -> std::io::Result<Self> {
        // SAFETY: `fcntl` with valid args reports failure via its
        // return; the fd is caller-owned and open.
        let saved = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if saved < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: same fd; `O_NONBLOCK` or-in never clears bits.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, saved | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            saved_flags: saved,
        })
    }

    /// Wraps process stdout (fd 1) — the CLI's terminal emit sink.
    pub fn stdout() -> std::io::Result<Self> {
        Self::new(libc::STDOUT_FILENO)
    }

    /// One stalled-sink wait: polls the fd writable for a single
    /// slice, then reports whether a fresh SIGINT arrived during it.
    fn poll_slice(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one valid `pollfd`; the timeout bounds the wait
        // even under `SA_RESTART` (a restarted poll still wakes per
        // slice — every wake re-checks the witness below).
        let _ = unsafe { libc::poll(&mut pfd, 1, INTERRUPT_POLL_MS) };
        SIGINT_SEEN.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::io::Write for InterruptibleWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // SAFETY: the fd is open (caller contract); `buf` is a
            // valid read of `len` bytes; the return is trusted only
            // for progress/errno classification.
            let wrote =
                unsafe { libc::write(self.fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
            if wrote > 0 {
                return Ok(wrote as usize);
            }
            if wrote == 0 {
                // No progress without an error: wait a slice (a
                // fresh SIGINT aborts here) and retry — a stalled
                // sink reads exactly like a blocking write, except
                // it stays interruptible.
                if self.poll_slice() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "stdout emit interrupted by SIGINT",
                    ));
                }
                continue;
            }
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                if self.poll_slice() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "stdout emit interrupted by SIGINT",
                    ));
                }
                continue;
            }
            if errno == libc::EINTR {
                // A signal cut the write short: only a SET witness
                // aborts (a foreign signal retries — the emit seam
                // re-checks the witness before mapping).
                if SIGINT_SEEN.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "stdout emit interrupted by SIGINT",
                    ));
                }
                continue;
            }
            return Err(std::io::Error::from_raw_os_error(errno));
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for InterruptibleWriter {
    fn drop(&mut self) {
        // SAFETY: same fd as construction; best-effort restore (a
        // drop cannot fail — the emit window owns the fd anyway).
        let _ = unsafe { libc::fcntl(self.fd, libc::F_SETFL, self.saved_flags) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifiers_partition_common_errnos() {
        // Each classifier fires on its own errnos and stays silent on
        // the others' (a refusal must never read as missing input).
        for errno in [libc::ENOENT, libc::ENOTDIR] {
            assert!(errno_is_missing(errno));
            assert!(!errno_is_refused(errno));
            assert!(!errno_is_absent_xattr(errno));
        }
        for errno in [libc::EPERM, libc::EACCES, libc::EOPNOTSUPP, libc::ENOTSUP] {
            assert!(!errno_is_missing(errno));
            assert!(errno_is_refused(errno));
            assert!(!errno_is_absent_xattr(errno));
        }
        assert!(!errno_is_missing(libc::ENODATA));
        assert!(!errno_is_refused(libc::ENODATA));
        assert!(errno_is_absent_xattr(libc::ENODATA));
        // Unrelated errnos classify nowhere (callers treat them as
        // internal failures, never as input/refusal).
        for errno in [libc::EIO, libc::EINVAL, 0] {
            assert!(!errno_is_missing(errno));
            assert!(!errno_is_refused(errno));
            assert!(!errno_is_absent_xattr(errno));
        }
    }

    #[test]
    fn euid_matches_libc() {
        // SAFETY: idempotent getter.
        assert_eq!(euid_is_root(), unsafe { libc::geteuid() } == 0);
    }

    /// P7-N1 host proof: 256 KiB into a full 64 KiB pipe whose
    /// reader has stopped, then a REAL SIGINT mid-emit — the writer
    /// aborts within the task's 10 s stop budget (mechanism target
    /// ~50 ms; the pre-fix blocking `write_all` hung 11+ s), the
    /// emitter thread is joined (nothing leaked), and the pipe holds
    /// exactly the pre-fill (the abort is real — zero post-fill
    /// bytes moved). No children: one joined thread.
    #[test]
    fn interruptible_writer_aborts_full_pipe_on_fresh_sigint() {
        use std::io::Write as _;
        use std::sync::atomic::Ordering;
        static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = GUARD.lock().expect("sigint serial");
        super::install_sigint_flag().expect("installs");
        // SAFETY: `pipe2` with a valid out-pointer; fds closed below.
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe creates"
        );
        let (read_fd, write_fd) = (fds[0], fds[1]);
        // Fill to EAGAIN under nonblock (the stalled-sink shape: the
        // read end stays open but is never read until after abort).
        // SAFETY: valid fds; flag or-in never clears bits.
        let saved = unsafe { libc::fcntl(write_fd, libc::F_GETFL) };
        assert!(saved >= 0, "fill flags read");
        assert_eq!(
            unsafe { libc::fcntl(write_fd, libc::F_SETFL, saved | libc::O_NONBLOCK) },
            0,
            "fill sets nonblock"
        );
        let chunk = vec![0xABu8; 65_536];
        let mut filled = 0usize;
        loop {
            // SAFETY: write end open; chunk is a valid read.
            let wrote = unsafe {
                libc::write(write_fd, chunk.as_ptr().cast::<libc::c_void>(), chunk.len())
            };
            if wrote > 0 {
                filled += wrote as usize;
                continue;
            }
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            assert!(
                errno == libc::EAGAIN || errno == libc::EWOULDBLOCK,
                "fill ends at EAGAIN, got errno {errno}"
            );
            break;
        }
        assert_eq!(filled, 65_536, "pipe capacity pre-filled");
        // Emitter thread: 256 KiB through the interruptible writer
        // (manual loop — `write_all` would retry `Interrupted`,
        // exactly what the emit seam must not do).
        let (tx, rx) = std::sync::mpsc::channel();
        let emitter = std::thread::spawn(move || {
            let mut writer = match super::InterruptibleWriter::new(write_fd) {
                Ok(writer) => writer,
                Err(err) => {
                    let _ = tx.send(Err(format!("wrap: {err}")));
                    return;
                }
            };
            let payload = vec![0xCDu8; 262_144];
            let mut off = 0usize;
            let outcome = loop {
                if off >= payload.len() {
                    break Ok(off);
                }
                match writer.write(&payload[off..]) {
                    Ok(0) => break Err("write-zero stall".to_owned()),
                    Ok(n) => off += n,
                    Err(err) => break Err(format!("{:?}:{err}", err.kind())),
                }
            };
            let _ = tx.send(outcome);
            // SAFETY: write end owned by this thread now.
            unsafe {
                libc::close(write_fd);
            }
        });
        // Let the emitter reach its stalled poll loop, then send a
        // REAL SIGINT (async arrival during the block — the exact
        // pre-fix hang shape).
        std::thread::sleep(std::time::Duration::from_millis(200));
        let armed = std::time::Instant::now();
        // SAFETY: `raise` to self with the plain-flag handler installed.
        assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0, "sigint raises");
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(10));
        let latency = armed.elapsed();
        // Restore the disposition + witness BEFORE asserting, so a
        // failure here cannot pollute later tests.
        // SAFETY: restoring the default disposition, no handler state.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        super::SIGINT_SEEN.store(false, Ordering::Relaxed);
        let outcome = match outcome {
            Ok(outcome) => {
                emitter.join().expect("emitter reaped");
                outcome
            }
            Err(_) => {
                // Hung past the task budget (the pre-fix shape): close
                // the read end so the emitter errors out, then reap it
                // before failing — never leak the thread.
                // SAFETY: read end owned here.
                unsafe {
                    libc::close(read_fd);
                }
                emitter.join().expect("emitter reaped");
                panic!("emitter still blocked {latency:?} after fresh SIGINT (pre-fix hang)");
            }
        };
        assert!(
            latency < std::time::Duration::from_secs(10),
            "abort within the stop budget: {latency:?}"
        );
        match outcome {
            Err(detail) => assert!(
                detail.starts_with("Interrupted:"),
                "fresh SIGINT maps to Interrupted, got {detail}"
            ),
            Ok(off) => {
                panic!("emitter completed {off} bytes into a full pipe (expected the stall abort)")
            }
        }
        // The abort is real: drain holds exactly the pre-fill (zero
        // post-fill bytes moved — the writer was truly stalled).
        let mut drained = 0usize;
        let mut sink = vec![0u8; 65_536];
        loop {
            // SAFETY: read end open; sink is a valid write.
            let got = unsafe {
                libc::read(
                    read_fd,
                    sink.as_mut_ptr().cast::<libc::c_void>(),
                    sink.len(),
                )
            };
            if got <= 0 {
                break;
            }
            drained += got as usize;
        }
        // SAFETY: read end owned here.
        unsafe {
            libc::close(read_fd);
        }
        assert_eq!(drained, 65_536, "exactly the pre-fill drains");
    }

    #[test]
    fn sigint_install_raise_sets_flag() {
        // 4B-M5: the installed handler records arrival; the test
        // restores the default disposition + clears the flag so no
        // other test observes either.
        super::install_sigint_flag().expect("installs");
        assert!(!super::SIGINT_SEEN.load(std::sync::atomic::Ordering::Relaxed));
        // SAFETY: `raise` to self with a plain-flag handler installed.
        unsafe {
            assert_eq!(libc::raise(libc::SIGINT), 0);
        }
        assert!(super::SIGINT_SEEN.load(std::sync::atomic::Ordering::Relaxed));
        // SAFETY: restoring the default disposition, no handler state.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        super::SIGINT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
