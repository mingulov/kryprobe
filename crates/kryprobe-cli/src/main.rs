// SPDX-License-Identifier: GPL-3.0-or-later
//! `kryprobe` binary: thin argv/exit-code shell over the library.

use std::io::Write;

/// Exit code when stdout fails (EPIPE/short write): truncated
/// evidence must never exit 0 (1A-L11).
const STDOUT_FAILED: i32 = 1;

/// Records the first stdout write/flush failure; the process exit
/// code then reflects truncated output even when the command itself
/// succeeded. Covers every command uniformly (JSON and human paths
/// share this one stream) — individual `write!` sites stay
/// best-effort and the guard observes them.
struct StdoutGuard<W: Write> {
    inner: W,
    failed: Option<String>,
}

impl<W: Write> StdoutGuard<W> {
    fn new(inner: W) -> Self {
        StdoutGuard {
            inner,
            failed: None,
        }
    }

    /// First failure detail, if stdout broke.
    fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }
}

impl StdoutGuard<kryprobe_privilege::host::InterruptibleWriter> {
    /// P7-N7: restores production stdout's saved flags before
    /// `process::exit` (which skips `Drop` — without this the
    /// installed `O_NONBLOCK` leaks to the caller's open-file
    /// description on every success/torn-abort/error exit).
    fn restore_stdout_flags(&self) {
        self.inner.restore();
    }
}

impl<W: Write> Write for StdoutGuard<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.inner.write(buf) {
            Err(err) if self.failed.is_none() => {
                self.failed = Some(err.to_string());
                Err(err)
            }
            ok_or_repeat => ok_or_repeat,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.inner.flush() {
            Err(err) if self.failed.is_none() => {
                self.failed = Some(err.to_string());
                Err(err)
            }
            ok_or_repeat => ok_or_repeat,
        }
    }
}

/// Map the command exit code through the stdout outcome: a broken
/// stdout turns 0 into [`STDOUT_FAILED`] with a stderr note (Rust
/// ignores SIGPIPE, so `kryprobe report … | head -1` would otherwise
/// exit 0 over truncated evidence). Nonzero commands keep their own
/// code — still nonzero, still honest.
fn stdout_exit(base: i32, failed: Option<&str>, stderr: &mut dyn Write) -> i32 {
    if base != 0 {
        return base;
    }
    match failed {
        None => 0,
        Some(detail) => {
            let _ = writeln!(stderr, "kryprobe: stdout write failed ({detail})");
            STDOUT_FAILED
        }
    }
}

/// Main tail (P2r2/R2 seam): the final flush (its failure records
/// like any write) plus the stdout exit mapping, factored verbatim
/// from `main` so unit tests can drive it with an injected writer.
/// `main` calls exactly this — no behavior change (same calls, same
/// order, generic over the same [`Write`] impl).
fn finish<W: Write>(code: i32, stdout: &mut StdoutGuard<W>, stderr: &mut dyn Write) -> i32 {
    // Final flush (its failure records like any write):
    // `process::exit` below skips destructors, so buffered bytes go now.
    let _ = stdout.flush();
    stdout_exit(code, stdout.failed(), stderr)
}

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    // P7-N1: production stdout is the interruptible fd writer (a
    // fresh SIGINT aborts a stalled terminal emit within ~50 ms
    // instead of hanging a blocked write under `SA_RESTART`).
    // Unbuffered by design — every accepted byte reached fd 1, so
    // the terminal flush below is a no-op and bytes are identical
    // to the old line-buffered path on success. A wrap failure
    // means stdout's flags are already broken: fail closed before
    // running anything (no evidence can leave anyway).
    let mut stdout = match kryprobe_privilege::host::InterruptibleWriter::stdout() {
        Ok(writer) => StdoutGuard::new(writer),
        Err(err) => {
            eprintln!("kryprobe: stdout unusable: {err}");
            std::process::exit(STDOUT_FAILED);
        }
    };
    let mut stderr = std::io::stderr().lock();
    let code = kryprobe_cli::run(
        &argv,
        &mut stdout as &mut dyn Write,
        &mut stderr as &mut dyn Write,
    );
    let code = finish(code, &mut stdout, &mut stderr);
    // P7-N7: `process::exit` skips destructors, so the writer's
    // restoring `Drop` never runs here — restore stdout's flags
    // explicitly on this one final exit (success, torn-abort and
    // every subcommand error code flow through it; the
    // constructor-failure exit above installed no writer, so
    // there is nothing to undo there).
    stdout.restore_stdout_flags();
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1A-L11: the guard records the first stdout failure and passes
    /// writes through untouched on success.
    #[test]
    fn guard_records_first_failure_only() {
        struct Failing;
        impl Write for Failing {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if buf == b"boom" {
                    Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "boom"))
                } else {
                    Ok(buf.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut guard = StdoutGuard::new(Failing);
        assert_eq!(guard.write(b"ok").expect("passthrough"), 2);
        assert!(guard.failed().is_none());
        assert!(guard.write(b"boom").is_err());
        assert_eq!(guard.failed(), Some("boom"));
        // A second failure does not overwrite the first.
        assert!(guard.write(b"boom").is_err());
        assert_eq!(guard.failed(), Some("boom"));
    }

    /// P2r2/R2(b): a flush-ONLY failure (writes succeed, the final
    /// flush fails) exits not-clean with the stdout note. The
    /// `/dev/full` integration test fails at write time, so it stays
    /// green when the final flush is removed (Astra's mutation) — this
    /// injected writer is the only seam that sees the flush. Control:
    /// a clean writer stays exit 0 with silent stderr.
    #[test]
    fn flush_only_failure_is_not_clean() {
        struct FlushFailing;
        impl Write for FlushFailing {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "flush failed",
                ))
            }
        }
        let mut guard = StdoutGuard::new(FlushFailing);
        guard
            .write_all(b"{\"complete\":true}\n")
            .expect("writes succeed");
        assert!(guard.failed().is_none(), "no failure before the flush");
        let mut stderr = Vec::new();
        let code = finish(0, &mut guard, &mut stderr);
        assert_eq!(code, 1, "a flush-only failure must not exit clean");
        let text = String::from_utf8(stderr).expect("stderr utf-8");
        assert!(text.contains("stdout"), "stderr names stdout: {text}");
        // Control: a clean writer through the same tail stays clean.
        let mut guard = StdoutGuard::new(Vec::new());
        guard.write_all(b"x").expect("write");
        let mut stderr = Vec::new();
        assert_eq!(finish(0, &mut guard, &mut stderr), 0);
        assert!(stderr.is_empty(), "clean run stays silent");
    }

    /// 1A-L11: truncated stdout turns exit 0 into exit 1 with a
    /// stderr note; nonzero commands keep their own code.
    #[test]
    fn stdout_failure_maps_exit_zero_to_one() {
        let mut stderr = Vec::new();
        assert_eq!(stdout_exit(0, None, &mut stderr), 0);
        assert!(stderr.is_empty());
        assert_eq!(stdout_exit(0, Some("broken pipe"), &mut stderr), 1);
        assert!(
            String::from_utf8(stderr.clone())
                .expect("utf-8")
                .contains("stdout"),
            "stderr names stdout: {stderr:?}"
        );
        let mut stderr = Vec::new();
        assert_eq!(stdout_exit(3, Some("broken pipe"), &mut stderr), 3);
    }
}
