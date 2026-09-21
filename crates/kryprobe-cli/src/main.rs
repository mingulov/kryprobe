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

fn main() {
    let argv: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let mut stdout = StdoutGuard::new(std::io::stdout().lock());
    let mut stderr = std::io::stderr().lock();
    let code = kryprobe_cli::run(
        &argv,
        &mut stdout as &mut dyn Write,
        &mut stderr as &mut dyn Write,
    );
    // Final flush (its failure records like any write): `process::exit`
    // below skips destructors, so buffered bytes must go now.
    let _ = stdout.flush();
    let code = stdout_exit(code, stdout.failed(), &mut stderr);
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
