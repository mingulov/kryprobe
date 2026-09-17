// SPDX-License-Identifier: GPL-3.0-or-later
//! BPF selftest pipeline as a library call (T10 extraction).
//!
//! Load → spawn fixture → attach entry/return → drain → reconcile. The T7
//! lane test keeps its own detailed asserts; `kryprobe selftest bpf` runs
//! this path. Denials (EPERM/EACCES) surface as [`BpfSelftestError::Denied`]
//! for honest-degraded exit 3; everything else is a hard error.

mod round;

use crate::bpfloader::{LoaderError, load_spine_object};
use std::path::PathBuf;

/// Whole-pipeline failure: denied (exit 3) vs hard errors.
#[derive(Debug)]
pub enum BpfSelftestError {
    /// Required artifact (object or fixture) is missing.
    MissingArtifact {
        /// `"object"` or `"fixture"`.
        what: &'static str,
        /// Expected path.
        path: PathBuf,
    },
    /// Loader failure (privilege denials map to [`Self::Denied`]).
    Loader(LoaderError),
    /// Honest capability denial at a named stage.
    Denied {
        /// Stage that hit EPERM/EACCES.
        stage: String,
        /// Refusing errno.
        errno: i32,
    },
    /// Fixture spawn/I/O/attach failure.
    Fixture(String),
    /// Fixture line timeout (`"READY"` or `"DONE"`).
    Timeout(&'static str),
    /// Malformed spine record or fixture protocol breach.
    BadEvent(&'static str),
    /// Fixture exited nonzero.
    FixtureExit(i32),
    /// Drain thread failure.
    Drain(String),
    /// Map failure after attach (denials map to [`Self::Denied`]).
    Map(String),
}

impl std::fmt::Display for BpfSelftestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingArtifact { what, path } => {
                write!(f, "missing {what} at {}", path.display())
            }
            Self::Loader(err) => write!(f, "loader: {err}"),
            Self::Denied { stage, errno } => write!(f, "Denied{{{stage}}} (errno {errno})"),
            Self::Fixture(detail) => write!(f, "fixture: {detail}"),
            Self::Timeout(what) => write!(f, "timed out waiting for fixture {what}"),
            Self::BadEvent(what) => write!(f, "bad spine event: {what}"),
            Self::FixtureExit(code) => write!(f, "fixture exited {code}"),
            Self::Drain(detail) => write!(f, "drain: {detail}"),
            Self::Map(detail) => write!(f, "map: {detail}"),
        }
    }
}

impl std::error::Error for BpfSelftestError {}

/// True for honest capability denials (exit 3); anything else is an error.
pub(crate) fn is_denied(errno: i32) -> bool {
    errno == libc::EPERM || errno == libc::EACCES
}

/// Spawns a line pump: stdout lines flow to a channel for deadline reads.
pub(crate) fn pump_lines<R: std::io::Read + Send + 'static>(
    reader: R,
) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(reader)).map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

pub(crate) fn await_line(
    rx: &std::sync::mpsc::Receiver<String>,
    what: &'static str,
    timeout: std::time::Duration,
) -> Result<String, BpfSelftestError> {
    rx.recv_timeout(timeout)
        .map_err(|_| BpfSelftestError::Timeout(what))
}

pub(crate) fn kill_quietly(child: &mut std::process::Child) {
    child.kill().ok();
    child.wait().ok();
}

/// Field-wise 64-byte spine record view (no alignment assumptions).
pub struct SpineEventView {
    /// Cookie: generation in the high 32 bits.
    pub cookie: u64,
    /// Entry (0) vs return (1).
    pub flags: u32,
    /// Per-index sequence number.
    pub seq: u64,
}

/// Parses one spine record; short/ragged records fail closed.
pub fn view_spine_event(bytes: &[u8]) -> Result<SpineEventView, BpfSelftestError> {
    if bytes.len() != 64 {
        return Err(BpfSelftestError::BadEvent("record must be 64 bytes"));
    }
    if !bytes[36..64].iter().all(|b| *b == 0) {
        return Err(BpfSelftestError::BadEvent("reserved bytes must be zero"));
    }
    let u64le = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().expect("u64 width"));
    let u32le = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().expect("u32 width"));
    Ok(SpineEventView {
        cookie: u64le(0),
        flags: u32le(32),
        seq: u64le(24),
    })
}

/// Pipeline inputs: call count plus artifact paths.
pub struct BpfSelftestConfig {
    /// Fixture call count (2 records per call).
    pub calls: u64,
    /// Built spine object path.
    pub object: PathBuf,
    /// `spine_fixture` binary path.
    pub fixture: PathBuf,
}

/// Pipeline outcome: counts, loss receipts, and the reconcile verdict.
pub struct BpfSelftestOutcome {
    /// Entry records drained.
    pub entries: u64,
    /// Return records drained.
    pub returns: u64,
    /// Total records drained.
    pub received: u64,
    /// Ringbuf reservation failures (LOSS[0]).
    pub ring: u64,
    /// BPF-side guard drops (LOSS[1]).
    pub dropped: u64,
    /// Userspace queue drops.
    pub queue_drops: u64,
    /// Loss-ledger verdict.
    pub verdict: kryprobe_core::ReconcileVerdict,
}

/// Runs load → attach → drain → reconcile for `config.calls` fixture calls.
pub fn run_bpf_selftest(
    config: &BpfSelftestConfig,
) -> Result<BpfSelftestOutcome, BpfSelftestError> {
    if config.calls > u64::MAX / 2 {
        return Err(BpfSelftestError::Fixture("calls out of range".to_owned()));
    }
    if !config.object.is_file() {
        return Err(BpfSelftestError::MissingArtifact {
            what: "object",
            path: config.object.clone(),
        });
    }
    if !config.fixture.is_file() {
        return Err(BpfSelftestError::MissingArtifact {
            what: "fixture",
            path: config.fixture.clone(),
        });
    }
    let loaded = load_spine_object(&config.object).map_err(|err| match err {
        LoaderError::MapFailed { stage, errno } | LoaderError::LoadFailed { stage, errno, .. }
            if is_denied(errno) =>
        {
            BpfSelftestError::Denied { stage, errno }
        }
        other => BpfSelftestError::Loader(other),
    })?;
    round::roundtrip(config, &loaded)
}
