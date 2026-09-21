// SPDX-License-Identifier: GPL-3.0-or-later
//! `JsonlWriter`: deterministic record envelopes + atomic file commit.
//!
//! One record advances the writer clock by exactly 1000ns from 0, so a
//! fixed call sequence is byte-deterministic. Envelopes serialize field
//! order (`schema` first, like the pack example), not sorted keys.

use crate::EVENT_SCHEMA_V0;
use kryprobe_core::synthetic::STEP_NS;
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Writer defects: Rust-only values with no frozen wire spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// `BackendId::Synthetic` never serializes (schema has no spelling).
    SyntheticBackend,
    /// `NativeResult::Synthetic` never serializes either: it is test-only
    /// (the driver test double emits it), and stamping `synthetic` into a
    /// real backend's `native_namespace` would launder harness output as
    /// native evidence.
    SyntheticResult,
    /// `EvidencePhase::Succeeded` is derived in Rust, never on the wire.
    SucceededPhase,
    /// `child_exit_code` must be 0–255 or null.
    ExitCodeOutOfRange(i32),
    /// `child_signal` must be 1–128 or null.
    SignalOutOfRange(i32),
    /// A `kind` record failed to serialize (a harness defect: every
    /// shipped payload serializes; only a future non-serializable
    /// payload can trip this).
    SerializeFailed {
        /// Record kind that failed to serialize.
        kind: &'static str,
        /// The underlying serialization failure.
        detail: String,
    },
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SyntheticBackend => write!(f, "synthetic backend has no wire spelling"),
            Self::SyntheticResult => {
                write!(f, "synthetic native result has no wire spelling")
            }
            Self::SucceededPhase => write!(f, "succeeded phase never serializes"),
            Self::ExitCodeOutOfRange(code) => write!(f, "exit code {code} out of range 0-255"),
            Self::SignalOutOfRange(sig) => write!(f, "signal {sig} out of range 1-128"),
            Self::SerializeFailed { kind, detail } => {
                write!(f, "cannot serialize {kind} record: {detail}")
            }
        }
    }
}

impl std::error::Error for ReportError {}

/// Envelope keys in pack order (struct order, not sorted).
#[derive(Serialize)]
struct Record<'a, P: Serialize> {
    schema: &'a str,
    kind: &'a str,
    session_id: &'a str,
    record_id: String,
    monotonic_ns: String,
    payload: P,
}

/// Deterministic JSONL session writer.
///
/// # Example
///
/// A start/end envelope round-trips through the stream checker clean.
///
/// ```
/// use kryprobe_core::enums::{BackendId, CaptureMode, TargetSelector};
/// use kryprobe_report::{
///     FinalBarrier, JsonlWriter, SessionEnd, SessionStart, SessionVerdict, check_stream,
/// };
///
/// let mut writer = JsonlWriter::new("session:demo");
/// writer
///     .session_start(&SessionStart {
///         target_selector: TargetSelector::System,
///         capture_mode: CaptureMode::Trace,
///         requested_backends: vec![BackendId::KCrypto],
///         qualification_id: "qualification:demo".to_owned(),
///     })
///     .expect("start emits");
/// writer
///     .session_end(&SessionEnd {
///         verdict: SessionVerdict::Observed,
///         final_barrier: FinalBarrier::Validated,
///         unresolved_gap_ids: Vec::new(),
///         child_exit_code: None,
///         child_signal: None,
///     })
///     .expect("end emits");
/// let text = writer.into_string();
/// assert_eq!(text.lines().count(), 2);
/// let kinds: &[(&str, &[&str])] = &[
///     ("session_start", &["target_selector"]),
///     ("session_end", &["verdict"]),
/// ];
/// assert_eq!(check_stream(&text, kinds), Vec::new());
/// ```
#[derive(Debug)]
pub struct JsonlWriter {
    session: String,
    next_record: u64,
    clock_ns: u64,
    out: String,
}

impl JsonlWriter {
    /// New writer for `session_id` (e.g. `"session:demo"`); clock starts at 0.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session: session_id.to_owned(),
            next_record: 1,
            clock_ns: 0,
            out: String::new(),
        }
    }

    /// Finished stream text.
    #[must_use]
    pub fn finish(&self) -> &str {
        &self.out
    }

    /// Finished stream text, owned.
    #[must_use]
    pub fn into_string(self) -> String {
        self.out
    }

    /// Appends one record; stamp advances the clock by [`STEP_NS`].
    /// Serialization failure is a typed [`ReportError`], never a panic:
    /// a failed emit appends nothing, so the stream stays well-formed.
    pub(crate) fn emit<P: Serialize>(
        &mut self,
        kind: &'static str,
        payload: P,
    ) -> Result<(), ReportError> {
        let record = Record {
            schema: EVENT_SCHEMA_V0,
            kind,
            session_id: &self.session,
            record_id: format!("record:{}", self.next_record),
            monotonic_ns: self.clock_ns.to_string(),
            payload,
        };
        let text = serde_json::to_string(&record).map_err(|err| ReportError::SerializeFailed {
            kind,
            detail: err.to_string(),
        })?;
        self.out.push_str(&text);
        self.out.push('\n');
        self.next_record += 1;
        self.clock_ns += STEP_NS;
        Ok(())
    }

    /// Commits the stream atomically: temp file + fsync + rename + dir fsync.
    pub fn write_file_atomic(&self, path: &Path) -> anyhow::Result<()> {
        write_str_atomic(path, &self.out)
    }
}

/// Atomically commits `text` to `path`: temp file + fsync + rename +
/// dir fsync. The one commit site: [`JsonlWriter::write_file_atomic`]
/// and the selftest `--out` paths share it, so no plain `fs::write`
/// can leave a torn file behind.
///
/// A failed commit removes its temp file (best-effort): callers never
/// inherit `.tmp` litter from an error path.
pub fn write_str_atomic(path: &Path, text: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("atomic write needs a file name"))?;
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        unique
    ));
    let outcome: anyhow::Result<()> = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("create temp {}", tmp.display()))?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("write temp {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync temp {}", tmp.display()))?;
        drop(file);
        std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
        let dir = std::fs::File::open(parent)
            .with_context(|| format!("open dir {}", parent.display()))?;
        dir.sync_all()
            .with_context(|| format!("fsync dir {}", parent.display()))?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A payload whose serialization always fails.
    struct Unserializable;

    impl serde::Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    #[test]
    fn emit_returns_typed_error_instead_of_panicking() {
        let mut writer = JsonlWriter::new("session:emit");
        let err = writer
            .emit("operation_observation", Unserializable)
            .expect_err("unserializable payload must fail");
        assert_eq!(
            err,
            ReportError::SerializeFailed {
                kind: "operation_observation",
                detail: "boom".to_owned(),
            }
        );
        assert_eq!(
            err.to_string(),
            "cannot serialize operation_observation record: boom"
        );
        // The failed emit appended nothing: no torn record.
        assert_eq!(writer.finish(), "");
    }
}
