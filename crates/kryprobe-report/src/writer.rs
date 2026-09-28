// SPDX-License-Identifier: GPL-3.0-or-later
//! `JsonlWriter`: deterministic record envelopes + atomic file commit.
//!
//! One record advances the writer clock by exactly 1000ns from 0, so a
//! fixed call sequence is byte-deterministic. Envelopes serialize field
//! order (`schema` first, like the pack example), not sorted keys.

use crate::EVENT_SCHEMA_V0;
use crate::{KCRYPTO_LIFECYCLE_SESSION_V1, KCRYPTO_LIFECYCLE_V1};
use kryprobe_core::synthetic::STEP_NS;
use serde::Serialize;
use std::collections::BTreeMap;
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
    /// Live export saw an observation without a supported capture
    /// profile: no honest boundary mapping exists (F01).
    UnsupportedCaptureProfile {
        /// Profile value found, or `"<missing>"`.
        profile: String,
    },
    /// An unobserved lifecycle terminal has no status, hence no wire
    /// outcome spelling (a zero-fill would fabricate success).
    UnknownNativeResult,
    /// A session-envelope export needs the outcome's lifecycle
    /// totals (coverage populations + loss evidence); the outcome
    /// carries none (wrong profile for this export).
    MissingLifecycleTotals,
    /// A session-envelope export met a row it cannot project: not a
    /// lifecycle row, or a lifecycle row failing payload-v1. Loud,
    /// never a silent skip.
    UnprojectableRow {
        /// Why the row cannot ride the envelope (static or
        /// validator-quoted detail — never raw payload bytes).
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
            Self::UnsupportedCaptureProfile { profile } => {
                write!(f, "no supported export boundary for profile {profile:?}")
            }
            Self::UnknownNativeResult => {
                write!(f, "unobserved terminal has no wire spelling")
            }
            Self::MissingLifecycleTotals => {
                write!(f, "session export needs lifecycle totals")
            }
            Self::UnprojectableRow { detail } => {
                write!(f, "row cannot ride the session envelope: {detail}")
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

/// Session-envelope write defects: Rust-only values, never wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionWriteError {
    /// A record was emitted before `session_start` (the envelope opens
    /// with start, always).
    NotStarted,
    /// `session_start` was called twice (one start per stream).
    AlreadyStarted,
    /// A record was emitted after the receipt (the receipt is last).
    Finished,
    /// An observation's `record` fails payload-v1 validation (nested
    /// finding count only — findings themselves are input-free, but the
    /// count is all the writer needs to refuse).
    InvalidObservation {
        /// Nested payload-v1 finding count.
        nested: usize,
    },
    /// A record body failed to serialize (a harness defect: every
    /// shipped body serializes; only a future non-serializable body
    /// can trip this).
    SerializeFailed {
        /// Record kind that failed to serialize.
        kind: &'static str,
        /// The underlying serialization failure.
        detail: String,
    },
}

impl std::fmt::Display for SessionWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted => write!(f, "session record before session_start"),
            Self::AlreadyStarted => write!(f, "duplicate session_start"),
            Self::Finished => write!(f, "session record after the receipt"),
            Self::InvalidObservation { nested } => {
                write!(f, "observation record fails payload-v1 ({nested} findings)")
            }
            Self::SerializeFailed { kind, detail } => {
                write!(f, "cannot serialize {kind} record: {detail}")
            }
        }
    }
}

impl std::error::Error for SessionWriteError {}

/// Session-envelope record: fixed header, then the kind body
/// (flattened — header order first, like the event-v0 `Record`).
#[derive(Serialize)]
struct SessionRecord<'a, P: Serialize> {
    schema: &'a str,
    kind: &'a str,
    session: &'a str,
    seq: u64,
    #[serde(flatten)]
    body: P,
}

/// `session_start` body (struct order is the wire order).
#[derive(Serialize)]
struct StartBody<'a> {
    profile: &'a str,
    source: &'a str,
    evidence_version: &'a str,
    rule_version: &'a str,
    payload_schema: &'a str,
}

/// `observation` body: the validated payload-v1 record, verbatim.
#[derive(Serialize)]
struct ObservationBody<'a> {
    record: &'a serde_json::Value,
}

/// `coverage` body: u64 populations + the stage→count loss map
/// (`BTreeMap` wire order is sorted — byte-deterministic).
#[derive(Serialize)]
struct CoverageBody {
    admitted: u64,
    emitted: u64,
    unfinished: u64,
    loss: BTreeMap<String, u64>,
    unknown: u64,
    filtered: u64,
}

/// `session_receipt` body.
#[derive(Serialize)]
struct ReceiptBody {
    verdict: &'static str,
    admitted: u64,
    emitted: u64,
    unfinished: u64,
    loss: BTreeMap<String, u64>,
    truncated: bool,
}

/// Deterministic lifecycle session-envelope writer (T11/P6: the ADR
/// session envelope — distinct from event-v0, which stays frozen).
///
/// A fixed call sequence is byte-deterministic: dense 1-based `seq`,
/// struct-ordered keys, sorted loss maps. Observations validate against
/// payload-v1 BEFORE the envelope admits them; a failed emit appends
/// nothing, so the stream stays well-formed.
///
/// # Example
///
/// ```
/// use kryprobe_report::{SessionWriter, validate_lifecycle_session};
///
/// let mut writer = SessionWriter::new("session:demo");
/// writer
///     .session_start("request-lifecycle", "evidence:v1", "rule:v1")
///     .expect("start emits");
/// writer
///     .observation(&serde_json::json!({
///         "schema": "kryprobe.kcrypto.lifecycle/v1",
///         "request_id": "fixture:req-1",
///         "tfm_id": null,
///         "terminal": "sync",
///         "status": 0,
///         "duration_ns": "120",
///     }))
///     .expect("valid observation emits");
/// writer.receipt(true, 1, 1, 0).expect("receipt emits");
/// assert!(validate_lifecycle_session(&writer.into_string()).is_empty());
/// ```
#[derive(Debug)]
pub struct SessionWriter {
    session: String,
    next_seq: u64,
    started: bool,
    finished: bool,
    out: String,
}

impl SessionWriter {
    /// New writer for `session_id` (e.g. `"session:demo"`); the first
    /// record (`session_start`) takes seq 1.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session: session_id.to_owned(),
            next_seq: 1,
            started: false,
            finished: false,
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

    /// Appends one envelope record; `seq` advances densely from 1. A
    /// failed emit appends nothing.
    fn emit<P: Serialize>(&mut self, kind: &'static str, body: P) -> Result<(), SessionWriteError> {
        if !self.started {
            return Err(SessionWriteError::NotStarted);
        }
        if self.finished {
            return Err(SessionWriteError::Finished);
        }
        let record = SessionRecord {
            schema: KCRYPTO_LIFECYCLE_SESSION_V1,
            kind,
            session: &self.session,
            seq: self.next_seq,
            body,
        };
        let text =
            serde_json::to_string(&record).map_err(|err| SessionWriteError::SerializeFailed {
                kind,
                detail: err.to_string(),
            })?;
        self.out.push_str(&text);
        self.out.push('\n');
        self.next_seq += 1;
        Ok(())
    }

    /// Opens the stream: session identity + capture config at seq 1.
    /// `source` pins to `kernel-crypto` (the only v0.1 source — the CLI
    /// refuses any other spelling, so the writer states the constant
    /// rather than taking a caller string it cannot verify).
    pub fn session_start(
        &mut self,
        profile: &str,
        evidence_version: &str,
        rule_version: &str,
    ) -> Result<(), SessionWriteError> {
        if self.started {
            return Err(SessionWriteError::AlreadyStarted);
        }
        self.started = true;
        self.emit(
            "session_start",
            StartBody {
                profile,
                source: "kernel-crypto",
                evidence_version,
                rule_version,
                payload_schema: KCRYPTO_LIFECYCLE_V1,
            },
        )
    }

    /// Appends one validated observation. The `record` MUST validate
    /// against payload-v1 first — an invalid record refuses (nothing
    /// appended), never a silent skip.
    pub fn observation(&mut self, record: &serde_json::Value) -> Result<(), SessionWriteError> {
        let nested = crate::validate::validate_lifecycle_v1(record);
        if !nested.is_empty() {
            return Err(SessionWriteError::InvalidObservation {
                nested: nested.len(),
            });
        }
        self.emit("observation", ObservationBody { record })
    }

    /// Appends a coverage update: exact populations plus per-stage loss
    /// (`loss` stage→count pairs; empty means no counted stage loss).
    /// Global loss evidence is retained here even when filters drop
    /// every detail row.
    pub fn coverage(
        &mut self,
        admitted: u64,
        emitted: u64,
        unfinished: u64,
        loss: Vec<(&str, u64)>,
        unknown: u64,
        filtered: u64,
    ) -> Result<(), SessionWriteError> {
        self.emit(
            "coverage",
            CoverageBody {
                admitted,
                emitted,
                unfinished,
                loss: loss
                    .into_iter()
                    .map(|(stage, count)| (stage.to_owned(), count))
                    .collect(),
                unknown,
                filtered,
            },
        )
    }

    /// Appends the terminal receipt: `clean` selects the `clean` vs
    /// `partial` verdict (a partial receipt here means unfinished work
    /// with no counted stage loss — counted loss needs
    /// [`SessionWriter::receipt_partial`]). `truncated` is always false:
    /// truncation is a reader-side verdict over a receiptless stream,
    /// never a writer claim.
    pub fn receipt(
        &mut self,
        clean: bool,
        admitted: u64,
        emitted: u64,
        unfinished: u64,
    ) -> Result<(), SessionWriteError> {
        let verdict = if clean { "clean" } else { "partial" };
        self.emit(
            "session_receipt",
            ReceiptBody {
                verdict,
                admitted,
                emitted,
                unfinished,
                loss: BTreeMap::new(),
                truncated: false,
            },
        )?;
        self.finished = true;
        Ok(())
    }

    /// Appends a partial terminal receipt WITH counted stage loss.
    pub fn receipt_partial(
        &mut self,
        admitted: u64,
        emitted: u64,
        unfinished: u64,
        loss: Vec<(&str, u64)>,
    ) -> Result<(), SessionWriteError> {
        self.emit(
            "session_receipt",
            ReceiptBody {
                verdict: "partial",
                admitted,
                emitted,
                unfinished,
                loss: loss
                    .into_iter()
                    .map(|(stage, count)| (stage.to_owned(), count))
                    .collect(),
                truncated: false,
            },
        )?;
        self.finished = true;
        Ok(())
    }

    /// Commits the stream atomically (same temp + fsync + rename path
    /// as [`JsonlWriter::write_file_atomic`]).
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
