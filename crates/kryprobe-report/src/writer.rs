// SPDX-License-Identifier: GPL-3.0-or-later
//! `JsonlWriter`: deterministic record envelopes + atomic file commit.
//!
//! One record advances the writer clock by exactly 1000ns from 0, so a
//! fixed call sequence is byte-deterministic. Envelopes serialize field
//! order (`schema` first, like the pack example), not sorted keys.

use crate::EVENT_SCHEMA_V0;
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Writer defects: Rust-only values with no frozen wire spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// `BackendId::Synthetic` never serializes (schema has no spelling).
    SyntheticBackend,
    /// `EvidencePhase::Succeeded` is derived in Rust, never on the wire.
    SucceededPhase,
    /// `child_exit_code` must be 0–255 or null.
    ExitCodeOutOfRange(i32),
    /// `child_signal` must be 1–128 or null.
    SignalOutOfRange(i32),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SyntheticBackend => write!(f, "synthetic backend has no wire spelling"),
            Self::SucceededPhase => write!(f, "succeeded phase never serializes"),
            Self::ExitCodeOutOfRange(code) => write!(f, "exit code {code} out of range 0-255"),
            Self::SignalOutOfRange(sig) => write!(f, "signal {sig} out of range 1-128"),
        }
    }
}

impl std::error::Error for ReportError {}

/// Clock step per emitted record, in monotonic nanoseconds.
const STEP_NS: u64 = 1_000;

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
    pub(crate) fn emit<P: Serialize>(&mut self, kind: &'static str, payload: P) {
        let record = Record {
            schema: EVENT_SCHEMA_V0,
            kind,
            session_id: &self.session,
            record_id: format!("record:{}", self.next_record),
            monotonic_ns: self.clock_ns.to_string(),
            payload,
        };
        // Payloads are plain string-keyed structs; serialization is infallible.
        self.out
            .push_str(&serde_json::to_string(&record).expect("record serializes"));
        self.out.push('\n');
        self.next_record += 1;
        self.clock_ns += STEP_NS;
    }

    /// Commits the stream atomically: temp file + fsync + rename + dir fsync.
    pub fn write_file_atomic(&self, path: &Path) -> anyhow::Result<()> {
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
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("create temp {}", tmp.display()))?;
        file.write_all(self.out.as_bytes())
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
    }
}
