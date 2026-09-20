// SPDX-License-Identifier: GPL-3.0-or-later
//! Stream validation: structural checks + schema const + schema freeze.
//!
//! [`check_stream`](crate::check_stream) checks envelope presence only
//! (T4 ruling); this module additionally requires every
//! record's `schema` to equal [`EVENT_SCHEMA_V0`](crate::EVENT_SCHEMA_V0)
//! and, when the dev-tree schema file is present, that it hash identically
//! to the compiled-in copy, else [`ValidationFinding::SchemaDrift`]. An
//! absent file means an installed binary (embed-only validation).

mod kinds;

use self::kinds::KIND_TABLE;
use crate::EVENT_SCHEMA_V0;
use crate::checker::{StreamChecker, StreamFinding};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// One validation defect; empty means the stream validates clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFinding {
    /// Structural defect from the stream checks.
    Stream(StreamFinding),
    /// Record `schema` is present but not the frozen const.
    SchemaMismatch {
        /// 1-based physical line number.
        line: usize,
        /// Offending schema value.
        found: String,
    },
    /// On-disk schema file hash differs from the compiled-in copy.
    SchemaDrift {
        /// Compiled-in hash (hex).
        expected: String,
        /// On-disk hash (hex), or `"unreadable"`.
        actual: String,
    },
    /// The stream file itself could not be read (fail-closed, never clean).
    Unreadable {
        /// I/O detail.
        detail: String,
    },
}

impl std::fmt::Display for ValidationFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(finding) => write!(f, "{finding}"),
            Self::SchemaMismatch { line, found } => {
                write!(
                    f,
                    "line {line}: schema is '{found}', want '{EVENT_SCHEMA_V0}'"
                )
            }
            Self::SchemaDrift { expected, actual } => {
                write!(f, "schema drift: disk {actual} != frozen {expected}")
            }
            Self::Unreadable { detail } => write!(f, "unreadable stream: {detail}"),
        }
    }
}

/// The frozen schema bytes compiled into this crate.
const EMBEDDED_SCHEMA: &str = include_str!("../../../schemas/event-v0.schema.json");

/// FNV-1a 64 over bytes (drift detection, not security).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Hex hash of the compiled-in frozen schema (the freeze pin).
#[must_use]
pub fn schema_fnv1a_hex() -> String {
    format!("{:016x}", fnv1a64(EMBEDDED_SCHEMA.as_bytes()))
}

/// Schema bytes resolved for drift detection: the single best-effort
/// fallback shared by [`validate_file`] and `selftest synthetic`.
///
/// Decision (fix-report-installed-schema): embed-only validation with a
/// best-effort disk check. Shipping the schema resolved from the executable
/// would need an install layout plus fallback logic; the compiled-in copy
/// is already the freeze pin, so the on-disk read stays a dev-tree
/// tripwire only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedSchema {
    /// Dev-tree copy is present: drift-compare against these bytes.
    Disk(Vec<u8>),
    /// No dev-tree copy (installed binary): validate embed-only.
    Embedded,
    /// Present-but-unreadable: callers must fail closed.
    Unreadable,
}

impl ResolvedSchema {
    /// Bytes to feed [`validate_str`]: the disk copy when present, else the
    /// embedded copy. `None` only for [`Self::Unreadable`] (fail closed).
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Disk(disk) => Some(disk),
            Self::Embedded => Some(EMBEDDED_SCHEMA.as_bytes()),
            Self::Unreadable => None,
        }
    }
}

/// Best-effort resolution of the dev-tree schema copy (see [`ResolvedSchema`]).
#[must_use]
pub fn resolve_schema() -> ResolvedSchema {
    resolve_schema_at(&default_schema_path())
}

/// [`resolve_schema`] with an explicit on-disk schema location (test seam:
/// installed binaries have no on-disk copy, so tests pass a missing path).
#[must_use]
pub fn resolve_schema_at(schema_path: &Path) -> ResolvedSchema {
    match std::fs::read(schema_path) {
        Ok(disk) => ResolvedSchema::Disk(disk),
        // No dev tree (installed binary): nothing to compare against.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => ResolvedSchema::Embedded,
        // Fail-closed: a present-but-unreadable file cannot prove no drift.
        Err(_) => ResolvedSchema::Unreadable,
    }
}

/// Dev-tree location of the schema copy both resolvers consult.
fn default_schema_path() -> std::path::PathBuf {
    // Manifest-dir relative: one fewer `..` than the `include_str!` above,
    // which resolves from `src/`.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/event-v0.schema.json")
}

/// Validates the stream at `path`; empty means clean.
///
/// Embed-only validation with a best-effort disk check; see
/// [`resolve_schema`] for the decision record. A missing schema file
/// (installed binary) validates against the embedded copy; a
/// present-but-unreadable file fails closed with `SchemaDrift{unreadable}`.
pub fn validate_file(path: &Path) -> Vec<ValidationFinding> {
    validate_file_with_schema(path, &default_schema_path())
}

/// [`validate_file`] with an explicit on-disk schema location (test seam:
/// installed binaries have no on-disk copy, so tests pass a missing path).
fn validate_file_with_schema(path: &Path, schema_path: &Path) -> Vec<ValidationFinding> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            return vec![ValidationFinding::Unreadable {
                detail: err.to_string(),
            }];
        }
    };
    match resolve_schema_at(schema_path).bytes() {
        Some(bytes) => validate_reader(BufReader::new(file), bytes),
        None => {
            // Fail-closed: a present-but-unreadable file cannot prove no drift.
            let mut findings = validate_reader(BufReader::new(file), EMBEDDED_SCHEMA.as_bytes());
            if !findings
                .iter()
                .any(|finding| matches!(finding, ValidationFinding::Unreadable { .. }))
            {
                findings.push(ValidationFinding::SchemaDrift {
                    expected: schema_fnv1a_hex(),
                    actual: "unreadable".to_owned(),
                });
            }
            findings
        }
    }
}

/// Single-pass validation state shared by [`validate_str`] and
/// [`validate_reader`]: structural findings keep line order, schema
/// mismatches follow, drift closes. Memory is O(1) in the record count
/// plus one entry per finding (clean streams stay flat).
struct LineValidator<'kinds> {
    checker: StreamChecker<'kinds>,
    mismatches: Vec<ValidationFinding>,
}

impl Default for LineValidator<'_> {
    fn default() -> Self {
        Self {
            checker: StreamChecker::new(KIND_TABLE),
            mismatches: Vec::new(),
        }
    }
}

impl LineValidator<'_> {
    fn new() -> Self {
        Self::default()
    }

    fn push_line(&mut self, line_no: usize, line: &str) {
        self.checker.push_line(line_no, line);
        if line.trim().is_empty() {
            return;
        }
        if let Ok(record) = serde_json::from_str::<Value>(line)
            && let Some(found) = record.get("schema").and_then(Value::as_str)
            && found != EVENT_SCHEMA_V0
        {
            self.mismatches.push(ValidationFinding::SchemaMismatch {
                line: line_no,
                found: found.to_owned(),
            });
        }
    }

    fn finish(self, schema_disk_bytes: &[u8]) -> Vec<ValidationFinding> {
        let mut findings: Vec<ValidationFinding> = self
            .checker
            .finish()
            .into_iter()
            .map(ValidationFinding::Stream)
            .collect();
        findings.extend(self.mismatches);
        if fnv1a64(schema_disk_bytes) != fnv1a64(EMBEDDED_SCHEMA.as_bytes()) {
            findings.push(ValidationFinding::SchemaDrift {
                expected: schema_fnv1a_hex(),
                actual: format!("{:016x}", fnv1a64(schema_disk_bytes)),
            });
        }
        findings
    }
}

/// Validates stream `text` against caller-supplied on-disk schema bytes.
/// Pure core of [`validate_file`]; tamper tests drive this directly.
pub fn validate_str(text: &str, schema_disk_bytes: &[u8]) -> Vec<ValidationFinding> {
    let mut validator = LineValidator::new();
    for (index, line) in text.lines().enumerate() {
        validator.push_line(index + 1, line);
    }
    validator.finish(schema_disk_bytes)
}

/// Validates the stream at `path` and renders its summary in one pass:
/// the single-open replacement for `validate_file` + render used by
/// `report` (T16 X1: closes the validate-then-render TOCTOU and halves
/// I/O). Findings match [`validate_file`]; the summary is `Some` and
/// byte-identical to [`render_summary_reader`](crate::render_summary_reader)
/// whenever the pass completes. Callers gate on findings first: a `Some`
/// summary with non-empty findings must be discarded, as before.
pub fn validate_and_render_file(path: &Path) -> (Vec<ValidationFinding>, Option<String>) {
    validate_and_render_file_with_schema(path, &default_schema_path())
}

/// [`validate_and_render_file`] with an explicit on-disk schema location
/// (test seam, mirroring [`validate_file_with_schema`]).
fn validate_and_render_file_with_schema(
    path: &Path,
    schema_path: &Path,
) -> (Vec<ValidationFinding>, Option<String>) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            return (
                vec![ValidationFinding::Unreadable {
                    detail: err.to_string(),
                }],
                None,
            );
        }
    };
    match resolve_schema_at(schema_path).bytes() {
        Some(bytes) => validate_and_render_reader(BufReader::new(file), bytes),
        None => {
            // Fail-closed: a present-but-unreadable file cannot prove no drift.
            let (mut findings, summary) =
                validate_and_render_reader(BufReader::new(file), EMBEDDED_SCHEMA.as_bytes());
            if !findings
                .iter()
                .any(|finding| matches!(finding, ValidationFinding::Unreadable { .. }))
            {
                findings.push(ValidationFinding::SchemaDrift {
                    expected: schema_fnv1a_hex(),
                    actual: "unreadable".to_owned(),
                });
            }
            (findings, summary)
        }
    }
}

/// Maximum single line accepted by the streaming readers (M-SEC-02):
/// unbounded lines are a local memory-exhaustion vector.
pub const MAX_VALIDATE_LINE_BYTES: usize = 1 << 20;

/// Outcome of one bounded line read.
pub(crate) enum CappedLine {
    /// A line (newline/`\r\n` stripped, UTF-8 checked).
    Line(String),
    /// Clean EOF (no bytes).
    Eof,
    /// I/O error, invalid UTF-8, or overlong line (fail-closed detail).
    Unreadable(String),
}

/// Bounded `lines()`: at most `MAX_VALIDATE_LINE_BYTES + 2` bytes are
/// ever buffered per line (content cap plus the newline probe), so a
/// hostile overlong line refuses instead of OOMing (M-SEC-02).
/// Otherwise identical to `BufRead::lines` (`\n`/`\r\n` stripped).
pub(crate) fn next_line_capped(reader: &mut impl BufRead) -> CappedLine {
    let mut buf = Vec::new();
    match reader
        .by_ref()
        .take(MAX_VALIDATE_LINE_BYTES as u64 + 2)
        .read_until(b'\n', &mut buf)
    {
        Ok(0) => return CappedLine::Eof,
        Ok(_) => (),
        Err(err) => return CappedLine::Unreadable(err.to_string()),
    }
    if buf.ends_with(b"\n") {
        buf.pop();
        if buf.ends_with(b"\r") {
            buf.pop();
        }
    }
    if buf.len() > MAX_VALIDATE_LINE_BYTES {
        return CappedLine::Unreadable(format!(
            "line too large (over {MAX_VALIDATE_LINE_BYTES} bytes)"
        ));
    }
    match String::from_utf8(buf) {
        Ok(line) => CappedLine::Line(line),
        Err(err) => CappedLine::Unreadable(err.to_string()),
    }
}

/// Streaming [`validate_str`]: same findings, O(1) records in memory.
/// Stops fail-closed with [`ValidationFinding::Unreadable`] on any I/O
/// error (including invalid UTF-8) or overlong line.
pub fn validate_reader(
    mut reader: impl BufRead,
    schema_disk_bytes: &[u8],
) -> Vec<ValidationFinding> {
    let mut validator = LineValidator::new();
    let mut index = 0usize;
    loop {
        match next_line_capped(&mut reader) {
            CappedLine::Line(line) => {
                index += 1;
                validator.push_line(index, &line);
            }
            CappedLine::Eof => break,
            CappedLine::Unreadable(detail) => {
                return vec![ValidationFinding::Unreadable { detail }];
            }
        }
    }
    validator.finish(schema_disk_bytes)
}

/// Single-pass [`validate_reader`] + [`render_summary_reader`](crate::render_summary_reader):
/// one line loop feeding both the line validator and the summary
/// accumulator. Findings match [`validate_reader`]; the summary is `Some`
/// and byte-identical to the render pass whenever the read completes.
/// Stops fail-closed with [`ValidationFinding::Unreadable`] and no
/// summary on any I/O error (including invalid UTF-8).
pub fn validate_and_render_reader(
    mut reader: impl BufRead,
    schema_disk_bytes: &[u8],
) -> (Vec<ValidationFinding>, Option<String>) {
    let mut validator = LineValidator::new();
    let mut summary = crate::render::Summary::default();
    let mut index = 0usize;
    loop {
        match next_line_capped(&mut reader) {
            CappedLine::Line(line) => {
                index += 1;
                validator.push_line(index, &line);
                summary.push_line(&line);
            }
            CappedLine::Eof => break,
            CappedLine::Unreadable(detail) => {
                return (vec![ValidationFinding::Unreadable { detail }], None);
            }
        }
    }
    (validator.finish(schema_disk_bytes), Some(summary.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/session-v0.jsonl")
    }

    #[test]
    fn missing_schema_file_validates_clean() {
        // Installed-binary simulation: the on-disk schema copy is absent,
        // so validation falls back to the embedded copy (no drift).
        let missing = std::env::temp_dir()
            .join(format!("kryprobe-absent-{}", std::process::id()))
            .join("event-v0.schema.json");
        assert!(!missing.exists(), "defect: {missing:?} unexpectedly exists");
        let fixture = fixture_path();
        assert!(
            fixture.is_file(),
            "missing fixture at {}",
            fixture.display()
        );
        let findings = validate_file_with_schema(&fixture, &missing);
        assert!(findings.is_empty(), "installed-mode findings: {findings:?}");
    }

    #[test]
    fn differing_schema_file_still_flags_drift() {
        // The best-effort check must survive: a present-but-edited copy flags.
        let dir = std::env::temp_dir().join(format!("kryprobe-drift-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let decoy = dir.join("event-v0.schema.json");
        std::fs::write(&decoy, b"{\"edited\": true}").expect("decoy schema");
        let findings = validate_file_with_schema(&fixture_path(), &decoy);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, ValidationFinding::SchemaDrift { .. })),
            "edited schema copy must flag drift, got {findings:?}"
        );
    }

    #[test]
    fn resolve_schema_states() {
        // Missing path -> Embedded; directory -> Unreadable; real file -> Disk.
        let missing = std::env::temp_dir()
            .join(format!("kryprobe-resolve-{}", std::process::id()))
            .join("event-v0.schema.json");
        assert!(!missing.exists(), "defect: {missing:?} unexpectedly exists");
        assert_eq!(resolve_schema_at(&missing), ResolvedSchema::Embedded);
        assert_eq!(
            resolve_schema_at(&std::env::temp_dir()),
            ResolvedSchema::Unreadable
        );
        let schema =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/event-v0.schema.json");
        assert!(matches!(
            resolve_schema_at(&schema),
            ResolvedSchema::Disk(_)
        ));
        assert!(matches!(resolve_schema(), ResolvedSchema::Disk(_)));
    }

    #[test]
    fn unreadable_schema_path_fails_closed() {
        // A schema path that exists but cannot be read as a file (here a
        // directory) still fails closed with `unreadable` drift.
        let findings = validate_file_with_schema(&fixture_path(), &std::env::temp_dir());
        assert!(
            findings.iter().any(|f| matches!(
                f,
                ValidationFinding::SchemaDrift { actual, .. } if actual == "unreadable"
            )),
            "unreadable schema path must flag drift, got {findings:?}"
        );
    }
}
