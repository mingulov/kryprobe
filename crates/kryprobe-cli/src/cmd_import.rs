// SPDX-License-Identifier: GPL-3.0-or-later
//! `import FILE`: read one osslscope report or p11scope profile doc and
//! emit one shell JSONL record (D6) to stdout (unprivileged; exit 0 ok,
//! 2 unreadable file / invalid JSON / unknown marker naming the marker,
//! 1 internal failure).
//!
//! Detection keys on the doc's own versioned marker (adapters); the
//! full original doc rides `native` verbatim, so import is lossless.

use kryprobe_report::JsonlWriter;
use kryprobe_report::adapters::{self, ImportError};
use std::io::{Read, Write};
use std::path::Path;

/// Session id stamped on the one-record import stream.
const IMPORT_SESSION: &str = "session:import";

/// Maximum import file accepted (M-SEC-02): unbounded reads are a
/// local memory-exhaustion vector.
const MAX_IMPORT_BYTES: usize = 4 << 20;

/// Reads an import file with a hard cap (the token-worker `take(+1)`
/// probe idiom): over-cap refuses with a size error, never parses.
fn read_import_capped(file: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(file)
        .and_then(|f| {
            f.take(MAX_IMPORT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| ())
        })
        .map_err(|err| format!("import: cannot read {}: {err}", file.display()))?;
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "import: {} too large ({} bytes, max {MAX_IMPORT_BYTES})",
            file.display(),
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Rejects an import defect on stderr (exit 2): unreadable bytes,
/// invalid JSON, or an unknown marker — always naming what was found.
fn reject(err: &ImportError, stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(stderr, "import: {err}");
    2
}

/// Runs `import`: parse → detect → adapt → one envelope record
/// (kind `import_shell`) to stdout.
pub fn run(file: &Path, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let bytes = match read_import_capped(file) {
        Ok(bytes) => bytes,
        Err(detail) => {
            let _ = writeln!(stderr, "{detail}");
            return 2;
        }
    };
    let shell = match adapters::adapt_bytes(&bytes) {
        Ok(shell) => shell,
        Err(err) => return reject(&err, stderr),
    };
    let mut writer = JsonlWriter::new(IMPORT_SESSION);
    if let Err(err) = adapters::emit_shell(&mut writer, &shell) {
        let _ = writeln!(stderr, "import: cannot serialize shell: {err}");
        return 1;
    }
    match stdout.write_all(writer.finish().as_bytes()) {
        Ok(()) => 0,
        Err(err) => {
            let _ = writeln!(stderr, "import: cannot write stdout: {err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_report::adapters::{IMPORT_SHELL_KIND, SHELL_KEYS, SHELL_SCHEMA_V1};

    /// Minimal versioned p11scope profile doc (current marker).
    const P11_MIN: &str =
        r#"{"schema":"p11scope/observed-profile/v3","capture":{"mode":"profile"}}"#;

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("kryprobe-k3-4-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn import_run_emits_shell_exit_0() {
        let dir = scratch_dir("ok");
        let file = dir.join("profile.json");
        std::fs::write(&file, P11_MIN).expect("write input");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(run(&file, &mut stdout, &mut stderr), 0);
        assert!(stderr.is_empty(), "clean run stays quiet");
        let line = String::from_utf8(stdout).expect("utf-8");
        assert!(
            line.ends_with('\n') && !line.trim().contains('\n'),
            "one JSONL record"
        );
        let record: serde_json::Value =
            serde_json::from_str(line.trim_end()).expect("record parses");
        assert_eq!(record["schema"], "kryprobe.event/v0");
        assert_eq!(record["kind"], IMPORT_SHELL_KIND);
        let shell = &record["payload"];
        let mut keys: Vec<&str> = shell
            .as_object()
            .expect("shell object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut want = SHELL_KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(keys, want);
        assert_eq!(shell["schema"], SHELL_SCHEMA_V1);
        assert_eq!(shell["source"], "p11scope");
        // Lossless at the CLI boundary too: `native` is the input doc.
        let original: serde_json::Value = serde_json::from_str(P11_MIN).expect("input parses");
        assert_eq!(shell["native"], original);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shell_schema_matches_shell_keys() {
        // 3B-M7: `schemas/shell-v1.schema.json` requires exactly the
        // emitted shell keys — schema and emitter cannot drift.
        let schema = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/shell-v1.schema.json");
        let text = std::fs::read_to_string(&schema).expect("shell schema reads");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("schema parses");
        let mut required: Vec<&str> = doc["required"]
            .as_array()
            .expect("required array")
            .iter()
            .map(|key| key.as_str().expect("string key"))
            .collect();
        required.sort_unstable();
        let mut want = SHELL_KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(required, want);
        assert_eq!(doc["properties"]["schema"]["const"], SHELL_SCHEMA_V1);
    }

    #[test]
    fn import_run_oversize_exit_2_names_limit() {
        // M-SEC-02: unbounded import reads are a local
        // memory-exhaustion vector — over 4 MiB refuses with a size
        // error, never parses.
        let dir = scratch_dir("oversize");
        let file = dir.join("huge.json");
        let big = "x".repeat(4 * 1024 * 1024 + 1);
        std::fs::write(&file, &big).expect("write input");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(run(&file, &mut stdout, &mut stderr), 2);
        assert!(stdout.is_empty());
        let detail = String::from_utf8(stderr).expect("utf-8");
        assert!(detail.contains("too large"), "size error, got: {detail}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn import_run_unknown_marker_exit_2_names_it() {
        let dir = scratch_dir("marker");
        let file = dir.join("weird.json");
        std::fs::write(&file, r#"{"schema":"p11scope/observed-profile/v9"}"#).expect("write");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(run(&file, &mut stdout, &mut stderr), 2);
        assert!(stdout.is_empty());
        let detail = String::from_utf8(stderr).expect("utf-8");
        assert!(
            detail.contains("p11scope/observed-profile/v9"),
            "names the marker: {detail}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn import_run_bad_input_exit_2() {
        // Missing file, invalid JSON, and non-object docs are all
        // invalid input (exit 2), never silent and never 0.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let missing =
            std::env::temp_dir().join(format!("kryprobe-k3-4-absent-{}.json", std::process::id()));
        assert_eq!(run(&missing, &mut stdout, &mut stderr), 2);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("cannot read"),
            "missing file names itself"
        );

        let dir = scratch_dir("bad");
        for (name, body) in [("broken.json", "not json"), ("array.json", "[1]")] {
            let file = dir.join(name);
            std::fs::write(&file, body).expect("write");
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            assert_eq!(run(&file, &mut stdout, &mut stderr), 2, "{name}");
            assert!(stdout.is_empty());
            assert!(!stderr.is_empty(), "{name} explains itself");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A writer that always fails (exit-1 probe for the stdout leg).
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("boom"))
        }
    }

    #[test]
    fn import_run_stdout_failure_exit_1() {
        let dir = scratch_dir("stdout");
        let file = dir.join("profile.json");
        std::fs::write(&file, P11_MIN).expect("write input");
        let mut stderr = Vec::new();
        assert_eq!(run(&file, &mut FailingWriter, &mut stderr), 1);
        assert!(
            String::from_utf8(stderr)
                .expect("utf-8")
                .contains("cannot write stdout")
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
