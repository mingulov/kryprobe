// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded untrusted metadata-file loading (spec §5.7, frozen contract
//! ADR-0012 §(c)–(d)).
//!
//! Discipline, in order:
//!
//! 1. Read at most [`MAX_METADATA_BYTES`] + 1 bytes (chunked, never
//!    over-allocating on a lying size). Overflow refuses
//!    [`MetadataUnavailable::BudgetExceeded`] before parsing.
//! 2. Parse as JSON; refuse [`MetadataUnavailable::ParseFailed`] on any
//!    malformation.
//! 3. Helper policy: refuse files that select a helper executable
//!    (`executable` / `helper_executable` keys anywhere in the document).
//!    The helper binary is fixed at launch; metadata never names code.
//! 4. Convert through the frozen [`decode_metadata`]: nesting guard, typed
//!    conversion, and snapshot validation.
//!
//! File-open/read failures refuse [`MetadataUnavailable::ParseFailed`]
//! with static diagnostics: paths never appear in errors.
//!
//! [`MAX_METADATA_BYTES`]: kryprobe_core::workload::MAX_METADATA_BYTES
//! [`MetadataUnavailable`]: kryprobe_core::workload::MetadataUnavailable
//! [`decode_metadata`]: kryprobe_core::workload::decode_metadata

use kryprobe_core::workload::{
    MAX_METADATA_BYTES, MetadataSnapshot, MetadataUnavailable, decode_metadata,
};
use std::io::Read;
use std::path::Path;

/// Metadata keys that would select executable code. Any occurrence —
/// top-level or nested in entries — refuses the whole file. The frozen
/// schema has no such fields; this policy makes the "never shell out to a
/// metadata-named path" rule a loud refusal instead of a silent ignore.
const EXECUTABLE_KEYS: [&str; 2] = ["executable", "helper_executable"];

/// Read chunk: the file may be up to 1 MiB; stream it bounded.
const READ_CHUNK_BYTES: usize = 65_536;

/// Load and validate one metadata file. See the module docs for the
/// refusal order.
pub fn load_metadata_file(path: &Path) -> Result<MetadataSnapshot, MetadataUnavailable> {
    let mut file = std::fs::File::open(path).map_err(|_| MetadataUnavailable::ParseFailed)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|_| MetadataUnavailable::ParseFailed)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
    }
    if bytes.is_empty() {
        return Err(MetadataUnavailable::ParseFailed);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| MetadataUnavailable::ParseFailed)?;
    reject_executable_selection(&value)?;
    decode_metadata(&bytes)
}

/// Refuse documents that name executable code (recursive key scan; the
/// document is already size-bounded and the frozen nesting guard applies
/// on conversion).
fn reject_executable_selection(value: &serde_json::Value) -> Result<(), MetadataUnavailable> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if EXECUTABLE_KEYS.contains(&key.as_str()) {
                    return Err(MetadataUnavailable::ParseFailed);
                }
                reject_executable_selection(child)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                reject_executable_selection(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_core::workload::MAX_METADATA_ENTRIES;
    use std::io::Write;

    fn scratch(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kwh-meta-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn write_scratch(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = scratch(tag);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(bytes).expect("write");
        path
    }

    fn valid_doc(entries: &str) -> String {
        format!(
            r#"{{"collector":"t","snapshot_interval":{{"start_ns":1,"end_ns":2}},"kernel_identity":{{"known":"k"}},"entries":[{entries}]}}"#
        )
    }

    fn valid_entry() -> String {
        r#"{"display_name":"web-0","cgroup_id":7,"binding":{"method":"metadata_file","source":"operator_metadata_file","status":"asserted"}}"#.to_string()
    }

    #[test]
    fn valid_file_loads() {
        let path = write_scratch("valid", valid_doc(&valid_entry()).as_bytes());
        let snapshot = load_metadata_file(&path).expect("loads");
        assert_eq!(snapshot.entries.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_parse_failed() {
        let missing = scratch("missing").join("no-such-file.json");
        assert_eq!(
            load_metadata_file(&missing),
            Err(MetadataUnavailable::ParseFailed)
        );
    }

    #[test]
    fn empty_file_is_parse_failed() {
        let path = write_scratch("empty", b"");
        assert_eq!(
            load_metadata_file(&path),
            Err(MetadataUnavailable::ParseFailed)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn over_byte_budget_refuses_before_parsing() {
        let path = write_scratch("big", &vec![b'x'; MAX_METADATA_BYTES + 1]);
        assert_eq!(
            load_metadata_file(&path),
            Err(MetadataUnavailable::BudgetExceeded)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn exact_byte_budget_parses() {
        // Reach exactly the byte bound with known fields plus inert
        // trailing whitespace (valid JSON, ignored by conversion):
        // boundary loads with no unknown keys, so the case survives
        // strict schemas.
        let doc = valid_doc(&valid_entry());
        assert!(doc.len() < MAX_METADATA_BYTES);
        let mut padded = doc;
        padded.push_str(&" ".repeat(MAX_METADATA_BYTES - padded.len()));
        assert_eq!(padded.len(), MAX_METADATA_BYTES);
        let path = write_scratch("exact", padded.as_bytes());
        assert!(load_metadata_file(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn over_entry_count_refuses() {
        let entries = vec![valid_entry(); MAX_METADATA_ENTRIES + 1].join(",");
        let path = write_scratch("many", valid_doc(&entries).as_bytes());
        assert_eq!(
            load_metadata_file(&path),
            Err(MetadataUnavailable::BudgetExceeded)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_json_refuses() {
        let path = write_scratch("bad", b"{definitely not json");
        assert_eq!(
            load_metadata_file(&path),
            Err(MetadataUnavailable::ParseFailed)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn executable_keys_refuse_at_any_depth() {
        for doc in [
            valid_doc(&valid_entry()).replace(
                r#""collector":"t""#,
                r#""collector":"t","helper_executable":"/bin/evil""#,
            ),
            valid_doc(&valid_entry()).replace(
                r#""cgroup_id":7"#,
                r#""cgroup_id":7,"executable":"/bin/evil""#,
            ),
            valid_doc(&valid_entry()).replace(
                r#""status":"asserted""#,
                r#""status":"asserted","helper_executable":{"nested":true}}"#,
            ),
        ] {
            let path = write_scratch("exec", doc.as_bytes());
            assert_eq!(
                load_metadata_file(&path),
                Err(MetadataUnavailable::ParseFailed),
                "doc: {doc}"
            );
            let _ = std::fs::remove_file(&path);
        }
        // Lookalike keys are untouched by the executable policy, but the
        // amended contract closes every IPC decoder (R2
        // `deny_unknown_fields`): unknown fields refuse instead of being
        // discarded, matching the closed schemas.
        let lookalike = valid_doc(&valid_entry()).replace(
            r#""collector":"t""#,
            r#""collector":"t","executable_path_hint":"x""#,
        );
        let path = write_scratch("lookalike", lookalike.as_bytes());
        assert_eq!(
            load_metadata_file(&path),
            Err(MetadataUnavailable::ParseFailed)
        );
        let _ = std::fs::remove_file(&path);
    }
}
