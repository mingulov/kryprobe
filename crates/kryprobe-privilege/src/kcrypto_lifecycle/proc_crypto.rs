// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded startup `/proc/crypto` enrichment (T07.5): a
//! point-in-time registry snapshot for CURRENT-context joins.
//!
//! The snapshot is inventory, never proof: it records which
//! (name, driver, type, priority, module, flags) tuples the
//! registry offered WHEN READ. Joins against it answer "what does
//! the registry offer NOW" — never "what did this generation use"
//! (registrations come and go; a current tuple proves nothing
//! about an earlier allocation). Dynamic registration tracking
//! stays outside R1: no refresh, no watch, no diff — one bounded
//! read at bring-up.
//!
//! Bounds (startup-only DoS envelope): the read caps at
//! [`MAX_PROC_CRYPTO_BYTES`], entries cap at
//! [`MAX_PROC_CRYPTO_ENTRIES`], and field values cap at
//! [`MAX_FIELD_CHARS`]. Breaching the read or entry cap flags
//! [`ProcCryptoSnapshot::truncated`]; a breached value cap flags
//! the entry ([`ProcCryptoEntry::truncated`]) — partial inventory
//! is recorded, never silently complete.
//!
//! Parse discipline: blocks split on blank lines; lines split on
//! the FIRST `:` (keys like `min keysize` contain spaces —
//! splitting past the first colon would eat them); keys and values
//! trim ASCII whitespace. Nameless blocks drop (the name keys the
//! entry — a block without one inventories nothing). Repeated keys
//! resolve last-wins (standard map insert — pinned by test).
//! Unparsable priorities resolve `None` (the entry stands — an
//! unreadable rank must not delete inventory). Lines without a
//! colon, and empty blocks, skip quietly (line-level tolerance;
//! block-level strictness on the name only).

use std::time::SystemTime;

/// Read cap: the first megabyte of `/proc/crypto` (live files run
/// ~20 KB — the cap only bites on corruption; breaching flags
/// [`ProcCryptoSnapshot::truncated`]).
pub const MAX_PROC_CRYPTO_BYTES: usize = 1 << 20;

/// Entry cap: 4096 registry blocks (live files carry dozens —
/// breaching stops the parse and flags
/// [`ProcCryptoSnapshot::truncated`]).
pub const MAX_PROC_CRYPTO_ENTRIES: usize = 4096;

/// Field-value cap: 1024 characters (live values run <128 —
/// breaching truncates the value and flags
/// [`ProcCryptoEntry::truncated`]).
pub const MAX_FIELD_CHARS: usize = 1024;

/// One registry block: the tuple `/proc/crypto` offered for `name`
/// at snapshot time. Every field but `name` is `None` where the
/// block did not supply it or it did not safely resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcCryptoEntry {
    /// Block key (`name` — blocks without one drop at parse).
    pub name: String,
    /// Selected driver (`driver`), where supplied.
    pub driver: Option<String>,
    /// Algorithm family (`type`: `skcipher`, `aead`, ...), where supplied.
    pub entry_type: Option<String>,
    /// Selection rank (`priority` as u32), where supplied and parsing.
    pub priority: Option<u32>,
    /// Providing module (`module`), where supplied.
    pub module: Option<String>,
    /// Flag word (`flags`), where supplied (absent on kernels that
    /// do not emit it — see the host inventory).
    pub flags: Option<String>,
    /// Some value in this block breached [`MAX_FIELD_CHARS`] and
    /// truncated (partial inventory — recorded, never silent).
    pub truncated: bool,
}

/// A point-in-time registry snapshot: entries in file order plus
/// the read timestamp and the bound verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcCryptoSnapshot {
    /// Wall-clock read time (staleness context — the snapshot is
    /// one read, never refreshed).
    pub at: SystemTime,
    /// Parsed entries in file order (nameless blocks dropped).
    pub entries: Vec<ProcCryptoEntry>,
    /// A bound breached (read cap or entry cap — inventory below
    /// is partial; see [`MAX_PROC_CRYPTO_BYTES`]).
    pub truncated: bool,
}

impl ProcCryptoSnapshot {
    /// Highest-priority entry named `name` (the kernel selects the
    /// same winner a chase resolves — current context only, never
    /// proof of what an earlier allocation used). Entries without
    /// a parsable priority lose to any ranked entry; unranked ties
    /// keep file order (first wins).
    #[must_use]
    pub fn winning_driver(&self, name: &str) -> Option<&ProcCryptoEntry> {
        let mut best: Option<&ProcCryptoEntry> = None;
        for entry in &self.entries {
            if entry.name != name {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => match (b.priority, entry.priority) {
                    // Unranked entries never displace (file order
                    // wins unranked ties by keeping the first).
                    (_, None) => false,
                    // Any rank beats no rank.
                    (None, Some(_)) => true,
                    // Strictly greater wins; ties keep the first.
                    (Some(p), Some(q)) => q > p,
                },
            };
            if better {
                best = Some(entry);
            }
        }
        best
    }
}

/// Cap one field value at [`MAX_FIELD_CHARS`] (char boundary —
/// never splits UTF-8); reports whether it truncated.
fn cap_value(value: &str) -> (String, bool) {
    if value.chars().count() <= MAX_FIELD_CHARS {
        return (value.to_owned(), false);
    }
    let capped: String = value.chars().take(MAX_FIELD_CHARS).collect();
    (capped, true)
}

/// Parse one registry block (non-blank lines, first-colon split).
/// Returns `None` for nameless blocks (nothing to inventory).
fn parse_block(lines: &[&str]) -> Option<ProcCryptoEntry> {
    let mut fields: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        fields.insert(key.trim(), value.trim());
    }
    let name = fields.get("name").filter(|n| !n.is_empty())?;
    let mut truncated = false;
    let mut take = |key: &str| -> Option<String> {
        fields.get(key).map(|v| {
            let (capped, cut) = cap_value(v);
            truncated |= cut;
            capped
        })
    };
    let priority = fields.get("priority").and_then(|v| v.parse::<u32>().ok());
    Some(ProcCryptoEntry {
        name: (*name).to_owned(),
        driver: take("driver"),
        entry_type: take("type"),
        priority,
        module: take("module"),
        flags: take("flags"),
        truncated,
    })
}

/// Parse registry text into entries (pure seam — the reader below
/// stamps time). Blocks split on blank lines; the entry cap stops
/// the parse (reported via the returned flag).
fn parse_entries(text: &str) -> (Vec<ProcCryptoEntry>, bool) {
    let mut entries = Vec::new();
    let mut block: Vec<&str> = Vec::new();
    let mut capped = false;
    let flush = |block: &mut Vec<&str>, entries: &mut Vec<ProcCryptoEntry>| {
        if block.is_empty() {
            return;
        }
        if let Some(entry) = parse_block(block) {
            entries.push(entry);
        }
        block.clear();
    };
    for line in text.lines() {
        if entries.len() >= MAX_PROC_CRYPTO_ENTRIES {
            capped = true;
            break;
        }
        if line.trim().is_empty() {
            flush(&mut block, &mut entries);
        } else {
            block.push(line);
        }
    }
    if !capped {
        flush(&mut block, &mut entries);
    }
    (entries, capped)
}

/// Read and parse `/proc/crypto` (or any registry-text file —
/// the path is a parameter for tests): bounded read, stamped
/// snapshot. Read/UTF-8 failure returns the io error (the sensor
/// treats enrichment as optional — capture never refuses on it).
pub fn snapshot_proc_crypto(path: &std::path::Path) -> std::io::Result<ProcCryptoSnapshot> {
    use std::io::Read as _;
    let at = SystemTime::now();
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    let mut limited = (&mut file).take(MAX_PROC_CRYPTO_BYTES as u64 + 1);
    limited.read_to_end(&mut buf)?;
    let truncated_read = buf.len() > MAX_PROC_CRYPTO_BYTES;
    buf.truncate(MAX_PROC_CRYPTO_BYTES);
    let text = String::from_utf8(buf)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let (entries, capped) = parse_entries(&text);
    Ok(ProcCryptoSnapshot {
        at,
        entries,
        truncated: truncated_read || capped,
    })
}
