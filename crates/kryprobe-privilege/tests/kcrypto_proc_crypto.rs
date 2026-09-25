// SPDX-License-Identifier: GPL-3.0-or-later
//! T07.5 `/proc/crypto` enrichment suite: bounded startup registry
//! snapshots in the privilege layer, without privilege.
//!
//! Pins the parser contract: blank-line blocks, first-colon
//! splits, name-keyed entries with optional driver/type/priority/
//! module/flags (missing or unresolvable stays `None` — never
//! fabricated); repeated keys resolve last-wins; nameless blocks
//! drop; read/entry/value caps bound the parse and flag
//! truncation (partial inventory is recorded, never silent).

use kryprobe_privilege::kcrypto_lifecycle::proc_crypto::{
    MAX_PROC_CRYPTO_BYTES, MAX_PROC_CRYPTO_ENTRIES, snapshot_proc_crypto,
};
use std::io::Write as _;

/// Write registry text to a unique temp file (no `tempfile` crate
/// in the tree — pid + name uniquifies; best-effort removal).
fn registry_file(name: &str, text: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "kryprobe-proc-crypto-{}-{name}",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&path).expect("temp registry must create");
    file.write_all(text.as_bytes())
        .expect("temp registry must write");
    path
}

const TWO_BLOCKS: &str = "name         : cbc(aes)\ndriver       : cryptd(cbc-aes-aesni)\nmodule       : cryptd\npriority     : 450\nrefcnt       : 1\nselftest     : passed\ninternal     : no\ntype         : skcipher\nasync        : yes\nblocksize    : 16\nmin keysize  : 16\nmax keysize  : 32\n\nname         : gcm(aes)\ndriver       : generic-gcm-vaes-avx512\nmodule       : aesni_intel\npriority     : 800\nrefcnt       : 1\nselftest     : passed\ninternal     : no\ntype         : aead\nasync        : no\nblocksize    : 1\nflags        : 0x1\n";

#[test]
fn wellformed_blocks_parse_named_fields() {
    let path = registry_file("good", TWO_BLOCKS);
    let snap = snapshot_proc_crypto(&path).expect("good registry must parse");
    let _ = std::fs::remove_file(&path);
    assert!(!snap.truncated);
    assert_eq!(snap.entries.len(), 2);
    let cbc = &snap.entries[0];
    assert_eq!(cbc.name, "cbc(aes)");
    assert_eq!(cbc.driver.as_deref(), Some("cryptd(cbc-aes-aesni)"));
    assert_eq!(cbc.entry_type.as_deref(), Some("skcipher"));
    assert_eq!(cbc.priority, Some(450));
    assert_eq!(cbc.module.as_deref(), Some("cryptd"));
    assert_eq!(cbc.flags, None, "no flags line, no flags");
    assert!(!cbc.truncated);
    let gcm = &snap.entries[1];
    assert_eq!(gcm.name, "gcm(aes)");
    assert_eq!(gcm.flags.as_deref(), Some("0x1"));
    // The snapshot stamps wall-clock read time (staleness context).
    assert!(
        snap.at <= std::time::SystemTime::now(),
        "stamp is not the future"
    );
}

#[test]
fn missing_fields_yield_none_not_fabrication() {
    let path = registry_file("sparse", "name : loner\n\nname : partial\ndriver : d\n\n");
    let snap = snapshot_proc_crypto(&path).expect("sparse registry must parse");
    let _ = std::fs::remove_file(&path);
    assert_eq!(snap.entries.len(), 2);
    let loner = &snap.entries[0];
    assert_eq!(loner.name, "loner");
    assert_eq!(loner.driver, None);
    assert_eq!(loner.entry_type, None);
    assert_eq!(loner.priority, None);
    assert_eq!(loner.module, None);
    assert_eq!(loner.flags, None);
    assert_eq!(snap.entries[1].driver.as_deref(), Some("d"));
}

#[test]
fn nameless_blocks_drop() {
    // A block without `name` inventories nothing — dropped, while
    // named neighbors survive.
    let path = registry_file(
        "nameless",
        "driver : ghost\npriority : 1\n\nname : real\ndriver : d\n\n",
    );
    let snap = snapshot_proc_crypto(&path).expect("nameless block must not fail the read");
    let _ = std::fs::remove_file(&path);
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].name, "real");
}

#[test]
fn repeated_field_last_wins() {
    // Duplicate keys resolve by standard map insert (last wins) —
    // pinned, so a kernel-side duplication can never silently take
    // the first.
    let path = registry_file(
        "repeated",
        "name : dup\ndriver : first\ndriver : second\npriority : 1\npriority : 9\n\n",
    );
    let snap = snapshot_proc_crypto(&path).expect("repeated keys must parse");
    let _ = std::fs::remove_file(&path);
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].driver.as_deref(), Some("second"));
    assert_eq!(snap.entries[0].priority, Some(9));
}

#[test]
fn unparsable_priority_yields_none_keeps_entry() {
    // An unreadable rank must not delete inventory: the entry
    // stands with `priority: None`.
    let path = registry_file("badprio", "name : odd\npriority : high\ndriver : d\n\n");
    let snap = snapshot_proc_crypto(&path).expect("bad priority must not fail the read");
    let _ = std::fs::remove_file(&path);
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].priority, None);
    assert_eq!(snap.entries[0].driver.as_deref(), Some("d"));
}

#[test]
fn colonless_lines_skip_values_keep_colons() {
    // Lines without a colon skip quietly (line-level tolerance);
    // values split on the FIRST colon only (a driver name carrying
    // a colon survives intact).
    let path = registry_file(
        "colons",
        "name : weird\ngarbage line without colon\ndriver : wrap(inner:tag)\n\n",
    );
    let snap = snapshot_proc_crypto(&path).expect("colonless line must not fail the read");
    let _ = std::fs::remove_file(&path);
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].driver.as_deref(), Some("wrap(inner:tag)"));
}

#[test]
fn keys_with_spaces_parse() {
    // `min keysize`-style keys contain spaces — the first-colon
    // split keeps them whole (parsed, then ignored as untracked).
    let path = registry_file(
        "spaces",
        "name : spaced\nmin keysize  : 16\nmax keysize  : 32\n\n",
    );
    let snap = snapshot_proc_crypto(&path).expect("spaced keys must parse");
    let _ = std::fs::remove_file(&path);
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].name, "spaced");
}

#[test]
fn empty_and_whitespace_input_parses_zero() {
    for (tag, text) in [("empty", ""), ("blank", "\n\n   \n\t\n")] {
        let path = registry_file(tag, text);
        let snap = snapshot_proc_crypto(&path).expect("empty input must parse");
        let _ = std::fs::remove_file(&path);
        assert!(snap.entries.is_empty(), "{tag} yields no entries");
        assert!(!snap.truncated);
    }
}

#[test]
fn unterminated_tail_block_still_parses() {
    // A file cut mid-stream (no trailing blank line) parses the
    // partial tail — truncation of INPUT is not truncation of
    // inventory while bounds hold.
    let path = registry_file("tail", "name : cut\ndriver : d");
    let snap = snapshot_proc_crypto(&path).expect("tail block must parse");
    let _ = std::fs::remove_file(&path);
    assert!(!snap.truncated);
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.entries[0].driver.as_deref(), Some("d"));
}

#[test]
fn overlong_value_truncates_and_flags_entry() {
    // A 2000-char driver truncates at the value cap with the entry
    // flagged — partial provenance, never silently complete.
    let long = "x".repeat(2000);
    let text = format!("name : big\ndriver : {long}\n\n");
    let path = registry_file("longval", &text);
    let snap = snapshot_proc_crypto(&path).expect("long value must parse");
    let _ = std::fs::remove_file(&path);
    assert!(!snap.truncated, "value cap is per-entry, not global");
    assert_eq!(snap.entries.len(), 1);
    let entry = &snap.entries[0];
    assert!(entry.truncated);
    assert_eq!(entry.driver.as_deref().map(str::len), Some(1024));
}

#[test]
fn overlong_name_truncates_and_flags_entry() {
    // T07-08/R9: a 2000-char block key caps at the same 1024-char
    // field bound — the block stays (inventory, not proof) with
    // `truncated` set, never silently complete.
    let long = "n".repeat(2000);
    let text = format!("name : {long}\\ndriver : d\\n\\n");
    let path = registry_file("longname", &text);
    let snap = snapshot_proc_crypto(&path).expect("long name must parse");
    let _ = std::fs::remove_file(&path);
    assert!(!snap.truncated, "name cap is per-entry, not global");
    assert_eq!(snap.entries.len(), 1);
    let entry = &snap.entries[0];
    assert!(entry.truncated);
    assert_eq!(entry.name.len(), 1024);
}

#[test]
fn entry_cap_stops_parse_and_flags_snapshot() {
    // Past 4096 entries the parse stops with `truncated` set —
    // bounded memory, loud stop.
    let mut text = String::new();
    for i in 0..MAX_PROC_CRYPTO_ENTRIES + 10 {
        text.push_str(&format!("name : alg{i}\ndriver : d{i}\n\n"));
    }
    let path = registry_file("many", &text);
    let snap = snapshot_proc_crypto(&path).expect("capped read must parse");
    let _ = std::fs::remove_file(&path);
    assert!(snap.truncated);
    assert_eq!(snap.entries.len(), MAX_PROC_CRYPTO_ENTRIES);
    assert_eq!(snap.entries[0].name, "alg0");
    assert_eq!(
        snap.entries[MAX_PROC_CRYPTO_ENTRIES - 1].name,
        format!("alg{}", MAX_PROC_CRYPTO_ENTRIES - 1)
    );
}

#[test]
fn read_cap_flags_snapshot() {
    // Past the 1 MiB read the snapshot flags truncated (the
    // parse covers the capped prefix only).
    let pad = "x".repeat(4096);
    let mut text = String::from("name : first\ndriver : d\n\n");
    while text.len() <= MAX_PROC_CRYPTO_BYTES + 4096 {
        text.push_str(&format!("name : {pad}\n\n"));
    }
    let path = registry_file("huge", &text);
    let snap = snapshot_proc_crypto(&path).expect("capped read must parse");
    let _ = std::fs::remove_file(&path);
    assert!(snap.truncated);
    assert_eq!(snap.entries[0].name, "first");
}

#[test]
fn missing_file_errors_loudly() {
    // The sensor treats enrichment as optional — but the reader
    // itself fails loud (no silent empty snapshot from a bad path).
    let missing = std::env::temp_dir().join(format!(
        "kryprobe-proc-crypto-{}-absent",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing);
    assert!(snapshot_proc_crypto(&missing).is_err());
}

#[test]
fn winning_driver_selects_highest_priority() {
    // The kernel selects the highest-priority same-named entry —
    // the join mirrors it (current context only).
    let path = registry_file(
        "winner",
        "name : pick\ndriver : low\npriority : 100\n\nname : pick\ndriver : high\npriority : 400\n\nname : pick\ndriver : mid\npriority : 200\n\n",
    );
    let snap = snapshot_proc_crypto(&path).expect("winner fixture must parse");
    let _ = std::fs::remove_file(&path);
    let win = snap.winning_driver("pick").expect("a winner exists");
    assert_eq!(win.driver.as_deref(), Some("high"));
    assert!(snap.winning_driver("absent").is_none());
}

#[test]
fn winning_driver_ties_keep_file_order_unranked_loses() {
    // Priority ties keep the first; any rank beats no rank; an
    // unranked-only name still resolves (first wins).
    let path = registry_file(
        "ties",
        "name : tie\ndriver : a\npriority : 50\n\nname : tie\ndriver : b\npriority : 50\n\nname : mixed\ndriver : u1\n\nname : mixed\ndriver : r\npriority : 1\n\nname : mixed\ndriver : u2\n\nname : bare\ndriver : only\n\n",
    );
    let snap = snapshot_proc_crypto(&path).expect("tie fixture must parse");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        snap.winning_driver("tie").unwrap().driver.as_deref(),
        Some("a")
    );
    assert_eq!(
        snap.winning_driver("mixed").unwrap().driver.as_deref(),
        Some("r")
    );
    assert_eq!(
        snap.winning_driver("bare").unwrap().driver.as_deref(),
        Some("only")
    );
}

#[test]
fn live_host_snapshot_reads_with_sane_shape() {
    // Unprivileged live read (honest skip without the file): every
    // entry names something, the stamp is fresh, bounds hold.
    if std::fs::metadata("/proc/crypto").is_err() {
        println!("SKIP: no /proc/crypto on this host");
        return;
    }
    let snap =
        snapshot_proc_crypto(std::path::Path::new("/proc/crypto")).expect("live read must parse");
    assert!(!snap.entries.is_empty(), "live registry is nonempty");
    assert!(!snap.truncated, "live registry fits the bounds");
    assert!(
        snap.at <= std::time::SystemTime::now(),
        "stamp is not the future"
    );
    for entry in &snap.entries {
        assert!(!entry.name.is_empty(), "nameless entries never surface");
    }
}
