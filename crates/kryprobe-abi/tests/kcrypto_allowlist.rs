// SPDX-License-Identifier: GPL-3.0-or-later
//! K1 Task 3: capture-allowlist drift tripwire.
//!
//! The BPF mirrors are not serde, so each ABI mirror struct carries a
//! MANUALLY maintained `FIELDS` list (`kryprobe_abi::kcrypto_agg`).
//! This test pins each list against a hardcoded expectation AND against
//! `docs/kcrypto-capture-allowlist.md` (every field appears backticked
//! in the doc): adding a captured field without updating the list, the
//! expectation, and the doc fails the build. The friction is deliberate
//! (brief Step 2): the field set, the doc, and the canary move as one.

use kryprobe_abi::kcrypto_agg::{KAgg, KConfig, KCtl, VAgg};
use std::path::PathBuf;

const KCONFIG_WANT: &[&str] = &[
    "sk_req_base",
    "async_tfm",
    "tfm_alg",
    "alg_name",
    "alg_drv",
    "task_flags",
    "pf_kthread",
    "aead_cryptlen_off",
    "ahash_nbytes_off",
    "shash_base",
    "_pad",
];
const KAGG_WANT: &[&str] = &["fam", "op", "res", "ctx", "alg", "drv"];
const VAGG_WANT: &[&str] = &[
    "calls", "bytes", "ok", "errors", "queued", "first_ns", "last_ns", "lat",
];
const KCTL_WANT: &[&str] = &["kind", "_p", "key_hash", "val0", "val1", "val2", "val3"];

/// Workspace `docs/kcrypto-capture-allowlist.md` (absolute via the
/// crate manifest dir, so the test runs from any CWD).
fn allowlist_doc() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("kcrypto-capture-allowlist.md");
    std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "allowlist doc must be readable at {}: {err}",
            path.display()
        )
    })
}

#[test]
fn allowlist_field_set_matches_docs() {
    // Hardcoded expectations: a struct gaining/losing/renaming a field
    // without a matching FIELDS + doc update fails here first.
    assert_eq!(KConfig::FIELDS, KCONFIG_WANT, "KConfig fields drifted");
    assert_eq!(KAgg::FIELDS, KAGG_WANT, "KAgg fields drifted");
    assert_eq!(VAgg::FIELDS, VAGG_WANT, "VAgg fields drifted");
    assert_eq!(KCtl::FIELDS, KCTL_WANT, "KCtl fields drifted");
    // Doc side: every listed field appears backticked in the allowlist
    // doc (updating FIELDS + this test but forgetting the doc fails).
    let doc = allowlist_doc();
    for (what, fields) in [
        ("KConfig", KConfig::FIELDS),
        ("KAgg", KAgg::FIELDS),
        ("VAgg", VAgg::FIELDS),
        ("KCtl", KCtl::FIELDS),
    ] {
        for field in fields {
            let ticked = format!("`{field}`");
            assert!(
                doc.contains(&ticked),
                "{what}.{field} is missing from docs/kcrypto-capture-allowlist.md"
            );
        }
    }
    // The NEVER boundary rides the same doc (fail-closed privacy gate).
    assert!(
        doc.contains("NEVER"),
        "allowlist doc must carry the NEVER capture boundary"
    );
}
