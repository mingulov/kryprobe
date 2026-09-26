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

use kryprobe_abi::kcrypto_agg::{KAgg, KConfig, KCtl, KWhoKey, VAgg, VParams, VWho};
use kryprobe_abi::kcrypto_lifecycle::{LConfig, LEdge, LTfm};
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
    "task_real_parent",
    "task_tgid",
    "task_comm",
    "cra_blocksize",
    "cra_ivsize",
    "cra_min_keysize",
    "cra_max_keysize",
    "parent_ok",
    "params_ok",
    "_pad2",
];
const KAGG_WANT: &[&str] = &["fam", "op", "res", "ctx", "alg", "drv"];
const VAGG_WANT: &[&str] = &[
    "calls", "bytes", "ok", "errors", "queued", "first_ns", "last_ns", "lat",
];
const KCTL_WANT: &[&str] = &["kind", "_p", "key_hash", "val0", "val1", "val2", "val3"];
const KWHOKEY_WANT: &[&str] = &["kh", "tgid", "_pad"];
const VWHO_WANT: &[&str] = &[
    "comm", "tid", "uid", "cgroup", "ppid", "pcomm", "stack", "calls", "first_ns", "last_ns",
];
const VPARAMS_WANT: &[&str] = &["blocksize", "ivsize", "min_keysize", "max_keysize"];
const LEDGE_WANT: &[&str] = &[
    "magic", "version", "edge", "site", "flags", "key", "ts_ns", "status", "aux", "invoc", "tfm",
    "drv",
];
const LTFM_WANT: &[&str] = &[
    "magic", "version", "edge", "site", "flags", "key", "ts_ns", "status", "aux", "aux2", "token",
    "name",
];
const LCONFIG_WANT: &[&str] = &[
    "magic",
    "version",
    "flags",
    "tfm_alg",
    "alg_drv",
    "sk_base",
    "refcnt_off",
    "refcnt_present",
    "req_base",
    "req_tfm",
    "reserved",
];

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
    assert_eq!(KWhoKey::FIELDS, KWHOKEY_WANT, "KWhoKey fields drifted");
    assert_eq!(VWho::FIELDS, VWHO_WANT, "VWho fields drifted");
    assert_eq!(VParams::FIELDS, VPARAMS_WANT, "VParams fields drifted");
    assert_eq!(LEdge::FIELDS, LEDGE_WANT, "LEdge fields drifted");
    assert_eq!(LTfm::FIELDS, LTFM_WANT, "LTfm fields drifted");
    assert_eq!(LConfig::FIELDS, LCONFIG_WANT, "LConfig fields drifted");
    // Doc side: every listed field appears backticked in the allowlist
    // doc (updating FIELDS + this test but forgetting the doc fails).
    let doc = allowlist_doc();
    for (what, fields) in [
        ("KConfig", KConfig::FIELDS),
        ("KAgg", KAgg::FIELDS),
        ("VAgg", VAgg::FIELDS),
        ("KCtl", KCtl::FIELDS),
        ("KWhoKey", KWhoKey::FIELDS),
        ("VWho", VWho::FIELDS),
        ("VParams", VParams::FIELDS),
        ("LEdge", LEdge::FIELDS),
        ("LTfm", LTfm::FIELDS),
        ("LConfig", LConfig::FIELDS),
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

#[test]
fn field_lists_match_declarations() {
    // R2-04: FIELDS↔declaration binding — every pattern below
    // names EVERY field (no `..rest`, literals in FIELDS order):
    // a struct gaining/losing/renaming a field fails COMPILE
    // here, so FIELDS cannot drift from the declaration it
    // claims to mirror. (BPF-read binding is empirical: the
    // record-tap lane test scans every raw transport byte for
    // secret markers — any undeclared secret capture trips it.)
    let KConfig {
        sk_req_base,
        async_tfm,
        tfm_alg,
        alg_name,
        alg_drv,
        task_flags,
        pf_kthread,
        aead_cryptlen_off,
        ahash_nbytes_off,
        shash_base,
        _pad,
        task_real_parent,
        task_tgid,
        task_comm,
        cra_blocksize,
        cra_ivsize,
        cra_min_keysize,
        cra_max_keysize,
        parent_ok,
        params_ok,
        _pad2,
    } = KConfig::default();
    let _ = (
        sk_req_base,
        async_tfm,
        tfm_alg,
        alg_name,
        alg_drv,
        task_flags,
        pf_kthread,
        aead_cryptlen_off,
        ahash_nbytes_off,
        shash_base,
        _pad,
        task_real_parent,
        task_tgid,
        task_comm,
        cra_blocksize,
        cra_ivsize,
        cra_min_keysize,
        cra_max_keysize,
        parent_ok,
        params_ok,
        _pad2,
    );
    let KAgg {
        fam,
        op,
        res,
        ctx,
        alg,
        drv,
    } = KAgg {
        fam: 0,
        op: 0,
        res: 0,
        ctx: 0,
        alg: [0; 16],
        drv: [0; 16],
    };
    let _ = (fam, op, res, ctx, alg, drv);
    let VAgg {
        calls,
        bytes,
        ok,
        errors,
        queued,
        first_ns,
        last_ns,
        lat,
    } = VAgg::default();
    let _ = (calls, bytes, ok, errors, queued, first_ns, last_ns, lat);
    let KCtl {
        kind,
        _p,
        key_hash,
        val0,
        val1,
        val2,
        val3,
    } = KCtl::default();
    let _ = (kind, _p, key_hash, val0, val1, val2, val3);
    let KWhoKey { kh, tgid, _pad } = KWhoKey::default();
    let _ = (kh, tgid, _pad);
    let VWho {
        comm,
        tid,
        uid,
        cgroup,
        ppid,
        pcomm,
        stack,
        calls,
        first_ns,
        last_ns,
    } = VWho::default();
    let _ = (
        comm, tid, uid, cgroup, ppid, pcomm, stack, calls, first_ns, last_ns,
    );
    let VParams {
        blocksize,
        ivsize,
        min_keysize,
        max_keysize,
    } = VParams::default();
    let _ = (blocksize, ivsize, min_keysize, max_keysize);
    let LEdge {
        magic,
        version,
        edge,
        site,
        flags,
        key,
        ts_ns,
        status,
        aux,
        invoc,
        tfm,
        drv,
    } = LEdge {
        magic: 0,
        version: 0,
        edge: 0,
        site: 0,
        flags: 0,
        key: 0,
        ts_ns: 0,
        status: 0,
        aux: 0,
        invoc: 0,
        tfm: 0,
        drv: [0; 64],
    };
    let _ = (
        magic, version, edge, site, flags, key, ts_ns, status, aux, invoc, tfm, drv,
    );
    let LTfm {
        magic,
        version,
        edge,
        site,
        flags,
        key,
        ts_ns,
        status,
        aux,
        aux2,
        token,
        name,
    } = LTfm {
        magic: 0,
        version: 0,
        edge: 0,
        site: 0,
        flags: 0,
        key: 0,
        ts_ns: 0,
        status: 0,
        aux: 0,
        aux2: 0,
        token: 0,
        name: [0; 64],
    };
    let _ = (
        magic, version, edge, site, flags, key, ts_ns, status, aux, aux2, token, name,
    );
    let LConfig {
        magic,
        version,
        flags,
        tfm_alg,
        alg_drv,
        sk_base,
        refcnt_off,
        refcnt_present,
        req_base,
        req_tfm,
        reserved,
    } = LConfig {
        magic: 0,
        version: 0,
        flags: 0,
        tfm_alg: 0,
        alg_drv: 0,
        sk_base: 0,
        refcnt_off: 0,
        refcnt_present: 0,
        req_base: 0,
        req_tfm: 0,
        reserved: [0; 24],
    };
    let _ = (
        magic,
        version,
        flags,
        tfm_alg,
        alg_drv,
        sk_base,
        refcnt_off,
        refcnt_present,
        req_base,
        req_tfm,
        reserved,
    );
}
