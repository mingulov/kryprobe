// SPDX-License-Identifier: GPL-3.0-or-later
//! T07 transform-lifecycle suite: allocation entry/return capture +
//! generation assignment (T07.2), without privilege.
//!
//! Pins the tracker contract: alloc entry/return pairs join by the
//! BPF attempt token into opaque generations carrying requested/
//! selected provenance; ERR_PTR failures classify without a
//! generation; unknown tokens, resubmits, taint and twin drift
//! refuse loudly with counts; frontend pointers normalize to the
//! canonical base by the configured offset (checked).

use kryprobe_abi::kcrypto_lifecycle::{
    LEDGE_RETURN, LEDGE_SUBMIT, LEDGE_TAINTED, LTFM_MAGIC, LTFM_SITE_ALLOC_SK, LTFM_SITE_DESTROY,
    LTFM_SITE_SETAUTHSIZE, LTFM_SITE_SETKEY_AEAD, LTFM_SITE_SETKEY_SK, LTFM_TRUNCATED,
    LTFM_VERSION,
};
use kryprobe_privilege::kcrypto_lifecycle::tfm::{
    TfmDrop, TransformTracker, decode_tfm_record, normalize_frontend,
};

/// One 112-byte v1 `LTfm` record (little-endian twin of the ABI struct).
#[allow(clippy::too_many_arguments)]
fn tfm_bytes(
    edge: u8,
    site: u16,
    flags: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    aux: u32,
    aux2: u32,
    token: u64,
    name: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&LTFM_MAGIC.to_le_bytes());
    out[2] = LTFM_VERSION;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[6..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out[28..32].copy_from_slice(&aux.to_le_bytes());
    out[32..36].copy_from_slice(&aux2.to_le_bytes());
    out[40..48].copy_from_slice(&token.to_le_bytes());
    let n = name.len().min(64);
    out[48..48 + n].copy_from_slice(&name[..n]);
    out
}

fn alloc_entry(token: u64, name: &[u8], alg_type: u32, alg_mask: u32) -> Vec<u8> {
    tfm_bytes(
        LEDGE_SUBMIT,
        LTFM_SITE_ALLOC_SK,
        0,
        0,
        100,
        0,
        alg_type,
        alg_mask,
        token,
        name,
    )
}

fn alloc_return_ok(token: u64, frontend: u64, drv: &[u8]) -> Vec<u8> {
    tfm_bytes(
        LEDGE_RETURN,
        LTFM_SITE_ALLOC_SK,
        0,
        frontend,
        150,
        0,
        0,
        0,
        token,
        drv,
    )
}

fn alloc_return_err(token: u64, errno: i32) -> Vec<u8> {
    tfm_bytes(
        LEDGE_RETURN,
        LTFM_SITE_ALLOC_SK,
        0,
        0,
        150,
        errno,
        0,
        0,
        token,
        b"",
    )
}

/// Destroy entry: frontend `mem` + refcount value/observed bit, empty
/// name (T07.3 twin: key admits ANY u64 — null/ERR classifies at the
/// join as a no-op release, never at decode).
fn destroy_entry(token: u64, mem: u64, refcnt: u32, observed: u32) -> Vec<u8> {
    tfm_bytes(
        LEDGE_SUBMIT,
        LTFM_SITE_DESTROY,
        0,
        mem,
        100,
        0,
        refcnt,
        observed,
        token,
        b"",
    )
}

/// Destroy return: bare token (the call returns void — every other
/// word must be zero).
fn destroy_return(token: u64) -> Vec<u8> {
    tfm_bytes(
        LEDGE_RETURN,
        LTFM_SITE_DESTROY,
        0,
        0,
        150,
        0,
        0,
        0,
        token,
        b"",
    )
}

/// Config entry: frontend + length scalar, empty name (T07.4 twin:
/// key admits ANY u64 — null classifies at the join as unlinked,
/// never at decode; aux is the key length / authsize).
fn config_entry(site: u16, token: u64, frontend: u64, len: u32) -> Vec<u8> {
    tfm_bytes(LEDGE_SUBMIT, site, 0, frontend, 100, 0, len, 0, token, b"")
}

/// Config return: errno + token only (every other word zero — the
/// join replays the parked entry).
fn config_return(site: u16, token: u64, errno: i32) -> Vec<u8> {
    tfm_bytes(LEDGE_RETURN, site, 0, 0, 150, errno, 0, 0, token, b"")
}

#[test]
fn alloc_pair_assigns_generation_with_provenance() {
    let mut tracker = TransformTracker::new(16, 8, true);
    assert!(
        tracker
            .feed(&alloc_entry(2, b"kxcipher", 0x05, 0x8f))
            .is_empty(),
        "entry emits no generation yet"
    );
    tracker.feed(&alloc_return_ok(
        2,
        0xFFFF_8880_0000_1000,
        b"kxcipher-sync-t07a",
    ));
    let generations = tracker.generations();
    assert_eq!(generations.len(), 1, "one generation assigned");
    let generation = &generations[0];
    assert_eq!(generation.id, 1, "first opaque id");
    assert_eq!(generation.req_name, "kxcipher", "requested name preserved");
    assert_eq!(generation.alg_type, 0x05, "type provenance");
    assert_eq!(generation.alg_mask, 0x8f, "mask provenance");
    assert_eq!(
        generation.drv_name, "kxcipher-sync-t07a",
        "selected driver preserved"
    );
    assert!(!generation.name_truncated, "short name intact");
    assert_eq!(tracker.stats().completed, 1, "one paired return");
}

#[test]
fn alloc_failure_records_no_generation() {
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_entry(2, b"kxcipher-no-such", 0, 0));
    tracker.feed(&alloc_return_err(2, -2));
    assert!(
        tracker.generations().is_empty(),
        "ERR_PTR assigns no generation"
    );
    assert_eq!(tracker.stats().failed_allocs, 1, "failure counted");
    assert_eq!(tracker.stats().completed, 1, "attempt consumed");
    // The attempt is gone: a late second return for it refuses.
    tracker.feed(&alloc_return_err(2, -2));
    assert_eq!(tracker.stats().unknown_returns, 1, "no double completion");
}

#[test]
fn return_without_entry_refuses() {
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv"));
    assert!(tracker.generations().is_empty(), "no phantom generation");
    assert_eq!(tracker.stats().unknown_returns, 1, "unknown token counted");
}

#[test]
fn resubmit_keeps_first() {
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_entry(2, b"first", 0, 0));
    tracker.feed(&alloc_entry(2, b"second", 0, 0));
    assert_eq!(tracker.stats().submit_refused, 1, "resubmit refused");
    tracker.feed(&alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv"));
    let generations = tracker.generations();
    assert_eq!(generations.len(), 1);
    assert_eq!(generations[0].req_name, "first", "first entry stands");
}

#[test]
fn tainted_edges_refuse_quietly() {
    let mut tracker = TransformTracker::new(16, 8, true);
    let mut entry = alloc_entry(2, b"kxcipher", 0, 0);
    entry[6] = LEDGE_TAINTED as u8;
    tracker.feed(&entry);
    let mut ret = alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv");
    ret[6] = LEDGE_TAINTED as u8;
    // Tainted edges name no token: zero it like honest BPF.
    ret[40..48].copy_from_slice(&0u64.to_le_bytes());
    tracker.feed(&ret);
    assert!(tracker.generations().is_empty(), "taint disturbs nothing");
    assert_eq!(tracker.stats().tainted_refused, 2, "both taints counted");
}

#[test]
fn pending_table_bound_refuses() {
    let mut tracker = TransformTracker::new(1, 8, true);
    tracker.feed(&alloc_entry(2, b"first", 0, 0));
    tracker.feed(&alloc_entry(4, b"second", 0, 0));
    assert_eq!(tracker.stats().table_full, 1, "overflow counted");
    // The refused attempt never pairs.
    tracker.feed(&alloc_return_ok(4, 0xFFFF_8880_0000_1000, b"drv"));
    assert_eq!(tracker.stats().unknown_returns, 1, "refused stays refused");
    assert_eq!(tracker.generations().len(), 0, "no phantom");
}

#[test]
fn overlong_name_truncates_with_flag() {
    let mut tracker = TransformTracker::new(16, 8, true);
    let mut long = vec![b'a'; 63];
    long.extend_from_slice(b"extra-that-does-not-fit");
    let mut entry = alloc_entry(2, &long, 0, 0);
    // Only 63 bytes + NUL fit the 64-byte field; BPF flags truncation.
    entry[48 + 63] = 0;
    entry[6] = LTFM_TRUNCATED as u8;
    tracker.feed(&entry);
    tracker.feed(&alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv"));
    let generations = tracker.generations();
    assert_eq!(generations.len(), 1, "truncated still assigns");
    assert_eq!(generations[0].req_name.len(), 63, "bound kept");
    assert!(generations[0].name_truncated, "truncation flagged");
}

#[test]
fn normalize_frontend_adds_offset_checked() {
    assert_eq!(normalize_frontend(0x1000, 4), Some(0x1004));
    assert_eq!(normalize_frontend(0x1000, 0), Some(0x1000));
    assert_eq!(
        normalize_frontend(u64::MAX, 4),
        None,
        "wrapping offset refuses"
    );
}

#[test]
fn twin_bad_magic_and_version_refuse() {
    let mut tracker = TransformTracker::new(16, 8, true);
    let mut bad_magic = alloc_entry(2, b"kxcipher", 0, 0);
    bad_magic[0] = 0x00;
    tracker.feed(&bad_magic);
    let mut bad_version = alloc_entry(2, b"kxcipher", 0, 0);
    bad_version[2] = 0x7f;
    tracker.feed(&bad_version);
    assert_eq!(tracker.stats().bad_records, 2, "both counted");
    assert!(tracker.generations().is_empty(), "nothing admitted");
}

#[test]
fn twin_bad_site_refuses() {
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&tfm_bytes(
        LEDGE_SUBMIT,
        99,
        0,
        0,
        100,
        0,
        0,
        0,
        2,
        b"kxcipher",
    ));
    assert_eq!(tracker.stats().bad_records, 1, "garbage site counted");
}

#[test]
fn twin_key_rules_refuse() {
    let mut tracker = TransformTracker::new(16, 8, true);
    // Entry carries no pointer yet: nonzero is drift.
    let mut entry_key = alloc_entry(2, b"kxcipher", 0, 0);
    entry_key[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
    tracker.feed(&entry_key);
    // Success names a tfm: null is drift.
    tracker.feed(&alloc_return_ok(4, 0, b"drv"));
    // Failure names nothing: a pointer is drift.
    let mut fail_key = alloc_return_err(6, -2);
    fail_key[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
    tracker.feed(&fail_key);
    assert_eq!(tracker.stats().bad_records, 3, "all three counted");
}

#[test]
fn twin_destroy_halves_decode() {
    // T07.3: the destroy site decodes — entry admits any key
    // (frontend, incl. 0/ERR classified later as a no-op release)
    // with the refcount value/observed bit; the bare return carries
    // the token only.
    let raw = decode_tfm_record(&destroy_entry(2, 0xFFFF_8880_0000_1000, 1, 1))
        .expect("destroy entry decodes");
    assert_eq!(raw.key, 0xFFFF_8880_0000_1000);
    assert_eq!((raw.aux, raw.aux2), (1, 1));
    assert_eq!(raw.site, LTFM_SITE_DESTROY);
    let raw = decode_tfm_record(&destroy_entry(4, 0, 0, 0)).expect("null-mem entry decodes");
    assert_eq!(raw.key, 0);
    let raw = decode_tfm_record(&destroy_return(2)).expect("destroy return decodes");
    assert_eq!(raw.key, 0);
    assert_eq!(raw.status, 0);
}

#[test]
fn twin_destroy_drift_refuses() {
    // Entry status is always 0 (the call returns void — there is no
    // status to snapshot at entry either).
    let mut bad = destroy_entry(2, 0x1000, 1, 1);
    bad[24..28].copy_from_slice(&(-2i32).to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadDestroyStatus),
        "entry status refused"
    );
    // Entry aux2 carries ONLY the observed bit.
    let mut bad = destroy_entry(2, 0x1000, 1, 1);
    bad[32..36].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadDestroyAux2),
        "entry aux2 beyond observed refused"
    );
    // Destroy halves carry no name, ever.
    let mut bad = destroy_entry(2, 0x1000, 1, 1);
    bad[48] = b'x';
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadName),
        "entry name refused"
    );
    let mut bad = destroy_return(2);
    bad[48] = b'x';
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadName),
        "return name refused"
    );
    // The bare return: nonzero key/aux/aux2/status are all drift
    // (the void call reports nothing — the token joins the entry).
    let mut bad = destroy_return(2);
    bad[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadDestroyKey),
        "return key refused"
    );
    let mut bad = destroy_return(2);
    bad[28..32].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadDestroyAux),
        "return aux refused"
    );
    let mut bad = destroy_return(2);
    bad[32..36].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadDestroyAux),
        "return aux2 refused"
    );
    let mut bad = destroy_return(2);
    bad[24..28].copy_from_slice(&(-2i32).to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadDestroyStatus),
        "return status refused"
    );
}

#[test]
fn twin_reserved_pad_refuses() {
    // T07-10: bytes 36–39 are the emitter-zeroed alignment pad — a
    // changed reserved word is wire drift on every half.
    let mut bad = alloc_entry(7, b"aes", 0, 0);
    bad[36] = 1;
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadReserved),
        "alloc entry pad refused"
    );
    let mut bad = alloc_return_ok(7, 0x1008, b"aes-generic");
    bad[39] = 0xFF;
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadReserved),
        "alloc return pad refused"
    );
    let mut bad = destroy_entry(2, 0x1000, 1, 1);
    bad[37] = 1;
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadReserved),
        "destroy entry pad refused"
    );
}

#[test]
fn first_seen_admits_unknown_generation() {
    // T07.3: an op-first transform (allocated before attach) admits
    // with EMPTY creation provenance — unknown, never fabricated —
    // flagged first-seen so consumers distinguish it from "saw the
    // alloc, name unreadable". A second sighting of the same base
    // admits nothing (one lifetime, one id). T07-04/F05: the
    // submit's runtime-selected driver rides along (selected
    // metadata captured; allocation/requested name stay unknown).
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    assert_eq!(tracker.admit_first_seen(f1, "aes-generic", false), Some(1));
    assert_eq!(
        tracker.admit_first_seen(f1, "other", true),
        None,
        "no duplicate"
    );
    let gens = tracker.generations();
    assert_eq!(gens.len(), 1);
    assert!(gens[0].first_seen);
    assert_eq!(gens[0].req_name, "");
    assert_eq!(gens[0].drv_name, "aes-generic", "selected driver captured");
    assert!(!gens[0].drv_truncated, "unclipped submit reads complete");
    assert_eq!((gens[0].alg_type, gens[0].alg_mask), (0, 0));
    assert!(!gens[0].retired && !gens[0].ambiguous);
}

#[test]
fn first_seen_zero_link_counts_unlinked() {
    // T07.3: a 0 tfm word (unreadable request link) admits nothing
    // and counts `unlinked_ops` — a sensor-truth gap, never silent.
    let mut tracker = TransformTracker::new(16, 8, true);
    assert_eq!(tracker.admit_first_seen(0, "", false), None);
    assert_eq!(tracker.stats().unlinked_ops, 1);
    assert!(tracker.generations().is_empty());
}

#[test]
fn destroy_final_free_retires() {
    // T07.3: refcount 1 + observed at destroy entry proves the dec
    // freed under EITHER historical semantic (observer rule) — the
    // generation retires and leaves the live table.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0x05, 0x8f));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 1, 1));
    tracker.feed(&destroy_return(4));
    let gens = tracker.generations();
    assert_eq!(gens.len(), 1);
    assert!(gens[0].retired, "proved final-free retires");
    assert!(!gens[0].ambiguous);
    assert_eq!(tracker.stats().releases, 1);
    assert_eq!(tracker.stats().retired, 1);
    assert!(tracker.reuse_exact(), "no ambiguity anywhere");
}

#[test]
fn destroy_retained_refcount_marks_ambiguous() {
    // T07.3: refcount > 1 proves the destroy did NOT free — but a
    // LATER destroy may still free it, so the generation stays live
    // AND flags ambiguous (its eventual end is no longer exactly
    // knowable from this edge alone... it stays live so the final
    // destroy still joins and retires it).
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 3, 1));
    tracker.feed(&destroy_return(4));
    let gens = tracker.generations();
    assert!(!gens[0].retired, "retained destroy never retires");
    assert!(gens[0].ambiguous, "uncertain end flags ambiguity");
    assert_eq!(tracker.stats().ambiguous_releases, 1);
    assert!(!tracker.reuse_exact(), "ambiguity disables exact reuse");
    // The final destroy still joins (live) and retires it — the
    // ambiguity flag survives (history is history).
    tracker.feed(&destroy_entry(6, f1 + 8, 1, 1));
    tracker.feed(&destroy_return(6));
    let gens = tracker.generations();
    assert!(gens[0].retired && gens[0].ambiguous);
}

#[test]
fn destroy_unobserved_refcount_marks_ambiguous() {
    // T07.3: unreadable refcount (faulted read, null tfm) proves
    // nothing — ambiguity, never a retire, never a no-op.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 0, 0));
    tracker.feed(&destroy_return(4));
    let gens = tracker.generations();
    assert!(!gens[0].retired && gens[0].ambiguous);
    assert_eq!(tracker.stats().ambiguous_releases, 1);
}

#[test]
fn destroy_zero_refcount_is_impossible_input() {
    // T07.3: refcount 0 at destroy entry is impossible on a live
    // transform (use-after-free already) — fail closed into
    // ambiguity, never a retire.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 0, 1));
    tracker.feed(&destroy_return(4));
    let gens = tracker.generations();
    assert!(!gens[0].retired && gens[0].ambiguous);
}

#[test]
fn destroy_null_and_err_mem_are_noop_releases() {
    // T07.3: `crypto_destroy_tfm` returns early on IS_ERR_OR_NULL
    // (no dec-test, no free) — counted, disturb nothing.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, 0, 0, 0));
    tracker.feed(&destroy_return(4));
    tracker.feed(&destroy_entry(6, 0xFFFF_FFFF_FFFF_FFFE, 0, 0));
    tracker.feed(&destroy_return(6));
    assert_eq!(tracker.stats().noop_releases, 2);
    assert_eq!(tracker.stats().releases, 2, "no-ops still complete");
    assert!(!tracker.generations()[0].retired);
}

#[test]
fn destroy_unknown_base_counts() {
    // T07.3: a release for a never-admitted base (missed alloc AND
    // missed ops, or a foreign transform) counts — never a phantom
    // generation, never a retire of thin air.
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&destroy_entry(2, 0xFFFF_8880_0000_1000, 1, 1));
    tracker.feed(&destroy_return(2));
    assert_eq!(tracker.stats().unknown_releases, 1);
    assert!(tracker.generations().is_empty());
}

#[test]
fn destroy_always_final_mode_retires_unconditionally() {
    // T07.3: on kernels without `crypto_tfm.refcnt` (7.2+) every
    // observed destroy retires — the field's absence IS the proof
    // (unconditional destroy), not a gap.
    let mut tracker = TransformTracker::new(16, 8, false);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 0, 0));
    tracker.feed(&destroy_return(4));
    assert!(tracker.generations()[0].retired);
    assert_eq!(tracker.stats().retired, 1);
    assert!(tracker.reuse_exact());
}

#[test]
fn alloc_after_proved_retire_assigns_fresh_id() {
    // Rapid address reuse must NOT merge object lifetimes (plan
    // line 29): same frontend after a proved final-free is a new
    // lifetime with a fresh id — exact, since both ends are proved.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0x05, 0x8f));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 1, 1));
    tracker.feed(&destroy_return(4));
    tracker.feed(&alloc_entry(6, b"kxcipher", 0x05, 0x8f));
    tracker.feed(&alloc_return_ok(6, f1, b"drv"));
    let gens = tracker.generations();
    assert_eq!(gens.len(), 2);
    assert_eq!((gens[0].id, gens[1].id), (1, 2), "fresh id, never merged");
    assert!(gens[0].retired && !gens[1].retired);
    assert!(tracker.reuse_exact(), "proved ends keep reuse exact");
}

#[test]
fn alloc_for_live_base_forces_retire_as_ambiguous() {
    // A new alloc at a LIVE base means the old lifetime ended
    // unobserved (missed free): the old generation forced-retires
    // as ambiguous (never kept live — a stale destroy must not
    // merge lifetimes), the new one takes the base fresh.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"first", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&alloc_entry(4, b"second", 0, 0));
    tracker.feed(&alloc_return_ok(4, f1, b"drv"));
    let gens = tracker.generations();
    assert_eq!(gens.len(), 2);
    assert_eq!(gens[0].req_name, "first");
    assert!(gens[0].retired && gens[0].ambiguous, "forced ambiguous");
    assert_eq!(gens[1].req_name, "second");
    assert!(!gens[1].retired && !gens[1].ambiguous);
    assert_eq!(tracker.stats().forced_retires, 1);
    assert!(!tracker.reuse_exact());
}

#[test]
fn twin_config_halves_decode_per_site() {
    // T07.4: all three config sites decode — entry admits any key
    // (frontend, incl. 0 classified later as unlinked) with the
    // length scalar in aux; the errno return carries status +
    // token only.
    for site in [
        LTFM_SITE_SETKEY_SK,
        LTFM_SITE_SETAUTHSIZE,
        LTFM_SITE_SETKEY_AEAD,
    ] {
        let raw = decode_tfm_record(&config_entry(site, 2, 0xFFFF_8880_0000_1000, 32))
            .expect("config entry decodes");
        assert_eq!(raw.key, 0xFFFF_8880_0000_1000);
        assert_eq!((raw.aux, raw.aux2), (32, 0));
        assert_eq!(raw.site, site);
        let raw = decode_tfm_record(&config_entry(site, 4, 0, 16)).expect("null-key entry decodes");
        assert_eq!(raw.key, 0);
        let raw = decode_tfm_record(&config_return(site, 2, 0)).expect("config return decodes");
        assert_eq!((raw.key, raw.status), (0, 0));
        let raw = decode_tfm_record(&config_return(site, 2, -22)).expect("errno return decodes");
        assert_eq!(raw.status, -22);
    }
}

#[test]
fn twin_config_drift_refuses() {
    // Entry status is always 0 (the errno exists only at return).
    let mut bad = config_entry(LTFM_SITE_SETKEY_SK, 2, 0x1000, 32);
    bad[24..28].copy_from_slice(&(-2i32).to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadConfigStatus),
        "entry status refused"
    );
    // Entry aux2 is always 0 (no second scalar on this path).
    let mut bad = config_entry(LTFM_SITE_SETKEY_SK, 2, 0x1000, 32);
    bad[32..36].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadConfigAux2),
        "entry aux2 refused"
    );
    // Config halves carry no name, ever.
    let mut bad = config_entry(LTFM_SITE_SETKEY_SK, 2, 0x1000, 32);
    bad[48] = b'x';
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadName),
        "entry name refused"
    );
    // The errno return carries the token only: nonzero key refuses.
    let mut bad = config_return(LTFM_SITE_SETKEY_SK, 2, 0);
    bad[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadConfigKey),
        "return key refused"
    );
    // Return aux/aux2 are always 0 (the length lives on the entry).
    let mut bad = config_return(LTFM_SITE_SETKEY_SK, 2, 0);
    bad[28..32].copy_from_slice(&32u32.to_le_bytes());
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadConfigAux),
        "return aux refused"
    );
    let mut bad = config_return(LTFM_SITE_SETKEY_SK, 2, 0);
    bad[48] = b'x';
    assert_eq!(
        decode_tfm_record(&bad),
        Err(TfmDrop::BadName),
        "return name refused"
    );
}

#[test]
fn twin_config_unrecognized_status_is_truth_not_drift() {
    // A positive or out-of-range status still decodes: only 0
    // means success, everything else is a recorded failure — a
    // weird kernel return is truth, never twin drift.
    let raw = decode_tfm_record(&config_return(LTFM_SITE_SETKEY_SK, 2, 1))
        .expect("positive status decodes");
    assert_eq!(raw.status, 1);
    let raw = decode_tfm_record(&config_return(LTFM_SITE_SETKEY_SK, 2, -5000))
        .expect("out-of-range errno decodes");
    assert_eq!(raw.status, -5000);
}

#[test]
fn config_success_bumps_epoch_and_records() {
    // T07.4: a joined success records site/len/errno and bumps the
    // generation's epoch — one keying era per success.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0x05, 0x8f));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 4, 0));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 6, f1, 16));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 6, 0));
    let gens = tracker.generations();
    assert_eq!(gens.len(), 1);
    assert_eq!(gens[0].epoch, 2, "one bump per success");
    assert_eq!(gens[0].configs, 2);
    assert_eq!(gens[0].last_config_site, LTFM_SITE_SETKEY_SK);
    assert_eq!(gens[0].last_config_len, 16);
    assert_eq!(gens[0].last_config_errno, 0);
    assert_eq!(tracker.stats().configs_joined, 2);
    assert_eq!(tracker.stats().configs_failed, 0);
}

#[test]
fn config_failure_records_without_bump() {
    // A failed rekey changes no kernel state: the attempt records
    // (site/len/errno) but the epoch stands — one era, not two.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 4, 0));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 6, f1, 5));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 6, -22));
    let gens = tracker.generations();
    assert_eq!(gens[0].epoch, 1, "failure never bumps");
    assert_eq!(gens[0].configs, 2, "failure still records");
    assert_eq!(gens[0].last_config_len, 5);
    assert_eq!(gens[0].last_config_errno, -22);
    assert_eq!(tracker.stats().configs_joined, 2);
    assert_eq!(tracker.stats().configs_failed, 1);
}

#[test]
fn config_unknown_base_admits_first_seen() {
    // A config edge observes a live transform like an op edge:
    // unknown bases admit first-seen with EMPTY provenance, and
    // the success bumps the fresh generation's epoch.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&config_entry(LTFM_SITE_SETAUTHSIZE, 2, f1, 16));
    tracker.feed(&config_return(LTFM_SITE_SETAUTHSIZE, 2, 0));
    let gens = tracker.generations();
    assert_eq!(gens.len(), 1);
    assert!(gens[0].first_seen);
    assert!(gens[0].req_name.is_empty(), "no fabricated provenance");
    assert_eq!(gens[0].epoch, 1);
    assert_eq!(gens[0].last_config_site, LTFM_SITE_SETAUTHSIZE);
}

#[test]
fn config_null_key_is_unlinked() {
    // A null frontend names no transform: the pair joins (the
    // attempt was real) but attributes nothing — counted, never
    // a phantom generation.
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 2, 0, 32));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 2, 0));
    assert!(tracker.generations().is_empty());
    assert_eq!(tracker.stats().configs_joined, 1);
    assert_eq!(tracker.stats().config_unlinked, 1);
}

#[test]
fn config_cross_site_return_refuses_with_entry_kept() {
    // A setauthsize return for a parked setkey-sk token is twin-
    // valid halves with the wrong pairing: refused, entry kept,
    // and the true return still pairs.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32));
    tracker.feed(&config_return(LTFM_SITE_SETAUTHSIZE, 4, 0));
    assert_eq!(tracker.stats().mismatched_returns, 1);
    assert_eq!(tracker.stats().configs_joined, 0);
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 4, 0));
    assert_eq!(tracker.stats().configs_joined, 1);
    assert_eq!(tracker.generations()[0].epoch, 1);
}

#[test]
fn destroy_return_after_realloc_retires_nothing() {
    // R1/T07-01: the kernel frees before `crypto_destroy_tfm`
    // returns, so another CPU can reallocate the address between
    // the entry and the return. The old return must NOT retire the
    // new lifetime: it counts stale, the new id stays live, and
    // the forced retire on the realloc already voided reuse_exact.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 1, 1));
    // Realloc lands before the old destroy returns: forced retire.
    tracker.feed(&alloc_entry(6, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(6, f1, b"drv"));
    assert_eq!(tracker.stats().forced_retires, 1);
    tracker.feed(&destroy_return(4));
    assert_eq!(tracker.stats().stale_releases, 1, "old return goes stale");
    assert_eq!(tracker.stats().retired, 0, "nothing proved final");
    let gens = tracker.generations();
    assert_eq!(gens.len(), 2);
    assert!(gens[0].retired && gens[0].ambiguous, "forced old lifetime");
    assert!(!gens[1].retired, "new lifetime stays live");
    assert!(!tracker.reuse_exact(), "forced retire voids exactness");
}

#[test]
fn destroy_entry_unmapped_then_live_refuses() {
    // The entry observed no live lifetime; a base that became live
    // between the halves leaves the destroy's true target
    // unknowable (ring order is not kernel order) — the return
    // counts unknown and touches nothing.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&destroy_entry(2, f1 + 8, 1, 1));
    tracker.feed(&alloc_entry(4, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(4, f1, b"drv"));
    tracker.feed(&destroy_return(2));
    assert_eq!(tracker.stats().unknown_releases, 1);
    assert_eq!(tracker.stats().retired, 0);
    assert!(!tracker.generations()[0].retired, "newcomer untouched");
}

#[test]
fn overlapping_destroy_second_return_goes_stale() {
    // Two destroys overlap on one lifetime (double destroy): the
    // first return retires it proved; the second return finds its
    // bound generation gone and counts stale — never unknown (it
    // HAD entry evidence) and never a second retire.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 1, 1));
    tracker.feed(&destroy_entry(6, f1 + 8, 1, 1));
    tracker.feed(&destroy_return(4));
    assert_eq!(tracker.stats().retired, 1);
    tracker.feed(&destroy_return(6));
    assert_eq!(tracker.stats().stale_releases, 1);
    assert_eq!(tracker.stats().unknown_releases, 0);
    assert_eq!(tracker.stats().retired, 1, "retired exactly once");
}

#[test]
fn config_return_after_realloc_unlinks() {
    // Config twin of the destroy interleaving: a setkey straddling
    // a reuse must never bump the new lifetime's epoch.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32));
    tracker.feed(&alloc_entry(6, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(6, f1, b"drv"));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 4, 0));
    assert_eq!(tracker.stats().config_unlinked, 1);
    let gens = tracker.generations();
    assert_eq!(gens[1].epoch, 0, "newcomer epoch untouched");
    assert_eq!(gens[1].configs, 0, "newcomer configs untouched");
}

#[test]
fn config_entry_unmapped_then_live_unlinks() {
    // Unbound config whose base became live between the halves:
    // first-seen admission is refused (the entry observed no live
    // lifetime and the base is taken) — unlinked, never merged.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 2, f1, 32));
    tracker.feed(&alloc_entry(4, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(4, f1, b"drv"));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 2, 0));
    assert_eq!(tracker.stats().config_unlinked, 1);
    assert_eq!(tracker.generations().len(), 1, "no phantom admission");
    assert_eq!(tracker.generations()[0].epoch, 0);
}

#[test]
fn config_after_retire_admits_fresh_never_merges() {
    // The retired lifetime ended proved; a later config on the
    // same base is a NEW lifetime (base→single-live-id holds —
    // the tombstone keeps its epoch, the fresh id starts at 0
    // before its own success bumps it).
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 4, 0));
    tracker.feed(&destroy_entry(6, f1 + 8, 1, 1));
    tracker.feed(&destroy_return(6));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 8, f1, 16));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_SK, 8, 0));
    let gens = tracker.generations();
    assert_eq!(gens.len(), 2);
    assert!(gens[0].retired);
    assert_eq!(gens[0].epoch, 1, "tombstone keeps its epoch");
    assert_eq!(gens[1].id, 2, "fresh id, never merged");
    assert!(gens[1].first_seen);
    assert_eq!(gens[1].epoch, 1, "its own success bumps it");
    // T07-02: the fresh lifetime's creation boundary was never
    // observed (config-admitted) — chaining is no longer exactly
    // provable, so exact reuse voids even though both ends here
    // are proved.
    assert_eq!(tracker.stats().unobserved_boundary, 1);
    assert!(
        !tracker.reuse_exact(),
        "unobserved creation voids exact reuse"
    );
}

#[test]
fn config_on_first_seen_flags_uncertain_identity() {
    // T07-02 attack shape: an AEAD lifetime (alloc unhooked — the
    // creation boundary is never observable) admitted first-seen;
    // a missed final-free, an address reuse, and a config for the
    // NEW lifetime all land on the OLD id. The epoch bump is
    // best-effort AND the uncertainty is counted — F06 partial,
    // never a confident old identity.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.admit_first_seen(f1, "", false);
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_AEAD, 2, f1, 16));
    tracker.feed(&config_return(LTFM_SITE_SETKEY_AEAD, 2, 0));
    let gens = tracker.generations();
    assert_eq!(gens.len(), 1);
    assert!(gens[0].first_seen);
    assert_eq!(gens[0].epoch, 1, "best-effort attribution bumps");
    assert_eq!(tracker.stats().unobserved_boundary, 1);
    assert!(
        !tracker.reuse_exact(),
        "config on unobserved creation voids exactness"
    );
}

#[test]
fn finish_dangling_destroy_marks_live_bound_ambiguous() {
    // T07-06: a destroy entry whose return never arrives leaves
    // its end unknown — the still-live bound generation flags
    // ambiguous (stays live, end unproven) and exact reuse voids.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 1, 1));
    assert!(tracker.reuse_exact(), "exact before the close");
    tracker.finish();
    assert_eq!(tracker.stats().unfinished, 1);
    assert_eq!(tracker.stats().ambiguous_releases, 1);
    let gens = tracker.generations();
    assert!(!gens[0].retired, "unproven end never retires");
    assert!(gens[0].ambiguous, "unknown end flags ambiguity");
    assert!(!tracker.reuse_exact(), "dangling destroy voids exactness");
    // The late return finds no attempt — unknown, never joined.
    tracker.feed(&destroy_return(4));
    assert_eq!(tracker.stats().unknown_returns, 1);
    assert!(!tracker.generations()[0].retired);
}

#[test]
fn finish_dangling_destroy_after_proved_end_counts_only() {
    // T07-06 mirror: a second overlapping destroy still pending
    // when the first already retired the generation — the proved
    // end stands (no ambiguity), the dangling attempt counts.
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&destroy_entry(4, f1 + 8, 1, 1));
    tracker.feed(&destroy_entry(6, f1 + 8, 1, 1));
    tracker.feed(&destroy_return(4));
    assert!(tracker.generations()[0].retired);
    tracker.finish();
    assert_eq!(tracker.stats().unfinished, 1);
    assert_eq!(tracker.stats().ambiguous_releases, 0);
    assert!(
        !tracker.generations()[0].ambiguous,
        "proved end keeps the generation clean"
    );
    assert!(
        !tracker.reuse_exact(),
        "the unfinished attempt still voids session exactness"
    );
}

#[test]
fn finish_dangling_alloc_and_config_count_without_taint() {
    // T07-06: dangling alloc/config attempts finalize as unknown
    // outcomes — counted, but no generation exists to taint (alloc)
    // and lifetime boundaries are unaffected (config excludes the
    // unknown change from the epoch).
    let mut tracker = TransformTracker::new(16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, f1, b"drv"));
    tracker.feed(&config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32));
    tracker.feed(&alloc_entry(6, b"other", 0, 0));
    tracker.finish();
    assert_eq!(tracker.stats().unfinished, 2);
    assert_eq!(tracker.stats().ambiguous_releases, 0);
    let gens = tracker.generations();
    assert_eq!(gens.len(), 1, "dangling alloc assigns nothing");
    assert_eq!(gens[0].configs, 0, "unknown config excluded");
    assert_eq!(gens[0].epoch, 0);
    assert!(!tracker.reuse_exact(), "unfinished close voids exactness");
}

#[test]
fn cross_site_halves_refuse_as_mismatched() {
    // Twin-valid halves from different sites never pair: a destroy
    // return for an alloc token (and vice versa) refuses WITHOUT
    // consuming the parked entry (the true return still pairs).
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&tfm_bytes(
        LEDGE_RETURN,
        LTFM_SITE_DESTROY,
        0,
        0,
        150,
        0,
        0,
        0,
        2,
        b"",
    ));
    assert_eq!(tracker.stats().mismatched_returns, 1);
    assert_eq!(tracker.stats().completed, 0, "entry unconsumed");
    // The true alloc return still pairs afterwards.
    tracker.feed(&alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv"));
    assert_eq!(tracker.generations().len(), 1);
}

#[test]
fn d4_live_cap_refuses_new_generations() {
    // D4: the live table is bounded — a success completion past the
    // cap consumes the attempt but assigns nothing (failures never
    // needed a slot, so the refusal lands at completion, not entry).
    let mut tracker = TransformTracker::new(2, 8, true);
    for (token, base) in [(2u64, 0x1000u64), (4, 0x2000)] {
        tracker.feed(&alloc_entry(token, b"k", 0, 0));
        tracker.feed(&alloc_return_ok(token, base, b"drv"));
    }
    assert_eq!(tracker.generations().len(), 2);
    tracker.feed(&alloc_entry(6, b"k", 0, 0));
    tracker.feed(&alloc_return_ok(6, 0x3000, b"drv"));
    assert_eq!(tracker.generations().len(), 2, "third live refused");
    assert_eq!(tracker.stats().live_full, 1);
    assert_eq!(tracker.stats().completed, 3, "attempt still consumed");
    // First-seen hits the same bound.
    assert_eq!(tracker.admit_first_seen(0x4000, "", false), None);
    assert_eq!(tracker.stats().live_full, 2);
}

#[test]
fn d4_retired_history_is_fifo_bounded() {
    // D4: retired generations become FIFO tombstones capped at the
    // bound — oldest history evicts (counted), live entries never
    // evict, total memory stays O(3 × capacity).
    let mut tracker = TransformTracker::new(2, 8, true);
    for (token, base) in [(2u64, 0x1000u64), (4, 0x2000)] {
        tracker.feed(&alloc_entry(token, b"k", 0, 0));
        tracker.feed(&alloc_return_ok(token, base, b"drv"));
        tracker.feed(&destroy_entry(token + 100, base + 8, 1, 1));
        tracker.feed(&destroy_return(token + 100));
    }
    assert_eq!(tracker.generations().len(), 2);
    for (token, base) in [(6u64, 0x3000u64), (8, 0x4000)] {
        tracker.feed(&alloc_entry(token, b"k", 0, 0));
        tracker.feed(&alloc_return_ok(token, base, b"drv"));
        tracker.feed(&destroy_entry(token + 100, base + 8, 1, 1));
        tracker.feed(&destroy_return(token + 100));
    }
    let gens = tracker.generations();
    assert_eq!(gens.len(), 2, "tombstones FIFO at the bound");
    assert_eq!((gens[0].id, gens[1].id), (3, 4), "oldest evicted");
    assert_eq!(tracker.stats().tombstone_evictions, 2);
}

#[test]
fn twin_bad_token_refuses() {
    let mut tracker = TransformTracker::new(16, 8, true);
    // Clean edge with a zero token names no attempt.
    tracker.feed(&alloc_entry(0, b"kxcipher", 0, 0));
    // Reserved bit set is no honest-BPF shape.
    tracker.feed(&alloc_entry(3, b"kxcipher", 0, 0));
    assert_eq!(tracker.stats().bad_records, 2, "both counted");
}

#[test]
fn twin_unterminated_name_refuses() {
    let mut tracker = TransformTracker::new(16, 8, true);
    let entry = alloc_entry(2, &[b'z'; 64], 0, 0);
    // All 64 bytes filled, no NUL anywhere: undecodable.
    assert!(!entry[48..112].contains(&0));
    tracker.feed(&entry);
    assert_eq!(tracker.stats().bad_records, 1, "unterminated counted");
}

#[test]
fn sensor_routes_tfm_records_to_tracker() {
    use kryprobe_privilege::kcrypto_lifecycle::sensor::{
        EnrichmentStatus, SensorCore, SessionContext,
    };
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let records = vec![
        alloc_entry(2, b"kxcipher", 0, 0),
        alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"kxcipher-sync-t07a"),
    ];
    core.ingest_records(&records);
    assert_eq!(
        core.tfm().generations().len(),
        1,
        "tfm pair routes to the tracker"
    );
    // An `LC`-magic op record still routes to the op decoder (magic-routed).
    let mut op = vec![0u8; 112];
    op[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    op[2] = 5;
    op[3] = 1;
    op[4..6].copy_from_slice(&1u16.to_le_bytes());
    op[8..16].copy_from_slice(&0xabcdu64.to_le_bytes());
    op[16..24].copy_from_slice(&100u64.to_le_bytes());
    op[32..40].copy_from_slice(&2u64.to_le_bytes());
    op[40..48].copy_from_slice(&0xf00du64.to_le_bytes());
    core.ingest_records(&[op]);
    let ledger = core
        .ledger(
            [0; 5],
            [0; 16],
            Vec::new(),
            SessionContext {
                loss_baseline: [0; 5],
                agg_baseline: [0; 16],
                view_valid: true,
                miss_baseline: Vec::new(),
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect("empty miss join");
    assert_eq!(ledger.decode.admitted, 1, "op record still decodes");
}

#[test]
fn sensor_tallies_destroy_pair_on_lanes_6_7_and_retires() {
    // T07.3f regression: destroy halves route through the sensor
    // like alloc halves — edge_hits lanes 6/7 (LAGG_DESTROY_*) —
    // and the tracker retires the generation. (Before the slot-arm
    // fix, a destroy record hit the alloc-only `debug_assert` and
    // would have corrupted the alloc-lane equation in release.)
    use kryprobe_privilege::kcrypto_lifecycle::sensor::{
        EnrichmentStatus, SensorCore, SessionContext,
    };
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    core.ingest_records(&[
        alloc_entry(2, b"kxcipher", 0x05, 0x8f),
        alloc_return_ok(2, f1, b"drv"),
        destroy_entry(4, f1 + 8, 1, 1),
        destroy_return(4),
    ]);
    assert_eq!(core.tfm().stats().retired, 1, "destroy pair retires");
    assert!(core.tfm().generations()[0].retired);
    let ledger = core
        .ledger(
            [0; 5],
            [0; 16],
            Vec::new(),
            SessionContext {
                loss_baseline: [0; 5],
                agg_baseline: [0; 16],
                view_valid: true,
                miss_baseline: Vec::new(),
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect("empty miss join");
    assert_eq!(ledger.edge_hits[4], 1, "alloc submit on lane 4");
    assert_eq!(ledger.edge_hits[5], 1, "alloc return on lane 5");
    assert_eq!(ledger.edge_hits[6], 1, "destroy submit on lane 6");
    assert_eq!(ledger.edge_hits[7], 1, "destroy return on lane 7");
}

#[test]
fn ledger_carries_generations_and_tfm_stats() {
    // T07.6 seam: the terminal ledger snapshots the tracker's
    // generations + loss counters — one terminal accounting
    // point, no side channel.
    use kryprobe_privilege::kcrypto_lifecycle::sensor::{
        EnrichmentStatus, SensorCore, SessionContext,
    };
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    core.ingest_records(&[
        alloc_entry(2, b"kxcipher", 0x05, 0x8f),
        alloc_return_ok(2, f1, b"drv"),
        config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32),
        config_return(LTFM_SITE_SETKEY_SK, 4, 0),
    ]);
    let ledger = core
        .ledger(
            [0; 5],
            [0; 16],
            Vec::new(),
            SessionContext {
                loss_baseline: [0; 5],
                agg_baseline: [0; 16],
                view_valid: true,
                miss_baseline: Vec::new(),
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect("empty miss join");
    assert_eq!(ledger.generations, core.tfm().generations());
    assert_eq!(ledger.generations.len(), 1);
    assert_eq!(ledger.generations[0].epoch, 1);
    assert_eq!(ledger.tfm_stats, core.tfm().stats());
    assert_eq!(ledger.tfm_stats.configs_joined, 1);
}

#[test]
fn public_views_carry_no_kernel_addresses() {
    // T07.6 leak check: the surfaced views (generations, stats,
    // ledger) render with NO pointer-looking text — ids are small
    // opaques, names are bounded inventory. A future pointer field
    // added to any public view trips this tripwire.
    use kryprobe_privilege::kcrypto_lifecycle::sensor::{
        EnrichmentStatus, SensorCore, SessionContext,
    };
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    core.ingest_records(&[
        alloc_entry(2, b"kxcipher", 0x05, 0x8f),
        alloc_return_ok(2, f1, b"drv"),
        config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32),
        config_return(LTFM_SITE_SETKEY_SK, 4, 0),
        destroy_entry(6, f1 + 8, 1, 1),
        destroy_return(6),
    ]);
    let ledger = core
        .ledger(
            [0; 5],
            [0; 16],
            Vec::new(),
            SessionContext {
                loss_baseline: [0; 5],
                agg_baseline: [0; 16],
                view_valid: true,
                miss_baseline: Vec::new(),
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect("empty miss join");
    let rendered = format!(
        "{:?}\n{:?}\n{:?}\n{:?}",
        ledger.generations,
        ledger.tfm_stats,
        ledger,
        core.tfm().stats(),
    );
    assert!(
        !rendered.contains("ffff") && !rendered.contains("FFFF"),
        "no kernel-address text in public views: {rendered}"
    );
    assert!(
        !rendered.contains("0x"),
        "no hex-pointer text in public views: {rendered}"
    );
    // R6: an accidentally exposed u64 renders DECIMAL under ordinary
    // `Debug` — pin the exact injected frontend AND its canonical
    // base in decimal, lowercase hex, and uppercase hex.
    let base = f1 + 8;
    for ptr in [f1, base] {
        for shape in [ptr.to_string(), format!("{ptr:x}"), format!("{ptr:X}")] {
            assert!(
                !rendered.contains(&shape),
                "injected address {ptr:#x} never renders ({shape}): {rendered}"
            );
        }
    }
    // The validated edge redacts its raw pointer even in Debug
    // (defense in depth — `RawTfm` never crosses the seam, but a
    // debug log of one must not leak either).
    let raw = kryprobe_privilege::kcrypto_lifecycle::tfm::decode_tfm_record(&alloc_return_ok(
        2, f1, b"drv",
    ))
    .expect("fixture decodes");
    let raw_rendered = format!("{raw:?}");
    assert!(
        raw_rendered.contains("redacted"),
        "raw key renders redacted: {raw_rendered}"
    );
    assert!(
        !raw_rendered.contains("ffff"),
        "raw key hex never renders: {raw_rendered}"
    );
    assert!(
        !raw_rendered.contains(&f1.to_string()),
        "raw key decimal never renders: {raw_rendered}"
    );
}

#[test]
fn sensor_tallies_config_pairs_on_lanes_8_11_14_15_and_bumps_epoch() {
    // T07.4: config halves route through the sensor like every
    // other transform edge — setkey-sk on lanes 8/9, setauthsize
    // on 10/11, setkey-aead on 14/15 — and the tracker records +
    // bumps the epoch on the live generation.
    use kryprobe_privilege::kcrypto_lifecycle::sensor::{
        EnrichmentStatus, SensorCore, SessionContext,
    };
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    let f2 = 0xFFFF_8880_0000_2000u64;
    core.ingest_records(&[
        alloc_entry(2, b"kxcipher", 0x05, 0x8f),
        alloc_return_ok(2, f1, b"drv"),
        config_entry(LTFM_SITE_SETKEY_SK, 4, f1, 32),
        config_return(LTFM_SITE_SETKEY_SK, 4, 0),
        config_entry(LTFM_SITE_SETAUTHSIZE, 6, f2, 16),
        config_return(LTFM_SITE_SETAUTHSIZE, 6, 0),
        config_entry(LTFM_SITE_SETKEY_AEAD, 8, f2, 24),
        config_return(LTFM_SITE_SETKEY_AEAD, 8, -22),
    ]);
    assert_eq!(core.tfm().stats().configs_joined, 3);
    assert_eq!(core.tfm().stats().configs_failed, 1);
    let gens = core.tfm().generations();
    assert_eq!(gens.len(), 2);
    assert_eq!((gens[0].epoch, gens[0].configs), (1, 1));
    assert!(gens[1].first_seen, "aead base admits first-seen");
    assert_eq!((gens[1].epoch, gens[1].configs), (1, 2));
    assert_eq!(gens[1].last_config_site, LTFM_SITE_SETKEY_AEAD);
    assert_eq!(gens[1].last_config_errno, -22);
    let ledger = core
        .ledger(
            [0; 5],
            [0; 16],
            Vec::new(),
            SessionContext {
                loss_baseline: [0; 5],
                agg_baseline: [0; 16],
                view_valid: true,
                miss_baseline: Vec::new(),
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect("empty miss join");
    assert_eq!(ledger.edge_hits[8], 1, "setkey-sk submit on lane 8");
    assert_eq!(ledger.edge_hits[9], 1, "setkey-sk return on lane 9");
    assert_eq!(ledger.edge_hits[10], 1, "setauthsize submit on lane 10");
    assert_eq!(ledger.edge_hits[11], 1, "setauthsize return on lane 11");
    assert_eq!(ledger.edge_hits[14], 1, "setkey-aead submit on lane 14");
    assert_eq!(ledger.edge_hits[15], 1, "setkey-aead return on lane 15");
    assert_eq!(ledger.edge_hits[12], 0, "aead-alloc lane stays dark");
    assert_eq!(ledger.edge_hits[13], 0, "aead-alloc lane stays dark");
}

#[test]
fn twin_bad_edge_and_flags_refuse() {
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&tfm_bytes(
        9,
        LTFM_SITE_ALLOC_SK,
        0,
        0,
        100,
        0,
        0,
        0,
        2,
        b"kxcipher",
    ));
    tracker.feed(&tfm_bytes(
        LEDGE_SUBMIT,
        LTFM_SITE_ALLOC_SK,
        0x0004,
        0,
        100,
        0,
        0,
        0,
        2,
        b"kxcipher",
    ));
    assert_eq!(tracker.stats().bad_records, 2, "both counted");
}

#[test]
fn twin_entry_status_and_return_aux_refuse() {
    let mut tracker = TransformTracker::new(16, 8, true);
    // Entry edges carry no status.
    tracker.feed(&tfm_bytes(
        LEDGE_SUBMIT,
        LTFM_SITE_ALLOC_SK,
        0,
        0,
        100,
        -2,
        0,
        0,
        2,
        b"kxcipher",
    ));
    // T07.2 return edges carry no aux words.
    tracker.feed(&tfm_bytes(
        LEDGE_RETURN,
        LTFM_SITE_ALLOC_SK,
        0,
        0x1000,
        150,
        0,
        7,
        0,
        2,
        b"drv",
    ));
    assert_eq!(tracker.stats().bad_records, 2, "both counted");
}

#[test]
fn twin_failure_name_and_bad_utf8_refuse() {
    let mut tracker = TransformTracker::new(16, 8, true);
    // Failure returns name nothing.
    let mut failure = alloc_return_err(2, -2);
    failure[48] = b'x';
    tracker.feed(&failure);
    // Names are kernel C strings; invalid UTF-8 is drift.
    let bad_utf8 = alloc_entry(4, b"\xff\xfe", 0, 0);
    tracker.feed(&bad_utf8);
    assert_eq!(tracker.stats().bad_records, 2, "both counted");
    // Success with an empty driver name is UNKNOWN, not drift.
    tracker.feed(&alloc_entry(6, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(6, 0xFFFF_8880_0000_1000, b""));
    assert_eq!(tracker.generations().len(), 1, "unknown drv assigns");
    assert_eq!(tracker.generations()[0].drv_name, "", "empty is unknown");
}

#[test]
fn wrapping_frontend_refuses_without_generation() {
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    tracker.feed(&alloc_return_ok(2, u64::MAX, b"drv"));
    assert_eq!(tracker.stats().bad_records, 1, "wrap counted");
    assert!(tracker.generations().is_empty(), "no wrapped identity");
}

#[test]
fn stale_return_refuses_with_attempt_kept() {
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    // Entry stamped ts 100; a return at ts 50 predates it.
    let mut stale = alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv");
    stale[16..24].copy_from_slice(&50u64.to_le_bytes());
    tracker.feed(&stale);
    assert_eq!(tracker.stats().stale_returns, 1, "stale counted");
    assert!(tracker.generations().is_empty(), "nothing assigned");
    // The attempt stands: the true return still pairs.
    tracker.feed(&alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv"));
    assert_eq!(tracker.generations().len(), 1, "true return pairs");
}

#[test]
fn decode_drop_variants_pin() {
    // The drop taxonomy is exact: each twin rule names its variant.
    let mut tracker = TransformTracker::new(16, 8, true);
    let _ = tracker.feed(&alloc_entry(0, b"kxcipher", 0, 0));
    assert!(matches!(
        kryprobe_privilege::kcrypto_lifecycle::tfm::decode_tfm_record(&alloc_entry(
            0,
            b"kxcipher",
            0,
            0
        )),
        Err(TfmDrop::BadToken)
    ));
}

#[test]
fn twin_positive_failure_status_refuses() {
    // D8: the BPF emits `(ret as i32)` over the ERR_PTR range only —
    // a positive "failure" status is twin drift, never classified.
    assert!(matches!(
        decode_tfm_record(&alloc_return_err(2, 1)),
        Err(TfmDrop::BadFailureStatus)
    ));
}

#[test]
fn twin_out_of_range_failure_status_refuses() {
    // D8: below -4095 is outside any native ERR_PTR encoding.
    for errno in [i32::MIN, -4096] {
        assert!(
            matches!(
                decode_tfm_record(&alloc_return_err(2, errno)),
                Err(TfmDrop::BadFailureStatus)
            ),
            "errno {errno} must refuse"
        );
    }
}

#[test]
fn twin_errno_floor_accepts_and_classifies() {
    // D8 boundary: -4095 is the floor the BPF can emit — a complete
    // attempt with it classifies as a failure (no generation).
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    assert!(decode_tfm_record(&alloc_return_err(2, -4095)).is_ok());
    tracker.feed(&alloc_return_err(2, -4095));
    assert_eq!(tracker.stats().failed_allocs, 1, "floor errno classifies");
    assert!(tracker.generations().is_empty(), "no phantom generation");
}

#[test]
fn twin_errptr_key_on_success_refuses() {
    // D8: the BPF classifies ERR_PTR-range returns as failures
    // before dereference — a success edge carrying one would
    // normalize to a phantom generation.
    for key in [0xFFFF_FFFF_FFFF_F001u64, 0xFFFF_FFFF_FFFF_FFFFu64] {
        assert!(
            matches!(
                decode_tfm_record(&alloc_return_ok(2, key, b"drv")),
                Err(TfmDrop::BadSuccessKey)
            ),
            "success key {key:#x} must refuse"
        );
    }
}

#[test]
fn twin_sub_floor_key_on_success_accepts() {
    // D8 boundary mirror: the twin mirrors the classifier exactly —
    // one below the floor is a success-shaped key (odd pointer, but
    // the contract's line is the classifier's line, no embellishment).
    assert!(decode_tfm_record(&alloc_return_ok(2, 0xFFFF_FFFF_FFFF_F000, b"drv")).is_ok());
}

#[test]
fn return_truncation_flag_survives_in_generation() {
    // D9: the halves carry independent truncation — a short request
    // with a flagged driver selection must not read as complete.
    let mut tracker = TransformTracker::new(16, 8, true);
    tracker.feed(&alloc_entry(2, b"kxcipher", 0, 0));
    let mut ret = alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv");
    ret[6] = LTFM_TRUNCATED as u8;
    tracker.feed(&ret);
    let generations = tracker.generations();
    assert_eq!(generations.len(), 1);
    assert!(!generations[0].name_truncated, "short request intact");
    assert!(generations[0].drv_truncated, "driver flag preserved");
}

#[test]
fn entry_truncation_flag_survives_without_return_flag() {
    // D9 independence, other direction: a flagged request with a
    // clean driver selection keeps exactly the request flag.
    let mut tracker = TransformTracker::new(16, 8, true);
    let mut long = vec![b'a'; 63];
    long.extend_from_slice(b"extra-that-does-not-fit");
    let mut entry = alloc_entry(2, &long, 0, 0);
    entry[48 + 63] = 0;
    entry[6] = LTFM_TRUNCATED as u8;
    tracker.feed(&entry);
    tracker.feed(&alloc_return_ok(2, 0xFFFF_8880_0000_1000, b"drv"));
    let generations = tracker.generations();
    assert_eq!(generations.len(), 1);
    assert!(generations[0].name_truncated, "request flag preserved");
    assert!(!generations[0].drv_truncated, "clean driver intact");
}

/// Bind one AF_ALG socket of type `typ` and return its fd (each
/// skcipher bind calls `crypto_alloc_skcipher` exactly once —
/// bpftrace-proven on the 7.0 host): the host capture positive
/// control. The caller holds the fd: closing releases the tfm, and
/// the `/proc/crypto` oracle below needs the instance alive.
fn afalg_bind(typ: &str, name: &str) -> i32 {
    // `struct sockaddr_alg` (`linux/if_alg.h`): family u16 @0,
    // type[14] @2, feat u32 @16, mask u32 @20, name[64] @24.
    let fd = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
    assert!(
        fd >= 0,
        "AF_ALG socket failed: {}",
        std::io::Error::last_os_error()
    );
    let mut addr = [0u8; 88];
    addr[0..2].copy_from_slice(&(libc::AF_ALG as u16).to_le_bytes());
    let t = typ.len().min(14);
    addr[2..2 + t].copy_from_slice(&typ.as_bytes()[..t]);
    let n = name.len().min(64);
    addr[24..24 + n].copy_from_slice(&name.as_bytes()[..n]);
    let rc = unsafe { libc::bind(fd, addr.as_ptr() as *const libc::sockaddr, 88) };
    assert_eq!(
        rc,
        0,
        "AF_ALG bind({typ}/{name}) failed: {}",
        std::io::Error::last_os_error()
    );
    fd
}

fn afalg_bind_skcipher(name: &str) -> i32 {
    afalg_bind("skcipher", name)
}

/// `setsockopt(ALG_SET_KEY)` on an AF_ALG fd (`linux/if_alg.h`:
/// `SOL_ALG` 279, `ALG_SET_KEY` 1): drives one
/// `crypto_skcipher_setkey` / `crypto_aead_setkey` call per
/// tfm layer (outer, plus template-inner when the driver
/// propagates through the API rather than the method pointer).
/// Returns the raw rc (the failing-key positive control needs it).
fn afalg_try_set_key(fd: i32, key: &[u8]) -> i32 {
    const SOL_ALG: libc::c_int = 279;
    const ALG_SET_KEY: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            SOL_ALG,
            ALG_SET_KEY,
            key.as_ptr() as *const libc::c_void,
            key.len() as libc::socklen_t,
        )
    }
}

fn afalg_set_key(fd: i32, key: &[u8]) {
    assert_eq!(
        afalg_try_set_key(fd, key),
        0,
        "AF_ALG setsockopt(KEY) failed: {}",
        std::io::Error::last_os_error()
    );
}

/// `setsockopt(ALG_SET_AEAD_AUTHSIZE)` on an AF_ALG AEAD fd
/// (`linux/if_alg.h`: `ALG_SET_AEAD_AUTHSIZE` 5): drives one
/// `crypto_aead_setauthsize` call. Kernel quirk (same idiom as
/// `alg_fixture::aead_roundtrip`): `optlen` CARRIES the authsize
/// value — `optval` is ignored. Passing a u32 value with
/// `optlen = 4` requests authsize 4 whatever the argument says.
fn afalg_set_authsize(fd: i32, authsize: u32) {
    const SOL_ALG: libc::c_int = 279;
    const ALG_SET_AEAD_AUTHSIZE: libc::c_int = 5;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            std::ptr::null(),
            authsize as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "AF_ALG setsockopt(AUTHSIZE) failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Independent driver oracle (D5): the winning `cra_driver_name`
/// for `name` from `/proc/crypto` (highest `priority` among
/// same-named entries — the kernel selects the same winner the
/// sensor's chase resolves). Fails loud when the inventory is
/// unreadable or the name is absent (broken positive control —
/// never a silent skip).
/// Suite serialization lock: the lifecycle sensor is system-wide
/// and exclusive (`SessionBusy` on double attach), so the ignored
/// host tests hold this across their whole body (bring-up through
/// detach), making sensor lifetimes disjoint. Poison-tolerant: a
/// failed test must not cascade into lock errors.
static SUITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn suite_guard() -> std::sync::MutexGuard<'static, ()> {
    SUITE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn proc_crypto_winning_driver(name: &str) -> String {
    let text = std::fs::read_to_string("/proc/crypto").expect("/proc/crypto must read");
    let mut winner: Option<(u32, String)> = None;
    for block in text.split("\n\n") {
        let mut entry_name = None;
        let mut driver = None;
        let mut priority = None;
        for line in block.lines() {
            let (key, value) = line
                .split_once(':')
                .map(|(k, v)| (k.trim(), v.trim()))
                .unwrap_or(("", ""));
            match key {
                "name" => entry_name = Some(value),
                "driver" => driver = Some(value),
                "priority" => priority = Some(value),
                _ => {}
            }
        }
        if entry_name == Some(name) {
            let prio: u32 = priority
                .expect("driver entry carries a priority")
                .parse()
                .expect("priority parses as u32");
            let drv = driver.expect("driver entry carries a driver").to_owned();
            if winner.as_ref().is_none_or(|(best, _)| prio > *best) {
                winner = Some((prio, drv));
            }
        }
    }
    winner
        .unwrap_or_else(|| panic!("no /proc/crypto entry named {name}"))
        .1
}

/// Host alloc-capture qualification (T07.2d): bring up the REAL
/// 3-program sensor on the host, bind 5 AF_ALG skcipher sockets,
/// drain, and assert the capture end to end — alloc-lane edge/agg
/// deltas, zero loss, twin-clean wire bytes, and generations
/// carrying the requested name + a resolved driver.
#[test]
#[ignore = "BPF lane: run with scripts/sudo-lane.sh (needs root + BTF + built BPF object)"]
fn host_alloc_capture_assigns_generations() {
    let _guard = suite_guard();
    use kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleSensor;
    // Honest skips (same idiom as the bring-up BTF test): without
    // root, host BTF, or the built object there is no sensor.
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIP: host capture needs root (sudo lane)");
        return;
    }
    if std::fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let object = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("kcrypto-lifecycle.bpf.o");
    if !object.is_file() {
        println!("SKIP: missing BPF lifecycle object — run `cargo xtask build --bpf`");
        return;
    }
    let bytes = std::fs::read(&object).expect("test fixture must be readable");
    let (mut sensor, points) =
        LifecycleSensor::bring_up(&bytes, None).expect("host sensor must attach");
    assert_eq!(
        points.len(),
        7,
        "seven session links (op/sub+ret, alloc, destroy, 3x config)"
    );
    assert_eq!(sensor.attached_points(), 7);
    let pre = sensor.ledger().expect("pre-bind ledger");
    let pre_stats = sensor.tfm().stats();
    let pre_gens = sensor.tfm().generations().len();
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(afalg_bind_skcipher("cbc(aes)"));
    }
    // T07.4: key every skcipher socket (32-byte AES-256 key —
    // valid for `cbc(aes)`, so every setkey succeeds and bumps).
    let key32 = [0x5au8; 32];
    // Failure positive control FIRST (a 7-byte key is invalid for
    // AES — the hooked `crypto_skcipher_setkey` fails loud with
    // EINVAL): the valid rekey below still leaves every generation
    // epoch ≥1 with a succeeding last config.
    let key7 = [0x5au8; 7];
    let bad_rc = afalg_try_set_key(held[0], &key7);
    assert_ne!(bad_rc, 0, "7-byte AES key must fail");
    for fd in &held {
        afalg_set_key(*fd, &key32);
    }
    // One AEAD socket: `crypto_alloc_aead` is unhooked (out of
    // scope — first-seen admits it), but its setkey + setauthsize
    // run on hooked sites.
    held.push(afalg_bind("aead", "gcm(aes)"));
    afalg_set_key(*held.last().unwrap(), &key32[..16]);
    afalg_set_authsize(*held.last().unwrap(), 16);
    for _ in 0..4 {
        let drained = sensor.drain_once(8192).expect("drain");
        if drained.records == 0 && !drained.busy {
            break;
        }
    }
    // The oracle reads the live inventory (fds held), then the
    // sockets close — all assertions run after release.
    let expected_drv = proc_crypto_winning_driver("cbc(aes)");
    for fd in held {
        unsafe {
            libc::close(fd);
        }
    }
    let _ = sensor.take_completed();
    sensor.close_input().expect("disarm+detach");
    let quiet = sensor.drain_quiet().expect("quiet drain");
    assert!(quiet.quiet, "close must reach a quiet round");
    assert_eq!(quiet.backlog_bytes, 0, "no close backlog");
    let post = sensor.ledger().expect("post-bind ledger");
    let stats = sensor.tfm().stats();
    // Failure context (host kernels vary — print the whole
    // accounting before asserting so a red run names its lane).
    eprintln!(
        "host-capture: edge={:?} agg={:?} loss={:?} tfm={stats:?} gens={:?}",
        post.edge_hits,
        post.agg_accepted,
        post.kernel_loss,
        sensor.tfm().generations(),
    );
    // Exact alloc-lane deltas: 5 binds → 5 submits + 5 returns (a
    // quiet host brackets the second-scale window; background
    // crypto would show here, worth knowing about).
    assert_eq!(post.edge_hits[4] - pre.edge_hits[4], 5, "alloc submits");
    assert_eq!(post.edge_hits[5] - pre.edge_hits[5], 5, "alloc returns");
    // Per-lane equation on the alloc lanes (accepted == consumed).
    assert_eq!(
        post.agg_accepted[4] - pre.agg_accepted[4],
        post.edge_hits[4] - pre.edge_hits[4],
        "alloc-sub equation"
    );
    assert_eq!(
        post.agg_accepted[5] - pre.agg_accepted[5],
        post.edge_hits[5] - pre.edge_hits[5],
        "alloc-ret equation"
    );
    // Zero loss everywhere (sensor errors, not traffic).
    assert_eq!(post.kernel_loss, [0, 0, 0, 0, 0], "zero kernel loss");
    assert_eq!(
        stats.failed_allocs - pre_stats.failed_allocs,
        0,
        "no failed allocs"
    );
    assert_eq!(
        stats.bad_records - pre_stats.bad_records,
        0,
        "twin-clean wire bytes"
    );
    assert_eq!(
        stats.unknown_returns - pre_stats.unknown_returns,
        0,
        "every return paired"
    );
    assert_eq!(
        stats.tainted_refused - pre_stats.tainted_refused,
        0,
        "no taint"
    );
    assert_eq!(stats.table_full - pre_stats.table_full, 0, "no spill");
    assert_eq!(
        stats.stale_returns - pre_stats.stale_returns,
        0,
        "no replays"
    );
    assert_eq!(
        stats.submit_refused - pre_stats.submit_refused,
        0,
        "no resubmits"
    );
    // T07.3+: `admitted` counts EVERY submit half (alloc +
    // destroy + config attempts) — the equation, not a fixed 5,
    // is the invariant.
    assert_eq!(
        stats.admitted - pre_stats.admitted,
        (post.edge_hits[4] - pre.edge_hits[4])
            + (post.edge_hits[6] - pre.edge_hits[6])
            + (post.edge_hits[8] - pre.edge_hits[8])
            + (post.edge_hits[10] - pre.edge_hits[10])
            + (post.edge_hits[14] - pre.edge_hits[14]),
        "every submit admitted exactly once"
    );
    assert_eq!(
        stats.completed - pre_stats.completed,
        5,
        "5 attempts completed"
    );
    for miss in &post.prog_misses {
        assert_eq!(miss.delta(), 0, "zero miss delta on {}", miss.section);
    }
    // Generations: the 5 socket tfms carry the requested name +
    // a resolved driver; config-admitted first-seen gens (the AEAD
    // socket, whose alloc is unhooked, plus any template-inner
    // layer the config path observed) carry EMPTY provenance —
    // unknown, never fabricated. (Op-admitted first-seen gens
    // carry the submit's driver instead — F05, pinned by
    // `host_op_first_seen_carries_selected_driver`; this E2E runs
    // no ops, so every first-seen gen here is config-admitted.)
    let gens = sensor.tfm().generations();
    let new_gens = gens.len() - pre_gens;
    assert!(
        new_gens >= 6,
        "5 socket tfms + the AEAD tfm at least: {new_gens}"
    );
    let mut socket_gens = 0;
    for g in gens.iter().skip(pre_gens) {
        if g.first_seen {
            assert!(
                g.req_name.is_empty() && g.drv_name.is_empty(),
                "config-admitted first-seen carries no provenance: {g:?}"
            );
        } else {
            socket_gens += 1;
            assert_eq!(g.req_name, "cbc(aes)", "requested name verbatim");
            assert_eq!(
                g.drv_name, expected_drv,
                "driver matches /proc/crypto winner: {g:?}"
            );
            assert!(!g.name_truncated, "short name never truncates: {g:?}");
        }
    }
    assert_eq!(socket_gens, 5, "5 alloc-assigned socket tfms");
    // T07.3 destroy lane: the 5 closes above ran
    // `crypto_destroy_tfm` synchronously (close returns after the
    // put). The destroy COUNT is driver-shaped — cryptd-wrapped
    // `cbc(aes)` destroys the outer tfm plus the template-inner
    // tfm (never seen at alloc: honestly `unknown`), so the
    // portable invariants are pairing + equations, not a fixed 5.
    let d_sub = post.edge_hits[6] - pre.edge_hits[6];
    let d_ret = post.edge_hits[7] - pre.edge_hits[7];
    assert_eq!(d_sub, d_ret, "destroy halves pair");
    assert!(d_ret >= 5, "every close provoked a destroy: {d_ret}");
    assert_eq!(
        post.agg_accepted[6] - pre.agg_accepted[6],
        d_sub,
        "destroy-sub equation"
    );
    assert_eq!(
        post.agg_accepted[7] - pre.agg_accepted[7],
        d_ret,
        "destroy-ret equation"
    );
    let releases = stats.releases - pre_stats.releases;
    assert_eq!(releases, d_ret, "every destroy return joined");
    let retired = stats.retired - pre_stats.retired;
    let ambiguous = stats.ambiguous_releases - pre_stats.ambiguous_releases;
    let unknown = stats.unknown_releases - pre_stats.unknown_releases;
    let noop = stats.noop_releases - pre_stats.noop_releases;
    assert_eq!(
        retired + ambiguous + unknown + noop,
        releases,
        "every release lands on exactly one verdict"
    );
    // Every new generation got exactly one verdict (retire vs
    // ambiguous is the observer rule's honest call); destroys for
    // never-observed bases (template-inner layers the config path
    // did NOT see — e.g. method-pointer propagation) land
    // unknown/noop.
    assert_eq!(
        retired + ambiguous,
        new_gens as u64,
        "one verdict per new generation (retired={retired} ambiguous={ambiguous})"
    );
    assert_eq!(
        unknown + noop,
        releases - new_gens as u64,
        "unobserved destroys land unknown/noop"
    );
    assert_eq!(
        stats.mismatched_returns - pre_stats.mismatched_returns,
        0,
        "no cross-site joins"
    );
    assert_eq!(
        stats.forced_retires - pre_stats.forced_retires,
        0,
        "no forced retires"
    );
    assert_eq!(
        stats.live_full - pre_stats.live_full,
        0,
        "live table never full"
    );
    assert_eq!(
        stats.tombstone_evictions - pre_stats.tombstone_evictions,
        0,
        "no tombstone evictions"
    );
    for g in gens.iter().skip(pre_gens) {
        assert!(
            g.retired != g.ambiguous,
            "exactly one verdict per generation: {g:?}"
        );
    }
    // T07.5 registry context: bring_up snapshotted `/proc/crypto`
    // (current inventory — the winner join must agree with the
    // independent oracle read above, same file, same moment).
    let registry = sensor.registry().expect("bring_up snapshots the registry");
    assert!(!registry.truncated, "live registry fits the bounds");
    let winner = registry
        .winning_driver("cbc(aes)")
        .expect("cbc(aes) is registered");
    assert_eq!(
        winner.driver.as_deref(),
        Some(expected_drv.as_str()),
        "registry winner agrees with the oracle"
    );
    // T07.4 config lanes: every setkey/setauthsize provoked ≥1
    // hooked call per tfm layer (template-inner propagation is
    // driver-shaped — pairing + equations, not fixed counts).
    for (sub, ret, name) in [
        (8usize, 9usize, "setkey-sk"),
        (10, 11, "setauthsize"),
        (14, 15, "setkey-aead"),
    ] {
        let s = post.edge_hits[sub] - pre.edge_hits[sub];
        let r = post.edge_hits[ret] - pre.edge_hits[ret];
        assert_eq!(s, r, "{name} halves pair");
        assert_eq!(
            post.agg_accepted[sub] - pre.agg_accepted[sub],
            s,
            "{name}-sub equation"
        );
        assert_eq!(
            post.agg_accepted[ret] - pre.agg_accepted[ret],
            r,
            "{name}-ret equation"
        );
    }
    let sk_ret = post.edge_hits[9] - pre.edge_hits[9];
    let sa_ret = post.edge_hits[11] - pre.edge_hits[11];
    let aead_ret = post.edge_hits[15] - pre.edge_hits[15];
    assert!(sk_ret >= 5, "every sk setsockopt keyed ≥1 tfm: {sk_ret}");
    assert!(sa_ret >= 1, "setauthsize ran: {sa_ret}");
    assert!(aead_ret >= 1, "aead setkey ran: {aead_ret}");
    assert_eq!(
        post.edge_hits[12] - pre.edge_hits[12],
        0,
        "aead-alloc lane stays dark (unhooked)"
    );
    assert_eq!(
        post.edge_hits[13] - pre.edge_hits[13],
        0,
        "aead-alloc lane stays dark (unhooked)"
    );
    assert_eq!(
        stats.configs_joined - pre_stats.configs_joined,
        sk_ret + sa_ret + aead_ret,
        "every config return joined"
    );
    // The 7-byte failing key above joined exactly one errno
    // verdict per tfm layer it reached (outer always — inner
    // propagation is driver-shaped, hence ≥1, never exact).
    assert!(
        stats.configs_failed - pre_stats.configs_failed >= 1,
        "failing key joined: {:?}",
        stats
    );
    assert_eq!(
        stats.config_unlinked - pre_stats.config_unlinked,
        0,
        "every config attributed (null keys impossible here)"
    );
    // Every new generation was keyed ≥once successfully (its own
    // setsockopt at least — inner layers keyed through
    // propagation carry their own epochs too).
    for g in gens.iter().skip(pre_gens) {
        assert!(
            g.configs >= 1 && g.epoch >= 1,
            "keyed ≥once with epoch bump: {g:?}"
        );
        assert_eq!(g.last_config_errno, 0, "last config succeeded: {g:?}");
    }
    // R10: the requested authsize (16, carried by `optlen`) is the
    // captured scalar — every generation whose most recent config
    // is the setauthsize carries exactly 16, and at least one does
    // (propagation order is driver-shaped — the scalar is not).
    let mut saw_authsize = false;
    for g in gens.iter().skip(pre_gens) {
        if g.last_config_site == LTFM_SITE_SETAUTHSIZE {
            saw_authsize = true;
            assert_eq!(
                g.last_config_len, 16,
                "captured authsize equals the request: {g:?}"
            );
        }
    }
    assert!(saw_authsize, "setauthsize attributed to a generation");
}

/// Lifecycle secret-canary lane test (R6): key a live transform
/// with a `KPROBE-CANARY-*` marker and prove no marker byte reaches
/// any generation, counter, or ledger render — the config path
/// captures the length scalar only, never key bytes. (The op path
/// carries scalars only — `LEdge` has no bytes field to scan; the
/// scan covers every string-carrying lifecycle view instead.)
#[test]
#[ignore = "BPF lane: run with scripts/sudo-lane.sh (needs root + BTF + built BPF object)"]
fn lifecycle_canary_no_secret_bytes_in_views() {
    let _guard = suite_guard();
    use kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleSensor;
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIP: lifecycle canary needs root (sudo lane)");
        return;
    }
    if std::fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let object = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("kcrypto-lifecycle.bpf.o");
    if !object.is_file() {
        println!("SKIP: missing BPF lifecycle object — run `cargo xtask build --bpf`");
        return;
    }
    let bytes = std::fs::read(&object).expect("test fixture must be readable");
    let (mut sensor, _) = LifecycleSensor::bring_up(&bytes, None).expect("host sensor must attach");
    // 16-byte AES-128 key with the marker prefix — a real key the
    // kernel accepts, carrying canary bytes the sensor must never
    // repeat back.
    let marker_key = b"KPROBE-CANARY-12";
    assert_eq!(marker_key.len(), 16);
    let fd = afalg_bind_skcipher("cbc(aes)");
    afalg_set_key(fd, marker_key);
    for _ in 0..4 {
        let drained = sensor.drain_once(8192).expect("drain");
        if drained.records == 0 && !drained.busy {
            break;
        }
    }
    unsafe { libc::close(fd) };
    let _ = sensor.take_completed();
    sensor.close_input().expect("disarm+detach");
    let quiet = sensor.drain_quiet().expect("quiet drain");
    assert!(quiet.quiet, "close must reach a quiet round");
    let ledger = sensor.ledger().expect("post-canary ledger");
    let gens = sensor.tfm().generations();
    assert!(!gens.is_empty(), "canary traffic assigned a generation");
    // The length scalar IS captured (16) — sizes, not contents.
    assert!(
        gens.iter().any(|g| g.configs >= 1),
        "marker setkey joined: {gens:?}"
    );
    // No marker byte in any surfaced view (names, ids, counters,
    // full ledger render).
    let rendered = format!(
        "{:?}\n{:?}\n{:?}\n{:?}",
        gens,
        sensor.tfm().stats(),
        ledger,
        sensor
            .registry()
            .map(|r| format!("{r:?}"))
            .unwrap_or_default(),
    );
    assert!(
        !rendered.contains("KPROBE-CANARY"),
        "no secret bytes in lifecycle views: {rendered}"
    );
    for g in &gens {
        assert!(
            !g.req_name.contains("KPROBE-CANARY") && !g.drv_name.contains("KPROBE-CANARY"),
            "no secret bytes in provenance names: {g:?}"
        );
    }
}

/// Host F05 proof (T07-04): a transform bound + keyed BEFORE the
/// sensor attaches is op-first-seen — its generation carries the
/// runtime-selected driver (checked against the independent
/// /proc/crypto winner oracle) with EMPTY creation provenance
/// (allocation/requested name/previous configuration unknown: the
/// alloc + setkey ran pre-attach, so configs == 0 and epoch == 0).
#[test]
#[ignore = "BPF lane: run with scripts/sudo-lane.sh (needs root + BTF + built BPF object)"]
fn host_op_first_seen_carries_selected_driver() {
    let _guard = suite_guard();
    use kryprobe_privilege::kcrypto_lifecycle::sensor::LifecycleSensor;
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIP: F05 oracle needs root (sudo lane)");
        return;
    }
    if std::fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        println!("SKIP: no /sys/kernel/btf/vmlinux on this host");
        return;
    }
    let object = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("kcrypto-lifecycle.bpf.o");
    if !object.is_file() {
        println!("SKIP: missing BPF lifecycle object — run `cargo xtask build --bpf`");
        return;
    }
    // Pre-attach: bind + key (the sensor observes NEITHER — its
    // first sighting of this transform is the op submit below).
    let fd = afalg_bind_skcipher("cbc(aes)");
    afalg_set_key(fd, &[0x5au8; 32]);
    let bytes = std::fs::read(&object).expect("test fixture must be readable");
    let (mut sensor, _) = LifecycleSensor::bring_up(&bytes, None).expect("host sensor must attach");
    let pre_gens = sensor.tfm().generations().len();
    // Post-attach: exactly one encrypt on the pre-bound socket.
    kryprobe_testkit::alg_fixture::skcipher_encrypt_once(fd)
        .expect("pre-bound encrypt must succeed");
    for _ in 0..4 {
        let drained = sensor.drain_once(8192).expect("drain");
        if drained.records == 0 && !drained.busy {
            break;
        }
    }
    // The oracle reads the live inventory (fd held), then the
    // socket closes — all assertions run after release.
    let expected_drv = proc_crypto_winning_driver("cbc(aes)");
    unsafe { libc::close(fd) };
    let _ = sensor.take_completed();
    sensor.close_input().expect("disarm+detach");
    let quiet = sensor.drain_quiet().expect("quiet drain");
    assert!(quiet.quiet, "close must reach a quiet round");
    let post = sensor.ledger().expect("post-op ledger");
    eprintln!(
        "f05-oracle: edge={:?} tfm={:?} gens={:?}",
        post.edge_hits,
        sensor.tfm().stats(),
        sensor.tfm().generations(),
    );
    // Op pairs ran post-attach (quiet host brackets the window —
    // the same assumption the alloc E2E already makes): one per
    // encrypt API call. cbc(aes) on aesni hosts resolves through
    // cryptd, whose child call trips the hook too (outer +
    // cryptd-inner = 2 pairs); other hosts see 1 — the count is
    // driver-shaped, the per-generation properties are not.
    let submits = post.edge_hits[0];
    assert!(
        submits >= 1,
        "the encrypt ran through the hooked API: {submits}"
    );
    assert_eq!(post.edge_hits[1], submits, "every submit returns");
    // The op-first-seen generations: selected drivers captured
    // (oracle), creation provenance empty (pre-attach truth).
    let gens = sensor.tfm().generations();
    let fresh: Vec<_> = gens.iter().skip(pre_gens).collect();
    assert_eq!(
        fresh.len() as u64,
        submits,
        "one generation per op pair: {fresh:?}"
    );
    assert!(
        fresh.iter().any(|g| g.drv_name == expected_drv),
        "outer driver matches /proc/crypto winner: {fresh:?}"
    );
    for g in &fresh {
        assert!(g.first_seen, "op-first sighting: {g:?}");
        assert!(!g.drv_name.is_empty(), "selected driver captured: {g:?}");
        assert!(!g.drv_truncated, "short driver never truncates: {g:?}");
        assert!(g.req_name.is_empty(), "requested name unknown: {g:?}");
        assert_eq!(g.configs, 0, "pre-attach setkey unobserved: {g:?}");
        assert_eq!(g.epoch, 0, "no observed configuration: {g:?}");
        assert!(
            g.retired && !g.ambiguous,
            "close destroy retires exactly: {g:?}"
        );
    }
}
