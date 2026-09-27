// SPDX-License-Identifier: GPL-3.0-or-later
//! P3 `kcrypto_requests` suite (test plan P3–P6): synchronous request
//! identity + entry-side metadata over LEdge v6 bytes, end to end through
//! [`SensorCore`] (decode → first-seen admission → submit-lifetime binding →
//! reducer → ledger).
//!
//! Contract pinned here: each admitted invocation owns its opaque id;
//! `tfm_id` binds the SUBMIT's live generation (never a later reuse, never
//! timing proximity); entry-side scalars (family, direction, API input
//! length, request flags, selected driver, submit-pinned config epoch) ride
//! the record; immediate errno is exact; duration spans submit→return; a
//! failed wrapper (bad setkey, early ENOKEY) claims no provider entry and no
//! successful work; unknown/ambiguous binding stays explicit (`None`) and
//! never destroys the invocation identity.

use kryprobe_core::kcrypto::{LifecycleFamily, OpDirection, Terminal};
use kryprobe_privilege::btf_resolve::ConfiguredError;
use kryprobe_privilege::kcrypto_lifecycle::sensor::{
    EnrichmentStatus, LifecycleSensor, SensorCore, SessionContext,
};

/// Encrypt site (v6 `dir` echoes the site byte).
const ENC: u16 = 1;
/// Submit / return edge tags.
const SUBMIT: u8 = 1;
const RETURN: u8 = 2;
/// Transform sites (v1 `LTfm`).
const ALLOC_SK: u16 = 1;
const DESTROY: u16 = 2;
const SETKEY_SK: u16 = 3;

/// One 112-byte v6 `LEdge` (little-endian twin of the ABI struct):
/// `cryptlen@28`, `invoc@32`, `tfm@40`, `req_flags@48`, `fam@52`, `dir@53`,
/// `mflags@54` (bit0 cryptlen-valid, bit1 req-flags-valid), `drv@56` (55+NUL).
/// Submits carry metadata; returns carry all-zero metadata (R2 extended).
#[allow(clippy::too_many_arguments)]
fn edge_v6(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    invoc: u64,
    tfm: u64,
    cryptlen: Option<u32>,
    req_flags: Option<u32>,
    drv: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 6;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    if edge == SUBMIT {
        let mut mflags = 0u16;
        if let Some(c) = cryptlen {
            out[28..32].copy_from_slice(&c.to_le_bytes());
            mflags |= 0x01;
        }
        if let Some(f) = req_flags {
            out[48..52].copy_from_slice(&f.to_le_bytes());
            mflags |= 0x02;
        }
        out[52] = 1; // LFAM_SK
        out[53] = site as u8; // dir == site
        out[54..56].copy_from_slice(&mflags.to_le_bytes());
        let n = drv.len().min(55);
        out[56..56 + n].copy_from_slice(&drv[..n]);
    }
    out[32..40].copy_from_slice(&invoc.to_le_bytes());
    out[40..48].copy_from_slice(&tfm.to_le_bytes());
    out
}

/// Default submit: encrypt, valid cryptlen + flags, selected driver.
fn op_submit(key: u64, ts: u64, invoc: u64, frontend: u64) -> Vec<u8> {
    edge_v6(
        SUBMIT,
        ENC,
        key,
        ts,
        0,
        invoc,
        frontend,
        Some(16),
        Some(0),
        b"kxcipher-sync",
    )
}

/// Default return: exact native status, zero metadata.
fn op_return(key: u64, ts: u64, invoc: u64, status: i32) -> Vec<u8> {
    edge_v6(RETURN, ENC, key, ts, status, invoc, 0, None, None, b"")
}

/// One 112-byte v1 `LTfm` (alloc/destroy/config halves for the tracker).
#[allow(clippy::too_many_arguments)]
fn tfm_rec(
    edge: u8,
    site: u16,
    key: u64,
    ts: u64,
    status: i32,
    aux: u32,
    aux2: u32,
    token: u64,
    name: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x544cu16.to_le_bytes());
    out[2] = 1;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out[28..32].copy_from_slice(&aux.to_le_bytes());
    out[32..36].copy_from_slice(&aux2.to_le_bytes());
    out[40..48].copy_from_slice(&token.to_le_bytes());
    let n = name.len().min(63);
    out[48..48 + n].copy_from_slice(&name[..n]);
    out
}

fn alloc_pair(token: u64, ts: u64, frontend: u64, req: &[u8], drv: &[u8]) -> Vec<Vec<u8>> {
    vec![
        tfm_rec(SUBMIT, ALLOC_SK, 0, ts, 0, 0, 0, token, req),
        tfm_rec(RETURN, ALLOC_SK, frontend, ts + 5, 0, 0, 0, token, drv),
    ]
}

fn setkey_pair(token: u64, ts: u64, frontend: u64, len: u32, errno: i32) -> Vec<Vec<u8>> {
    vec![
        tfm_rec(SUBMIT, SETKEY_SK, frontend, ts, 0, len, 0, token, b""),
        tfm_rec(RETURN, SETKEY_SK, 0, ts + 5, errno, 0, 0, token, b""),
    ]
}

fn destroy_pair(token: u64, ts: u64, base: u64) -> Vec<Vec<u8>> {
    vec![
        tfm_rec(SUBMIT, DESTROY, base, ts, 0, 1, 1, token, b""),
        tfm_rec(RETURN, DESTROY, 0, ts + 5, 0, 0, 0, token, b""),
    ]
}

fn ctx() -> SessionContext {
    SessionContext {
        loss_baseline: [0; 5],
        agg_baseline: [0; 22],
        view_valid: true,
        miss_baseline: Vec::new(),
        enrichment: EnrichmentStatus::Available {
            entries: 0,
            truncated: false,
        },
    }
}

#[test]
fn request_storage_reused_1000_times_has_distinct_ids() {
    let mut core = SensorCore::new(2048, 2048, 2048, 8, 8, true);
    let key = 0xabc_u64; // same request storage, reused 1,000 times
    let frontend = 0xFFFF_8880_0000_1000_u64; // one pre-attach transform
    let mut recs = Vec::with_capacity(2000);
    for i in 0..1000u64 {
        let invoc = 0x4000 + i * 2; // nonzero, poison-bit clear, distinct
        let ts = 100 + i * 10;
        recs.push(op_submit(key, ts, invoc, frontend));
        recs.push(op_return(key, ts + 5, invoc, 0));
    }
    assert_eq!(core.ingest_records(&recs), 1000, "all pairs complete");
    let done = core.take_completed();
    assert_eq!(done.len(), 1000);
    let mut ids: Vec<u64> = done.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 1000, "each admitted invocation owns its id");
    assert_eq!(ids[0], 1, "opaque ids start at 1");
    for r in &done {
        assert_eq!(r.tfm_id, Some(1), "every reuse binds the one generation");
        assert_eq!(r.terminal, Terminal::Sync(0));
        assert_eq!(r.duration_ns, Some(5), "submit→return span, exact");
        assert_eq!(r.meta.family, LifecycleFamily::Skcipher);
        assert_eq!(r.meta.direction, OpDirection::Encrypt);
        assert_eq!(r.meta.cryptlen, Some(16), "API input length at entry");
        assert_eq!(r.meta.req_flags, Some(0), "valid-zero flags stay Some");
        assert_eq!(r.meta.epoch, Some(0), "pre-attach epoch pins 0");
        assert!(r.evidence_valid());
    }
    let gens = core.tfm().generations();
    assert_eq!(gens.len(), 1, "one transform across 1,000 reuses");
    assert!(gens[0].first_seen, "op-only admission is first-seen");
    assert_eq!(core.tfm().stats().unobserved_boundary, 1);
}

#[test]
fn nested_same_storage_returns_pair_to_own_cookie() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let key = 0xabc_u64;
    let frontend = 0xFFFF_8880_0000_1000_u64;
    // Outer submit A, inner submit B (same storage, nested), B returns, A returns.
    let recs = vec![
        op_submit(key, 100, 0x4000, frontend),
        op_submit(key, 110, 0x4002, frontend),
        op_return(key, 120, 0x4002, 0),
        op_return(key, 130, 0x4000, 0),
    ];
    assert_eq!(core.ingest_records(&recs), 2);
    let done = core.take_completed();
    assert_eq!(done.len(), 2);
    assert_ne!(done[0].id, done[1].id, "nested calls own distinct ids");
    // Inner (submitted at 110, returned at 120) completes first.
    assert_eq!(done[0].duration_ns, Some(10), "inner pairs to own cookie");
    assert_eq!(done[1].duration_ns, Some(30), "outer pairs to own cookie");
    for r in &done {
        assert_eq!(r.tfm_id, Some(1));
        assert_eq!(r.terminal, Terminal::Sync(0));
        assert_eq!(r.meta.cryptlen, Some(16));
    }
    let ledger = core.ledger([0; 5], [0; 22], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.decode.admitted, 2);
    assert_eq!(ledger.decode.unknown_invoc_returns, 0);
}

#[test]
fn migration_preserves_invocation() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let key = 0xabc_u64;
    let frontend = 0xFFFF_8880_0000_1000_u64;
    // The exit run reads the per-call cookie, not a CPU-keyed slot: the
    // return carries the SAME invocation even if the thread migrated, so it
    // joins. The entry chase was unreadable here (cryptlen None) — unknown
    // metadata stays explicit and never destroys the identity.
    let submit = edge_v6(
        SUBMIT,
        ENC,
        key,
        100,
        0,
        0x4000,
        frontend,
        None,
        Some(0),
        b"kxcipher-sync",
    );
    assert_eq!(
        core.ingest_records(&[submit, op_return(key, 150, 0x4000, 0)]),
        1,
        "same-invocation return joins across migration"
    );
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].tfm_id, Some(1));
    assert_eq!(done[0].meta.cryptlen, None, "unreadable chase stays None");
    assert_eq!(done[0].meta.req_flags, Some(0));
    // Control: a return with a FLIPPED invocation (what CPU-keyed pairing
    // would emit post-migration) never joins by proximity.
    let joined = core.ingest_records(&[
        op_submit(key, 200, 0x5000, frontend),
        op_return(key, 250, 0x5002, 0),
    ]);
    assert_eq!(joined, 0, "flipped invocation never binds");
    let ledger = core.ledger([0; 5], [0; 22], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.decode.unknown_invoc_returns, 1);
    assert_eq!(ledger.decode.admitted, 2);
}

#[test]
fn missing_submit_never_binds_return() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let key = 0xabc_u64;
    // Return with no submit: counted, never joined, never admitted.
    assert_eq!(core.ingest_records(&[op_return(key, 150, 0x4000, 0)]), 0);
    assert!(core.take_completed().is_empty());
    assert!(core.tfm().generations().is_empty(), "returns never admit");
    assert_eq!(core.tfm().stats().unlinked_ops, 0);
    let ledger = core.ledger([0; 5], [0; 22], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.decode.unknown_invoc_returns, 1);
    assert_eq!(ledger.decode.admitted, 0);
    // Submit with no return: binding happens AT SUBMIT, but the missing
    // return fabricates no terminal — finish drains it truthless.
    assert_eq!(
        core.ingest_records(&[op_submit(key, 200, 0x5000, 0xFFFF_8880_0000_1000)]),
        0
    );
    core.finish(300);
    let done = core.take_completed();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].terminal, Terminal::Unknown);
    assert_eq!(done[0].duration_ns, None);
    assert_eq!(
        done[0].tfm_id,
        Some(1),
        "submit-side binding, return or not"
    );
    assert!(!done[0].evidence_valid());
    let ledger = core.ledger([0; 5], [0; 22], Vec::new(), ctx()).unwrap();
    assert_eq!(ledger.reducer.unfinished, 1);
}

#[test]
fn pre_attach_transform_keeps_creation_unknown() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    // No alloc observed: the op names a pre-attach transform.
    let recs = vec![
        op_submit(0xabc, 100, 0x4000, 0xFFFF_8880_0000_1000),
        op_return(0xabc, 150, 0x4000, 0),
    ];
    assert_eq!(core.ingest_records(&recs), 1);
    let done = core.take_completed();
    assert_eq!(done[0].tfm_id, Some(1));
    assert_eq!(done[0].meta.epoch, Some(0));
    let gens = core.tfm().generations();
    assert_eq!(gens.len(), 1);
    let g = &gens[0];
    assert!(g.first_seen, "admitted first-seen from the op edge");
    assert_eq!(g.req_name, "", "creation name unknown, never fabricated");
    assert_eq!(g.alg_type, 0);
    assert_eq!(g.alg_mask, 0);
    assert_eq!(g.drv_name, "kxcipher-sync", "SELECTED driver captured");
    assert_eq!(g.epoch, 0);
    assert_eq!(g.configs, 0);
    assert!(!g.retired);
    assert_eq!(core.tfm().stats().unobserved_boundary, 1);
    assert!(!core.tfm().reuse_exact(), "first-seen voids exact reuse");
}

#[test]
fn early_enokey_does_not_claim_provider_entry() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let f1 = 0xFFFF_8880_0000_1000_u64;
    // Allocated transform, FAILED key setup: the wrapper failed, so the
    // generation records the failure and the epoch does not move.
    let mut recs = alloc_pair(2, 10, f1, b"kxcipher", b"kxcipher-sync");
    recs.extend(setkey_pair(4, 20, f1, 16, -22));
    // The op fails early with ENOKEY: exact immediate errno, bound to the
    // generation, claiming no provider entry and no successful work.
    recs.push(op_submit(0xabc, 100, 0x4000, f1));
    recs.push(op_return(0xabc, 150, 0x4000, -126)); // -ENOKEY
    assert_eq!(core.ingest_records(&recs), 1);
    let done = core.take_completed();
    assert_eq!(
        done[0].terminal,
        Terminal::Sync(-126),
        "exact immediate errno"
    );
    assert_eq!(done[0].tfm_id, Some(1));
    assert_eq!(done[0].meta.epoch, Some(0), "failed wrapper pins epoch 0");
    assert_eq!(done[0].duration_ns, Some(50));
    let gens = core.tfm().generations();
    assert_eq!(gens.len(), 1);
    assert!(!gens[0].first_seen);
    assert_eq!(gens[0].configs, 1, "failed config recorded");
    assert_eq!(gens[0].epoch, 0, "failed rekey bumps nothing");
    assert_eq!(gens[0].last_config_errno, -22);
    assert_eq!(core.tfm().stats().configs_failed, 1);
    // Control: a SUCCESSFUL key setup IS provider entry — epoch 1 pins.
    let f2 = 0xFFFF_8880_0000_2000_u64;
    let mut recs2 = alloc_pair(6, 200, f2, b"kxcipher", b"kxcipher-sync");
    recs2.extend(setkey_pair(8, 210, f2, 16, 0));
    recs2.push(op_submit(0xdef, 300, 0x4002, f2));
    recs2.push(op_return(0xdef, 350, 0x4002, 0));
    assert_eq!(core.ingest_records(&recs2), 1);
    let done2 = core.take_completed();
    assert_eq!(done2[0].tfm_id, Some(2));
    assert_eq!(done2[0].terminal, Terminal::Sync(0));
    assert_eq!(done2[0].meta.epoch, Some(1), "op ran under keying era 1");
    assert_eq!(core.tfm().generations()[1].epoch, 1);
}

#[test]
fn tfm_binding_uses_submit_lifetime_not_later_reuse() {
    let mut core = SensorCore::new(16, 16, 16, 8, 8, true);
    let f = 0xFFFF_8880_0000_1000_u64; // frontend; base is f+8
    let base = f + 8;
    // G1 allocated; op submits against G1; G1 destroyed (proved final);
    // G2 allocated at the SAME base (slab reuse); op returns.
    let mut recs = alloc_pair(2, 10, f, b"kxcipher", b"kxcipher-sync");
    recs.push(op_submit(0xabc, 100, 0x4000, f));
    recs.extend(destroy_pair(4, 120, base));
    recs.extend(alloc_pair(6, 140, f, b"kxcipher", b"kxcipher-sync"));
    recs.push(op_return(0xabc, 200, 0x4000, 0));
    assert_eq!(core.ingest_records(&recs), 1);
    let done = core.take_completed();
    assert_eq!(
        done[0].tfm_id,
        Some(1),
        "bound at submit to G1, not the later reuse G2"
    );
    assert_eq!(done[0].terminal, Terminal::Sync(0));
    assert_eq!(done[0].duration_ns, Some(100));
    let gens = core.tfm().generations();
    assert_eq!(gens.len(), 2);
    assert!(gens[0].retired, "G1 retired on proved final-free");
    assert!(!gens[1].retired, "G2 holds the reused base");
    assert_eq!((gens[0].id, gens[1].id), (1, 2));
}

// ---------------------------------------------------------------------------
// vng-lane sync guest controls (ignored: privileged + staged guest only).
//
// `guest_sync_meta_matches_fixture_truth` (floor+ kernels): brings up the
// real lifecycle sensor, runs the fixture `sync-meta` scenario, and
// reconciles every observed request record against fixture truth —
// cryptlen/flags/direction/family per op, submit-pinned epochs across a
// mid-run rekey, exact errnos, submit→return spans bounded by the
// fixture's own ktime anchors — plus a raw-transport scan proving the
// new v6 metadata words carry no key bytes.
// `guest_enokey_leaves_provider_unentered` (floor+ kernels): the live
// failed-wrapper control — refused -ENOKEY ops reconcile exactly while
// the provider-body entry marker stays unchanged at zero.
// `guest_below_floor_refuses_typed` (6.12 refusal control): the same
// bring-up refuses with the typed EINVAL/7.0 diagnostic, never a hang
// or a partial attach.
//
// Inputs ride env (guest.py stages them): `KP_T08_BPF_OBJECT` (staged
// `kcrypto-lifecycle.bpf.o`), `KP_T08_RUN` (fixture run id, default
// `run-t08`). A skipped lane prints `verdict=SKIP` — the cell only
// passes on `verdict=PASS`, so a mis-staged guest can never pass by
// skipping.
// ---------------------------------------------------------------------------

const FIXTURE_CTL: &str = "/sys/kernel/debug/kcrypto_fixture/control";
const FIXTURE_LEDGER: &str = "/sys/kernel/debug/kcrypto_fixture/ledger";
/// Fixture setkey bytes (`kxc_key`): the guest privacy marker — the
/// raw v6 transport + every render must contain it zero times.
const FIXTURE_KEY: &[u8] = b"0123456789abcdef";

fn guest_bpf_object() -> Option<std::path::PathBuf> {
    std::env::var_os("KP_T08_BPF_OBJECT").map(std::path::PathBuf::from)
}

fn guest_run_id() -> String {
    std::env::var("KP_T08_RUN").unwrap_or_else(|_| "run-t08".to_owned())
}

fn guest_euid_zero() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// One fixture submit truth row (op/len/flags/errno/submit-ts/return-ts
/// + provider-body entries at the return-row emit).
struct FixtureOp {
    /// Validated at parse: exactly `"encrypt"` or `"decrypt"`.
    op: String,
    len: u32,
    flags: u32,
    errno: i32,
    submit_ts: u64,
    return_ts: u64,
    epoch: u64,
    /// Provider-body entries at the return-row emit (P3r marker).
    entries: u64,
}

/// Strictly parsed fixture transcript for one run.
struct FixtureTruth {
    ops: Vec<FixtureOp>,
    configs_ok: u64,
    configs_failed: u64,
    era: u64,
    /// Provider-body entries over the run (done-row trailer).
    entries: u64,
}

/// Required row field (missing → reject, never default).
fn row_field<'v>(
    v: &'v serde_json::Value,
    line: &str,
    name: &str,
) -> Result<&'v serde_json::Value, String> {
    v.get(name)
        .ok_or_else(|| format!("row lacks field `{name}`: {line}"))
}

fn row_u64(v: &serde_json::Value, line: &str, name: &str) -> Result<u64, String> {
    let f = row_field(v, line, name)?;
    f.as_u64()
        .ok_or_else(|| format!("row field `{name}` is not u64: {line}"))
}

/// Checked narrowing: overflowing scalars REJECT (no `as` casts).
fn row_u32(v: &serde_json::Value, line: &str, name: &str) -> Result<u32, String> {
    let n = row_u64(v, line, name)?;
    u32::try_from(n).map_err(|_| format!("row field `{name}` overflows u32: {line}"))
}

fn row_i32(v: &serde_json::Value, line: &str, name: &str) -> Result<i32, String> {
    let f = row_field(v, line, name)?;
    let n = f
        .as_i64()
        .ok_or_else(|| format!("row field `{name}` is not an integer: {line}"))?;
    i32::try_from(n).map_err(|_| format!("row field `{name}` overflows i32: {line}"))
}

fn row_str<'v>(v: &'v serde_json::Value, line: &str, name: &str) -> Result<&'v str, String> {
    let f = row_field(v, line, name)?;
    f.as_str()
        .ok_or_else(|| format!("row field `{name}` is not a string: {line}"))
}

fn row_bool(v: &serde_json::Value, line: &str, name: &str) -> Result<bool, String> {
    let f = row_field(v, line, name)?;
    f.as_bool()
        .ok_or_else(|| format!("row field `{name}` is not a bool: {line}"))
}

/// Strict fixture-transcript validation (A-P3-N2 + P3r-N1 + P3r2-N1):
/// every row of our run is schema-checked AND stream-state-checked —
/// nonzero unique seqs, checked (non-wrapping) scalars, known op
/// names, submit/return/terminal triples with matching errnos,
/// config/free rows referencing a prior alloc, return/terminal rows
/// requiring a PRECEDING submit for that seq (arrival order, not join
/// existence), allocation finality (no config/free after a final free
/// for that seq), every alloc closed by a free, and DONE closing the
/// stream (no row of our run follows it). Duplicates, zero seqs,
/// wrapping scalars, unknown phases/op names, missing halves,
/// incompatible orders, post-final activity, unclosed allocs,
/// terminal/trailer gaps and failed-run trailers all REJECT. Unknown
/// FIELDS are ignored per the ledger contract (fixture.h:
/// forward-compatible rows); unknown PHASES reject. Foreign runs never
/// leak in.
fn parse_fixture_transcript(text: &str, run: &str) -> Result<FixtureTruth, String> {
    // (seq, op, len, flags, submit-ts, keying era at submit). Ledger
    // order is append order: config rows before a submit pin that
    // submit's keying era, and the era rides the submit tuple so the
    // later seq-sort cannot strand it.
    let mut allocs: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut submits: Vec<(u64, String, u32, u32, u64, u64)> = Vec::new();
    let mut submit_seqs: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut returns: std::collections::HashMap<u64, (i32, u64, u64)> =
        std::collections::HashMap::new();
    let mut terminals: std::collections::HashMap<u64, i32> = std::collections::HashMap::new();
    let mut freed: std::collections::HashSet<u64> = std::collections::HashSet::new();
    // P3r2-N1: alloc seqs whose lifetime ENDED via a final free
    // (testkit R5 keeps `final_free` per alloc,
    // `kernel_crypto_ledger.rs:355`).
    let mut finalized: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut epoch = 0u64;
    let mut configs_ok = 0u64;
    let mut configs_failed = 0u64;
    let mut done: Option<u64> = None;
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("ledger row is not JSON: {e}: {line}"))?;
        let row_run = v
            .get("run")
            .and_then(|r| r.as_str())
            .ok_or_else(|| format!("row lacks run: {line}"))?;
        if row_run != run {
            continue;
        }
        if row_u64(&v, line, "v")? != 1 {
            return Err(format!("row version is not 1: {line}"));
        }
        let phase = row_str(&v, line, "phase")?;
        // P3r-N1: DONE closes the stream — no row of our run may
        // follow the trailer (fixture.h: "no row follows DONE";
        // testkit parse_ledger rejects "row after done" likewise).
        // Foreign rows already skipped above; they never leak in.
        if done.is_some() {
            if phase == "done" {
                return Err(format!("duplicate done trailer: {line}"));
            }
            return Err(format!("row arrives after the done trailer: {line}"));
        }
        match phase {
            "alloc" => {
                let seq = row_u64(&v, line, "seq")?;
                if seq == 0 {
                    return Err(format!("alloc seq is zero: {line}"));
                }
                if !allocs.insert(seq) {
                    return Err(format!("duplicate alloc seq {seq}: {line}"));
                }
                if row_str(&v, line, "req")?.is_empty() || row_str(&v, line, "drv")?.is_empty() {
                    return Err(format!("alloc names are empty: {line}"));
                }
                row_u32(&v, line, "type")?;
                row_u32(&v, line, "mask")?;
                row_u64(&v, line, "ts")?;
            }
            "submit" => {
                let seq = row_u64(&v, line, "seq")?;
                if seq == 0 {
                    return Err(format!("submit seq is zero: {line}"));
                }
                if !submit_seqs.insert(seq) {
                    return Err(format!("duplicate submit seq {seq}: {line}"));
                }
                let op = row_str(&v, line, "op")?;
                if op != "encrypt" && op != "decrypt" {
                    return Err(format!("unsupported op `{op}`: {line}"));
                }
                let len = row_u32(&v, line, "len")?;
                let flags = row_u32(&v, line, "flags")?;
                let ts = row_u64(&v, line, "ts")?;
                submits.push((seq, op.to_owned(), len, flags, ts, epoch));
            }
            "return" => {
                let seq = row_u64(&v, line, "seq")?;
                if seq == 0 {
                    return Err(format!("return seq is zero: {line}"));
                }
                if returns.contains_key(&seq) {
                    return Err(format!("duplicate return seq {seq}: {line}"));
                }
                // P3r-N1: causal order — the submit for this seq must
                // already have arrived (the later join alone cannot
                // prove arrival order).
                if !submit_seqs.contains(&seq) {
                    return Err(format!(
                        "return seq {seq} arrived before its submit: {line}"
                    ));
                }
                let errno = row_i32(&v, line, "errno")?;
                let ts = row_u64(&v, line, "ts")?;
                let entries = row_u64(&v, line, "entries")?;
                returns.insert(seq, (errno, ts, entries));
            }
            "terminal" => {
                let seq = row_u64(&v, line, "seq")?;
                if seq == 0 {
                    return Err(format!("terminal seq is zero: {line}"));
                }
                if terminals.contains_key(&seq) {
                    return Err(format!("duplicate terminal seq {seq}: {line}"));
                }
                // P3r-N1: same causal rule as return. (No order is
                // required between return and terminal: a genuine
                // terminal may land first under preemption — testkit
                // matrix Q04.)
                if !submit_seqs.contains(&seq) {
                    return Err(format!(
                        "terminal seq {seq} arrived before its submit: {line}"
                    ));
                }
                let errno = row_i32(&v, line, "errno")?;
                terminals.insert(seq, errno);
            }
            "config" => {
                let seq = row_u64(&v, line, "seq")?;
                if !allocs.contains(&seq) {
                    return Err(format!("config without a prior alloc: {line}"));
                }
                // P3r2-N1: mirrors testkit R5 — "configuration after
                // the final free configures a dead transform"
                // (`kernel_crypto_ledger.rs:393`, rejects "seq {seq}
                // config arrived after final free").
                if finalized.contains(&seq) {
                    return Err(format!("seq {seq} config arrived after final free: {line}"));
                }
                if row_str(&v, line, "op")? != "setkey" {
                    return Err(format!("unsupported config op: {line}"));
                }
                let errno = row_i32(&v, line, "errno")?;
                row_u32(&v, line, "len")?;
                if errno == 0 {
                    configs_ok += 1;
                    epoch += 1;
                } else {
                    configs_failed += 1;
                }
            }
            "free" => {
                let seq = row_u64(&v, line, "seq")?;
                if !allocs.contains(&seq) {
                    return Err(format!("free without a prior alloc: {line}"));
                }
                // P3r2-N1: mirrors testkit R5 — "a final free ends
                // the lifetime, so any further release is an
                // impossible history (a duplicate final is not a
                // shared release)" (`kernel_crypto_ledger.rs:363`,
                // rejects "seq {seq} free arrived after final free").
                // Only `final:true` ends the lifetime
                // (`kernel_crypto_ledger.rs:373`); non-final
                // releases leave later activity legal.
                if finalized.contains(&seq) {
                    return Err(format!("seq {seq} free arrived after final free: {line}"));
                }
                let is_final = row_bool(&v, line, "final")?;
                freed.insert(seq);
                if is_final {
                    finalized.insert(seq);
                }
            }
            "done" => {
                // (Duplicate done is rejected by the stream-closure
                // check above, with the same message.)
                if row_i32(&v, line, "fixture_result")? != 0 {
                    return Err(format!("failed-run trailer is not truth: {line}"));
                }
                if row_u64(&v, line, "overflow")? != 0 {
                    return Err(format!("ledger overflow trailer is not truth: {line}"));
                }
                done = Some(row_u64(&v, line, "entries")?);
            }
            // Sync transcripts never carry async progress markers: their
            // presence contradicts the sync contract.
            "progress" => return Err(format!("unexpected progress row: {line}")),
            other => return Err(format!("unknown phase `{other}`: {line}")),
        }
    }
    submits.sort_by_key(|s| s.0);
    let mut ops = Vec::with_capacity(submits.len());
    for (seq, op, len, flags, submit_ts, era) in submits {
        let (errno, return_ts, entries) = returns
            .remove(&seq)
            .ok_or_else(|| format!("submit seq {seq} has no return row"))?;
        let term = terminals
            .remove(&seq)
            .ok_or_else(|| format!("submit seq {seq} has no terminal row"))?;
        if term != errno {
            return Err(format!(
                "seq {seq}: terminal errno {term} != return errno {errno}"
            ));
        }
        if return_ts < submit_ts {
            return Err(format!("seq {seq}: return ts precedes submit ts"));
        }
        ops.push(FixtureOp {
            op,
            len,
            flags,
            errno,
            submit_ts,
            return_ts,
            epoch: era,
            entries,
        });
    }
    if let Some(seq) = returns.keys().next() {
        return Err(format!("return seq {seq} has no submit row"));
    }
    if let Some(seq) = terminals.keys().next() {
        return Err(format!("terminal seq {seq} has no submit row"));
    }
    // P3r-N1: closure — every alloc must close with a free (testkit
    // parse_ledger: "allocated but never freed" rejects). Deleting
    // the final-free row trips this. (P3r2-N1: close requires a free
    // row, not `final:true` — testkit finalize requires `freed`, not
    // `final_free` (`kernel_crypto_ledger.rs:482`); accepted.)
    let mut unclosed: Vec<u64> = allocs.difference(&freed).copied().collect();
    unclosed.sort_unstable();
    if let Some(seq) = unclosed.first() {
        return Err(format!("alloc seq {seq} was never freed"));
    }
    let entries = done.ok_or_else(|| "transcript lacks the done trailer".to_owned())?;
    Ok(FixtureTruth {
        ops,
        configs_ok,
        configs_failed,
        era: epoch,
        entries,
    })
}

/// Oracle duration rule (S-P3-N2): the observer submit→return span must
/// be POSITIVE (a zero span proves no submit→return elapsed) and lie
/// within the fixture's own ktime span (+1µs scheduling slack).
fn check_duration_within_span(dur_ns: u64, span_ns: u64) -> Result<(), String> {
    if dur_ns == 0 {
        return Err("observer span is zero: no positive submit→return".to_owned());
    }
    if u128::from(dur_ns) > u128::from(span_ns) + 1000 {
        return Err(format!(
            "observer span {dur_ns} exceeds fixture span {span_ns} + 1000"
        ));
    }
    Ok(())
}

#[test]
fn guest_oracle_reads_truth_not_constants() {
    // The guest oracle compares observer records against PARSED
    // fixture truth (mutation-sensitive: corrupt any row and the
    // parsed truth moves, so a hardcoded oracle cannot hide here).
    // Pins the parser incl. a nonzero immediate errno + a rekey era.
    let text = [
        r#"{"v":1,"run":"r","seq":1,"phase":"alloc","req":"kxcipher-sync-t08","drv":"kxcipher-sync-t08","type":0,"mask":0,"ts":1,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":2,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":10,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"terminal","errno":0,"ts":21,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":30,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"submit","op":"decrypt","len":64,"flags":1024,"ts":40,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"return","errno":-22,"ts":50,"cpu":0,"entries":2}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"terminal","errno":-22,"ts":51,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":60,"cpu":0}"#,
        r#"{"v":1,"run":"r","phase":"done","fixture_result":0,"overflow":0,"entries":2,"ts":70}"#,
        r#"{"v":1,"run":"other","seq":9,"phase":"submit","op":"encrypt","len":1,"flags":0,"ts":60,"cpu":0}"#,
    ]
    .join("\n");
    let truth = parse_fixture_transcript(&text, "r").expect("valid transcript parses");
    let ops = &truth.ops;
    assert_eq!(
        (truth.configs_ok, truth.configs_failed, truth.era),
        (2, 0, 2)
    );
    assert_eq!(ops.len(), 2, "foreign runs never leak in");
    assert_eq!(
        (ops[0].op.as_str(), ops[0].len, ops[0].flags),
        ("encrypt", 16, 0)
    );
    assert_eq!((ops[0].errno, ops[0].epoch), (0, 1));
    assert_eq!((ops[0].submit_ts, ops[0].return_ts), (10, 20));
    assert_eq!(
        (ops[1].op.as_str(), ops[1].len, ops[1].flags),
        ("decrypt", 64, 1024)
    );
    assert_eq!((ops[1].errno, ops[1].epoch), (-22, 2));
    // Mutation: flip one truth byte — the parsed truth MUST move.
    let mutated = text.replace(r#""len":64"#, r#""len":65"#);
    let truth2 = parse_fixture_transcript(&mutated, "r").expect("mutated transcript parses");
    assert_eq!(
        truth2.ops[1].len, 65,
        "oracle tracks the row, not a constant"
    );
}

// ---------------------------------------------------------------------------
// P3r oracle strictness controls (A-P3-N2 / S-P3-N2). Each mutation below
// was ACCEPTED by the P3 oracle (same expectations as the valid ledger);
// the strict transcript must REJECT every one, while the valid control
// keeps parsing. RED: these FAIL against the lenient scaffold above.
// ---------------------------------------------------------------------------

/// Minimal valid transcript: alloc + one successful setkey + two full
/// op triples (submit/return/terminal) + free + done trailer.
fn valid_transcript() -> String {
    [
        r#"{"v":1,"run":"r","seq":1,"phase":"alloc","req":"kxcipher-sync-t08","drv":"kxcipher-sync-t08","type":0,"mask":0,"ts":1,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":2,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":10,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"terminal","errno":0,"ts":21,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"submit","op":"decrypt","len":64,"flags":1024,"ts":40,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"return","errno":0,"ts":50,"cpu":0,"entries":2}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"terminal","errno":0,"ts":51,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":60,"cpu":0}"#,
        r#"{"v":1,"run":"r","phase":"done","fixture_result":0,"overflow":0,"entries":2,"ts":70}"#,
    ]
    .join("\n")
}

#[test]
fn oracle_accepts_valid_transcript() {
    let truth = parse_fixture_transcript(&valid_transcript(), "r").expect("valid parses");
    assert_eq!(truth.ops.len(), 2);
    assert_eq!(
        (truth.configs_ok, truth.configs_failed, truth.era),
        (1, 0, 1)
    );
    assert_eq!(
        truth.ops[0].entries, 1,
        "per-op provider entries ride the return row"
    );
    assert_eq!(truth.ops[1].entries, 2);
    assert_eq!(
        (
            truth.ops[1].op.as_str(),
            truth.ops[1].len,
            truth.ops[1].flags
        ),
        ("decrypt", 64, 1024)
    );
}

#[test]
fn oracle_done_trailer_carries_provider_entries() {
    let truth = parse_fixture_transcript(&valid_transcript(), "r").expect("valid parses");
    assert_eq!(truth.entries, 2, "done trailer totals provider entries");
}

#[test]
fn oracle_rejects_duplicate_return() {
    // Contradictory -22 followed by the original 0 for the same seq:
    // the P3 `insert` silently kept the last write.
    let dup =
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":-22,"ts":19,"cpu":0,"entries":1}"#
            .to_owned()
            + "\n"
            + r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#;
    let text = valid_transcript().replace(
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#,
        &dup,
    );
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "duplicate seq return rows must REJECT"
    );
}

#[test]
fn oracle_rejects_zero_seq() {
    let text = valid_transcript().replace(r#""seq":2"#, r#""seq":0"#);
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "zero seq must REJECT"
    );
}

#[test]
fn oracle_rejects_deleted_terminals_and_trailer() {
    let text = valid_transcript()
        .lines()
        .filter(|l| !l.contains("terminal") && !l.contains("done"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "missing terminal rows + done trailer must REJECT"
    );
}

#[test]
fn oracle_rejects_wrapping_len() {
    // 2^32+64 aliases 64 under `as u32`.
    let text = valid_transcript().replace(r#""len":64"#, r#""len":4294967360"#);
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "overflowing len must REJECT, never wrap"
    );
}

#[test]
fn oracle_rejects_wrapping_errno() {
    // 2^31 overflows i32.
    let text = valid_transcript().replace(r#""errno":0,"ts":50"#, r#""errno":2147483648,"ts":50"#);
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "overflowing errno must REJECT, never wrap"
    );
}

#[test]
fn oracle_rejects_unknown_op() {
    let text = valid_transcript().replace(r#""op":"decrypt""#, r#""op":"aead-decrypt""#);
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "unsupported op name must REJECT, never default to decrypt"
    );
}

#[test]
fn oracle_rejects_return_row_without_entries() {
    let text = valid_transcript().replace(r#""ts":50,"cpu":0,"entries":2"#, r#""ts":50,"cpu":0"#);
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "return row without the entry marker must REJECT"
    );
}

#[test]
fn oracle_rejects_unexpected_progress_row() {
    let text = valid_transcript()
        + "\n"
        + r#"{"v":1,"run":"r","seq":4,"phase":"progress","errno":-115,"ts":55,"cpu":0}"#;
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "async progress row in a sync transcript must REJECT"
    );
}

#[test]
fn oracle_rejects_terminal_errno_mismatch() {
    let text = valid_transcript().replace(
        r#""phase":"terminal","errno":0,"ts":51"#,
        r#""phase":"terminal","errno":-22,"ts":51"#,
    );
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "terminal/return errno mismatch must REJECT"
    );
}

#[test]
fn oracle_rejects_dangling_return() {
    let text = valid_transcript()
        + "\n"
        + r#"{"v":1,"run":"r","seq":9,"phase":"return","errno":0,"ts":80,"cpu":0,"entries":2}"#;
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "return without a submit must REJECT"
    );
}

// ---------------------------------------------------------------------------
// P3r2 stream-state controls (P3r-N1). The P3r oracle validated row
// shapes but not stream state: DONE-first, return-before-submit and
// terminal-before-submit all parsed with identical comparator values,
// and a deleted final-free passed unchanged (witnessed on the sealed
// 7.2.6 ledger). The order-aware transcript must REJECT every
// incompatible order while causally valid orders keep parsing. RED:
// the rejection tests below FAIL against the shape-only parser.
// ---------------------------------------------------------------------------

#[test]
fn oracle_rejects_done_first() {
    // Witness move 1 on the sealed shape: DONE opens the stream, so
    // every content row arrives after the trailer.
    let text = valid_transcript();
    let mut lines: Vec<&str> = text.lines().collect();
    let done = lines.pop().expect("valid transcript ends with done");
    assert!(
        done.contains(r#""phase":"done""#),
        "test setup: last line is done"
    );
    lines.insert(0, done);
    let moved = lines.join("\n");
    assert!(
        parse_fixture_transcript(&moved, "r").is_err(),
        "DONE-first must REJECT: no content row may follow the trailer"
    );
}

#[test]
fn oracle_rejects_row_after_done() {
    // DONE closes the stream: even a well-formed fresh submit after
    // the trailer rejects (fixture.h: "no row follows DONE").
    let text = valid_transcript()
        + "\n"
        + r#"{"v":1,"run":"r","seq":9,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":80,"cpu":0}"#;
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "rows after DONE must REJECT"
    );
}

#[test]
fn oracle_rejects_return_before_submit() {
    // Witness move 2: the first return lands before its submit. The
    // seq join still finds both halves — arrival order must reject.
    let text = valid_transcript();
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(
        lines[2].contains(r#""phase":"submit""#),
        "test setup: line 2 is submit"
    );
    assert!(
        lines[3].contains(r#""phase":"return""#),
        "test setup: line 3 is return"
    );
    lines.swap(2, 3);
    let moved = lines.join("\n");
    assert!(
        parse_fixture_transcript(&moved, "r").is_err(),
        "return before its submit must REJECT"
    );
}

#[test]
fn oracle_rejects_terminal_before_submit() {
    // Witness move 3: the first terminal lands before its submit.
    let text = valid_transcript();
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(
        lines[2].contains(r#""phase":"submit""#),
        "test setup: line 2 is submit"
    );
    assert!(
        lines[4].contains(r#""phase":"terminal""#),
        "test setup: line 4 is terminal"
    );
    lines.swap(2, 4);
    let moved = lines.join("\n");
    assert!(
        parse_fixture_transcript(&moved, "r").is_err(),
        "terminal before its submit must REJECT"
    );
}

#[test]
fn oracle_rejects_deleted_final_free() {
    // The sealed shape carries one final free per alloc: deleting it
    // leaves the alloc unclosed, which the contract rejects.
    let text = valid_transcript()
        .lines()
        .filter(|l| !l.contains(r#""phase":"free""#))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        parse_fixture_transcript(&text, "r").is_err(),
        "deleted final-free must REJECT: every alloc must close"
    );
}

#[test]
fn oracle_accepts_interleaved_submit_order() {
    // Causal, not positional: submits may interleave as long as each
    // return/terminal follows its own submit.
    let text = [
        r#"{"v":1,"run":"r","seq":1,"phase":"alloc","req":"kxcipher-sync-t08","drv":"kxcipher-sync-t08","type":0,"mask":0,"ts":1,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":2,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":10,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"submit","op":"decrypt","len":64,"flags":1024,"ts":40,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"terminal","errno":0,"ts":21,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"return","errno":0,"ts":50,"cpu":0,"entries":2}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"terminal","errno":0,"ts":51,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":60,"cpu":0}"#,
        r#"{"v":1,"run":"r","phase":"done","fixture_result":0,"overflow":0,"entries":2,"ts":70}"#,
    ]
    .join("\n");
    let truth = parse_fixture_transcript(&text, "r").expect("interleaved submits parse");
    assert_eq!(truth.ops.len(), 2);
    assert_eq!(
        (truth.ops[0].submit_ts, truth.ops[1].submit_ts),
        (10, 40),
        "seq-sorted truth keeps submit order"
    );
}

#[test]
fn oracle_accepts_terminal_before_return() {
    // No order requirement between return and terminal: a genuine
    // terminal may land first under preemption (testkit matrix Q04);
    // only the preceding submit is causal.
    let text = valid_transcript();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.swap(3, 4);
    let moved = lines.join("\n");
    let truth = parse_fixture_transcript(&moved, "r").expect("terminal-before-return parses");
    assert_eq!(truth.ops.len(), 2);
}

#[test]
fn oracle_failed_config_holds_era() {
    // Failed key setup: recorded, epoch unmoved (live sync-enokey shape).
    let text = [
        r#"{"v":1,"run":"r","seq":1,"phase":"alloc","req":"kxcipher-sync-t08","drv":"kxcipher-sync-t08","type":0,"mask":0,"ts":1,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":-22,"len":7,"ts":2,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":10,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":-126,"ts":20,"cpu":0,"entries":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"terminal","errno":-126,"ts":21,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":60,"cpu":0}"#,
        r#"{"v":1,"run":"r","phase":"done","fixture_result":0,"overflow":0,"entries":0,"ts":70}"#,
    ]
    .join("\n");
    let truth = parse_fixture_transcript(&text, "r").expect("failed config parses");
    assert_eq!(
        (truth.configs_ok, truth.configs_failed, truth.era),
        (0, 1, 0)
    );
    assert_eq!(truth.ops.len(), 1);
    assert_eq!((truth.ops[0].errno, truth.ops[0].epoch), (-126, 0));
}

// ---------------------------------------------------------------------------
// P3r3 allocation-finality controls (P3r2-N1). The P3r2 oracle discarded
// the `final` flag (`row_bool(...)?;` return dropped) and recorded only
// release presence, so config-after-final-free and free-after-final-free
// parsed with unchanged comparator values — while the fixture's own
// testkit ledger rejects both (R5, `kernel_crypto_ledger.rs:363` for
// free / `:393` for config). The finality-aware transcript must REJECT
// every release/config after a final free while valid orders keep
// parsing. RED: the rejection tests below FAIL against the
// finality-blind parser.
// ---------------------------------------------------------------------------

/// Two-key transcript: mirrors the sealed 7.2.6 meta shape (two
/// successful setkeys bracketing op triples) so Astra's witness moves
/// replay exactly (final-free before the SECOND setkey).
fn two_key_transcript() -> String {
    [
        r#"{"v":1,"run":"r","seq":1,"phase":"alloc","req":"kxcipher-sync-t08","drv":"kxcipher-sync-t08","type":0,"mask":0,"ts":1,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":2,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":10,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"terminal","errno":0,"ts":21,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":30,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"submit","op":"decrypt","len":64,"flags":1024,"ts":40,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"return","errno":0,"ts":50,"cpu":0,"entries":2}"#,
        r#"{"v":1,"run":"r","seq":3,"phase":"terminal","errno":0,"ts":51,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":60,"cpu":0}"#,
        r#"{"v":1,"run":"r","phase":"done","fixture_result":0,"overflow":0,"entries":2,"ts":70}"#,
    ]
    .join("\n")
}

#[test]
fn oracle_rejects_config_after_final_free() {
    // Astra witness move 1 on the sealed 7.2.6 meta ledger: the
    // final-free lands immediately before the second setkey, so a
    // config arrives after the lifetime ended.
    let text = two_key_transcript();
    let mut lines: Vec<&str> = text.lines().collect();
    let free = lines.remove(9);
    assert!(
        free.contains(r#""phase":"free""#),
        "test setup: line 9 is the final free"
    );
    assert!(
        lines[5].contains(r#""phase":"config""#),
        "test setup: line 5 is the second setkey"
    );
    lines.insert(5, free);
    let moved = lines.join("\n");
    let err = match parse_fixture_transcript(&moved, "r") {
        Ok(_) => panic!("config after final-free must REJECT"),
        Err(e) => e,
    };
    assert!(
        err.contains("after final free"),
        "causal finality message: {err}"
    );
}

#[test]
fn oracle_rejects_duplicate_final_free() {
    // Astra witness move 2: the final-free is duplicated before DONE
    // (a duplicate final is not a shared release — testkit R5,
    // `kernel_crypto_ledger.rs:363`).
    let text = two_key_transcript();
    let mut lines: Vec<&str> = text.lines().collect();
    let done = lines.pop().expect("valid transcript ends with done");
    assert!(
        done.contains(r#""phase":"done""#),
        "test setup: last line is done"
    );
    lines.push(r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":61,"cpu":0}"#);
    lines.push(done);
    let moved = lines.join("\n");
    let err = match parse_fixture_transcript(&moved, "r") {
        Ok(_) => panic!("duplicated final-free must REJECT"),
        Err(e) => e,
    };
    assert!(
        err.contains("after final free"),
        "causal finality message: {err}"
    );
}

#[test]
fn oracle_rejects_release_after_final_free() {
    // A non-final release after the final free is still an impossible
    // history: the lifetime already ended (testkit R5,
    // `kernel_crypto_ledger.rs:367` rejects ANY free after final).
    let text = two_key_transcript();
    let mut lines: Vec<&str> = text.lines().collect();
    let done = lines.pop().expect("valid transcript ends with done");
    assert!(
        done.contains(r#""phase":"done""#),
        "test setup: last line is done"
    );
    lines.push(r#"{"v":1,"run":"r","seq":1,"phase":"free","final":false,"ts":61,"cpu":0}"#);
    lines.push(done);
    let moved = lines.join("\n");
    let err = match parse_fixture_transcript(&moved, "r") {
        Ok(_) => panic!("release after final-free must REJECT"),
        Err(e) => e,
    };
    assert!(
        err.contains("after final free"),
        "causal finality message: {err}"
    );
}

#[test]
fn oracle_accepts_two_key_valid_transcript() {
    // Valid-order control: the two-key base (final-free at end)
    // parses with both keying eras.
    let truth = parse_fixture_transcript(&two_key_transcript(), "r").expect("two-key parses");
    assert_eq!(truth.ops.len(), 2);
    assert_eq!(
        (truth.configs_ok, truth.configs_failed, truth.era),
        (2, 0, 2)
    );
    assert_eq!((truth.ops[0].epoch, truth.ops[1].epoch), (1, 2));
}

#[test]
fn oracle_accepts_activity_after_nonfinal_free() {
    // Valid-order control: a non-final release does NOT end the
    // lifetime — later configs and the eventual final free parse
    // (testkit: only `final:true` sets `final_free`,
    // `kernel_crypto_ledger.rs:373`).
    let text = [
        r#"{"v":1,"run":"r","seq":1,"phase":"alloc","req":"kxcipher-sync-t08","drv":"kxcipher-sync-t08","type":0,"mask":0,"ts":1,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":2,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":false,"ts":3,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":30,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":10,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"terminal","errno":0,"ts":21,"cpu":1}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":60,"cpu":0}"#,
        r#"{"v":1,"run":"r","phase":"done","fixture_result":0,"overflow":0,"entries":1,"ts":70}"#,
    ]
    .join("\n");
    let truth = parse_fixture_transcript(&text, "r").expect("post-release activity parses");
    assert_eq!(
        (truth.configs_ok, truth.configs_failed, truth.era),
        (2, 0, 2)
    );
    assert_eq!(truth.ops.len(), 1);
}

#[test]
fn oracle_accepts_requests_after_final_free() {
    // Accepted boundary: submit/return/terminal rows carry request
    // seqs in a separate namespace with no alloc linkage — testkit
    // `parse_ledger` never consults `final_free` for them (only the
    // free branch `:359-385` and config branch `:386-409` read it),
    // so no rejection is mirrored here. Pins the mirror decision.
    let text = [
        r#"{"v":1,"run":"r","seq":1,"phase":"alloc","req":"kxcipher-sync-t08","drv":"kxcipher-sync-t08","type":0,"mask":0,"ts":1,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"config","op":"setkey","errno":0,"len":16,"ts":2,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":1,"phase":"free","final":true,"ts":3,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"submit","op":"encrypt","len":16,"flags":0,"ts":10,"cpu":0}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"return","errno":0,"ts":20,"cpu":0,"entries":1}"#,
        r#"{"v":1,"run":"r","seq":2,"phase":"terminal","errno":0,"ts":21,"cpu":1}"#,
        r#"{"v":1,"run":"r","phase":"done","fixture_result":0,"overflow":0,"entries":1,"ts":70}"#,
    ]
    .join("\n");
    let truth = parse_fixture_transcript(&text, "r").expect("requests after final-free parse");
    assert_eq!(truth.ops.len(), 1);
}

#[test]
fn oracle_duration_zero_is_rejected() {
    assert!(
        check_duration_within_span(0, 3938).is_err(),
        "Some(0) must FAIL: a zero span proves no positive submit→return"
    );
    assert!(check_duration_within_span(0, 0).is_err());
}

#[test]
fn oracle_duration_bounds_are_checked() {
    // Sealed 7.2.6 spans were 1,523–3,938 ns; the observer window sits
    // strictly inside the fixture window.
    assert!(check_duration_within_span(1500, 1523).is_ok());
    assert!(check_duration_within_span(1, 1523).is_ok());
    assert!(check_duration_within_span(1523, 1523).is_ok());
    assert!(check_duration_within_span(2523, 1523).is_ok(), "slack edge");
    assert!(
        check_duration_within_span(2524, 1523).is_err(),
        "past slack"
    );
}

#[test]
#[ignore = "BPF lane: vng lane, staged guest with fixture + BPF object (KP_T08_BPF_OBJECT)"]
fn guest_sync_meta_matches_fixture_truth() {
    if std::env::var("KP_T08_EXPECT").as_deref() == Ok("refusal") {
        println!("verdict=SKIP reason=wrong-cell-for-expect");
        return;
    }
    if !guest_euid_zero() {
        println!("verdict=SKIP reason=needs-root");
        return;
    }
    let Some(object_path) = guest_bpf_object() else {
        println!("verdict=SKIP reason=no-bpf-object");
        return;
    };
    if std::fs::metadata(FIXTURE_CTL).is_err() {
        println!("verdict=SKIP reason=no-fixture");
        return;
    }
    let run = guest_run_id();
    let bytes = std::fs::read(&object_path).expect("staged BPF object reads");
    let (mut sensor, points) =
        LifecycleSensor::bring_up(&bytes, None).expect("floor+ sensor attaches");
    assert_eq!(points.len(), 7, "seven fsession links");
    assert_eq!(sensor.attached_points(), 7);

    // Run the fixture scenario (GO is synchronous — the write blocks
    // until the scenario completes or fails).
    std::fs::write(FIXTURE_CTL, format!("PREPARE {run} sync-meta 42")).expect("PREPARE");
    let status = std::fs::read_to_string(FIXTURE_CTL).expect("control reads");
    assert!(status.contains("prepared=1"), "READY: {status}");
    std::fs::write(FIXTURE_CTL, "GO").expect("GO runs sync-meta");
    let status = std::fs::read_to_string(FIXTURE_CTL).expect("control reads");
    assert!(status.contains("done=1"), "DONE: {status}");
    assert!(status.contains("fixture_result=0"), "result 0: {status}");
    assert!(status.contains("overflow=0"), "no ledger drops: {status}");
    let ledger_text = std::fs::read_to_string(FIXTURE_LEDGER).expect("ledger reads");
    let truth = parse_fixture_transcript(&ledger_text, &run).expect("strict transcript validates");
    let ops = &truth.ops;
    assert_eq!(ops.len(), 12, "sync-meta runs 12 ops");
    assert_eq!(
        (truth.configs_ok, truth.configs_failed, truth.era),
        (2, 0, 2),
        "two keying eras"
    );
    assert_eq!(
        truth.entries, 12,
        "positive control: the provider body ran once per op"
    );

    // Drain to quiet (bounded): raw-transport tap feeds the privacy
    // scan; ingest is the identical production path.
    let mut raw_bytes: Vec<u8> = Vec::new();
    let mut quiet_rounds = 0u32;
    for _ in 0..40 {
        let (outcome, raw) = sensor.drain_once_raw(8192).expect("drain");
        for rec in &raw {
            raw_bytes.extend_from_slice(rec);
        }
        if outcome.completed == 0 && outcome.records == 0 {
            quiet_rounds += 1;
            if quiet_rounds >= 3 {
                break;
            }
        } else {
            quiet_rounds = 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let done = sensor.take_completed();
    let gens = sensor.tfm().generations();
    let fx: Vec<_> = gens
        .iter()
        .filter(|g| g.req_name.starts_with("kxcipher-sync"))
        .collect();
    assert_eq!(fx.len(), 1, "one fixture generation: {gens:?}");
    let fxgen = fx[0];
    assert!(!fxgen.first_seen, "alloc observed first");
    assert_eq!(fxgen.drv_name, fxgen.req_name, "exact-driver alloc");
    assert_eq!((fxgen.configs, fxgen.epoch), (2, 2), "two successful keys");
    let mine: Vec<_> = done.iter().filter(|r| r.tfm_id == Some(fxgen.id)).collect();
    let background = done.len() - mine.len();
    println!(
        "guest=records total={} fixture={} background={background}",
        done.len(),
        mine.len()
    );
    assert_eq!(mine.len(), 12, "12 fixture ops observed");
    assert_eq!(background, 0, "quiet guest: no background skcipher traffic");
    for (i, (rec, truth)) in mine.iter().zip(ops.iter()).enumerate() {
        assert_eq!(
            rec.terminal,
            Terminal::Sync(truth.errno),
            "op {i}: exact immediate errno"
        );
        assert_eq!(rec.meta.family, LifecycleFamily::Skcipher, "op {i}");
        // Total: the strict parser admits only "encrypt"/"decrypt".
        let want_dir = if truth.op == "encrypt" {
            OpDirection::Encrypt
        } else {
            OpDirection::Decrypt
        };
        assert_eq!(rec.meta.direction, want_dir, "op {i}");
        assert_eq!(rec.meta.cryptlen, Some(truth.len), "op {i}: API length");
        assert_eq!(rec.meta.req_flags, Some(truth.flags), "op {i}: req flags");
        assert_eq!(
            rec.meta.epoch,
            Some(truth.epoch),
            "op {i}: submit-pinned era"
        );
        assert_eq!(
            truth.entries,
            i as u64 + 1,
            "op {i}: provider entered exactly once per op"
        );
        let span = truth
            .return_ts
            .checked_sub(truth.submit_ts)
            .expect("fixture span non-negative");
        let dur = rec.duration_ns.expect("sync duration");
        check_duration_within_span(dur, span)
            .unwrap_or_else(|e| panic!("op {i}: product span {dur}: {e}"));
        // Replayable per-op row: observer duration + fixture edge
        // timestamps + span, so the duration verdict reconciles from
        // this log plus the sealed ledger alone.
        println!(
            "guest=op i={i} op={} len={} flags={} epoch={} errno={} \
             dur_ns={dur} submit_ts={} return_ts={} span_ns={span} entries={}",
            truth.op,
            truth.len,
            truth.flags,
            truth.epoch,
            truth.errno,
            truth.submit_ts,
            truth.return_ts,
            truth.entries,
        );
    }
    // Privacy: the fixture key appears in NO raw v6 record and NO
    // render (the metadata words are fixed-offset u32 scalars —
    // structurally incapable of carrying key bytes; the scan is the
    // tripwire, not the argument).
    let hits = raw_bytes
        .windows(FIXTURE_KEY.len())
        .filter(|w| *w == FIXTURE_KEY)
        .count();
    assert_eq!(hits, 0, "raw transport carries no key bytes");
    let rendered = format!("{done:?} {gens:?}");
    assert!(
        !rendered.contains("0123456789abcdef"),
        "renders carry no key bytes"
    );
    println!("guest=privacy raw_bytes={} key_hits=0", raw_bytes.len());
    println!("verdict=PASS ops=12 epochs=1,2 entries=12");
}

#[test]
#[ignore = "BPF lane: vng lane, staged guest with fixture + BPF object (KP_T08_BPF_OBJECT)"]
fn guest_enokey_leaves_provider_unentered() {
    // Live failed-wrapper control (S-P3-N1/A-P3-N3): the fixture runs
    // encrypt/decrypt with no usable key, so the crypto wrapper must
    // refuse each op early with -ENOKEY. The observer reconciles the
    // refused ops (exact errno, metadata, era 0, positive bounded
    // spans) while the provider-body entry marker stays UNCHANGED at
    // zero — errno alone cannot prove that, because the provider
    // itself returns -ENOKEY after entry when keyless.
    if std::env::var("KP_T08_EXPECT").as_deref() == Ok("refusal") {
        println!("verdict=SKIP reason=wrong-cell-for-expect");
        return;
    }
    if !guest_euid_zero() {
        println!("verdict=SKIP reason=needs-root");
        return;
    }
    let Some(object_path) = guest_bpf_object() else {
        println!("verdict=SKIP reason=no-bpf-object");
        return;
    };
    if std::fs::metadata(FIXTURE_CTL).is_err() {
        println!("verdict=SKIP reason=no-fixture");
        return;
    }
    let run = guest_run_id();
    let bytes = std::fs::read(&object_path).expect("staged BPF object reads");
    let (mut sensor, points) =
        LifecycleSensor::bring_up(&bytes, None).expect("floor+ sensor attaches");
    assert_eq!(points.len(), 7, "seven fsession links");
    assert_eq!(sensor.attached_points(), 7);

    std::fs::write(FIXTURE_CTL, format!("PREPARE {run} sync-enokey 42")).expect("PREPARE");
    let status = std::fs::read_to_string(FIXTURE_CTL).expect("control reads");
    assert!(status.contains("prepared=1"), "READY: {status}");
    std::fs::write(FIXTURE_CTL, "GO").expect("GO runs sync-enokey");
    let status = std::fs::read_to_string(FIXTURE_CTL).expect("control reads");
    assert!(status.contains("done=1"), "DONE: {status}");
    assert!(status.contains("fixture_result=0"), "result 0: {status}");
    assert!(status.contains("overflow=0"), "no ledger drops: {status}");
    let ledger_text = std::fs::read_to_string(FIXTURE_LEDGER).expect("ledger reads");
    let truth = parse_fixture_transcript(&ledger_text, &run).expect("strict transcript validates");
    let ops = &truth.ops;
    assert_eq!(ops.len(), 4, "sync-enokey runs 4 refused ops");
    assert_eq!(
        (truth.configs_ok, truth.configs_failed, truth.era),
        (0, 1, 0),
        "one failed key setup, epoch unmoved"
    );
    assert_eq!(
        truth.entries, 0,
        "failed wrapper path leaves provider-body entries UNCHANGED at 0"
    );

    let mut raw_bytes: Vec<u8> = Vec::new();
    let mut quiet_rounds = 0u32;
    for _ in 0..40 {
        let (outcome, raw) = sensor.drain_once_raw(8192).expect("drain");
        for rec in &raw {
            raw_bytes.extend_from_slice(rec);
        }
        if outcome.completed == 0 && outcome.records == 0 {
            quiet_rounds += 1;
            if quiet_rounds >= 3 {
                break;
            }
        } else {
            quiet_rounds = 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let done = sensor.take_completed();
    let gens = sensor.tfm().generations();
    let fx: Vec<_> = gens
        .iter()
        .filter(|g| g.req_name.starts_with("kxcipher-sync"))
        .collect();
    assert_eq!(fx.len(), 1, "one fixture generation: {gens:?}");
    let fxgen = fx[0];
    assert!(!fxgen.first_seen, "alloc observed first");
    assert_eq!(
        (fxgen.configs, fxgen.epoch),
        (1, 0),
        "failed config recorded, epoch unmoved"
    );
    let mine: Vec<_> = done.iter().filter(|r| r.tfm_id == Some(fxgen.id)).collect();
    let background = done.len() - mine.len();
    println!(
        "guest=records total={} fixture={} background={background}",
        done.len(),
        mine.len()
    );
    assert_eq!(mine.len(), 4, "4 refused fixture ops observed");
    assert_eq!(background, 0, "quiet guest: no background skcipher traffic");
    for (i, (rec, truth)) in mine.iter().zip(ops.iter()).enumerate() {
        assert_eq!(
            rec.terminal,
            Terminal::Sync(-126),
            "op {i}: exact immediate -ENOKEY"
        );
        assert_eq!(truth.errno, -126, "op {i}: fixture refused early");
        assert_eq!(rec.meta.family, LifecycleFamily::Skcipher, "op {i}");
        // Total: the strict parser admits only "encrypt"/"decrypt".
        let want_dir = if truth.op == "encrypt" {
            OpDirection::Encrypt
        } else {
            OpDirection::Decrypt
        };
        assert_eq!(rec.meta.direction, want_dir, "op {i}");
        assert_eq!(rec.meta.cryptlen, Some(truth.len), "op {i}: API length");
        assert_eq!(rec.meta.req_flags, Some(truth.flags), "op {i}: req flags");
        assert_eq!(
            rec.meta.epoch,
            Some(0),
            "op {i}: failed wrapper pins epoch 0"
        );
        assert_eq!(
            truth.entries, 0,
            "op {i}: provider body not entered on the refused path"
        );
        let span = truth
            .return_ts
            .checked_sub(truth.submit_ts)
            .expect("fixture span non-negative");
        let dur = rec.duration_ns.expect("sync duration");
        check_duration_within_span(dur, span)
            .unwrap_or_else(|e| panic!("op {i}: product span {dur}: {e}"));
        println!(
            "guest=op i={i} op={} len={} flags={} epoch={} errno={} \
             dur_ns={dur} submit_ts={} return_ts={} span_ns={span} entries={}",
            truth.op,
            truth.len,
            truth.flags,
            truth.epoch,
            truth.errno,
            truth.submit_ts,
            truth.return_ts,
            truth.entries,
        );
    }
    let hits = raw_bytes
        .windows(FIXTURE_KEY.len())
        .filter(|w| *w == FIXTURE_KEY)
        .count();
    assert_eq!(hits, 0, "raw transport carries no key bytes");
    let rendered = format!("{done:?} {gens:?}");
    assert!(
        !rendered.contains("0123456789abcdef"),
        "renders carry no key bytes"
    );
    println!("guest=privacy raw_bytes={} key_hits=0", raw_bytes.len());
    println!("verdict=PASS ops=4 enokey=-126 entries=0");
}

#[test]
#[ignore = "BPF lane: vng lane, 6.12 refusal control (KP_T08_EXPECT=refusal)"]
fn guest_below_floor_refuses_typed() {
    if std::env::var("KP_T08_EXPECT").as_deref() != Ok("refusal") {
        println!("verdict=SKIP reason=wrong-cell-for-expect");
        return;
    }
    if !guest_euid_zero() {
        println!("verdict=SKIP reason=needs-root");
        return;
    }
    let Some(object_path) = guest_bpf_object() else {
        println!("verdict=SKIP reason=no-bpf-object");
        return;
    };
    let bytes = std::fs::read(&object_path).expect("staged BPF object reads");
    let err = match LifecycleSensor::bring_up(&bytes, None) {
        Ok(_) => panic!("below-floor bring-up must refuse, never attach"),
        Err(err) => err,
    };
    // Typed refusal (T07 shape): fsession load fails EINVAL with the
    // 7.0 hint — bring_up's contract drops any partial state, so a
    // returned error always means no live sensor.
    assert!(
        matches!(err, ConfiguredError::Load(_)),
        "refusal is a typed load error: {err:?}"
    );
    assert_eq!(err.bringup_errno(), 22, "EINVAL: {err:?}");
    assert!(
        err.to_string().contains("7.0"),
        "diagnostic names the floor: {err}"
    );
    println!("verdict=PASS refusal={err:?}");
}
