// SPDX-License-Identifier: GPL-3.0-or-later
//! K5 Task 4: who-row decode + stack symbolizer + latency surfacing.
//!
//! Unprivileged: the symbolizer is pure over fixture text, who decode is
//! pure over a hand-built [`WhoSnapshot`](kryprobe_privilege::kcrypto_backend::WhoSnapshot),
//! and the agg `key_hash`/`lat` pins decode a hand-encoded row through the
//! frozen [`Backend`](kryprobe_core::backend::Backend) trait.

use kryprobe_abi::kcrypto_agg::{
    KATTRLOSS_CAP, KATTRLOSS_SLOTS, KCTX_PROC, KFAM_SK, KIDN_DROPS, KOP_ENC, KPROG_AEADDEC,
    KPROG_SHASH, KPROG_SKENC, KRES_OK, KWHO_IDENTITY_PRESENT, KWhoKey, N_KPROGS, VParams, VWho,
    kattrloss_fold, kh_of, try_fold_vwho,
};
use kryprobe_abi::kcrypto_ctx::{KCTX_MAX_ENTRIES, VCtx, try_fold_vctx};
use kryprobe_core::backend::{Backend, DecodeContext};
use kryprobe_core::enums::EvidencePhase;
use kryprobe_core::evidence::{IntegritySummary, NativeObservation};
use kryprobe_core::ids::{IdIssuer, ObservationId, PlanGeneration, SessionId};
use kryprobe_privilege::kallsyms::{SymTable, read_kallsyms, symbolize, symbolize_with};
use kryprobe_privilege::kcrypto_backend::{KCryptoBackend, WhoSnapshot, observation_for_who};
use kryprobe_privilege::kcrypto_snapshot::{RowBytes, raw_event_for_agg};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Tiny map for unit symbolization (the brief's verbatim shape).
const TINY_MAP: &str = "ffffffff81000000 T _stext\n\
    ffffffff81001000 T hash_sendmsg\n\
    ffffffff81002000 T _etext\n";

/// Hand-written 6-line fixture (nearest-below pins + helper/type coverage).
const FIXTURE: &str = include_str!("data/kallsyms-sample.txt");

#[test]
fn k5_symbolize_nearest_below() {
    let map =
        "ffffffff81000000 T _stext\nffffffff81001000 T hash_sendmsg\nffffffff81002000 T _etext\n";
    let out = symbolize(&[0xffffffff81001500], map);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg"));
    let out = symbolize(&[0x10], "garbage\n");
    assert_eq!(out[0].sym, None);
    // IPs echo through; empty input yields empty output.
    let out = symbolize(&[0xffffffff81001500], map);
    assert_eq!(out[0].ip, 0xffffffff81001500);
    assert!(symbolize(&[], map).is_empty());
}

#[test]
fn k5_symbolize_fixture_file() {
    assert_eq!(FIXTURE.lines().count(), 6, "hand-written 6-line fixture");
    // Exact hit.
    let out = symbolize(&[0xffffffff81001000], FIXTURE);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg"));
    // Floor across a gap (local `t` type symbolizes like globals).
    let out = symbolize(&[0xffffffff81001800], FIXTURE);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg_helper"));
    // Below the first entry: no floor, `None`.
    let out = symbolize(&[0xffffffff80ffffff], FIXTURE);
    assert_eq!(out[0].sym, None);
    // Past the last entry: floor is the last symbol.
    let out = symbolize(&[0xffffffff81004099], FIXTURE);
    assert_eq!(out[0].sym.as_deref(), Some("crypto_alloc_tfm_node"));
}

#[test]
fn k5_symbolize_ignores_hidden_and_unparseable() {
    // `kptr_restrict` hides addresses as zero: zero entries must not
    // capture every IP (spec §2.2: hidden addrs -> `sym: null`).
    let hidden = "0000000000000000 T hidden_a\n0000000000000000 T hidden_b\n";
    let out = symbolize(&[0xffffffff81001500], hidden);
    assert_eq!(out[0].sym, None);
    // Mixed: the zero line is skipped, the real line still floors.
    let mixed =
        "0000000000000000 T hidden\nffffffff81001000 T hash_sendmsg\nnot-an-addr T bogus\nshort\n";
    let out = symbolize(&[0xffffffff81001500, 0x10], mixed);
    assert_eq!(out[0].sym.as_deref(), Some("hash_sendmsg"));
    assert_eq!(out[1].sym, None);
    // Empty map: all `None`.
    let out = symbolize(&[0xffffffff81001500], "");
    assert_eq!(out[0].sym, None);
}

#[test]
fn k5_read_kallsyms_never_fails() {
    // Best-effort: a `String` on every machine (empty when unreadable),
    // never `Err`, never a panic; whatever it holds must symbolize cleanly.
    let text = read_kallsyms();
    let out = symbolize(&[0xffffffff81001500], &text);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ip, 0xffffffff81001500);
}

#[test]
fn sym_table_parse_once_shared_across_rows() {
    // 2B-C2: one parse per tick, shared across all who rows. Decoding two
    // rows against the same table must match, with the parse explicit and
    // singular at the call site (the tick used to re-parse + re-sort the
    // whole map for every who row).
    let table = SymTable::parse(TINY_MAP);
    let snap = who_snapshot(true, true);
    let first = observation_for_who(&snap, ObservationId::new(7), &table);
    let second = observation_for_who(&snap, ObservationId::new(8), &table);
    assert_eq!(first.backend_payload, second.backend_payload);
    let frames = first
        .backend_payload
        .get("stack")
        .and_then(|s| s.get("frames"))
        .and_then(Value::as_array)
        .expect("frames array");
    assert_eq!(
        frames[0].get("sym").and_then(Value::as_str),
        Some("hash_sendmsg")
    );
}

#[test]
fn symbolize_with_matches_symbolize() {
    // Refactor guard: the shared-table path must equal the legacy
    // per-call parse path on every input shape.
    let cases: [&[u64]; 3] = [&[0xffffffff81001500], &[0x10], &[]];
    for text in [TINY_MAP, FIXTURE, "garbage\n", ""] {
        let table = SymTable::parse(text);
        for ips in cases {
            assert_eq!(symbolize_with(ips, &table), symbolize(ips, text));
        }
    }
}

/// Hand-built `WhoSnapshot` with comm `python3`; the ok-flags shape the
/// DATA exactly as the BPF does when the chase is skipped: `parent_ok=false`
/// leaves `ppid`/`pcomm` zero, `params_ok=false` leaves `params` absent.
fn who_snapshot(parent_ok: bool, params_ok: bool) -> WhoSnapshot {
    let mut comm = [0u8; 16];
    comm[..7].copy_from_slice(b"python3");
    let mut pcomm = [0u8; 16];
    if parent_ok {
        pcomm[..4].copy_from_slice(b"bash");
    }
    WhoSnapshot {
        key: KWhoKey {
            kh: 0x8e83_4f55_dbe2_59a5,
            tgid: 4242,
            _pad: 0,
        },
        val: VWho {
            comm,
            tid: 4243,
            uid: 1000,
            cgroup: 0x9c,
            ppid: if parent_ok { 12 } else { 0 },
            pcomm,
            stack: 3,
            calls: 7,
            first_ns: 111,
            last_ns: 222,
            identity_present: KWHO_IDENTITY_PRESENT,
            _rsv: 0,
        },
        stack_ips: vec![0xffffffff81001500],
        first_errno: None,
        params: params_ok.then_some(VParams {
            blocksize: 16,
            ivsize: 16,
            min_keysize: 16,
            max_keysize: 32,
        }),
    }
}

/// Decode the hand-built fixture (both ok-flags false: parent zeroed,
/// params absent).
fn decode_who_fixture(parent_ok: bool, params_ok: bool) -> NativeObservation {
    let table = SymTable::parse(TINY_MAP);
    observation_for_who(
        &who_snapshot(parent_ok, params_ok),
        ObservationId::new(1),
        &table,
    )
}

#[test]
fn k5_who_row_omits_unresolved() {
    let obs = decode_who_fixture(/* parent_ok=false, params_ok=false */ false, false);
    let p = &obs.backend_payload;
    assert!(p.get("ppid").is_none() && p.get("blocksize").is_none());
    assert_eq!(p.get("comm").and_then(Value::as_str), Some("python3"));
}

#[test]
fn k5_who_row_exact_keys_when_resolved() {
    let mut snap = who_snapshot(true, true);
    snap.first_errno = Some(-5);
    let table = SymTable::parse(TINY_MAP);
    let obs = observation_for_who(&snap, ObservationId::new(2), &table);
    assert_eq!(obs.phase, EvidencePhase::Discovered);
    let p = &obs.backend_payload;
    assert_eq!(p.get("row").and_then(Value::as_str), Some("who"));
    assert_eq!(
        p.get("key_hash").and_then(Value::as_u64),
        Some(0x8e83_4f55_dbe2_59a5)
    );
    assert_eq!(p.get("tgid").and_then(Value::as_u64), Some(4242));
    assert_eq!(p.get("tid").and_then(Value::as_u64), Some(4243));
    assert_eq!(p.get("comm").and_then(Value::as_str), Some("python3"));
    assert_eq!(p.get("uid").and_then(Value::as_u64), Some(1000));
    assert_eq!(p.get("cgroup").and_then(Value::as_u64), Some(0x9c));
    assert_eq!(p.get("ppid").and_then(Value::as_u64), Some(12));
    assert_eq!(p.get("pcomm").and_then(Value::as_str), Some("bash"));
    assert_eq!(p.get("calls").and_then(Value::as_u64), Some(7));
    assert_eq!(p.get("first_ns").and_then(Value::as_u64), Some(111));
    assert_eq!(p.get("last_ns").and_then(Value::as_u64), Some(222));
    assert_eq!(p.get("blocksize").and_then(Value::as_u64), Some(16));
    assert_eq!(p.get("ivsize").and_then(Value::as_u64), Some(16));
    assert_eq!(p.get("min_keysize").and_then(Value::as_u64), Some(16));
    assert_eq!(p.get("max_keysize").and_then(Value::as_u64), Some(32));
    assert_eq!(p.get("first_errno").and_then(Value::as_i64), Some(-5));
    // Stack: id echoes, frames symbolize through the map.
    assert_eq!(
        p.get("stack")
            .and_then(|s| s.get("id"))
            .and_then(Value::as_i64),
        Some(3)
    );
    let frames = p
        .get("stack")
        .and_then(|s| s.get("frames"))
        .and_then(Value::as_array)
        .expect("frames array");
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].get("ip").and_then(Value::as_u64),
        Some(0xffffffff81001500)
    );
    assert_eq!(
        frames[0].get("sym").and_then(Value::as_str),
        Some("hash_sendmsg")
    );
    // The full key set is exactly the brief's list (plus the `row` discriminator).
    let keys: BTreeSet<&str> = p
        .as_object()
        .expect("payload object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "row",
        "key_hash",
        "tgid",
        "tid",
        "comm",
        "uid",
        "cgroup",
        "ppid",
        "pcomm",
        "stack",
        "calls",
        "first_ns",
        "last_ns",
        "blocksize",
        "ivsize",
        "min_keysize",
        "max_keysize",
        "first_errno",
        "capture_profile",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
}

#[test]
fn k5_who_row_omit_key_set_when_unresolved() {
    let obs = decode_who_fixture(false, false);
    let keys: BTreeSet<&str> = obs
        .backend_payload
        .as_object()
        .expect("payload object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "row",
        "key_hash",
        "tgid",
        "tid",
        "comm",
        "uid",
        "cgroup",
        "stack",
        "calls",
        "first_ns",
        "last_ns",
        "capture_profile",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
    // The stack survives omission (id + frames are never gated).
    assert_eq!(
        obs.backend_payload
            .get("stack")
            .and_then(|s| s.get("frames"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn k5_who_row_first_errno_rule() {
    // Task 2 review M-1: render ONLY when < 0 and not -EINPROGRESS/-EBUSY.
    for (input, expected) in [
        (None, None),
        (Some(0), None),
        (Some(5), None),
        (Some(-115), None),
        (Some(-16), None),
        (Some(-5), Some(-5)),
        (Some(-22), Some(-22)),
    ] {
        let mut snap = who_snapshot(false, false);
        snap.first_errno = input;
        let table = SymTable::parse(TINY_MAP);
        let obs = observation_for_who(&snap, ObservationId::new(3), &table);
        assert_eq!(
            obs.backend_payload
                .get("first_errno")
                .and_then(Value::as_i64),
            expected,
            "first_errno render for input {input:?}"
        );
    }
}

#[test]
fn k5_who_row_negative_stack_id_renders_empty_frames() {
    // Task 4 review M1: a negative `stack` (raw helper errno) has no
    // KSTACK row, so `frames` is empty and `id` echoes the errno.
    let mut snap = who_snapshot(false, false);
    snap.val.stack = -14;
    snap.stack_ips = Vec::new();
    let table = SymTable::parse(TINY_MAP);
    let obs = observation_for_who(&snap, ObservationId::new(5), &table);
    let stack = obs.backend_payload.get("stack").expect("stack block");
    assert_eq!(stack.get("id").and_then(Value::as_i64), Some(-14));
    assert_eq!(
        stack.get("frames").and_then(Value::as_array).map(Vec::len),
        Some(0)
    );
}

#[test]
fn k5_who_row_frames_null_when_unresolvable() {
    let snap = who_snapshot(false, false);
    let table = SymTable::parse("garbage\n");
    let obs = observation_for_who(&snap, ObservationId::new(4), &table);
    let frames = obs
        .backend_payload
        .get("stack")
        .and_then(|s| s.get("frames"))
        .and_then(Value::as_array)
        .expect("frames array");
    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0].get("ip").and_then(Value::as_u64),
        Some(0xffffffff81001500),
        "raw ip kept"
    );
    assert!(
        frames[0].get("sym").is_some_and(Value::is_null),
        "unresolvable sym is null"
    );
}

/// Hand 382B agg payload: skcipher/encrypt/ok/proc, `t-alg`/`t-drv`,
/// nonzero latency buckets to pin passthrough.
fn agg_payload_with_lat(lat: [u64; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(382);
    out.push(0x01);
    out.push(1);
    out.extend_from_slice(&[KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC]);
    let mut alg = [0u8; 128];
    alg[..6].copy_from_slice(b"t-alg\0");
    out.extend_from_slice(&alg);
    let mut drv = [0u8; 128];
    drv[..6].copy_from_slice(b"t-drv\0");
    out.extend_from_slice(&drv);
    for word in [7u64, 224, 7, 0, 0, 100, 200] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for bucket in lat {
        out.extend_from_slice(&bucket.to_le_bytes());
    }
    assert_eq!(out.len(), 382);
    out
}

#[test]
fn k5_agg_row_gains_key_hash_and_lat() {
    let payload = agg_payload_with_lat([1, 2, 3, 4, 5, 6, 7, 8]);
    let backend = KCryptoBackend::new();
    let issuer = IdIssuer::default();
    let baseline = IntegritySummary::default();
    let ctx = DecodeContext {
        session: SessionId::new(1),
        generation: PlanGeneration::new(1),
        integrity: &baseline,
        id_issuer: &issuer,
    };
    let row = RowBytes::new(payload).expect("hand row");
    let obs = backend
        .decode(&ctx, raw_event_for_agg(&row))
        .expect("agg decodes");
    let p = &obs.backend_payload;
    assert_eq!(p.get("row").and_then(Value::as_str), Some("agg"));
    // `key_hash` is the shared FNV-1a row hash over the decoded row.
    let mut alg = [0u64; 16];
    alg[0] = u64::from_le_bytes(*b"t-alg\0\0\0");
    let mut drv = [0u64; 16];
    drv[0] = u64::from_le_bytes(*b"t-drv\0\0\0");
    assert_eq!(
        p.get("key_hash").and_then(Value::as_u64),
        Some(kh_of(KFAM_SK, KOP_ENC, KRES_OK, KCTX_PROC, &alg, &drv))
    );
    // `lat` passes the 8 buckets through verbatim.
    assert_eq!(
        p.get("lat"),
        Some(&serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8]))
    );
}

// ---------------------------------------------------------------------------
// F01/BPF3: kernel-faithful per-CPU WHO producer/fold regression.
// ---------------------------------------------------------------------------

/// Kernel-faithful per-CPU-hash WHO lane model (Linux 6.12
/// `kernel/bpf/hashtab.c`: `pcpu_init_value` copies the insert input
/// to the CURRENT CPU lane and zeroes every other lane;
/// `htab_percpu_map_update_elem` passes `onallcpus=false` — an
/// insert is NOT a broadcast).
///
/// Hit updates mirror BPF `update_who_slot`: `calls` + 1
/// (saturating), first-touch `first_ns` stamp, `last_ns`, and the
/// last-writer `tid`/`comm` — identity fields are never refreshed on
/// the hit path. The FOLD under test is always the real shipped
/// [`try_fold_vwho`]; only the kernel/BPF producer side is modeled
/// (the owned live migration control exercises actual helper
/// semantics; see the F01 handoff for its lease gate).
struct PcpuWho {
    lanes: Vec<VWho>,
}

impl PcpuWho {
    fn new(ncpu: usize) -> Self {
        Self {
            lanes: vec![VWho::default(); ncpu],
        }
    }

    /// `BPF_NOEXIST` insert on `cpu`: the current lane takes the full
    /// init value; every other lane stays zero (kernel insert
    /// semantics).
    fn insert(&mut self, cpu: usize, val: VWho) {
        self.lanes[cpu] = val;
    }

    /// Concurrent-insert race: the winner's lane takes the marked
    /// init value; the loser's insert fails (`EEXIST`), so its lane
    /// stays exactly as the kernel left it (zero — never marked).
    fn race_insert(&mut self, winner_cpu: usize, loser_cpu: usize, val: VWho) {
        self.lanes[winner_cpu] = val;
        assert_eq!(
            self.lanes[loser_cpu],
            VWho::default(),
            "losing insert marks nothing"
        );
    }

    /// Hit-path update on `cpu` (mirrors `update_who_slot`; observes
    /// no identity — `uid`/`cgroup`/`ppid`/`pcomm`/`stack` untouched).
    fn hit(&mut self, cpu: usize, tid: u32, comm: &[u8; 16], now: u64) {
        let lane = &mut self.lanes[cpu];
        let was = lane.calls;
        lane.calls = was.saturating_add(1);
        if was == 0 {
            lane.first_ns = now;
        }
        lane.last_ns = now;
        lane.tid = tid;
        lane.comm = *comm;
    }

    fn fold(&self) -> Option<VWho> {
        try_fold_vwho(&self.lanes)
    }
}

/// BPF `who_upsert` init value: full observed identity with zero
/// tallies/stamps plus the insertion marker (the insert carries
/// `calls == 0`; the re-lookup stamps the inserting lane).
fn who_init(
    comm: [u8; 16],
    tid: u32,
    uid: u32,
    cgroup: u64,
    ppid: u32,
    pcomm: [u8; 16],
    stack: i32,
) -> VWho {
    VWho {
        comm,
        tid,
        uid,
        cgroup,
        ppid,
        pcomm,
        stack,
        calls: 0,
        first_ns: 0,
        last_ns: 0,
        identity_present: KWHO_IDENTITY_PRESENT,
        _rsv: 0,
    }
}

fn comm_of(name: &[u8]) -> [u8; 16] {
    let mut comm = [0u8; 16];
    comm[..name.len()].copy_from_slice(name);
    comm
}

#[test]
fn who_migration_initializes_secondary_lane() {
    // BPF3: a non-root caller creates one (kh, tgid) KWHO key on CPU
    // A, then the same process makes the same call on CPU B. The
    // kernel zeroed B's lane at insert; the hit path only counts.
    // The fold must report insertion-observed identity (never
    // fabricated zeros) with exact summed calls.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    // Pin the kernel premise, not just the conclusion: the secondary
    // lane is all zero before its first hit.
    assert_eq!(
        map.lanes[1],
        VWho::default(),
        "kernel zeroes non-inserting lanes"
    );
    map.hit(1, 4243, &comm, 200);
    let folded = map.fold().expect("migration fold qualifies");
    assert_eq!(folded.calls, 2, "exact summed calls");
    assert_eq!(folded.uid, 1000, "insertion-frozen uid, not lane-B zero");
    assert_eq!(folded.cgroup, 123, "insertion cgroup, not lane-B zero");
    assert_eq!(folded.ppid, 12, "insertion parent, not lane-B zero");
    assert_eq!(&folded.pcomm[..4], b"bash");
    assert_eq!(folded.stack, 7, "insertion stack, not unrelated stack-id 0");
    assert_eq!((folded.first_ns, folded.last_ns), (100, 200));
}

#[test]
fn who_single_cpu_control_keeps_identity() {
    // Positive control: no migration — insert + two hits on one CPU
    // keep identity, sum calls, and fold stamps exactly.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    map.hit(0, 4243, &comm, 200);
    let folded = map.fold().expect("single-CPU fold qualifies");
    assert_eq!(folded.calls, 2);
    assert_eq!(
        (folded.uid, folded.cgroup, folded.ppid, folded.stack),
        (1000, 123, 12, 7)
    );
    assert_eq!(
        (folded.tid, folded.first_ns, folded.last_ns),
        (4243, 100, 200)
    );
    assert_eq!(&folded.comm[..7], b"python3");
}

#[test]
fn who_migration_under_change_keeps_insertion_identity() {
    // Migration accompanied by a changed thread/comm: the hit path
    // observes no identity (mirrors `update_who_slot`, which reads
    // no uid/cgroup/stack), so even changed live credentials cannot
    // move the folded identity — insertion-frozen fields stay from
    // the original key insert while tid/comm follow the latest
    // writer.
    let comm_a = comm_of(b"python3");
    let comm_b = comm_of(b"worker");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm_a, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm_a, 100);
    map.hit(1, 4244, &comm_b, 200);
    let folded = map.fold().expect("changed-context fold qualifies");
    assert_eq!(folded.calls, 2, "exact summed calls");
    assert_eq!(
        (folded.uid, folded.cgroup, folded.ppid, folded.stack),
        (1000, 123, 12, 7),
        "insertion-frozen identity survives migration under change"
    );
    assert_eq!(folded.tid, 4244, "tid follows the latest writer");
    assert_eq!(&folded.comm[..6], b"worker", "comm follows latest writer");
}

#[test]
fn who_noexist_race_loser_never_marks() {
    // BPF_NOEXIST race preserved: two CPUs miss concurrently; the
    // winner's insert marks its lane, the loser's insert fails and
    // its lane stays unmarked through its own hit update. The fold
    // keeps the winner's insertion identity with exact summed calls.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(2);
    map.race_insert(0, 1, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    map.hit(1, 4243, &comm, 200);
    assert_eq!(
        map.lanes[1].identity_present, 0,
        "loser lane stays unmarked after its hit"
    );
    let folded = map.fold().expect("race fold qualifies");
    assert_eq!(folded.calls, 2, "exact summed calls");
    assert_eq!(
        (folded.uid, folded.cgroup, folded.ppid, folded.stack),
        (1000, 123, 12, 7),
        "winner insertion identity, never loser zeros"
    );
    assert_eq!(folded.identity_present, KWHO_IDENTITY_PRESENT);
}

#[test]
fn who_fold_ignores_unrelated_stack_id_zero() {
    // One marked insert plus hits across three secondary lanes: every
    // secondary carries stack-id 0 (kernel-zeroed, unrelated to any
    // KSTACK row); the fold must report the insertion stack, never
    // the unrelated zero.
    let comm = comm_of(b"python3");
    let pcomm = comm_of(b"bash");
    let mut map = PcpuWho::new(4);
    map.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    map.hit(0, 4243, &comm, 100);
    map.hit(1, 4243, &comm, 200);
    map.hit(2, 4243, &comm, 300);
    map.hit(3, 4243, &comm, 400);
    for lane in &map.lanes[1..] {
        assert_eq!((lane.stack, lane.identity_present), (0, 0));
    }
    let folded = map.fold().expect("multi-lane fold qualifies");
    assert_eq!(folded.calls, 4);
    assert_eq!(folded.stack, 7, "insertion stack, not unrelated id 0");
    assert_eq!((folded.uid, folded.cgroup), (1000, 123));
    assert_eq!((folded.first_ns, folded.last_ns), (100, 400));
}

#[test]
fn who_fold_accepts_genuine_root_and_stack_zero() {
    // Validity comes from the marker, never from numeric zeros: a
    // MARKED uid 0 is genuine root and a MARKED stack 0 is a genuine
    // stack-id 0 (both legitimate), never a refusal.
    let comm = comm_of(b"init");
    let pcomm = comm_of(b"swapper");
    let mut map = PcpuWho::new(2);
    map.insert(0, who_init(comm, 1, 0, 5, 0, pcomm, 0));
    map.hit(0, 1, &comm, 100);
    map.hit(1, 1, &comm, 200);
    let folded = map.fold().expect("marked zeros qualify");
    assert_eq!(folded.calls, 2);
    assert_eq!((folded.uid, folded.cgroup, folded.stack), (0, 5, 0));
}

#[test]
fn who_fold_refuses_missing_and_conflicting_provenance() {
    // Missing: busy lanes with no marked insert refuse (no observed
    // identity to report — never guess from zeros).
    let comm = comm_of(b"python3");
    let mut missing = PcpuWho::new(2);
    missing.hit(0, 4243, &comm, 100);
    missing.hit(1, 4243, &comm, 200);
    assert_eq!(missing.fold(), None, "unmarked lanes refuse");
    // Conflicting: two marked inserts (contradictory kernel state)
    // refuse rather than pick a lane.
    let pcomm = comm_of(b"bash");
    let mut conflicting = PcpuWho::new(2);
    conflicting.insert(0, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    conflicting.insert(1, who_init(comm, 4243, 1000, 123, 12, pcomm, 7));
    assert_eq!(conflicting.fold(), None, "double-marked lanes refuse");
}

// ---------------------------------------------------------------------------
// F02/BPF2: WHO loss indication independent of KIDN capacity.
// ---------------------------------------------------------------------------

/// `KIDN` capacity mirror (BPF `KIDN` + loader `KCRYPTO_MAPS` pin 256;
/// F02 keeps it — no silent identity-capacity reduction).
const KIDN_CAP: usize = 256;
/// `KWHO` capacity mirror (BPF `KWHO` + loader pin 2048; F02 keeps it).
const KWHO_CAP: usize = 2048;

/// Finite-capacity `KIDN` gate model: 256-entry `u64 -> u8` with
/// `BPF_NOEXIST` insert discipline (an insert into a full map fails
/// and the key stays absent — the kernel premise BPF2 turns on).
#[derive(Default)]
struct SimKidn {
    entries: HashMap<u64, u8>,
}

/// Finite-capacity `KWHO` key model: 2048-entry `(kh, tgid)` set.
#[derive(Default)]
struct SimKwho {
    keys: HashSet<(u64, u32)>,
}

impl SimKwho {
    /// `BPF_NOEXIST` insert: `false` when the key is new but the map
    /// is full (the re-lookup then misses and the miss path counts
    /// the loss channel — never the aggregates, which already counted).
    fn insert_noexist(&mut self, key: (u64, u32)) -> bool {
        if self.keys.contains(&key) {
            return true;
        }
        if self.keys.len() >= KWHO_CAP {
            return false;
        }
        self.keys.insert(key)
    }
}

/// `KERR` capacity mirror (BPF `KERR` + loader pin 256).
const KERR_CAP: usize = 256;
/// `KPARAMS` capacity mirror (BPF `KPARAMS` + loader pin 256).
const KPARAMS_CAP: usize = 256;

/// `KATTRLOSS` producer/reader oracle: `ncpu` lanes x per-program
/// slots (slot-major: `slots[prog * ncpu + cpu]`, the host lookup
/// order). Producer increments mirror BPF `who_drops_inc` (this
/// CPU's lane of the failing program's slot, each increment
/// saturating at 255); the READ under test is always the real
/// shipped [`kattrloss_fold`], never a re-implementation.
struct SimAttrLoss {
    ncpu: usize,
    slots: Vec<u64>,
}

impl SimAttrLoss {
    fn new(ncpu: usize) -> Self {
        assert_eq!(KATTRLOSS_SLOTS, N_KPROGS, "oracle sizes by the ABI twin");
        Self {
            ncpu,
            slots: vec![0; ncpu * KATTRLOSS_SLOTS as usize],
        }
    }

    /// One attribution-insert failure on `cpu` from program `prog`
    /// (mirrors BPF `who_drops_inc`: lane increment saturating at
    /// [`KATTRLOSS_CAP`]).
    fn inc(&mut self, cpu: usize, prog: u32) {
        assert!(prog < KATTRLOSS_SLOTS, "program ordinal indexes a slot");
        let lane = &mut self.slots[prog as usize * self.ncpu + cpu];
        if *lane < KATTRLOSS_CAP {
            *lane += 1;
        }
    }

    /// Host read: the real shipped fold over every lane x slot.
    fn read(&self) -> u64 {
        kattrloss_fold(&self.slots)
    }
}

/// Caller-attribution verdict mirror (`kryprobe-cli/src/live.rs`
/// `session_coverage`: `Partial` iff `who_drops > 0`, else
/// `CompleteForDeclaredBoundary`).
fn attribution_is_partial(who_drops: u64) -> bool {
    who_drops > 0
}

#[test]
fn who_loss_survives_full_identity_map() {
    // BPF2 flagship: 256 identity-gate entries (no reserved key
    // consumed — all 256 stay identity-usable), then 2048 WHO keys
    // for one retained KAGG identity, then one more WHO key. The WHO
    // insert fails; the `KATTRLOSS` indication must survive the full
    // gate (nonzero `who_drops` + Partial attribution) while the
    // aggregate totals stay exact. (RED pre-F02: the lazy `KIDN`
    // marker insert failed on the full gate and the host read
    // absent-as-zero; see evidence/red-who-loss.log.)
    let mut kidn = SimKidn::default();
    for gate in 0..KIDN_CAP as u64 {
        assert_ne!(gate, KIDN_DROPS, "gate keys never take the ring key");
        kidn.entries.insert(gate, 0);
    }
    assert_eq!(kidn.entries.len(), KIDN_CAP, "gate is exactly full");
    // One retained KAGG identity (fixed crypto identity — the 256
    // natural algorithms are a fixture problem, solved by preloading
    // the gate directly instead).
    let kh = 0x0123_4567_89ab_cdefu64;
    let mut kwho = SimKwho::default();
    let mut loss = SimAttrLoss::new(2);
    let (mut kagg_calls, mut ktot_calls) = (0u64, 0u64);
    for tgid in 0..KWHO_CAP as u32 {
        assert!(kwho.insert_noexist((kh, tgid)), "WHO fills to capacity");
        kagg_calls += 1;
        ktot_calls += 1;
    }
    assert_eq!(kwho.keys.len(), KWHO_CAP, "WHO is exactly full");
    // One more caller: the WHO insert fails (map full) while the
    // aggregates still record (totals always); the WHO failure site
    // (`who_upsert` re-lookup miss) flags this CPU's lane of the
    // failing program's slot.
    assert!(
        !kwho.insert_noexist((kh, KWHO_CAP as u32)),
        "overflow WHO key refuses"
    );
    kagg_calls += 1;
    ktot_calls += 1;
    loss.inc(0, KPROG_SKENC);
    let folded = loss.read();
    assert_eq!(
        kagg_calls, ktot_calls,
        "aggregate totals reconcile despite WHO loss"
    );
    assert_ne!(folded, 0, "WHO loss survives a full identity map");
    assert!(
        attribution_is_partial(folded),
        "attribution degrades to Partial on WHO loss"
    );
}

#[test]
fn who_loss_below_capacity_control() {
    // Positive control: gate and WHO below capacity, no insert
    // failure — the loss flag reads healthy-zero (Complete) while
    // aggregates reconcile.
    let mut kidn = SimKidn::default();
    for gate in 0..128u64 {
        kidn.entries.insert(gate, 0);
    }
    let kh = 0x0123_4567_89ab_cdefu64;
    let mut kwho = SimKwho::default();
    let loss = SimAttrLoss::new(2);
    let (mut kagg_calls, mut ktot_calls) = (0u64, 0u64);
    for tgid in 0..128u32 {
        assert!(kwho.insert_noexist((kh, tgid)));
        kagg_calls += 1;
        ktot_calls += 1;
    }
    let folded = loss.read();
    assert_eq!(kagg_calls, ktot_calls);
    assert_eq!(folded, 0, "no failure means no loss");
    assert!(
        !attribution_is_partial(folded),
        "clean WHO attribution stays Complete"
    );
}

#[test]
fn who_loss_already_nonzero_control() {
    // Positive control: a flag recorded BEFORE the gate fills remains
    // visible and saturates upward rather than disappearing — a
    // further failure on the full gate keeps the indication nonzero.
    let mut kidn = SimKidn::default();
    for gate in 0..KIDN_CAP as u64 {
        kidn.entries.insert(gate, 0);
    }
    assert_eq!(kidn.entries.len(), KIDN_CAP, "gate is exactly full");
    let mut loss = SimAttrLoss::new(2);
    loss.inc(0, KPROG_SKENC);
    assert_eq!(loss.read(), 1, "early flag is visible");
    let kh = 0x0123_4567_89ab_cdefu64;
    let mut kwho = SimKwho::default();
    for tgid in 0..KWHO_CAP as u32 {
        assert!(kwho.insert_noexist((kh, tgid)));
    }
    assert!(!kwho.insert_noexist((kh, KWHO_CAP as u32)));
    loss.inc(0, KPROG_SKENC);
    let folded = loss.read();
    assert_eq!(folded, 2, "present flag saturates upward");
    assert!(
        attribution_is_partial(folded),
        "visible loss degrades attribution to Partial"
    );
}

#[test]
fn who_loss_repeated_failures_saturate_at_cap() {
    // Repeated failures on one lane saturate at 255: the diagnostic
    // is a flag, never an exact lost-call count (300 failures fold
    // to 255, not 300).
    let mut loss = SimAttrLoss::new(2);
    for _ in 0..300 {
        loss.inc(1, KPROG_AEADDEC);
    }
    assert_eq!(loss.slots[KPROG_AEADDEC as usize * 2 + 1], 255);
    assert_eq!(loss.read(), 255, "flag saturates, never counts exact");
    assert!(attribution_is_partial(loss.read()));
}

#[test]
fn who_loss_saturated_lane_stays_capped() {
    // An already-saturated lane stays capped under further failures
    // (idempotent at the cap — no wrap, no growth past 255).
    let mut loss = SimAttrLoss::new(2);
    for _ in 0..255 {
        loss.inc(0, KPROG_SHASH);
    }
    assert_eq!(loss.read(), 255);
    for _ in 0..10 {
        loss.inc(0, KPROG_SHASH);
    }
    assert_eq!(loss.read(), 255, "saturated flag stays at the cap");
}

#[test]
fn who_loss_cross_cpu_failures_fold() {
    // Simultaneous cross-CPU failures accumulate across lanes: one
    // failure on each of 4 CPUs (same program) folds to 4 while
    // every other lane stays zero.
    let mut loss = SimAttrLoss::new(4);
    for cpu in 0..4 {
        loss.inc(cpu, KPROG_SKENC);
    }
    assert_eq!(loss.read(), 4, "cross-CPU lanes accumulate");
    assert!(attribution_is_partial(loss.read()));
}

#[test]
fn who_loss_cross_program_failures_fold() {
    // Simultaneous cross-program failures accumulate across slots:
    // one failure on each of 3 programs folds to 3, and idle program
    // slots contribute nothing.
    let mut loss = SimAttrLoss::new(2);
    loss.inc(0, KPROG_SKENC);
    loss.inc(1, KPROG_AEADDEC);
    loss.inc(0, KPROG_SHASH);
    assert_eq!(loss.read(), 3, "cross-program slots accumulate");
    let idle: u64 = loss
        .slots
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            let prog = i / 2;
            prog != KPROG_SKENC as usize
                && prog != KPROG_AEADDEC as usize
                && prog != KPROG_SHASH as usize
        })
        .map(|(_, &v)| v)
        .sum();
    assert_eq!(idle, 0, "idle program slots stay zero");
}

#[test]
fn who_loss_kerr_site_routes_to_flag() {
    // `KERR` loss site (`record_kerr`): a zero return records nothing
    // (no row, no loss), while a nonzero return past the full 256
    // rows flags the loss channel.
    let mut kerr: HashSet<u64> = HashSet::new();
    let mut loss = SimAttrLoss::new(2);
    // Zero return: no row, no loss (BPF `kerr != 0` guard).
    let zero_kerr = 0i32;
    if zero_kerr != 0 {
        loss.inc(0, KPROG_SKENC);
    }
    assert_eq!(loss.read(), 0, "zero return records nothing");
    for kh in 0..KERR_CAP as u64 {
        kerr.insert(kh);
    }
    assert_eq!(kerr.len(), KERR_CAP, "KERR is exactly full");
    // Nonzero return for a new identity past capacity: insert fails,
    // re-lookup misses, the KERR site flags.
    let kh = KERR_CAP as u64;
    let inserted = if kerr.contains(&kh) {
        true
    } else if kerr.len() >= KERR_CAP {
        false
    } else {
        kerr.insert(kh)
    };
    assert!(!inserted, "overflow KERR key refuses");
    loss.inc(0, KPROG_SKENC);
    assert_eq!(loss.read(), 1, "KERR loss routes to the flag");
    assert!(attribution_is_partial(loss.read()));
}

#[test]
fn who_loss_kparams_site_routes_to_flag() {
    // `KPARAMS` loss site (`record_params`): no `alg` means no row
    // (never zero-filled, no loss), while a chased `alg` past the
    // full 256 rows flags the loss channel.
    let mut kparams: HashSet<u64> = HashSet::new();
    let mut loss = SimAttrLoss::new(2);
    // Failed alloc (`alg == 0`): no row, no loss.
    let alg = 0u64;
    if alg != 0 {
        loss.inc(0, KPROG_SKENC);
    }
    assert_eq!(loss.read(), 0, "missing alg records nothing");
    for kh in 0..KPARAMS_CAP as u64 {
        kparams.insert(kh);
    }
    assert_eq!(kparams.len(), KPARAMS_CAP, "KPARAMS is exactly full");
    let kh = KPARAMS_CAP as u64;
    let inserted = if kparams.contains(&kh) {
        true
    } else if kparams.len() >= KPARAMS_CAP {
        false
    } else {
        kparams.insert(kh)
    };
    assert!(!inserted, "overflow KPARAMS key refuses");
    loss.inc(1, KPROG_AEADDEC);
    assert_eq!(loss.read(), 1, "KPARAMS loss routes to the flag");
    assert!(attribution_is_partial(loss.read()));
}

#[test]
fn who_loss_kctx_refusal_stays_separate() {
    // KCTX refusal stays an independent channel: a full `KCTX`
    // (1024 rows) counts its own exact refused-insert tally while a
    // simultaneous WHO loss flags `KATTRLOSS` — neither masks the
    // other. And the fold contracts stay distinct: the ctx checked
    // fold REFUSES saturated input while the loss flag SATURATES
    // (never refuses on magnitude).
    let mut kctx: HashSet<u64> = HashSet::new();
    for kh in 0..KCTX_MAX_ENTRIES as u64 {
        kctx.insert(kh);
    }
    assert_eq!(kctx.len(), KCTX_MAX_ENTRIES as usize, "KCTX is full");
    // Refused ctx insert: exact `KCTX_DROPS`-style tally (a real u64
    // count, never a saturating flag).
    let mut ctx_exact_drops = 0u64;
    let kh = KCTX_MAX_ENTRIES as u64;
    if kctx.contains(&kh) || (kctx.len() as u32) < KCTX_MAX_ENTRIES {
        kctx.insert(kh);
    } else {
        ctx_exact_drops += 1;
    }
    // Simultaneous WHO loss on the same event.
    let mut loss = SimAttrLoss::new(2);
    loss.inc(0, KPROG_SKENC);
    assert_eq!(ctx_exact_drops, 1, "ctx refusal counts exactly");
    assert_eq!(loss.read(), 1, "WHO loss flags independently");
    // Contract separation on shipped folds: saturated ctx input
    // refuses the receipt; saturated loss lanes fold to the cap.
    let saturated = VCtx {
        calls: u64::MAX,
        ..Default::default()
    };
    assert_eq!(
        try_fold_vctx(&[saturated]),
        None,
        "saturated ctx input refuses"
    );
    assert_eq!(
        kattrloss_fold(&[KATTRLOSS_CAP, KATTRLOSS_CAP]),
        KATTRLOSS_CAP,
        "saturated loss lanes fold to the cap, never refuse"
    );
}

#[test]
fn who_row_render_scales_to_2048_rows() {
    // Audit #9/R1: per-tick who-row render cost must stay sane at row
    // scale. Generous wall bound (pure serde_json builds take ~ms) —
    // trips only on pathological blowup, never flakes.
    let table = SymTable::parse(TINY_MAP);
    let snap = who_snapshot(true, true);
    let first = observation_for_who(&snap, ObservationId::new(0), &table);
    assert!(first.backend_payload.is_object());
    let start = std::time::Instant::now();
    for i in 1..2048u64 {
        let obs = observation_for_who(&snap, ObservationId::new(i), &table);
        assert_eq!(obs.backend_payload, first.backend_payload);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "2048 who rows took {elapsed:?}"
    );
}
