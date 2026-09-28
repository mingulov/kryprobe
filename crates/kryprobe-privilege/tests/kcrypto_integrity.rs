// SPDX-License-Identifier: GPL-3.0-or-later
//! P7/T12 integrity suite: per-stage loss injection, one stage at a
//! time. Each cell injects at exactly one stage and names its
//! stage-specific partial/unknown verdict plus its bounded-resource
//! proof. All cells run unprivileged (pure ingest core + reducer +
//! decoder + allocator); the guest lane (E04–E07, sol04) proves the
//! same stages against real kernel mechanisms.

use kryprobe_abi::kcrypto_lifecycle::{LEDGE_RETURN, LEDGE_SUBMIT};
use kryprobe_core::LossLedger;
use kryprobe_core::ReconcileVerdict;
use kryprobe_core::attach::{COUNT_SLOTS, CookieAllocator};
use kryprobe_core::evidence::SharedLosses;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::kcrypto::{
    CallbackDisposition, Edge, LifecycleFamily, LifecycleReducer, OpDirection, RequestMeta,
    ReturnDisposition, Terminal,
};
use kryprobe_privilege::bpfloader::{LoaderError, check_record_align};
use kryprobe_privilege::drain::DrainStats;
use kryprobe_privilege::kcrypto_context::Histogram;
use kryprobe_privilege::kcrypto_lifecycle::decode::{DecodeDrop, decode_record};
use kryprobe_privilege::kcrypto_lifecycle::sensor::{EnrichmentStatus, SensorCore, SessionContext};

fn meta() -> RequestMeta {
    RequestMeta {
        family: LifecycleFamily::Skcipher,
        direction: OpDirection::Encrypt,
        cryptlen: Some(16),
        req_flags: Some(0),
        epoch: Some(0),
        aead: None,
    }
}

fn submit(id: u64, ts_ns: u64) -> Edge {
    Edge::Submit {
        id,
        tfm_id: None,
        ts_ns,
        meta: meta(),
    }
}

/// P01 — reducer expiry drains stale pending as explicit-unknown
/// with the equation intact: five submits, one with retained
/// callback truth; `expire_before(60, 45)` drains the three older
/// than the bound (ascending, truth preserved where retained) while
/// the boundary-age id (age == 45, deadline inclusive) and the
/// fresh id stay live. A later `finish` drains the remainder; the
/// equation `admitted == emitted + live`, `unfinished ⊆ emitted`
/// holds after every step; expired ids are tombstoned (late
/// terminals diagnose, never rejoin).
#[test]
fn p01_reducer_expiry_drains_stale_pending_as_unknown() {
    let mut r = LifecycleReducer::new(8);
    for (id, ts) in [(1u64, 0u64), (2, 10), (3, 55), (4, 5), (5, 15)] {
        assert!(
            r.apply(submit(id, ts)).is_empty(),
            "submit {id} opens, emits nothing"
        );
    }
    // Retained terminal truth on a stale id: a terminal callback
    // with no joining return retains, never emits.
    assert!(
        r.apply(Edge::Callback {
            id: 2,
            ts_ns: 30,
            status: -5,
            disposition: CallbackDisposition::Terminal,
        })
        .is_empty(),
        "unjoined terminal callback retains"
    );
    // Ages at now=60: 1→60, 2→50, 3→5, 4→55, 5→45. Bound 45 expires
    // 1, 2, 4 (strictly older); 5 sits exactly on the bound (live),
    // 3 is fresh (live).
    let expired = r.expire_before(60, 45);
    assert_eq!(
        expired.iter().map(|rec| rec.id).collect::<Vec<_>>(),
        vec![1, 2, 4],
        "stale ids expire in ascending order"
    );
    assert_eq!(expired[0].terminal, Terminal::Unknown, "truthless id 1");
    assert_eq!(
        expired[1].terminal,
        Terminal::Callback(-5),
        "retained truth on id 2 emits"
    );
    assert_eq!(expired[2].terminal, Terminal::Unknown, "truthless id 4");
    assert!(
        expired[0].duration_ns.is_none() && expired[2].duration_ns.is_none(),
        "unknown records carry no duration"
    );
    let stats = r.stats();
    assert_eq!(stats.admitted, 5, "admitted");
    assert_eq!(stats.emitted, 3, "emitted");
    assert_eq!(stats.unfinished, 2, "only truthless expirations count");
    // Survivor completes grounded; the boundary id drains truthless
    // at finish.
    let done = r.apply(Edge::Return {
        id: 3,
        ts_ns: 61,
        status: 0,
        disposition: ReturnDisposition::Terminal,
    });
    assert_eq!(done.len(), 1, "live id 3 completes");
    assert_eq!(done[0].terminal, Terminal::Sync(0));
    let rest = r.finish(70);
    assert_eq!(rest.len(), 1, "boundary id 5 drains at finish");
    assert_eq!(rest[0].id, 5);
    assert_eq!(rest[0].terminal, Terminal::Unknown);
    let stats = r.stats();
    assert_eq!((stats.admitted, stats.emitted, stats.unfinished), (5, 5, 3));
    assert!(r.finish(80).is_empty(), "second finish emits nothing");
    // Expired ids are tombstoned: a late terminal diagnoses as a
    // duplicate (Unknown claims no truth to contradict), emits
    // nothing, disturbs no counter but `duplicate`.
    let dup_before = r.stats().duplicate;
    assert!(
        r.apply(Edge::Return {
            id: 1,
            ts_ns: 90,
            status: 0,
            disposition: ReturnDisposition::Terminal,
        })
        .is_empty(),
        "late terminal on expired id emits nothing"
    );
    assert_eq!(r.stats().duplicate, dup_before + 1, "counted duplicate");
    assert_eq!((r.stats().admitted, r.stats().emitted), (5, 5));
}

/// Clean session context (verified identity, zero baselines).
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

/// One 112-byte v7 `LEdge` submit/return pair for call `call` (fresh
/// even invocation per call — bit 0 set is the reserved bit).
fn submit_bytes(call: u64, ts_ns: u64) -> Vec<u8> {
    edge_bytes(
        LEDGE_SUBMIT,
        1,
        0x1000 + call,
        ts_ns,
        0,
        0,
        0x4000 + 2 * call,
    )
}

/// Matching return for [`submit_bytes`] (`status` rides the return).
fn return_bytes(call: u64, ts_ns: u64, status: i32) -> Vec<u8> {
    edge_bytes(
        LEDGE_RETURN,
        1,
        0x1000 + call,
        ts_ns,
        status,
        0,
        0x4000 + 2 * call,
    )
}

fn edge_bytes(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    flags: u16,
    invoc: u64,
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 7;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[6..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out[32..40].copy_from_slice(&invoc.to_le_bytes());
    if edge == LEDGE_SUBMIT {
        out[52] = 1; // skcipher family
        out[53] = site as u8; // direction echoes the site
    }
    out
}

/// I01 — decode-table admission: with a 2-deep outstanding table,
/// three concurrent submits admit two and refuse the third with
/// `submit_refused` (never admitted, never disturbing — the refused
/// submit reaches no reducer, mints no id). Completing one frees
/// the slot and the retry admits. Bounded: at most `capacity`
/// outstanding, counted — never silent, never growing.
#[test]
fn i01_decode_table_full_refuses_fresh_submit() {
    let mut core = SensorCore::new(2, 8, 8, 8, 8, true);
    let three = vec![
        submit_bytes(1, 100),
        submit_bytes(2, 101),
        submit_bytes(3, 102),
    ];
    assert_eq!(core.ingest_records(&three), 0, "submits emit nothing");
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.decode.admitted, 2, "two admitted");
    assert_eq!(ledger.decode.submit_refused, 1, "third refused");
    assert_eq!(ledger.reducer.admitted, 2, "refused submit mints no id");
    // Completing one frees the slot; the retry admits fresh.
    let pair = vec![return_bytes(1, 150, 0), submit_bytes(3, 160)];
    assert_eq!(core.ingest_records(&pair), 1, "call 1 completes");
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.decode.admitted, 3, "retry admits");
    assert_eq!(ledger.decode.submit_refused, 1, "refusal count holds");
    assert_eq!(ledger.reducer.admitted, 3);
}

/// I02 — decode rejection: twin-drift records (bad magic, short
/// length, bad version, unknown edge kind) count `bad_records`,
/// mint no edges, disturb no outstanding id, and complete nothing.
/// The stage verdict is counted loss (`bad_records` feeds the
/// envelope loss map), never a silent skip.
#[test]
fn i02_decode_rejection_counts_without_edges() {
    let mut core = SensorCore::new(8, 8, 8, 8, 8, true);
    let mut bad_magic = submit_bytes(1, 100);
    bad_magic[0] = 0;
    let mut short = submit_bytes(2, 101);
    short.truncate(64);
    let mut bad_version = submit_bytes(3, 102);
    bad_version[2] = 6;
    let mut bad_edge = submit_bytes(4, 103);
    bad_edge[3] = 9;
    let drift = vec![bad_magic, short, bad_version, bad_edge];
    assert_eq!(core.ingest_records(&drift), 0, "drift completes nothing");
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.decode.bad_records, 4, "four counted refusals");
    assert_eq!(ledger.decode.admitted, 0, "nothing admitted");
    assert_eq!(ledger.reducer.admitted, 0, "no phantom reducer ids");
    assert!(ledger.completed.is_empty(), "no completions");
    assert_eq!(ledger.edge_hits, [0; 22], "no hook hits from drift");
    // The twin names each refusal (spot-check the four shapes).
    assert_eq!(
        decode_record(&{
            let mut b = submit_bytes(9, 100);
            b[0] = 0;
            b
        }),
        Err(DecodeDrop::BadMagic)
    );
    assert_eq!(decode_record(&[0u8; 64]), Err(DecodeDrop::BadLength));
}

/// I03 — retention bound: completions past the ledger bound drop but
/// COUNT (`retained_dropped`) — retention never grows unbounded, and
/// a draining reader never drops. Five grounded pairs against a
/// 2-deep retention keep two and count three.
#[test]
fn i03_retention_bound_drops_counted_not_silent() {
    let mut core = SensorCore::new(16, 16, 2, 8, 8, true);
    let mut records = Vec::new();
    for call in 1..=5u64 {
        records.push(submit_bytes(call, 100 + call));
        records.push(return_bytes(call, 200 + call, 0));
    }
    assert_eq!(core.ingest_records(&records), 5, "five complete");
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.completed.len(), 2, "retention capped at two");
    assert_eq!(ledger.retained_dropped, 3, "three counted drops");
    assert_eq!(ledger.reducer.emitted, 5, "emitted counts all five");
    // Draining frees retention for new completions.
    assert_eq!(core.take_completed().len(), 2, "drain takes two");
    let more = vec![submit_bytes(6, 300), return_bytes(6, 301, 0)];
    assert_eq!(core.ingest_records(&more), 1, "call 6 completes");
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.retained_dropped, 3, "no new drops after drain");
    assert_eq!(ledger.completed.len(), 1, "fresh completion retained");
}

/// I04 — reducer capacity: fresh submits past a full live set count
/// `admission_failed` (never admitted, never queued unbounded);
/// completing one frees the slot. The equation holds throughout:
/// `admitted == emitted + live`.
#[test]
fn i04_reducer_full_refuses_fresh_submit() {
    let mut core = SensorCore::new(8, 2, 8, 8, 8, true);
    let three = vec![
        submit_bytes(1, 100),
        submit_bytes(2, 101),
        submit_bytes(3, 102),
    ];
    assert_eq!(core.ingest_records(&three), 0);
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.decode.admitted, 3, "decoder admits all three");
    assert_eq!(ledger.reducer.admitted, 2, "reducer holds two live");
    assert_eq!(ledger.reducer.admission_failed, 1, "third refused live");
    // Complete one; the refused call resubmits and admits.
    let free = vec![return_bytes(1, 150, 0), submit_bytes(3, 160)];
    assert_eq!(core.ingest_records(&free), 1, "call 1 completes");
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.reducer.admitted, 3, "retry admits");
    assert_eq!(ledger.reducer.emitted, 1, "one emitted");
    assert_eq!(ledger.reducer.admission_failed, 1, "refusal count holds");
}

/// P01 boundary — a clock running backwards (submit newer than
/// `now_ns`) never expires: saturating age reads zero, the id stays
/// live, and a zero bound expires only strictly-older ids (an id
/// submitted exactly at `now_ns` survives a zero bound).
#[test]
fn p01_expiry_clock_backwards_and_zero_bound() {
    let mut r = LifecycleReducer::new(4);
    assert!(r.apply(submit(1, 100)).is_empty());
    assert!(
        r.expire_before(50, 1000).is_empty(),
        "future submit never expires"
    );
    assert!(r.apply(submit(2, 50)).is_empty());
    assert!(
        r.expire_before(50, 0).is_empty(),
        "zero bound keeps the now-submitted id"
    );
    let expired = r.expire_before(51, 0);
    assert_eq!(
        expired.iter().map(|rec| rec.id).collect::<Vec<_>>(),
        vec![2],
        "zero bound expires the strictly-older id"
    );
    assert_eq!(r.stats().unfinished, 1);
}

/// P02 — generation exhaustion: the cookie allocator issues all 64
/// slots, then refuses with a typed error naming the request and
/// the zero remainder (no wraparound, no reuse, consumed count
/// holds). Empty requests refuse without consuming.
#[test]
fn p02_cookie_allocator_exhaustion_refuses_typed() {
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    let first = alloc.allocate(63).expect("63 slots free");
    assert_eq!(first.base(), 0, "first range starts at zero");
    assert_eq!(alloc.used(), 63);
    assert_eq!(alloc.remaining(), 1);
    let last = alloc.allocate(1).expect("one slot free");
    assert_eq!(last.base(), 63, "ranges disjoint by construction");
    assert_ne!(first.base(), last.base());
    assert_eq!(alloc.used(), COUNT_SLOTS);
    assert_eq!(alloc.remaining(), 0);
    let err = alloc.allocate(1).expect_err("exhausted refuses");
    assert_eq!(err.requested, 1, "refusal names the request");
    assert_eq!(err.remaining, 0, "refusal names the remainder");
    assert_eq!(alloc.used(), COUNT_SLOTS, "refusal consumes nothing");
    assert!(
        alloc.allocate(0).is_err(),
        "empty requests refuse without consuming"
    );
    assert_eq!(alloc.used(), COUNT_SLOTS);
}

/// Q09 — user-queue pressure: drain queue drops ride the shared
/// feed exactly (ring + queue counts, never folded), and a
/// queue-drop-shaped shortfall reconciles `Partial` (missing
/// counts the shortfall) — user-queue loss never reads clean and
/// never vanishes into a balanced ledger.
#[test]
fn q09_user_queue_drops_feed_shared_losses_and_partial() {
    let stats = DrainStats {
        records: 100,
        queue_drops: 7,
    };
    let shared = stats.shared_losses(3);
    assert_eq!(
        shared,
        SharedLosses::new(3, 7),
        "ring + queue ride the shared feed exactly"
    );
    assert_eq!(shared.ring_reservation_failures, 3);
    assert_eq!(shared.user_queue_drops, 7);
    // The 7 queue drops never reach the ring/guard/truncation
    // counters, so the ledger shortfall stays partial (missing 7).
    let ledger = LossLedger {
        exact: 200,
        received: 190,
        drops: 3,
    };
    assert_eq!(
        ledger.reconcile(),
        ReconcileVerdict::Partial { missing: 7 },
        "queue-shaped shortfall is partial, never clean"
    );
}

/// E07 (host seam) — intentional sampling stays distinguishable
/// from accidental loss: a sampled render announces its mode AND
/// the exact aggregate population, while a loss ledger over the
/// same population reconciles its own partial — neither the
/// sampling announcement nor the loss verdict absorbs the other.
/// (The guest E07 cell proves the same distinction under real
/// ring/map/user-queue overload.)
#[test]
fn e07_sampling_announcement_survives_loss() {
    let mut hist = Histogram::new("submit_bytes", "bytes", vec![64, 4096, 65536]);
    for _ in 0..10 {
        hist.observe(16);
    }
    let rendered = hist.render_with_cap(3);
    assert!(
        rendered.contains("mode=sampled"),
        "sampling announces itself: {rendered}"
    );
    assert!(
        rendered.contains("samples=10"),
        "exact population kept under sampling: {rendered}"
    );
    // Accidental loss over the same population is its own verdict.
    let ledger = LossLedger {
        exact: 10,
        received: 9,
        drops: 0,
    };
    assert_eq!(
        ledger.reconcile(),
        ReconcileVerdict::Partial { missing: 1 },
        "loss verdict independent of the sampling announcement"
    );
}

/// sol04 needle (the `KPROBE-CANARY` tripwire prefix every marked
/// fixture buffer carries, plus a T12-local suffix): refused
/// record bytes still trip the raw-transport scan.
const SOL04_NEEDLE: &[u8] = b"KPROBE-CANARY-T12!";

/// True when `data` carries the tripwire needle.
fn carries_marker(data: &[u8]) -> bool {
    data.len() >= SOL04_NEEDLE.len() && data.windows(SOL04_NEEDLE.len()).any(|w| w == SOL04_NEEDLE)
}

/// sol04 (host seam) — decoder-refused bytes are scanned, not
/// skipped: a marker planted in a twin-drift record trips the
/// raw-transport scan at its index, while the refusal itself
/// (`DecodeDrop` debug) echoes no marker bytes. Positive controls:
/// the clean record passes the scan and the dirty record still
/// counts `bad_records` (refused, never silently skipped).
#[test]
fn sol04_rejected_record_markers_found_by_scan() {
    let mut dirty = submit_bytes(1, 100);
    dirty[2] = 6; // bad version: twin drift, still 112 bytes
    dirty[64..64 + SOL04_NEEDLE.len()].copy_from_slice(SOL04_NEEDLE);
    let drop = decode_record(&dirty).expect_err("drift refuses");
    assert_eq!(drop, DecodeDrop::BadVersion);
    assert!(
        carries_marker(&dirty),
        "refused bytes trip the transport scan"
    );
    let debug = format!("{drop:?}");
    assert!(
        !carries_marker(debug.as_bytes()),
        "refusal debug echoes no marker bytes: {debug}"
    );
    // Every refusal variant is input-free by construction
    // (fieldless — a future payload-carrying variant fails HERE).
    for variant in [
        DecodeDrop::BadLength,
        DecodeDrop::BadMagic,
        DecodeDrop::BadVersion,
        DecodeDrop::BadEdge,
        DecodeDrop::BadSite,
        DecodeDrop::BadFlags,
        DecodeDrop::BadMeta,
        DecodeDrop::NullKey,
        DecodeDrop::BadSubmitStatus,
        DecodeDrop::BadInvoc,
        DecodeDrop::BadReturnTfm,
        DecodeDrop::BadDrv,
    ] {
        let rendered = format!("{variant:?}");
        assert!(
            !rendered.contains("KPROBE"),
            "variant {rendered} echoes no input bytes"
        );
    }
    // Controls: clean bytes pass; the dirty record counts refused.
    assert!(
        !carries_marker(&submit_bytes(2, 101)),
        "clean record passes the scan"
    );
    let mut core = SensorCore::new(8, 8, 8, 8, 8, true);
    assert_eq!(core.ingest_records(&[dirty]), 0);
    let ledger = core
        .ledger([0; 5], [0; 22], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.decode.bad_records, 1, "refused, counted");
}

/// sol04 — no pointers through errors: a misaligned record buffer
/// refuses with the misalignment RESIDUE (`addr % 8`, nonzero by
/// construction — the same diagnostic value), never the buffer
/// address. Both `Display` and `Debug` render address-free (no
/// `0x` hex anywhere).
#[test]
fn sol04_misaligned_record_error_carries_no_address() {
    // Guaranteed-aligned control (a plain `[u8; 64]` is only
    // 1-aligned — stack luck, not a control).
    #[repr(align(8))]
    struct Aligned([u8; 64]);
    let aligned = Aligned([0u8; 64]);
    assert_eq!(aligned.0.as_ptr() as usize % 8, 0, "control aligned");
    assert!(check_record_align(&aligned.0).is_ok(), "aligned passes");
    // A misaligned offset always exists among 8 consecutive
    // addresses (exactly one is 8-aligned) — no ASLR luck.
    let base = aligned.0.as_ptr() as usize;
    let off = (1..=8)
        .find(|o| !(base + o).is_multiple_of(8))
        .expect("a misaligned offset exists");
    let bytes = &aligned.0[off..];
    let residue = bytes.as_ptr() as usize % 8;
    assert_ne!(residue, 0, "residue nonzero by construction");
    let err = check_record_align(bytes).expect_err("misaligned refuses");
    assert_eq!(
        err,
        LoaderError::MisalignedRecord { misalign: residue },
        "residue-only refusal"
    );
    for rendered in [format!("{err}"), format!("{err:?}")] {
        assert!(
            !rendered.contains("0x"),
            "no address renders through errors: {rendered}"
        );
    }
}
