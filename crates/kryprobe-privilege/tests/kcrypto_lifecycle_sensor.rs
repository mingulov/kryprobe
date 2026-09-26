// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 sensor suite: pure ingest (records → decode → reducer → ledger).
//!
//! Pins the terminal ledger contract without privilege: paired edges
//! complete grounded records, queued returns stay pending, unknown
//! keys and bad records count loss without phantoms, and `finish`
//! drains pending truthless. The mmap shell (`drain_once`) rides the
//! same `ingest_records` and is covered by the VM canary lane.

use kryprobe_abi::kcrypto_lifecycle::{
    LEDGE_RETURN, LEDGE_SUBMIT, LTFM_MAGIC, LTFM_SITE_ALLOC_SK, LTFM_SITE_DESTROY,
    LTFM_SITE_SETAUTHSIZE, LTFM_SITE_SETKEY_SK, LTFM_VERSION,
};
use kryprobe_core::kcrypto::Terminal;
use kryprobe_privilege::kcrypto_lifecycle::canary::{
    SensorBaseline, SensorView, parse_transcript, verdict,
};
use kryprobe_privilege::kcrypto_lifecycle::sensor::{
    EnrichmentStatus, SensorCore, SessionContext, fold_loss_lanes,
};

/// Clean session context (verified identity, zero baselines).
fn ctx() -> SessionContext {
    SessionContext {
        loss_baseline: [0; 5],
        agg_baseline: [0; 16],
        view_valid: true,
        miss_baseline: Vec::new(),
        enrichment: EnrichmentStatus::Available {
            entries: 0,
            truncated: false,
        },
    }
}

/// One 112-byte v5 `LEdge` (little-endian twin of the ABI struct;
/// the transform word defaults to 0 = unknown link).
fn edge_bytes_invoc(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    flags: u16,
    invoc: u64,
) -> Vec<u8> {
    edge_bytes_tfm(edge, site, key, ts_ns, status, flags, invoc, 0, b"")
}

/// Full builder with an explicit transform word (T07.3 first-seen
/// tests pass a frontend here) and driver name (submit edges only —
/// returns carry tfm 0 + empty name per the R2 twin).
#[allow(clippy::too_many_arguments)]
fn edge_bytes_tfm(
    edge: u8,
    site: u16,
    key: u64,
    ts_ns: u64,
    status: i32,
    flags: u16,
    invoc: u64,
    tfm: u64,
    drv: &[u8],
) -> Vec<u8> {
    let mut out = vec![0u8; 112];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 5;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[6..8].copy_from_slice(&flags.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out[32..40].copy_from_slice(&invoc.to_le_bytes());
    out[40..48].copy_from_slice(&tfm.to_le_bytes());
    let n = drv.len().min(63);
    out[48..48 + n].copy_from_slice(&drv[..n]);
    out
}

/// Realistic default builder: same v5 record with a VALID
/// invocation (see the decode-suite twin).
fn edge_bytes(edge: u8, site: u16, key: u64, ts_ns: u64, status: i32, flags: u16) -> Vec<u8> {
    edge_bytes_invoc(edge, site, key, ts_ns, status, flags, 0x4000)
}

#[test]
fn ingest_paired_edges_complete_grounded_record() {
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let records = vec![
        edge_bytes(1, 1, 0xabc, 100, 0, 0),
        edge_bytes(2, 1, 0xabc, 150, 0, 0),
    ];
    assert_eq!(core.ingest_records(&records), 1);
    let ledger = core
        .ledger([0; 5], [0; 16], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.completed.len(), 1);
    let rec = &ledger.completed[0];
    assert_eq!((rec.id, rec.tfm_id, rec.duration_ns), (1, None, Some(50)));
    assert_eq!(rec.terminal, Terminal::Sync(0));
    assert!(rec.evidence_valid());
    assert_eq!(
        ledger.edge_hits,
        [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(ledger.decode.admitted, 1);
    assert_eq!(ledger.reducer.admitted, 1);
}

#[test]
fn ingest_queued_return_stays_pending() {
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let records = vec![
        edge_bytes(1, 1, 0xabc, 100, 0, 0),
        edge_bytes(2, 1, 0xabc, 150, -115, 0),
    ];
    assert_eq!(core.ingest_records(&records), 0);
    assert!(
        core.ledger([0; 5], [0; 16], Vec::new(), ctx())
            .expect("empty miss join")
            .completed
            .is_empty()
    );
    assert_eq!(
        core.ledger([0; 5], [0; 16], Vec::new(), ctx())
            .expect("empty miss join")
            .decode
            .admitted,
        1
    );
    assert_eq!(
        core.ledger([0; 5], [0; 16], Vec::new(), ctx())
            .expect("empty miss join")
            .edge_hits,
        [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn ingest_loss_counts_without_phantoms() {
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let records = vec![
        edge_bytes(2, 1, 0xabc, 150, 0, 0), // unknown-invocation return
        vec![0u8; 31],                      // short record
        edge_bytes(9, 1, 1, 1, 0, 0),       // bad edge kind
    ];
    assert_eq!(core.ingest_records(&records), 0);
    let ledger = core
        .ledger([7, 0, 0, 0, 0], [0; 16], Vec::new(), ctx())
        .expect("empty miss join");
    assert!(ledger.completed.is_empty());
    assert_eq!(ledger.decode.unknown_invoc_returns, 1);
    assert_eq!(ledger.decode.bad_records, 2);
    assert_eq!(ledger.kernel_loss, [7, 0, 0, 0, 0]);
    assert_eq!(ledger.reducer.admitted, 0);
}

#[test]
fn finish_drains_pending_truthless() {
    // `finish` reconciles into retention and returns nothing: the
    // take is the ONE read path (a returning finish double-surfaced
    // every reconciled record — round-3 async canary).
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    core.ingest_records(&[edge_bytes(1, 1, 0xabc, 100, 0, 0)]);
    assert!(
        core.ledger([0; 5], [0; 16], Vec::new(), ctx())
            .expect("empty miss join")
            .completed
            .is_empty()
    );
    core.finish(200);
    assert_eq!(
        core.ledger([0; 5], [0; 16], Vec::new(), ctx())
            .expect("empty miss join")
            .completed
            .len(),
        1
    );
    let drained = core.take_completed();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].terminal, Terminal::Unknown);
    assert!(!drained[0].evidence_valid());
    assert!(core.take_completed().is_empty());
}

#[test]
fn f7_completed_retention_is_bounded_and_counted() {
    // Round-1 (astra-M7) + design C12: every output queue has a
    // configured bound. Past the ledger cap, completions stop being
    // retained and count retained_dropped (explicit loss, never
    // silent growth).
    let mut core = SensorCore::new(16, 16, 2, 8, true);
    for i in 0..3u64 {
        let key = 0x1000 + i;
        let records = vec![
            edge_bytes(1, 1, key, 100 + i * 10, 0, 0),
            edge_bytes(2, 1, key, 105 + i * 10, 0, 0),
        ];
        assert_eq!(core.ingest_records(&records), 1);
    }
    let ledger = core
        .ledger([0; 5], [0; 16], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.completed.len(), 2);
    assert_eq!(ledger.retained_dropped, 1);
    assert_eq!(ledger.reducer.emitted, 3);
}

#[test]
fn f7_take_completed_drains_and_releases_the_bound() {
    // The live tick drains retained completions; drained records
    // free retention for new ones (a draining reader never drops).
    let mut core = SensorCore::new(16, 16, 1, 8, true);
    let one = vec![
        edge_bytes(1, 1, 0xabc, 100, 0, 0),
        edge_bytes(2, 1, 0xabc, 150, 0, 0),
    ];
    assert_eq!(core.ingest_records(&one), 1);
    let taken = core.take_completed();
    assert_eq!(taken.len(), 1);
    let two = vec![
        edge_bytes(1, 1, 0xabd, 200, 0, 0),
        edge_bytes(2, 1, 0xabd, 250, 0, 0),
    ];
    assert_eq!(core.ingest_records(&two), 1);
    let ledger = core
        .ledger([0; 5], [0; 16], Vec::new(), ctx())
        .expect("empty miss join");
    assert_eq!(ledger.completed.len(), 1);
    assert_eq!(ledger.retained_dropped, 0);
}

#[test]
fn w8_ledger_carries_session_context() {
    // M2/H2: the pre-arm counter baselines and the sticky identity
    // verdict land in the terminal ledger untouched (coverage and
    // integrity consult them; pairing never does).
    let core = SensorCore::new(16, 16, 16, 8, true);
    let ledger = core
        .ledger(
            [1, 2, 3, 4, 5],
            [6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Vec::new(),
            SessionContext {
                loss_baseline: [0, 1, 0, 0, 0],
                agg_baseline: [0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                view_valid: false,
                miss_baseline: Vec::new(),
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect("empty miss join");
    assert_eq!(ledger.kernel_loss, [1, 2, 3, 4, 5]);
    assert_eq!(
        ledger.agg_accepted,
        [6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(ledger.loss_baseline, [0, 1, 0, 0, 0]);
    assert_eq!(
        ledger.agg_baseline,
        [0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert!(!ledger.view_valid);
}

#[test]
fn w9_ledger_joins_prog_miss_deltas_from_absolutes() {
    // Round-9 H2: the terminal ledger joins pre-arm and current
    // per-program miss absolutes by section (the one join site) and
    // carries the final absolutes for the canary's GO-baselines.
    use kryprobe_privilege::kcrypto_lifecycle::view::ProgMisses;
    let core = SensorCore::new(16, 16, 16, 8, true);
    let base = vec![
        ProgMisses {
            section: "fsession/a".to_owned(),
            id: 11,
            misses: 3,
        },
        ProgMisses {
            section: "fsession/b".to_owned(),
            id: 12,
            misses: 0,
        },
    ];
    let cur = vec![
        ProgMisses {
            section: "fsession/b".to_owned(),
            id: 12,
            misses: 1,
        },
        ProgMisses {
            section: "fsession/a".to_owned(),
            id: 11,
            misses: 5,
        },
    ];
    let ledger = core
        .ledger(
            [0; 5],
            [0; 16],
            cur.clone(),
            SessionContext {
                loss_baseline: [0; 5],
                agg_baseline: [0; 16],
                view_valid: true,
                miss_baseline: base,
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect("monotone join");
    assert_eq!(ledger.miss_current, cur);
    assert_eq!(ledger.prog_misses.len(), 2);
    assert_eq!(ledger.prog_misses[0].section, "fsession/b");
    assert_eq!(ledger.prog_misses[0].delta(), 1);
    assert_eq!(ledger.prog_misses[1].section, "fsession/a");
    assert_eq!(ledger.prog_misses[1].delta(), 2);
}

#[test]
fn w10_ledger_refuses_untrustworthy_miss_join() {
    // Round-10 astra-Major: a backwards miss join refuses the
    // terminal ledger (no ledger, no clean verdict — never zero).
    use kryprobe_privilege::kcrypto_lifecycle::view::ProgMisses;
    let core = SensorCore::new(16, 16, 16, 8, true);
    let base = vec![ProgMisses {
        section: "fsession/a".to_owned(),
        id: 11,
        misses: 9,
    }];
    let cur = vec![ProgMisses {
        section: "fsession/a".to_owned(),
        id: 11,
        misses: 4,
    }];
    let err = core
        .ledger(
            [0; 5],
            [0; 16],
            cur,
            SessionContext {
                loss_baseline: [0; 5],
                agg_baseline: [0; 16],
                view_valid: true,
                miss_baseline: base,
                enrichment: EnrichmentStatus::Available {
                    entries: 0,
                    truncated: false,
                },
            },
        )
        .expect_err("backwards miss join must refuse the ledger");
    assert!(format!("{err}").contains("ran backwards"), "{err:?}");
}

#[test]
fn ingest_op_edge_admits_first_seen_transform() {
    // T07.3 wiring: an ingested op SUBMIT with a nonzero transform
    // word admits a first-seen generation in the core's tracker
    // (creation provenance unknown; the submit's driver rides along
    // — F05). Returns never admit (R2: no exit-side chase — the
    // paired return joins by invocation only); a 0 submit word
    // counts unlinked.
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    let f1 = 0xFFFF_8880_0000_1000u64;
    core.ingest_records(&[edge_bytes_tfm(
        1,
        1,
        0xabc,
        100,
        0,
        0,
        0x4000,
        f1,
        b"aes-generic",
    )]);
    let gens = core.tfm().generations();
    assert_eq!(gens.len(), 1, "op submit admits its transform");
    assert!(gens[0].first_seen);
    assert_eq!(gens[0].req_name, "");
    assert_eq!(gens[0].drv_name, "aes-generic", "submit driver captured");
    core.ingest_records(&[edge_bytes_tfm(2, 1, 0xabc, 150, 0, 0, 0x4000, 0, b"")]);
    assert_eq!(core.tfm().generations().len(), 1, "return admits nothing");
    core.ingest_records(&[edge_bytes(1, 1, 0xdef, 200, 0, 0)]);
    assert_eq!(core.tfm().stats().unlinked_ops, 1, "zero word counted");
}

#[test]
fn mixed_inventory_destroys_green_through_production_ingest() {
    // T07-R3-12 / astra R3-07: complete digest destroy pairs
    // (never-live bases) ingested through the PRODUCTION path
    // alongside one clean fixture lifetime — the reconciled
    // verdict greens: the unknown counter, the destroy lanes, and
    // the admitted/releases equations all agree on the inventory
    // magnitude (a counter-only view is not real inventory).
    let run = "run-mixed-inventory";
    let text = [
        format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"alloc","req":"kxcipher","drv":"drv","type":0,"mask":0}}"#),
        format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"config","op":"setkey","errno":0,"len":16}}"#),
        format!(r#"{{"v":1,"run":"{run}","seq":1,"phase":"free","final":true}}"#),
        format!(r#"{{"v":1,"run":"{run}","phase":"done","fixture_result":0,"overflow":0}}"#),
    ]
    .join("\n");
    let truth = parse_transcript(&text, run).expect("mixed transcript parses");
    let f1 = 0xFFFF_8880_0000_1000u64;
    let b1 = f1 + 8;
    let stream = vec![
        // Fixture alloc pair (submit names req, return names drv).
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_ALLOC_SK,
            0,
            100,
            0,
            0,
            0,
            2,
            b"kxcipher",
        ),
        tfm_record(
            LEDGE_RETURN,
            LTFM_SITE_ALLOC_SK,
            f1,
            150,
            0,
            0,
            0,
            2,
            b"drv",
        ),
        // Fixture setkey pair.
        tfm_record(LEDGE_SUBMIT, LTFM_SITE_SETKEY_SK, f1, 200, 0, 16, 0, 4, b""),
        tfm_record(LEDGE_RETURN, LTFM_SITE_SETKEY_SK, 0, 250, 0, 0, 0, 4, b""),
        // Fixture destroy pair (observed refcount 1: proved final).
        tfm_record(LEDGE_SUBMIT, LTFM_SITE_DESTROY, b1, 300, 0, 1, 1, 6, b""),
        tfm_record(LEDGE_RETURN, LTFM_SITE_DESTROY, 0, 350, 0, 0, 0, 6, b""),
        // Two background digest destroy pairs (never-live bases).
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_DESTROY,
            0xFFFF_8880_0000_2000,
            400,
            0,
            1,
            1,
            8,
            b"",
        ),
        tfm_record(LEDGE_RETURN, LTFM_SITE_DESTROY, 0, 450, 0, 0, 0, 8, b""),
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_DESTROY,
            0xFFFF_8880_0000_3000,
            500,
            0,
            1,
            1,
            10,
            b"",
        ),
        tfm_record(LEDGE_RETURN, LTFM_SITE_DESTROY, 0, 550, 0, 0, 0, 10, b""),
    ];
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    core.ingest_records(&stream);
    core.finish(600);
    // Lossless ring: accepted == consumed on every lane.
    let probe = core
        .ledger([0; 5], [0; 16], Vec::new(), ctx())
        .expect("probe ledger");
    let ledger = core
        .ledger([0; 5], probe.edge_hits, Vec::new(), ctx())
        .expect("mixed ledger");
    assert_eq!(
        ledger.tfm_stats.unknown_releases, 2,
        "digest pairs land unknown"
    );
    assert_eq!(ledger.tfm_stats.releases, 3);
    assert_eq!(ledger.tfm_stats.admitted, 5);
    assert!(core.tfm().reuse_exact(), "inventory keeps exactness");
    let view = SensorView {
        completed: &ledger.completed,
        edge_hits: ledger.edge_hits,
        decode: ledger.decode,
        reducer: ledger.reducer,
        kernel_loss: [0; 5],
        agg_accepted: ledger.edge_hits,
        retained_dropped: 0,
        baseline: SensorBaseline::default(),
        quiet_backlog_bytes: 0,
        view_valid: true,
        attached_links: 7,
        foreign_links: 0,
        prog_misses: Vec::new(),
        tfm: ledger.tfm_stats,
        generations: &ledger.generations,
        reuse_exact: core.tfm().reuse_exact(),
    };
    verdict("reuse-burst", &truth, &view).expect("mixed inventory greens");
}

#[test]
fn ingest_zero_word_op_voids_exact_reuse() {
    // T07-R3-01 / astra R3-04 sensor-ingest regression: a lone
    // zero-word op submit (no admission, no other refusal) still
    // voids exact reuse — the unidentified operation is an identity
    // gap, not a clean session.
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    core.ingest_records(&[edge_bytes(1, 1, 0xdef, 200, 0, 0)]);
    assert_eq!(core.tfm().stats().unlinked_ops, 1);
    assert!(
        !core.tfm().reuse_exact(),
        "unlinked op voids exact reuse through ingest"
    );
}

#[test]
fn w7_fold_loss_lanes_sums_per_class_saturating() {
    // Round-7: one `LLOSS` lane per program per class (an interrupt
    // can run a different program on the same CPU mid-bump, so
    // per-CPU alone lost updates). The fold sums the sixteen hook
    // lanes class-major, saturating — a saturated lane must not
    // wrap the ledger.
    let mut lanes = [0u64; 80];
    lanes[0] = 1;
    lanes[1] = 2;
    lanes[2] = 3;
    lanes[3] = 4;
    lanes[17] = 7;
    lanes[64] = u64::MAX;
    lanes[79] = u64::MAX;
    assert_eq!(fold_loss_lanes(lanes), [10, 7, 0, 0, u64::MAX]);
}

#[test]
fn ledger_carries_enrichment_status_both_arms() {
    // T07-09: the terminal ledger distinguishes an available
    // registry snapshot from a failed one WITH its reason —
    // capture never refuses on enrichment, but the report never
    // stays silent about its absence either.
    let core = SensorCore::new(16, 16, 16, 8, true);
    let mut available = ctx();
    available.enrichment = EnrichmentStatus::Available {
        entries: 41,
        truncated: true,
    };
    let ledger = core
        .ledger([0; 5], [0; 16], Vec::new(), available)
        .expect("empty miss join");
    assert_eq!(
        ledger.enrichment,
        EnrichmentStatus::Available {
            entries: 41,
            truncated: true,
        }
    );
    let mut missing = ctx();
    missing.enrichment = EnrichmentStatus::Unavailable {
        reason: "No such file or directory (os error 2)".to_owned(),
    };
    let ledger = core
        .ledger([0; 5], [0; 16], Vec::new(), missing)
        .expect("empty miss join");
    assert_eq!(
        ledger.enrichment,
        EnrichmentStatus::Unavailable {
            reason: "No such file or directory (os error 2)".to_owned(),
        }
    );
}

#[test]
fn enrichment_projection_folds_entry_truncation() {
    // R2-06: the REAL snapshot-to-status conversion (the same
    // `from_snapshot` the sensor shell calls) reports truncated
    // when EITHER the snapshot hit a bound OR any entry clipped
    // a field — a clipped name must never read untruncated.
    use kryprobe_privilege::kcrypto_lifecycle::proc_crypto::{ProcCryptoEntry, ProcCryptoSnapshot};
    use std::time::SystemTime;
    fn entry(name: &str, truncated: bool) -> ProcCryptoEntry {
        ProcCryptoEntry {
            name: name.to_owned(),
            driver: None,
            entry_type: None,
            priority: None,
            module: None,
            flags: None,
            truncated,
            name_truncated: false,
        }
    }
    fn snap(entries: Vec<ProcCryptoEntry>, truncated: bool) -> ProcCryptoSnapshot {
        ProcCryptoSnapshot {
            at: SystemTime::UNIX_EPOCH,
            entries,
            truncated,
        }
    }
    // Clean snapshot: available, untruncated, entry count kept.
    assert_eq!(
        EnrichmentStatus::from_snapshot(&Some(snap(vec![entry("cbc(aes)", false)], false)), &None),
        EnrichmentStatus::Available {
            entries: 1,
            truncated: false,
        }
    );
    // Snapshot-level bound: truncated.
    assert_eq!(
        EnrichmentStatus::from_snapshot(&Some(snap(vec![], true)), &None),
        EnrichmentStatus::Available {
            entries: 0,
            truncated: true,
        }
    );
    // Entry-level field clip ALONE (snapshot clean): truncated.
    assert_eq!(
        EnrichmentStatus::from_snapshot(&Some(snap(vec![entry("cbc(aes)", true)], false)), &None),
        EnrichmentStatus::Available {
            entries: 1,
            truncated: true,
        }
    );
    // Failed read: unavailable with the reason, never empty.
    assert_eq!(
        EnrichmentStatus::from_snapshot(&None, &Some("os error 2".to_owned())),
        EnrichmentStatus::Unavailable {
            reason: "os error 2".to_owned(),
        }
    );
    // Unreachable-by-construction arms report loud, never invent.
    assert!(matches!(
        EnrichmentStatus::from_snapshot(&None, &None),
        EnrichmentStatus::Unavailable { reason } if reason.contains("invariant")
    ));
    assert!(matches!(
        EnrichmentStatus::from_snapshot(
            &Some(snap(vec![], false)),
            &Some("x".to_owned())
        ),
        EnrichmentStatus::Unavailable { reason } if reason.contains("invariant")
    ));
}

/// Twin-valid 112B `LTfm` record (byte layout mirrors the
/// canonical `tfm_bytes` builder in `kcrypto_tfm_lifecycle` —
/// magic, version, edge, site, key, timestamp, status, aux words,
/// token, name).
#[allow(clippy::too_many_arguments)]
fn tfm_record(
    edge: u8,
    site: u16,
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

#[test]
fn suppressed_free_forces_ambiguous_retire_at_ingest() {
    // T07-R2-04 suppressed-free qualification (deterministic,
    // sensor-facing): a recorded-shape edge stream — alloc pair,
    // WITHHELD destroy pair (the deliberately suppressed free
    // observation), realloc pair at the same base — through the
    // PRODUCTION ingest path (decode + join + tracker). The
    // observer must force-retire the old lifetime as AMBIGUOUS
    // (never merge, never confident), mint the newcomer fresh,
    // and void exact reuse. (Live BPF edge-completeness is proven
    // separately by the in-guest reuse-burst equation + zero-loss
    // gate; together they qualify the suppressed-free case.)
    let base = 0xFFFF_8880_0000_1000u64;
    let stream = vec![
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_ALLOC_SK,
            0,
            100,
            0,
            0,
            0,
            2,
            b"kxcipher",
        ),
        tfm_record(
            LEDGE_RETURN,
            LTFM_SITE_ALLOC_SK,
            base,
            150,
            0,
            0,
            0,
            2,
            b"drv",
        ),
        // Destroy pair for `base` deliberately withheld here.
        // (Tokens stay even: the LSB is the BPF invoc-poison bit —
        // an odd token is twin drift and refuses at decode.)
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_ALLOC_SK,
            0,
            200,
            0,
            0,
            0,
            4,
            b"kxcipher",
        ),
        tfm_record(
            LEDGE_RETURN,
            LTFM_SITE_ALLOC_SK,
            base,
            250,
            0,
            0,
            0,
            4,
            b"drv",
        ),
    ];
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    core.ingest_records(&stream);
    let tracker = core.tfm();
    let stats = tracker.stats();
    assert_eq!(stats.forced_retires, 1, "realloc forces the retire");
    assert_eq!(stats.releases, 0, "no destroy observed at all");
    let generations = tracker.generations();
    assert_eq!(generations.len(), 2, "old + newcomer");
    assert!(
        generations[0].retired && generations[0].ambiguous,
        "old lifetime ambiguous-retired: {:?}",
        generations[0]
    );
    assert!(
        !generations[1].retired && !generations[1].ambiguous,
        "newcomer live and clean: {:?}",
        generations[1]
    );
    assert_ne!(
        generations[0].id, generations[1].id,
        "no id merge across the gap"
    );
    assert!(
        !tracker.reuse_exact(),
        "exactness voids on the unobserved end"
    );
}

#[test]
fn shared_release_retained_then_final_at_ingest() {
    // T07-R2-04 retained/final-release qualification
    // (deterministic, sensor-facing): the fixture `shared-release`
    // shape — alloc pair, retained destroy pair (refcount 2,
    // observed), final destroy pair (refcount 1) — through the
    // PRODUCTION ingest path. The observer must retire the
    // lifetime on the proved final free, keep the ambiguity the
    // retained release proved (one end uncertain), and void exact
    // reuse. (In-guest this scenario is kernel-excluded from the
    // sensor lane: 7.2+ removed the tfm refcount so the fixture
    // refuses, while 6.12 predates fsession so the sensor
    // refuses — the host ingest pins the same verdict shape the
    // canary asserts: retired + ambiguous + exactness void.)
    let frontend = 0xFFFF_8880_0000_1000u64;
    let base = frontend + 8;
    let stream = vec![
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_ALLOC_SK,
            0,
            100,
            0,
            0,
            0,
            2,
            b"kxcipher",
        ),
        tfm_record(
            LEDGE_RETURN,
            LTFM_SITE_ALLOC_SK,
            frontend,
            150,
            0,
            0,
            0,
            2,
            b"drv",
        ),
        // Retained release: refcount 2 observed (no free yet).
        tfm_record(LEDGE_SUBMIT, LTFM_SITE_DESTROY, base, 200, 0, 2, 1, 4, b""),
        tfm_record(LEDGE_RETURN, LTFM_SITE_DESTROY, 0, 250, 0, 0, 0, 4, b""),
        // Proved final free: refcount 1 observed.
        tfm_record(LEDGE_SUBMIT, LTFM_SITE_DESTROY, base, 300, 0, 1, 1, 6, b""),
        tfm_record(LEDGE_RETURN, LTFM_SITE_DESTROY, 0, 350, 0, 0, 0, 6, b""),
    ];
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    core.ingest_records(&stream);
    let tracker = core.tfm();
    let stats = tracker.stats();
    assert_eq!(stats.releases, 2, "both destroys join");
    assert_eq!(stats.retired, 1, "final free retires");
    assert_eq!(
        stats.ambiguous_releases, 1,
        "retained release flags ambiguity"
    );
    assert_eq!(stats.forced_retires, 0, "no realloc, no force");
    let generations = tracker.generations();
    assert_eq!(generations.len(), 1, "one lifetime, never split");
    assert!(
        generations[0].retired && generations[0].ambiguous,
        "retired on proved final, ambiguity survives: {:?}",
        generations[0]
    );
    assert!(
        !tracker.reuse_exact(),
        "exactness voids on the retained release"
    );
}

#[test]
fn invalid_authsize_records_failure_without_epoch_at_ingest() {
    // T07-R2-04 sensor-facing invalid-authsize case (the round-2
    // coverage note): an oversize setauthsize (errno -EINVAL)
    // through the PRODUCTION ingest path. The observer must join
    // the config onto the live generation (scalars recorded,
    // failure classified) WITHOUT bumping the epoch — a rejected
    // length changes nothing — while exact reuse stands (a
    // classified failure is truth, not boundary uncertainty).
    let frontend = 0xFFFF_8880_0000_1000u64;
    let stream = vec![
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_ALLOC_SK,
            0,
            100,
            0,
            0,
            0,
            2,
            b"kxcipher",
        ),
        tfm_record(
            LEDGE_RETURN,
            LTFM_SITE_ALLOC_SK,
            frontend,
            150,
            0,
            0,
            0,
            2,
            b"drv",
        ),
        // Oversize authsize: entry carries frontend + length 64,
        // the errno return carries status + token only.
        tfm_record(
            LEDGE_SUBMIT,
            LTFM_SITE_SETAUTHSIZE,
            frontend,
            200,
            0,
            64,
            0,
            4,
            b"",
        ),
        tfm_record(
            LEDGE_RETURN,
            LTFM_SITE_SETAUTHSIZE,
            0,
            250,
            -22,
            0,
            0,
            4,
            b"",
        ),
    ];
    let mut core = SensorCore::new(16, 16, 16, 8, true);
    core.ingest_records(&stream);
    let tracker = core.tfm();
    let stats = tracker.stats();
    assert_eq!(stats.configs_joined, 1, "config joins");
    assert_eq!(stats.configs_failed, 1, "errno verdict classified");
    let generations = tracker.generations();
    assert_eq!(generations.len(), 1, "one lifetime");
    let info = &generations[0];
    assert_eq!(info.configs, 1, "config attributed");
    assert_eq!(info.epoch, 0, "rejected length bumps no epoch");
    assert_eq!(info.last_config_site, LTFM_SITE_SETAUTHSIZE);
    assert_eq!(info.last_config_len, 64, "rejected length kept");
    assert_eq!(info.last_config_errno, -22, "native errno kept");
    assert!(!info.ambiguous, "classified failure is not ambiguity");
    assert!(tracker.reuse_exact(), "truth keeps reuse exact");
}
