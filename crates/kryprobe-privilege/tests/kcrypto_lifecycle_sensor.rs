// SPDX-License-Identifier: GPL-3.0-or-later
//! T06 sensor suite: pure ingest (records → decode → reducer → ledger).
//!
//! Pins the terminal ledger contract without privilege: paired edges
//! complete grounded records, queued returns stay pending, unknown
//! keys and bad records count loss without phantoms, and `finish`
//! drains pending truthless. The mmap shell (`drain_once`) rides the
//! same `ingest_records` and is covered by the VM canary lane.

use kryprobe_core::kcrypto::Terminal;
use kryprobe_privilege::kcrypto_lifecycle::sensor::SensorCore;

/// One 32-byte `LEdge` (little-endian twin of the ABI struct).
fn edge_bytes(edge: u8, site: u16, key: u64, ts_ns: u64, status: i32) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[0..2].copy_from_slice(&0x434cu16.to_le_bytes());
    out[2] = 1;
    out[3] = edge;
    out[4..6].copy_from_slice(&site.to_le_bytes());
    out[8..16].copy_from_slice(&key.to_le_bytes());
    out[16..24].copy_from_slice(&ts_ns.to_le_bytes());
    out[24..28].copy_from_slice(&status.to_le_bytes());
    out
}

#[test]
fn ingest_paired_edges_complete_grounded_record() {
    let mut core = SensorCore::new(16, 16, 16);
    let records = vec![
        edge_bytes(1, 1, 0xabc, 100, 0),
        edge_bytes(2, 1, 0xabc, 150, 0),
    ];
    assert_eq!(core.ingest_records(&records), 1);
    let ledger = core.ledger([0; 4]);
    assert_eq!(ledger.completed.len(), 1);
    let rec = &ledger.completed[0];
    assert_eq!((rec.id, rec.tfm_id, rec.duration_ns), (1, None, Some(50)));
    assert_eq!(rec.terminal, Terminal::Sync(0));
    assert!(rec.evidence_valid());
    assert_eq!(ledger.edge_hits, [1, 1, 0, 0]);
    assert_eq!(ledger.decode.admitted, 1);
    assert_eq!(ledger.reducer.admitted, 1);
}

#[test]
fn ingest_queued_return_stays_pending() {
    let mut core = SensorCore::new(16, 16, 16);
    let records = vec![
        edge_bytes(1, 1, 0xabc, 100, 0),
        edge_bytes(2, 1, 0xabc, 150, -115),
    ];
    assert_eq!(core.ingest_records(&records), 0);
    assert!(core.ledger([0; 4]).completed.is_empty());
    assert_eq!(core.ledger([0; 4]).decode.admitted, 1);
    assert_eq!(core.ledger([0; 4]).edge_hits, [1, 1, 0, 0]);
}

#[test]
fn ingest_loss_counts_without_phantoms() {
    let mut core = SensorCore::new(16, 16, 16);
    let records = vec![
        edge_bytes(2, 1, 0xabc, 150, 0), // unknown-key return
        vec![0u8; 31],                   // short record
        edge_bytes(9, 1, 1, 1, 0),       // bad edge kind
    ];
    assert_eq!(core.ingest_records(&records), 0);
    let ledger = core.ledger([7, 0, 0, 0]);
    assert!(ledger.completed.is_empty());
    assert_eq!(ledger.decode.unknown_key_returns, 1);
    assert_eq!(ledger.decode.bad_records, 2);
    assert_eq!(ledger.kernel_loss, [7, 0, 0, 0]);
    assert_eq!(ledger.reducer.admitted, 0);
}

#[test]
fn finish_drains_pending_truthless() {
    let mut core = SensorCore::new(16, 16, 16);
    core.ingest_records(&[edge_bytes(1, 1, 0xabc, 100, 0)]);
    assert!(core.ledger([0; 4]).completed.is_empty());
    let drained = core.finish(200);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].terminal, Terminal::Unknown);
    assert!(!drained[0].evidence_valid());
    assert_eq!(core.ledger([0; 4]).completed.len(), 1);
}

#[test]
fn f7_completed_retention_is_bounded_and_counted() {
    // Round-1 (astra-M7) + design C12: every output queue has a
    // configured bound. Past the ledger cap, completions stop being
    // retained and count retained_dropped (explicit loss, never
    // silent growth).
    let mut core = SensorCore::new(16, 16, 2);
    for i in 0..3u64 {
        let key = 0x1000 + i;
        let records = vec![
            edge_bytes(1, 1, key, 100 + i * 10, 0),
            edge_bytes(2, 1, key, 105 + i * 10, 0),
        ];
        assert_eq!(core.ingest_records(&records), 1);
    }
    let ledger = core.ledger([0; 4]);
    assert_eq!(ledger.completed.len(), 2);
    assert_eq!(ledger.retained_dropped, 1);
    assert_eq!(ledger.reducer.emitted, 3);
}

#[test]
fn f7_take_completed_drains_and_releases_the_bound() {
    // The live tick drains retained completions; drained records
    // free retention for new ones (a draining reader never drops).
    let mut core = SensorCore::new(16, 16, 1);
    let one = vec![
        edge_bytes(1, 1, 0xabc, 100, 0),
        edge_bytes(2, 1, 0xabc, 150, 0),
    ];
    assert_eq!(core.ingest_records(&one), 1);
    let taken = core.take_completed();
    assert_eq!(taken.len(), 1);
    let two = vec![
        edge_bytes(1, 1, 0xabd, 200, 0),
        edge_bytes(2, 1, 0xabd, 250, 0),
    ];
    assert_eq!(core.ingest_records(&two), 1);
    let ledger = core.ledger([0; 4]);
    assert_eq!(ledger.completed.len(), 1);
    assert_eq!(ledger.retained_dropped, 0);
}
