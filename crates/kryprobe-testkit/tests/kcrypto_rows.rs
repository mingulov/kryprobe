// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical kcrypto row bytes (3A-M-T7 / 1A-L4): layout pins for the
//! single builder set both suites decode through.

use kryprobe_testkit::kcrypto_rows::{AggSpec, agg_row_bytes, ident_row_bytes, totals_row_bytes};

fn le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 counter bytes"))
}

#[test]
fn agg_layout_pins_header_name_and_counters() {
    let row = agg_row_bytes(AggSpec {
        family: 7,
        op: 1,
        result: 0,
        ctx: 3,
        name: b"cbc(aes)",
        calls: 10,
        bytes: 640,
        ok: 9,
    });
    assert_eq!(row.len(), 382);
    assert_eq!(row[0], 0x01, "snapshot version");
    assert_eq!(row[1], 1, "agg kind");
    assert_eq!(&row[2..6], &[7, 1, 0, 3], "family/op/result/ctx");
    assert_eq!(&row[6..14], b"cbc(aes)", "algorithm name");
    assert_eq!(row[14], 0, "NUL terminator");
    assert!(row[15..262].iter().all(|b| *b == 0), "name padding");
    assert_eq!(le(&row, 262), 10, "calls");
    assert_eq!(le(&row, 270), 640, "bytes");
    assert_eq!(le(&row, 278), 9, "ok");
    assert!(row[286..].iter().all(|b| *b == 0), "tail padding");
}

#[test]
fn totals_layout_pins_header_and_counters() {
    let row = totals_row_bytes(40, 640, 39);
    assert_eq!(row.len(), 122);
    assert_eq!(row[0], 0x01, "snapshot version");
    assert_eq!(row[1], 2, "totals kind");
    assert_eq!(le(&row, 2), 40, "calls");
    assert_eq!(le(&row, 10), 640, "bytes");
    assert_eq!(le(&row, 18), 39, "ok");
    assert!(row[26..].iter().all(|b| *b == 0), "tail padding");
}

#[test]
fn ident_layout_pins_header() {
    let row = ident_row_bytes();
    assert_eq!(row.len(), 50);
    assert_eq!(row[0], 0x01, "snapshot version");
    assert_eq!(row[1], 3, "ident kind");
    assert!(row[2..].iter().all(|b| *b == 0), "zeroed ident body");
}
