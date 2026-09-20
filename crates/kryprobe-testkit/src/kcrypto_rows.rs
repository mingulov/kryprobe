// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical hand-rolled kcrypto snapshot row bytes (3A-M-T7 / 1A-L4).
//!
//! Single source for the agg/totals/ident vectors both suites decode
//! through: `kryprobe-privilege` snapshot tests and the CLI
//! payload-contract suite previously kept diverging copies (ok/bytes
//! fills disagreed). A codec change edits one site; fills are
//! explicit params so call sites show their assumptions.
//!
//! Layout authority stays in `kryprobe-privilege` (`SNAPSHOT_VERSION`,
//! `ROW_KIND_*`, `*_BYTES_LEN`); these builders mirror it byte for
//! byte and the consumers' constructors (`RowBytes::new`, …) reject
//! drift at decode time. Hand-rolled, not captured — the G9 lane
//! test `captured_row_matches_canonical_layout` closes that leg
//! (3A-H-T4) against live sensor bytes.

/// Snapshot version byte (mirrors `SNAPSHOT_VERSION`).
pub const VERSION: u8 = 0x01;
/// Agg row kind byte (mirrors `ROW_KIND_AGG`).
pub const KIND_AGG: u8 = 1;
/// Totals row kind byte (mirrors `ROW_KIND_TOTALS`).
pub const KIND_TOTALS: u8 = 2;
/// Ident row kind byte (mirrors `ROW_KIND_IDENT`).
pub const KIND_IDENT: u8 = 3;
/// Agg row length (mirrors `ROW_BYTES_LEN`).
pub const AGG_LEN: usize = 382;
/// Totals row length (mirrors `TOTALS_BYTES_LEN`).
pub const TOTALS_LEN: usize = 122;
/// Ident row length (mirrors `IDENT_BYTES_LEN`).
pub const IDENT_LEN: usize = 50;
/// NUL-padded algorithm-name field inside an agg row.
const NAME_FIELD: usize = 256;

/// Agg-row fill spec: header identity plus the calls/bytes/ok
/// counters. Fills stay explicit so call sites show their
/// assumptions; the builder pins the layout around them.
#[derive(Debug, Clone, Copy)]
pub struct AggSpec<'a> {
    /// Key family byte.
    pub family: u8,
    /// Operation byte.
    pub op: u8,
    /// Result byte.
    pub result: u8,
    /// Context byte.
    pub ctx: u8,
    /// Algorithm name (<256 bytes so the NUL terminator fits).
    pub name: &'a [u8],
    /// Observed calls.
    pub calls: u64,
    /// Observed bytes.
    pub bytes: u64,
    /// Successful calls.
    pub ok: u64,
}

/// One 382B agg row: version, kind, family/op/result/ctx, NUL-padded
/// name, then the calls/bytes/ok counters and zero tail.
///
/// Panics when `name` reaches 256 bytes: silently truncating an
/// algorithm name would build a lying fixture.
#[must_use]
pub fn agg_row_bytes(spec: AggSpec<'_>) -> Vec<u8> {
    assert!(spec.name.len() < NAME_FIELD, "algorithm name fits with NUL");
    let mut out = Vec::with_capacity(AGG_LEN);
    out.push(VERSION);
    out.push(KIND_AGG);
    out.extend_from_slice(&[spec.family, spec.op, spec.result, spec.ctx]);
    out.extend_from_slice(spec.name);
    out.push(0);
    out.extend_from_slice(&vec![0u8; NAME_FIELD - spec.name.len() - 1]);
    out.extend_from_slice(&spec.calls.to_le_bytes());
    out.extend_from_slice(&spec.bytes.to_le_bytes());
    out.extend_from_slice(&spec.ok.to_le_bytes());
    out.extend_from_slice(&[0u8; 120 - 24]);
    assert_eq!(out.len(), AGG_LEN);
    out
}

/// One 122B totals row: version, kind, then calls/bytes/ok and zero tail.
#[must_use]
pub fn totals_row_bytes(calls: u64, bytes: u64, ok: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOTALS_LEN);
    out.push(VERSION);
    out.push(KIND_TOTALS);
    out.extend_from_slice(&calls.to_le_bytes());
    out.extend_from_slice(&bytes.to_le_bytes());
    out.extend_from_slice(&ok.to_le_bytes());
    out.extend_from_slice(&[0u8; 120 - 24]);
    assert_eq!(out.len(), TOTALS_LEN);
    out
}

/// One 50B ident row: version, kind, zeroed body.
#[must_use]
pub fn ident_row_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(IDENT_LEN);
    out.push(VERSION);
    out.push(KIND_IDENT);
    out.extend_from_slice(&[0u8; IDENT_LEN - 2]);
    out
}
