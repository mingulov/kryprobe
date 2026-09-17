// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure ringbuf record walk: framing math, unit-tested (T7c2).
//!
//! Operates on a linear view of the double-mapped data area, so wrap
//! reads are plain slices. The mmap/epoll shell lives in `drain.rs`.

/// Record header size: `len` u32 + kernel-internal `pg_off` u32.
pub const HDR_SZ: usize = 8;
/// Producer still writing: consumer must stop and retry later.
pub const BUSY_BIT: u32 = 1 << 31;
/// Committed but discarded: advance past, emit nothing.
pub const DISCARD_BIT: u32 = 1 << 30;
/// Data-length bits of the header word.
pub const LEN_MASK: u32 = !(BUSY_BIT | DISCARD_BIT);

/// One walk's output: kept payloads + advanced consumer position.
#[derive(Debug, PartialEq, Eq)]
pub struct Consumed {
    pub records: Vec<Vec<u8>>,
    pub consumer: u64,
    /// Stopped on a busy/torn record: more may arrive later.
    pub busy: bool,
}

/// Walk records from `consumer` toward `producer` (both absolute).
///
/// `data` is the double-mapped area (`2 * max_entries` bytes);
/// `mask` is `max_entries - 1` (entries a power of two). At most
/// `budget` record visits per call (discards count: a discard flood
/// must not starve the iteration budget).
pub fn consume_range(
    data: &[u8],
    mask: u64,
    mut consumer: u64,
    producer: u64,
    budget: usize,
) -> Consumed {
    let mut records = Vec::new();
    let mut busy = false;
    let mut visited = 0;
    let max = mask + 1;
    while consumer < producer && visited < budget {
        visited += 1;
        let off = (consumer & mask) as usize;
        let hdr_at = off + HDR_SZ;
        if hdr_at > data.len() {
            busy = true;
            break;
        }
        let hdr = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        if hdr & BUSY_BIT != 0 {
            busy = true;
            break;
        }
        let len = (hdr & LEN_MASK) as u64;
        if len > max {
            busy = true;
            break;
        }
        let total = HDR_SZ as u64 + ((len + 7) & !7);
        if consumer + total > producer {
            busy = true;
            break;
        }
        if hdr & DISCARD_BIT == 0 {
            let start = off + HDR_SZ;
            // Defense in depth: framing math bounds this, but a corrupt
            // consumer position must stop the walk, never panic it.
            if start + len as usize > data.len() {
                busy = true;
                break;
            }
            records.push(data[start..start + len as usize].to_vec());
        }
        consumer += total;
    }
    Consumed {
        records,
        consumer,
        busy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Double-mapped area simulator: `2 * max` zeroed bytes.
    fn area(max: usize) -> Vec<u8> {
        vec![0u8; 2 * max]
    }

    /// Emit one record header + payload at absolute `pos`.
    fn emit(area: &mut [u8], mask: u64, pos: u64, flags: u32, payload: &[u8]) -> u64 {
        let off = (pos & mask) as usize;
        let hdr = flags | payload.len() as u32;
        area[off..off + 4].copy_from_slice(&hdr.to_le_bytes());
        area[off + 8..off + 8 + payload.len()].copy_from_slice(payload);
        pos + HDR_SZ as u64 + ((payload.len() as u64 + 7) & !7)
    }

    #[test]
    fn empty_range_keeps_consumer() {
        let area = area(256);
        let out = consume_range(&area, 255, 100, 100, 16);
        assert_eq!(
            out,
            Consumed {
                records: vec![],
                consumer: 100,
                busy: false
            }
        );
    }

    #[test]
    fn one_record_advances_past_padding() {
        let mut area = area(256);
        let end = emit(&mut area, 255, 0, 0, &[7u8; 64]);
        assert_eq!(end, 72);
        let out = consume_range(&area, 255, 0, end, 16);
        assert_eq!(out.records, vec![vec![7u8; 64]]);
        assert_eq!(out.consumer, 72);
        assert!(!out.busy);
    }

    #[test]
    fn budget_bounds_visits() {
        let mut area = area(256);
        let mut pos = 0;
        for _ in 0..4 {
            pos = emit(&mut area, 255, pos, 0, &[1u8; 8]);
        }
        let out = consume_range(&area, 255, 0, pos, 1);
        assert_eq!(out.records.len(), 1);
        assert_eq!(out.consumer, 16);
        assert!(!out.busy);
    }

    #[test]
    fn discard_advances_without_emit() {
        let mut area = area(256);
        let mid = emit(&mut area, 255, 0, DISCARD_BIT, &[9u8; 8]);
        let end = emit(&mut area, 255, mid, 0, &[3u8; 8]);
        let out = consume_range(&area, 255, 0, end, 16);
        assert_eq!(out.records, vec![vec![3u8; 8]]);
        assert_eq!(out.consumer, end);
    }

    #[test]
    fn busy_stops_without_advance() {
        let mut area = area(256);
        let end = emit(&mut area, 255, 0, BUSY_BIT, &[0u8; 8]);
        let out = consume_range(&area, 255, 0, end, 16);
        assert!(out.records.is_empty());
        assert_eq!(out.consumer, 0);
        assert!(out.busy);
    }

    #[test]
    fn wrap_reads_linearly() {
        let mut area = area(64);
        // Record straddling the 64-byte boundary reads linearly
        // from the double-mapped area.
        let end = emit(&mut area, 63, 56, 0, &[5u8; 8]);
        assert_eq!(end, 72);
        let out = consume_range(&area, 63, 56, end, 16);
        assert_eq!(out.records, vec![vec![5u8; 8]]);
        assert_eq!(out.consumer, 72);
    }

    #[test]
    fn torn_record_stops() {
        let mut area = area(256);
        let end = emit(&mut area, 255, 0, 0, &[1u8; 8]);
        // Producer covers only the header: torn body, stop like busy.
        let out = consume_range(&area, 255, 0, end - 1, 16);
        assert!(out.records.is_empty());
        assert_eq!(out.consumer, 0);
        assert!(out.busy);
    }

    #[test]
    fn short_payload_rounds_up() {
        let mut area = area(256);
        let end = emit(&mut area, 255, 0, 0, &[42u8; 1]);
        assert_eq!(end, 16);
        let out = consume_range(&area, 255, 0, end, 16);
        assert_eq!(out.records, vec![vec![42u8]]);
        assert_eq!(out.consumer, 16);
    }
}
