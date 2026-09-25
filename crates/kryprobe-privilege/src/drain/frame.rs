// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure ringbuf framing step: one header word → one decision (T7c2,
//! H1 rework).
//!
//! The live walker ([`crate::drain::area::RingArea::consume_live`])
//! reads each header straight from the mapping (volatile, never a
//! shared reference over live bytes) and asks [`frame_step`] what the
//! word means; payload bytes copy out only on [`FrameStep::Emit`],
//! then the header revalidates (libbpf pattern) before anything
//! advances. No snapshot, no bulk copy, no torn reads.

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
    /// Kept record payloads.
    pub records: Vec<Vec<u8>>,
    /// Advanced consumer position.
    pub consumer: u64,
    /// Stopped on a busy/torn record: more may arrive later.
    pub busy: bool,
}

/// One header word's framing decision (pure over the word +
/// positions; the live walker owns the bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStep {
    /// Copy `len` payload bytes, revalidate, advance `total`.
    Emit {
        /// Payload length in bytes.
        len: u64,
        /// Header + 8-aligned payload.
        total: u64,
    },
    /// Advance `total` without emitting.
    Skip {
        /// Header + 8-aligned payload.
        total: u64,
    },
    /// Stop the walk (busy/torn/corrupt): more may arrive later.
    Stop,
}

/// Decide one record from its header word (both positions absolute).
///
/// `Stop` on: busy writer, length past the ring size, or a frame
/// overrunning the producer snapshot (torn tail — the commit had not
/// landed when the producer was read). Discards skip; exact fits emit
/// (a frame ending exactly on the producer is committed, never torn).
/// Saturating: `consumer + total` at `u64::MAX` saturates instead of
/// wrapping (a corrupt producer near the top stops the walk, and a
/// producer pinned at `u64::MAX` with an exact fit still emits).
pub fn frame_step(hdr: u32, max: u64, consumer: u64, producer: u64) -> FrameStep {
    if hdr & BUSY_BIT != 0 {
        return FrameStep::Stop;
    }
    let len = u64::from(hdr & LEN_MASK);
    if len > max {
        return FrameStep::Stop;
    }
    let total = HDR_SZ as u64 + ((len + 7) & !7);
    if consumer.saturating_add(total) > producer {
        return FrameStep::Stop;
    }
    if hdr & DISCARD_BIT != 0 {
        FrameStep::Skip { total }
    } else {
        FrameStep::Emit { len, total }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_rounds_payload_up() {
        assert_eq!(
            frame_step(64, 256, 0, 72),
            FrameStep::Emit { len: 64, total: 72 }
        );
        assert_eq!(
            frame_step(1, 256, 0, 16),
            FrameStep::Emit { len: 1, total: 16 }
        );
        // Exact fit on the producer emits (committed, never torn).
        assert_eq!(
            frame_step(8, 256, 0, 16),
            FrameStep::Emit { len: 8, total: 16 }
        );
    }

    #[test]
    fn discard_skips_without_emit() {
        assert_eq!(
            frame_step(DISCARD_BIT | 8, 256, 0, 16),
            FrameStep::Skip { total: 16 }
        );
    }

    #[test]
    fn busy_stops() {
        assert_eq!(frame_step(BUSY_BIT | 8, 256, 0, 100), FrameStep::Stop);
    }

    #[test]
    fn oversize_stops() {
        assert_eq!(frame_step(257, 256, 0, 1000), FrameStep::Stop);
        assert_eq!(
            frame_step(256, 256, 0, 264),
            FrameStep::Emit {
                len: 256,
                total: 264
            }
        );
    }

    #[test]
    fn overrun_stops() {
        // Producer covers only the header: torn body, stop like busy.
        assert_eq!(frame_step(8, 256, 0, 15), FrameStep::Stop);
    }

    #[test]
    fn near_max_consumer_stops_without_wrap() {
        // Corrupt producer just below u64::MAX: `consumer + total`
        // would wrap (and panic in debug); saturation stops instead.
        assert_eq!(
            frame_step(0, 256, u64::MAX - 7, u64::MAX - 3),
            FrameStep::Stop
        );
    }

    #[test]
    fn max_producer_exact_fit_emits() {
        // Producer pinned at u64::MAX with an exact fit: emit (the
        // walker saturates the consumer onto the producer).
        assert_eq!(
            frame_step(0, 256, u64::MAX - 7, u64::MAX),
            FrameStep::Emit { len: 0, total: 8 }
        );
    }
}
