// SPDX-License-Identifier: GPL-3.0-or-later
//! Ringbuf memory mappings: consumer page + producer/data area (T7c2 split).

use super::DrainError;
use super::frame::{self, Consumed, HDR_SZ};
use crate::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};

fn page_size() -> usize {
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n < 1 { 4096 } else { n as usize }
}

/// The two ringbuf mappings; unmapped on drop.
pub(crate) struct RingArea {
    cons: *mut u8,
    prod: *mut u8,
    page: usize,
    max: usize,
}

// SAFETY: mappings are thread-confined to the drain thread.
unsafe impl Send for RingArea {}

impl RingArea {
    pub(crate) fn map(fd: &OwnedFd, max_entries: u32) -> Result<Self, DrainError> {
        let page = page_size();
        let max = max_entries as usize;
        let fail = |stage: &str| DrainError::MmapFailed {
            stage: stage.to_owned(),
            errno: std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        };
        // SAFETY: page-aligned lengths, valid map fd, checked for failure.
        let cons = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if cons == libc::MAP_FAILED {
            return Err(fail("consumer"));
        }
        let prod_len = page + 2 * max;
        let prod = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                prod_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                page as libc::off_t,
            )
        };
        if prod == libc::MAP_FAILED {
            unsafe { libc::munmap(cons, page) };
            return Err(fail("producer"));
        }
        Ok(Self {
            cons: cons as *mut u8,
            prod: prod as *mut u8,
            page,
            max,
        })
    }

    pub(crate) fn consumer(&self) -> u64 {
        unsafe { (*(self.cons as *const AtomicU64)).load(Ordering::Acquire) }
    }

    pub(crate) fn set_consumer(&self, value: u64) {
        unsafe { (*(self.cons as *const AtomicU64)).store(value, Ordering::Release) }
    }

    pub(crate) fn producer(&self) -> u64 {
        unsafe { (*(self.prod as *const AtomicU64)).load(Ordering::Acquire) }
    }

    /// Walk `[consumer, producer)` live (H1): per-record volatile
    /// header read → pure [`frame::frame_step`] → volatile payload
    /// copy → header revalidation (libbpf pattern). Never forms a
    /// shared reference over the mapping (the kernel producer may
    /// commit concurrently — `&[u8]` over live bytes is UB); a header
    /// that changes under the copy proves a torn read — discard, stop,
    /// never advance past unverified bytes. In-order always: the walk
    /// never skips past busy.
    pub(crate) fn consume_live(&self, mut consumer: u64, producer: u64, budget: usize) -> Consumed {
        let mut records = Vec::new();
        let mut busy = false;
        let mut visited = 0usize;
        let mask = self.max as u64 - 1;
        let max = self.max as u64;
        let span = 2 * self.max;
        while consumer < producer && visited < budget {
            visited += 1;
            let off = (consumer & mask) as usize;
            // Mapping bound (the old walk's defense-in-depth twin): a
            // corrupt position stops the walk, never reads past the map.
            if off + HDR_SZ > span {
                busy = true;
                break;
            }
            // SAFETY: bounded above — inside the double mapping.
            let hdr = unsafe { self.read_hdr(off) };
            match frame::frame_step(hdr, max, consumer, producer) {
                frame::FrameStep::Stop => {
                    busy = true;
                    break;
                }
                frame::FrameStep::Skip { total } => {
                    consumer = consumer.saturating_add(total);
                }
                frame::FrameStep::Emit { len, total } => {
                    if off + HDR_SZ + len as usize > span {
                        busy = true;
                        break;
                    }
                    let mut payload = vec![0u8; len as usize];
                    // SAFETY: bounded above — inside the double mapping;
                    // `payload` holds `len` bytes.
                    unsafe { self.copy_payload(off, payload.as_mut_ptr(), len as usize) };
                    // Revalidate: a header that changed under the copy
                    // proves a torn read — discard, stop, no advance.
                    let hdr2 = unsafe { self.read_hdr(off) };
                    if hdr2 != hdr {
                        busy = true;
                        break;
                    }
                    records.push(payload);
                    consumer = consumer.saturating_add(total);
                }
            }
        }
        Consumed {
            records,
            consumer,
            busy,
        }
    }

    /// One volatile header word (byte-wise: alignment-free — ring
    /// offsets are 8-multiples in practice, but a corrupt consumer
    /// must stop the walk, never trap the reader).
    ///
    /// # Safety
    ///
    /// `off + HDR_SZ` must lie inside the double mapping.
    unsafe fn read_hdr(&self, off: usize) -> u32 {
        // SAFETY: upheld by the caller (see above).
        unsafe {
            let base = self.prod.add(self.page + off);
            u32::from_le_bytes([
                base.read_volatile(),
                base.add(1).read_volatile(),
                base.add(2).read_volatile(),
                base.add(3).read_volatile(),
            ])
        }
    }

    /// Volatile payload copy out of the live mapping.
    ///
    /// # Safety
    ///
    /// `off + HDR_SZ + len` must lie inside the double mapping and
    /// `dst` must hold `len` bytes.
    unsafe fn copy_payload(&self, off: usize, dst: *mut u8, len: usize) {
        // SAFETY: upheld by the caller (see above).
        unsafe {
            let src = self.prod.add(self.page + off + HDR_SZ);
            for i in 0..len {
                dst.add(i).write(src.add(i).read_volatile());
            }
        }
    }
}

impl Drop for RingArea {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.cons as *mut libc::c_void, self.page);
            libc::munmap(self.prod as *mut libc::c_void, self.page + 2 * self.max);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RingArea;
    use super::frame::BUSY_BIT;
    use super::frame::DISCARD_BIT;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Simulated ringbuf area: anonymous mappings in the kernel layout
    /// (consumer page + producer word + a linear data span standing in
    /// for the double map — reads within the span behave identically).
    /// The producer side (`commit`) follows the kernel protocol:
    /// BUSY header → payload bytes → plain header swap → producer
    /// advance (all Release; the reader's Acquire observes them).
    struct Sim {
        area: RingArea,
    }

    impl Sim {
        fn new(max: usize) -> Self {
            let page = 4096usize;
            // SAFETY: anonymous mappings, checked; `RingArea::drop`
            // munmaps both. Writable here — the sim plays the kernel
            // producer; production maps the data side read-only.
            let cons = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(cons, libc::MAP_FAILED, "cons maps");
            let prod = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    page + 2 * max,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(prod, libc::MAP_FAILED, "prod maps");
            Self {
                area: RingArea {
                    cons: cons as *mut u8,
                    prod: prod as *mut u8,
                    page,
                    max,
                },
            }
        }

        fn set_producer(&self, value: u64) {
            unsafe {
                (*(self.area.prod as *const AtomicU64)).store(value, Ordering::Release);
            }
        }

        fn write_hdr(&self, off: usize, word: u32) {
            debug_assert_eq!(off % 4, 0, "sim headers stay aligned");
            unsafe {
                self.area
                    .prod
                    .add(self.area.page + off)
                    .cast::<u32>()
                    .write_volatile(word);
            }
        }

        /// Reserve→write→commit one record at absolute `pos` (BUSY
        /// header, payload bytes, plain header swap); returns the next
        /// position. The caller advances the producer past it.
        fn commit(&self, pos: u64, payload: &[u8]) -> u64 {
            let off = (pos & (self.area.max as u64 - 1)) as usize;
            self.write_hdr(off, BUSY_BIT | payload.len() as u32);
            unsafe {
                self.area
                    .prod
                    .add(self.area.page + off + super::frame::HDR_SZ)
                    .copy_from_nonoverlapping(payload.as_ptr(), payload.len());
            }
            self.write_hdr(off, payload.len() as u32);
            pos + super::frame::HDR_SZ as u64 + ((payload.len() as u64 + 7) & !7)
        }
    }

    #[test]
    fn empty_range_keeps_consumer() {
        let sim = Sim::new(256);
        let out = sim.area.consume_live(100, 100, 16);
        assert!(out.records.is_empty());
        assert_eq!(out.consumer, 100);
        assert!(!out.busy);
    }

    #[test]
    fn committed_record_emits_and_advances() {
        let sim = Sim::new(256);
        let end = sim.commit(0, &[7u8; 64]);
        assert_eq!(end, 72);
        sim.set_producer(end);
        let out = sim.area.consume_live(0, sim.area.producer(), 16);
        assert_eq!(out.records, vec![vec![7u8; 64]]);
        assert_eq!(out.consumer, 72);
        assert!(!out.busy);
    }

    #[test]
    fn busy_stops_then_recommits() {
        let sim = Sim::new(256);
        // Reserve without commit: the walk stops, never advances.
        sim.write_hdr(0, BUSY_BIT | 8);
        sim.set_producer(16);
        let out = sim.area.consume_live(0, 16, 16);
        assert!(out.records.is_empty());
        assert_eq!(out.consumer, 0);
        assert!(out.busy);
        // Commit lands: the retry emits (in-order, never skipped past).
        let end = sim.commit(0, &[3u8; 8]);
        sim.set_producer(end);
        let out = sim.area.consume_live(0, end, 16);
        assert_eq!(out.records, vec![vec![3u8; 8]]);
        assert_eq!(out.consumer, end);
        assert!(!out.busy);
    }

    #[test]
    fn wrap_reads_linearly() {
        let sim = Sim::new(64);
        // Record straddling the 64-byte boundary reads linearly from
        // the double-mapped span.
        let end = sim.commit(56, &[5u8; 8]);
        assert_eq!(end, 72);
        sim.set_producer(end);
        let out = sim.area.consume_live(56, end, 16);
        assert_eq!(out.records, vec![vec![5u8; 8]]);
        assert_eq!(out.consumer, 72);
        assert!(!out.busy);
    }

    #[test]
    fn discard_advances_without_emit() {
        let sim = Sim::new(256);
        let off = 0usize;
        sim.write_hdr(off, BUSY_BIT | DISCARD_BIT | 8);
        sim.write_hdr(off, DISCARD_BIT | 8);
        let mid = 16u64;
        let end = sim.commit(mid, &[3u8; 8]);
        sim.set_producer(end);
        let out = sim.area.consume_live(0, end, 16);
        assert_eq!(out.records, vec![vec![3u8; 8]]);
        assert_eq!(out.consumer, end);
        assert!(!out.busy);
    }

    #[test]
    fn budget_bounds_visits() {
        let sim = Sim::new(4096);
        let mut pos = 0;
        for _ in 0..4 {
            pos = sim.commit(pos, &[1u8; 8]);
        }
        sim.set_producer(pos);
        let out = sim.area.consume_live(0, pos, 1);
        assert_eq!(out.records.len(), 1);
        assert_eq!(out.consumer, 16);
        assert!(!out.busy);
    }

    #[test]
    fn torn_tail_stops_like_busy() {
        let sim = Sim::new(256);
        let end = sim.commit(0, &[1u8; 8]);
        sim.set_producer(end);
        // Stale producer covering only the header: torn body, stop.
        let out = sim.area.consume_live(0, end - 1, 16);
        assert!(out.records.is_empty());
        assert_eq!(out.consumer, 0);
        assert!(out.busy);
    }

    #[test]
    fn concurrent_producer_never_emits_torn_bytes() {
        // Writer thread commits uniform records while the reader
        // drains: every emitted payload must be byte-consistent
        // (all one index value — never a mix of two commits).
        let sim = Sim::new(65536);
        let prod = sim.area.prod as usize;
        let page = sim.area.page;
        let max = sim.area.max;
        const N: u64 = 200;
        let writer = std::thread::spawn(move || {
            let prod = prod as *mut u8;
            let mut pos = 0u64;
            for i in 0u64..N {
                let payload = [i as u8; 8];
                let off = (pos & (max as u64 - 1)) as usize;
                unsafe {
                    prod.add(page + off)
                        .cast::<u32>()
                        .write_volatile(BUSY_BIT | 8);
                    prod.add(page + off + super::frame::HDR_SZ)
                        .copy_from_nonoverlapping(payload.as_ptr(), 8);
                    prod.add(page + off).cast::<u32>().write_volatile(8);
                }
                pos += 16;
                unsafe {
                    (*(prod as *const AtomicU64)).store(pos, Ordering::Release);
                }
            }
            pos
        });
        let mut consumer = 0u64;
        let mut got = 0u64;
        while got < N {
            let producer = sim.area.producer();
            let out = sim.area.consume_live(consumer, producer, 8);
            for record in &out.records {
                assert_eq!(record.len(), 8, "payload length");
                assert!(
                    record.iter().all(|b| *b == record[0]),
                    "byte-consistent payload, got {record:?}"
                );
                got += 1;
            }
            consumer = out.consumer;
            if out.records.is_empty() && !out.busy {
                std::thread::yield_now();
            }
        }
        let end = writer.join().expect("writer joins");
        assert_eq!(consumer, end);
    }
}
