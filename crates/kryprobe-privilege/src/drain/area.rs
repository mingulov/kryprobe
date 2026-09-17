// SPDX-License-Identifier: GPL-3.0-or-later
//! Ringbuf memory mappings: consumer page + producer/data area (T7c2 split).

use super::DrainError;
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

    /// Copy the pending window `[consumer, producer)` into the reusable
    /// full-size buffer at its ring-indexed position.
    ///
    /// Soundness: bytes below `producer` are stable — the kernel appends
    /// past `producer` and never wraps over `consumer` (a full ring
    /// fails reservations instead, counted as ring loss). The tail race
    /// (a record being written while copied) is caught by the frame
    /// walk's busy/length/producer checks, exactly as with the old
    /// volatile whole-area copy, at a fraction of the cost.
    pub(crate) fn snapshot_into(&self, buf: &mut [u8], consumer: u64, producer: u64) {
        debug_assert_eq!(buf.len(), 2 * self.max);
        let (start, len) = copy_window(self.max, consumer, producer);
        if len == 0 {
            return;
        }
        // SAFETY: `copy_window` bounds `start + len` by `2 * max`, which
        // is inside both the double mapping and `buf`.
        unsafe {
            let src = self.prod.add(self.page + start);
            std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(start), len);
        }
        // The walk indexes `(consumer & mask)`, so a window crossing the
        // ring end must also refresh the mirrored head: without it the
        // walk reads stale bytes from the previous round.
        if let Some((src, dst, n)) = mirror_span(self.max, start, len) {
            buf.copy_within(src..src + n, dst);
        }
    }
}

/// Mirror span refreshing the wrapped head of a copied window.
///
/// When `start + len` crosses the ring end (`max`), the walk's masked
/// indexing reads the wrapped bytes from the first mapping, so
/// `[max, start + len)` must be mirrored down to `[0, start + len -
/// max)`. Returns `(src, dst, len)` for the within-buffer copy, or
/// `None` when the window does not wrap.
fn mirror_span(max: usize, start: usize, len: usize) -> Option<(usize, usize, usize)> {
    if start + len > max {
        Some((max, 0, start + len - max))
    } else {
        None
    }
}

/// Ring-indexed copy window for `[consumer, producer)`.
///
/// `max` is the ring size (power of two). The window starts at the
/// consumer's ring offset and covers the pending bytes, clamped to the
/// double mapping (`2 * max - start`); pending past the ring size is a
/// kernel impossibility (reserve fails first), so clamping only guards
/// against a corrupt producer position, never a real one.
fn copy_window(max: usize, consumer: u64, producer: u64) -> (usize, usize) {
    let mask = max as u64 - 1;
    let start = (consumer & mask) as usize;
    let pending = producer.saturating_sub(consumer) as usize;
    let room = 2 * max - start;
    (start, pending.min(room))
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
    use super::{copy_window, mirror_span};

    #[test]
    fn window_covers_pending_at_ring_offset() {
        assert_eq!(copy_window(256, 100, 160), (100, 60));
        assert_eq!(copy_window(256, 0, 0), (0, 0));
    }

    #[test]
    fn window_wraps_linearly_in_double_mapping() {
        // Consumer near the ring end: the window runs into the second
        // mapping, which mirrors the first.
        assert_eq!(copy_window(256, 200, 300), (200, 100));
    }

    #[test]
    fn window_clamps_to_mapping() {
        // A corrupt producer far ahead cannot overrun the buffer.
        assert_eq!(copy_window(256, 0, 10_000), (0, 512));
        assert_eq!(copy_window(256, 200, 10_000), (200, 312));
    }

    #[test]
    fn window_ignores_consumer_ahead() {
        assert_eq!(copy_window(256, 300, 100), (44, 0));
    }

    #[test]
    fn mirror_only_when_wrapping() {
        assert_eq!(mirror_span(256, 200, 100), Some((256, 0, 44)));
        assert_eq!(mirror_span(256, 200, 56), None);
        assert_eq!(mirror_span(256, 0, 512), Some((256, 0, 256)));
        assert_eq!(mirror_span(256, 100, 0), None);
    }
}
