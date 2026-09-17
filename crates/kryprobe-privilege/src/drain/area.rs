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

    /// Volatile copy of the double-mapped data area.
    pub(crate) fn snapshot(&self) -> Vec<u8> {
        let mut out = vec![0u8; 2 * self.max];
        unsafe {
            let src = self.prod.add(self.page);
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = std::ptr::read_volatile(src.add(i));
            }
        }
        out
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
