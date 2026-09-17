// SPDX-License-Identifier: GPL-3.0-or-later
//! Private read-only file mapping used as an [`ElfBytes`] source.

use super::ElfBytes;
use anyhow::{Context, anyhow};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// RAII read-only `mmap` of a file.
pub struct MmapGuard {
    ptr: *mut libc::c_void,
    len: usize,
}

impl MmapGuard {
    /// Maps `path` read-only via `mmap`.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let len = file
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len() as usize;
        if len == 0 {
            return Err(anyhow!("empty file {}", path.display()));
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(anyhow!(
                "mmap {} failed: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { ptr, len })
    }
}

impl ElfBytes for MmapGuard {
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for MmapGuard {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}
