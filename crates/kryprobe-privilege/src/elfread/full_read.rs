// SPDX-License-Identifier: GPL-3.0-or-later
//! Whole-file buffered reader used as an [`ElfBytes`] source.

use super::ElfBytes;
use anyhow::Context;
use std::path::Path;

/// Owning buffered copy of a file's bytes.
#[derive(Debug)]
pub struct FullRead {
    data: Vec<u8>,
}

impl FullRead {
    /// Reads `path` fully into memory.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Ok(Self { data })
    }
}

impl ElfBytes for FullRead {
    fn bytes(&self) -> &[u8] {
        &self.data
    }
}
