// SPDX-License-Identifier: GPL-3.0-or-later
//! ELF byte readers and dynamic-symbol resolution (T6a interface).
//!
//! Readers implement [`ElfBytes`]; parsers resolve dynamic-symbol
//! names to file offsets. [`symbol_file_offset`] is the primary
//! (minimal-parser) implementation; [`goblin_parser`] is the
//! correctness oracle. Both parsers expose the same signatures.
//!
//! Default pairing is `MmapGuard` + [`minimal`], the T6b spike winner
//! (fastest median on all fixtures; see
//! `docs/dependencies/elf-access.md`). All four combinations stay
//! compiled (no `cfg` gating: `cfg(test)` would hide the losers from
//! integration-test builds of this crate, breaking the oracle test).

pub mod full_read;
pub mod goblin_parser;
pub mod minimal;
pub mod mmap;

pub use full_read::FullRead;
pub use minimal::symbol_file_offset;
pub use mmap::MmapGuard;

/// Byte source for ELF parsing (mmap or full read).
pub trait ElfBytes {
    /// Returns the mapped or buffered ELF bytes.
    fn bytes(&self) -> &[u8];
}
