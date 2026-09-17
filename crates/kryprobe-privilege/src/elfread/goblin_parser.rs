// SPDX-License-Identifier: GPL-3.0-or-later
//! Goblin-based dynamic-symbol to file-offset resolution.

use anyhow::Context;
use goblin::elf::Elf;
use goblin::elf::program_header::PT_LOAD;
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::sym::{STB_GLOBAL, STT_FUNC, STT_NOTYPE, STT_OBJECT};

/// Resolves dynamic symbol `name` to its file offset, if present.
pub fn symbol_file_offset(bytes: &[u8], name: &str) -> anyhow::Result<Option<u64>> {
    for (sym_name, offset) in dynamic_symbols(bytes)? {
        if sym_name == name {
            return Ok(Some(offset));
        }
    }
    Ok(None)
}

/// Lists all resolvable dynamic symbols as `(name, file_offset)` pairs.
pub fn dynamic_symbols(bytes: &[u8]) -> anyhow::Result<Vec<(String, u64)>> {
    let elf = Elf::parse(bytes).context("goblin elf parse")?;
    let mut out = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx == SHN_UNDEF as usize || sym.st_value == 0 {
            continue;
        }
        let typ = sym.st_type();
        if typ != STT_FUNC && typ != STT_OBJECT && typ != STT_NOTYPE {
            continue;
        }
        let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if sym_name.is_empty() {
            continue;
        }
        if let Some(off) = va_to_offset(&elf, sym.st_value) {
            out.push((sym_name.to_string(), off));
        }
    }
    out.sort();
    Ok(out)
}

/// Resolves a static (symtab) symbol `name` to its file offset, if present.
/// Static resolution is goblin-only by design: it walks section-backed
/// symbol tables, while the `minimal` parser covers dynamic symbols.
pub fn static_symbol_file_offset(bytes: &[u8], name: &str) -> anyhow::Result<Option<u64>> {
    let elf = Elf::parse(bytes).context("goblin elf parse")?;
    let mut fallback = None;
    for sym in elf.syms.iter() {
        if sym.st_shndx == SHN_UNDEF as usize || sym.st_value == 0 {
            continue;
        }
        let typ = sym.st_type();
        if typ != STT_FUNC && typ != STT_OBJECT && typ != STT_NOTYPE {
            continue;
        }
        let Some(sym_name) = elf.strtab.get_at(sym.st_name) else {
            continue;
        };
        if sym_name != name {
            continue;
        }
        let Some(off) = va_to_offset(&elf, sym.st_value) else {
            continue;
        };
        if sym.st_bind() == STB_GLOBAL {
            return Ok(Some(off));
        }
        if fallback.is_none() {
            fallback = Some(off);
        }
    }
    Ok(fallback)
}

fn va_to_offset(elf: &Elf<'_>, va: u64) -> Option<u64> {
    for ph in elf.program_headers.iter() {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if va >= ph.p_vaddr && va < ph.p_vaddr.saturating_add(ph.p_memsz) {
            return Some(ph.p_offset.saturating_add(va - ph.p_vaddr));
        }
    }
    None
}
