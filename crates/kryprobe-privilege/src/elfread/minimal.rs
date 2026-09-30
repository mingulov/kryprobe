// SPDX-License-Identifier: GPL-3.0-or-later
//! Dependency-free 64-bit LE dynsym resolution (oracle).
//!
//! Walks ehdr, phdrs, dynamic table, dynsym, dynstr. ET_DYN and
//! ET_EXEC both work: symbol VAs map via PT_LOAD segments.

use anyhow::anyhow;
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
    if bytes_at(bytes, 0, 4)? != [0x7f, b'E', b'L', b'F'].as_slice() {
        return Err(anyhow!("not an ELF file"));
    }
    if bytes_at(bytes, 4, 2)? != [2u8, 1u8].as_slice() {
        return Err(anyhow!("only 64-bit little-endian ELF supported"));
    }
    let phoff = u64le(bytes, 0x20)? as usize;
    let phentsize = u16le(bytes, 0x36)? as usize;
    let phnum = u16le(bytes, 0x38)? as usize;
    if phentsize < 56 {
        return Err(anyhow!("bad phentsize {phentsize}"));
    }
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut dyn_va: Option<u64> = None;
    for i in 0..phnum {
        let off = phoff.saturating_add(i.saturating_mul(phentsize));
        let p_type = u32le(bytes, off)?;
        let p_offset = u64le(bytes, checked_off(off, 8)?)?;
        let p_vaddr = u64le(bytes, checked_off(off, 16)?)?;
        let p_memsz = u64le(bytes, checked_off(off, 40)?)?;
        if p_type == 1 {
            loads.push((p_offset, p_vaddr, p_memsz));
        } else if p_type == 2 {
            dyn_va = Some(p_vaddr);
        }
    }
    let Some(dyn_va) = dyn_va else {
        return Ok(Vec::new());
    };
    let dyn_off = va_to_offset(&loads, dyn_va).ok_or_else(|| anyhow!("bad dynamic VA"))?;
    let (mut symtab, mut strtab, mut strsz) = (None, None, None);
    let (mut hash, mut gnu_hash) = (None, None);
    for idx in 0usize..128 {
        let base = (dyn_off as usize).saturating_add(idx.saturating_mul(16));
        let tag = i64le(bytes, base)?;
        let val = u64le(bytes, checked_off(base, 8)?)?;
        match tag {
            0 => break,
            4 => hash = Some(val),
            5 => strtab = Some(val),
            6 => symtab = Some(val),
            10 => strsz = Some(val),
            0x6ffffef5 => gnu_hash = Some(val),
            _ => {}
        }
    }
    let (Some(sym_va), Some(str_va), Some(str_sz)) = (symtab, strtab, strsz) else {
        return Err(anyhow!("dynamic table lacks symtab/strtab"));
    };
    let sym_off = va_to_offset(&loads, sym_va).ok_or_else(|| anyhow!("bad symtab VA"))?;
    let str_off = va_to_offset(&loads, str_va).ok_or_else(|| anyhow!("bad strtab VA"))?;
    let count = symbol_count(bytes, &loads, hash, gnu_hash)?;
    let mut out = Vec::new();
    for i in 0..count {
        let base = (sym_off as usize).saturating_add(i.saturating_mul(24));
        let st_name = u32le(bytes, base)?;
        let st_type = bytes_at(bytes, checked_off(base, 4)?, 1)?[0] & 0xf;
        let st_shndx = u16le(bytes, checked_off(base, 6)?)?;
        let st_value = u64le(bytes, checked_off(base, 8)?)?;
        if st_shndx == 0 || st_value == 0 {
            continue;
        }
        if st_type != 0 && st_type != 1 && st_type != 2 {
            continue;
        }
        let Some(sym_name) = strtab_name(bytes, str_off as usize, str_sz, st_name)? else {
            continue;
        };
        if sym_name.is_empty() {
            continue;
        }
        if let Some(file_off) = va_to_offset(&loads, st_value) {
            out.push((sym_name, file_off));
        }
    }
    out.sort();
    Ok(out)
}

fn symbol_count(
    bytes: &[u8],
    loads: &[(u64, u64, u64)],
    hash: Option<u64>,
    gnu_hash: Option<u64>,
) -> anyhow::Result<usize> {
    if let Some(va) = hash {
        let off = va_to_offset(loads, va).ok_or_else(|| anyhow!("bad DT_HASH VA"))? as usize;
        return Ok(u32le(bytes, checked_off(off, 4)?)? as usize);
    }
    let Some(va) = gnu_hash else {
        return Err(anyhow!("no DT_HASH or DT_GNU_HASH"));
    };
    let off = va_to_offset(loads, va).ok_or_else(|| anyhow!("bad DT_GNU_HASH VA"))? as usize;
    let nbuckets = u32le(bytes, off)? as usize;
    let symoffset = u32le(bytes, checked_off(off, 4)?)? as usize;
    let bloom_size = u32le(bytes, checked_off(off, 8)?)? as usize;
    let buckets = off
        .saturating_add(16)
        .saturating_add(bloom_size.saturating_mul(8));
    let chains = buckets.saturating_add(nbuckets.saturating_mul(4));
    let mut hi = symoffset;
    let mut found = false;
    for i in 0..nbuckets {
        let b = u32le(bytes, buckets.saturating_add(i.saturating_mul(4)))? as usize;
        if b == 0 {
            continue;
        }
        found = true;
        let mut idx = b;
        for _ in 0..(bytes.len() / 24).saturating_add(2) {
            hi = hi.max(idx);
            let coff = chains.saturating_add(idx.saturating_sub(symoffset).saturating_mul(4));
            if u32le(bytes, coff)? & 1 == 1 {
                break;
            }
            idx = idx.saturating_add(1);
        }
    }
    Ok(if found {
        hi.saturating_add(1)
    } else {
        symoffset
    })
}

fn strtab_name(
    bytes: &[u8],
    str_off: usize,
    str_sz: u64,
    st_name: u32,
) -> anyhow::Result<Option<String>> {
    let start = str_off.saturating_add(st_name as usize);
    let end = str_off.saturating_add(str_sz as usize);
    if start >= end || end > bytes.len() {
        return Ok(None);
    }
    let tail = bytes_at(bytes, start, end - start)?;
    let len = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    match std::str::from_utf8(&tail[..len]) {
        Ok(s) => Ok(Some(s.to_string())),
        Err(_) => Ok(None),
    }
}

fn va_to_offset(loads: &[(u64, u64, u64)], va: u64) -> Option<u64> {
    for (p_offset, p_vaddr, p_memsz) in loads {
        if va >= *p_vaddr && va < p_vaddr.saturating_add(*p_memsz) {
            return Some(p_offset.saturating_add(va - p_vaddr));
        }
    }
    None
}
/// Adds a small constant stride to an untrusted-derived file offset, failing
/// closed on overflow instead of wrapping (release) or panicking (debug).
fn checked_off(off: usize, n: usize) -> anyhow::Result<usize> {
    off.checked_add(n)
        .ok_or_else(|| anyhow!("elf offset overflow"))
}

fn bytes_at(bytes: &[u8], off: usize, len: usize) -> anyhow::Result<&[u8]> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| anyhow!("elf offset overflow"))?;
    bytes.get(off..end).ok_or_else(|| anyhow!("elf truncated"))
}

fn u16le(bytes: &[u8], off: usize) -> anyhow::Result<u16> {
    let s = bytes_at(bytes, off, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(bytes: &[u8], off: usize) -> anyhow::Result<u32> {
    let s = bytes_at(bytes, off, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64le(bytes: &[u8], off: usize) -> anyhow::Result<u64> {
    let s = bytes_at(bytes, off, 8)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn i64le(bytes: &[u8], off: usize) -> anyhow::Result<i64> {
    Ok(u64le(bytes, off)? as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(dst: &mut [u8], off: usize, v: u16) {
        dst[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u32(dst: &mut [u8], off: usize, v: u32) {
        dst[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u64(dst: &mut [u8], off: usize, v: u64) {
        dst[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn put_phdr(
        dst: &mut [u8],
        off: usize,
        p_type: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_memsz: u64,
    ) {
        put_u32(dst, off, p_type);
        put_u64(dst, off + 8, p_offset);
        put_u64(dst, off + 16, p_vaddr);
        put_u64(dst, off + 40, p_memsz);
    }

    fn put_dyn(dst: &mut [u8], off: usize, tag: i64, val: u64) {
        put_u64(dst, off, tag as u64);
        put_u64(dst, off + 8, val);
    }

    /// Crafted ELF whose DT_HASH file offset lands on `usize::MAX`: the
    /// `off + 4` read must fail closed, never wrap (release) or panic
    /// (debug). Pre-fix this panics in debug / mis-parses to Ok in release.
    #[test]
    fn dt_hash_offset_overflow_is_rejected() {
        let mut bytes = vec![0u8; 2 * 1024 * 1024];
        bytes[0..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        put_u64(&mut bytes, 0x20, 0x40); // phoff
        put_u16(&mut bytes, 0x36, 56); // phentsize
        put_u16(&mut bytes, 0x38, 3); // phnum
        // Normal LOAD covering the dynamic table + symtab-zero area.
        put_phdr(&mut bytes, 0x40, 1, 0x100, 0x1000, 0x100);
        // Hostile LOAD: file offset pinned at u64::MAX.
        put_phdr(&mut bytes, 0x78, 1, u64::MAX, 0x2000, 0x1000);
        put_phdr(&mut bytes, 0xb0, 2, 0, 0x1000, 0);
        put_dyn(&mut bytes, 0x100, 6, 0x1080); // DT_SYMTAB -> zero area
        put_dyn(&mut bytes, 0x110, 5, 0x1000); // DT_STRTAB
        put_dyn(&mut bytes, 0x120, 10, 0x10); // DT_STRSZ
        put_dyn(&mut bytes, 0x130, 4, 0x2000); // DT_HASH -> usize::MAX
        put_dyn(&mut bytes, 0x140, 0, 0); // DT_NULL
        let err = dynamic_symbols(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("elf offset overflow"),
            "unexpected error: {err}"
        );
    }

    /// Positive control: header-only ELF with no dynamic segment.
    #[test]
    fn no_dynamic_segment_yields_empty() {
        let mut bytes = vec![0u8; 64];
        bytes[0..6].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1]);
        put_u64(&mut bytes, 0x20, 0x40);
        put_u16(&mut bytes, 0x36, 56);
        put_u16(&mut bytes, 0x38, 0);
        assert_eq!(dynamic_symbols(&bytes).unwrap(), Vec::new());
    }
}
