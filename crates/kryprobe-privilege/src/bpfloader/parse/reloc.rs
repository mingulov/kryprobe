// SPDX-License-Identifier: GPL-3.0-or-later
//! Relocation decode + apply: map plans now, call targets now (T7c1 split).

use super::{MapReloc, bad, section_bytes};
use crate::bpfloader::{LoaderError, ParsedProg};
use goblin::elf::Elf;

/// Section type `SHT_REL` (relocations without explicit addends).
const SHT_REL: u32 = 9;
/// `R_BPF_64_64`: 64-bit map-fd fixup of an `ld_imm64` pair.
const R_BPF_64_64: u32 = 1;
/// `R_BPF_64_32`: 32-bit call-target fixup of a `call` insn.
const R_BPF_64_32: u32 = 10;
/// Opcode `LD | DW` (64-bit immediate load).
const OP_LD_DW: u8 = 0x18;
/// Opcode `JMP | CALL` (relative subprogram call).
const OP_CALL: u8 = 0x85;

/// One raw `Elf64_Rel` entry: offset, symbol index, type.
struct RelocEntry {
    offset: usize,
    sym_idx: usize,
    rel_type: u32,
}

fn decode_relocs(content: &[u8]) -> Result<Vec<RelocEntry>, LoaderError> {
    if !content.len().is_multiple_of(16) {
        return Err(bad(
            "reloc section length is not a multiple of 16".to_owned()
        ));
    }
    let mut out = Vec::with_capacity(content.len() / 16);
    for entry in content.as_chunks::<16>().0 {
        // Indexing is safe: chunks_exact(16) guarantees 16 bytes.
        let lo = u64::from_le_bytes([
            entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7],
        ]);
        let hi = u64::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11], entry[12], entry[13], entry[14], entry[15],
        ]);
        // `as usize` lossless by the 64-bit gate in `parse.rs`; the
        // `as u32` is an explicit low-32 mask, exact on every target.
        out.push(RelocEntry {
            offset: lo as usize,
            sym_idx: (hi >> 32) as usize,
            rel_type: (hi & 0xffff_ffff) as u32,
        });
    }
    Ok(out)
}

/// Target streams for one reloc section: (program, insn base).
/// `.text` relocs apply to every program past its main part.
fn reloc_streams(
    target: usize,
    text_idx: usize,
    bases: &[(usize, usize)],
) -> Result<Vec<(usize, usize)>, LoaderError> {
    if target == text_idx {
        Ok(bases
            .iter()
            .enumerate()
            .map(|(p, (_, main_len))| (p, *main_len))
            .collect())
    } else {
        match bases.iter().position(|(sec_idx, _)| target == *sec_idx) {
            Some(p) => Ok(vec![(p, 0)]),
            None => Err(bad(format!("reloc targets unknown section {target}"))),
        }
    }
}

/// `bases[p] = (main section index, main insn count)` per program stream.
pub(crate) fn apply_relocs(
    elf: &Elf,
    bytes: &[u8],
    text_idx: usize,
    bases: &[(usize, usize)],
    programs: &mut [ParsedProg],
    map_relocs: &mut Vec<MapReloc>,
) -> Result<(), LoaderError> {
    for sh in elf.section_headers.iter() {
        if sh.sh_type != SHT_REL {
            continue;
        }
        let target = sh.sh_info as usize;
        let content = section_bytes(bytes, sh.sh_offset, sh.sh_size)?;
        let streams = reloc_streams(target, text_idx, bases)?;
        for entry in decode_relocs(content)? {
            apply_one(elf, text_idx, bases, programs, map_relocs, &streams, entry)?;
        }
    }
    Ok(())
}

/// Checked reloc target index: `base + offset / 8` on
/// attacker-controlled `offset` (callers reject misaligned offsets first).
/// Every overflow is `BadObject`, never a wrap or a panic.
fn reloc_idx(base: usize, offset: usize, what: &str) -> Result<usize, LoaderError> {
    base.checked_add(offset / 8).ok_or_else(|| {
        bad(format!(
            "{what} reloc offset {offset} overflows the insn index"
        ))
    })
}

/// `ld_imm64` pair `[idx, idx + 1]` strictly inside `len`. The `+ 1` is
/// checked: `idx == USIZE_MAX` fails closed instead of wrapping to 0 and
/// passing a naive bounds check before an out-of-bounds index.
fn pair_fits(idx: usize, len: usize) -> bool {
    idx.checked_add(1).is_some_and(|end| end < len)
}

/// Call target: symbol value plus the insn addend (LLVM's `-1`
/// pseudo-call placeholder counts as 0). The `u64`→`i64` narrowing and
/// the add are both checked: every overflow is `BadObject`, never a
/// debug panic or a release wrap.
fn call_dest(st_value: u64, imm: i32) -> Result<i64, LoaderError> {
    let base = i64::try_from(st_value)
        .map_err(|_| bad(format!("call reloc symbol value {st_value} overflows i64")))?;
    let addend = if imm == -1 { 0 } else { i64::from(imm) };
    base.checked_add(addend)
        .ok_or_else(|| bad(format!("call reloc target {base} + {addend} overflows")))
}

fn apply_one(
    elf: &Elf,
    text_idx: usize,
    bases: &[(usize, usize)],
    programs: &mut [ParsedProg],
    map_relocs: &mut Vec<MapReloc>,
    streams: &[(usize, usize)],
    entry: RelocEntry,
) -> Result<(), LoaderError> {
    let sym = elf
        .syms
        .get(entry.sym_idx)
        .ok_or_else(|| bad(format!("reloc references missing symbol {}", entry.sym_idx)))?;
    let sym_name = elf.strtab.get_at(sym.st_name).unwrap_or_default();
    if !entry.offset.is_multiple_of(8) {
        return Err(bad(format!(
            "reloc offset {} is not insn-aligned",
            entry.offset
        )));
    }
    match entry.rel_type {
        R_BPF_64_64 => {
            if sym.st_shndx == 0 {
                return Err(bad(format!("map reloc for undefined symbol '{sym_name}'")));
            }
            for (p, base) in streams {
                let idx = reloc_idx(*base, entry.offset, "map")?;
                let insns = &programs[*p].insns;
                if !pair_fits(idx, insns.len()) || insns[idx].code != OP_LD_DW {
                    return Err(bad(format!(
                        "map reloc at {} is not an ld_imm64 pair",
                        entry.offset
                    )));
                }
                map_relocs.push(MapReloc {
                    prog: *p,
                    insn_idx: idx,
                    map: sym_name.to_owned(),
                });
            }
            Ok(())
        }
        R_BPF_64_32 => {
            // Call target = symbol value + original imm, inside .text.
            if sym.st_shndx != text_idx {
                return Err(bad(format!("call reloc outside .text: '{sym_name}'")));
            }
            for (p, base) in streams {
                let idx = reloc_idx(*base, entry.offset, "call")?;
                let main_len = bases[*p].1;
                let insns = &mut programs[*p].insns;
                if idx >= insns.len() || insns[idx].code != OP_CALL || insns[idx].dst_src != 0x10 {
                    return Err(bad(format!("call reloc at {} is not a call", entry.offset)));
                }
                let dest = call_dest(sym.st_value, insns[idx].imm)?;
                if dest < 0 {
                    return Err(bad(format!("call reloc target {dest} is negative")));
                }
                let tail = insns.len().checked_sub(main_len).ok_or_else(|| {
                    bad(format!("call reloc main length {main_len} exceeds stream"))
                })?;
                let text_bytes = tail
                    .checked_mul(8)
                    .ok_or_else(|| bad("call reloc stream length overflows".to_owned()))?;
                // `dest as usize` is exact: `dest` is non-negative
                // (checked above) and `usize` is 64-bit (gate in
                // `parse.rs`); the bounds check below still applies.
                if !(dest as usize).is_multiple_of(8) || dest as usize >= text_bytes {
                    return Err(bad(format!("call reloc target {dest} misaligned/short")));
                }
                let target_idx = main_len.checked_add(dest as usize / 8).ok_or_else(|| {
                    bad(format!("call reloc target {dest} overflows the insn index"))
                })?;
                // Both indices are below `insns.len()` (checked above), so
                // the casts are exact and the difference cannot overflow.
                let rel = target_idx as i64 - idx as i64 - 1;
                let rel = i32::try_from(rel)
                    .map_err(|_| bad(format!("call reloc target {dest} too far")))?;
                insns[idx].imm = rel;
            }
            Ok(())
        }
        other => Err(bad(format!("unsupported reloc type {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idx_happy_path() {
        assert_eq!(reloc_idx(0, 16, "map").unwrap(), 2);
        assert_eq!(reloc_idx(4, 8, "call").unwrap(), 5);
    }

    #[test]
    fn idx_add_is_checked() {
        // `base + offset/8` would wrap to a small index unchecked.
        let err = reloc_idx(usize::MAX - 1, 16, "map").unwrap_err();
        assert!(matches!(err, LoaderError::BadObject { .. }), "{err}");
        // An exact `USIZE_MAX` index survives the add; the pair check
        // below is what rejects it.
        assert_eq!(reloc_idx(usize::MAX, 0, "call").unwrap(), usize::MAX);
    }

    #[test]
    fn pair_at_usize_max_fails_closed() {
        // `USIZE_MAX + 1` wraps to 0 unchecked, passing a naive bounds
        // check before an out-of-bounds index. Unreachable through the
        // public parse (bases are file-size-bounded), pinned at the
        // helper so the check cannot regress.
        assert!(!pair_fits(usize::MAX, 64));
        assert!(!pair_fits(usize::MAX, usize::MAX));
        assert!(pair_fits(62, 64));
        assert!(!pair_fits(63, 64));
        assert!(!pair_fits(64, 64));
    }

    #[test]
    fn dest_overflow_is_bad_object() {
        let err = call_dest(i64::MAX as u64, 1).unwrap_err();
        assert!(matches!(err, LoaderError::BadObject { .. }), "{err}");
        let err = call_dest(u64::MAX, 0).unwrap_err();
        assert!(matches!(err, LoaderError::BadObject { .. }), "{err}");
        let err = call_dest(i64::MAX as u64, i32::MAX).unwrap_err();
        assert!(matches!(err, LoaderError::BadObject { .. }), "{err}");
    }

    #[test]
    fn dest_happy_path_and_pseudo_call() {
        assert_eq!(call_dest(0x100, 8).unwrap(), 0x108);
        // LLVM's -1 pseudo-call placeholder counts as addend 0.
        assert_eq!(call_dest(0x100, -1).unwrap(), 0x100);
        assert_eq!(call_dest(0, 0).unwrap(), 0);
    }
}
