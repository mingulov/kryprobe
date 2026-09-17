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
                let idx = base + entry.offset / 8;
                let insns = &programs[*p].insns;
                if idx + 1 >= insns.len() || insns[idx].code != OP_LD_DW {
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
                let idx = base + entry.offset / 8;
                let main_len = bases[*p].1;
                let insns = &mut programs[*p].insns;
                if idx >= insns.len() || insns[idx].code != OP_CALL || insns[idx].dst_src != 0x10 {
                    return Err(bad(format!("call reloc at {} is not a call", entry.offset)));
                }
                // LLVM marks unresolved calls with BPF_PSEUDO_CALL (-1) in
                // both imm and the src nibble; the true addend is then 0
                // (verified: all 3 call sites in spine.bpf.o carry -1).
                let raw = i64::from(insns[idx].imm);
                let dest = sym.st_value as i64 + if raw == -1 { 0 } else { raw };
                if dest < 0 {
                    return Err(bad(format!("call reloc target {dest} is negative")));
                }
                let text_bytes = (insns.len() - main_len) * 8;
                if !(dest as usize).is_multiple_of(8) || dest as usize >= text_bytes {
                    return Err(bad(format!("call reloc target {dest} misaligned/short")));
                }
                let target_idx = main_len + dest as usize / 8;
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
