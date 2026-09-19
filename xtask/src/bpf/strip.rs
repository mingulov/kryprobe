// SPDX-License-Identifier: GPL-3.0-or-later
//! Build-time dead-code strip for `.text`: a `--gc-sections` equivalent.
//!
//! rustc exports `memcpy`/`memmove`/`memset` as link roots and bpf-linker
//! has no GC, so the whole compiler_builtins mem member lands in `.text`
//! even though nothing calls it. Unreachable instructions make the kernel
//! verifier reject the program, so `build --bpf` strips dead functions
//! here, after the link. The runtime loader re-checks reachability at
//! parse time and fails closed if dead code ever reappears.

use goblin::elf::Elf;
use goblin::elf::section_header::SHT_REL;
use goblin::elf::section_header::SHT_SYMTAB;
use goblin::elf::section_header::SHT_SYMTAB_SHNDX;
use goblin::elf::sym::STB_LOCAL;
use goblin::elf::sym::STT_FUNC;

/// `R_BPF_64_32`: 32-bit call-target fixup of a `call` insn.
const R_BPF_64_32: u32 = 10;
/// Opcode `JMP | CALL` (relative subprogram call).
const OP_CALL: u8 = 0x85;
/// ELF machine id for eBPF.
const EM_BPF: u16 = 247;

/// Outcome of [`strip_dead_text_funcs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StripReport {
    /// Names of removed functions, ascending by old `.text` offset.
    pub(crate) removed: Vec<String>,
    /// `.text` length before the strip, in bytes.
    pub(crate) text_before: usize,
    /// `.text` length after the strip, in bytes.
    pub(crate) text_after: usize,
}

/// One `.text` function symbol.
#[derive(Debug, Clone)]
struct Func {
    name: String,
    value: usize,
    size: usize,
    sym_idx: usize,
}

/// One raw `Elf64_Rel` entry plus its section context.
#[derive(Debug, Clone, Copy)]
struct Reloc {
    /// Index of the `SHT_REL` section holding the entry.
    rel_sect: usize,
    /// Section the reloc applies to (`sh_info` of the reloc section).
    target_sect: usize,
    /// Byte offset within the target section.
    offset: usize,
    /// Referenced symbol index.
    sym_idx: usize,
    /// Relocation type.
    typ: u32,
}

fn err(reason: impl Into<String>) -> String {
    format!("strip: {}", reason.into())
}

/// Drop `.text` functions unreachable from the program entry calls.
///
/// Pure over bytes: dead functions are spliced out, kept functions shift
/// down, symbols and relocations are rewritten, and the result is
/// re-parsed. Any unexpected shape (overlap, gaps, calls into dropped
/// code, shifted entry targets) is an error, never a guess.
pub(crate) fn strip_dead_text_funcs(obj: &[u8]) -> Result<(Vec<u8>, StripReport), String> {
    let elf = Elf::parse(obj).map_err(|e| err(format!("ELF parse: {e}")))?;
    if elf.header.e_machine != EM_BPF {
        return Err(err(format!(
            "e_machine {} is not EM_BPF",
            elf.header.e_machine
        )));
    }
    let text_idx = find_text(&elf)?;
    let symtab_idx = find_only_symtab(&elf)?;
    let funcs = collect_funcs(&elf, text_idx, obj)?;
    let relocs = collect_relocs(&elf, obj)?;
    let roots = entry_roots(&elf, obj, text_idx, &relocs)?;
    let live = reachable(&elf, obj, text_idx, &funcs, &relocs, &roots)?;
    let dead: Vec<&Func> = funcs.iter().filter(|f| !live[f.sym_idx]).collect();
    let text_len = text_len(&elf, text_idx);
    if dead.is_empty() {
        let report = StripReport {
            removed: Vec::new(),
            text_before: text_len,
            text_after: text_len,
        };
        return Ok((obj.to_vec(), report));
    }
    let removed: Vec<String> = dead.iter().map(|f| f.name.clone()).collect();
    let out = rewrite(obj, &elf, text_idx, symtab_idx, &funcs, &relocs, &live)?;
    let report = StripReport {
        removed,
        text_before: text_len,
        text_after: text_len_of(&out)?,
    };
    verify(&out, &report)?;
    Ok((out, report))
}

fn section_file_range(elf: &Elf, idx: usize) -> Result<(usize, usize), String> {
    let sh = &elf.section_headers[idx];
    let (off, len) = (sh.sh_offset as usize, sh.sh_size as usize);
    off.checked_add(len)
        .ok_or_else(|| err("section range overflows"))?;
    Ok((off, len))
}

fn find_text(elf: &Elf) -> Result<usize, String> {
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default();
        if name == ".text" {
            return Ok(idx);
        }
    }
    Err(err("missing section '.text'"))
}

fn find_only_symtab(elf: &Elf) -> Result<usize, String> {
    for sh in elf.section_headers.iter() {
        if sh.sh_type == SHT_SYMTAB_SHNDX {
            return Err(err("extended section indices unsupported"));
        }
    }
    let mut found = None;
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        if sh.sh_type == SHT_SYMTAB {
            if found.is_some() {
                return Err(err("more than one symtab"));
            }
            found = Some(idx);
        }
    }
    found.ok_or_else(|| err("missing symtab"))
}

fn text_len(elf: &Elf, text_idx: usize) -> usize {
    elf.section_headers[text_idx].sh_size as usize
}

/// Drop the whole `.text` section after proving it unreferenced (R4).
///
/// K1 kcrypto recipe (`evidence/k0/P1-attach-matrix.txt` R4): the
/// bpf-linker `.text` carries only dead compiler-builtins mem fns;
/// proven unreferenced here (zero `R_BPF_64_32` call relocs in the
/// whole object, no relocs of any kind against `.text` itself) and the
/// section is then retired in place (header nulled: type + name
/// cleared, so name scans see no `.text`). Any call reloc anywhere
/// fails the build — a called `.text` needs the spine-style GC strip,
/// not this drop. Missing `.text` is a no-op success.
///
/// Pure over bytes; errors are build failures, never guesses.
pub(crate) fn drop_unreferenced_text(obj: &[u8]) -> Result<(Vec<u8>, StripReport), String> {
    let elf = Elf::parse(obj).map_err(|e| err(format!("ELF parse: {e}")))?;
    if elf.header.e_machine != EM_BPF {
        return Err(err(format!(
            "e_machine {} is not EM_BPF",
            elf.header.e_machine
        )));
    }
    let text_idx = match find_text(&elf) {
        Ok(idx) => idx,
        Err(_) => {
            return Ok((
                obj.to_vec(),
                StripReport {
                    removed: Vec::new(),
                    text_before: 0,
                    text_after: 0,
                },
            ));
        }
    };
    let relocs = collect_relocs(&elf, obj)?;
    let calls = relocs.iter().filter(|r| r.typ == R_BPF_64_32).count();
    if calls > 0 {
        return Err(err(format!(
            "R4: object has {calls} call relocs; kcrypto objects must be call-free"
        )));
    }
    let against_text = relocs.iter().filter(|r| r.target_sect == text_idx).count();
    if against_text > 0 {
        return Err(err(format!(
            "R4: {against_text} relocs against .text; refusing to drop a referenced section"
        )));
    }
    let mut out = obj.to_vec();
    let shoff = elf.header.e_shoff as usize;
    // Retire `.text` plus its (proven empty) reloc sections: type and
    // name cleared, bytes left unreferenced. Unlike an
    // llvm-objcopy removal the headers are not renumbered — equivalent
    // for every ELF reader on this path (scans match by name/type).
    let mut retire = vec![text_idx];
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        if sh.sh_type == SHT_REL && sh.sh_info as usize == text_idx {
            retire.push(idx);
        }
    }
    for idx in &retire {
        write_u32(&mut out, shdr_field(shoff, *idx, 0), 0)?;
        write_u32(&mut out, shdr_field(shoff, *idx, 4), 0)?;
    }
    let report = StripReport {
        removed: vec![".text".to_owned()],
        text_before: text_len(&elf, text_idx),
        text_after: 0,
    };
    verify_drop(&out)?;
    Ok((out, report))
}

/// Structural re-check of the dropped object: no `.text` by name, no
/// reloc section against a retired header, every entry in range.
fn verify_drop(out: &[u8]) -> Result<(), String> {
    let elf = Elf::parse(out).map_err(|e| err(format!("verify parse: {e}")))?;
    for sh in elf.section_headers.iter() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default();
        if name == ".text" {
            return Err(err("verify: .text survived the drop"));
        }
        if sh.sh_type != SHT_REL {
            continue;
        }
        let target = sh.sh_info as usize;
        if target >= elf.section_headers.len() {
            return Err(err("verify: reloc section targets nothing"));
        }
        if elf.section_headers[target].sh_type == 0 {
            return Err(err("verify: reloc section targets a retired section"));
        }
    }
    let relocs = collect_relocs(&elf, out)?;
    for reloc in &relocs {
        if reloc.sym_idx >= elf.syms.len() {
            return Err(err("verify: reloc symbol out of range"));
        }
        let (_, len) = section_file_range(&elf, reloc.target_sect)?;
        if reloc.offset >= len {
            return Err(err("verify: reloc offset out of range"));
        }
    }
    Ok(())
}

fn collect_funcs(elf: &Elf, text_idx: usize, obj: &[u8]) -> Result<Vec<Func>, String> {
    let _ = obj;
    let len = text_len(elf, text_idx);
    if !len.is_multiple_of(8) {
        return Err(err(format!(".text length {len} is not insn-aligned")));
    }
    let mut funcs = Vec::new();
    for (sym_idx, sym) in elf.syms.iter().enumerate() {
        if sym.st_shndx != text_idx || goblin::elf::sym::st_type(sym.st_info) != STT_FUNC {
            continue;
        }
        if sym.st_size == 0 {
            return Err(err(format!(
                "function '{}' has zero size",
                sym_name(elf, sym.st_name)
            )));
        }
        let (value, size) = (sym.st_value as usize, sym.st_size as usize);
        if !value.is_multiple_of(8) || !size.is_multiple_of(8) {
            return Err(err(format!(
                "function '{}' is not insn-aligned",
                sym_name(elf, sym.st_name)
            )));
        }
        if value.checked_add(size).is_none_or(|end| end > len) {
            return Err(err(format!(
                "function '{}' runs past .text",
                sym_name(elf, sym.st_name)
            )));
        }
        funcs.push(Func {
            name: sym_name(elf, sym.st_name),
            value,
            size,
            sym_idx,
        });
    }
    if funcs.is_empty() {
        return Err(err("no function symbols in .text"));
    }
    funcs.sort_by_key(|f| f.value);
    // Functions must tile `.text` exactly: no overlap, no gaps.
    let mut end = 0;
    for func in &funcs {
        if func.value != end {
            return Err(err(format!(
                "function '{}' at {:#x} breaks .text tiling (want {end:#x})",
                func.name, func.value,
            )));
        }
        end = func.value + func.size;
    }
    if end != len {
        return Err(err(format!(
            ".text has unclaimed trailing bytes ({end:#x}..{len:#x})"
        )));
    }
    Ok(funcs)
}

fn sym_name(elf: &Elf, st_name: usize) -> String {
    elf.strtab.get_at(st_name).unwrap_or_default().to_owned()
}

fn collect_relocs(elf: &Elf, obj: &[u8]) -> Result<Vec<Reloc>, String> {
    let mut out = Vec::new();
    for (rel_sect, sh) in elf.section_headers.iter().enumerate() {
        if sh.sh_type != SHT_REL {
            continue;
        }
        let target_sect = sh.sh_info as usize;
        if target_sect >= elf.section_headers.len() {
            return Err(err(format!(
                "reloc section targets section {target_sect} (nonexistent)"
            )));
        }
        let (off, len) = section_file_range(elf, rel_sect)?;
        let bytes = obj
            .get(off..off + len)
            .ok_or_else(|| err("reloc section outside file"))?;
        if !len.is_multiple_of(16) {
            return Err(err("reloc section length is not a multiple of 16"));
        }
        for entry in bytes.as_chunks::<16>().0 {
            let r_offset = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
            let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            out.push(Reloc {
                rel_sect,
                target_sect,
                offset: r_offset,
                sym_idx: (r_info >> 32) as usize,
                typ: (r_info & 0xffff_ffff) as u32,
            });
        }
    }
    Ok(out)
}

/// Resolve one call reloc to a `.text` byte offset.
///
/// Mirrors the runtime loader (`reloc.rs`): the target is the symbol
/// value plus the call insn's own imm, where LLVM's unresolved `-1`
/// means a zero addend.
fn call_target(elf: &Elf, obj: &[u8], text_idx: usize, reloc: &Reloc) -> Result<usize, String> {
    let sym = elf.syms.get(reloc.sym_idx).ok_or_else(|| {
        err(format!(
            "call reloc references missing symbol {}",
            reloc.sym_idx
        ))
    })?;
    if sym.st_shndx != text_idx {
        return Err(err(format!(
            "call reloc target outside .text: '{}'",
            sym_name(elf, sym.st_name)
        )));
    }
    let (off, len) = section_file_range(elf, reloc.target_sect)?;
    if reloc.offset.checked_add(8).is_none_or(|end| end > len) {
        return Err(err(format!(
            "call reloc at {:#x} runs past its section",
            reloc.offset
        )));
    }
    let at = off + reloc.offset;
    if obj[at] != OP_CALL {
        return Err(err(format!(
            "call reloc at {:#x} is not a call",
            reloc.offset
        )));
    }
    let raw = i32::from_le_bytes(obj[at + 4..at + 8].try_into().unwrap());
    let dest = sym.st_value as i64 + if raw == -1 { 0 } else { i64::from(raw) };
    if dest < 0 {
        return Err(err(format!("call reloc target {dest} is negative")));
    }
    let dest = dest as usize;
    if !dest.is_multiple_of(8) || dest >= text_len(elf, text_idx) {
        return Err(err(format!("call reloc target {dest:#x} misaligned/short")));
    }
    Ok(dest)
}

/// Entry roots: call relocs in non-`.text` program sections.
fn entry_roots(
    elf: &Elf,
    obj: &[u8],
    text_idx: usize,
    relocs: &[Reloc],
) -> Result<Vec<usize>, String> {
    let mut roots = Vec::new();
    for reloc in relocs {
        if reloc.typ != R_BPF_64_32 || reloc.target_sect == text_idx {
            continue;
        }
        roots.push(call_target(elf, obj, text_idx, reloc)?);
    }
    if roots.is_empty() {
        return Err(err("no entry call into .text"));
    }
    Ok(roots)
}

fn func_at(funcs: &[Func], offset: usize) -> Option<usize> {
    funcs
        .iter()
        .position(|f| offset >= f.value && offset < f.value + f.size)
}

/// Functions reachable from the entry roots over call edges.
///
/// Liveness is keyed by symbol index so the rewrite can test it
/// without another lookup.
fn reachable(
    elf: &Elf,
    obj: &[u8],
    text_idx: usize,
    funcs: &[Func],
    relocs: &[Reloc],
    roots: &[usize],
) -> Result<Vec<bool>, String> {
    let mut live = vec![false; elf.syms.len()];
    let mut stack = Vec::new();
    for root in roots {
        let Some(pos) = func_at(funcs, *root) else {
            return Err(err(format!(
                "entry call targets {root:#x} (no function there)"
            )));
        };
        if funcs[pos].value != *root {
            return Err(err(format!(
                "entry call targets {root:#x} (inside '{}')",
                funcs[pos].name
            )));
        }
        stack.push(pos);
    }
    while let Some(pos) = stack.pop() {
        if live[funcs[pos].sym_idx] {
            continue;
        }
        live[funcs[pos].sym_idx] = true;
        for reloc in relocs {
            if reloc.typ != R_BPF_64_32 || reloc.target_sect != text_idx {
                continue;
            }
            if func_at(funcs, reloc.offset) != Some(pos) {
                continue;
            }
            let dest = call_target(elf, obj, text_idx, reloc)?;
            let Some(next) = func_at(funcs, dest) else {
                return Err(err(format!("call targets {dest:#x} (no function there)")));
            };
            if funcs[next].value != dest {
                return Err(err(format!(
                    "call targets {dest:#x} (inside '{}')",
                    funcs[next].name
                )));
            }
            stack.push(next);
        }
    }
    Ok(live)
}

/// Byte offset of a section header field.
fn shdr_field(shoff: usize, idx: usize, field: usize) -> usize {
    shoff + idx * 64 + field
}

fn write_u64(out: &mut [u8], at: usize, val: u64) -> Result<(), String> {
    out.get_mut(at..at + 8)
        .ok_or_else(|| err("section header outside file"))?
        .copy_from_slice(&val.to_le_bytes());
    Ok(())
}

fn write_u32(out: &mut [u8], at: usize, val: u32) -> Result<(), String> {
    out.get_mut(at..at + 4)
        .ok_or_else(|| err("section header outside file"))?
        .copy_from_slice(&val.to_le_bytes());
    Ok(())
}

/// New `.text` offset for an old one; `None` when the byte is dropped.
fn remap(kept: &[(usize, usize, usize)], old: usize) -> Option<usize> {
    for (start, end, new) in kept {
        if old >= *start && old < *end {
            return Some(new + (old - start));
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn rewrite(
    obj: &[u8],
    elf: &Elf,
    text_idx: usize,
    symtab_idx: usize,
    funcs: &[Func],
    relocs: &[Reloc],
    live: &[bool],
) -> Result<Vec<u8>, String> {
    // Kept ranges in address order; new offsets pack from zero.
    let mut kept: Vec<(usize, usize, usize)> = Vec::new();
    let mut cursor = 0;
    for func in funcs {
        if live[func.sym_idx] {
            kept.push((func.value, func.value + func.size, cursor));
            cursor += func.size;
        }
    }
    // Entry calls carry a raw byte addend against the `.text` section
    // symbol, so a shifted root would silently retarget: refuse loudly.
    // Intra-text calls resolve through function symbols, whose values
    // are rewritten below, and therefore survive any shift.
    for reloc in relocs {
        if reloc.typ != R_BPF_64_32 {
            continue;
        }
        let dest = call_target(elf, obj, text_idx, reloc)?;
        let Some(new) = remap(&kept, dest) else {
            let name = funcs
                .iter()
                .find(|f| dest >= f.value && dest < f.value + f.size);
            match name {
                Some(f) => return Err(err(format!("call to stripped function '{}'", f.name))),
                None => return Err(err(format!("call targets {dest:#x} (no function there)"))),
            }
        };
        if reloc.target_sect != text_idx && new != dest {
            return Err(err(format!(
                "entry call target {dest:#x} shifted to {new:#x}"
            )));
        }
    }
    let mut out = obj.to_vec();
    let shoff = elf.header.e_shoff as usize;
    // Compact `.text` in ascending order (ranges only move down) and
    // zero the slack so no stale bytes survive past the new end.
    let (text_off, text_old) = section_file_range(elf, text_idx)?;
    check_range(obj, text_off, text_old, ".text")?;
    for (start, end, new) in &kept {
        out.copy_within(text_off + start..text_off + end, text_off + new);
    }
    out[text_off + cursor..text_off + text_old].fill(0);
    write_u64(&mut out, shdr_field(shoff, text_idx, 32), cursor as u64)?;
    // Rewrite kept function values, then compact the symtab.
    let sym_sh = &elf.section_headers[symtab_idx];
    if sym_sh.sh_entsize != 24 {
        return Err(err("symtab entry size is not 24"));
    }
    let (sym_off, sym_len) = section_file_range(elf, symtab_idx)?;
    check_range(obj, sym_off, sym_len, "symtab")?;
    if !sym_len.is_multiple_of(24) {
        return Err(err("symtab length is not a multiple of 24"));
    }
    let sym_count = sym_len / 24;
    for func in funcs {
        if live[func.sym_idx] {
            let new = remap(&kept, func.value).expect("live function remaps");
            write_u64(&mut out, sym_off + func.sym_idx * 24 + 8, new as u64)?;
        }
    }
    let dead_sym: Vec<bool> = (0..sym_count)
        .map(|i| funcs.iter().any(|f| f.sym_idx == i && !live[f.sym_idx]))
        .collect();
    let mut map: Vec<Option<usize>> = vec![None; sym_count];
    let mut next = 0;
    for old in 0..sym_count {
        if !dead_sym[old] {
            if next != old {
                out.copy_within(
                    sym_off + old * 24..sym_off + old * 24 + 24,
                    sym_off + next * 24,
                );
            }
            map[old] = Some(next);
            next += 1;
        }
    }
    write_u64(
        &mut out,
        shdr_field(shoff, symtab_idx, 32),
        (next * 24) as u64,
    )?;
    let mut first_global = next;
    for (new, old) in map.iter().enumerate() {
        let Some(old) = old else { continue };
        let sym = elf
            .syms
            .get(*old)
            .ok_or_else(|| err("symtab index out of range"))?;
        if goblin::elf::sym::st_bind(sym.st_info) != STB_LOCAL {
            first_global = new;
            break;
        }
    }
    write_u32(
        &mut out,
        shdr_field(shoff, symtab_idx, 44),
        first_global as u32,
    )?;
    // Decide every reloc entry: kept (with new symbol + offset) or
    // dropped with its dead function. A call from live code into
    // dropped code is a hard error; the loader would resolve it
    // through the rewritten (missing) symbol.
    struct Kept {
        rel_sect: usize,
        offset: usize,
        sym: usize,
        typ: u32,
    }
    let mut kept_entries: Vec<Kept> = Vec::with_capacity(relocs.len());
    for reloc in relocs {
        let rel_sh = &elf.section_headers[reloc.rel_sect];
        if rel_sh.sh_entsize != 16 {
            return Err(err("reloc entry size is not 16"));
        }
        let mut drop = false;
        let mut offset = reloc.offset;
        if reloc.target_sect == text_idx {
            match remap(&kept, offset) {
                Some(new) => {
                    if reloc.typ != R_BPF_64_32 {
                        // Map fixups patch an 8-byte `ld_imm64` pair:
                        // both halves must survive inside kept code.
                        let end_ok = remap(&kept, offset + 8) == Some(new + 8);
                        if !end_ok {
                            return Err(err(format!(
                                "reloc pair straddles stripped code at {offset:#x}"
                            )));
                        }
                    }
                    offset = new;
                }
                None => {
                    if reloc.typ == R_BPF_64_32 && caller_is_live(funcs, live, offset) {
                        return Err(err(format!("call to stripped code at {offset:#x}")));
                    }
                    drop = true;
                }
            }
        }
        if drop {
            continue;
        }
        let new_sym = map.get(reloc.sym_idx).copied().flatten().ok_or_else(|| {
            let name = elf
                .syms
                .get(reloc.sym_idx)
                .map(|s| sym_name(elf, s.st_name))
                .unwrap_or_else(|| "?".to_owned());
            err(format!("reloc references removed symbol '{name}'"))
        })?;
        kept_entries.push(Kept {
            rel_sect: reloc.rel_sect,
            offset,
            sym: new_sym,
            typ: reloc.typ,
        });
    }
    // Compact each reloc section in place and shrink it.
    let mut sections: Vec<usize> = kept_entries.iter().map(|k| k.rel_sect).collect();
    sections.sort_unstable();
    sections.dedup();
    for rel_sect in sections {
        let (rel_off, _) = section_file_range(elf, rel_sect)?;
        check_range(
            obj,
            rel_off,
            reloc_section_len(elf, rel_sect),
            "reloc section",
        )?;
        let mut at = rel_off;
        for kept in kept_entries.iter().filter(|k| k.rel_sect == rel_sect) {
            let r_info = ((kept.sym as u64) << 32) | u64::from(kept.typ);
            write_u64(&mut out, at, kept.offset as u64)?;
            write_u64(&mut out, at + 8, r_info)?;
            at += 16;
        }
        let kept_count = kept_entries
            .iter()
            .filter(|k| k.rel_sect == rel_sect)
            .count();
        write_u64(
            &mut out,
            shdr_field(shoff, rel_sect, 32),
            (kept_count * 16) as u64,
        )?;
    }
    // Sections that lost every entry are absent from `sections`: find
    // them and zero their size.
    for reloc in relocs {
        if !kept_entries.iter().any(|k| k.rel_sect == reloc.rel_sect) {
            write_u64(&mut out, shdr_field(shoff, reloc.rel_sect, 32), 0)?;
        }
    }
    Ok(out)
}

/// True when the `.text` offset sits inside a live function.
fn caller_is_live(funcs: &[Func], live: &[bool], offset: usize) -> bool {
    funcs
        .iter()
        .any(|f| offset >= f.value && offset < f.value + f.size && live[f.sym_idx])
}

fn reloc_section_len(elf: &Elf, idx: usize) -> usize {
    elf.section_headers[idx].sh_size as usize
}

fn check_range(obj: &[u8], off: usize, len: usize, what: &str) -> Result<(), String> {
    if off.checked_add(len).is_none_or(|end| end > obj.len()) {
        return Err(err(format!("{what} outside file")));
    }
    Ok(())
}

fn text_len_of(bytes: &[u8]) -> Result<usize, String> {
    let elf = Elf::parse(bytes).map_err(|e| err(format!("re-parse: {e}")))?;
    Ok(text_len(&elf, find_text(&elf)?))
}

/// Structural re-check of the rewritten object.
fn verify(out: &[u8], report: &StripReport) -> Result<(), String> {
    let elf = Elf::parse(out).map_err(|e| err(format!("verify parse: {e}")))?;
    let text_idx = find_text(&elf)?;
    if text_len(&elf, text_idx) != report.text_after {
        return Err(err("verify: .text length mismatch"));
    }
    for sym in elf.syms.iter() {
        if goblin::elf::sym::st_type(sym.st_info) != STT_FUNC {
            continue;
        }
        let name = sym_name(&elf, sym.st_name);
        if report.removed.iter().any(|r| r == &name) {
            return Err(err(format!("verify: '{name}' was not removed")));
        }
    }
    let relocs = collect_relocs(&elf, out)?;
    for reloc in &relocs {
        if reloc.sym_idx >= elf.syms.len() {
            return Err(err("verify: reloc symbol out of range"));
        }
        let (_, len) = section_file_range(&elf, reloc.target_sect)?;
        if reloc.offset >= len {
            return Err(err("verify: reloc offset out of range"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXIT: [u8; 8] = [0x95, 0, 0, 0, 0, 0, 0, 0];
    const LIVE_EXIT: [u8; 16] = [0x95, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    const LIVE_CALL: [u8; 16] = [
        0x85, 0x10, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x95, 0, 0, 0, 0, 0, 0, 0,
    ];

    /// Section bytes plus header fields (type, flags, link, info, align, entsize).
    type Blob<'a> = (&'a [u8], u32, u64, u32, u32, u64, u64);
    /// Section header row (name, type, flags, addr, off, size, link, info, align, entsize).
    type Shdr = (u32, u32, u64, u64, u64, u64, u32, u32, u64, u64);
    /// Parsed reloc row (offset, sym, type, target section).
    type RelocRow = (u64, usize, u32, usize);

    /// Minimal relocatable BPF object: `.text` (16-byte live + 8-byte
    /// dead funcs), one entry stub, symtab, and reloc sections.
    fn fixture(
        live_bytes: [u8; 16],
        live_value: u64,
        dead_value: u64,
        main_imm: i32,
        rel_text: &[(u64, u64, u32)],
    ) -> Vec<u8> {
        let mut text = vec![0u8; 24];
        text[live_value as usize..live_value as usize + 16].copy_from_slice(&live_bytes);
        text[dead_value as usize..dead_value as usize + 8].copy_from_slice(&EXIT);
        let mut main = vec![0x85u8, 0x10, 0, 0];
        main.extend_from_slice(&main_imm.to_le_bytes());
        let mut rel_uprobe = Vec::new();
        rel_uprobe.extend_from_slice(&0u64.to_le_bytes());
        rel_uprobe.extend_from_slice(&((2u64 << 32) | u64::from(R_BPF_64_32)).to_le_bytes());
        // symtab: null, dead, .text-section, live, entry.
        let strtab = b"\0dead\0.text\0live\0entry\0";
        let mut symtab = Vec::new();
        let sym = |name: u32, info: u8, shndx: u16, value: u64, size: u64| {
            let mut e = Vec::new();
            e.extend_from_slice(&name.to_le_bytes());
            e.push(info);
            e.push(0);
            e.extend_from_slice(&shndx.to_le_bytes());
            e.extend_from_slice(&value.to_le_bytes());
            e.extend_from_slice(&size.to_le_bytes());
            e
        };
        symtab.extend_from_slice(&sym(0, 0, 0, 0, 0));
        symtab.extend_from_slice(&sym(1, 0x02, 1, dead_value, 8));
        symtab.extend_from_slice(&sym(6, 0x03, 1, 0, 0));
        symtab.extend_from_slice(&sym(12, 0x02, 1, live_value, 16));
        symtab.extend_from_slice(&sym(17, 0x12, 2, 0, 8));
        let mut rel_text_bytes = Vec::new();
        for (off, sym_idx, typ) in rel_text {
            rel_text_bytes.extend_from_slice(&off.to_le_bytes());
            rel_text_bytes.extend_from_slice(&((sym_idx << 32) | u64::from(*typ)).to_le_bytes());
        }
        let shstrtab =
            b"\0.text\0uprobe.multi\0.rel.uprobe.multi\0symtab\0strtab\0shstrtab\0.rel.text\0";
        // Layout: ehdr, then section bytes, then section headers.
        let mut out = vec![0u8; 64];
        let mut blobs: Vec<Blob<'_>> = vec![
            (&text, 1, 6, 0, 0, 8, 0),            // 1 .text
            (&main, 1, 6, 0, 0, 8, 0),            // 2 uprobe.multi
            (&rel_uprobe, 9, 0, 4, 2, 8, 16),     // 3 .rel.uprobe.multi
            (&symtab, 2, 0, 5, 4, 8, 24),         // 4 symtab
            (strtab, 3, 0, 0, 0, 1, 0),           // 5 strtab
            (shstrtab, 3, 0, 0, 0, 1, 0),         // 6 shstrtab
            (&rel_text_bytes, 9, 0, 4, 1, 8, 16), // 7 .rel.text
        ];
        let names = [0u32, 1, 7, 20, 38, 45, 52, 61];
        let mut off = 64usize;
        let mut shdrs: Vec<Shdr> = vec![(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)];
        for (idx, (bytes, typ, flags, link, info, align, entsize)) in blobs.drain(..).enumerate() {
            let pad = (align as usize - off % align as usize) % align as usize;
            out.extend(std::iter::repeat_n(0, pad));
            off += pad;
            out.extend_from_slice(bytes);
            shdrs.push((
                names[idx + 1],
                typ,
                flags,
                0,
                off as u64,
                bytes.len() as u64,
                link,
                info,
                align,
                entsize,
            ));
            off += bytes.len();
        }
        let shoff = out.len();
        for (name, typ, flags, addr, offset, size, link, info, align, entsize) in &shdrs {
            out.extend_from_slice(&name.to_le_bytes());
            out.extend_from_slice(&typ.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&addr.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&link.to_le_bytes());
            out.extend_from_slice(&info.to_le_bytes());
            out.extend_from_slice(&align.to_le_bytes());
            out.extend_from_slice(&entsize.to_le_bytes());
        }
        // ELF header.
        out[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;
        out[16..18].copy_from_slice(&1u16.to_le_bytes());
        out[18..20].copy_from_slice(&EM_BPF.to_le_bytes());
        out[20..24].copy_from_slice(&1u32.to_le_bytes());
        out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        out[52..54].copy_from_slice(&64u16.to_le_bytes());
        out[58..60].copy_from_slice(&64u16.to_le_bytes());
        out[60..62].copy_from_slice(&(shdrs.len() as u16).to_le_bytes());
        out[62..64].copy_from_slice(&6u16.to_le_bytes());
        out
    }

    fn parse_names(bytes: &[u8]) -> (Vec<(String, u64)>, Vec<RelocRow>, usize) {
        let elf = Elf::parse(bytes).unwrap();
        let funcs: Vec<(String, u64)> = elf
            .syms
            .iter()
            .filter(|s| goblin::elf::sym::st_type(s.st_info) == STT_FUNC && s.st_name != 0)
            .map(|s| {
                (
                    elf.strtab.get_at(s.st_name).unwrap_or_default().to_owned(),
                    s.st_value,
                )
            })
            .collect();
        let mut relocs = Vec::new();
        for sh in elf.section_headers.iter() {
            if sh.sh_type != SHT_REL {
                continue;
            }
            let target = sh.sh_info as usize;
            let (off, len) = (sh.sh_offset as usize, sh.sh_size as usize);
            for entry in bytes[off..off + len].as_chunks::<16>().0 {
                let r_offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
                let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
                relocs.push((
                    r_offset,
                    (r_info >> 32) as usize,
                    (r_info & 0xffff_ffff) as u32,
                    target,
                ));
            }
        }
        let text_idx = elf
            .section_headers
            .iter()
            .position(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default() == ".text")
            .unwrap();
        (
            funcs,
            relocs,
            elf.section_headers[text_idx].sh_size as usize,
        )
    }

    #[test]
    fn strips_dead_function_and_remaps() {
        let obj = fixture(LIVE_EXIT, 0, 16, -1, &[(0, 4, 1)]);
        let (out, report) = strip_dead_text_funcs(&obj).unwrap();
        assert_eq!(report.removed, vec!["dead".to_owned()]);
        assert_eq!((report.text_before, report.text_after), (24, 16));
        let (funcs, relocs, text_len) = parse_names(&out);
        assert_eq!(text_len, 16);
        // Dead symbol gone; entry index shifted 4 -> 3.
        assert!(funcs.iter().all(|(n, _)| n != "dead"));
        assert!(funcs.contains(&("live".to_owned(), 0)));
        assert!(relocs.contains(&(0, 3, 1, 1)));
        // Entry call reloc: symbol 2 -> 1, target unchanged.
        assert!(relocs.contains(&(0, 1, R_BPF_64_32, 2)));
        // Idempotent: a second strip changes nothing.
        let (out2, report2) = strip_dead_text_funcs(&out).unwrap();
        assert!(report2.removed.is_empty());
        assert_eq!(out2, out);
    }

    #[test]
    fn call_marks_callee_live() {
        // `live` calls `dead`: nothing is stripped.
        let obj = fixture(LIVE_CALL, 0, 16, -1, &[(0, 1, R_BPF_64_32)]);
        let (out, report) = strip_dead_text_funcs(&obj).unwrap();
        assert!(report.removed.is_empty());
        assert_eq!(out, obj);
    }

    #[test]
    fn reloc_in_dead_code_is_dropped() {
        let obj = fixture(LIVE_EXIT, 0, 16, -1, &[(0, 4, 1), (16, 4, 1)]);
        let (out, report) = strip_dead_text_funcs(&obj).unwrap();
        assert_eq!(report.removed, vec!["dead".to_owned()]);
        let (_, relocs, _) = parse_names(&out);
        assert_eq!(relocs.iter().filter(|(_, _, _, t)| *t == 1).count(), 1);
    }

    #[test]
    fn entry_into_function_body_fails() {
        let obj = fixture(LIVE_EXIT, 0, 16, 8, &[]);
        let err = strip_dead_text_funcs(&obj).unwrap_err();
        assert!(err.contains("inside"), "unexpected: {err}");
    }

    #[test]
    fn overlapping_functions_fail() {
        let obj = fixture(LIVE_EXIT, 0, 8, -1, &[]);
        let err = strip_dead_text_funcs(&obj).unwrap_err();
        assert!(err.contains("tiling"), "unexpected: {err}");
    }

    #[test]
    fn shifted_entry_target_fails() {
        // Dead first, entry targets live@8: stripping would move it.
        let obj = fixture(LIVE_EXIT, 8, 0, 8, &[]);
        let err = strip_dead_text_funcs(&obj).unwrap_err();
        assert!(err.contains("shifted"), "unexpected: {err}");
    }

    /// Rewrite reloc entries of type `from` to `to` in one reloc
    /// section; returns the patched count.
    fn rewrite_reloc_types(obj: &mut [u8], sect: &str, from: u32, to: u32) -> usize {
        let sites: Vec<usize> = {
            let elf = Elf::parse(obj).unwrap();
            let mut sites = Vec::new();
            for sh in elf.section_headers.iter() {
                if sh.sh_type != SHT_REL {
                    continue;
                }
                if elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default() != sect {
                    continue;
                }
                let (off, len) = (sh.sh_offset as usize, sh.sh_size as usize);
                for e in 0..len / 16 {
                    let info_at = off + e * 16 + 8;
                    let info = u64::from_le_bytes(obj[info_at..info_at + 8].try_into().unwrap());
                    if (info & 0xffff_ffff) as u32 == from {
                        sites.push(info_at);
                    }
                }
            }
            sites
        };
        for at in &sites {
            let info = u64::from_le_bytes(obj[*at..*at + 8].try_into().unwrap());
            let patched = (info & !0xffff_ffff) | u64::from(to);
            obj[*at..*at + 8].copy_from_slice(&patched.to_le_bytes());
        }
        sites.len()
    }

    #[test]
    fn drop_retires_text_and_keeps_map_relocs() {
        let mut obj = fixture(LIVE_EXIT, 0, 16, -1, &[]);
        assert_eq!(
            rewrite_reloc_types(&mut obj, ".rel.uprobe.multi", R_BPF_64_32, 1),
            1
        );
        let (out, report) = drop_unreferenced_text(&obj).unwrap();
        assert_eq!(report.removed, vec![".text".to_owned()]);
        assert_eq!((report.text_before, report.text_after), (24, 0));
        // No `.text` by name anymore; the map reloc survives untouched.
        let elf = Elf::parse(&out).unwrap();
        assert!(
            elf.section_headers.iter().all(|sh| elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or_default()
                != ".text")
        );
        let relocs = collect_relocs(&elf, &out).unwrap();
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].typ, 1);
        // Idempotent: a second drop is a no-op.
        let (out2, report2) = drop_unreferenced_text(&out).unwrap();
        assert!(report2.removed.is_empty());
        assert_eq!(out2, out);
    }

    #[test]
    fn drop_refuses_call_relocs() {
        let obj = fixture(LIVE_EXIT, 0, 16, -1, &[]);
        let err = drop_unreferenced_text(&obj).unwrap_err();
        assert!(err.contains("call reloc"), "unexpected: {err}");
    }

    #[test]
    fn drop_refuses_relocs_against_text() {
        let mut obj = fixture(LIVE_EXIT, 0, 16, -1, &[(0, 4, 1)]);
        assert_eq!(
            rewrite_reloc_types(&mut obj, ".rel.uprobe.multi", R_BPF_64_32, 1),
            1
        );
        let err = drop_unreferenced_text(&obj).unwrap_err();
        assert!(err.contains(".text"), "unexpected: {err}");
    }

    #[test]
    fn drop_without_text_is_noop() {
        // Retire `.text` by hand (name + type cleared), then the drop
        // must no-op on the missing section.
        let mut obj = fixture(LIVE_EXIT, 0, 16, -1, &[]);
        let text_hdr: usize = {
            let elf = Elf::parse(&obj).unwrap();
            (elf.header.e_shoff as usize) + 64
        };
        obj[text_hdr..text_hdr + 8].fill(0);
        let (out, report) = drop_unreferenced_text(&obj).unwrap();
        assert!(report.removed.is_empty());
        assert_eq!(out, obj);
    }
}
