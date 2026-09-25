// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure ELF parse of the spine object: no syscalls (T7c1).
//!
//! [`parse_spine_object`] checks the license, extracts the five frozen map
//! defs, builds one insn stream per program (main section ++ `.text`), and
//! resolves call relocs. Map-fd fixups stay a plan
//! ([`MapReloc`]) applied at instantiate time, when fds exist.
//!
//! K1 adds [`parse_kcrypto_object`]: same machinery, fexit shape — the
//! section allowlist is the `fexit/` prefix (Task-1 fentry migrated per
//! ruling C1), 1..=16 programs, `.text` optional (stripped objects lack
//! it per R4), dims asserted against
//! [`KCRYPTO_MAPS`](crate::bpfloader::KCRYPTO_MAPS).

mod maps;
mod reach;
mod reloc;

use crate::bpfloader::{KCRYPTO_MAPS, LoaderError, ParsedMap, ParsedProg};
use crate::kcrypto_lifecycle::profile::{
    LifecycleProfile, manifest as profile_manifest, max_programs, section_allowed,
};
use goblin::elf::Elf;

/// 64-bit gate: the `u64 as usize` casts in this module (section
/// ranges in [`section_bytes`], `.text` symbol values below) and in
/// `reloc` (offsets/symbol indices, call-target bytes) are
/// lossless-by-construction only where `usize` holds every `u64`.
/// Unsupported 32-bit targets fail the build here, loudly, instead of
/// silently truncating attacker-controlled ELF fields.
const _: () = assert!(
    size_of::<usize>() >= size_of::<u64>(),
    "kryprobe-privilege requires a 64-bit target"
);

/// ELF machine id for eBPF.
const EM_BPF: u16 = 247;
/// `src_reg` nibble marking a map-fd `ld_imm64` (`BPF_PSEUDO_MAP_FD`).
const PSEUDO_MAP_FD: u8 = 1;

/// One decoded 8-byte BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    /// Opcode.
    pub code: u8,
    /// Packed dst (low nibble) / src (high nibble) registers.
    pub dst_src: u8,
    /// Signed jump/data offset.
    pub off: i16,
    /// Immediate constant.
    pub imm: i32,
}

impl BpfInsn {
    fn decode(bytes: &[u8]) -> Self {
        Self {
            code: bytes[0],
            dst_src: bytes[1],
            off: i16::from_le_bytes([bytes[2], bytes[3]]),
            imm: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    /// Encode back to 8 bytes (used after reloc fixups).
    pub fn encode(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.code;
        out[1] = self.dst_src;
        out[2..4].copy_from_slice(&self.off.to_le_bytes());
        out[4..8].copy_from_slice(&self.imm.to_le_bytes());
        out
    }
}

/// One planned map-fd fixup: `prog`'s `ld_imm64` at `insn_idx` takes `map`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapReloc {
    /// Program index the fixup applies to.
    pub prog: usize,
    /// Instruction index of the `ld_imm64`.
    pub insn_idx: usize,
    /// Map name whose fd the instruction takes.
    pub map: String,
}

/// Fully parsed object: dims, insn streams (calls resolved), fixup plan.
#[derive(Debug, Clone)]
pub struct ParsedSpine {
    /// Parsed maps.
    pub maps: Vec<ParsedMap>,
    /// Parsed programs.
    pub programs: Vec<ParsedProg>,
    /// Planned map-fd fixups.
    pub map_relocs: Vec<MapReloc>,
}

/// Fully parsed kcrypto object: dims, insn streams (calls resolved),
/// fixup plan (K1 Task 1; K0 G1 — `evidence/k0/VERDICT.md`).
#[derive(Debug, Clone)]
pub struct ParsedKcrypto {
    /// Parsed maps.
    pub maps: Vec<ParsedMap>,
    /// Parsed programs.
    pub programs: Vec<ParsedProg>,
    /// Planned map-fd fixups.
    pub map_relocs: Vec<MapReloc>,
}

/// Section-name allowlist for kcrypto objects: the section name must
/// start with `fexit/` (K1 Task 2, C1; the Task-1 `fentry/` shape is
/// rejected — K0 G1 re-proven for the exit edge).
#[must_use]
pub fn valid_kcrypto_section(name: &str) -> bool {
    name.starts_with("fexit/")
}

/// Dims gate for kcrypto objects: exactly [`KCRYPTO_MAPS`], no missing
/// and no extra maps (K1 Task 1; the Task-2 contract).
#[must_use]
pub fn valid_kcrypto_dims(maps: &[ParsedMap]) -> bool {
    maps.len() == KCRYPTO_MAPS.len()
        && KCRYPTO_MAPS.iter().all(|(want_name, want_dims)| {
            maps.iter()
                .any(|got| got.name == *want_name && got.dims == *want_dims)
        })
}

pub(crate) fn bad(reason: String) -> LoaderError {
    LoaderError::BadObject { reason }
}

pub(crate) fn section_bytes(bytes: &[u8], off: u64, len: u64) -> Result<&[u8], LoaderError> {
    // Lossless by the 64-bit gate above; the range check below still
    // bounds both against the actual file.
    let (off, len) = (off as usize, len as usize);
    let end = off
        .checked_add(len)
        .ok_or_else(|| bad("section range overflows".to_owned()))?;
    bytes
        .get(off..end)
        .ok_or_else(|| bad("section range outside file".to_owned()))
}

pub(crate) fn find_section(
    elf: &Elf,
    bytes: &[u8],
    name: &str,
) -> Result<(usize, Vec<u8>), LoaderError> {
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        let sec_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default();
        if sec_name == name {
            let content = section_bytes(bytes, sh.sh_offset, sh.sh_size)?.to_vec();
            return Ok((idx, content));
        }
    }
    Err(bad(format!("missing section '{name}'")))
}

fn decode_insns(bytes: &[u8], what: &str) -> Result<Vec<BpfInsn>, LoaderError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(bad(format!("{what} length is not a multiple of 8")));
    }
    let (chunks, _) = bytes.as_chunks::<8>();
    Ok(chunks.iter().map(|c| BpfInsn::decode(c)).collect())
}

/// Program main sections in load order: (section, symbol).
const PROGRAMS: [(&str, &str); 2] = [
    ("uprobe.multi", "spine_selftest"),
    ("uretprobe.multi", "spine_selftest_ret"),
];

/// Parse the object: license, dims, insn streams, reloc plan. No syscalls.
pub fn parse_spine_object(bytes: &[u8]) -> Result<ParsedSpine, LoaderError> {
    let elf = Elf::parse(bytes).map_err(|err| bad(format!("ELF parse: {err}")))?;
    if elf.header.e_machine != EM_BPF {
        return Err(bad(format!(
            "e_machine {} is not EM_BPF",
            elf.header.e_machine
        )));
    }
    let (_, license) = find_section(&elf, bytes, "license")?;
    if !license.starts_with(b"GPL") {
        return Err(bad("license section is not GPL".to_owned()));
    }
    let maps = maps::parse_maps(&elf, bytes)?;
    let (text_idx, text) = find_section(&elf, bytes, ".text")?;
    let text_insns = decode_insns(&text, ".text")?;
    // One stream per program: main section ++ .text, relocs applied below.
    let mut programs: Vec<ParsedProg> = Vec::with_capacity(PROGRAMS.len());
    let mut bases: Vec<(usize, usize)> = Vec::new();
    for (section, symbol) in PROGRAMS {
        let (sec_idx, main) = find_section(&elf, bytes, section)?;
        let mut insns = decode_insns(&main, section)?;
        let main_len = insns.len();
        insns.extend_from_slice(&text_insns);
        let mut named = false;
        for sym in elf.syms.iter() {
            if sym.st_shndx == sec_idx && elf.strtab.get_at(sym.st_name) == Some(symbol) {
                named = true;
            }
        }
        if !named {
            return Err(bad(format!("section '{section}' lacks symbol '{symbol}'")));
        }
        bases.push((sec_idx, main_len));
        programs.push(ParsedProg {
            name: symbol.to_owned(),
            section: section.to_owned(),
            insns,
        });
    }
    let mut map_relocs = Vec::new();
    reloc::apply_relocs(
        &elf,
        bytes,
        text_idx,
        &bases,
        &mut programs,
        &mut map_relocs,
    )?;
    let text_funcs = text_func_symbols(&elf, text_idx);
    for (prog, (_, main_len)) in programs.iter().zip(bases.iter()) {
        let funcs: Vec<(String, usize)> = text_funcs
            .iter()
            .map(|(name, off)| (name.clone(), main_len + off / 8))
            .collect();
        reach::check_reachable(&prog.name, &prog.insns, &funcs)?;
    }
    Ok(ParsedSpine {
        maps,
        programs,
        map_relocs,
    })
}

/// Maximum kcrypto programs in one object (1..=16 per the brief).
const KCRYPTO_PROG_MAX: usize = 16;

/// Parse a kcrypto object: license, KCRYPTO dims, one insn stream per
/// `fexit/*` section (main section ++ `.text` when present), relocs
/// applied, reachability gated. No syscalls.
///
/// `.text` is optional: R4-stripped fexit objects lack it
/// (`evidence/k0/P1-attach-matrix.txt` R4); when present it must decode
/// and every stream is gated exactly like the spine path. Program names
/// come from the first function symbol in each section; the attach id
/// lookup keys on the section suffix after `fexit/` (see `load_kcrypto`).
pub fn parse_kcrypto_object(bytes: &[u8]) -> Result<ParsedKcrypto, LoaderError> {
    let elf = Elf::parse(bytes).map_err(|err| bad(format!("ELF parse: {err}")))?;
    if elf.header.e_machine != EM_BPF {
        return Err(bad(format!(
            "e_machine {} is not EM_BPF",
            elf.header.e_machine
        )));
    }
    let (_, license) = find_section(&elf, bytes, "license")?;
    if !license.starts_with(b"GPL") {
        return Err(bad("license section is not GPL".to_owned()));
    }
    // Section shape first: a non-fexit object (e.g. the spine) names
    // the allowlist instead of tripping the dims assert further down.
    let mut sections: Vec<(usize, String)> = Vec::new();
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        let sec_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default();
        if valid_kcrypto_section(sec_name) {
            sections.push((idx, sec_name.to_owned()));
        }
    }
    if sections.is_empty() || sections.len() > KCRYPTO_PROG_MAX {
        return Err(bad(format!(
            "want 1..=16 programs in `fexit/*` sections, found {}",
            sections.len()
        )));
    }
    let maps = maps::parse_kcrypto_maps(&elf, bytes)?;
    // Present `.text` must decode (errors propagate); absent is fine.
    let present = elf
        .section_headers
        .iter()
        .any(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default() == ".text");
    let (text_idx, text_insns) = if present {
        let (idx, text) = find_section(&elf, bytes, ".text")?;
        (Some(idx), decode_insns(&text, ".text")?)
    } else {
        (None, Vec::new())
    };
    let mut programs: Vec<ParsedProg> = Vec::with_capacity(sections.len());
    let mut bases: Vec<(usize, usize)> = Vec::new();
    for (sec_idx, sec_name) in &sections {
        let symbol = sec_name.strip_prefix("fexit/").unwrap_or_default();
        if symbol.is_empty() {
            return Err(bad(format!(
                "section '{sec_name}' has an empty target symbol"
            )));
        }
        let sh = &elf.section_headers[*sec_idx];
        let main = section_bytes(bytes, sh.sh_offset, sh.sh_size)?;
        let mut insns = decode_insns(main, sec_name)?;
        let main_len = insns.len();
        insns.extend_from_slice(&text_insns);
        let mut named: Option<(u64, String)> = None;
        for sym in elf.syms.iter() {
            if sym.st_shndx != *sec_idx
                || goblin::elf::sym::st_type(sym.st_info) != goblin::elf::sym::STT_FUNC
            {
                continue;
            }
            let candidate = (
                sym.st_value,
                elf.strtab
                    .get_at(sym.st_name)
                    .unwrap_or_default()
                    .to_owned(),
            );
            if named.as_ref().is_none_or(|best| candidate.0 < best.0) {
                named = Some(candidate);
            }
        }
        let Some((_, name)) = named else {
            return Err(bad(format!("section '{sec_name}' has no function symbol")));
        };
        bases.push((*sec_idx, main_len));
        programs.push(ParsedProg {
            name,
            section: sec_name.clone(),
            insns,
        });
    }
    let mut map_relocs = Vec::new();
    // Without `.text` no section can match the sentinel: call relocs
    // fail closed ("call reloc outside .text"), map relocs in the main
    // sections apply per stream.
    reloc::apply_relocs(
        &elf,
        bytes,
        text_idx.unwrap_or(usize::MAX),
        &bases,
        &mut programs,
        &mut map_relocs,
    )?;
    let text_funcs = text_idx
        .map(|idx| text_func_symbols(&elf, idx))
        .unwrap_or_default();
    for (prog, (_, main_len)) in programs.iter().zip(bases.iter()) {
        let funcs: Vec<(String, usize)> = text_funcs
            .iter()
            .map(|(name, off)| (name.clone(), main_len + off / 8))
            .collect();
        reach::check_reachable(&prog.name, &prog.insns, &funcs)?;
    }
    Ok(ParsedKcrypto {
        maps,
        programs,
        map_relocs,
    })
}

/// ELF section flag `SHF_EXECINSTR`: marks program sections. Only
/// sections carrying it are candidate programs; metadata sections
/// (symtab, strtabs, relocs) never trip the section allowlist.
const SHF_EXECINSTR: u64 = 0x4;
/// ELF section type `SHT_NULL`: non-content (bpf-linker emits an
/// unnamed `AX`-flagged NULL stub — `readelf` section [2] — which is
/// never a program despite the exec flag).
const SHT_NULL: u32 = 0;

/// Parse a request-lifecycle object (T06): license, lifecycle dims,
/// one insn stream per `fentry/*`+`fexit/*` section pair (main section
/// ++ `.text` when present), required-site gate, relocs applied,
/// reachability gated. No syscalls.
///
/// Unlike the api-returns path (per-point independence), a missing
/// REQUIRED site refuses the whole object: lifecycle startup needs
/// every edge to pair submit with result. The program limit derives
/// from the profile manifest, not the api-returns 16-cap. `.text`
/// stays optional (R4 strip rule, shared with the kcrypto path).
/// Program names come from the first function symbol in each section.
pub fn parse_lifecycle_object(bytes: &[u8]) -> Result<ParsedKcrypto, LoaderError> {
    let profile = LifecycleProfile::RequestLifecycle;
    let table = profile_manifest(profile);
    let elf = Elf::parse(bytes).map_err(|err| bad(format!("ELF parse: {err}")))?;
    if elf.header.e_machine != EM_BPF {
        return Err(bad(format!(
            "e_machine {} is not EM_BPF",
            elf.header.e_machine
        )));
    }
    let (_, license) = find_section(&elf, bytes, "license")?;
    if !license.starts_with(b"GPL") {
        return Err(bad("license section is not GPL".to_owned()));
    }
    // Section shape first: executable content sections outside the
    // profile allowlist name themselves instead of tripping later
    // gates. NULL-typed sections (the bpf-linker AX stub) and `.text`
    // (optional, handled below) never trip the allowlist.
    let mut sections: Vec<(usize, String)> = Vec::new();
    for (idx, sh) in elf.section_headers.iter().enumerate() {
        if sh.sh_type == SHT_NULL || sh.sh_flags & SHF_EXECINSTR == 0 {
            continue;
        }
        let sec_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default();
        if sec_name == ".text" {
            continue;
        }
        if !section_allowed(profile, sec_name) {
            return Err(bad(format!(
                "unsupported program section '{sec_name}' for profile '{}'",
                table.name
            )));
        }
        sections.push((idx, sec_name.to_owned()));
    }
    // Required-site gate: every manifest edge must have its section.
    for site in table.required {
        for (edge, want) in [("fentry", site.entry), ("fexit", site.exit)] {
            if !want {
                continue;
            }
            let section = format!("{edge}/{}", site.symbol);
            if !sections.iter().any(|(_, name)| name == &section) {
                return Err(bad(format!("missing required lifecycle site '{section}'")));
            }
        }
    }
    let limit = max_programs(&table);
    if sections.len() > limit {
        return Err(bad(format!(
            "want {} programs from {} manifest, found {}",
            limit,
            table.name,
            sections.len()
        )));
    }
    let maps = maps::parse_lifecycle_maps(&elf, bytes)?;
    // Present `.text` must decode (errors propagate); absent is fine.
    let present = elf
        .section_headers
        .iter()
        .any(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default() == ".text");
    let (text_idx, text_insns) = if present {
        let (idx, text) = find_section(&elf, bytes, ".text")?;
        (Some(idx), decode_insns(&text, ".text")?)
    } else {
        (None, Vec::new())
    };
    let mut programs: Vec<ParsedProg> = Vec::with_capacity(sections.len());
    let mut bases: Vec<(usize, usize)> = Vec::new();
    for (sec_idx, sec_name) in &sections {
        let symbol = sec_name
            .strip_prefix("fentry/")
            .or_else(|| sec_name.strip_prefix("fexit/"))
            .unwrap_or_default();
        if symbol.is_empty() {
            return Err(bad(format!(
                "section '{sec_name}' has an empty target symbol"
            )));
        }
        let sh = &elf.section_headers[*sec_idx];
        let main = section_bytes(bytes, sh.sh_offset, sh.sh_size)?;
        let mut insns = decode_insns(main, sec_name)?;
        let main_len = insns.len();
        insns.extend_from_slice(&text_insns);
        let mut named: Option<(u64, String)> = None;
        for sym in elf.syms.iter() {
            if sym.st_shndx != *sec_idx
                || goblin::elf::sym::st_type(sym.st_info) != goblin::elf::sym::STT_FUNC
            {
                continue;
            }
            let candidate = (
                sym.st_value,
                elf.strtab
                    .get_at(sym.st_name)
                    .unwrap_or_default()
                    .to_owned(),
            );
            if named.as_ref().is_none_or(|best| candidate.0 < best.0) {
                named = Some(candidate);
            }
        }
        let Some((_, name)) = named else {
            return Err(bad(format!("section '{sec_name}' has no function symbol")));
        };
        bases.push((*sec_idx, main_len));
        programs.push(ParsedProg {
            name,
            section: sec_name.clone(),
            insns,
        });
    }
    let mut map_relocs = Vec::new();
    // Without `.text` no section can match the sentinel: call relocs
    // fail closed ("call reloc outside .text"), map relocs in the main
    // sections apply per stream.
    reloc::apply_relocs(
        &elf,
        bytes,
        text_idx.unwrap_or(usize::MAX),
        &bases,
        &mut programs,
        &mut map_relocs,
    )?;
    let text_funcs = text_idx
        .map(|idx| text_func_symbols(&elf, idx))
        .unwrap_or_default();
    for (prog, (_, main_len)) in programs.iter().zip(bases.iter()) {
        let funcs: Vec<(String, usize)> = text_funcs
            .iter()
            .map(|(name, off)| (name.clone(), main_len + off / 8))
            .collect();
        reach::check_reachable(&prog.name, &prog.insns, &funcs)?;
    }
    Ok(ParsedKcrypto {
        maps,
        programs,
        map_relocs,
    })
}

/// `.text` function symbols (name, byte offset) for reachability reports.
fn text_func_symbols(elf: &goblin::elf::Elf, text_idx: usize) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for sym in elf.syms.iter() {
        if sym.st_shndx != text_idx
            || goblin::elf::sym::st_type(sym.st_info) != goblin::elf::sym::STT_FUNC
        {
            continue;
        }
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .unwrap_or_default()
            .to_owned();
        // Lossless by the 64-bit gate above.
        out.push((name, sym.st_value as usize));
    }
    out.sort_by_key(|(_, off)| *off);
    out
}

/// Flatten one program stream back to bytes for `BPF_PROG_LOAD`.
pub fn insns_to_bytes(insns: &[BpfInsn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 8);
    for insn in insns {
        out.extend_from_slice(&insn.encode());
    }
    out
}

/// `BPF_PSEUDO_MAP_FD` marker for instantiate-time fixups.
pub const fn pseudo_map_fd() -> u8 {
    PSEUDO_MAP_FD
}

#[cfg(test)]
mod tests {
    // K1 Task 1 Step 1 (RED): kcrypto allowlist/dims validators as pure
    // functions. Full-object parse tests land once the kcrypto object
    // exists (Step 4 skeleton); the spine-shape discrimination test for
    // `parse_kcrypto_object` rides with them.

    #[test]
    fn kcrypto_section_allowlist_is_fexit_prefix() {
        use super::valid_kcrypto_section;
        assert!(valid_kcrypto_section("fexit/crypto_alloc_tfm_node"));
        assert!(valid_kcrypto_section("fexit/x"));
        assert!(!valid_kcrypto_section("uprobe.multi"));
        assert!(!valid_kcrypto_section("uretprobe.multi"));
        assert!(!valid_kcrypto_section("fexit"));
        assert!(!valid_kcrypto_section(""));
        assert!(!valid_kcrypto_section("maps"));
        assert!(!valid_kcrypto_section(".text"));
        // The Task-1 fentry shape no longer parses (C1 migration).
        assert!(!valid_kcrypto_section("fentry/crypto_alloc_tfm_node"));
        assert!(!valid_kcrypto_section("fentry/x"));
    }

    #[test]
    fn kcrypto_dims_pin_task2_contract() {
        use super::valid_kcrypto_dims;
        use crate::bpfloader::{KCRYPTO_MAPS, MapDims, ParsedMap};
        let good: Vec<ParsedMap> = KCRYPTO_MAPS
            .iter()
            .map(|(name, dims)| ParsedMap {
                name: (*name).to_owned(),
                dims: *dims,
            })
            .collect();
        // 5 K1 maps + 4 K5 attribution maps + KDROPS (fix wave).
        assert_eq!(good.len(), 10);
        assert!(valid_kcrypto_dims(&good));
        // Spine shape is NOT kcrypto shape (discrimination).
        let spineish = vec![ParsedMap {
            name: "CONFIG".to_owned(),
            dims: MapDims {
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 2,
            },
        }];
        assert!(!valid_kcrypto_dims(&spineish));
        // Right names, wrong dims.
        let mut wrong = good.clone();
        wrong[0].dims.max_entries += 1;
        assert!(!valid_kcrypto_dims(&wrong));
        // Missing map / extra map.
        assert!(!valid_kcrypto_dims(&good[..8]));
        let mut extra = good.clone();
        extra.push(ParsedMap {
            name: "ZZZ".to_owned(),
            dims: extra[0].dims,
        });
        assert!(!valid_kcrypto_dims(&extra));
    }

    #[test]
    fn usize_holds_every_u64() {
        // The property the 64-bit gate above pins at compile time:
        // every `u64 as usize` cast in this module and `reloc` is exact.
        // (The gate itself refuses 32-bit builds; this test pins the
        // intent on the host target.)
        assert!(size_of::<usize>() >= size_of::<u64>());
        assert_eq!(u64::MAX as usize as u64, u64::MAX);
    }
}
