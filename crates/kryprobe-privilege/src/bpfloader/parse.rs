// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure ELF parse of the spine object: no syscalls (T7c1).
//!
//! [`parse_spine_object`] checks the license, extracts the five frozen map
//! defs, builds one insn stream per program (main section ++ `.text`), and
//! resolves call relocs. Map-fd fixups stay a plan
//! ([`MapReloc`]) applied at instantiate time, when fds exist.

mod maps;
mod reloc;

use crate::bpfloader::{LoaderError, ParsedMap, ParsedProg};
use goblin::elf::Elf;

/// ELF machine id for eBPF.
const EM_BPF: u16 = 247;
/// `src_reg` nibble marking a map-fd `ld_imm64` (`BPF_PSEUDO_MAP_FD`).
const PSEUDO_MAP_FD: u8 = 1;

/// One decoded 8-byte BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_src: u8,
    pub off: i16,
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
    pub prog: usize,
    pub insn_idx: usize,
    pub map: String,
}

/// Fully parsed object: dims, insn streams (calls resolved), fixup plan.
#[derive(Debug, Clone)]
pub struct ParsedSpine {
    pub maps: Vec<ParsedMap>,
    pub programs: Vec<ParsedProg>,
    pub map_relocs: Vec<MapReloc>,
}

pub(crate) fn bad(reason: String) -> LoaderError {
    LoaderError::BadObject { reason }
}

pub(crate) fn section_bytes(bytes: &[u8], off: u64, len: u64) -> Result<&[u8], LoaderError> {
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
    Ok(ParsedSpine {
        maps,
        programs,
        map_relocs,
    })
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
