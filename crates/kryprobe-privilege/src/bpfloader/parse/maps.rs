// SPDX-License-Identifier: GPL-3.0-or-later
//! Map-def extraction + frozen-dim asserts (T7c1 split).

use super::{bad, find_section};
use crate::bpfloader::{LoaderError, MapDims, ParsedMap, SPINE_MAPS};
use goblin::elf::Elf;

/// Legacy `bpf_map_def` size: 7 × u32.
const MAP_DEF_LEN: usize = 28;

/// Parse one 28-byte legacy map def into frozen dims.
fn parse_map_def(def: &[u8]) -> Result<MapDims, LoaderError> {
    if def.len() != MAP_DEF_LEN {
        return Err(bad(format!("map def length {}", def.len())));
    }
    let word = |i: usize| u32::from_le_bytes([def[i], def[i + 1], def[i + 2], def[i + 3]]);
    Ok(MapDims {
        map_type: word(0),
        key_size: word(4),
        value_size: word(8),
        max_entries: word(12),
    })
}

pub(crate) fn parse_maps(elf: &Elf, bytes: &[u8]) -> Result<Vec<ParsedMap>, LoaderError> {
    let (maps_idx, maps_bytes) = find_section(elf, bytes, "maps")?;
    let mut found: Vec<(String, MapDims)> = Vec::new();
    for sym in elf.syms.iter() {
        if sym.st_shndx != maps_idx || sym.st_name == 0 {
            continue;
        }
        let name = elf.strtab.get_at(sym.st_name).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let off = sym.st_value as usize;
        let def = maps_bytes
            .get(off..off.saturating_add(MAP_DEF_LEN))
            .filter(|d| d.len() == MAP_DEF_LEN)
            .ok_or_else(|| bad(format!("map '{name}' def outside maps section")))?;
        found.push((name.to_owned(), parse_map_def(def)?));
    }
    let mut out = Vec::with_capacity(SPINE_MAPS.len());
    for (want_name, want_dims) in SPINE_MAPS {
        match found.iter().find(|(name, _)| name == want_name) {
            Some((_, dims)) if dims == want_dims => out.push(ParsedMap {
                name: (*want_name).to_owned(),
                dims: *dims,
            }),
            Some(_) => {
                return Err(LoaderError::DimMismatch {
                    name: (*want_name).to_owned(),
                });
            }
            None => return Err(bad(format!("missing map '{want_name}'"))),
        }
    }
    for (name, _) in &found {
        if !SPINE_MAPS.iter().any(|(want, _)| want == name) {
            return Err(LoaderError::UnsupportedMap { name: name.clone() });
        }
    }
    Ok(out)
}
