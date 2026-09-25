// SPDX-License-Identifier: GPL-3.0-or-later
//! Map-def extraction + frozen-dim asserts (T7c1 split).

use super::{bad, find_section};
use crate::bpfloader::{KCRYPTO_MAPS, LoaderError, MapDims, ParsedMap, SPINE_MAPS};
use crate::kcrypto_lifecycle::profile::LIFECYCLE_MAPS;
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

/// Shared symbol collector for the three table asserts below: one
/// legacy map def per named symbol in the `maps` section. A name
/// appearing TWICE refuses typed (`DuplicateMap`) — the frozen
/// tables name each map once, so a duplicate is a corrupt/aliased
/// object; silently taking the first would bless whichever def the
/// symbol order happened to surface.
fn collect_map_defs(elf: &Elf, bytes: &[u8]) -> Result<Vec<(String, MapDims)>, LoaderError> {
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
        if found.iter().any(|(seen, _)| seen == name) {
            return Err(LoaderError::DuplicateMap {
                name: name.to_owned(),
            });
        }
        let off = sym.st_value as usize;
        let def = maps_bytes
            .get(off..off.saturating_add(MAP_DEF_LEN))
            .filter(|d| d.len() == MAP_DEF_LEN)
            .ok_or_else(|| bad(format!("map '{name}' def outside maps section")))?;
        found.push((name.to_owned(), parse_map_def(def)?));
    }
    Ok(found)
}

pub(crate) fn parse_maps(elf: &Elf, bytes: &[u8]) -> Result<Vec<ParsedMap>, LoaderError> {
    let found = collect_map_defs(elf, bytes)?;
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

/// Kcrypto twin of [`parse_maps`]: same legacy `maps` decode, dims
/// asserted against [`KCRYPTO_MAPS`] instead of the spine names (K1
/// Task 1; K0 G1). Deliberately a second function, not a parameter: the
/// spine path stays byte-identical (both share only the symbol
/// collector + duplicate gate).
pub(crate) fn parse_kcrypto_maps(elf: &Elf, bytes: &[u8]) -> Result<Vec<ParsedMap>, LoaderError> {
    let found = collect_map_defs(elf, bytes)?;
    let mut out = Vec::with_capacity(KCRYPTO_MAPS.len());
    for (want_name, want_dims) in KCRYPTO_MAPS {
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
        if !KCRYPTO_MAPS.iter().any(|(want, _)| want == name) {
            return Err(LoaderError::UnsupportedMap { name: name.clone() });
        }
    }
    Ok(out)
}

/// Lifecycle twin of [`parse_kcrypto_maps`]: same legacy `maps`
/// decode, dims asserted against [`LIFECYCLE_MAPS`] (T06). Deliberately
/// a third function, not a parameter: both older paths stay
/// byte-identical (all three share only the symbol collector +
/// duplicate gate).
pub(crate) fn parse_lifecycle_maps(elf: &Elf, bytes: &[u8]) -> Result<Vec<ParsedMap>, LoaderError> {
    let found = collect_map_defs(elf, bytes)?;
    let mut out = Vec::with_capacity(LIFECYCLE_MAPS.len());
    for (want_name, want_dims) in LIFECYCLE_MAPS {
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
        if !LIFECYCLE_MAPS.iter().any(|(want, _)| want == name) {
            return Err(LoaderError::UnsupportedMap { name: name.clone() });
        }
    }
    Ok(out)
}
