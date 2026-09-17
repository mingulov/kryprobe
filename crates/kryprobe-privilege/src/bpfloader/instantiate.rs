// SPDX-License-Identifier: GPL-3.0-or-later
//! Syscall half of the raw loader: maps, fixups, program loads (T7c1).

use super::mapcreate::map_create_raw;
use super::parse::{BpfInsn, insns_to_bytes, pseudo_map_fd};
use super::progload::prog_load_raw;
use crate::bpfloader::{LoadedSpine, LoaderError, ParsedSpine, SpineMaps, SpineProgs};
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::fd_or_errno;
use std::os::fd::RawFd;

/// 1 MiB verifier-log capture buffer.
const LOG_CAP: usize = 1 << 20;
/// Bytes of verifier-log tail kept on load failure.
const LOG_TAIL: usize = 2048;

/// Create maps, apply map-fd fixups, load both programs. No BTF fd.
pub fn instantiate(parsed: &ParsedSpine) -> Result<LoadedSpine, LoaderError> {
    instantiate_with_token(parsed, None)
}

/// [`instantiate`] with an optional BPF token fd instead of privilege.
/// `None` builds the short attrs; `Some` the token-extended attrs.
pub fn instantiate_with_token(
    parsed: &ParsedSpine,
    token: Option<RawFd>,
) -> Result<LoadedSpine, LoaderError> {
    let mut fds: Vec<(String, OwnedFd)> = Vec::with_capacity(parsed.maps.len());
    for map in &parsed.maps {
        let ret = map_create_raw(
            map.dims.map_type,
            map.dims.key_size,
            map.dims.value_size,
            map.dims.max_entries,
            token,
        );
        let fd = fd_or_errno(ret).map_err(|errno| LoaderError::MapFailed {
            stage: map.name.clone(),
            errno,
        })?;
        fds.push((map.name.clone(), fd));
    }
    let fd_of = |name: &str| -> Result<i32, LoaderError> {
        fds.iter()
            .find(|(n, _)| n == name)
            .map(|(_, fd)| fd.as_raw_fd())
            .ok_or_else(|| LoaderError::BadObject {
                reason: format!("reloc names unknown map '{name}'"),
            })
    };
    let mut streams: Vec<Vec<BpfInsn>> = parsed.programs.iter().map(|p| p.insns.clone()).collect();
    for reloc in &parsed.map_relocs {
        let fd = fd_of(&reloc.map)?;
        let insns = streams
            .get_mut(reloc.prog)
            .ok_or_else(|| LoaderError::BadObject {
                reason: format!("reloc names unknown program {}", reloc.prog),
            })?;
        let first = insns
            .get_mut(reloc.insn_idx)
            .ok_or_else(|| LoaderError::BadObject {
                reason: "map reloc index out of range".to_owned(),
            })?;
        if first.code != 0x18 {
            return Err(LoaderError::BadObject {
                reason: "map reloc is not an ld_imm64 pair".to_owned(),
            });
        }
        first.dst_src |= pseudo_map_fd() << 4;
        first.imm = fd;
        let second = insns
            .get_mut(reloc.insn_idx + 1)
            .ok_or_else(|| LoaderError::BadObject {
                reason: "map reloc pair truncated".to_owned(),
            })?;
        second.imm = 0;
    }
    if streams.len() != 2 {
        return Err(LoaderError::BadObject {
            reason: format!("want 2 programs, parsed {}", streams.len()),
        });
    }
    let mut progs = Vec::with_capacity(2);
    for (prog, insns) in parsed.programs.iter().zip(streams.iter()) {
        progs.push(load_program(&prog.name, insns, token)?);
    }
    let mut take = |name: &str| -> Result<OwnedFd, LoaderError> {
        let pos =
            fds.iter()
                .position(|(n, _)| n == name)
                .ok_or_else(|| LoaderError::BadObject {
                    reason: format!("missing map '{name}'"),
                })?;
        Ok(fds.remove(pos).1)
    };
    let mut progs = progs.into_iter();
    let entry = progs.next().ok_or_else(|| LoaderError::BadObject {
        reason: "missing entry program".to_owned(),
    })?;
    let ret = progs.next().ok_or_else(|| LoaderError::BadObject {
        reason: "missing return program".to_owned(),
    })?;
    Ok(LoadedSpine {
        maps: SpineMaps {
            config: take("CONFIG")?,
            start: take("START")?,
            count: take("COUNT")?,
            events: take("EVENTS")?,
            loss: take("LOSS")?,
        },
        progs: SpineProgs { entry, ret },
    })
}

fn load_program(
    name: &str,
    insns: &[BpfInsn],
    token: Option<RawFd>,
) -> Result<OwnedFd, LoaderError> {
    if insns.is_empty() {
        return Err(LoaderError::BadObject {
            reason: format!("program '{name}' has no insns"),
        });
    }
    let bytes = insns_to_bytes(insns);
    let mut log = vec![0u8; LOG_CAP];
    let ret = prog_load_raw(name, &bytes, insns.len() as u32, &mut log, token);
    match fd_or_errno(ret) {
        Ok(fd) => Ok(fd),
        Err(errno) => Err(LoaderError::LoadFailed {
            stage: name.to_owned(),
            errno,
            log: log_tail(&log),
        }),
    }
}

/// Verifier-log tail: bytes first (never panics on char boundaries).
fn log_tail(log: &[u8]) -> String {
    let end = log.iter().position(|b| *b == 0).unwrap_or(log.len());
    let bytes = &log[..end];
    let start = bytes.len().saturating_sub(LOG_TAIL);
    String::from_utf8_lossy(&bytes[start..]).trim().to_owned()
}
