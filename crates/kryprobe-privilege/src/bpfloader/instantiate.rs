// SPDX-License-Identifier: GPL-3.0-or-later
//! Syscall half of the raw loader: maps, fixups, program loads (T7c1).

use super::parse::{BpfInsn, insns_to_bytes, pseudo_map_fd};
use crate::bpfloader::{LoadedSpine, LoaderError, ParsedSpine, SpineMaps, SpineProgs};
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{
    BPF_MAP_CREATE, BPF_PROG_LOAD, BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, MapAttr, bpf,
    fd_or_errno,
};
use std::os::raw::c_void;

/// Verifier log verbosity (2 = verbose) and 1 MiB capture buffer.
const LOG_LEVEL: u32 = 2;
const LOG_CAP: usize = 1 << 20;
/// Bytes of verifier-log tail kept on load failure.
const LOG_TAIL: usize = 2048;

/// `BPF_PROG_LOAD` attr through `expected_attach_type` (72 bytes, UAPI order).
#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

static LICENSE: &[u8; 4] = b"GPL\0";

/// Create maps, apply map-fd fixups, load both programs. No BTF fd.
pub fn instantiate(parsed: &ParsedSpine) -> Result<LoadedSpine, LoaderError> {
    let mut fds: Vec<(String, OwnedFd)> = Vec::with_capacity(parsed.maps.len());
    for map in &parsed.maps {
        let mut attr = MapAttr {
            map_type: map.dims.map_type,
            key_size: map.dims.key_size,
            value_size: map.dims.value_size,
            max_entries: map.dims.max_entries,
        };
        // SAFETY: `attr` is a live stack struct; size matches its type.
        let ret = unsafe {
            bpf(
                BPF_MAP_CREATE,
                (&raw mut attr).cast::<c_void>(),
                size_of::<MapAttr>() as u32,
            )
        };
        match fd_or_errno(ret) {
            Ok(fd) => fds.push((map.name.clone(), fd)),
            Err(errno) => {
                return Err(LoaderError::MapFailed {
                    stage: map.name.clone(),
                    errno,
                });
            }
        }
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
        progs.push(load_program(&prog.name, insns)?);
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

fn prog_name16(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn load_program(name: &str, insns: &[BpfInsn]) -> Result<OwnedFd, LoaderError> {
    if insns.is_empty() {
        return Err(LoaderError::BadObject {
            reason: format!("program '{name}' has no insns"),
        });
    }
    let bytes = insns_to_bytes(insns);
    let mut log = vec![0u8; LOG_CAP];
    let mut attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_KPROBE,
        insn_cnt: insns.len() as u32,
        insns: bytes.as_ptr() as u64,
        license: LICENSE.as_ptr() as u64,
        log_level: LOG_LEVEL,
        log_size: LOG_CAP as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name: prog_name16(name),
        prog_ifindex: 0,
        expected_attach_type: BPF_TRACE_UPROBE_MULTI,
    };
    // SAFETY: attr + pointees (insns, license, log) outlive the syscall.
    let ret = unsafe {
        bpf(
            BPF_PROG_LOAD,
            (&raw mut attr).cast::<c_void>(),
            size_of::<ProgLoadAttr>() as u32,
        )
    };
    match fd_or_errno(ret) {
        Ok(fd) => Ok(fd),
        Err(errno) => Err(LoaderError::LoadFailed {
            stage: name.to_owned(),
            errno,
            log: log_tail(&log),
        }),
    }
}

/// Verifier-log tail (up to the first NUL, last `LOG_TAIL` bytes).
fn log_tail(log: &[u8]) -> String {
    let end = log.iter().position(|b| *b == 0).unwrap_or(log.len());
    let text = String::from_utf8_lossy(&log[..end]);
    let text = text.trim();
    if text.len() > LOG_TAIL {
        text[text.len() - LOG_TAIL..].to_owned()
    } else {
        text.to_owned()
    }
}
