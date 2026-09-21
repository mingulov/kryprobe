// SPDX-License-Identifier: GPL-3.0-or-later
//! Syscall half of the raw loader: maps, fixups, program loads (T7c1).
//!
//! K1 adds [`load_kcrypto`] (fexit objects: [`ParsedKcrypto`](super::parse::ParsedKcrypto),
//! per-prog `attach_btf_id`, per-point outcomes) plus the dot-free pin
//! gate ([`check_pin_name`]) and [`pin_fd`] (R2/R3).

use super::mapcreate::map_create_raw;
use super::parse::{BpfInsn, insns_to_bytes, parse_kcrypto_object, pseudo_map_fd};
use super::progload::{prog_load_fexit_raw, prog_load_raw};
use crate::bpfloader::{
    KcryptoMaps, LoadedKcrypto, LoadedSpine, LoaderError, ParsedSpine, PointStatus, SpineMaps,
    SpineProgs,
};
use crate::fd::OwnedFd;
use crate::probe::bpf_sys::{BPF_OBJ_PIN, bpf, fd_or_errno, last_errno};
use core::ffi::{c_long, c_void};
use std::ffi::CString;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// 1 MiB verifier-log capture buffer.
const LOG_CAP: usize = 1 << 20;
/// Bytes of verifier-log tail kept on load failure.
const LOG_TAIL: usize = 2048;

/// Create maps, apply map-fd fixups, load both programs. No BTF fd.
///
/// Crate-private: the only external entries are the load facet
/// (`BpfLoadAuthority::load_program*` on `LocalPrivilegedAuthority`).
pub(crate) fn instantiate(parsed: &ParsedSpine) -> Result<LoadedSpine, LoaderError> {
    instantiate_with_token(parsed, None)
}

/// [`instantiate`] with an optional BPF token fd instead of privilege.
/// `None` builds the short attrs; `Some` the token-extended attrs.
///
/// Crate-private: fronted by `BpfLoadAuthority::load_program_with_token`.
pub(crate) fn instantiate_with_token(
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

/// Load a kcrypto object through the real loader: parse, create the
/// five frozen maps, apply map-fd fixups, load each `fexit/` program
/// with its `attach_btf_id` (R1 — `evidence/k0/P1-attach-matrix.txt`).
///
/// `attach_ids` maps kernel symbol names (the section suffix after
/// `fexit/`, as returned by `btf_resolve::resolve_btf_ids`) to vmlinux
/// BTF ids. `token_fd` is an optional borrowed BPF token fd (`None`
/// loads with privilege, like the spine path; `Some` threads the token
/// to map create + prog load — link create carries no token field and
/// authorizes via the token-loaded program).
///
/// Per-point outcomes (attach independence): a program without a
/// supplied id is [`PointStatus::Missing`], a refused load is
/// [`PointStatus::Unsupported`], and the load succeeds iff at least one
/// program loads. Structural failures (bad object, map creation,
/// fixups) fail the whole load; so does a load where nothing loads
/// (the first error is preserved, or `BadObject` when every point is
/// `Missing`).
///
/// Shape-authenticated entry (no `ProgramId` allowlist): the `fexit/`
/// sections + frozen [`KCRYPTO_MAPS`](crate::bpfloader::KCRYPTO_MAPS)
/// dims fully determine the loaded behavior, so there is no trusted-id
/// claim to spoof; the syscalls still need privilege or a token.
pub fn load_kcrypto(
    bytes: &[u8],
    attach_ids: &[(String, u32)],
    token_fd: Option<RawFd>,
) -> Result<(LoadedKcrypto, Vec<PointStatus>), LoaderError> {
    let parsed = parse_kcrypto_object(bytes)?;
    let mut fds: Vec<(String, OwnedFd)> = Vec::with_capacity(parsed.maps.len());
    for map in &parsed.maps {
        let ret = map_create_raw(
            map.dims.map_type,
            map.dims.key_size,
            map.dims.value_size,
            map.dims.max_entries,
            token_fd,
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
    let mut progs: Vec<(String, OwnedFd)> = Vec::with_capacity(parsed.programs.len());
    let mut statuses: Vec<PointStatus> = Vec::with_capacity(parsed.programs.len());
    let mut first_err: Option<LoaderError> = None;
    for (prog, insns) in parsed.programs.iter().zip(streams.iter()) {
        let symbol = prog.section.strip_prefix("fexit/").unwrap_or_default();
        let Some((_, id)) = attach_ids.iter().find(|(name, _)| name == symbol) else {
            statuses.push(PointStatus::Missing {
                name: prog.name.clone(),
            });
            continue;
        };
        match load_fexit_program(&prog.name, insns, *id, token_fd) {
            Ok(fd) => {
                statuses.push(PointStatus::Loaded {
                    name: prog.name.clone(),
                });
                progs.push((prog.name.clone(), fd));
            }
            Err(err) => {
                statuses.push(PointStatus::Unsupported {
                    name: prog.name.clone(),
                    detail: short_detail(&err),
                });
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
    }
    if progs.is_empty() {
        return Err(first_err.unwrap_or_else(|| LoaderError::BadObject {
            reason: format!(
                "no attach_btf_id supplied for any of {} programs",
                parsed.programs.len()
            ),
        }));
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
    Ok((
        LoadedKcrypto {
            maps: KcryptoMaps {
                config: take("KCFG")?,
                agg: take("KAGG")?,
                total: take("KTOT")?,
                ident: take("KIDN")?,
                ring: take("KRING")?,
                who: take("KWHO")?,
                stack: take("KSTACK")?,
                err: take("KERR")?,
                params: take("KPARAMS")?,
                drops: take("KDROPS")?,
            },
            progs,
        },
        statuses,
    ))
}

/// Short per-point failure reason: errno only for load refuses (the
/// full verifier tail stays in the preserved [`LoaderError`]).
fn short_detail(err: &LoaderError) -> String {
    match err {
        LoaderError::LoadFailed { errno, .. } => {
            format!("prog load refused: errno {errno}")
        }
        other => other.to_string(),
    }
}

fn load_fexit_program(
    name: &str,
    insns: &[BpfInsn],
    attach_btf_id: u32,
    token_fd: Option<RawFd>,
) -> Result<OwnedFd, LoaderError> {
    if insns.is_empty() {
        return Err(LoaderError::BadObject {
            reason: format!("program '{name}' has no insns"),
        });
    }
    let bytes = insns_to_bytes(insns);
    let mut log = vec![0u8; LOG_CAP];
    let ret = prog_load_fexit_raw(
        name,
        &bytes,
        insns.len() as u32,
        attach_btf_id,
        &mut log,
        token_fd,
    );
    match fd_or_errno(ret) {
        Ok(fd) => Ok(fd),
        Err(errno) => Err(LoaderError::LoadFailed {
            stage: name.to_owned(),
            errno,
            log: log_tail(&log),
        }),
    }
}

/// Pin-name gate (R3 — `evidence/k0/P1-attach-matrix.txt`): bpffs
/// refuses dotted names, so the loader rejects them typed, before any
/// syscall. Empty names, `/`, and NUL fail here too (fail-closed path
/// hygiene, same [`LoaderError::BadPinName`] variant).
pub fn check_pin_name(name: &str) -> Result<(), LoaderError> {
    if name.is_empty() || name.contains('.') || name.contains('/') || name.contains('\0') {
        return Err(LoaderError::BadPinName {
            name: name.to_owned(),
        });
    }
    Ok(())
}

/// `BPF_OBJ_PIN` attr (20 bytes of UAPI payload, R2): `repr(C)` pads to
/// 24, so the kernel length is explicit ([`PIN_ATTR_LEN`]).
#[repr(C)]
struct PinAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: i32,
}

/// Bytes handed to the kernel for pin: exactly 20 (R2 — 16 → EPERM,
/// 24 → EINVAL on the K0 host).
const PIN_ATTR_LEN: u32 = 20;

const _: () = assert!(size_of::<PinAttr>() == 24);

/// Raw `BPF_OBJ_PIN`; returns 0 or -1 (see `last_errno`).
///
/// Crate-private: reached only via [`pin_fd`].
pub(crate) fn obj_pin_raw(fd: RawFd, path: &CString) -> c_long {
    // SAFETY: `attr` is a live stack struct; `path` outlives the syscall.
    unsafe {
        let mut attr = PinAttr {
            pathname: path.as_ptr() as u64,
            bpf_fd: fd as u32,
            file_flags: 0,
            path_fd: 0,
        };
        bpf(BPF_OBJ_PIN, (&raw mut attr).cast::<c_void>(), PIN_ATTR_LEN)
    }
}

/// Pin `fd` at `dir/name` after the [`check_pin_name`] gate (R2/R3).
/// The caller owns cleanup (unlink); pins are outside RAII by design.
pub fn pin_fd(fd: &OwnedFd, dir: &Path, name: &str) -> Result<(), LoaderError> {
    check_pin_name(name)?;
    let full = dir.join(name);
    let path = CString::new(full.as_os_str().as_bytes()).map_err(|_| LoaderError::Io {
        stage: "obj_pin",
        detail: "pin path is not NUL-safe".to_owned(),
    })?;
    let ret = obj_pin_raw(fd.as_raw_fd(), &path);
    if ret < 0 {
        return Err(LoaderError::Io {
            stage: "obj_pin",
            detail: format!("{}: errno {}", full.display(), last_errno()),
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::check_pin_name;
    use crate::bpfloader::LoaderError;

    #[test]
    fn pin_gate_rejects_dotted_names_typed() {
        // R3: bpffs refuses dotted names (EPERM); the loader rejects
        // them typed before any syscall (unprivileged).
        for name in ["kcrypto.prog", "a.b.c", ".", "KCFG.0"] {
            assert!(
                matches!(check_pin_name(name), Err(LoaderError::BadPinName { .. })),
                "{name} must be BadPinName"
            );
        }
    }

    #[test]
    fn pin_gate_rejects_empty_slash_nul() {
        for name in ["", "a/b", "a\0b", "/abs"] {
            assert!(
                matches!(check_pin_name(name), Err(LoaderError::BadPinName { .. })),
                "{name:?} must be BadPinName"
            );
        }
    }

    #[test]
    fn pin_gate_accepts_kcrypto_names() {
        for name in ["KCFG", "KAGG", "KTOT", "KIDN", "KRING", "kcrypto-link-0"] {
            assert!(check_pin_name(name).is_ok(), "{name} must pass");
        }
    }
}
