// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw BPF spine loader: pure parse + syscall instantiate (T7c1).
//!
//! The load facet (`BpfLoadAuthority::load_program*` on
//! `LocalPrivilegedAuthority`) is the only entry: it asserts the frozen
//! [`SPINE_MAPS`] dims via [`parse_spine_object`], creates the maps,
//! applies relocations, and loads both programs with
//! `expected_attach_type = UPROBE_MULTI` and no BTF. Every fallible BPF
//! step reports stage + errno. The syscall half (`instantiate`,
//! `mapcreate`, `progload`) is crate-private.
//!
//! Micro-borrow: fail-closed raw loader incl. frozen dims + symbolic
//! map-fd fixups (osslscope loader-prepare pattern, reimplemented).

pub(crate) mod instantiate;
pub(crate) mod mapcreate;
pub mod parse;
pub(crate) mod progload;

pub use parse::{BpfInsn, MapReloc, ParsedSpine, insns_to_bytes, parse_spine_object};

use crate::fd::OwnedFd;
use kryprobe_core::ProgramId;

/// Frozen dims of one spine map (ground truth: the built object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapDims {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// Frozen spine maps, in creation order. Asserted against the object.
pub const SPINE_MAPS: &[(&str, MapDims)] = &[
    (
        "CONFIG",
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 2,
        },
    ),
    (
        "START",
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
        },
    ),
    (
        "COUNT",
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 64,
        },
    ),
    (
        "EVENTS",
        MapDims {
            map_type: 27,
            key_size: 0,
            value_size: 0,
            max_entries: 262_144,
        },
    ),
    (
        "LOSS",
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 3,
        },
    ),
];

/// One parsed map: name + dims as found in the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMap {
    pub name: String,
    pub dims: MapDims,
}

/// One parsed program: insn stream with calls resolved, map fds pending.
#[derive(Debug, Clone)]
pub struct ParsedProg {
    pub name: String,
    pub section: String,
    pub insns: Vec<BpfInsn>,
}

/// Raw loader failure: stage + detail, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderError {
    Io {
        stage: &'static str,
        detail: String,
    },
    BadObject {
        reason: String,
    },
    /// Program id refused by the load-facet allowlist: a forbidden
    /// program, NOT a corrupt object (X16). Callers map this to exit 3
    /// / `Denied`, never to a corruption bucket.
    NotAllowed {
        id: ProgramId,
    },
    DimMismatch {
        name: String,
    },
    UnsupportedMap {
        name: String,
    },
    MapFailed {
        stage: String,
        errno: i32,
    },
    LoadFailed {
        stage: String,
        errno: i32,
        log: String,
    },
    MisalignedRecord {
        addr: usize,
    },
}

impl std::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { stage, detail } => write!(f, "loader I/O at {stage}: {detail}"),
            Self::BadObject { reason } => write!(f, "bad spine object: {reason}"),
            Self::NotAllowed { id } => {
                write!(f, "program {id:?} not in approved allowlist")
            }
            Self::DimMismatch { name } => write!(f, "map '{name}' dims mismatch frozen SPINE_MAPS"),
            Self::UnsupportedMap { name } => write!(f, "object has unknown map '{name}'"),
            Self::MapFailed { stage, errno } => {
                write!(f, "map create failed at {stage}: errno {errno}")
            }
            Self::LoadFailed { stage, errno, log } => {
                write!(f, "prog load failed at {stage}: errno {errno}: {log}")
            }
            Self::MisalignedRecord { addr } => {
                write!(f, "record buffer {addr:#x} violates 8-alignment")
            }
        }
    }
}

impl std::error::Error for LoaderError {}

/// Loaded spine maps, one RAII fd per map.
pub struct SpineMaps {
    pub config: OwnedFd,
    pub start: OwnedFd,
    pub count: OwnedFd,
    pub events: OwnedFd,
    pub loss: OwnedFd,
}

/// Loaded spine programs: entry + return.
pub struct SpineProgs {
    pub entry: OwnedFd,
    pub ret: OwnedFd,
}

/// Fully loaded spine: maps + programs, all RAII-owned.
pub struct LoadedSpine {
    pub maps: SpineMaps,
    pub progs: SpineProgs,
}

/// 8-alignment precondition for record buffers (abi `split_header` rule).
pub fn check_record_align(bytes: &[u8]) -> Result<(), LoaderError> {
    let addr = bytes.as_ptr() as usize;
    if addr.is_multiple_of(8) {
        Ok(())
    } else {
        Err(LoaderError::MisalignedRecord { addr })
    }
}
