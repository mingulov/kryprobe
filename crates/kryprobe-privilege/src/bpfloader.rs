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
//!
//! K1 adds a second, independent load path for fexit/kcrypto objects
//! ([`parse_kcrypto_object`], [`load_kcrypto`]): `fexit/*` sections,
//! 1..=16 programs, optional `.text`, the frozen [`KCRYPTO_MAPS`] dims,
//! `TRACING`/`FEXIT` loads with per-prog `attach_btf_id` (R1), and a
//! dot-free pin gate (R3). The spine path above is byte-identical.

pub(crate) mod instantiate;
pub(crate) mod mapcreate;
pub mod parse;
pub(crate) mod progload;

pub use instantiate::{check_pin_name, load_kcrypto, pin_fd};
pub use parse::{
    BpfInsn, MapReloc, ParsedKcrypto, ParsedSpine, insns_to_bytes, parse_kcrypto_object,
    parse_spine_object, valid_kcrypto_dims, valid_kcrypto_section,
};

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

/// Frozen kcrypto maps, in creation order. Asserted against the object.
///
/// The exact Task-2 contract (`KConfig` 40B per C2, `KAgg` 260B, `VAgg`
/// 120B — `planning/kryprobe-phaseK1-sensor-plan.md` Task 2); names
/// dot-free per R3 (`evidence/k0/P1-attach-matrix.txt`).
pub const KCRYPTO_MAPS: &[(&str, MapDims)] = &[
    (
        "KCFG",
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 40,
            max_entries: 1,
        },
    ),
    (
        "KAGG",
        MapDims {
            map_type: 5,
            key_size: 260,
            value_size: 120,
            max_entries: 256,
        },
    ),
    (
        "KTOT",
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 120,
            max_entries: 1,
        },
    ),
    (
        "KIDN",
        MapDims {
            map_type: 1,
            key_size: 8,
            value_size: 1,
            max_entries: 256,
        },
    ),
    (
        "KRING",
        MapDims {
            map_type: 27,
            key_size: 0,
            value_size: 0,
            max_entries: 1_048_576,
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
    /// program, NOT a corrupt object (X16). Callers map this to exit 4
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
    /// Pin name refused by the dot-free gate (R3): bpffs refuses dotted
    /// names with EPERM, so the loader rejects them typed, before any
    /// syscall. Empty names, `/`, and NUL fail here too (fail-closed
    /// path hygiene, same variant).
    BadPinName {
        name: String,
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
            Self::BadPinName { name } => {
                write!(
                    f,
                    "pin name '{name}' rejected: dot-free, slash-free, non-empty (R3)"
                )
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

/// Loaded kcrypto maps, one RAII fd per map (K1 Task 1).
pub struct KcryptoMaps {
    pub config: OwnedFd,
    pub agg: OwnedFd,
    pub total: OwnedFd,
    pub ident: OwnedFd,
    pub ring: OwnedFd,
}

/// Fully loaded kcrypto object: maps + per-program fds, all RAII-owned.
///
/// `progs` carries only the programs that loaded; the per-point outcomes
/// (including `Missing`/`Unsupported`) ride the sibling [`PointStatus`]
/// vector returned by [`load_kcrypto`].
pub struct LoadedKcrypto {
    pub maps: KcryptoMaps,
    pub progs: Vec<(String, OwnedFd)>,
}

/// Per-point load outcome (K1 Task 1; the plan's Self-Review pre-authorizes
/// this return extension: `load_kcrypto` takes attach ids and returns
/// per-point outcomes). A missing point degrades its op, never fails the
/// load: the load succeeds iff at least one program loads. Attach-level
/// attached/unsupported/missing arrives with the attach wiring (Task 3/K2),
/// which maps `Loaded` forward; `Missing`/`Unsupported` already degrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointStatus {
    /// Program loaded with its `attach_btf_id`, ready to attach.
    Loaded { name: String },
    /// No `attach_btf_id` was supplied for this program; skipped.
    Missing { name: String },
    /// Load refused (verifier/capability); `detail` is a short reason.
    Unsupported { name: String, detail: String },
}

impl PointStatus {
    /// Program name this outcome belongs to.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Loaded { name } | Self::Missing { name } | Self::Unsupported { name, .. } => name,
        }
    }
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
