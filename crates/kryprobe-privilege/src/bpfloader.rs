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
pub(crate) mod kfunc;
pub(crate) mod mapcreate;
pub mod parse;
pub(crate) mod progload;

pub use instantiate::{CallbackLoad, check_pin_name, load_kcrypto, load_lifecycle, pin_fd};
pub use parse::{
    BpfInsn, MapReloc, ParsedKcrypto, ParsedSpine, insns_to_bytes, parse_kcrypto_object,
    parse_spine_object, valid_kcrypto_dims, valid_kcrypto_section,
};

use crate::fd::OwnedFd;
use kryprobe_core::ProgramId;

/// Frozen dims of one spine map (ground truth: the built object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapDims {
    /// BPF map type id.
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum entries.
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
/// The exact Task-2 contract (`KConfig` 76B per C2 + the K4-fix3
/// `shash_base` word + the K5 attribution tail, `KAgg` 260B, `VAgg`
/// 120B — `planning/kryprobe-phaseK1-sensor-plan.md` Task 2) plus the
/// four K5 attribution maps (`KWHO`/`KSTACK`/`KERR`/`KPARAMS` —
/// `planning/kryprobe-phaseK5-attribution-token-design.md` §2.1) plus
/// the fix-wave `KDROPS` pre-`KTOT` site counters (G-C1), plus the R1
/// `KIDENT` per-socket identity cache (BPF-internal, never snapshotted).
/// names dot-free per R3 (`evidence/k0/P1-attach-matrix.txt`).
pub const KCRYPTO_MAPS: &[(&str, MapDims)] = &[
    (
        "KCFG",
        MapDims {
            map_type: 2,
            key_size: 4,
            value_size: 76,
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
    (
        "KWHO",
        MapDims {
            map_type: 5,
            key_size: 16,
            value_size: 80,
            max_entries: 2048,
        },
    ),
    (
        "KSTACK",
        MapDims {
            map_type: 7,
            key_size: 4,
            value_size: 1016,
            max_entries: 1024,
        },
    ),
    (
        "KERR",
        MapDims {
            map_type: 1,
            key_size: 8,
            value_size: 4,
            max_entries: 256,
        },
    ),
    (
        "KPARAMS",
        MapDims {
            map_type: 1,
            key_size: 8,
            value_size: 16,
            max_entries: 256,
        },
    ),
    (
        "KDROPS",
        MapDims {
            map_type: 6,
            key_size: 4,
            value_size: 8,
            max_entries: 8,
        },
    ),
    (
        "KIDENT",
        MapDims {
            map_type: 1,
            key_size: 8,
            value_size: 256,
            max_entries: 256,
        },
    ),
];

/// One parsed map: name + dims as found in the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMap {
    /// Map name as found in the object.
    pub name: String,
    /// Dims as found in the object.
    pub dims: MapDims,
}

/// One parsed program: insn stream with calls resolved, map fds pending.
#[derive(Debug, Clone)]
pub struct ParsedProg {
    /// Program name.
    pub name: String,
    /// ELF section the program came from.
    pub section: String,
    /// Instruction stream with calls resolved.
    pub insns: Vec<BpfInsn>,
}

/// Raw loader failure: stage + detail, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderError {
    /// Object I/O failure.
    Io {
        /// Loader stage that failed.
        stage: &'static str,
        /// Failure detail.
        detail: String,
    },
    /// Object failed structural validation.
    BadObject {
        /// Rejection reason.
        reason: String,
    },
    /// Program id refused by the load-facet allowlist: a forbidden
    /// program, NOT a corrupt object (X16). Callers map this to exit 4
    /// / `Denied`, never to a corruption bucket.
    NotAllowed {
        /// Refused program id.
        id: ProgramId,
    },
    /// Map dims disagree with the frozen ground truth.
    DimMismatch {
        /// Offending map name.
        name: String,
    },
    /// Map type the raw loader does not support.
    UnsupportedMap {
        /// Offending map name.
        name: String,
    },
    /// Map symbol defined twice: the frozen table names each map once,
    /// so a duplicate is a corrupt/aliased object, never a merge.
    DuplicateMap {
        /// Offending map name.
        name: String,
    },
    /// Map creation failed.
    MapFailed {
        /// Loader stage that failed.
        stage: String,
        /// Kernel errno.
        errno: i32,
    },
    /// Program load failed.
    LoadFailed {
        /// Loader stage that failed.
        stage: String,
        /// Kernel errno.
        errno: i32,
        /// Verifier log tail.
        log: String,
    },
    /// Record buffer violates the 8-alignment precondition.
    MisalignedRecord {
        /// Misalignment residue (`addr % 8`, nonzero by
        /// construction): the same diagnostic value as the
        /// address, without carrying a pointer through the
        /// error (P7/T12 sol04 — no raw pointers in
        /// errors/debug/logs, even for rejected data).
        misalign: usize,
    },
    /// Pin name refused by the dot-free gate (R3): bpffs refuses dotted
    /// names with EPERM, so the loader rejects them typed, before any
    /// syscall. Empty names, `/`, and NUL fail here too (fail-closed
    /// path hygiene, same variant).
    BadPinName {
        /// Refused pin name.
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
            Self::DuplicateMap { name } => write!(f, "object defines map '{name}' twice"),
            Self::MapFailed { stage, errno } => {
                write!(f, "map create failed at {stage}: errno {errno}")
            }
            Self::LoadFailed { stage, errno, log } => {
                write!(f, "prog load failed at {stage}: errno {errno}: {log}")
            }
            Self::MisalignedRecord { misalign } => {
                write!(
                    f,
                    "record buffer misaligned by {misalign} (violates 8-alignment)"
                )
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
#[derive(Debug)]
pub struct SpineMaps {
    /// CONFIG map handle.
    pub config: OwnedFd,
    /// START map handle.
    pub start: OwnedFd,
    /// COUNT map handle.
    pub count: OwnedFd,
    /// EVENTS map handle.
    pub events: OwnedFd,
    /// LOSS map handle.
    pub loss: OwnedFd,
}

/// Loaded spine programs: entry + return.
#[derive(Debug)]
pub struct SpineProgs {
    /// Entry probe program handle.
    pub entry: OwnedFd,
    /// Return probe program handle.
    pub ret: OwnedFd,
}

/// Fully loaded spine: maps + programs, all RAII-owned.
#[derive(Debug)]
pub struct LoadedSpine {
    /// Loaded spine maps.
    pub maps: SpineMaps,
    /// Loaded spine programs.
    pub progs: SpineProgs,
}

/// Loaded kcrypto maps, one RAII fd per map (K1 Task 1 five + K5
/// Task 3 attribution four — [`snapshot_who`](crate::kcrypto_backend::snapshot_who)
/// reads the tail; dropping them here would close userspace's only
/// handles while the programs still reference the maps).
#[derive(Debug)]
pub struct KcryptoMaps {
    /// `KCFG` (resolved BTF ids + offsets).
    pub config: OwnedFd,
    /// `KAGG` (percpu aggregate counters).
    pub agg: OwnedFd,
    /// `KTOT` (global totals).
    pub total: OwnedFd,
    /// `KIDN` (ident/drop counters).
    pub ident: OwnedFd,
    /// `KRING` (ident record ring).
    pub ring: OwnedFd,
    /// `KWHO` (per-cpu caller identity, 2048 entries).
    pub who: OwnedFd,
    /// `KSTACK` (kernel stack traces, 1024 entries).
    pub stack: OwnedFd,
    /// `KERR` (first errno per row hash, 256 entries).
    pub err: OwnedFd,
    /// `KPARAMS` (crypto params per row hash, 256 entries).
    pub params: OwnedFd,
    /// `KDROPS` (pre-`KTOT` skip sites, 8 per-CPU u64 counters).
    pub drops: OwnedFd,
    /// `KIDENT` (R1 identity cache, BPF-internal: never read here;
    /// the fd only keeps the map alive with the sensor).
    pub ident_cache: OwnedFd,
}

/// Fully loaded kcrypto object: maps + per-program fds, all RAII-owned.
///
/// `progs` carries only the programs that loaded; the per-point outcomes
/// (including `Missing`/`Unsupported`) ride the sibling [`PointStatus`]
/// vector returned by [`load_kcrypto`].
#[derive(Debug)]
pub struct LoadedKcrypto {
    /// Loaded kcrypto maps.
    pub maps: KcryptoMaps,
    /// Loaded programs as (name, handle) pairs.
    pub progs: Vec<(String, OwnedFd)>,
}

impl KcryptoMaps {
    /// Duplicates every map handle (H1(b)): clones address the SAME
    /// kernel maps (no second sensor, no double memory).
    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            config: self.config.try_clone_cloexec()?,
            agg: self.agg.try_clone_cloexec()?,
            total: self.total.try_clone_cloexec()?,
            ident: self.ident.try_clone_cloexec()?,
            ring: self.ring.try_clone_cloexec()?,
            who: self.who.try_clone_cloexec()?,
            stack: self.stack.try_clone_cloexec()?,
            err: self.err.try_clone_cloexec()?,
            params: self.params.try_clone_cloexec()?,
            drops: self.drops.try_clone_cloexec()?,
            ident_cache: self.ident_cache.try_clone_cloexec()?,
        })
    }
}

impl LoadedKcrypto {
    /// Duplicates maps + program handles onto the same kernel objects.
    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        let mut progs = Vec::with_capacity(self.progs.len());
        for (name, prog) in &self.progs {
            progs.push((name.clone(), prog.try_clone_cloexec()?));
        }
        Ok(Self {
            maps: self.maps.try_clone()?,
            progs,
        })
    }
}

/// Loaded lifecycle maps, by T06 profile name.
#[derive(Debug)]
pub struct LifecycleMaps {
    /// `LCFG` (sensor config, 64 bytes).
    pub config: OwnedFd,
    /// `LRING` (raw edge ringbuf).
    pub ring: OwnedFd,
    /// `LLOSS` (per-CPU per-hook loss counters, 5 classes × 4
    /// lanes; userspace folds per class).
    pub loss: OwnedFd,
    /// `LAGG` (per-CPU accepted-edge aggregate, 4 entries).
    pub agg: OwnedFd,
    /// `LCTR` (per-CPU per-program invocation sequences, 2 lanes;
    /// BPF-owned — userspace keeps the fd, never reads it).
    pub ctr: OwnedFd,
}

/// Loaded lifecycle object: maps + programs as (section, handle)
/// pairs (sections, not bare names: the attach dispatch routes on
/// the `fentry/`/`fexit/` prefix each program was parsed from).
///
/// No `try_clone` by design (T06): the sensor has exactly one owner.
/// The live-tick duplication (H1(b) pattern) arrives with the T08
/// backend wiring, alongside its first user.
#[derive(Debug)]
pub struct LoadedLifecycle {
    /// Loaded lifecycle maps.
    pub maps: LifecycleMaps,
    /// Loaded programs as (section, handle) pairs.
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
    Loaded {
        /// Program name.
        name: String,
    },
    /// No `attach_btf_id` was supplied for this program; skipped.
    Missing {
        /// Program name.
        name: String,
    },
    /// Load refused (verifier/capability); `detail` is a short reason.
    Unsupported {
        /// Program name.
        name: String,
        /// Short refusal reason.
        detail: String,
    },
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
        Err(LoaderError::MisalignedRecord { misalign: addr % 8 })
    }
}
