// SPDX-License-Identifier: GPL-3.0-or-later
//! kryprobe-privilege: privileged helpers (ELF readers/parsers in T6a).
//!
//! This crate hosts operations that need elevated privilege or raw
//! binary parsing. T6a provides ELF byte readers and dynamic-symbol
//! resolution; BPF/probe/authority attachment arrives in T6c.
//!
//! Program identities live in [`kryprobe_core::ProgramId`]
//! (re-exported here for convenience).

pub mod attach;
pub mod bpfloader;
pub mod bpfselftest;
mod btf;
pub mod btf_resolve;
pub mod capture_gate;
pub mod decoy;
pub mod drain;
pub mod elevate;
pub mod elfread;
pub mod fanout;
pub mod fd;
pub mod filecaps;
pub mod host;
pub mod inspect;
pub mod kallsyms;
pub mod kcrypto_backend;
pub mod kcrypto_context;
pub mod kcrypto_lifecycle;
pub mod kcrypto_snapshot;
pub mod local;
pub mod mapops;
pub mod probe;
pub mod refused;
pub mod token;

pub use inspect::{InspectError, TargetSnapshot};
pub use kcrypto_backend::{
    LocateMiss, ObjectLocateError, locate_kcrypto_object_bytes, locate_kcrypto_object_identity,
    locate_lifecycle_object_bytes, locate_lifecycle_object_identity, pins_enforced,
    profile_pins_enforced, sha256_hex,
};
pub use kryprobe_core::ProgramId;
pub use local::LocalPrivilegedAuthority;
pub use probe::{ProbeMatrix, ProbeOutcome, run_probe_matrix};
pub use refused::TokenBrokerStub;
