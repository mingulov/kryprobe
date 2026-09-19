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
pub mod btf_resolve;
pub mod decoy;
pub mod drain;
pub mod elfread;
pub mod fanout;
pub mod fd;
pub mod inspect;
pub mod kcrypto_snapshot;
pub mod local;
pub mod mapops;
pub mod probe;
pub mod refused;
pub mod token;

pub use inspect::{InspectError, TargetSnapshot};
pub use kryprobe_core::ProgramId;
pub use local::LocalPrivilegedAuthority;
pub use probe::{ProbeMatrix, ProbeOutcome, run_probe_matrix};
pub use refused::TokenBrokerStub;
