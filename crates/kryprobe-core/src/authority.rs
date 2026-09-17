// SPDX-License-Identifier: GPL-3.0-or-later
//! Three independent privilege authorities (SECURITY §3, ARCH §4.3).
//!
//! Privilege is three separate facets, never one blanket capability. Backend
//! code performs no privileged syscalls directly; every privileged operation
//! passes through one of these interfaces. Method signatures arrive with the
//! runtime tasks that need them; this module pins the facet boundaries now.

/// BPF load authority (SECURITY §3.1).
///
/// May create only approved map types and load only compiled-in approved
/// BPF programs with reviewed program/attach types. A BPF token may
/// participate in load delegation; it authorizes categories of BPF
/// operations, never target/PID confinement.
pub trait BpfLoadAuthority {}

/// Attach authority (SECURITY §3.2).
///
/// May create links only for validated [`ProbePlan`](crate::plan::ProbePlan)
/// objects with exact target scope, object, and offsets. This is the
/// target-authorization boundary: the authority refuses unfiltered or
/// out-of-policy links.
pub trait AttachAuthority {}

/// Target inspection authority (SECURITY §3.3).
///
/// May read the minimum process/object state needed to derive or verify a
/// plan: bounded `/proc/<pid>/maps`, `/proc/<pid>/exe`/`root`, mapped ELF
/// files, and explicitly approved small memory reads. Nothing more.
pub trait TargetInspectionAuthority {}
