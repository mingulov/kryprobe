// SPDX-License-Identifier: GPL-3.0-or-later
//! Three independent privilege authorities (SECURITY §3, ARCH §4.3).
//!
//! Privilege is three separate facets, never one blanket capability. Backend
//! code performs no privileged syscalls directly; every privileged operation
//! passes through one of these interfaces. Each facet is structural: the
//! trait declares the real entry methods. Core sits below privilege in the
//! dependency order, so privilege-owned values (loaded maps/programs,
//! links, token handles, snapshots, error types) stay associated types
//! the privilege crate concretes.

use crate::attach::{GenerationGuard, LinkGroup};
use crate::program::ProgramId;
use std::path::Path;

/// BPF load authority (SECURITY §3.1).
///
/// May create only approved map types and load only compiled-in approved
/// BPF programs with reviewed program/attach types. A BPF token may
/// participate in load delegation; it authorizes categories of BPF
/// operations, never target/PID confinement.
pub trait BpfLoadAuthority {
    /// Fully loaded programs + maps, owned by the privilege crate.
    type Loaded;
    /// Loader failure: stage + errno detail, never a panic.
    type LoadError;
    /// Verified BPF token handle for delegated (tokenized) loads.
    type Token;

    /// Approved programs (SECURITY §3.1): loads of any other id refuse.
    #[must_use]
    fn allowed_programs() -> &'static [ProgramId]
    where
        Self: Sized;

    /// Load one approved program from object `bytes`: allowlist check
    /// first (fail-closed), then parse + map create + program load.
    fn load_program(&self, id: ProgramId, bytes: &[u8]) -> Result<Self::Loaded, Self::LoadError>;

    /// [`load_program`](Self::load_program) delegated through `token`
    /// instead of ambient privilege.
    fn load_program_with_token(
        &self,
        id: ProgramId,
        bytes: &[u8],
        token: &Self::Token,
    ) -> Result<Self::Loaded, Self::LoadError>;
}

/// Attach authority (SECURITY §3.2).
///
/// May create links only for validated [`ProbePlan`](crate::plan::ProbePlan)
/// objects with exact target scope, object, and offsets. This is the
/// target-authorization boundary: the authority refuses unfiltered or
/// out-of-policy links.
///
/// Deliberately OUT of this contract (X15): `Tree`/`Cgroup` fan-out
/// (`LocalPrivilegedAuthority::resolve_scope`/`refresh_fanout`) stays an
/// inherent helper, not a facet method. Fan-out performs no privileged
/// operation itself — enumeration is world-readable `/proc`+cgroupfs
/// reads, admission goes through [`TargetInspectionAuthority::inspect`],
/// and links flow through the unchanged Pid path here — so folding it
/// in would widen this shared contract for zero boundary gain. Future
/// brokers reuse the same in-crate helper over their three facets rather
/// than reimplementing policy; broker mode meanwhile refuses Tree/Cgroup
/// plans wholesale (`TokenBrokerStub::attach_plan`, R-030), never a
/// silent subset.
pub trait AttachAuthority {
    /// RAII link: dropping the link detaches it.
    type Link;
    /// Link-group attach failure: rejection or syscall errno.
    type AttachError;
    /// Loaded program fd the link binds to.
    type ProgFd;

    /// Attach one link group: scope-checked, generation-guarded link.
    /// Cookies are `(generation << 32) | (index_base + offset_index)` over
    /// the group's allocator-issued range (see [`CookieAllocator`](crate::attach::CookieAllocator),
    /// owned by the driver); out-of-range bases reject.
    fn attach_group(
        &self,
        group: &LinkGroup,
        guard: &GenerationGuard,
        prog_fd: &Self::ProgFd,
        object: &Path,
        offsets: &[u64],
    ) -> Result<Self::Link, Self::AttachError>;
}

/// Target inspection authority (SECURITY §3.3).
///
/// May read the minimum process/object state needed to derive or verify a
/// plan: bounded `/proc/<pid>/maps`, `/proc/<pid>/exe`/`root`, mapped ELF
/// files, and explicitly approved small memory reads. Nothing more.
pub trait TargetInspectionAuthority {
    /// Minimal process/object state for plan derivation or verification.
    type Snapshot;
    /// Inspection failure: the target is gone, or a stage was denied.
    type InspectError;

    /// Inspect one process with bounded reads.
    fn inspect(&self, pid: u32) -> Result<Self::Snapshot, Self::InspectError>;
}
