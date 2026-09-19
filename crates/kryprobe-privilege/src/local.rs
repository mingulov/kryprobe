// SPDX-License-Identifier: GPL-3.0-or-later
//! In-process privileged authority: all three facets, really fronted.
//!
//! `LocalPrivilegedAuthority` implements the three SECURITY §3 authority
//! traits in-process. Each trait method fronts its real path: object bytes
//! parse + instantiate (§3.1, plain or token-delegated), scope-checked
//! link creation (§3.2), and bounded target inspection (§3.3). The free
//! functions behind these methods are crate-private; outside this crate
//! the ONLY load/link/inspect entries are the facet methods.

use std::path::Path;

use kryprobe_core::ProgramId;
use kryprobe_core::attach::{GenerationGuard, LinkGroup};
use kryprobe_core::authority::{AttachAuthority, BpfLoadAuthority, TargetInspectionAuthority};

use crate::attach::{AttachError, OwnedLink, attach_group};
use crate::bpfloader::instantiate::{instantiate, instantiate_with_token};
use crate::bpfloader::{LoadedSpine, LoaderError, parse_spine_object};
use crate::fanout::{FanoutPlan, FanoutRefresh, refresh_with, resolve_with};
use crate::fd::OwnedFd;
use crate::inspect::{InspectError, TargetSnapshot, inspect_pid};
use crate::token::TokenHandle;

/// Approved program allowlist: exactly the T6 self-probe.
static ALLOWLIST: &[ProgramId] = &[ProgramId::UprobeMultiSelfProbe];

/// In-process authority for local (non-broker) operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalPrivilegedAuthority;

impl LocalPrivilegedAuthority {
    /// Resolve a `Tree`/`Cgroup` scope to admitted members (FU4 fan-out).
    ///
    /// Inherent (not a facet method) by design (X15, see `AttachAuthority`):
    /// a composition helper over the inspect facet, not a fourth authority.
    /// Each member admits through the inspection facet; the plan's
    /// [`FanoutPlan::link_groups`] then flow through the unchanged Pid
    /// attach path. `Pid`/`System`/`OwnedRun` reject honestly here:
    /// `System` is system-wide kernel probes with nothing to enumerate
    /// (kp2 §3: skips fan-out).
    pub fn resolve_scope(
        &self,
        scope: &kryprobe_core::plan::TargetScope,
        max_targets: u64,
    ) -> Result<FanoutPlan, AttachError> {
        resolve_with(scope, max_targets, &|pid| {
            <Self as TargetInspectionAuthority>::inspect(self, pid)
        })
    }

    /// Follow-fork refresh: re-resolve the plan's scope and diff.
    ///
    /// A failed refresh leaves the caller's plan untouched.
    pub fn refresh_fanout(
        &self,
        plan: &FanoutPlan,
        max_targets: u64,
    ) -> Result<(FanoutPlan, FanoutRefresh), AttachError> {
        refresh_with(plan, max_targets, &|pid| {
            <Self as TargetInspectionAuthority>::inspect(self, pid)
        })
    }

    /// Fail-closed allowlist gate shared by both load entries.
    /// Denials are typed [`LoaderError::NotAllowed`] (X16: forbidden
    /// program, never `BadObject`), so callers can route them to exit
    /// 3 / `Denied` instead of a corruption bucket.
    fn check_allowlist(id: ProgramId) -> Result<(), LoaderError> {
        if ALLOWLIST.contains(&id) {
            Ok(())
        } else {
            Err(LoaderError::NotAllowed { id })
        }
    }
}

impl BpfLoadAuthority for LocalPrivilegedAuthority {
    type Loaded = LoadedSpine;
    type LoadError = LoaderError;
    type Token = TokenHandle;

    fn allowed_programs() -> &'static [ProgramId] {
        ALLOWLIST
    }

    /// Allowlist, then the real parse + instantiate path.
    fn load_program(&self, id: ProgramId, bytes: &[u8]) -> Result<LoadedSpine, LoaderError> {
        Self::check_allowlist(id)?;
        let parsed = parse_spine_object(bytes)?;
        instantiate(&parsed)
    }

    /// Allowlist, then the real token-delegated instantiate path.
    fn load_program_with_token(
        &self,
        id: ProgramId,
        bytes: &[u8],
        token: &TokenHandle,
    ) -> Result<LoadedSpine, LoaderError> {
        Self::check_allowlist(id)?;
        let parsed = parse_spine_object(bytes)?;
        instantiate_with_token(&parsed, Some(token.as_raw_fd()))
    }
}

impl AttachAuthority for LocalPrivilegedAuthority {
    type Link = OwnedLink;
    type AttachError = AttachError;
    type ProgFd = OwnedFd;

    /// Fronts the scope-checked, generation-guarded link path.
    fn attach_group(
        &self,
        group: &LinkGroup,
        guard: &GenerationGuard,
        prog_fd: &OwnedFd,
        object: &Path,
        offsets: &[u64],
    ) -> Result<OwnedLink, AttachError> {
        attach_group(group, guard, prog_fd, object, offsets)
    }
}

impl TargetInspectionAuthority for LocalPrivilegedAuthority {
    type Snapshot = TargetSnapshot;
    type InspectError = InspectError;

    /// Fronts the bounded inspection path.
    fn inspect(&self, pid: u32) -> Result<TargetSnapshot, InspectError> {
        inspect_pid(pid)
    }
}
