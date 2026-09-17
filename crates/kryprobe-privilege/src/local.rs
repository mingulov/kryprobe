// SPDX-License-Identifier: GPL-3.0-or-later
//! In-process privileged authority: all three facets, one honest stub.
//!
//! `LocalPrivilegedAuthority` implements the three SECURITY §3 authority
//! traits in-process. T6c wires inspection for real; program load and link
//! creation stay honest `Unsupported` stubs until T7 (`bpfloader`/`attach`).

use kryprobe_core::ProgramId;
use kryprobe_core::authority::{AttachAuthority, BpfLoadAuthority, TargetInspectionAuthority};
use kryprobe_core::error::{BackendError, InputReason, UnsupportedReason};
use kryprobe_core::plan::ProbePlan;

use crate::inspect::{InspectError, TargetSnapshot, inspect_pid};

/// Approved program allowlist: exactly the T6 self-probe.
static ALLOWLIST: &[ProgramId] = &[ProgramId::UprobeMultiSelfProbe];

/// In-process authority for local (non-broker) operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalPrivilegedAuthority;

impl BpfLoadAuthority for LocalPrivilegedAuthority {}
impl AttachAuthority for LocalPrivilegedAuthority {}
impl TargetInspectionAuthority for LocalPrivilegedAuthority {}

impl LocalPrivilegedAuthority {
    /// Approved programs (SECURITY §3.1): exactly `UprobeMultiSelfProbe`.
    #[must_use]
    pub fn allowed_programs() -> &'static [ProgramId] {
        ALLOWLIST
    }

    /// Load one approved program (SECURITY §3.1).
    ///
    /// Honest T6 stub: unknown ids are `Unsupported`, and even allowlisted
    /// ids are `Unsupported` until T7 wires the real `bpfloader`.
    pub fn load_program(&self, id: ProgramId) -> Result<(), BackendError> {
        if !Self::allowed_programs().contains(&id) {
            return Err(BackendError::Unsupported(UnsupportedReason::new(
                "program id not in approved allowlist",
            )));
        }
        Err(BackendError::Unsupported(UnsupportedReason::new(
            "program load arrives with T7 bpfloader",
        )))
    }

    /// Attach one validated plan (SECURITY §3.2, target-authorization boundary).
    ///
    /// Invalid plans are `CorruptInput`; valid plans are `Unsupported`
    /// until T7 wires real link creation.
    pub fn attach_plan(&self, plan: &ProbePlan) -> Result<(), BackendError> {
        if let Err(err) = plan.validate() {
            return Err(BackendError::CorruptInput(InputReason::with_detail(
                "plan_validate",
                &err.to_string(),
            )));
        }
        Err(BackendError::Unsupported(UnsupportedReason::new(
            "link creation arrives with T7 attach",
        )))
    }

    /// Inspect one process (SECURITY §3.3): delegates to `inspect_pid`,
    /// the ONLY inspection path.
    pub fn inspect(&self, pid: u32) -> Result<TargetSnapshot, InspectError> {
        inspect_pid(pid)
    }
}
