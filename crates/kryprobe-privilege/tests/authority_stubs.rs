// SPDX-License-Identifier: GPL-3.0-or-later
//! LocalPrivilegedAuthority allowlist + honest stubs; TokenBrokerStub R-030.

use kryprobe_core::ProgramId;
use kryprobe_core::enums::BackendId;
use kryprobe_core::error::BackendError;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::{
    CapabilityRequirements, OffsetProbe, PlanBudget, ProbePlan, TargetScope,
};
use kryprobe_privilege::{LocalPrivilegedAuthority, TokenBrokerStub};

/// Exact R-030 refusal string (hardcoded: must match the stub, not mirror it).
const R030: &str = "token/broker mode requires pack experiment T6 + Phase B receipts (R-030)";

fn sample_plan() -> ProbePlan {
    ProbePlan {
        backend: BackendId::OpenSsl,
        generation: PlanGeneration::new(3),
        target_scope: TargetScope::Pid { pid: 4242 },
        object: ObjectRef {
            dev: 1,
            ino: 2,
            size: 4096,
            mtime: 1_700_000_000_000_000_000,
            role: ObjectRole::SharedLibrary,
        },
        offsets: vec![OffsetProbe {
            file_offset: 0x10,
            cookie: 0xabc,
            descriptor_id: 7,
        }],
        required_capabilities: CapabilityRequirements {
            ringbuf: true,
            ..CapabilityRequirements::default()
        },
        budget: PlanBudget {
            max_targets: 8,
            max_objects: 16,
            max_bytes: 1 << 20,
            max_links: 32,
            max_state_entries: 1024,
            max_queue: 512,
            max_duration_ns: 60_000_000_000,
        },
    }
}

fn unsupported_reason(err: BackendError) -> String {
    match err {
        BackendError::Unsupported(reason) => reason.reason.to_owned(),
        other => panic!("expected Unsupported, got {other}"),
    }
}

#[test]
fn allowlist_is_exactly_self_probe() {
    assert_eq!(
        LocalPrivilegedAuthority::allowed_programs(),
        &[ProgramId::UprobeMultiSelfProbe]
    );
}

#[test]
fn load_returns_unsupported_not_ok() {
    let auth = LocalPrivilegedAuthority;
    match auth.load_program(ProgramId::UprobeMultiSelfProbe) {
        Ok(()) => panic!("load must not succeed before T7"),
        Err(err) => assert_eq!(
            unsupported_reason(err),
            "program load arrives with T7 bpfloader"
        ),
    }
}

#[test]
fn attach_valid_returns_unsupported_invalid_returns_corrupt() {
    let auth = LocalPrivilegedAuthority;
    match auth.attach_plan(&sample_plan()) {
        Ok(()) => panic!("attach must not succeed before T7"),
        Err(err) => assert_eq!(
            unsupported_reason(err),
            "link creation arrives with T7 attach"
        ),
    }
    let mut bad = sample_plan();
    bad.offsets.clear();
    match auth.attach_plan(&bad) {
        Ok(()) => panic!("invalid plan must not attach"),
        Err(BackendError::CorruptInput(reason)) => {
            assert_eq!(reason.reason, "plan_validate");
        }
        Err(other) => panic!("invalid plan must be CorruptInput, got {other}"),
    }
}

#[test]
fn stub_methods_return_exact_r030_string() {
    assert_eq!(kryprobe_privilege::refused::REFUSED_REASON, R030);
    let stub = TokenBrokerStub;
    match TokenBrokerStub::allowed_programs() {
        Ok(_) => panic!("stub allowlist must refuse"),
        Err(err) => assert_eq!(unsupported_reason(err), R030),
    }
    match stub.load_program(ProgramId::UprobeMultiSelfProbe) {
        Ok(()) => panic!("stub load must refuse"),
        Err(err) => assert_eq!(unsupported_reason(err), R030),
    }
    match stub.attach_plan(&sample_plan()) {
        Ok(()) => panic!("stub attach must refuse"),
        Err(err) => assert_eq!(unsupported_reason(err), R030),
    }
    match stub.inspect(std::process::id()) {
        Ok(_) => panic!("stub inspect must refuse"),
        Err(err) => assert_eq!(unsupported_reason(err), R030),
    }
}
