// SPDX-License-Identifier: GPL-3.0-or-later
//! Facet fronting: allowlist + load/attach/inspect through the authority
//! traits; TokenBrokerStub R-030.
//!
//! Every privileged entry goes through its facet interface on
//! `LocalPrivilegedAuthority` (`BpfLoadAuthority`, `AttachAuthority`,
//! `TargetInspectionAuthority`): allowlisted loads reach the real loader,
//! garbage bytes fail closed at parse, out-of-policy attaches reject, and
//! inspection matches `/proc`. The broker stub still refuses everything
//! with the exact R-030 receipt string.

use kryprobe_core::ProgramId;
use kryprobe_core::attach::{CookieAllocator, GenerationGuard, LinkGroup};
use kryprobe_core::authority::{AttachAuthority, BpfLoadAuthority, TargetInspectionAuthority};
use kryprobe_core::error::BackendError;
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_privilege::attach::AttachError;
use kryprobe_privilege::bpfloader::LoaderError;
use kryprobe_privilege::{InspectError, LocalPrivilegedAuthority, TokenBrokerStub};
use std::path::PathBuf;

/// Exact R-030 refusal string (hardcoded: must match the stub, not mirror it).
const R030: &str = "token/broker mode requires pack experiment T6 + Phase B receipts (R-030)";

fn spine_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("spine.bpf.o")
}

fn object_bytes() -> Vec<u8> {
    let path = spine_object_path();
    assert!(
        path.is_file(),
        "missing BPF spine object at {} — run `cargo xtask build --bpf`",
        path.display()
    );
    std::fs::read(&path).expect("test fixture must be readable")
}

fn group(scope: TargetScope) -> LinkGroup {
    let mut alloc = CookieAllocator::new(PlanGeneration::new(1));
    let range = alloc.allocate(1).expect("fixture range fits");
    LinkGroup::from_range(
        ObjectRef {
            dev: 0,
            ino: 0,
            size: 0,
            mtime: 0,
            role: ObjectRole::Executable,
        },
        ProgramId::UprobeMultiSelfProbe,
        scope,
        true,
        range,
    )
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
fn load_fronts_real_loader_through_facet() {
    let bytes = object_bytes();
    match LocalPrivilegedAuthority.load_program(ProgramId::UprobeMultiSelfProbe, &bytes) {
        Ok(loaded) => {
            for fd in [
                loaded.maps.config.as_raw_fd(),
                loaded.maps.start.as_raw_fd(),
                loaded.maps.count.as_raw_fd(),
                loaded.maps.events.as_raw_fd(),
                loaded.maps.loss.as_raw_fd(),
                loaded.progs.entry.as_raw_fd(),
                loaded.progs.ret.as_raw_fd(),
            ] {
                assert!(fd >= 0, "privileged facet load gave invalid fd");
            }
        }
        Err(LoaderError::MapFailed { errno, .. }) | Err(LoaderError::LoadFailed { errno, .. }) => {
            assert!(
                errno == libc::EPERM || errno == libc::EACCES,
                "unprivileged facet load must surface EPERM/EACCES, got {errno}"
            );
        }
        Err(other) => panic!("facet load failed dishonestly: {other}"),
    }
}

#[test]
fn load_rejects_garbage_bytes_through_facet() {
    // Pure-parse rejection: no privilege needed, must fail closed.
    match LocalPrivilegedAuthority.load_program(
        ProgramId::UprobeMultiSelfProbe,
        b"not an elf file at all....................",
    ) {
        Ok(_) => panic!("garbage bytes must not load"),
        Err(err) => assert!(
            matches!(err, LoaderError::BadObject { .. }),
            "garbage bytes must be BadObject, got {err}"
        ),
    }
}

#[test]
fn load_rejects_non_allowlisted_id_through_facet() {
    // C3 (+ T5 "allowlist + rejection behavior"): the id-refusal arm
    // pinned end-to-end. A declared-but-unapproved id refuses with
    // typed NotAllowed however valid the bytes are (gate precedes parse).
    let bytes = object_bytes();
    let garbage: &[u8] = b"not an elf file at all....................";
    for input in [bytes.as_slice(), garbage] {
        match LocalPrivilegedAuthority.load_program(ProgramId::UprobeMultiP11Probe, input) {
            Ok(_) => panic!("non-allowlisted id must not load"),
            Err(LoaderError::NotAllowed { id }) => {
                assert_eq!(id, ProgramId::UprobeMultiP11Probe);
            }
            Err(other) => panic!("non-allowlisted id must be NotAllowed, got {other}"),
        }
    }
}

#[test]
fn attach_rejects_stale_generation_through_facet() {
    // SAFETY: never dereferenced; the gate rejects before any syscall.
    let bad_fd = unsafe { kryprobe_privilege::fd::OwnedFd::from_raw_fd(-1) };
    let guard = GenerationGuard {
        generation: PlanGeneration::new(2),
    };
    let err = LocalPrivilegedAuthority
        .attach_group(
            &group(TargetScope::Pid { pid: 1 }),
            &guard,
            &bad_fd,
            &PathBuf::from("/nonexistent-kryprobe-object"),
            &[0x1000],
        )
        .unwrap_err();
    assert!(
        matches!(err, AttachError::Rejected { ref reason } if reason.contains("stale")),
        "got {err}"
    );
}

#[test]
fn inspect_fronts_real_inspection_through_facet() {
    let pid = std::process::id();
    let snap = LocalPrivilegedAuthority
        .inspect(pid)
        .unwrap_or_else(|err| panic!("facet inspect(self) must succeed: {err}"));
    assert_eq!(snap.pid, pid);
    assert!(snap.starttime > 0, "starttime must be nonzero");
}

#[test]
fn inspect_dead_pid_is_target_gone_through_facet() {
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn true helper");
    let pid = child.id();
    child.wait().expect("wait for true helper");
    assert!(
        matches!(
            LocalPrivilegedAuthority.inspect(pid),
            Err(InspectError::TargetGone)
        ),
        "reaped pid {pid} must be TargetGone"
    );
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
    match stub.attach_plan(&sample_plan_for_stub()) {
        Ok(()) => panic!("stub attach must refuse"),
        Err(err) => assert_eq!(unsupported_reason(err), R030),
    }
    match stub.inspect(std::process::id()) {
        Ok(_) => panic!("stub inspect must refuse"),
        Err(err) => assert_eq!(unsupported_reason(err), R030),
    }
}

#[test]
fn stub_refuses_tree_scope_with_exact_r030() {
    // X15: broker mode never silently lacks fan-out policy — a
    // Tree-scoped plan refuses with the same R-030 receipt.
    let mut plan = sample_plan_for_stub();
    plan.target_scope = TargetScope::Tree { root: 1 };
    match TokenBrokerStub.attach_plan(&plan) {
        Ok(()) => panic!("stub attach must refuse Tree scope"),
        Err(err) => assert_eq!(unsupported_reason(err), R030),
    }
}

fn sample_plan_for_stub() -> kryprobe_core::plan::ProbePlan {
    use kryprobe_core::enums::BackendId;
    use kryprobe_core::plan::{CapabilityRequirements, OffsetProbe, PlanBudget, ProbePlan};
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
