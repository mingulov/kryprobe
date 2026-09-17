// SPDX-License-Identifier: GPL-3.0-or-later
//! 5c registry tests: static registration, panic-free duplicate rejection.

use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendPlan, BackendRegistry, BackendSummary, ConfigureContext,
    DecodeContext, DetectContext, DetectedInstance, DuplicateBackend, FinalizeContext, PlanContext,
    RawEvent,
};
use kryprobe_core::enums::{BackendId, CaptureMode};
use kryprobe_core::error::{BackendError, UnsupportedReason};
use kryprobe_core::evidence::NativeObservation;

fn caps() -> &'static BackendCapabilities {
    static CAPS: BackendCapabilities = BackendCapabilities {
        backend: BackendId::P11,
        name: "stub",
        required: kryprobe_core::plan::CapabilityRequirements {
            uprobe_multi: false,
            cookies: false,
            ringbuf: false,
            btf: false,
        },
    };
    &CAPS
}

struct StubBackend {
    id: BackendId,
}

impl Backend for StubBackend {
    fn id(&self) -> BackendId {
        self.id
    }

    fn capabilities(&self) -> &'static BackendCapabilities {
        caps()
    }

    fn detect(&self, _ctx: &DetectContext<'_>) -> Result<Vec<DetectedInstance>, BackendError> {
        Ok(Vec::new())
    }

    fn plan(
        &self,
        _ctx: &PlanContext<'_>,
        _instance: &DetectedInstance,
        _mode: CaptureMode,
    ) -> Result<BackendPlan, BackendError> {
        Err(BackendError::Unsupported(UnsupportedReason::new("stub")))
    }

    fn configure(
        &self,
        _ctx: &mut ConfigureContext<'_>,
        _plan: &BackendPlan,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unsupported(UnsupportedReason::new("stub")))
    }

    fn decode(
        &self,
        _ctx: &DecodeContext<'_>,
        _event: RawEvent<'_>,
    ) -> Result<NativeObservation, BackendError> {
        Err(BackendError::Unsupported(UnsupportedReason::new("stub")))
    }

    fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
        Err(BackendError::Unsupported(UnsupportedReason::new("stub")))
    }
}

#[test]
fn duplicate_backend_id_is_err_not_panic() {
    static FIRST: StubBackend = StubBackend { id: BackendId::P11 };
    static SECOND: StubBackend = StubBackend { id: BackendId::P11 };
    let mut registry = BackendRegistry::new();
    assert!(registry.register(&FIRST).is_ok());
    let err = registry.register(&SECOND).unwrap_err();
    assert_eq!(
        err,
        DuplicateBackend {
            backend: BackendId::P11
        }
    );
    assert_eq!(err.to_string(), "duplicate backend: p11");
    // Refused registration must not displace the original.
    assert_eq!(registry.discover_all().len(), 1);
}

#[test]
fn discover_all_returns_statically_registered_backends() {
    static P11: StubBackend = StubBackend { id: BackendId::P11 };
    static OPENSSL: StubBackend = StubBackend {
        id: BackendId::OpenSsl,
    };
    let mut registry = BackendRegistry::new();
    assert!(registry.register(&P11).is_ok());
    assert!(registry.register(&OPENSSL).is_ok());
    let found = registry.discover_all();
    assert_eq!(found.len(), 2);
    let ids: Vec<BackendId> = found.iter().map(|backend| backend.id()).collect();
    assert_eq!(ids, vec![BackendId::P11, BackendId::OpenSsl]);
}
