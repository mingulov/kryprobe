// SPDX-License-Identifier: GPL-3.0-or-later
//! Registry tests: owned registration, panic-free duplicate rejection,
//! leak-free drop.

use kryprobe_core::backend::{
    Backend, BackendCapabilities, BackendPlan, BackendRegistry, BackendSummary, ConfigureContext,
    DecodeContext, DetectContext, DetectedInstance, DuplicateBackend, FinalizeContext, PlanContext,
    RawEvent,
};
use kryprobe_core::enums::{BackendId, CaptureMode};
use kryprobe_core::error::{BackendError, UnsupportedReason};
use kryprobe_core::evidence::NativeObservation;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Stub reporting its own drop so tests prove the registry frees it.
struct DropBackend {
    dropped: Arc<AtomicBool>,
}

impl Drop for DropBackend {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl Backend for DropBackend {
    fn id(&self) -> BackendId {
        BackendId::KCrypto
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
    let mut registry = BackendRegistry::new();
    assert!(
        registry
            .register(Box::new(StubBackend { id: BackendId::P11 }))
            .is_ok()
    );
    let err = registry
        .register(Box::new(StubBackend { id: BackendId::P11 }))
        .unwrap_err();
    assert_eq!(
        err,
        DuplicateBackend {
            backend: BackendId::P11
        }
    );
    assert_eq!(err.to_string(), "duplicate backend: p11");
    // Refused registration must not displace the original.
    assert_eq!(registry.discover_all().len(), 1);
    assert!(registry.get(BackendId::P11).is_some());
}

#[test]
fn discover_all_returns_owned_backends_in_registration_order() {
    let mut registry = BackendRegistry::new();
    assert!(
        registry
            .register(Box::new(StubBackend { id: BackendId::P11 }))
            .is_ok()
    );
    assert!(
        registry
            .register(Box::new(StubBackend {
                id: BackendId::OpenSsl
            }))
            .is_ok()
    );
    let found = registry.discover_all();
    assert_eq!(found.len(), 2);
    let ids: Vec<BackendId> = found.iter().map(|backend| backend.id()).collect();
    assert_eq!(ids, vec![BackendId::P11, BackendId::OpenSsl]);
    assert!(registry.get(BackendId::KCrypto).is_none());
}

#[test]
fn dropping_registry_frees_owned_backends() {
    let dropped = Arc::new(AtomicBool::new(false));
    let mut registry = BackendRegistry::new();
    registry
        .register(Box::new(DropBackend {
            dropped: Arc::clone(&dropped),
        }))
        .expect("fresh registry accepts kcrypto");
    assert!(!dropped.load(Ordering::SeqCst));
    drop(registry);
    assert!(
        dropped.load(Ordering::SeqCst),
        "registry must own (and free) its backends: no Box::leak"
    );
}

#[test]
fn rejected_duplicate_handle_is_freed_not_leaked() {
    let dropped = Arc::new(AtomicBool::new(false));
    let mut registry = BackendRegistry::new();
    registry
        .register(Box::new(StubBackend {
            id: BackendId::KCrypto,
        }))
        .expect("fresh registry accepts kcrypto");
    let err = registry
        .register(Box::new(DropBackend {
            dropped: Arc::clone(&dropped),
        }))
        .unwrap_err();
    assert_eq!(
        err,
        DuplicateBackend {
            backend: BackendId::KCrypto
        }
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "rejected duplicate handle must be freed with the Err"
    );
    assert_eq!(registry.discover_all().len(), 1);
}

#[test]
fn owned_registry_stays_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BackendRegistry>();
    assert_send_sync::<Box<dyn Backend>>();
}
