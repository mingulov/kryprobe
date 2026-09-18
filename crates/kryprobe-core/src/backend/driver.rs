// SPDX-License-Identifier: GPL-3.0-or-later
//! Production backend driver: one lifecycle pass over owned backends.
//!
//! [`BackendDriver`] owns the session state every lifecycle step borrows
//! (budgets, ID issuer, integrity baseline, coverage assessment) and calls
//! the frozen [`Backend`](crate::backend::Backend) trait in order — detect
//! → plan → configure → decode → finalize — for each registered backend in
//! registration order. Events route by header `backend_id` to the backend
//! whose [`BackendId::wire_id`](crate::enums::BackendId::wire_id) matches;
//! an event no registered backend claims is
//! [`DriverError::UnroutedEvent`], checked before anything runs (input
//! validation precedes effects).
//!
//! Failure policy (fail-closed): the first backend error aborts the run
//! with the failing backend attributed ([`DriverError::Backend`]); partial
//! observations are discarded with the `Err`, never returned as success.
//! Capability gates are environmental, not defects: a backend whose static
//! or plan requirements the host cannot satisfy is skipped with a
//! [`SkippedBackend`] receipt in [`DriverReport::skipped`], so a skipped
//! backend is visible, never silent. Plan gates are atomic per backend:
//! every instance's plan is gate-checked before ANY `configure` runs, so
//! a skip publishes no partial plans and charges no budget (only
//! `configure` charges, and it never runs for a skipped backend — no
//! rollback or refund path exists or is needed). Events routed to a
//! skipped backend are dropped undecoded; the receipt counts them
//! (`dropped_events`, totaled by [`DriverReport::skipped_drops`]) so
//! skip-drops stay visible to integrity accounting alongside the rollup.

use crate::attach::{CookieAllocator, CookieExhausted, CookieRange};
use crate::backend::{
    Backend, BackendPlan, BackendRegistry, BackendSummary, ConfigureContext, DecodeContext,
    DetectContext, FinalizeContext, PlanContext, RawEvent,
};
use crate::budget::BudgetManager;
use crate::capability::RuntimeCapabilities;
use crate::enums::{BackendId, CaptureMode, CoverageStatus};
use crate::error::BackendError;
use crate::evidence::{
    CoverageSummary, DimensionCoverage, IntegritySummary, NativeObservation, ValidityInterval,
};
use crate::ids::{IdIssuer, PlanGeneration, SessionId};
use crate::plan::PlanBudget;
use std::fmt::{Display, Formatter};

/// Session state owned by the driver; every lifecycle context borrows it.
#[derive(Debug)]
pub struct BackendDriver {
    session: SessionId,
    mode: CaptureMode,
    generation: PlanGeneration,
    budget: BudgetManager,
    integrity: IntegritySummary,
    coverage: CoverageSummary,
    id_issuer: IdIssuer,
    cookies: CookieAllocator,
}

impl BackendDriver {
    /// Driver for one session: `budget` ceilings are enforced per counter,
    /// `coverage` is the session assessment backends finalize against.
    /// Integrity starts zeroed (no losses observed yet) and the ID issuer
    /// is fresh, so observation IDs are unique across backends.
    #[must_use]
    pub fn new(
        session: SessionId,
        mode: CaptureMode,
        generation: PlanGeneration,
        budget: PlanBudget,
        coverage: CoverageSummary,
    ) -> Self {
        Self {
            session,
            mode,
            generation,
            budget: BudgetManager::new(budget),
            integrity: IntegritySummary::default(),
            coverage,
            id_issuer: IdIssuer::default(),
            cookies: CookieAllocator::new(generation),
        }
    }

    /// Issue a disjoint cookie-index range for one link group of this
    /// session: the driver owns the cookie namespace the way it owns
    /// observation IDs, so concurrent groups never conflate `COUNT[idx]`.
    /// Exhaustion refuses with [`CookieExhausted`] (fail closed, never
    /// alias); the caller attaches nothing on `Err`.
    pub fn allocate_cookies(&mut self, len: usize) -> Result<CookieRange, CookieExhausted> {
        self.cookies.allocate(len)
    }

    /// Deterministic minimal session state for harnesses and liveness
    /// proofs: session 1, [`CaptureMode::Trace`], generation 1, wide-open
    /// budgets, all-[`CoverageStatus::NotRun`] coverage. Production callers
    /// use [`BackendDriver::new`] with real session state.
    #[must_use]
    pub fn harness() -> Self {
        let budget = PlanBudget {
            max_targets: u64::MAX,
            max_objects: u64::MAX,
            max_bytes: u64::MAX,
            max_links: u64::MAX,
            max_state_entries: u64::MAX,
            max_queue: u64::MAX,
            max_duration_ns: u64::MAX,
        };
        let dimension = || {
            DimensionCoverage::new(
                CoverageStatus::NotRun,
                ValidityInterval {
                    start_ns: 0,
                    end_ns: None,
                },
            )
        };
        let coverage = CoverageSummary {
            target_population: dimension(),
            object_discovery: dimension(),
            attachment: dimension(),
            aggregate_counts: dimension(),
            detailed_events: dimension(),
            attribution: dimension(),
            correlation: dimension(),
            completion: dimension(),
        };
        Self::new(
            SessionId::new(1),
            CaptureMode::Trace,
            PlanGeneration::new(1),
            budget,
            coverage,
        )
    }

    /// One lifecycle pass over `registry`: every event must route to a
    /// registered backend (else [`DriverError::UnroutedEvent`]), then each
    /// backend runs detect → plan → configure → decode → finalize. The
    /// first backend error aborts with that backend attributed.
    pub fn run(
        &mut self,
        registry: &BackendRegistry,
        runtime: &RuntimeCapabilities,
        events: &[RawEvent<'_>],
    ) -> Result<DriverReport, DriverError> {
        let backends = registry.discover_all();
        for event in events {
            let routed = backends
                .iter()
                .any(|backend| backend.id().wire_id() == event.header.backend_id);
            if !routed {
                return Err(DriverError::UnroutedEvent {
                    backend_id: event.header.backend_id,
                });
            }
        }
        let mut report = DriverReport::default();
        for backend in backends {
            self.drive_one(backend, runtime, events, &mut report)?;
        }
        Ok(report)
    }

    /// One backend's lifecycle pass; capability-gate failures skip the
    /// backend (recorded with a drop receipt) instead of aborting the
    /// session. Planning is atomic per backend: every instance is
    /// planned and gate-checked before any `configure` runs.
    fn drive_one(
        &mut self,
        backend: &dyn Backend,
        runtime: &RuntimeCapabilities,
        events: &[RawEvent<'_>],
        report: &mut DriverReport,
    ) -> Result<(), DriverError> {
        let id = backend.id();
        if !runtime.satisfies(&backend.capabilities().required) {
            report.skip(id, events);
            return Ok(());
        }
        let detect_ctx = DetectContext {
            session: self.session,
            runtime,
        };
        let instances = backend
            .detect(&detect_ctx)
            .map_err(|error| DriverError::Backend { backend: id, error })?;
        let mut plans = Vec::with_capacity(instances.len());
        for instance in &instances {
            let plan_ctx = PlanContext {
                session: self.session,
                runtime,
            };
            let plan = backend
                .plan(&plan_ctx, instance, self.mode)
                .map_err(|error| DriverError::Backend { backend: id, error })?;
            plans.push(plan);
        }
        // Atomic plan gate: one failing instance skips the whole backend
        // with nothing configured — no partial plans in the report, no
        // budget charged, nothing for the runtime to attach.
        if plans.iter().any(|plan| !runtime.satisfies(&plan.required)) {
            report.skip(id, events);
            return Ok(());
        }
        for plan in &plans {
            let mut configure_ctx = ConfigureContext {
                session: self.session,
                generation: self.generation,
                budget: &mut self.budget,
            };
            backend
                .configure(&mut configure_ctx, plan)
                .map_err(|error| DriverError::Backend { backend: id, error })?;
            report.plans.push(plan.clone());
        }
        for event in events
            .iter()
            .filter(|event| event.header.backend_id == id.wire_id())
        {
            let decode_ctx = DecodeContext {
                session: self.session,
                generation: self.generation,
                integrity: &self.integrity,
                id_issuer: &self.id_issuer,
            };
            let observation = backend
                .decode(&decode_ctx, *event)
                .map_err(|error| DriverError::Backend { backend: id, error })?;
            report.observations.push(observation);
        }
        let finalize_ctx = FinalizeContext {
            session: self.session,
            coverage: &self.coverage,
            integrity: &self.integrity,
        };
        let summary = backend
            .finalize(&finalize_ctx)
            .map_err(|error| DriverError::Backend { backend: id, error })?;
        report.summaries.push(summary);
        Ok(())
    }
}

/// One backend skipped on a capability gate, with its drop receipt.
///
/// A skip is atomic: the backend contributed no plans, no observations,
/// and no summary, and `configure` never ran for it (no budget charged).
/// Every input event routed to the backend was dropped undecoded instead,
/// counted here so the loss stays visible to integrity accounting — the
/// rollup only totals backends that ran, so without this receipt
/// skip-drops would be invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SkippedBackend {
    /// Backend that was skipped.
    pub backend: BackendId,
    /// Input events routed to this backend that were dropped undecoded
    /// because the backend never ran.
    pub dropped_events: u64,
}

/// Outcome of one [`BackendDriver::run`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverReport {
    /// Decoded observations: backends in registration order, each backend's
    /// events in input order.
    pub observations: Vec<NativeObservation>,
    /// Accepted plans, in drive order (the runtime attaches from these).
    pub plans: Vec<BackendPlan>,
    /// Per-backend end-of-session facts, in drive order.
    pub summaries: Vec<BackendSummary>,
    /// Backends skipped on capability gates (static or plan requirements
    /// the host cannot satisfy), in skip order. Each receipt counts the
    /// routed-but-undelivered events for that backend.
    pub skipped: Vec<SkippedBackend>,
}

impl DriverReport {
    /// Session integrity rollup: the summaries' backend-scoped counters
    /// totaled through [`IntegritySummary::rollup`] (the one rollup site).
    /// Skipped backends contribute no summary; their dropped events are
    /// receipted separately in [`DriverReport::skipped`] (see
    /// [`DriverReport::skipped_drops`]).
    #[must_use]
    pub fn session_integrity(&self) -> IntegritySummary {
        IntegritySummary::rollup(self.summaries.iter().map(|summary| &summary.integrity))
    }

    /// Total events dropped on skipped backends this pass: the
    /// driver-observed loss the rollup cannot see (skipped backends file
    /// no summary). Consumers reconciling exact vs received + drops add
    /// this to the rollup. Saturates rather than wraps.
    #[must_use]
    pub fn skipped_drops(&self) -> u64 {
        self.skipped.iter().fold(0_u64, |total, skip| {
            total.saturating_add(skip.dropped_events)
        })
    }

    /// Record a capability-gate skip: `backend` never ran, so every input
    /// event routed to it is dropped undecoded and counted on the receipt.
    fn skip(&mut self, backend: BackendId, events: &[RawEvent<'_>]) {
        let dropped_events = events
            .iter()
            .filter(|event| event.header.backend_id == backend.wire_id())
            .count() as u64;
        self.skipped.push(SkippedBackend {
            backend,
            dropped_events,
        });
    }
}

/// Driver failure: attributed backend error or unroutable input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    /// `backend` failed a lifecycle step with `error`; the run aborted.
    Backend {
        /// Backend that failed.
        backend: BackendId,
        /// Typed backend failure.
        error: BackendError,
    },
    /// No registered backend claims this wire discriminator; nothing ran.
    UnroutedEvent {
        /// `backend_id` header value with no registered backend.
        backend_id: u16,
    },
}

impl Display for DriverError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { backend, error } => {
                write!(f, "backend {} failed: {error}", backend_name(*backend))
            }
            Self::UnroutedEvent { backend_id } => write!(
                f,
                "unrouted event: no registered backend for wire id {backend_id:#x}"
            ),
        }
    }
}

impl std::error::Error for DriverError {}

/// Static backend name for diagnostics (mirrors the registry's spelling).
fn backend_name(id: BackendId) -> &'static str {
    match id {
        BackendId::P11 => "p11",
        BackendId::OpenSsl => "openssl",
        BackendId::KCrypto => "kcrypto",
        BackendId::Synthetic => "synthetic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendCapabilities;
    use crate::enums::{CallKind, EvidencePhase, OperationClass};
    use crate::error::UnsupportedReason;
    use crate::evidence::{IntegrityRef, NativeResult};
    use crate::plan::CapabilityRequirements;
    use kryprobe_abi::RawEventHeader;
    use std::sync::{Arc, Mutex};

    static OPEN_CAPS: BackendCapabilities = BackendCapabilities {
        backend: BackendId::P11,
        name: "recorder",
        required: CapabilityRequirements {
            uprobe_multi: false,
            cookies: false,
            ringbuf: false,
            btf: false,
        },
    };

    static NEEDY_CAPS: BackendCapabilities = BackendCapabilities {
        backend: BackendId::P11,
        name: "recorder",
        required: CapabilityRequirements {
            uprobe_multi: false,
            cookies: false,
            ringbuf: false,
            btf: true,
        },
    };

    /// Backend recording lifecycle calls in order; `fail_plan` turns `plan`
    /// into a typed error to prove abort-with-attribution.
    struct Recorder {
        needy: bool,
        fail_plan: bool,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Recorder {
        fn record(&self, step: &'static str) {
            self.calls.lock().expect("calls mutex").push(step);
        }
    }

    impl Backend for Recorder {
        fn id(&self) -> BackendId {
            BackendId::P11
        }

        fn capabilities(&self) -> &'static BackendCapabilities {
            if self.needy { &NEEDY_CAPS } else { &OPEN_CAPS }
        }

        fn detect(
            &self,
            _ctx: &DetectContext<'_>,
        ) -> Result<Vec<crate::backend::DetectedInstance>, BackendError> {
            self.record("detect");
            Ok(vec![crate::backend::DetectedInstance {
                backend: BackendId::P11,
                object: None,
                detail: String::from("recorded instance"),
            }])
        }

        fn plan(
            &self,
            _ctx: &PlanContext<'_>,
            _instance: &crate::backend::DetectedInstance,
            _mode: CaptureMode,
        ) -> Result<BackendPlan, BackendError> {
            self.record("plan");
            if self.fail_plan {
                return Err(BackendError::Unsupported(UnsupportedReason::new("nope")));
            }
            Ok(BackendPlan {
                backend: BackendId::P11,
                probes: Vec::new(),
                required: CapabilityRequirements::default(),
            })
        }

        fn configure(
            &self,
            _ctx: &mut ConfigureContext<'_>,
            _plan: &BackendPlan,
        ) -> Result<(), BackendError> {
            self.record("configure");
            Ok(())
        }

        fn decode(
            &self,
            ctx: &DecodeContext<'_>,
            event: RawEvent<'_>,
        ) -> Result<NativeObservation, BackendError> {
            self.record("decode");
            Ok(NativeObservation {
                id: ctx.id_issuer.issue().expect("test issues never exhaust"),
                backend: BackendId::P11,
                target: None,
                object: None,
                implementation: None,
                phase: EvidencePhase::Entered,
                call_kind: CallKind::Operation,
                operation_class: OperationClass::Sign,
                native_name: None,
                native_code: None,
                native_result: NativeResult::Synthetic { code: 0 },
                started_ns: Some(event.header.monotonic_ns),
                ended_ns: None,
                correlation: None,
                integrity: IntegrityRef::new(0),
                backend_payload: serde_json::Value::Null,
            })
        }

        fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
            self.record("finalize");
            // Backend-observed counters only (none on this path); the
            // session baseline in `ctx` is never echoed.
            Ok(BackendSummary {
                backend: BackendId::P11,
                observations: 1,
                integrity: IntegritySummary::default(),
            })
        }
    }

    fn runtime(all: bool) -> RuntimeCapabilities {
        RuntimeCapabilities {
            kernel_release: String::from("test"),
            uprobe_multi: all,
            cookies: all,
            ringbuf: all,
            btf_present: all,
            userns: all,
            yama_scope: 0,
            caps: Vec::new(),
        }
    }

    fn event_for(backend_id: u16) -> (RawEventHeader, [u8; 8]) {
        (
            RawEventHeader {
                abi_version: kryprobe_abi::ABI_VERSION,
                backend_id,
                event_kind: kryprobe_abi::EVENT_OBSERVATION,
                flags: 0,
                total_len: 64,
                cpu: 0,
                session_cookie: 0,
                monotonic_ns: 1_000_000,
                tgid: 0,
                tid: 0,
                process_generation: 0,
                plan_generation: 1,
                reserved: 0,
            },
            [0_u8; 8],
        )
    }

    fn registered(recorder: Recorder) -> (BackendRegistry, Arc<Mutex<Vec<&'static str>>>) {
        let calls = Arc::clone(&recorder.calls);
        let mut registry = BackendRegistry::new();
        registry.register(Box::new(recorder)).expect("fresh id");
        (registry, calls)
    }

    fn recorder(needy: bool, fail_plan: bool) -> Recorder {
        Recorder {
            needy,
            fail_plan,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Two instances, open static gates; the SECOND instance's plan
    /// demands `btf`, so a no-btf runtime trips the plan gate only
    /// after the first instance already planned (the C10 half-skip
    /// shape). `plan` tells instances apart by `detail`.
    struct TwoInstance {
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl TwoInstance {
        fn record(&self, step: &'static str) {
            self.calls.lock().expect("calls mutex").push(step);
        }
    }

    impl Backend for TwoInstance {
        fn id(&self) -> BackendId {
            BackendId::P11
        }

        fn capabilities(&self) -> &'static BackendCapabilities {
            &OPEN_CAPS
        }

        fn detect(
            &self,
            _ctx: &DetectContext<'_>,
        ) -> Result<Vec<crate::backend::DetectedInstance>, BackendError> {
            self.record("detect");
            Ok(["first", "second"]
                .into_iter()
                .map(|which| crate::backend::DetectedInstance {
                    backend: BackendId::P11,
                    object: None,
                    detail: String::from(which),
                })
                .collect())
        }

        fn plan(
            &self,
            _ctx: &PlanContext<'_>,
            instance: &crate::backend::DetectedInstance,
            _mode: CaptureMode,
        ) -> Result<BackendPlan, BackendError> {
            self.record("plan");
            let needy = instance.detail == "second";
            Ok(BackendPlan {
                backend: BackendId::P11,
                probes: Vec::new(),
                required: CapabilityRequirements {
                    btf: needy,
                    ..CapabilityRequirements::default()
                },
            })
        }

        fn configure(
            &self,
            _ctx: &mut ConfigureContext<'_>,
            _plan: &BackendPlan,
        ) -> Result<(), BackendError> {
            self.record("configure");
            Ok(())
        }

        fn decode(
            &self,
            ctx: &DecodeContext<'_>,
            event: RawEvent<'_>,
        ) -> Result<NativeObservation, BackendError> {
            self.record("decode");
            Ok(NativeObservation {
                id: ctx.id_issuer.issue().expect("test issues never exhaust"),
                backend: BackendId::P11,
                target: None,
                object: None,
                implementation: None,
                phase: EvidencePhase::Entered,
                call_kind: CallKind::Operation,
                operation_class: OperationClass::Sign,
                native_name: None,
                native_code: None,
                native_result: NativeResult::Synthetic { code: 0 },
                started_ns: Some(event.header.monotonic_ns),
                ended_ns: None,
                correlation: None,
                integrity: IntegrityRef::new(0),
                backend_payload: serde_json::Value::Null,
            })
        }

        fn finalize(&self, _ctx: &FinalizeContext<'_>) -> Result<BackendSummary, BackendError> {
            self.record("finalize");
            Ok(BackendSummary {
                backend: BackendId::P11,
                observations: 0,
                integrity: IntegritySummary::default(),
            })
        }
    }

    #[test]
    fn lifecycle_runs_detect_plan_configure_decode_finalize_in_order() {
        let (registry, calls) = registered(recorder(false, false));
        let (header, payload) = event_for(BackendId::P11.wire_id());
        let events = [RawEvent {
            header,
            payload: &payload,
        }];
        let mut driver = BackendDriver::harness();
        let report = driver
            .run(&registry, &runtime(true), &events)
            .expect("open gates + routed event runs clean");
        assert_eq!(
            *calls.lock().expect("calls mutex"),
            ["detect", "plan", "configure", "decode", "finalize"]
        );
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.plans.len(), 1);
        assert_eq!(report.summaries.len(), 1);
        assert!(report.skipped.is_empty());
        assert_eq!(report.summaries[0].backend, BackendId::P11);
    }

    #[test]
    fn backend_error_aborts_with_attribution_and_no_later_steps() {
        let (registry, calls) = registered(recorder(false, true));
        let (header, payload) = event_for(BackendId::P11.wire_id());
        let events = [RawEvent {
            header,
            payload: &payload,
        }];
        let mut driver = BackendDriver::harness();
        let err = driver
            .run(&registry, &runtime(true), &events)
            .expect_err("failing plan aborts the run");
        assert_eq!(
            err,
            DriverError::Backend {
                backend: BackendId::P11,
                error: BackendError::Unsupported(UnsupportedReason::new("nope")),
            }
        );
        assert_eq!(err.to_string(), "backend p11 failed: unsupported: nope");
        assert_eq!(*calls.lock().expect("calls mutex"), ["detect", "plan"]);
    }

    #[test]
    fn unrouted_event_fails_before_any_backend_runs() {
        let (registry, calls) = registered(recorder(false, false));
        let (header, payload) = event_for(BackendId::KCrypto.wire_id());
        let events = [RawEvent {
            header,
            payload: &payload,
        }];
        let mut driver = BackendDriver::harness();
        let err = driver
            .run(&registry, &runtime(true), &events)
            .expect_err("kcrypto event with only p11 registered is unrouted");
        assert_eq!(
            err,
            DriverError::UnroutedEvent {
                backend_id: BackendId::KCrypto.wire_id(),
            }
        );
        assert!(calls.lock().expect("calls mutex").is_empty());
    }

    #[test]
    fn unsatisfied_static_gates_skip_and_record_the_backend() {
        let (registry, calls) = registered(recorder(true, false));
        let (header, payload) = event_for(BackendId::P11.wire_id());
        let events = [RawEvent {
            header,
            payload: &payload,
        }];
        let mut driver = BackendDriver::harness();
        let report = driver
            .run(&registry, &runtime(false), &events)
            .expect("gate failure skips, not aborts");
        assert_eq!(
            report.skipped,
            vec![SkippedBackend {
                backend: BackendId::P11,
                dropped_events: 1,
            }]
        );
        assert_eq!(report.skipped_drops(), 1);
        assert!(report.observations.is_empty());
        assert!(report.plans.is_empty());
        assert!(report.summaries.is_empty());
        assert!(calls.lock().expect("calls mutex").is_empty());
    }

    #[test]
    fn plan_gate_skip_is_atomic_leaves_no_partial_plans() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut registry = BackendRegistry::new();
        registry
            .register(Box::new(TwoInstance {
                calls: Arc::clone(&calls),
            }))
            .expect("fresh id");
        let (header_a, payload_a) = event_for(BackendId::P11.wire_id());
        let (header_b, payload_b) = event_for(BackendId::P11.wire_id());
        let events = [
            RawEvent {
                header: header_a,
                payload: &payload_a,
            },
            RawEvent {
                header: header_b,
                payload: &payload_b,
            },
        ];
        let mut driver = BackendDriver::harness();
        let report = driver
            .run(&registry, &runtime(false), &events)
            .expect("plan-gate skip, not abort");
        // Both routed events dropped on the skip, receipted for
        // integrity accounting (C11).
        assert_eq!(
            report.skipped,
            vec![SkippedBackend {
                backend: BackendId::P11,
                dropped_events: 2,
            }]
        );
        assert_eq!(report.skipped_drops(), 2);
        assert!(
            report.plans.is_empty(),
            "half-skip published partial plans: {:?}",
            report.plans
        );
        assert!(report.observations.is_empty());
        assert!(report.summaries.is_empty());
        // Both instances planned before the gate tripped; `configure`
        // never ran, so no budget was charged and none needs refunding.
        assert_eq!(
            *calls.lock().expect("calls mutex"),
            ["detect", "plan", "plan"]
        );
    }

    #[test]
    fn driver_and_owned_registry_stay_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BackendDriver>();
        assert_send_sync::<BackendRegistry>();
        assert_send_sync::<Box<dyn Backend>>();
        assert_send_sync::<DriverReport>();
        assert_send_sync::<SkippedBackend>();
    }
}
