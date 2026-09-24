// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-operation records: `operation_observation` and `relationship`.
//!
//! Outcome/result derivation: pre-return phases carry a null native result
//! (`pending` once entered, `not_applicable` before); returned/completed
//! phases derive the outcome from the native result (OpenSSL `1` is success
//! per the pack example; kcrypto `-EINPROGRESS` is pending).

use crate::writer::{JsonlWriter, ReportError};
use kryprobe_core::enums::EvidencePhase;
use kryprobe_core::evidence::{NativeObservation, NativeResult};
use serde::Serialize;

/// Wire-only observation context with no core counterpart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationExtra {
    /// Boundary crossed (schema `boundary` enum).
    pub boundary: String,
    /// Native operation name (e.g. `"C_Sign"`).
    pub native_operation: String,
    /// Native algorithm name, or `None` for null.
    pub algorithm_native: Option<String>,
    /// Canonical algorithm id, or `None` for null.
    pub algorithm_canonical: Option<String>,
    /// Algorithm resolution (schema enum).
    pub algorithm_resolution: String,
}

#[derive(Serialize)]
struct AlgorithmPayload<'a> {
    safe_native_name: Option<&'a str>,
    canonical_id: Option<&'a str>,
    resolution: &'a str,
}

#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct ObsPayload<'a> {
    observation_id: String,
    target_id: Option<String>,
    implementation_id: Option<String>,
    backend: &'a str,
    boundary: &'a str,
    phase: &'a str,
    call_kind: kryprobe_core::enums::CallKind,
    operation_class: kryprobe_core::enums::OperationClass,
    outcome: &'a str,
    native_namespace: &'static str,
    native_operation: &'a str,
    native_result: Option<String>,
    algorithm: AlgorithmPayload<'a>,
    duration_ns: Option<String>,
}

/// kcrypto pending status (`-EINPROGRESS`); any other negative fails.
const EINPROGRESS: i32 = 115;

fn outcome_of(result: NativeResult) -> &'static str {
    match result {
        NativeResult::P11 { rv } => {
            if rv == 0 {
                "success"
            } else {
                "failure"
            }
        }
        NativeResult::OpenSsl { code } => {
            if code == 1 {
                "success"
            } else {
                "failure"
            }
        }
        NativeResult::KCrypto { status } => {
            if status == 0 {
                "success"
            } else if status == -EINPROGRESS {
                "pending"
            } else {
                "failure"
            }
        }
        NativeResult::Synthetic { code } => {
            if code == 0 {
                "success"
            } else {
                "failure"
            }
        }
    }
}

fn result_string(result: NativeResult) -> String {
    match result {
        NativeResult::P11 { rv } => {
            if rv == 0 {
                "CKR_OK".to_owned()
            } else {
                format!("0x{rv:x}")
            }
        }
        NativeResult::OpenSsl { code } => code.to_string(),
        NativeResult::KCrypto { status } => status.to_string(),
        NativeResult::Synthetic { code } => code.to_string(),
    }
}

fn namespace_of(result: NativeResult) -> &'static str {
    match result {
        NativeResult::P11 { .. } => "pkcs11",
        NativeResult::OpenSsl { .. } => "openssl-provider",
        NativeResult::KCrypto { .. } => "kcrypto",
        NativeResult::Synthetic { .. } => "synthetic",
    }
}

impl JsonlWriter {
    /// Appends `operation_observation`; `Synthetic`/`Succeeded` fail closed.
    /// The result variant is cross-checked too: a test-only `Synthetic`
    /// result on a real backend (exactly what the driver test double
    /// emits) refuses rather than stamping `synthetic` into
    /// `native_namespace`.
    pub fn observation(
        &mut self,
        obs: &NativeObservation,
        extra: &ObservationExtra,
    ) -> Result<(), ReportError> {
        let Some(backend) = obs.backend.as_wire_str() else {
            return Err(ReportError::SyntheticBackend);
        };
        if matches!(obs.native_result, NativeResult::Synthetic { .. }) {
            return Err(ReportError::SyntheticResult);
        }
        let Some(phase) = obs.phase.as_wire_str() else {
            return Err(ReportError::SucceededPhase);
        };
        // F01: a canonical class representative is not an exact native
        // errno — export null rather than an unqualified code.
        let canonical = obs
            .backend_payload
            .get("status_canonical")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let (outcome, native_result) = match obs.phase {
            EvidencePhase::Discovered | EvidencePhase::Selected => ("not_applicable", None),
            EvidencePhase::Entered => ("pending", None),
            EvidencePhase::Returned | EvidencePhase::Completed => {
                let native = (!canonical).then(|| result_string(obs.native_result));
                (outcome_of(obs.native_result), native)
            }
            EvidencePhase::Succeeded => return Err(ReportError::SucceededPhase),
        };
        // F01: api-returns rows carry aggregate window bounds, never a
        // per-request duration — export null rather than window width.
        let api_returns = obs
            .backend_payload
            .get("capture_profile")
            .and_then(serde_json::Value::as_str)
            == Some("api-returns");
        let duration_ns = match (obs.started_ns, obs.ended_ns) {
            (Some(start), Some(end)) if !api_returns => Some(end.saturating_sub(start).to_string()),
            _ => None,
        };
        self.emit(
            "operation_observation",
            ObsPayload {
                observation_id: obs.id.to_string(),
                target_id: obs.target.map(|id| id.to_string()),
                implementation_id: obs.implementation.map(|id| id.to_string()),
                backend,
                boundary: &extra.boundary,
                phase,
                call_kind: obs.call_kind,
                operation_class: obs.operation_class,
                outcome,
                native_namespace: namespace_of(obs.native_result),
                native_operation: &extra.native_operation,
                native_result,
                algorithm: AlgorithmPayload {
                    safe_native_name: extra.algorithm_native.as_deref(),
                    canonical_id: extra.algorithm_canonical.as_deref(),
                    resolution: &extra.algorithm_resolution,
                },
                duration_ns,
            },
        )?;
        Ok(())
    }
}
