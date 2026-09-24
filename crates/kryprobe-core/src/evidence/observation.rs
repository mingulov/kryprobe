// SPDX-License-Identifier: GPL-3.0-or-later
//! Native observations: one backend's facts about one call boundary.
//!
//! Follows CONTRACTS §5. `native_code` stays a JSON number: it is a domain
//! code, not a nanosecond or counter value.

use crate::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
use crate::ids::{CorrelationId, ImplementationId, ObjectId, ObservationId, TargetId};
use serde::{Deserialize, Serialize};

/// Allowlisted safe native name (schema `safe_name` shape: 1–96 chars).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeTextId(String);

impl SafeTextId {
    /// Accept non-empty printable ASCII of at most 96 bytes; else `None`.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let shaped = !text.is_empty()
            && text.len() <= 96
            && text.bytes().all(|b| b.is_ascii_graphic() || b == b' ');
        if shaped {
            Some(Self(text.to_owned()))
        } else {
            None
        }
    }

    /// Borrow the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SafeTextId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).ok_or_else(|| serde::de::Error::custom("safe_name shape violated"))
    }
}

/// Binding of an observation to its BPF correlation frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationRef {
    /// Session correlation identity shared with relationship records.
    pub correlation: CorrelationId,
}

impl CorrelationRef {
    /// Bind an observation to a correlation identity.
    #[must_use]
    pub const fn new(correlation: CorrelationId) -> Self {
        Self { correlation }
    }
}

/// Opaque integrity-ledger generation pinning an observation to counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntegrityRef {
    /// Monotonic integrity-ledger generation at observation time.
    pub generation: u64,
}

impl IntegrityRef {
    /// Pin an observation to an integrity-ledger generation.
    #[must_use]
    pub const fn new(generation: u64) -> Self {
        Self { generation }
    }
}

/// Backend-owned extra facts; small, secret-free JSON (`Null` when empty).
pub type BackendPayload = serde_json::Value;

/// Shared payload-string lookup (1A-L5): `Some` for present strings
/// (including `""`), `None` for missing or non-string values.
/// Policy matches on the `&str` flavor (`.unwrap_or("")`), render
/// owns the `Option<String>` flavor (`.map(str::to_owned)`).
#[must_use]
pub fn payload_str_opt<'a>(payload: &'a BackendPayload, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(serde_json::Value::as_str)
}

/// Domain-native result value; success is derived, never stored here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NativeResult {
    /// PKCS#11 `CK_RV`. Compatibility-only: decodes legacy data;
    /// no p11 backend ships (ADR-0004).
    P11 {
        /// Raw `CK_RV` value.
        rv: u64,
    },
    /// OpenSSL callback return code. Reserved: no backend ships
    /// (ADR-0004); kept for wire stability and legacy data.
    OpenSsl {
        /// Raw callback return value.
        code: i32,
    },
    /// Kernel-crypto status (0 or negative errno; `-EINPROGRESS` = pending).
    KCrypto {
        /// Raw completion status.
        status: i32,
    },
    /// Synthetic scripted result (test-only backends).
    Synthetic {
        /// Scripted return code.
        code: i32,
    },
}

/// One backend's native facts about one observed call (CONTRACTS §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeObservation {
    /// Session-scoped observation identity.
    pub id: ObservationId,
    /// Backend that produced this observation.
    pub backend: BackendId,
    /// Attributed target, when known.
    pub target: Option<TargetId>,
    /// Attributed object, when known.
    pub object: Option<ObjectId>,
    /// Attributed implementation, when known.
    pub implementation: Option<ImplementationId>,
    /// Evidence-ladder phase reached.
    pub phase: EvidencePhase,
    /// API-shape classification of the call.
    pub call_kind: CallKind,
    /// Cryptographic operation class.
    pub operation_class: OperationClass,
    /// Safe native function/operation name, when known.
    pub native_name: Option<SafeTextId>,
    /// Raw native code (domain value, not ns/count).
    pub native_code: Option<u64>,
    /// Domain-native result; success derives from this plus call kind.
    pub native_result: NativeResult,
    /// Observation start, monotonic nanoseconds (JSON string).
    #[serde(default, with = "crate::evidence::wire::opt_u64_string")]
    pub started_ns: Option<u64>,
    /// Observation end, monotonic nanoseconds (JSON string).
    #[serde(default, with = "crate::evidence::wire::opt_u64_string")]
    pub ended_ns: Option<u64>,
    /// Correlation-frame binding, when assigned.
    pub correlation: Option<CorrelationRef>,
    /// Integrity-ledger generation at observation time.
    pub integrity: IntegrityRef,
    /// Backend-owned extra facts.
    pub backend_payload: BackendPayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_str_opt_distinguishes_missing_and_empty() {
        // 1A-L5: the shared lookup — Some("") for present-empty,
        // None for missing or non-string.
        let payload = serde_json::json!({"a": "x", "e": "", "n": 1});
        assert_eq!(payload_str_opt(&payload, "a"), Some("x"));
        assert_eq!(payload_str_opt(&payload, "e"), Some(""));
        assert_eq!(payload_str_opt(&payload, "n"), None);
        assert_eq!(payload_str_opt(&payload, "missing"), None);
    }
}
