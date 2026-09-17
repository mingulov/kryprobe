// SPDX-License-Identifier: GPL-3.0-or-later
//! Core enums (CONTRACTS §2).
//!
//! Wire spellings are exactly the `schemas/event-v0.schema.json` enum
//! strings. `EvidencePhase::Succeeded` is Rust-only and never serializes.

use serde::{Deserialize, Serialize};

mod backend_id;

pub use backend_id::BackendId;

/// Capture depth requested for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMode {
    /// Catalog implementations without executing them.
    Inventory,
    /// Aggregate counts with sampled detail.
    Profile,
    /// Full per-operation observation detail.
    Trace,
}

/// Population selector used to start a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetSelector {
    /// KryProbe spawns and owns the observed process.
    #[serde(rename = "owned_run")]
    OwnedRun,
    /// One explicit process ID.
    #[serde(rename = "pid")]
    Pid,
    /// A process tree rooted at one process.
    #[serde(rename = "tree")]
    ProcessTree,
    /// A cgroup subtree.
    #[serde(rename = "cgroup")]
    Cgroup,
}

/// Evidence ladder phase (CONTRACTS §7).
///
/// The wire carries only the five observable phases; `Succeeded` is derived
/// in Rust when the native result establishes success, and serializing it is
/// a defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidencePhase {
    /// An implementation, path, or object was found.
    Discovered,
    /// A selection, fetch, or allocation result was observed.
    Selected,
    /// An implementation callback or API boundary was entered.
    Entered,
    /// The observed function returned with a native result.
    Returned,
    /// The backend's operation-completion condition occurred.
    Completed,
    /// Rust-only: the native result establishes success. Never serialized.
    Succeeded,
}

const PHASE_WIRE_STRS: [&str; 5] = ["discovered", "selected", "entered", "returned", "completed"];

impl EvidencePhase {
    /// Wire spelling, or `None` for the internal `Succeeded` phase.
    #[must_use]
    pub const fn as_wire_str(self) -> Option<&'static str> {
        match self {
            Self::Discovered => Some(PHASE_WIRE_STRS[0]),
            Self::Selected => Some(PHASE_WIRE_STRS[1]),
            Self::Entered => Some(PHASE_WIRE_STRS[2]),
            Self::Returned => Some(PHASE_WIRE_STRS[3]),
            Self::Completed => Some(PHASE_WIRE_STRS[4]),
            Self::Succeeded => None,
        }
    }

    /// Parse a wire spelling; `None` for anything else, including `succeeded`.
    #[must_use]
    pub fn from_wire_str(text: &str) -> Option<Self> {
        match text {
            "discovered" => Some(Self::Discovered),
            "selected" => Some(Self::Selected),
            "entered" => Some(Self::Entered),
            "returned" => Some(Self::Returned),
            "completed" => Some(Self::Completed),
            _ => None,
        }
    }
}

impl Serialize for EvidencePhase {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.as_wire_str() {
            Some(wire) => serializer.serialize_str(wire),
            None => Err(serde::ser::Error::custom(
                "defect: EvidencePhase::Succeeded is internal and never serialized",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for EvidencePhase {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_wire_str(&text)
            .ok_or_else(|| serde::de::Error::unknown_variant(&text, &PHASE_WIRE_STRS))
    }
}

/// API-shape classification of one observed call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    /// Single-shot operation call.
    Operation,
    /// Operation initialization call.
    Initialization,
    /// Output-size query call (for example a `NULL` output pointer).
    SizeQuery,
    /// Incremental update call.
    Update,
    /// Finalization call.
    Finalization,
    /// Call kind could not be determined.
    Unknown,
}

/// Per-dimension coverage status (CONTRACTS §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// Complete within the declared boundary.
    CompleteForDeclaredBoundary,
    /// Partially covered; omissions recorded.
    Partial,
    /// Declared boundary is not supported.
    Unsupported,
    /// Dimension was not run.
    NotRun,
    /// Coverage state could not be determined.
    Unknown,
}

/// Cryptographic operation class; exactly the 13 frozen-schema variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationClass {
    #[serde(rename = "sign")]
    Sign,
    #[serde(rename = "verify")]
    Verify,
    #[serde(rename = "encrypt")]
    Encrypt,
    #[serde(rename = "decrypt")]
    Decrypt,
    #[serde(rename = "digest")]
    Digest,
    #[serde(rename = "mac")]
    Mac,
    #[serde(rename = "kdf")]
    Kdf,
    #[serde(rename = "key_agreement")]
    KeyAgreement,
    #[serde(rename = "kem_encapsulate")]
    KemEncapsulate,
    #[serde(rename = "kem_decapsulate")]
    KemDecapsulate,
    #[serde(rename = "random")]
    Random,
    #[serde(rename = "key_management")]
    KeyManagement,
    #[serde(rename = "unknown")]
    Unknown,
}
