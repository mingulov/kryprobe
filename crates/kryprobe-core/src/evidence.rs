// SPDX-License-Identifier: GPL-3.0-or-later
//! Evidence model: observations, catalog, coverage, integrity, relationships.
//!
//! Follows CONTRACTS §5–§10. Nanosecond and counter fields serialize as
//! JSON strings per the frozen schema, never as numbers.

pub mod catalog;
pub mod coverage;
pub mod integrity;
pub mod observation;
pub mod relationship;

pub use catalog::{ImplementationRecord, ImplementationResolution};
pub use coverage::{CoverageSummary, DimensionCounter, DimensionCoverage};
pub use integrity::IntegritySummary;
pub use observation::{
    BackendPayload, CorrelationRef, IntegrityRef, NativeObservation, NativeResult, SafeTextId,
};
pub use relationship::{
    RelationshipConfidence, RelationshipEvidence, RelationshipKind, RelationshipRecord,
};

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Opaque omission identity; displays as `omission:<n>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OmissionId(u64);

impl OmissionId {
    /// Wrap a raw omission value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Unwrap the raw omission value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for OmissionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "omission:{}", self.0)
    }
}

/// Rejection message for a malformed `omission:<int>` string.
fn bad_id(text: &str) -> String {
    format!("invalid id: expected `omission:<int>`, found `{text}`")
}

impl FromStr for OmissionId {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let digits = match text.strip_prefix("omission:") {
            Some(digits) => digits,
            None => return Err(bad_id(text)),
        };
        let shaped = !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit());
        if !shaped {
            return Err(bad_id(text));
        }
        match digits.parse::<u64>() {
            Ok(value) => Ok(Self(value)),
            Err(_) => Err(bad_id(text)),
        }
    }
}

impl Serialize for OmissionId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OmissionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Validity interval in monotonic nanoseconds (JSON strings on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidityInterval {
    /// Interval start, monotonic nanoseconds.
    #[serde(with = "wire::u64_string")]
    pub start_ns: u64,
    /// Interval end, or `None` while still valid.
    #[serde(default, with = "wire::opt_u64_string")]
    pub end_ns: Option<u64>,
}

/// JSON-string integer encoding: the frozen schema spells ns/counts as
/// decimal strings (`^(0|[1-9][0-9]*)$`). Output is always canonical;
/// input parses any decimal `u64` spelling.
pub(crate) mod wire {
    use serde::{Deserialize, Deserializer, Serializer};

    pub mod u64_string {
        use super::*;

        pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&value.to_string())
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
            let text = String::deserialize(deserializer)?;
            text.parse().map_err(serde::de::Error::custom)
        }
    }

    pub mod opt_u64_string {
        use super::*;

        pub fn serialize<S: Serializer>(
            value: &Option<u64>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => serializer.serialize_str(&value.to_string()),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<u64>, D::Error> {
            let text: Option<String> = Option::deserialize(deserializer)?;
            text.map(|text| text.parse().map_err(serde::de::Error::custom))
                .transpose()
        }
    }
}
