// SPDX-License-Identifier: GPL-3.0-or-later
//! Evidence model: observations, catalog, coverage, integrity, relationships.
//!
//! Follows CONTRACTS §5–§10. Nanosecond and counter fields serialize as
//! JSON strings per the frozen schema, never as numbers.

pub mod catalog;
pub mod coverage;
pub mod integrity;
pub mod observation;
pub mod payload_keys;
pub mod relationship;

pub use catalog::{ImplementationRecord, ImplementationResolution};
pub use coverage::{CoverageDimension, CoverageSummary, DimensionCounter, DimensionCoverage};
pub use integrity::{IntegritySummary, SharedLosses};
pub use observation::{
    BackendPayload, CorrelationRef, IntegrityRef, NativeObservation, NativeResult, SafeTextId,
};
pub use relationship::{
    RelationshipConfidence, RelationshipEvidence, RelationshipKind, RelationshipRecord,
};

use crate::ids::IdParseError;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

crate::define_id!(OmissionId, u64, "omission");

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

#[cfg(test)]
mod tests {
    use super::OmissionId;
    use crate::ids::IdParseError;

    #[test]
    fn omission_id_rejects_with_typed_error() {
        let err: IdParseError = "target:7".parse::<OmissionId>().unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid id: expected `omission:<int>`, found `target:7`"
        );
    }
}
