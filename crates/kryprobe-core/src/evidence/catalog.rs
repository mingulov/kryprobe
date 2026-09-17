// SPDX-License-Identifier: GPL-3.0-or-later
//! Implementation catalog: which boundaries can be attributed.
//!
//! Follows CONTRACTS §6 and the frozen `implementation_catalog` record.
//! Algorithm-candidate sets and callback descriptors live in backend-owned
//! state (CONTRACTS §11); execution counts live in observations/aggregates.

use crate::enums::BackendId;
use crate::evidence::{SafeTextId, ValidityInterval};
use crate::ids::{ImplementationId, ObjectId};
use serde::{Deserialize, Serialize};

/// How precisely an implementation is resolved (frozen wire spellings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImplementationResolution {
    /// Exact object file plus exact callback.
    #[serde(rename = "exact_object_callback")]
    ExactObjectCallback,
    /// Exact object file plus exact symbol.
    #[serde(rename = "exact_object_symbol")]
    ExactObjectSymbol,
    /// Observed selected/fetched, nothing more.
    #[serde(rename = "selected_only")]
    SelectedOnly,
    /// Resolution could not be determined.
    #[serde(rename = "unknown")]
    Unknown,
}

/// One attributable implementation boundary (CONTRACTS §6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImplementationRecord {
    /// Session-scoped implementation identity.
    pub id: ImplementationId,
    /// Backend that owns this boundary.
    pub backend: BackendId,
    /// Object file carrying the implementation.
    pub object: ObjectId,
    /// Allowlisted human-readable name.
    pub safe_name: SafeTextId,
    /// How precisely the boundary is resolved.
    pub resolution: ImplementationResolution,
    /// Interval during which this record holds.
    pub validity: ValidityInterval,
}
