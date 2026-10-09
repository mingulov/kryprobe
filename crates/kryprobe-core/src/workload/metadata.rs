// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed metadata snapshots (Stage 2A contract, spec F07): the validated,
//! bounded operator-supplied metadata file input. Files assert; only the
//! resolver's kernel-corroborated joins verify.
//!
//! Pure by construction: no OS reads, no I/O, no ambient clocks. All
//! intervals are monotonic boot-time nanoseconds (the `start_ns` clock
//! domain), never wall clock.

use super::{
    AttributionStatus, ContainerRef, MAX_KERNEL_IDENTITY_BYTES, MAX_METADATA_BYTES,
    MAX_METADATA_ENTRIES, MAX_STRING_FIELD_BYTES, METHOD_METADATA_FILE, METHOD_METADATA_LABEL,
    MetadataUnavailable, PodRef, ValidityInterval, WorkloadIdentity, WorkloadOrigin,
};
use serde::{Deserialize, Serialize};

/// The frozen metadata-file schema bytes compiled into this crate.
const EMBEDDED_METADATA_SCHEMA: &str =
    include_str!("../../../../schemas/workload-metadata-v1.schema.json");

/// Fixed freeze pin (FNV-1a 64 hex) over the metadata schema bytes: any
/// schema edit must update this pin deliberately.
pub const WORKLOAD_METADATA_SCHEMA_FNV1A: &str = "bf8a6a4cba2b04d4";

/// FNV-1a 64 over bytes (drift detection, not security).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Hex hash of the compiled-in frozen metadata schema.
#[must_use]
pub fn metadata_schema_fnv1a_hex() -> String {
    format!("{:016x}", fnv1a64(EMBEDDED_METADATA_SCHEMA.as_bytes()))
}

/// Whether on-disk metadata-schema bytes drifted from the freeze pin.
#[must_use]
pub fn metadata_schema_drifted(schema_disk_bytes: &[u8]) -> bool {
    format!("{:016x}", fnv1a64(schema_disk_bytes)) != WORKLOAD_METADATA_SCHEMA_FNV1A
}

/// Execution-kernel identity carried by a metadata snapshot: either the
/// kernel/boot scope tag the collector observed, or an explicit inability
/// to establish it. `Unknown` never matches a captured key — resolution
/// refuses rather than assuming same-kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelIdentity {
    /// Observed kernel/boot scope tag (1..=128 bytes).
    Known(String),
    /// The collector could not establish the execution kernel.
    Unknown,
}

impl KernelIdentity {
    /// Validate the bound: known tags are non-empty and within
    /// [`MAX_KERNEL_IDENTITY_BYTES`]; unknown is always well-formed.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        match self {
            Self::Known(tag) => {
                if tag.is_empty() || tag.len() > MAX_KERNEL_IDENTITY_BYTES {
                    return Err(MetadataUnavailable::ParseFailed);
                }
                Ok(())
            }
            Self::Unknown => Ok(()),
        }
    }

    /// Whether this snapshot kernel can serve a captured key scoped to
    /// `scope`: exact match only, never prefix or pattern.
    #[must_use]
    pub fn matches_scope(&self, scope: &str) -> bool {
        match self {
            Self::Known(tag) => tag == scope,
            Self::Unknown => false,
        }
    }
}

/// A monotonic-nanosecond interval `[start_ns, end_ns]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotInterval {
    /// Interval start (inclusive).
    pub start_ns: u64,
    /// Interval end (inclusive).
    pub end_ns: u64,
}

impl SnapshotInterval {
    /// Well-ordered (`start <= end`) intervals only.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        if self.start_ns > self.end_ns {
            return Err(MetadataUnavailable::ParseFailed);
        }
        Ok(())
    }

    /// Whether two intervals overlap (either may be unbounded via `None`
    /// on the caller side; missing validity always overlaps).
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start_ns <= other.end_ns && other.start_ns <= self.end_ns
    }
}

/// How one metadata entry's kernel-cgroup association was obtained. File
/// entries assert; `verified` status in a file refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingProvenance {
    /// Method: `metadata_file` or `metadata_label` (frozen vocabulary).
    pub method: String,
    /// Source: always the operator metadata file in M1 snapshots.
    pub source: WorkloadOrigin,
    /// Status: `asserted` or `stale` only — never verified from a file.
    pub status: AttributionStatus,
    /// Validity interval with clock domain, if known.
    #[serde(default)]
    pub validity: Option<ValidityInterval>,
}

impl BindingProvenance {
    /// File-entry provenance rules: frozen method vocabulary, operator
    /// source, asserted-or-stale status, ordered validity.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        if self.method != METHOD_METADATA_FILE && self.method != METHOD_METADATA_LABEL {
            return Err(MetadataUnavailable::ParseFailed);
        }
        if self.source != WorkloadOrigin::OperatorMetadataFile {
            return Err(MetadataUnavailable::ParseFailed);
        }
        if self.status != AttributionStatus::Asserted && self.status != AttributionStatus::Stale {
            return Err(MetadataUnavailable::ParseFailed);
        }
        if let Some(validity) = &self.validity
            && !validity.is_ordered()
        {
            return Err(MetadataUnavailable::ParseFailed);
        }
        Ok(())
    }
}

/// One metadata-file entry: workload associations plus the kernel cgroup
/// they claim, with provenance. All strings are bounded display/identity
/// fields — no paths, no labels beyond the M1 allowlist (`display_name`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEntry {
    /// Claimed container association.
    #[serde(default)]
    pub container: Option<ContainerRef>,
    /// Claimed pod association.
    #[serde(default)]
    pub pod: Option<PodRef>,
    /// Claimed cluster identity.
    #[serde(default)]
    pub cluster: Option<String>,
    /// Claimed node identity.
    #[serde(default)]
    pub node: Option<String>,
    /// Claimed outer-container association (kind nodes).
    #[serde(default)]
    pub ancestor_container: Option<ContainerRef>,
    /// Allowlisted display name (display only, never identity).
    #[serde(default)]
    pub display_name: Option<String>,
    /// Claimed kernel cgroup association.
    #[serde(default)]
    pub cgroup_id: Option<u64>,
    /// How the association was obtained.
    pub binding: BindingProvenance,
}

impl MetadataEntry {
    /// Entry rules: bounded strings, cluster-consistent associations,
    /// valid provenance. Duplicate cgroup claims across entries are NOT
    /// refused here — the resolver qualifies them ambiguous.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        for field in [
            self.container
                .as_ref()
                .map(|c| c.runtime.as_str())
                .unwrap_or(""),
            self.container.as_ref().map(|c| c.id.as_str()).unwrap_or(""),
            self.container
                .as_ref()
                .and_then(|c| c.lifetime.as_deref())
                .unwrap_or(""),
            self.pod.as_ref().map(|p| p.cluster.as_str()).unwrap_or(""),
            self.pod.as_ref().map(|p| p.uid.as_str()).unwrap_or(""),
            self.pod.as_ref().map(|p| p.name.as_str()).unwrap_or(""),
            self.pod
                .as_ref()
                .map(|p| p.namespace.as_str())
                .unwrap_or(""),
            self.cluster.as_deref().unwrap_or(""),
            self.node.as_deref().unwrap_or(""),
            self.ancestor_container
                .as_ref()
                .map(|c| c.runtime.as_str())
                .unwrap_or(""),
            self.ancestor_container
                .as_ref()
                .map(|c| c.id.as_str())
                .unwrap_or(""),
            self.ancestor_container
                .as_ref()
                .and_then(|c| c.lifetime.as_deref())
                .unwrap_or(""),
            self.display_name.as_deref().unwrap_or(""),
            self.binding.method.as_str(),
        ] {
            if field.len() > MAX_STRING_FIELD_BYTES {
                return Err(MetadataUnavailable::BudgetExceeded);
            }
        }
        let identity = WorkloadIdentity {
            container: self.container.clone(),
            pod: self.pod.clone(),
            cluster: self.cluster.clone(),
            node: self.node.clone(),
            ancestor_container: self.ancestor_container.clone(),
        };
        if !identity.check_consistency() {
            return Err(MetadataUnavailable::ParseFailed);
        }
        self.binding.validate()
    }
}

/// A validated operator-supplied metadata snapshot (spec §5.7): collector
/// identity, snapshot interval, execution-kernel identity (or explicit
/// inability), and bounded asserted entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataSnapshot {
    /// Collector/source identity (non-empty, bounded).
    pub collector: String,
    /// The interval this snapshot claims to cover (monotonic ns).
    pub snapshot_interval: SnapshotInterval,
    /// Execution-kernel identity, or explicit inability.
    pub kernel_identity: KernelIdentity,
    /// Asserted entries (bounded count).
    pub entries: Vec<MetadataEntry>,
}

impl MetadataSnapshot {
    /// Snapshot rules: non-empty bounded collector, ordered interval,
    /// valid kernel identity, bounded entries, every entry valid.
    pub fn validate(&self) -> Result<(), MetadataUnavailable> {
        if self.collector.is_empty() || self.collector.len() > MAX_STRING_FIELD_BYTES {
            return Err(MetadataUnavailable::ParseFailed);
        }
        self.snapshot_interval.validate()?;
        self.kernel_identity.validate()?;
        if self.entries.len() > MAX_METADATA_ENTRIES {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }

    /// Encoded byte length of this snapshot (JSON).
    pub fn encoded_len(&self) -> Result<usize, MetadataUnavailable> {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .map_err(|_| MetadataUnavailable::ParseFailed)
    }

    /// Full wire validation: parsed-value rules plus the byte budget.
    pub fn validate_wire(&self) -> Result<(), MetadataUnavailable> {
        self.validate()?;
        if self.encoded_len()? > MAX_METADATA_BYTES {
            return Err(MetadataUnavailable::BudgetExceeded);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> MetadataEntry {
        MetadataEntry {
            container: None,
            pod: None,
            cluster: None,
            node: None,
            ancestor_container: None,
            display_name: Some("web-0".to_string()),
            cgroup_id: Some(43812),
            binding: BindingProvenance {
                method: METHOD_METADATA_FILE.to_string(),
                source: WorkloadOrigin::OperatorMetadataFile,
                status: AttributionStatus::Asserted,
                validity: None,
            },
        }
    }

    fn snapshot() -> MetadataSnapshot {
        MetadataSnapshot {
            collector: "docker-fixture-v1".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: 1000,
                end_ns: 2000,
            },
            kernel_identity: KernelIdentity::Known("kernel-A".to_string()),
            entries: vec![entry()],
        }
    }

    #[test]
    fn valid_snapshot_passes() {
        assert!(snapshot().validate().is_ok());
    }

    #[test]
    fn metadata_schema_freeze_pin_is_fixed() {
        assert_eq!(metadata_schema_fnv1a_hex(), WORKLOAD_METADATA_SCHEMA_FNV1A);
        assert!(!metadata_schema_drifted(
            EMBEDDED_METADATA_SCHEMA.as_bytes()
        ));
        assert!(metadata_schema_drifted(b"{tampered}"));
    }

    #[test]
    fn kernel_scope_match_is_exact() {
        let known = KernelIdentity::Known("kernel-A".to_string());
        assert!(known.matches_scope("kernel-A"));
        assert!(!known.matches_scope("kernel-A-extra"));
        assert!(!known.matches_scope("kernel-"));
        assert!(!known.matches_scope(""));
        assert!(!KernelIdentity::Unknown.matches_scope("kernel-A"));
        assert!(KernelIdentity::Known(String::new()).validate().is_err());
        assert!(
            KernelIdentity::Known("k".repeat(MAX_KERNEL_IDENTITY_BYTES + 1))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn inverted_interval_refuses() {
        let mut bad = snapshot();
        bad.snapshot_interval = SnapshotInterval {
            start_ns: 2000,
            end_ns: 1000,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn verified_status_in_file_refuses() {
        let mut bad = snapshot();
        bad.entries[0].binding.status = AttributionStatus::Verified;
        assert!(bad.validate().is_err());
        let mut bad = snapshot();
        bad.entries[0].binding.status = AttributionStatus::Unresolved;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn foreign_provenance_in_file_refuses() {
        let mut bad = snapshot();
        bad.entries[0].binding.method = "captured_cgroup".to_string();
        assert!(bad.validate().is_err());
        let mut bad = snapshot();
        bad.entries[0].binding.source = WorkloadOrigin::HostProc;
        assert!(bad.validate().is_err());
        let mut bad = snapshot();
        bad.entries[0].binding.validity = Some(ValidityInterval::monotonic(200, 100));
        assert!(bad.validate().is_err());
    }

    #[test]
    fn contradictory_cluster_sources_refuse() {
        let mut bad = snapshot();
        bad.entries[0].cluster = Some("cluster-a".to_string());
        bad.entries[0].pod = Some(super::PodRef {
            cluster: "cluster-b".to_string(),
            uid: "uid-1".to_string(),
            name: "api".to_string(),
            namespace: "production".to_string(),
        });
        assert!(bad.validate().is_err());
        let mut ok = snapshot();
        ok.entries[0].cluster = Some("cluster-a".to_string());
        ok.entries[0].pod = Some(super::PodRef {
            cluster: "cluster-a".to_string(),
            uid: "uid-1".to_string(),
            name: "api".to_string(),
            namespace: "production".to_string(),
        });
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn oversized_entry_string_is_budget_exceeded() {
        let mut bad = snapshot();
        bad.entries[0].display_name = Some("d".repeat(MAX_STRING_FIELD_BYTES + 1));
        assert_eq!(bad.validate(), Err(MetadataUnavailable::BudgetExceeded));
    }

    #[test]
    fn entry_count_bound_is_enforced() {
        let mut bad = snapshot();
        bad.entries = vec![entry(); MAX_METADATA_ENTRIES + 1];
        assert_eq!(bad.validate(), Err(MetadataUnavailable::BudgetExceeded));
        let mut ok = snapshot();
        ok.entries = vec![entry(); MAX_METADATA_ENTRIES];
        assert!(ok.validate().is_ok());
    }
}
