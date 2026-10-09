// SPDX-License-Identifier: GPL-3.0-or-later
//! Report codec (M1 Stage 2C): typed reports to v2 bytes (live output)
//! and v2 bytes back to typed reports (offline replay).
//!
//! Encode builds the exact v2 wire shape (digit-string magnitudes, the
//! `native`/`native_ref` identity XOR, closed objects) and enforces the
//! byte budget. Decode enforces the byte budget BEFORE parsing, runs the
//! frozen v2 validator, and only then converts — malformed, truncated,
//! oversized, or contradictory input refuses typed, never yields a
//! partial report. Both directions are pure over caller bytes: replay
//! performs no host or runtime queries.
//!
//! Streaming output propagates every I/O failure: short writes, EPIPE,
//! flush failures, and disk-full surface as [`WorkloadWriteError::Io`]
//! with the original [`std::io::ErrorKind`] intact. No clean terminal
//! result follows failed output — the write returns `Err`.

use super::model::{
    CoverageLevel, GroupBy, MetadataAvailability, NativeIdentity, ReportCoverage, ReportInterval,
    ReportLedger, ReportRow, ReportScope, ReportSession, WorkloadBuildError, WorkloadReport,
    WorkloadSelector,
};
use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, ContainerRef, ContextIdentity, ExecutionKind,
    MAX_REPORT_V2_BYTES, MAX_V2_CONTEXT_ROWS, MAX_V2_DICTIONARY_ENTRIES, MetadataUnavailable,
    ObservationBoundary, PodRef, Relationship, ScopePartition, SnapshotConsistency,
    ValidityInterval, WorkloadIdentity, WorkloadObservation, WorkloadOrigin,
};
use serde_json::{Map, Value};
use std::io::{Read, Write};

/// Typed decode/replay refusal. Diagnostics are static: counts and rule
/// names only, never input bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadDecodeError {
    /// Input exceeds the 1 MiB report budget (refused before parsing).
    TooLarge,
    /// The reader failed mid-stream.
    Unreadable,
    /// Input is not JSON (covers truncation that breaks syntax).
    Malformed,
    /// Input parses but the frozen v2 validator reports defects (count
    /// only — findings never echo input bytes).
    SchemaDefects {
        /// Number of validator findings.
        count: usize,
    },
    /// A validated row's identity contradicts its evidence (frozen
    /// observation coherence, enforced symmetric with assembly).
    IncoherentRow,
    /// Two rows share one accounting key (refused symmetric with
    /// assembly: merging would corrupt rows).
    DuplicateContext,
    /// A validated value still fails typed conversion (defensive: the
    /// validator accepts only convertible shapes).
    Inconsistent,
}

impl std::fmt::Display for WorkloadDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "report exceeds 1048576 bytes"),
            Self::Unreadable => write!(f, "report reader failed"),
            Self::Malformed => write!(f, "report is not valid JSON"),
            Self::SchemaDefects { count } => {
                write!(f, "workload-report-v2 schema defects: {count}")
            }
            Self::IncoherentRow => write!(f, "row identity contradicts its evidence"),
            Self::DuplicateContext => write!(f, "two rows share one accounting key"),
            Self::Inconsistent => write!(f, "report value contradicts its validated shape"),
        }
    }
}

impl std::error::Error for WorkloadDecodeError {}

/// Typed streaming-output failure: encode refusals plus raw I/O errors
/// with their original [`std::io::ErrorKind`] preserved (callers match
/// on [`std::io::ErrorKind::BrokenPipe`], `StorageFull`, `WriteZero`,
/// and flush failures distinctly).
#[derive(Debug)]
pub enum WorkloadWriteError {
    /// The report refused to encode (budget or shape).
    Encode(WorkloadBuildError),
    /// The underlying writer failed (kind preserved).
    Io(std::io::Error),
}

impl std::fmt::Display for WorkloadWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(err) => write!(f, "report encode failed: {err}"),
            Self::Io(err) => write!(f, "report output failed: {err}"),
        }
    }
}

impl std::error::Error for WorkloadWriteError {}

// ---------------------------------------------------------------------------
// Wire literals (one direction each; the frozen validator is the checker
// and the roundtrip tests prove these spellings against it).
// ---------------------------------------------------------------------------

fn consistency_wire(consistency: SnapshotConsistency) -> &'static str {
    match consistency {
        SnapshotConsistency::Quiescent => "quiescent",
        SnapshotConsistency::Unproven => "unproven",
    }
}

fn execution_kind_wire(kind: ExecutionKind) -> &'static str {
    match kind {
        ExecutionKind::Proc => "proc",
        ExecutionKind::Kthread => "kthread",
        ExecutionKind::Softirq => "softirq",
        ExecutionKind::Unknown => "unknown",
    }
}

fn relationship_wire(relationship: Relationship) -> &'static str {
    match relationship {
        Relationship::HookContext => "hook_context",
        Relationship::Submitter => "submitter",
        Relationship::CompletionContext => "completion_context",
        Relationship::WorkloadOrigin => "workload_origin",
        Relationship::Consumer => "consumer",
    }
}

fn origin_wire(origin: WorkloadOrigin) -> &'static str {
    match origin {
        WorkloadOrigin::KernelCapture => "kernel_capture",
        WorkloadOrigin::OperatorMetadataFile => "operator_metadata_file",
        WorkloadOrigin::RuntimeAdapter => "runtime_adapter",
        WorkloadOrigin::HostProc => "host_proc",
        WorkloadOrigin::Unknown => "unknown",
    }
}

fn status_wire(status: AttributionStatus) -> &'static str {
    match status {
        AttributionStatus::Verified => "verified",
        AttributionStatus::Asserted => "asserted",
        AttributionStatus::Unresolved => "unresolved",
        AttributionStatus::Ambiguous => "ambiguous",
        AttributionStatus::Stale => "stale",
        AttributionStatus::Unsupported => "unsupported",
    }
}

fn coverage_wire(level: CoverageLevel) -> &'static str {
    match level {
        CoverageLevel::Complete => "complete",
        CoverageLevel::Partial => "partial",
        CoverageLevel::Unavailable => "unavailable",
    }
}

fn unavailability_reason_wire(reason: MetadataUnavailable) -> &'static str {
    match reason {
        MetadataUnavailable::NoPrincipal => "no_principal",
        MetadataUnavailable::HelperRefused => "helper_refused",
        MetadataUnavailable::BudgetExceeded => "budget_exceeded",
        MetadataUnavailable::UnsupportedEnvironment => "unsupported_environment",
        MetadataUnavailable::ParseFailed => "parse_failed",
    }
}

fn boundary_wire(boundary: ObservationBoundary) -> &'static str {
    match boundary {
        ObservationBoundary::ApiReturn => "api_return",
    }
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Digit-string magnitude (v2 carries `u64` without JSON precision loss).
fn digit(value: u64) -> Value {
    Value::String(value.to_string())
}

fn encode_container(container: &ContainerRef) -> Value {
    let mut obj = Map::new();
    obj.insert(
        "runtime".to_string(),
        Value::String(container.runtime.clone()),
    );
    obj.insert("id".to_string(), Value::String(container.id.clone()));
    if let Some(lifetime) = container.lifetime.as_deref().filter(|l| !l.is_empty()) {
        obj.insert("lifetime".to_string(), Value::String(lifetime.to_string()));
    }
    Value::Object(obj)
}

fn encode_identity(identity: &WorkloadIdentity) -> Value {
    let mut obj = Map::new();
    if let Some(container) = &identity.container {
        obj.insert("container".to_string(), encode_container(container));
    }
    if let Some(pod) = &identity.pod {
        obj.insert(
            "pod".to_string(),
            serde_json::json!({
                "cluster": pod.cluster,
                "uid": pod.uid,
                "name": pod.name,
                "namespace": pod.namespace,
            }),
        );
    }
    if let Some(cluster) = &identity.cluster {
        obj.insert("cluster".to_string(), Value::String(cluster.clone()));
    }
    if let Some(node) = &identity.node {
        obj.insert("node".to_string(), Value::String(node.clone()));
    }
    if let Some(ancestor) = &identity.ancestor_container {
        obj.insert("ancestor_container".to_string(), encode_container(ancestor));
    }
    Value::Object(obj)
}

fn encode_evidence(evidence: &AttributionEvidence) -> Value {
    let mut obj = Map::new();
    obj.insert(
        "relationship".to_string(),
        Value::String(relationship_wire(evidence.relationship).to_string()),
    );
    obj.insert("method".to_string(), Value::String(evidence.method.clone()));
    obj.insert(
        "source".to_string(),
        Value::String(origin_wire(evidence.source).to_string()),
    );
    obj.insert(
        "status".to_string(),
        Value::String(status_wire(evidence.status).to_string()),
    );
    if let Some(validity) = &evidence.validity {
        obj.insert(
            "validity".to_string(),
            serde_json::json!({
                "start_ns": validity.start_ns.to_string(),
                "end_ns": validity.end_ns.to_string(),
                "clock": "monotonic_boot",
            }),
        );
    }
    Value::Object(obj)
}

fn encode_native(native: &NativeIdentity) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("family".to_string(), Value::from(native.family));
    obj.insert("op".to_string(), Value::from(native.op));
    obj.insert("result".to_string(), Value::from(native.result));
    obj.insert("context".to_string(), Value::from(native.context));
    obj.insert(
        "algorithm".to_string(),
        Value::String(native.algorithm.clone()),
    );
    obj.insert("driver".to_string(), Value::String(native.driver.clone()));
    obj
}

impl WorkloadReport {
    /// Encode this report as its exact v2 JSON value: schema id, session,
    /// interval, profile, boundary, collision-qualified dictionary (one
    /// entry per distinct `(kh, native)` pair, `dict_id`s `n0..` in
    /// sorted order), context rows (every row via `native_ref`),
    /// ledger, partition, selectors, scope, metadata, coverage.
    #[must_use]
    pub fn to_json_value(&self) -> Value {
        let mut pairs: Vec<(u64, &NativeIdentity)> = self
            .rows
            .iter()
            .map(|row| (row.context.kh, &row.native))
            .collect();
        pairs.sort();
        pairs.dedup();
        let mut dictionary = Vec::with_capacity(pairs.len());
        for (index, (kh, native)) in pairs.iter().enumerate() {
            let mut entry = encode_native(native);
            entry.insert("dict_id".to_string(), Value::String(format!("n{index}")));
            entry.insert("kh".to_string(), digit(*kh));
            dictionary.push(Value::Object(entry));
        }
        let dict_id_of = |kh: u64, native: &NativeIdentity| -> String {
            let index = pairs
                .iter()
                .position(|(k, n)| *k == kh && *n == native)
                .expect("dictionary covers every row");
            format!("n{index}")
        };
        let mut contexts = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let mut obj = Map::new();
            obj.insert("kh".to_string(), digit(row.context.kh));
            obj.insert("cgroup_id".to_string(), digit(row.context.cgroup));
            obj.insert("tgid".to_string(), Value::from(row.context.tgid));
            obj.insert("uid".to_string(), Value::from(row.context.uid));
            obj.insert("start_ns".to_string(), digit(row.context.start_ns));
            obj.insert(
                "execution_kind".to_string(),
                Value::String(execution_kind_wire(row.context.execution_kind).to_string()),
            );
            obj.insert("calls".to_string(), digit(row.calls));
            obj.insert(
                "native_ref".to_string(),
                Value::String(dict_id_of(row.context.kh, &row.native)),
            );
            if let Some(workload) = &row.workload {
                obj.insert("workload".to_string(), encode_identity(workload));
            }
            if let Some(evidence) = &row.evidence {
                obj.insert("attribution".to_string(), encode_evidence(evidence));
            }
            contexts.push(Value::Object(obj));
        }
        let mut selectors = Map::new();
        match &self.selector {
            WorkloadSelector::None => {
                selectors.insert("kind".to_string(), Value::String("none".to_string()));
            }
            WorkloadSelector::CgroupId(id) => {
                selectors.insert("kind".to_string(), Value::String("cgroup-id".to_string()));
                selectors.insert("cgroup_id".to_string(), digit(*id));
            }
            WorkloadSelector::ContainerId {
                runtime,
                id,
                lifetime,
            } => {
                selectors.insert(
                    "kind".to_string(),
                    Value::String("container-id".to_string()),
                );
                let mut container = Map::new();
                container.insert("runtime".to_string(), Value::String(runtime.clone()));
                container.insert("id".to_string(), Value::String(id.clone()));
                if let Some(lifetime) = lifetime.as_deref().filter(|l| !l.is_empty()) {
                    container.insert("lifetime".to_string(), Value::String(lifetime.to_string()));
                }
                selectors.insert("container".to_string(), Value::Object(container));
            }
        }
        let mut metadata = Map::new();
        match self.metadata {
            MetadataAvailability::Available => {
                metadata.insert("status".to_string(), Value::String("available".to_string()));
            }
            MetadataAvailability::Unavailable(reason) => {
                metadata.insert(
                    "status".to_string(),
                    Value::String("unavailable".to_string()),
                );
                metadata.insert(
                    "reason".to_string(),
                    Value::String(unavailability_reason_wire(reason).to_string()),
                );
            }
        }
        serde_json::json!({
            "schema": crate::validate::workload_v2::SCHEMA_ID,
            "session": {
                "session_id": self.session.session_id,
                "kernel_identity": self.session.kernel_identity,
            },
            "interval": {
                "start_ns": self.interval.start_ns.to_string(),
                "end_ns": self.interval.end_ns.to_string(),
                "consistency": consistency_wire(self.interval.consistency),
                "clock": "monotonic_boot",
            },
            "profile": self.profile,
            "boundary": boundary_wire(self.boundary),
            "dictionary": dictionary,
            "contexts": contexts,
            "ledger": {
                "system_total": self.ledger.system_total.to_string(),
                "per_context_sum": self.ledger.per_context_sum.to_string(),
                "unknown": self.ledger.unknown.to_string(),
                "consistency": consistency_wire(self.ledger.consistency),
                "gap_unreconciled": self.ledger.gap_unreconciled,
                "system_saturated": self.ledger.system_saturated,
                "per_context_saturated": self.ledger.per_context_saturated,
                "refused_inserts": self.ledger.refused_inserts.to_string(),
            },
            "partition": {
                "matched": self.partition.matched().to_string(),
                "nonmatched": self.partition.nonmatched().to_string(),
                "unknown_match": self.partition.unknown_match().to_string(),
            },
            "selectors": selectors,
            "scope": {
                "capture_scope": "system",
                "report_scope": match self.scope {
                    ReportScope::Unscoped => "unscoped",
                    ReportScope::Scoped => "scoped",
                },
                "group_by": match self.group_by {
                    GroupBy::None => "none",
                    GroupBy::Cgroup => "cgroup",
                    GroupBy::Container => "container",
                },
            },
            "metadata": metadata,
            "coverage": {
                "capture": coverage_wire(self.coverage.capture),
                "attribution": coverage_wire(self.coverage.attribution),
                "metadata": coverage_wire(self.coverage.metadata),
                "correlation": coverage_wire(self.coverage.correlation),
            },
        })
    }

    /// Encode this report to v2 bytes, enforcing the row, dictionary, and
    /// byte budgets.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, WorkloadBuildError> {
        if self.rows.len() > MAX_V2_CONTEXT_ROWS {
            return Err(WorkloadBuildError::TooManyRows);
        }
        let value = self.to_json_value();
        let dictionary_len = value
            .get("dictionary")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if dictionary_len > MAX_V2_DICTIONARY_ENTRIES {
            return Err(WorkloadBuildError::TooManyDictionaryEntries);
        }
        // `serde_json::Value` serializes infallibly (no maps with
        // non-string keys, no non-finite floats by construction).
        let bytes = serde_json::to_vec(&value).expect("JSON values serialize");
        if bytes.len() > MAX_REPORT_V2_BYTES {
            return Err(WorkloadBuildError::ReportTooLarge);
        }
        Ok(bytes)
    }

    /// Write the v2 bytes to `writer` (`write_all` + `flush`): every I/O
    /// failure — short writes, EPIPE, flush failure, disk full —
    /// surfaces as [`WorkloadWriteError::Io`] with its kind intact. A
    /// returned `Err` means the output is NOT a clean terminal result.
    pub fn write_json_to(&self, mut writer: impl Write) -> Result<(), WorkloadWriteError> {
        let bytes = self.to_json_bytes().map_err(WorkloadWriteError::Encode)?;
        writer.write_all(&bytes).map_err(WorkloadWriteError::Io)?;
        writer.flush().map_err(WorkloadWriteError::Io)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode one report from stored bytes (replay): budget first, then
/// parse, then the frozen v2 validator, then typed conversion. Pure over
/// caller bytes — no host or runtime queries, so replay works after the
/// observed workloads disappear.
pub fn report_from_bytes(bytes: &[u8]) -> Result<WorkloadReport, WorkloadDecodeError> {
    if bytes.len() > MAX_REPORT_V2_BYTES {
        return Err(WorkloadDecodeError::TooLarge);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| WorkloadDecodeError::Malformed)?;
    let findings = crate::validate::workload_v2::validate_workload_v2(&value);
    if !findings.is_empty() {
        return Err(WorkloadDecodeError::SchemaDefects {
            count: findings.len(),
        });
    }
    convert_validated(&value)
}

/// Decode one report from a reader (replay over a stream): at most
/// `MAX_REPORT_V2_BYTES + 1` bytes are ever buffered, so an unbounded or
/// hostile stream refuses with [`WorkloadDecodeError::TooLarge`] instead
/// of exhausting memory. Truncated streams refuse as [`Malformed`](WorkloadDecodeError::Malformed)
/// (broken syntax) or [`SchemaDefects`](WorkloadDecodeError::SchemaDefects)
/// (valid JSON missing required keys) — never a partial report.
pub fn report_from_reader(reader: impl Read) -> Result<WorkloadReport, WorkloadDecodeError> {
    let mut bounded = reader.take(MAX_REPORT_V2_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| WorkloadDecodeError::Unreadable)?;
    if bytes.len() > MAX_REPORT_V2_BYTES {
        return Err(WorkloadDecodeError::TooLarge);
    }
    report_from_bytes(&bytes)
}

/// Parse a digit-string magnitude.
fn parse_digit(value: Option<&Value>) -> Option<u64> {
    value?.as_str()?.parse::<u64>().ok()
}

/// Parse a bounded JSON integer.
fn parse_small(value: Option<&Value>, max: u64) -> Option<u64> {
    value?.as_u64().filter(|n| *n <= max)
}

fn decode_consistency(value: Option<&Value>) -> Option<SnapshotConsistency> {
    match value?.as_str()? {
        "quiescent" => Some(SnapshotConsistency::Quiescent),
        "unproven" => Some(SnapshotConsistency::Unproven),
        _ => None,
    }
}

fn decode_execution_kind(value: Option<&Value>) -> Option<ExecutionKind> {
    match value?.as_str()? {
        "proc" => Some(ExecutionKind::Proc),
        "kthread" => Some(ExecutionKind::Kthread),
        "softirq" => Some(ExecutionKind::Softirq),
        "unknown" => Some(ExecutionKind::Unknown),
        _ => None,
    }
}

fn decode_relationship(value: Option<&Value>) -> Option<Relationship> {
    match value?.as_str()? {
        "hook_context" => Some(Relationship::HookContext),
        "submitter" => Some(Relationship::Submitter),
        "completion_context" => Some(Relationship::CompletionContext),
        "workload_origin" => Some(Relationship::WorkloadOrigin),
        "consumer" => Some(Relationship::Consumer),
        _ => None,
    }
}

fn decode_origin(value: Option<&Value>) -> Option<WorkloadOrigin> {
    match value?.as_str()? {
        "kernel_capture" => Some(WorkloadOrigin::KernelCapture),
        "operator_metadata_file" => Some(WorkloadOrigin::OperatorMetadataFile),
        "runtime_adapter" => Some(WorkloadOrigin::RuntimeAdapter),
        "host_proc" => Some(WorkloadOrigin::HostProc),
        "unknown" => Some(WorkloadOrigin::Unknown),
        _ => None,
    }
}

fn decode_status(value: Option<&Value>) -> Option<AttributionStatus> {
    match value?.as_str()? {
        "verified" => Some(AttributionStatus::Verified),
        "asserted" => Some(AttributionStatus::Asserted),
        "unresolved" => Some(AttributionStatus::Unresolved),
        "ambiguous" => Some(AttributionStatus::Ambiguous),
        "stale" => Some(AttributionStatus::Stale),
        "unsupported" => Some(AttributionStatus::Unsupported),
        _ => None,
    }
}

fn decode_coverage_level(value: Option<&Value>) -> Option<CoverageLevel> {
    match value?.as_str()? {
        "complete" => Some(CoverageLevel::Complete),
        "partial" => Some(CoverageLevel::Partial),
        "unavailable" => Some(CoverageLevel::Unavailable),
        _ => None,
    }
}

fn decode_unavailability(value: Option<&Value>) -> Option<MetadataUnavailable> {
    match value?.as_str()? {
        "no_principal" => Some(MetadataUnavailable::NoPrincipal),
        "helper_refused" => Some(MetadataUnavailable::HelperRefused),
        "budget_exceeded" => Some(MetadataUnavailable::BudgetExceeded),
        "unsupported_environment" => Some(MetadataUnavailable::UnsupportedEnvironment),
        "parse_failed" => Some(MetadataUnavailable::ParseFailed),
        _ => None,
    }
}

fn decode_native(obj: &Map<String, Value>) -> Option<NativeIdentity> {
    Some(NativeIdentity {
        family: parse_small(obj.get("family"), 255)? as u8,
        op: parse_small(obj.get("op"), 255)? as u8,
        result: parse_small(obj.get("result"), 255)? as u8,
        context: parse_small(obj.get("context"), 255)? as u8,
        algorithm: obj.get("algorithm")?.as_str()?.to_string(),
        driver: obj.get("driver")?.as_str()?.to_string(),
    })
}

fn decode_container(obj: &Map<String, Value>) -> Option<ContainerRef> {
    Some(ContainerRef {
        runtime: obj.get("runtime")?.as_str()?.to_string(),
        id: obj.get("id")?.as_str()?.to_string(),
        lifetime: obj
            .get("lifetime")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn decode_identity(value: &Value) -> Option<WorkloadIdentity> {
    let obj = value.as_object()?;
    let container = match obj.get("container") {
        None => None,
        Some(c) => Some(decode_container(c.as_object()?)?),
    };
    let pod = match obj.get("pod") {
        None => None,
        Some(pod) => {
            let pod = pod.as_object()?;
            Some(PodRef {
                cluster: pod.get("cluster")?.as_str()?.to_string(),
                uid: pod.get("uid")?.as_str()?.to_string(),
                name: pod.get("name")?.as_str()?.to_string(),
                namespace: pod.get("namespace")?.as_str()?.to_string(),
            })
        }
    };
    let ancestor = match obj.get("ancestor_container") {
        None => None,
        Some(c) => Some(decode_container(c.as_object()?)?),
    };
    Some(WorkloadIdentity {
        container,
        pod,
        cluster: obj
            .get("cluster")
            .and_then(Value::as_str)
            .map(str::to_string),
        node: obj.get("node").and_then(Value::as_str).map(str::to_string),
        ancestor_container: ancestor,
    })
}

fn decode_evidence(value: &Value) -> Option<AttributionEvidence> {
    let obj = value.as_object()?;
    let validity = match obj.get("validity") {
        None => None,
        Some(window) => {
            let window = window.as_object()?;
            Some(ValidityInterval::monotonic(
                parse_digit(window.get("start_ns"))?,
                parse_digit(window.get("end_ns"))?,
            ))
        }
    };
    Some(AttributionEvidence {
        relationship: decode_relationship(obj.get("relationship"))?,
        method: obj.get("method")?.as_str()?.to_string(),
        source: decode_origin(obj.get("source"))?,
        status: decode_status(obj.get("status"))?,
        validity,
    })
}

fn decode_selector(selectors: &Map<String, Value>) -> Option<WorkloadSelector> {
    match selectors.get("kind")?.as_str()? {
        "none" => Some(WorkloadSelector::None),
        "cgroup-id" => Some(WorkloadSelector::CgroupId(parse_digit(
            selectors.get("cgroup_id"),
        )?)),
        "container-id" => {
            let container = selectors.get("container")?.as_object()?;
            Some(WorkloadSelector::ContainerId {
                runtime: container.get("runtime")?.as_str()?.to_string(),
                id: container.get("id")?.as_str()?.to_string(),
                lifetime: container
                    .get("lifetime")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        }
        _ => None,
    }
}

fn decode_availability(metadata: &Map<String, Value>) -> Option<MetadataAvailability> {
    match metadata.get("status")?.as_str()? {
        "available" => Some(MetadataAvailability::Available),
        "unavailable" => Some(MetadataAvailability::Unavailable(decode_unavailability(
            metadata.get("reason"),
        )?)),
        _ => None,
    }
}

/// Convert a validator-accepted value into its typed report. Returns
/// `Err` when the value contradicts its validated shape (defensive —
/// the validator accepts only convertible shapes), when a row breaks
/// identity/evidence coherence, or when two rows share one accounting
/// key. Rows normalize to accounting-key order (symmetric with
/// assembly), so live and replay renders agree regardless of file row
/// order.
fn convert_validated(value: &Value) -> Result<WorkloadReport, WorkloadDecodeError> {
    let obj = value.as_object().ok_or(WorkloadDecodeError::Inconsistent)?;
    let session = obj.get("session").and_then(Value::as_object);
    let interval = obj.get("interval").and_then(Value::as_object);
    let ledger = obj.get("ledger").and_then(Value::as_object);
    let partition = obj.get("partition").and_then(Value::as_object);
    let selectors = obj.get("selectors").and_then(Value::as_object);
    let scope = obj.get("scope").and_then(Value::as_object);
    let metadata = obj.get("metadata").and_then(Value::as_object);
    let coverage = obj.get("coverage").and_then(Value::as_object);
    let entries = obj.get("dictionary").and_then(Value::as_array);
    let contexts = obj.get("contexts").and_then(Value::as_array);
    let (
        Some(session),
        Some(interval),
        Some(ledger),
        Some(partition),
        Some(selectors),
        Some(scope),
        Some(metadata),
        Some(coverage),
        Some(entries),
        Some(contexts),
    ) = (
        session, interval, ledger, partition, selectors, scope, metadata, coverage, entries,
        contexts,
    )
    else {
        return Err(WorkloadDecodeError::Inconsistent);
    };

    let mut rows = Vec::with_capacity(contexts.len());
    for context in contexts {
        let row = context
            .as_object()
            .ok_or(WorkloadDecodeError::Inconsistent)?;
        let native = match (row.get("native"), row.get("native_ref")) {
            (Some(native), None) => decode_native(
                native
                    .as_object()
                    .ok_or(WorkloadDecodeError::Inconsistent)?,
            ),
            (None, Some(native_ref)) => {
                let id = native_ref
                    .as_str()
                    .ok_or(WorkloadDecodeError::Inconsistent)?;
                let entry = entries
                    .iter()
                    .find(|e| e.get("dict_id").and_then(Value::as_str) == Some(id))
                    .and_then(Value::as_object)
                    .ok_or(WorkloadDecodeError::Inconsistent)?;
                decode_native(entry)
            }
            _ => None,
        }
        .ok_or(WorkloadDecodeError::Inconsistent)?;
        let identity = match row.get("workload") {
            Some(workload) => decode_identity(workload),
            None => Some(WorkloadIdentity::none()),
        }
        .ok_or(WorkloadDecodeError::Inconsistent)?;
        let evidence = match row.get("attribution") {
            Some(attribution) => decode_evidence(attribution),
            None => Some(AttributionEvidence::unresolved(Relationship::HookContext)),
        }
        .ok_or(WorkloadDecodeError::Inconsistent)?;
        let context_id = ContextIdentity::new(
            parse_digit(row.get("kh")).ok_or(WorkloadDecodeError::Inconsistent)?,
            parse_digit(row.get("cgroup_id")).ok_or(WorkloadDecodeError::Inconsistent)?,
            parse_small(row.get("tgid"), 4_294_967_295).ok_or(WorkloadDecodeError::Inconsistent)?
                as u32,
            parse_small(row.get("uid"), 4_294_967_295).ok_or(WorkloadDecodeError::Inconsistent)?
                as u32,
            parse_digit(row.get("start_ns")).ok_or(WorkloadDecodeError::Inconsistent)?,
            decode_execution_kind(row.get("execution_kind"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
        );
        WorkloadObservation {
            context: context_id,
            identity: identity.clone(),
            evidence: evidence.clone(),
        }
        .validate()
        .map_err(|_| WorkloadDecodeError::IncoherentRow)?;
        let bare_default = !identity.is_resolved()
            && evidence == AttributionEvidence::unresolved(Relationship::HookContext);
        rows.push(ReportRow {
            context: context_id,
            calls: parse_digit(row.get("calls")).ok_or(WorkloadDecodeError::Inconsistent)?,
            native,
            workload: super::model::identity_has_association(&identity).then(|| identity.clone()),
            evidence: (!bare_default).then(|| evidence.clone()),
        });
    }

    rows.sort_by_key(|row: &ReportRow| row.context.accounting_key());
    for pair in rows.windows(2) {
        if pair[0].context.accounting_key() == pair[1].context.accounting_key() {
            return Err(WorkloadDecodeError::DuplicateContext);
        }
    }

    let selector = decode_selector(selectors).ok_or(WorkloadDecodeError::Inconsistent)?;

    let report_scope = match scope.get("report_scope").and_then(Value::as_str) {
        Some("unscoped") => Some(ReportScope::Unscoped),
        Some("scoped") => Some(ReportScope::Scoped),
        _ => None,
    }
    .ok_or(WorkloadDecodeError::Inconsistent)?;
    let group_by = match scope.get("group_by").and_then(Value::as_str) {
        Some("none") => Some(GroupBy::None),
        Some("cgroup") => Some(GroupBy::Cgroup),
        Some("container") => Some(GroupBy::Container),
        _ => None,
    }
    .ok_or(WorkloadDecodeError::Inconsistent)?;
    let availability = decode_availability(metadata).ok_or(WorkloadDecodeError::Inconsistent)?;

    Ok(WorkloadReport {
        session: ReportSession {
            session_id: session
                .get("session_id")
                .and_then(Value::as_str)
                .ok_or(WorkloadDecodeError::Inconsistent)?
                .to_string(),
            kernel_identity: session
                .get("kernel_identity")
                .and_then(Value::as_str)
                .ok_or(WorkloadDecodeError::Inconsistent)?
                .to_string(),
        },
        interval: ReportInterval {
            start_ns: parse_digit(interval.get("start_ns"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            end_ns: parse_digit(interval.get("end_ns")).ok_or(WorkloadDecodeError::Inconsistent)?,
            consistency: decode_consistency(interval.get("consistency"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
        },
        profile: obj
            .get("profile")
            .and_then(Value::as_str)
            .ok_or(WorkloadDecodeError::Inconsistent)?
            .to_string(),
        boundary: match obj.get("boundary").and_then(Value::as_str) {
            Some("api_return") => ObservationBoundary::ApiReturn,
            _ => return Err(WorkloadDecodeError::Inconsistent),
        },
        rows,
        ledger: ReportLedger {
            system_total: parse_digit(ledger.get("system_total"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            per_context_sum: parse_digit(ledger.get("per_context_sum"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            unknown: parse_digit(ledger.get("unknown")).ok_or(WorkloadDecodeError::Inconsistent)?,
            consistency: decode_consistency(ledger.get("consistency"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            gap_unreconciled: ledger
                .get("gap_unreconciled")
                .and_then(Value::as_bool)
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            system_saturated: ledger
                .get("system_saturated")
                .and_then(Value::as_bool)
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            per_context_saturated: ledger
                .get("per_context_saturated")
                .and_then(Value::as_bool)
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            refused_inserts: parse_digit(ledger.get("refused_inserts"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
        },
        partition: ScopePartition::from_counts(
            parse_digit(partition.get("matched")).ok_or(WorkloadDecodeError::Inconsistent)?,
            parse_digit(partition.get("nonmatched")).ok_or(WorkloadDecodeError::Inconsistent)?,
            parse_digit(partition.get("unknown_match")).ok_or(WorkloadDecodeError::Inconsistent)?,
        )
        .map_err(|_| WorkloadDecodeError::Inconsistent)?,
        scope: report_scope,
        selector,
        group_by,
        metadata: availability,
        coverage: ReportCoverage {
            capture: decode_coverage_level(coverage.get("capture"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            attribution: decode_coverage_level(coverage.get("attribution"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            metadata: decode_coverage_level(coverage.get("metadata"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
            correlation: decode_coverage_level(coverage.get("correlation"))
                .ok_or(WorkloadDecodeError::Inconsistent)?,
        },
    })
}
