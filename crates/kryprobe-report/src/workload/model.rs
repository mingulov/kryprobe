// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed workload report model (M1 Stage 2C): the in-memory form of
//! `workload-report-v2` shared by live assembly and offline replay.
//!
//! The model mirrors the frozen v2 wire shape field-for-field (see the
//! Stage 2A contract, ADR-0012 §(e)) while reusing the frozen core types
//! for every shared concept: [`ContextIdentity`], [`WorkloadIdentity`],
//! [`AttributionEvidence`], [`ScopePartition`], [`SnapshotConsistency`],
//! [`CountOperand`], and [`MetadataUnavailable`]. Only the report-level
//! envelope (native tuples, ledger, selectors, scope, coverage) is new,
//! and it encodes/decodes through the frozen v2 validator — never around
//! it.

use kryprobe_core::workload::{
    AttributionEvidence, ContextIdentity, CountOperand, DifferenceError, MetadataUnavailable,
    ObservationBoundary, ScopePartition, SnapshotConsistency, WorkloadIdentity,
};

/// One captured context row with its native operation identity, call
/// count, and optional workload association — the typed assembly input
/// row (live capture folds `KCTX` rows into these; replay rebuilds them
/// from stored bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRowInput {
    /// The captured kernel/session context (accounting key).
    pub context: ContextIdentity,
    /// Folded call count for this context.
    pub calls: u64,
    /// Full native operation identity (never hash-only).
    pub native: NativeIdentity,
    /// Established workload identity ([`WorkloadIdentity::none`] when
    /// unresolved — unresolved rows stay in their context rows and never
    /// promote into a resolved row).
    pub identity: WorkloadIdentity,
    /// Evidence for the association.
    pub evidence: AttributionEvidence,
}

/// Full native operation identity: the `(family, op, result, context)`
/// numerics plus the verbatim algorithm/driver names. This is what the
/// v2 `native` object (inline or dictionary entry) carries; `kh` alone is
/// an index, never identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NativeIdentity {
    /// Algorithm family (`KAgg.fam`).
    pub family: u8,
    /// Operation (`KAgg.op`).
    pub op: u8,
    /// Result class (`KAgg.res`).
    pub result: u8,
    /// Execution context (`KAgg.ctx`).
    pub context: u8,
    /// Verbatim algorithm name (`cra_name`).
    pub algorithm: String,
    /// Verbatim driver name (`cra_driver_name`).
    pub driver: String,
}

impl NativeIdentity {
    /// One native tuple. Unvalidated; call [`Self::validate`] before
    /// assembly or encoding.
    #[must_use]
    pub fn new(family: u8, op: u8, result: u8, context: u8, algorithm: &str, driver: &str) -> Self {
        Self {
            family,
            op,
            result,
            context,
            algorithm: algorithm.to_string(),
            driver: driver.to_string(),
        }
    }

    /// Wire rules: both names are non-empty and within the frozen string
    /// bound. Diagnostics are static (never echo input bytes).
    pub fn validate(&self) -> Result<(), WorkloadBuildError> {
        for name in [&self.algorithm, &self.driver] {
            if name.is_empty() || name.len() > kryprobe_core::workload::MAX_STRING_FIELD_BYTES {
                return Err(WorkloadBuildError::BadNativeIdentity);
            }
        }
        Ok(())
    }
}

/// One resolved report row: captured context, calls, native identity,
/// and the optional workload association. `workload` is `Some` when the
/// identity carries any association (keyed or pendant — pendant tags are
/// preserved, only keyed identities resolve); `evidence` is `Some` when
/// an association claim rides the row (usable statuses with an identity,
/// or unusable statuses explicitly marking the unknown population).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRow {
    /// The captured kernel/session context.
    pub context: ContextIdentity,
    /// Folded call count for this context.
    pub calls: u64,
    /// Full native operation identity (resolved from inline or `ref`).
    pub native: NativeIdentity,
    /// Established workload identity, if any.
    pub workload: Option<WorkloadIdentity>,
    /// Association evidence, if any claim rides the row.
    pub evidence: Option<AttributionEvidence>,
}

/// Report session envelope: session id plus execution-kernel identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportSession {
    /// Session id (32 lowercase hex chars).
    pub session_id: String,
    /// Execution-kernel identity (non-empty, within 128 bytes).
    pub kernel_identity: String,
}

/// Report interval: monotonic-boot nanosecond bounds plus the fence
/// consistency qualifying every ledger magnitude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportInterval {
    /// Interval start, inclusive (monotonic boot-time ns).
    pub start_ns: u64,
    /// Interval end, inclusive (monotonic boot-time ns).
    pub end_ns: u64,
    /// Fence consistency (shared with the ledger).
    pub consistency: SnapshotConsistency,
}

/// Authoritative ledger: the exact operands behind the unknown
/// population, with saturation and gap flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLedger {
    /// System total (`KTOT`).
    pub system_total: u64,
    /// Summed per-context calls (`ΣKCTX`).
    pub per_context_sum: u64,
    /// Unknown magnitude (`system − per_context` when quiescent, else 0).
    pub unknown: u64,
    /// Fence consistency (agrees with the interval).
    pub consistency: SnapshotConsistency,
    /// True exactly when unproven: the gap is exported, never an exact
    /// unknown.
    pub gap_unreconciled: bool,
    /// Whether the system operand saturated (refuses quiescence).
    pub system_saturated: bool,
    /// Whether the per-context operand saturated (refuses quiescence).
    pub per_context_saturated: bool,
    /// Exact refused-insert count (bounded above by `unknown`).
    pub refused_inserts: u64,
}

/// Workload selector carried by the report: `None` is the whole observed
/// population; the other kinds are exact post-ingestion views (Stage 2D
/// evaluates them; this crate only carries and renders them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadSelector {
    /// No selector: the report covers its whole observed population.
    None,
    /// Exact cgroup-id view.
    CgroupId(u64),
    /// Exact full-container-identity view.
    ContainerId {
        /// Runtime instance identity.
        runtime: String,
        /// Full container id (64 lowercase hex chars).
        id: String,
        /// Runtime lifetime metadata, when captured.
        lifetime: Option<String>,
    },
}

impl WorkloadSelector {
    /// Whether any workload selector is applied (drives `report_scope`).
    #[must_use]
    pub fn is_scoped(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Report scope: unscoped reports match their whole observed population;
/// scoped reports carry an applied selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportScope {
    /// Whole observed population, no selector applied.
    Unscoped,
    /// A workload selector view is applied.
    Scoped,
}

/// Row grouping declared by the report (a rendering/view axis, never a
/// second counting: every row belongs to exactly one group).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    /// No grouping.
    None,
    /// Group by captured cgroup id.
    Cgroup,
    /// Group by resolved container identity.
    Container,
}

/// Typed metadata availability: present, or absent with the frozen
/// unavailability reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataAvailability {
    /// Captured metadata rode the report.
    Available,
    /// No metadata, with the typed reason.
    Unavailable(MetadataUnavailable),
}

/// One coverage dimension value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageLevel {
    /// Dimension is complete.
    Complete,
    /// Dimension is partially covered.
    Partial,
    /// Dimension is unavailable.
    Unavailable,
}

/// Four independent coverage dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportCoverage {
    /// Capture completeness.
    pub capture: CoverageLevel,
    /// Attribution completeness.
    pub attribution: CoverageLevel,
    /// Metadata completeness.
    pub metadata: CoverageLevel,
    /// Correlation completeness.
    pub correlation: CoverageLevel,
}

/// The typed workload report: session, interval, profile, boundary,
/// deterministically ordered rows, ledger, partition, selectors, scope,
/// metadata availability, and coverage. Built by [`assemble`](crate::workload::assemble)
/// from captured rows (live) or [`report_from_bytes`](crate::workload::report_from_bytes)
/// from stored bytes (replay); both paths render through the same
/// renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadReport {
    /// Session envelope.
    pub session: ReportSession,
    /// Capture interval.
    pub interval: ReportInterval,
    /// Capture profile name.
    pub profile: String,
    /// Observed boundary (M1: `ApiReturn`).
    pub boundary: ObservationBoundary,
    /// Context rows in accounting-key order.
    pub rows: Vec<ReportRow>,
    /// Authoritative ledger.
    pub ledger: ReportLedger,
    /// Selector partition over the observed population.
    pub partition: ScopePartition,
    /// Applied workload selector.
    pub selector: WorkloadSelector,
    /// Report scope (derived from the selector).
    pub scope: ReportScope,
    /// Declared row grouping.
    pub group_by: GroupBy,
    /// Metadata availability.
    pub metadata: MetadataAvailability,
    /// Independent coverage.
    pub coverage: ReportCoverage,
}

/// Assembly/encode input for one report: captured rows plus the session,
/// ledger-operand, partition, selector, metadata, and coverage inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyInput {
    /// Session id (32 lowercase hex chars).
    pub session_id: String,
    /// Execution-kernel identity (non-empty, within 128 bytes).
    pub kernel_identity: String,
    /// Interval start, inclusive (monotonic boot-time ns).
    pub interval_start_ns: u64,
    /// Interval end, inclusive (monotonic boot-time ns).
    pub interval_end_ns: u64,
    /// Fence consistency qualifying the ledger.
    pub consistency: SnapshotConsistency,
    /// Capture profile name (non-empty, within 256 bytes).
    pub profile: String,
    /// System-total operand with its saturation qualification.
    pub system_total: CountOperand,
    /// Whether the per-context fold saturated.
    pub per_context_saturated: bool,
    /// Exact refused-insert count.
    pub refused_inserts: u64,
    /// Captured rows (sorted at assembly; at most 1024).
    pub rows: Vec<ReportRowInput>,
    /// Selector partition (observed must equal summed calls).
    pub partition: ScopePartition,
    /// Applied workload selector.
    pub selector: WorkloadSelector,
    /// Declared row grouping.
    pub group_by: GroupBy,
    /// Metadata availability.
    pub metadata: MetadataAvailability,
    /// Independent coverage.
    pub coverage: ReportCoverage,
}

/// Typed assembly/encode refusal. Diagnostics are static: they name the
/// rule, never input bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadBuildError {
    /// Session id is not 32 lowercase hex chars.
    BadSession,
    /// Kernel identity is empty or over 128 bytes.
    BadKernelIdentity,
    /// Profile is empty or over 256 bytes.
    BadProfile,
    /// Interval start exceeds interval end.
    InvertedInterval,
    /// More than 1024 context rows.
    TooManyRows,
    /// More than 1024 dictionary entries (unreachable: entries are
    /// bounded by rows — kept as a defensive encode check).
    TooManyDictionaryEntries,
    /// Two rows share one accounting key (merging would corrupt rows).
    DuplicateContext,
    /// Summed calls overflow `u64`.
    CallsOverflow,
    /// A row's identity/evidence coherence refuses (frozen observation
    /// rule), or an identity/evidence value breaks its wire shape.
    IncoherentRow,
    /// A native tuple breaks its wire shape (empty/oversized names).
    BadNativeIdentity,
    /// A workload identity breaks its wire shape (non-hex id, empty
    /// components, cluster contradiction, oversized strings).
    BadIdentity,
    /// Association evidence breaks its wire shape (method outside the
    /// frozen vocabulary).
    BadEvidence,
    /// A selector breaks its wire shape.
    BadSelector,
    /// The qualified ledger difference refuses (unproven, saturated, or
    /// contradictory operands).
    LedgerRefused(DifferenceError),
    /// Refused inserts exceed the ledger unknown.
    RefusedExceedsUnknown,
    /// Partition observed disagrees with summed context calls.
    PartitionMismatch,
    /// Encoded bytes exceed the 1 MiB report budget.
    ReportTooLarge,
}

/// Whether an identity carries any association at all — keyed or
/// pendant (e.g. a cluster tag without a keyed identity). Assembly and
/// decode emit a `workload` object exactly in this case: pendant
/// associations are preserved, never silently dropped, while promotion
/// rules are unaffected (only keyed associations resolve).
#[must_use]
pub(crate) fn identity_has_association(identity: &WorkloadIdentity) -> bool {
    identity.container.is_some()
        || identity.pod.is_some()
        || identity.cluster.is_some()
        || identity.node.is_some()
        || identity.ancestor_container.is_some()
}

impl std::fmt::Display for WorkloadBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSession => write!(f, "session id is not 32 lowercase hex chars"),
            Self::BadKernelIdentity => write!(f, "kernel identity is empty or over 128 bytes"),
            Self::BadProfile => write!(f, "profile is empty or over 256 bytes"),
            Self::InvertedInterval => write!(f, "report interval is inverted"),
            Self::TooManyRows => write!(f, "report carries more than 1024 context rows"),
            Self::TooManyDictionaryEntries => {
                write!(f, "report carries more than 1024 dictionary entries")
            }
            Self::DuplicateContext => write!(f, "two rows share one accounting key"),
            Self::CallsOverflow => write!(f, "summed context calls overflow u64"),
            Self::IncoherentRow => write!(f, "row identity contradicts its evidence"),
            Self::BadNativeIdentity => write!(f, "native identity breaks its wire shape"),
            Self::BadIdentity => write!(f, "workload identity breaks its wire shape"),
            Self::BadEvidence => write!(f, "association evidence breaks its wire shape"),
            Self::BadSelector => write!(f, "workload selector breaks its wire shape"),
            Self::LedgerRefused(err) => write!(f, "ledger difference refuses: {err}"),
            Self::RefusedExceedsUnknown => {
                write!(f, "refused inserts exceed ledger unknown")
            }
            Self::PartitionMismatch => {
                write!(f, "partition observed disagrees with summed context calls")
            }
            Self::ReportTooLarge => write!(f, "encoded report exceeds 1048576 bytes"),
        }
    }
}

impl std::error::Error for WorkloadBuildError {}
