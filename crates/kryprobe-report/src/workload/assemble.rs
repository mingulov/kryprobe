// SPDX-License-Identifier: GPL-3.0-or-later
//! Report assembly (M1 Stage 2C): captured rows plus session,
//! ledger-operand, partition, selector, metadata, and coverage inputs in;
//! one validated [`WorkloadReport`] out.
//!
//! Pure by construction: no OS reads, no I/O, no ambient clocks, no host
//! queries. Deterministic: rows sort by accounting key, so shuffled
//! inputs encode byte-identically.

use super::model::{
    AssemblyInput, ReportInterval, ReportLedger, ReportRow, ReportScope, ReportSession,
    WorkloadBuildError, WorkloadReport, WorkloadSelector,
};
use kryprobe_core::workload::{
    AttributionEvidence, MAX_KERNEL_IDENTITY_BYTES, MAX_STRING_FIELD_BYTES, MAX_V2_CONTEXT_ROWS,
    METHOD_CAPTURED_CGROUP, METHOD_CGROUP_INODE_BIND, METHOD_METADATA_FILE, METHOD_METADATA_LABEL,
    METHOD_RUNTIME_ADAPTER, METHOD_UNRESOLVED, ObservationBoundary, Relationship,
    SnapshotConsistency, WorkloadIdentity, WorkloadObservation, compute_qualified,
    validate_session_id,
};

/// Assemble one typed report from captured inputs.
///
/// Rules (frozen-adjacent: every refusal keeps an invalid or skewed
/// report from existing):
///
/// - Session, kernel, profile, and interval shapes refuse typed.
/// - At most [`MAX_V2_CONTEXT_ROWS`] rows; rows sort by accounting key;
///   duplicate accounting keys refuse (merging would corrupt rows).
/// - Every row's identity/evidence must satisfy the frozen observation
///   coherence rule, and every native tuple, identity, evidence, and the
///   selector must satisfy its v2 wire shape — assembly emits only bytes
///   the frozen validator accepts.
/// - Summed calls use checked arithmetic (overflow refuses); the
///   quiescent ledger derives via the frozen qualified difference and
///   refused inserts stay within unknown; unproven exports a gap with
///   unknown 0, never an exact unknown.
/// - The partition's observed population must equal the summed calls,
///   and the report scope derives from the selector (never mismatched).
pub fn assemble(input: AssemblyInput) -> Result<WorkloadReport, WorkloadBuildError> {
    validate_session_id(&input.session_id).map_err(|_| WorkloadBuildError::BadSession)?;
    if input.kernel_identity.is_empty() || input.kernel_identity.len() > MAX_KERNEL_IDENTITY_BYTES {
        return Err(WorkloadBuildError::BadKernelIdentity);
    }
    if input.profile.is_empty() || input.profile.len() > MAX_STRING_FIELD_BYTES {
        return Err(WorkloadBuildError::BadProfile);
    }
    if input.interval_start_ns > input.interval_end_ns {
        return Err(WorkloadBuildError::InvertedInterval);
    }
    if input.rows.len() > MAX_V2_CONTEXT_ROWS {
        return Err(WorkloadBuildError::TooManyRows);
    }
    check_selector(&input.selector)?;

    let AssemblyInput {
        session_id,
        kernel_identity,
        interval_start_ns,
        interval_end_ns,
        consistency,
        profile,
        system_total,
        per_context_saturated,
        refused_inserts,
        mut rows,
        partition,
        selector,
        group_by,
        metadata,
        coverage,
    } = input;
    for row in &rows {
        row.native.validate()?;
        check_identity(&row.identity)?;
        check_evidence(&row.evidence)?;
        WorkloadObservation {
            context: row.context,
            identity: row.identity.clone(),
            evidence: row.evidence.clone(),
        }
        .validate()
        .map_err(|_| WorkloadBuildError::IncoherentRow)?;
    }
    rows.sort_by_key(|row| row.context.accounting_key());
    for pair in rows.windows(2) {
        if pair[0].context.accounting_key() == pair[1].context.accounting_key() {
            return Err(WorkloadBuildError::DuplicateContext);
        }
    }

    let mut per_context_sum: u64 = 0;
    for row in &rows {
        per_context_sum = per_context_sum
            .checked_add(row.calls)
            .ok_or(WorkloadBuildError::CallsOverflow)?;
    }
    if partition.observed() != per_context_sum {
        return Err(WorkloadBuildError::PartitionMismatch);
    }

    let ledger = build_ledger(
        consistency,
        system_total,
        per_context_saturated,
        refused_inserts,
        per_context_sum,
    )?;
    let typed_rows = rows.into_iter().map(split_row).collect();
    Ok(WorkloadReport {
        session: ReportSession {
            session_id,
            kernel_identity,
        },
        interval: ReportInterval {
            start_ns: interval_start_ns,
            end_ns: interval_end_ns,
            consistency,
        },
        profile,
        boundary: ObservationBoundary::ApiReturn,
        rows: typed_rows,
        ledger,
        partition,
        scope: if selector.is_scoped() {
            ReportScope::Scoped
        } else {
            ReportScope::Unscoped
        },
        selector,
        group_by,
        metadata,
        coverage,
    })
}

/// Split one validated input row into its typed resolved/unknown form:
/// the workload rides iff the identity carries any association (keyed
/// or pendant — pendant tags are preserved, never dropped); the
/// evidence rides iff any association claim rides the row (a bare
/// unresolved default with no identity stays implicit, matching the
/// frozen raw-id fixtures).
fn split_row(row: super::model::ReportRowInput) -> ReportRow {
    let resolved = row.identity.is_resolved();
    let carries = super::model::identity_has_association(&row.identity);
    let bare_default =
        !resolved && row.evidence == AttributionEvidence::unresolved(Relationship::HookContext);
    ReportRow {
        context: row.context,
        calls: row.calls,
        native: row.native,
        workload: carries.then(|| row.identity.clone()),
        evidence: (!bare_default).then(|| row.evidence.clone()),
    }
}

/// Build the authoritative ledger: quiescent derives the exact unknown
/// via the frozen qualified difference; unproven exports a gap.
fn build_ledger(
    consistency: SnapshotConsistency,
    system_total: kryprobe_core::workload::CountOperand,
    per_context_saturated: bool,
    refused_inserts: u64,
    per_context_sum: u64,
) -> Result<ReportLedger, WorkloadBuildError> {
    match consistency {
        SnapshotConsistency::Quiescent => {
            let qualified = compute_qualified(
                SnapshotConsistency::Quiescent,
                "global",
                system_total,
                kryprobe_core::workload::CountOperand {
                    value: per_context_sum,
                    saturated: per_context_saturated,
                },
            )
            .map_err(WorkloadBuildError::LedgerRefused)?;
            if refused_inserts > qualified.difference.unknown {
                return Err(WorkloadBuildError::RefusedExceedsUnknown);
            }
            Ok(ReportLedger {
                system_total: system_total.value,
                per_context_sum,
                unknown: qualified.difference.unknown,
                consistency: SnapshotConsistency::Quiescent,
                gap_unreconciled: false,
                system_saturated: system_total.saturated,
                per_context_saturated,
                refused_inserts,
            })
        }
        SnapshotConsistency::Unproven => Ok(ReportLedger {
            system_total: system_total.value,
            per_context_sum,
            unknown: 0,
            consistency: SnapshotConsistency::Unproven,
            gap_unreconciled: true,
            system_saturated: system_total.saturated,
            per_context_saturated,
            refused_inserts,
        }),
    }
}

/// Lowercase-hex string of exactly `len` chars.
fn is_hex_string(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Identity wire-shape check: every present association must encode to
/// valid v2 (non-empty bounded components, full 64-hex container ids,
/// consistent cluster sources). Static diagnostics only.
fn check_identity(identity: &WorkloadIdentity) -> Result<(), WorkloadBuildError> {
    if !identity.check_consistency() {
        return Err(WorkloadBuildError::BadIdentity);
    }
    for container in [&identity.container, &identity.ancestor_container]
        .into_iter()
        .flatten()
    {
        if container.runtime.is_empty()
            || container.runtime.len() > MAX_STRING_FIELD_BYTES
            || !is_hex_string(&container.id, 64)
        {
            return Err(WorkloadBuildError::BadIdentity);
        }
        if container
            .lifetime
            .as_deref()
            .is_some_and(|lifetime| lifetime.len() > MAX_STRING_FIELD_BYTES)
        {
            return Err(WorkloadBuildError::BadIdentity);
        }
    }
    if let Some(pod) = &identity.pod {
        for field in [&pod.cluster, &pod.uid] {
            if field.is_empty() || field.len() > MAX_STRING_FIELD_BYTES {
                return Err(WorkloadBuildError::BadIdentity);
            }
        }
        for field in [&pod.name, &pod.namespace] {
            if field.len() > MAX_STRING_FIELD_BYTES {
                return Err(WorkloadBuildError::BadIdentity);
            }
        }
    }
    for field in [&identity.cluster, &identity.node].into_iter().flatten() {
        if field.len() > MAX_STRING_FIELD_BYTES {
            return Err(WorkloadBuildError::BadIdentity);
        }
    }
    Ok(())
}

/// Evidence wire-shape check: the method must be one of the six frozen
/// vocabulary strings (relationship/source/status are typed enums whose
/// every variant is v2-valid; ordering/coherence is the observation
/// rule's job).
fn check_evidence(evidence: &AttributionEvidence) -> Result<(), WorkloadBuildError> {
    if ![
        METHOD_CAPTURED_CGROUP,
        METHOD_CGROUP_INODE_BIND,
        METHOD_METADATA_FILE,
        METHOD_METADATA_LABEL,
        METHOD_RUNTIME_ADAPTER,
        METHOD_UNRESOLVED,
    ]
    .contains(&evidence.method.as_str())
    {
        return Err(WorkloadBuildError::BadEvidence);
    }
    Ok(())
}

/// Selector wire-shape check: container selectors carry full identities.
fn check_selector(selector: &WorkloadSelector) -> Result<(), WorkloadBuildError> {
    if let WorkloadSelector::ContainerId {
        runtime,
        id,
        lifetime,
    } = selector
        && (runtime.is_empty()
            || runtime.len() > MAX_STRING_FIELD_BYTES
            || !is_hex_string(id, 64)
            || lifetime
                .as_deref()
                .is_some_and(|lifetime| lifetime.len() > MAX_STRING_FIELD_BYTES))
    {
        return Err(WorkloadBuildError::BadSelector);
    }
    Ok(())
}
