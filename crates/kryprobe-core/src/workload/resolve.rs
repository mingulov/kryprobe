// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure snapshot resolution (Stage 2A contract): captured request keys +
//! a validated metadata snapshot in, a bound snapshot response out.
//!
//! Pure by construction: no OS reads, no I/O, no ambient clocks, no
//! current-host queries. Replay after workloads disappear uses exactly
//! this entry point over captured bytes.

use super::{
    AttributionEvidence, AttributionStatus, ChunkInfo, MAX_SNAPSHOT_RESPONSE_BYTES,
    METHOD_METADATA_FILE, MetadataSnapshot, MetadataUnavailable, Relationship, ResolvedAssociation,
    ResponseStatus, SnapshotCounters, SnapshotErrorCode, SnapshotInterval, SnapshotKey,
    SnapshotKeyDetail, SnapshotKeyError, SnapshotRequest, SnapshotResponse, ValidityInterval,
    WorkloadIdentity, WorkloadOrigin,
};

/// Resolve one snapshot request against one metadata snapshot.
///
/// Rules (frozen, Stage 2A contract):
///
/// - The request and snapshot validate first; malformed input refuses
///   typed before any association is produced.
/// - Kernel binding is exact: a key is servable only when the snapshot
///   kernel is `Known` and equals the key's `kernel_scope`. Mismatch
///   yields [`SnapshotErrorCode::KernelMismatch`]; unknown snapshot
///   kernel yields [`SnapshotErrorCode::UnknownKernel`]. Either way the
///   key is refused — never served under a foreign kernel.
/// - Cgroup matching is exact `u64` equality against entry `cgroup_id`,
///   except cgroup 0 (unreadable): a zero key never resolves, whatever
///   the file claims. Zero matches yield `Unresolved`; two or more
///   yield `Ambiguous` (counts stay split, never merged).
/// - A single match with no established identity stays `Unresolved`
///   (observation coherence: usable statuses require an identity).
/// - A single match whose binding is explicitly `Stale` stays `Stale`
///   (reported with its identity, counted as unusable).
/// - Otherwise the binding asserts only when its validity interval
///   COVERS the request's capture interval: uncovered counts stay
///   unknown (`Stale` when a validity window exists but does not
///   cover, `Unresolved` when none does), never `Asserted`. An absent
///   capture interval or an absent validity window cannot establish
///   coverage. The pure path never corroborates: `Verified` is
///   unreachable here by construction.
/// - Associations keep request order. The response fits
///   [`MAX_SNAPSHOT_RESPONSE_BYTES`]: tail associations convert to
///   `BudgetExceeded` errors (status `Truncated`) until it fits; if even
///   the all-errors response cannot fit, resolution refuses with
///   [`MetadataUnavailable::BudgetExceeded`].
pub fn resolve(
    request: &SnapshotRequest,
    snapshot: &MetadataSnapshot,
) -> Result<SnapshotResponse, MetadataUnavailable> {
    request.validate()?;
    snapshot.validate()?;
    let mut associations = Vec::with_capacity(request.keys.len());
    let mut errors = Vec::new();
    for key in &request.keys {
        match resolve_one_key(key, snapshot, request.capture_interval.as_ref()) {
            Ok(assoc) => associations.push(assoc),
            Err(error) => errors.push(error),
        }
    }
    let mut response = SnapshotResponse {
        session_id: request.session_id.clone(),
        kernel_identity: snapshot.kernel_identity.clone(),
        associations,
        errors,
        status: ResponseStatus::Complete,
        chunk: ChunkInfo::single(),
        counters: SnapshotCounters {
            resolved: 0,
            unresolved: 0,
            refused: 0,
        },
    };
    recount(&mut response);
    truncate_to_budget(&mut response)?;
    recount(&mut response);
    response.validate()?;
    Ok(response)
}

/// Whether a binding validity window covers the counted capture
/// interval: both must exist, and the validity must contain the whole
/// capture. Overlap alone does not establish applicability to every call
/// in the aggregate.
fn validity_covers_capture(
    capture: Option<&SnapshotInterval>,
    validity: Option<&ValidityInterval>,
) -> bool {
    match (capture, validity) {
        (Some(capture), Some(validity)) => {
            validity.start_ns <= capture.start_ns && capture.end_ns <= validity.end_ns
        }
        _ => false,
    }
}

/// Resolve one key: kernel gate first, then cgroup match, then identity,
/// staleness, and capture coverage.
fn resolve_one_key(
    key: &SnapshotKey,
    snapshot: &MetadataSnapshot,
    capture: Option<&SnapshotInterval>,
) -> Result<ResolvedAssociation, SnapshotKeyError> {
    if !snapshot.kernel_identity.matches_scope(&key.kernel_scope) {
        let (code, detail) = match &snapshot.kernel_identity {
            super::KernelIdentity::Known(_) => (
                SnapshotErrorCode::KernelMismatch,
                SnapshotKeyDetail::KernelDiffers,
            ),
            super::KernelIdentity::Unknown => (
                SnapshotErrorCode::UnknownKernel,
                SnapshotKeyDetail::KernelUnknown,
            ),
        };
        return Err(SnapshotKeyError {
            key: key.clone(),
            code,
            detail,
        });
    }
    // Cgroup 0 is unreadable: the unknown-cgroup population never
    // resolves, whatever the file claims for id 0.
    if key.cgroup == 0 {
        return Ok(ResolvedAssociation {
            key: key.clone(),
            identity: WorkloadIdentity::none(),
            evidence: AttributionEvidence::unresolved(Relationship::HookContext),
        });
    }
    let matches: Vec<_> = snapshot
        .entries
        .iter()
        .filter(|entry| entry.cgroup_id == Some(key.cgroup))
        .collect();
    match matches.len() {
        0 => Ok(ResolvedAssociation {
            key: key.clone(),
            identity: WorkloadIdentity::none(),
            evidence: AttributionEvidence::unresolved(Relationship::HookContext),
        }),
        1 => {
            let entry = matches[0];
            let identity = WorkloadIdentity {
                container: entry.container.clone(),
                pod: entry.pod.clone(),
                cluster: entry.cluster.clone(),
                node: entry.node.clone(),
                ancestor_container: entry.ancestor_container.clone(),
            };
            // Observation coherence: a usable status requires an
            // established identity.
            if !identity.is_resolved() {
                return Ok(ResolvedAssociation {
                    key: key.clone(),
                    identity: WorkloadIdentity::none(),
                    evidence: AttributionEvidence::unresolved(Relationship::HookContext),
                });
            }
            // An explicitly stale binding stays stale.
            if entry.binding.status == AttributionStatus::Stale {
                return Ok(ResolvedAssociation {
                    key: key.clone(),
                    identity,
                    evidence: AttributionEvidence::new(
                        Relationship::HookContext,
                        METHOD_METADATA_FILE,
                        WorkloadOrigin::OperatorMetadataFile,
                        AttributionStatus::Stale,
                        entry.binding.validity,
                    ),
                });
            }
            // Assertion requires capture coverage; uncovered counts stay
            // unknown, never asserted.
            if validity_covers_capture(capture, entry.binding.validity.as_ref()) {
                return Ok(ResolvedAssociation {
                    key: key.clone(),
                    identity,
                    evidence: AttributionEvidence::asserted_metadata(
                        Relationship::HookContext,
                        METHOD_METADATA_FILE,
                        entry.binding.validity,
                    ),
                });
            }
            if entry.binding.validity.is_some() {
                return Ok(ResolvedAssociation {
                    key: key.clone(),
                    identity,
                    evidence: AttributionEvidence::new(
                        Relationship::HookContext,
                        METHOD_METADATA_FILE,
                        WorkloadOrigin::OperatorMetadataFile,
                        AttributionStatus::Stale,
                        entry.binding.validity,
                    ),
                });
            }
            Ok(ResolvedAssociation {
                key: key.clone(),
                identity: WorkloadIdentity::none(),
                evidence: AttributionEvidence::unresolved(Relationship::HookContext),
            })
        }
        _ => Ok(ResolvedAssociation {
            key: key.clone(),
            identity: WorkloadIdentity::none(),
            evidence: AttributionEvidence::new(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                WorkloadOrigin::OperatorMetadataFile,
                AttributionStatus::Ambiguous,
                None,
            ),
        }),
    }
}

/// Recompute exact counters over the current associations/errors.
fn recount(response: &mut SnapshotResponse) {
    let mut resolved: u64 = 0;
    let mut unresolved: u64 = 0;
    for assoc in &response.associations {
        match assoc.evidence.status {
            AttributionStatus::Verified | AttributionStatus::Asserted => resolved += 1,
            AttributionStatus::Unresolved
            | AttributionStatus::Ambiguous
            | AttributionStatus::Stale
            | AttributionStatus::Unsupported => unresolved += 1,
        }
    }
    response.counters = SnapshotCounters {
        resolved,
        unresolved,
        refused: response.errors.len() as u64,
    };
}

/// Convert request-order tail associations into budget errors until the
/// response fits the byte budget. Refuses when even the all-errors
/// response cannot fit.
fn truncate_to_budget(response: &mut SnapshotResponse) -> Result<(), MetadataUnavailable> {
    while response.encoded_len()? > MAX_SNAPSHOT_RESPONSE_BYTES {
        let Some(dropped) = response.associations.pop() else {
            return Err(MetadataUnavailable::BudgetExceeded);
        };
        response.errors.push(SnapshotKeyError {
            key: dropped.key,
            code: SnapshotErrorCode::BudgetExceeded,
            detail: SnapshotKeyDetail::BudgetDropped,
        });
        response.status = ResponseStatus::Truncated;
    }
    Ok(())
}

/// Verify that a response answers a request: session equality, kernel
/// scope agreement (every served association answers a key inside the
/// response kernel scope; only typed kernel refusals may come from a
/// foreign kernel), temporal agreement (every Asserted/Verified
/// association's validity covers the request capture interval),
/// chunk validity, every association/error key drawn from (and
/// covering, for single-chunk responses) the request keys exactly once,
/// and a valid response value. Refusals name the rule, never input bytes.
pub fn bind_response_to_request(
    request: &SnapshotRequest,
    response: &SnapshotResponse,
) -> Result<(), String> {
    request
        .validate()
        .map_err(|e| format!("binding requires a valid request: {e:?}"))?;
    response
        .validate()
        .map_err(|e| format!("binding requires a valid response: {e:?}"))?;
    if response.session_id != request.session_id {
        return Err("response session does not match request session".to_string());
    }
    for assoc in &response.associations {
        if !response
            .kernel_identity
            .matches_scope(&assoc.key.kernel_scope)
        {
            return Err(
                "response association answers a key outside the response kernel scope".to_string(),
            );
        }
        // Receiving-boundary temporal validation (R3): an Asserted or
        // Verified association applies its counts only when its validity
        // window covers the request's counted capture interval — the same
        // coverage rule the resolver enforces when producing replies.
        // Stale and weaker statuses assert nothing about the counted
        // interval, so they carry no temporal requirement here.
        if matches!(
            assoc.evidence.status,
            AttributionStatus::Asserted | AttributionStatus::Verified
        ) && !validity_covers_capture(
            request.capture_interval.as_ref(),
            assoc.evidence.validity.as_ref(),
        ) {
            return Err(
                "response association validity does not cover the request capture interval"
                    .to_string(),
            );
        }
    }
    for error in &response.errors {
        let kernel_refusal = matches!(
            error.code,
            SnapshotErrorCode::KernelMismatch | SnapshotErrorCode::UnknownKernel
        );
        if !kernel_refusal
            && !response
                .kernel_identity
                .matches_scope(&error.key.kernel_scope)
        {
            return Err(
                "response error answers a key outside the response kernel scope".to_string(),
            );
        }
    }
    let mut seen: Vec<&SnapshotKey> = Vec::new();
    for assoc in &response.associations {
        check_key_membership(request, &assoc.key, &mut seen, "association")?;
    }
    for error in &response.errors {
        check_key_membership(request, &error.key, &mut seen, "error")?;
    }
    if response.chunk.total == 1 && seen.len() != request.keys.len() {
        return Err("single-chunk response must cover every request key exactly once".to_string());
    }
    Ok(())
}

/// One membership + duplication check for a bound key.
fn check_key_membership<'k>(
    request: &SnapshotRequest,
    key: &'k SnapshotKey,
    seen: &mut Vec<&'k SnapshotKey>,
    role: &str,
) -> Result<(), String> {
    if !request.keys.contains(key) {
        return Err(format!("response {role} answers no request key"));
    }
    if seen.contains(&key) {
        return Err(format!("request key answered twice by response {role}s"));
    }
    seen.push(key);
    Ok(())
}

/// Whether chunk `indices` form exactly one complete sequence for
/// `total` chunks: every index in `0..total` present exactly once.
#[must_use]
pub fn chunk_sequence_complete(total: u32, indices: &[u32]) -> bool {
    if total == 0 || indices.len() != total as usize {
        return false;
    }
    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    sorted.iter().enumerate().all(|(i, v)| *v == i as u32)
}

#[cfg(test)]
mod tests {
    use super::super::{MetadataEntry, SnapshotInterval};
    use super::*;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    fn key(cgroup: u64) -> SnapshotKey {
        SnapshotKey {
            kernel_scope: "kernel-A".to_string(),
            cgroup,
            tgid: 1000,
            start_ns: 555,
        }
    }

    fn snapshot() -> MetadataSnapshot {
        MetadataSnapshot {
            collector: "test".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: 1000,
                end_ns: 2000,
            },
            kernel_identity: super::super::KernelIdentity::Known("kernel-A".to_string()),
            entries: Vec::new(),
        }
    }

    #[test]
    fn chunk_completeness_is_exact() {
        assert!(chunk_sequence_complete(1, &[0]));
        assert!(chunk_sequence_complete(2, &[1, 0]));
        assert!(!chunk_sequence_complete(0, &[]));
        assert!(!chunk_sequence_complete(2, &[0]));
        assert!(!chunk_sequence_complete(2, &[0, 0, 1]));
        assert!(!chunk_sequence_complete(2, &[0, 2]));
    }

    #[test]
    fn duplicate_answers_refuse_binding() {
        let request = SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: vec![key(1)],
            capture_interval: None,
        };
        let response = resolve(&request, &snapshot()).expect("resolves");
        assert!(bind_response_to_request(&request, &response).is_ok());
        let mut doubled = response.clone();
        doubled.associations.push(doubled.associations[0].clone());
        doubled.counters.unresolved += 1;
        assert!(bind_response_to_request(&request, &doubled).is_err());
    }

    #[test]
    fn key_in_both_association_and_error_refuses() {
        let request = SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: vec![key(1)],
            capture_interval: None,
        };
        let mut response = resolve(&request, &snapshot()).expect("resolves");
        response.errors.push(SnapshotKeyError {
            key: key(1),
            code: SnapshotErrorCode::Unsupported,
            detail: SnapshotKeyDetail::UnsupportedKey,
        });
        response.counters.refused += 1;
        assert!(bind_response_to_request(&request, &response).is_err());
    }

    #[test]
    fn unresolved_cgroup_zero_stays_unknown() {
        let mut zero = key(0);
        zero.cgroup = 0;
        let request = SnapshotRequest {
            session_id: SESSION.to_string(),
            keys: vec![zero],
            capture_interval: None,
        };
        let mut snap = snapshot();
        snap.entries.push(MetadataEntry {
            container: None,
            pod: None,
            cluster: None,
            node: None,
            ancestor_container: None,
            display_name: None,
            cgroup_id: Some(0),
            binding: super::super::BindingProvenance {
                method: METHOD_METADATA_FILE.to_string(),
                source: WorkloadOrigin::OperatorMetadataFile,
                status: AttributionStatus::Asserted,
                validity: None,
            },
        });
        // Cgroup 0 is unreadable: a file claiming cgroup 0 never yields
        // an asserted association — the unknown-cgroup population stays
        // unknown with no identity, counted unresolved.
        let response = resolve(&request, &snap).expect("resolves");
        assert_eq!(response.associations.len(), 1);
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert!(!response.associations[0].identity.is_resolved());
        assert_eq!(response.counters.resolved, 0);
        assert_eq!(response.counters.unresolved, 1);
    }
}
