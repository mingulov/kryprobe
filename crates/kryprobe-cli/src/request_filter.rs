// SPDX-License-Identifier: GPL-3.0-or-later
//! Post-ingestion per-request submitter filtering (P6-N3).
//!
//! Applies [`ContextFilter`](kryprobe_privilege::kcrypto_context::ContextFilter)
//! to captured observations AFTER ingestion, per request — capture is
//! unfiltered, views filter. Wired into the production watch/report
//! paths (CLI `--filter-pid`/`--filter-uid`/`--filter-comm`):
//!
//! - api-returns who rows (the qualifiable path): the submitter is
//!   rebuilt from the row's own scalars through
//!   [`SubmitterContext::from_who`](kryprobe_privilege::kcrypto_context::SubmitterContext::from_who)
//!   plus a userspace start-marker read. `Admitted` rows render,
//!   `FilteredOut` rows hide, `Unknown` rows render (filters hide
//!   only PROVED mismatches — unevaluable rows stay visible and
//!   count `unknown`, never admitted-by-default).
//! - request-lifecycle rows: contexts are explicit-unavailable
//!   (frozen edges carry no task identity — never guessed), so a
//!   constrained row evaluates `Unknown` under the CLI's `Exclude`
//!   policy — and ALWAYS renders: an admitted completion follows
//!   its request, and the filter never splits sync from callback
//!   terminals.
//! - agg/totals/ident rows are snapshots, not requests: they pass
//!   through UNEVALUATED (never tallied).
//!
//! Tallies are exact (every evaluated request lands in exactly one
//! population) and ride the coverage `filter_*` counters, the human
//! FILTER line, and (lifecycle) the session envelope.

use crate::args::FilterArgs;
use kryprobe_abi::kcrypto_agg::{KWhoKey, VWho};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCounter, NativeObservation, payload_keys as K,
};
use kryprobe_privilege::kcrypto_context::{
    CompletionContext, ContextFilter, ExecutionContext, FilterTally, FilterVerdict, RequestContext,
    SubmitterContext, UnknownPolicy, apply_filter, read_start_marker,
};
use serde_json::Value;

/// Evidence version stamped on filtered request contexts: the
/// producing binary + workspace version (names what produced the
/// bytes — the CLI and report crates share one workspace version, so
/// this is true for the binary too).
pub(crate) const EVIDENCE_VERSION: &str = concat!("kryprobe/", env!("CARGO_PKG_VERSION"));

/// Builds the production [`ContextFilter`] from CLI flags: exact
/// submitter constraints, unknown policy always `Exclude`
/// (unresolvable requests count `unknown`, never admitted).
#[must_use]
pub fn context_filter(args: &FilterArgs) -> ContextFilter {
    ContextFilter {
        submitter_pid: args.pid,
        submitter_uid: args.uid,
        submitter_comm: args.comm.clone(),
        unknown_policy: UnknownPolicy::Exclude,
    }
}

/// One filtered view: the rendered observations plus the exact tally
/// and the envelope unknown population.
#[derive(Debug, Clone)]
pub struct FilteredView {
    /// Rendered observations (admitted + unknown + unevaluated
    /// snapshots; filtered-out request rows hidden).
    pub observations: Vec<NativeObservation>,
    /// Exact verdict tally over the EVALUATED requests.
    pub tally: FilterTally,
    /// Envelope `unknown` population (P6-N3 union rule): lifecycle
    /// rows with an unknown terminal OR an unknown filter verdict,
    /// plus who rows with an unknown verdict — exact, no
    /// double-count (a row in both counts once).
    pub unknown_union: u64,
}

/// u32 scalar from a decoded row (shape-checked — never truncated).
fn u32_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<u32> {
    obj.get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

/// u64 scalar from a decoded row.
fn u64_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    obj.get(key).and_then(serde_json::Value::as_u64)
}

/// Copies a comm string into `TASK_COMM_LEN` bytes (truncate on a
/// char boundary, NUL-pad — the kernel shape `from_who` decodes).
fn comm_bytes(comm: &str) -> [u8; 16] {
    let bytes = comm.as_bytes();
    let mut len = bytes.len().min(16);
    while len > 0 && !comm.is_char_boundary(len) {
        len -= 1;
    }
    let mut out = [0u8; 16];
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// Rebuilds the ABI who structs from a decoded who payload, then
/// qualifies the submitter through [`SubmitterContext::from_who`]
/// (the JSON carries every scalar the ABI row had, so the rebuilt
/// context equals the decode-time one for the same marker — ASCII
/// comms round-trip exactly; lossy-decoded comms match what the row
/// visibly carries, truncated to `TASK_COMM_LEN`). Returns `None`
/// when a required scalar is missing or misshaped: the submitter is
/// unavailable then, never guessed. Display-only words (`calls`,
/// `first_ns`, `last_ns`, unparseable `stack.id`) degrade without
/// voiding the row — they never gate a filter.
fn submitter_from_who_payload(
    payload: &serde_json::Value,
    marker: Option<u64>,
) -> Option<SubmitterContext> {
    let obj = payload.as_object()?;
    let key = KWhoKey {
        kh: u64_field(obj, K::KEY_HASH)?,
        tgid: u32_field(obj, K::TGID)?,
        _pad: 0,
    };
    let val = VWho {
        comm: comm_bytes(obj.get(K::COMM)?.as_str()?),
        tid: u32_field(obj, K::TID)?,
        uid: u32_field(obj, K::UID)?,
        cgroup: u64_field(obj, K::CGROUP)?,
        ppid: u32_field(obj, K::PPID).unwrap_or(0),
        pcomm: obj
            .get(K::PCOMM)
            .and_then(serde_json::Value::as_str)
            .map(comm_bytes)
            .unwrap_or([0u8; 16]),
        stack: obj
            .get(K::STACK)
            .and_then(|stack| stack.get(K::ID))
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .unwrap_or(-1),
        calls: u64_field(obj, K::CALLS).unwrap_or(0),
        first_ns: u64_field(obj, K::FIRST_NS).unwrap_or(0),
        last_ns: u64_field(obj, K::LAST_NS).unwrap_or(0),
    };
    Some(SubmitterContext::from_who(&key, &val, marker))
}

/// One who row's request contexts: submitter qualified from the row
/// (or unavailable), execution in the caller's process context, the
/// observed return as its completion. A row that does not rebuild
/// keeps an unavailable submitter with an unknown execution — never
/// a guessed identity.
fn who_request(
    payload: &serde_json::Value,
    evidence_version: &str,
    rule_version: &str,
) -> RequestContext {
    let tid = payload.as_object().and_then(|obj| u32_field(obj, K::TID));
    let tgid = payload.as_object().and_then(|obj| u32_field(obj, K::TGID));
    let kh = payload
        .as_object()
        .and_then(|obj| u64_field(obj, K::KEY_HASH));
    let marker = tid.and_then(read_start_marker);
    let submitter = submitter_from_who_payload(payload, marker);
    let request_id = match (kh, tgid) {
        (Some(kh), Some(tgid)) => format!("who:{kh}:{tgid}"),
        _ => "who:unknown".to_owned(),
    };
    match submitter {
        Some(submitter) => {
            let execution = ExecutionContext::process(submitter.lifetime);
            RequestContext {
                request_id,
                submitter: Some(submitter),
                execution,
                completion: Some(CompletionContext::follows(execution)),
                evidence_version: evidence_version.to_owned(),
                rule_version: rule_version.to_owned(),
                consumer_label: None,
            }
        }
        None => RequestContext {
            request_id,
            submitter: None,
            execution: ExecutionContext::unknown(),
            completion: None,
            evidence_version: evidence_version.to_owned(),
            rule_version: rule_version.to_owned(),
            consumer_label: None,
        },
    }
}

/// Applies `filter` to `observations` (post-ingestion, per request).
/// See the module docs for the per-row rules. Pure over the rows
/// except the start-marker reads (userspace `/proc` truth, read at
/// filter time — dead tasks read unqualified, never guessed).
#[must_use]
pub fn apply_request_filter(
    observations: &[NativeObservation],
    filter: &ContextFilter,
    evidence_version: &str,
    rule_version: &str,
) -> FilteredView {
    let mut rendered = Vec::with_capacity(observations.len());
    let mut tally = FilterTally::default();
    let mut unknown_union = 0u64;
    for (index, obs) in observations.iter().enumerate() {
        let payload = &obs.backend_payload;
        let row = payload.get(K::ROW).and_then(serde_json::Value::as_str);
        match row {
            Some("who") => {
                let req = who_request(payload, evidence_version, rule_version);
                let verdict = apply_filter(&req, filter);
                tally.record(verdict);
                match verdict {
                    FilterVerdict::Admitted | FilterVerdict::Unknown => {
                        if verdict == FilterVerdict::Unknown {
                            unknown_union = unknown_union.saturating_add(1);
                        }
                        rendered.push(obs.clone());
                    }
                    FilterVerdict::FilteredOut => {}
                }
            }
            Some("lifecycle") => {
                let id = payload
                    .get(K::ID)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("lifecycle-row-{index}"));
                let req = RequestContext::lifecycle_unobserved(&id, evidence_version, rule_version);
                let verdict = apply_filter(&req, filter);
                tally.record(verdict);
                // Lifecycle rows always render (explicit-unavailable
                // contexts are shown, never gated): an admitted
                // completion follows its request.
                let terminal_unknown =
                    payload.get(K::TERMINAL).and_then(serde_json::Value::as_str) == Some("unknown");
                if terminal_unknown || verdict == FilterVerdict::Unknown {
                    unknown_union = unknown_union.saturating_add(1);
                }
                rendered.push(obs.clone());
            }
            // Snapshots, not requests: pass through unevaluated.
            _ => rendered.push(obs.clone()),
        }
    }
    FilteredView {
        observations: rendered,
        tally,
        unknown_union,
    }
}

/// Pushes the exact filter tally into the coverage attribution
/// dimension (verdict-neutral counters — the status is untouched;
/// filtering judges views, never coverage). Callers push only when
/// the filter is active, so unfiltered sessions keep their exact
/// existing coverage bytes.
pub fn push_filter_counters(coverage: &mut CoverageSummary, tally: &FilterTally) {
    coverage.attribution.counters.push(DimensionCounter {
        name: "filter_admitted".to_owned(),
        value: tally.admitted,
    });
    coverage.attribution.counters.push(DimensionCounter {
        name: "filter_filtered".to_owned(),
        value: tally.filtered_out,
    });
    coverage.attribution.counters.push(DimensionCounter {
        name: "filter_unknown".to_owned(),
        value: tally.unknown,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_core::enums::{BackendId, CallKind, EvidencePhase, OperationClass};
    use kryprobe_core::evidence::{IntegrityRef, NativeResult};
    use kryprobe_core::ids::ObservationId;

    fn who_obs(tid: u32, tgid: u32, comm: &str, uid: u32) -> NativeObservation {
        NativeObservation {
            id: ObservationId::new(u64::from(tid)),
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Discovered,
            call_kind: CallKind::Unknown,
            operation_class: OperationClass::Unknown,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns: None,
            ended_ns: None,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "who",
                "key_hash": 194,
                "tgid": tgid,
                "tid": tid,
                "comm": comm,
                "uid": uid,
                "cgroup": 7,
                "stack": {"id": -22, "frames": []},
                "calls": 6,
                "first_ns": 10,
                "last_ns": 20,
                "capture_profile": "api-returns",
            }),
        }
    }

    fn lifecycle_obs(id: &str, terminal: &str) -> NativeObservation {
        let grounded = terminal != "unknown";
        NativeObservation {
            id: ObservationId::new(1),
            backend: BackendId::KCrypto,
            target: None,
            object: None,
            implementation: None,
            phase: EvidencePhase::Completed,
            call_kind: CallKind::Operation,
            operation_class: OperationClass::Unknown,
            native_name: None,
            native_code: None,
            native_result: NativeResult::KCrypto { status: 0 },
            started_ns: None,
            ended_ns: None,
            correlation: None,
            integrity: IntegrityRef::new(0),
            backend_payload: serde_json::json!({
                "row": "lifecycle",
                "capture_profile": "request-lifecycle",
                "id": id,
                "tfm_id": null,
                "terminal": terminal,
                "status": if grounded { serde_json::json!(0) } else { serde_json::json!(null) },
                "duration_ns": if grounded { serde_json::json!("50") } else { serde_json::json!(null) },
                "evidence": grounded,
                "count_unit": "request_lifecycle",
                "completion_coverage": if grounded { "observed" } else { "unobserved" },
                "family": "skcipher",
                "cryptlen": 16,
                "assoclen": null,
                "authsize": null,
            }),
        }
    }

    fn pid_filter(pid: u32) -> ContextFilter {
        ContextFilter {
            submitter_pid: Some(pid),
            submitter_uid: None,
            submitter_comm: None,
            unknown_policy: UnknownPolicy::Exclude,
        }
    }

    #[test]
    fn who_rows_admit_and_filter_exactly() {
        // Matching pid admits, mismatched hides, tally exact.
        let obs = [
            who_obs(101, 100, "bash", 1000),
            who_obs(102, 100, "bash", 1000),
        ];
        let view = apply_request_filter(&obs, &pid_filter(101), "evidence:v1", "rule:v1");
        assert_eq!(view.observations.len(), 1);
        assert_eq!(
            view.observations[0].backend_payload["tid"],
            serde_json::json!(101)
        );
        assert_eq!(
            view.tally,
            FilterTally {
                admitted: 1,
                filtered_out: 1,
                unknown: 0,
            }
        );
        assert_eq!(view.unknown_union, 0);
    }

    #[test]
    fn who_row_missing_tid_counts_unknown_and_stays_visible() {
        // A who row without its tid cannot qualify: unknown verdict,
        // still rendered (filters hide only proved mismatches).
        let mut obs = who_obs(101, 100, "bash", 1000);
        obs.backend_payload
            .as_object_mut()
            .expect("object")
            .remove("tid");
        let view = apply_request_filter(&[obs], &pid_filter(101), "evidence:v1", "rule:v1");
        assert_eq!(view.observations.len(), 1, "unknown stays visible");
        assert_eq!(view.tally.unknown, 1);
        assert_eq!(view.unknown_union, 1);
    }

    #[test]
    fn lifecycle_rows_evaluate_unknown_and_always_render() {
        // Unobserved contexts under a constraint: Unknown verdicts,
        // every row rendered (completion follows its request — the
        // callback row is never split from its request).
        let obs = [
            lifecycle_obs("lc:1", "sync"),
            lifecycle_obs("lc:2", "callback"),
            lifecycle_obs("lc:3", "unknown"),
        ];
        let view = apply_request_filter(&obs, &pid_filter(101), "evidence:v1", "rule:v1");
        assert_eq!(view.observations.len(), 3, "lifecycle never gates rows");
        assert_eq!(view.tally.unknown, 3);
        assert_eq!(view.tally.admitted, 0);
        assert_eq!(view.tally.filtered_out, 0);
        // Union: all three verdict-unknown (one also terminal-unknown
        // — counted once, never twice).
        assert_eq!(view.unknown_union, 3);
    }

    #[test]
    fn unconstrained_filter_admits_everything() {
        // No constraints: every request admits (unfiltered sessions
        // keep their exact existing bytes — the CLI skips filtering
        // entirely when inactive, and this pins the engine).
        let obs = [
            who_obs(101, 100, "bash", 1000),
            lifecycle_obs("lc:1", "sync"),
        ];
        let view = apply_request_filter(&obs, &ContextFilter::default(), "evidence:v1", "rule:v1");
        assert_eq!(view.observations.len(), 2);
        assert_eq!(view.tally.admitted, 2);
        assert_eq!(view.unknown_union, 0);
    }

    #[test]
    fn snapshots_pass_through_unevaluated() {
        // Agg rows are not requests: rendered, never tallied.
        let mut obs = who_obs(101, 100, "bash", 1000);
        obs.backend_payload
            .as_object_mut()
            .expect("object")
            .insert("row".to_owned(), serde_json::json!("agg"));
        let view = apply_request_filter(&[obs], &pid_filter(999), "evidence:v1", "rule:v1");
        assert_eq!(view.observations.len(), 1);
        assert_eq!(view.tally.total(), 0, "snapshots never tally");
    }

    #[test]
    fn comm_filter_matches_exactly() {
        let obs = [
            who_obs(101, 100, "bash", 1000),
            who_obs(102, 100, "sh", 1000),
        ];
        let filter = ContextFilter {
            submitter_comm: Some("bash".to_owned()),
            ..ContextFilter::default()
        };
        let view = apply_request_filter(&obs, &filter, "evidence:v1", "rule:v1");
        assert_eq!(view.observations.len(), 1);
        assert_eq!(view.tally.admitted, 1);
        assert_eq!(view.tally.filtered_out, 1);
    }
}
