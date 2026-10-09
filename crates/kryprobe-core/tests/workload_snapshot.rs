// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2A snapshot-contract tests (frozen): typed metadata snapshots,
//! snapshot responses, pure resolution, byte/count budgets, and the exact
//! wire field names consumed by Stage 2B/2C/2D.

use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, BindingProvenance, ChunkInfo, KernelIdentity,
    METHOD_METADATA_FILE, MetadataEntry, MetadataSnapshot, Relationship, ResolvedAssociation,
    ResponseStatus, SnapshotCounters, SnapshotErrorCode, SnapshotKey, SnapshotRequest,
    SnapshotResponse, ValidityInterval, WorkloadIdentity, WorkloadOrigin,
};
use kryprobe_core::workload::{
    MAX_METADATA_BYTES, MAX_SNAPSHOT_ASSOCIATIONS, MAX_SNAPSHOT_REQUEST_BYTES,
    MAX_SNAPSHOT_RESPONSE_BYTES, MAX_STRING_FIELD_BYTES,
};

const SESSION: &str = "0123456789abcdef0123456789abcdef";
const KERNEL_A: &str = "kernel-A/boot-A";
const KERNEL_B: &str = "kernel-B/boot-A";
const KERNEL_A_REBOOTED: &str = "kernel-A/boot-B";

fn key(kernel: &str, cgroup: u64) -> SnapshotKey {
    SnapshotKey {
        kernel_scope: kernel.to_string(),
        cgroup,
        tgid: 1000,
        start_ns: 555,
    }
}

fn request(keys: Vec<SnapshotKey>) -> SnapshotRequest {
    SnapshotRequest {
        session_id: SESSION.to_string(),
        keys,
        capture_interval: None,
    }
}

fn request_with_capture(keys: Vec<SnapshotKey>, start_ns: u64, end_ns: u64) -> SnapshotRequest {
    SnapshotRequest {
        session_id: SESSION.to_string(),
        keys,
        capture_interval: Some(kryprobe_core::workload::SnapshotInterval { start_ns, end_ns }),
    }
}

fn entry(cgroup: u64, validity: Option<ValidityInterval>) -> MetadataEntry {
    MetadataEntry {
        container: Some(kryprobe_core::workload::ContainerRef {
            runtime: "docker://host-a".to_string(),
            id: "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57".to_string(),
            lifetime: Some("lifetime-a".to_string()),
        }),
        pod: None,
        cluster: None,
        node: None,
        ancestor_container: None,
        display_name: Some("web-0".to_string()),
        cgroup_id: Some(cgroup),
        binding: BindingProvenance {
            method: kryprobe_core::workload::METHOD_METADATA_FILE.to_string(),
            source: WorkloadOrigin::OperatorMetadataFile,
            status: AttributionStatus::Asserted,
            validity,
        },
    }
}

fn snapshot(kernel: KernelIdentity, entries: Vec<MetadataEntry>) -> MetadataSnapshot {
    MetadataSnapshot {
        collector: "docker-fixture-v1".to_string(),
        snapshot_interval: kryprobe_core::workload::SnapshotInterval {
            start_ns: 1000,
            end_ns: 2000,
        },
        kernel_identity: kernel,
        entries,
    }
}

/// Metadata from a different kernel or a different boot is refused for
/// a captured key: the resolver compares kernel/boot scope tags, it does
/// not assume them.
#[test]
fn snapshot_kernel_mismatch_is_refused() {
    for wrong_scope in [KERNEL_B, KERNEL_A_REBOOTED] {
        let req = request(vec![key(KERNEL_A, 43812)]);
        let snap = snapshot(
            KernelIdentity::Known(wrong_scope.to_string()),
            vec![entry(43812, None)],
        );
        let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
        assert_eq!(response.associations.len(), 0);
        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].code, SnapshotErrorCode::KernelMismatch);
        assert_eq!(response.errors[0].key, key(KERNEL_A, 43812));
        assert_eq!(response.counters.refused, 1);
    }
}

/// A snapshot that cannot establish its kernel cannot serve any key.
#[test]
fn unknown_snapshot_kernel_is_refused() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(KernelIdentity::Unknown, vec![entry(43812, None)]);
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
    assert_eq!(response.errors.len(), 1);
    assert_eq!(response.errors[0].code, SnapshotErrorCode::UnknownKernel);
}

/// A same-kernel cgroup match whose validity COVERS the capture
/// interval resolves to an asserted association; the pure path never
/// corroborates past asserted.
#[test]
fn same_kernel_match_resolves_asserted() {
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, Some(ValidityInterval::monotonic(500, 2500)))],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
    assert_eq!(response.session_id, SESSION);
    assert_eq!(response.associations.len(), 1);
    assert!(response.errors.is_empty());
    let assoc = &response.associations[0];
    assert_eq!(assoc.key, key(KERNEL_A, 43812));
    assert!(assoc.identity.is_resolved());
    assert_eq!(assoc.evidence.status, AttributionStatus::Asserted);
    assert!(assoc.evidence.validate().is_ok());
    assert_eq!(response.status, ResponseStatus::Complete);
    assert_eq!(
        response.counters,
        SnapshotCounters {
            resolved: 1,
            unresolved: 0,
            refused: 0,
        }
    );
}

/// Two entries claiming one cgroup yield ambiguity, never a merged row.
#[test]
fn duplicate_cgroup_claims_yield_ambiguous() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None), entry(43812, None)],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Ambiguous
    );
    assert!(!response.associations[0].identity.is_resolved());
}

/// Capture coverage gates assertion: a validity window covering the
/// whole counted interval asserts; mere overlap, absent validity, or
/// absent capture never assert. (Round-2 D01 oracles.)
#[test]
fn covered_capture_asserts() {
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, Some(ValidityInterval::monotonic(500, 2500)))],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Asserted
    );
    assert_eq!(response.counters.resolved, 1);
}

#[test]
fn uncovered_capture_with_validity_stays_stale() {
    // B2's trace: counts captured during [100,200] must not receive
    // Asserted metadata whose validity is [1000,2000].
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 100, 200);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, Some(ValidityInterval::monotonic(1000, 2000)))],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Stale
    );
    assert!(response.associations[0].identity.is_resolved());
    assert_eq!(response.counters.resolved, 0);
    assert_eq!(response.counters.unresolved, 1);
}

#[test]
fn uncovered_capture_without_validity_stays_unresolved() {
    // No validity window: applicability cannot be established, so the
    // match retains unknown attribution with no identity.
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert!(!response.associations[0].identity.is_resolved());
    assert_eq!(response.counters.resolved, 0);
    assert_eq!(response.counters.unresolved, 1);
}

#[test]
fn absent_capture_never_asserts() {
    // Without a counted interval, coverage cannot be established: even a
    // wide validity window must not assert.
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, Some(ValidityInterval::monotonic(0, u64::MAX)))],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_ne!(
        response.associations[0].evidence.status,
        AttributionStatus::Asserted
    );
    assert_eq!(response.counters.resolved, 0);
}

/// Typed refusal details round-trip exactly, with static rendering.
/// (Round-2 D09 oracle.)
#[test]
fn typed_error_details_round_trip() {
    use kryprobe_core::workload::SnapshotKeyDetail;
    for detail in [
        SnapshotKeyDetail::KernelDiffers,
        SnapshotKeyDetail::KernelUnknown,
        SnapshotKeyDetail::BudgetDropped,
        SnapshotKeyDetail::UnsupportedKey,
    ] {
        let wire = serde_json::to_string(&detail).expect("serializes");
        let decoded: SnapshotKeyDetail = serde_json::from_str(&wire).expect("decodes");
        assert_eq!(decoded, detail);
        assert!(!format!("{detail}").is_empty());
    }
    assert!(serde_json::from_str::<SnapshotKeyDetail>("\"free text\"").is_err());
}

/// A binding whose validity ended before the snapshot interval stays
/// stale: it is reported with its identity, never as resolved.
#[test]
fn expired_binding_stays_stale() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, Some(ValidityInterval::monotonic(100, 200)))],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Stale
    );
    assert_eq!(response.counters.resolved, 0);
    assert_eq!(response.counters.unresolved, 1);
}

/// A key with no entry stays unresolved in its own association.
#[test]
fn unmatched_key_stays_unresolved() {
    let req = request(vec![key(KERNEL_A, 99999)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert!(!response.associations[0].identity.is_resolved());
}

/// Response-to-request/session binding: wrong session, foreign keys,
/// duplicates, and incomplete single-chunk coverage all refuse.
#[test]
fn response_binding_is_exact() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let good = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
    assert!(kryprobe_core::workload::bind_response_to_request(&req, &good).is_ok());

    let mut wrong_session = good.clone();
    wrong_session.session_id = "ffffffffffffffffffffffffffffffff".to_string();
    assert!(kryprobe_core::workload::bind_response_to_request(&req, &wrong_session).is_err());

    let mut foreign_key = good.clone();
    foreign_key.associations[0].key = key(KERNEL_A, 77777);
    assert!(kryprobe_core::workload::bind_response_to_request(&req, &foreign_key).is_err());

    let mut incomplete = good.clone();
    incomplete.associations.clear();
    incomplete.counters = SnapshotCounters {
        resolved: 0,
        unresolved: 0,
        refused: 0,
    };
    assert!(kryprobe_core::workload::bind_response_to_request(&req, &incomplete).is_err());
}

/// Byte limits apply before allocation/parsing; count limits after.
#[test]
fn codec_enforces_byte_limits_before_parsing() {
    // Oversized request bytes refuse without parsing.
    let big = vec![b'x'; MAX_SNAPSHOT_REQUEST_BYTES + 1];
    assert!(kryprobe_core::workload::decode_request(&big).is_err());
    // Oversized response bytes refuse without parsing.
    let big = vec![b'x'; MAX_SNAPSHOT_RESPONSE_BYTES + 1];
    assert!(kryprobe_core::workload::decode_response(&big).is_err());
    // Oversized metadata bytes refuse without parsing.
    let big = vec![b'x'; MAX_METADATA_BYTES + 1];
    assert!(kryprobe_core::workload::decode_metadata(&big).is_err());
    // Well-formed small DTOs round-trip exactly.
    let req = request(vec![key(KERNEL_A, 43812)]);
    let bytes = kryprobe_core::workload::encode_request(&req).expect("encodes");
    assert_eq!(
        kryprobe_core::workload::decode_request(&bytes).expect("decodes"),
        req
    );
}

/// Malformed requests refuse typed: bad session, empty keys, duplicate
/// keys, over-count keys, oversized scope.
#[test]
fn malformed_requests_refuse_typed() {
    let mut bad_session = request(vec![key(KERNEL_A, 1)]);
    bad_session.session_id = "NOT-HEX-AT-ALL".to_string();
    assert!(kryprobe_core::workload::encode_request(&bad_session).is_err());

    let mut upper_session = request(vec![key(KERNEL_A, 1)]);
    upper_session.session_id = "0123456789ABCDEF0123456789ABCDEF".to_string();
    assert!(kryprobe_core::workload::encode_request(&upper_session).is_err());

    let empty = request(vec![]);
    assert!(kryprobe_core::workload::encode_request(&empty).is_err());

    let dup = request(vec![key(KERNEL_A, 1), key(KERNEL_A, 1)]);
    assert!(kryprobe_core::workload::encode_request(&dup).is_err());

    let many: Vec<SnapshotKey> = (0..(MAX_SNAPSHOT_ASSOCIATIONS + 1) as u64)
        .map(|c| key(KERNEL_A, c + 1))
        .collect();
    assert!(kryprobe_core::workload::encode_request(&request(many)).is_err());

    let mut big_scope = key(KERNEL_A, 1);
    big_scope.kernel_scope = "k".repeat(MAX_STRING_FIELD_BYTES + 1);
    assert!(kryprobe_core::workload::encode_request(&request(vec![big_scope])).is_err());
}

/// A metadata file claiming verified status is rejected: files assert.
#[test]
fn metadata_file_cannot_claim_verified() {
    let mut bad = entry(43812, None);
    bad.binding.status = AttributionStatus::Verified;
    let snap = snapshot(KernelIdentity::Known(KERNEL_A.to_string()), vec![bad]);
    assert!(kryprobe_core::workload::resolve(&request(vec![key(KERNEL_A, 43812)]), &snap).is_err());
}

/// Frozen wire field names: any rename/add/remove breaks this test by
/// design. Stage 2B/2C/2D implement against these exact names.
#[test]
fn wire_field_names_are_frozen() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let req_value = serde_json::to_value(&req).expect("request serializes");
    let req_keys: Vec<&str> = req_value
        .as_object()
        .expect("request is an object")
        .keys()
        .map(String::as_str)
        .collect();
    // The additive capture interval omits itself when unset: old senders
    // encode byte-identical requests.
    assert_eq!(req_keys, vec!["keys", "session_id"]);

    let captured = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    let captured_value = serde_json::to_value(&captured).expect("request serializes");
    let captured_keys: Vec<&str> = captured_value
        .as_object()
        .expect("request is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        captured_keys,
        vec!["capture_interval", "keys", "session_id"]
    );
    let interval_keys: Vec<&str> = captured_value["capture_interval"]
        .as_object()
        .expect("interval is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(interval_keys, vec!["end_ns", "start_ns"]);

    let key_keys: Vec<&str> = req_value["keys"][0]
        .as_object()
        .expect("key is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(key_keys, vec!["cgroup", "kernel_scope", "start_ns", "tgid"]);

    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let response = kryprobe_core::workload::resolve(&request(vec![key(KERNEL_A, 43812)]), &snap)
        .expect("resolver runs");
    let response_value = serde_json::to_value(&response).expect("response serializes");
    let response_keys: Vec<&str> = response_value
        .as_object()
        .expect("response is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        response_keys,
        vec![
            "associations",
            "chunk",
            "counters",
            "errors",
            "kernel_identity",
            "session_id",
            "status"
        ]
    );
}

/// Chunk sequences are complete only with contiguous 0..total indexes.
#[test]
fn chunk_sequences_validate() {
    assert!(kryprobe_core::workload::chunk_sequence_complete(1, &[0]));
    assert!(kryprobe_core::workload::chunk_sequence_complete(
        3,
        &[2, 0, 1]
    ));
    assert!(!kryprobe_core::workload::chunk_sequence_complete(2, &[0]));
    assert!(!kryprobe_core::workload::chunk_sequence_complete(
        2,
        &[0, 0, 1]
    ));
    assert!(!kryprobe_core::workload::chunk_sequence_complete(0, &[]));
    let bad_chunk = ChunkInfo { index: 1, total: 1 };
    assert!(bad_chunk.validate().is_err());
}

/// A response that cannot fit the 64 KiB budget truncates its tail into
/// typed budget errors instead of merging or silently dropping.
#[test]
fn oversized_response_truncates_with_typed_errors() {
    let keys: Vec<SnapshotKey> = (0..MAX_SNAPSHOT_ASSOCIATIONS as u64)
        .map(|c| SnapshotKey {
            kernel_scope: "k".repeat(64),
            cgroup: c + 1,
            tgid: 1000,
            start_ns: 555,
        })
        .collect();
    let entries: Vec<MetadataEntry> = keys
        .iter()
        .map(|k| {
            let mut e = entry(k.cgroup, None);
            e.display_name = Some("d".repeat(256));
            e
        })
        .collect();
    let req = request(keys);
    let snap = snapshot(KernelIdentity::Known("k".repeat(64)), entries);
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolver runs");
    assert_eq!(response.status, ResponseStatus::Truncated);
    assert!(
        response
            .errors
            .iter()
            .any(|e| e.code == SnapshotErrorCode::BudgetExceeded)
    );
    let bytes = kryprobe_core::workload::encode_response(&response).expect("truncated fits");
    assert!(bytes.len() <= MAX_SNAPSHOT_RESPONSE_BYTES);
    // Every request key is still accounted: association or error.
    assert_eq!(
        response.associations.len() + response.errors.len(),
        MAX_SNAPSHOT_ASSOCIATIONS
    );
    // Truncation drops the request-order tail only: associations form a
    // prefix of the request keys.
    for (assoc, key) in response.associations.iter().zip(req.keys.iter()) {
        assert_eq!(&assoc.key, key);
    }
}

/// A key set that cannot fit even as all-errors refuses outright: the
/// caller must split it across smaller requests/chunks.
#[test]
fn unwritable_response_refuses() {
    // Max-size keys (128-char scope, wide numerics) with asserted
    // identity-carrying matches: even the all-errors form of 256 such
    // keys exceeds the 64 KiB budget.
    let keys: Vec<SnapshotKey> = (0..MAX_SNAPSHOT_ASSOCIATIONS as u64)
        .map(|c| SnapshotKey {
            kernel_scope: "k".repeat(128),
            cgroup: u64::MAX - c,
            tgid: u32::MAX,
            start_ns: u64::MAX,
        })
        .collect();
    let entries: Vec<MetadataEntry> = keys
        .iter()
        .map(|k| entry(k.cgroup, Some(ValidityInterval::monotonic(0, u64::MAX))))
        .collect();
    let req = request_with_capture(keys, 1000, 2000);
    let snap = snapshot(KernelIdentity::Known("k".repeat(128)), entries);
    let err = kryprobe_core::workload::resolve(&req, &snap).expect_err("unwritable refuses");
    assert_eq!(
        err,
        kryprobe_core::workload::MetadataUnavailable::BudgetExceeded
    );
}

/// An explicitly Stale binding never resolves Asserted, even when its
/// validity overlaps the snapshot window. (Round-2 D01 oracle.)
#[test]
fn explicit_stale_status_is_honored() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let mut stale_entry = entry(43812, Some(ValidityInterval::monotonic(500, 2500)));
    stale_entry.binding.status = AttributionStatus::Stale;
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![stale_entry],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Stale
    );
    assert_eq!(response.counters.resolved, 0);
    assert_eq!(response.counters.unresolved, 1);
}

/// Matching metadata with NO established identity never asserts and never
/// increments resolved counters (observation coherence). (Round-2 oracle.)
#[test]
fn identityless_match_stays_unresolved() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let bare = MetadataEntry {
        container: None,
        pod: None,
        cluster: None,
        node: None,
        ancestor_container: None,
        display_name: Some("web-0".to_string()),
        cgroup_id: Some(43812),
        binding: BindingProvenance {
            method: kryprobe_core::workload::METHOD_METADATA_FILE.to_string(),
            source: WorkloadOrigin::OperatorMetadataFile,
            status: AttributionStatus::Asserted,
            validity: Some(ValidityInterval::monotonic(500, 2500)),
        },
    };
    let snap = snapshot(KernelIdentity::Known(KERNEL_A.to_string()), vec![bare]);
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert!(!response.associations[0].identity.is_resolved());
    assert_eq!(response.counters.resolved, 0);
    assert_eq!(response.counters.unresolved, 1);
    assert_eq!(response.counters.refused, 0);
}

/// cgroup 0 means unreadable: even an identity-carrying file entry for
/// cgroup 0 never yields asserted identity. (Round-2 oracle.)
#[test]
fn cgroup_zero_with_identity_stays_unknown() {
    let req = request(vec![key(KERNEL_A, 0)]);
    let claimed = entry(0, Some(ValidityInterval::monotonic(500, 2500)));
    let snap = snapshot(KernelIdentity::Known(KERNEL_A.to_string()), vec![claimed]);
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_eq!(response.associations.len(), 1);
    assert_eq!(
        response.associations[0].evidence.status,
        AttributionStatus::Unresolved
    );
    assert!(!response.associations[0].identity.is_resolved());
    assert_eq!(response.counters.resolved, 0);
    assert_eq!(response.counters.unresolved, 1);
}

/// A response serves only keys inside its own kernel scope: retargeting a
/// valid response at another kernel refuses binding. (Round-2 oracle.)
#[test]
fn bound_response_requires_matching_kernel_scope() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let mut response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    response.kernel_identity = KernelIdentity::Known(KERNEL_B.to_string());
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &response).is_err(),
        "foreign-kernel response must not bind served associations"
    );
}

/// A kernel-mismatch refusal is legitimate cross-kernel evidence: it binds
/// to the request it answers. (Round-2 oracle.)
#[test]
fn foreign_kernel_typed_refusal_still_binds() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_B.to_string()),
        vec![entry(43812, None)],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    assert_eq!(response.errors.len(), 1);
    assert_eq!(response.errors[0].code, SnapshotErrorCode::KernelMismatch);
    assert!(kryprobe_core::workload::bind_response_to_request(&req, &response).is_ok());
}

/// Response kernel bounds are enforced: empty or oversized kernel tags
/// refuse validation. (Round-2 oracle.)
#[test]
fn response_kernel_bounds_are_checked() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let mut response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    response.kernel_identity = KernelIdentity::Known(String::new());
    assert!(response.validate().is_err());
    response.kernel_identity = KernelIdentity::Known("k".repeat(129));
    assert!(response.validate().is_err());
}

/// Per-key refusal details are a closed static vocabulary: arbitrary
/// strings never decode. (Round-2 D09 oracle.)
#[test]
fn arbitrary_error_detail_refuses_decode() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    let mut value = serde_json::to_value(&response).expect("serializes");
    value["errors"] = serde_json::json!([{
        "key": {"kernel_scope": KERNEL_A, "cgroup": 43812, "tgid": 1000, "start_ns": 555},
        "code": "unsupported",
        "detail": "attacker-controlled free text",
    }]);
    value["counters"]["refused"] = serde_json::json!(1);
    let bytes = serde_json::to_vec(&value).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_response(&bytes).is_err(),
        "arbitrary detail must refuse"
    );
}

/// Closed IPC schemas: unknown request fields refuse instead of being
/// discarded. (Round-2 oracle; B2's `cgroup_path` example.)
#[test]
fn unknown_request_fields_refuse() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let mut value = serde_json::to_value(&req).expect("serializes");
    value["cgroup_path"] = serde_json::json!("/sys/fs/cgroup/foo");
    let bytes = serde_json::to_vec(&value).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_request(&bytes).is_err(),
        "unknown request field must refuse"
    );
}

/// Closed IPC schemas: unknown response fields refuse at every level.
/// (Round-2 oracle.)
#[test]
fn unknown_response_fields_refuse() {
    let req = request(vec![key(KERNEL_A, 43812)]);
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let response = kryprobe_core::workload::resolve(&req, &snap).expect("resolves");
    let mut value = serde_json::to_value(&response).expect("serializes");
    value["cgroup_path"] = serde_json::json!("/sys/fs/cgroup/foo");
    let bytes = serde_json::to_vec(&value).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_response(&bytes).is_err(),
        "unknown top-level response field must refuse"
    );
    let mut value = serde_json::to_value(&response).expect("serializes");
    value["associations"][0]["cgroup_path"] = serde_json::json!("/sys/fs/cgroup/foo");
    let bytes = serde_json::to_vec(&value).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_response(&bytes).is_err(),
        "unknown nested response field must refuse"
    );
}

/// Closed IPC schemas: unknown metadata fields refuse at every level.
/// (Round-2 oracle.)
#[test]
fn unknown_metadata_fields_refuse() {
    let snap = snapshot(
        KernelIdentity::Known(KERNEL_A.to_string()),
        vec![entry(43812, None)],
    );
    let mut value = serde_json::to_value(&snap).expect("serializes");
    value["cgroup_path"] = serde_json::json!("/sys/fs/cgroup/foo");
    let bytes = serde_json::to_vec(&value).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_metadata(&bytes).is_err(),
        "unknown top-level metadata field must refuse"
    );
    let mut value = serde_json::to_value(&snap).expect("serializes");
    value["entries"][0]["cgroup_path"] = serde_json::json!("/sys/fs/cgroup/foo");
    let bytes = serde_json::to_vec(&value).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_metadata(&bytes).is_err(),
        "unknown nested metadata field must refuse"
    );
}

/// Unused-import guard: every imported contract type is exercised above.
#[test]
fn contract_types_are_all_exercised() {
    let _ = WorkloadIdentity::none();
    let _ = ResponseStatus::Complete;
    let _ = SnapshotErrorCode::Unsupported;
}

fn container_identity() -> WorkloadIdentity {
    WorkloadIdentity::container(
        "docker://host-a",
        "70f16eb35cd4991d07a1545beb8522e7f3f59b6642aa2f2afecff68f2be2eb57",
        Some("lifetime-a"),
    )
}

/// B3 escape-payload shape: matching session/kernel/key, Complete single
/// chunk, exact counters, Asserted `metadata_file` evidence. Coherence is
/// supplied by the caller (identity + validity); the shape itself is the
/// wire the R2 ingress accepted unconditionally.
fn escape_response(
    key: SnapshotKey,
    identity: WorkloadIdentity,
    validity: Option<ValidityInterval>,
) -> SnapshotResponse {
    SnapshotResponse {
        session_id: SESSION.to_string(),
        kernel_identity: KernelIdentity::Known(KERNEL_A.to_string()),
        associations: vec![ResolvedAssociation {
            key,
            identity,
            evidence: AttributionEvidence::asserted_metadata(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                validity,
            ),
        }],
        errors: vec![],
        status: ResponseStatus::Complete,
        chunk: ChunkInfo::single(),
        counters: SnapshotCounters {
            resolved: 1,
            unresolved: 0,
            refused: 0,
        },
    }
}

/// Ingress coherence, variant A: Asserted-with-empty-identity refuses at
/// every receiving boundary — decode, validate, bind. (Round-3 oracle.)
#[test]
fn ingress_asserted_without_identity_refuses() {
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    let response = escape_response(
        key(KERNEL_A, 43812),
        WorkloadIdentity::none(),
        Some(ValidityInterval::monotonic(500, 2500)),
    );
    assert!(
        response.validate().is_err(),
        "Asserted without identity must refuse validate"
    );
    let bytes = serde_json::to_vec(&response).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_response(&bytes).is_err(),
        "Asserted without identity must refuse decode"
    );
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &response).is_err(),
        "Asserted without identity must refuse bind"
    );
}

/// Ingress coherence, variant B: a cgroup-zero key carrying an identity
/// refuses at every receiving boundary. (Round-3 oracle.)
#[test]
fn ingress_cgroup_zero_with_identity_refuses() {
    let req = request_with_capture(vec![key(KERNEL_A, 0)], 1000, 2000);
    let response = escape_response(
        key(KERNEL_A, 0),
        container_identity(),
        Some(ValidityInterval::monotonic(500, 2500)),
    );
    assert!(
        response.validate().is_err(),
        "cgroup-zero with identity must refuse validate"
    );
    let bytes = serde_json::to_vec(&response).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_response(&bytes).is_err(),
        "cgroup-zero with identity must refuse decode"
    );
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &response).is_err(),
        "cgroup-zero with identity must refuse bind"
    );
}

/// Receiving-boundary temporal validation: a coherent Asserted reply whose
/// validity does not cover the request capture interval validates as a
/// value but refuses binding; a covering reply binds. (Round-3 oracle.)
#[test]
fn bind_refuses_asserted_when_validity_does_not_cover_capture() {
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    // Expired binding: validity [100,200] cannot cover capture [1000,2000].
    let expired = escape_response(
        key(KERNEL_A, 43812),
        container_identity(),
        Some(ValidityInterval::monotonic(100, 200)),
    );
    assert!(
        expired.validate().is_ok(),
        "coherent expired reply still validates as a value"
    );
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &expired).is_err(),
        "expired Asserted must refuse bind"
    );
    // Positive control: covering validity binds.
    let covered = escape_response(
        key(KERNEL_A, 43812),
        container_identity(),
        Some(ValidityInterval::monotonic(500, 2500)),
    );
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &covered).is_ok(),
        "covering Asserted must bind"
    );
}

/// Verified replies obey the same receiving-boundary coverage rule: the
/// kernel corroboration proves the binding, not its applicability to the
/// counted interval. (Round-3 oracle.)
#[test]
fn bind_refuses_verified_when_validity_does_not_cover_capture() {
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    let mut response = escape_response(
        key(KERNEL_A, 43812),
        container_identity(),
        Some(ValidityInterval::monotonic(100, 200)),
    );
    response.associations[0].evidence = AttributionEvidence::verified_kernel_capture(
        Relationship::HookContext,
        ValidityInterval::monotonic(100, 200),
    );
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &response).is_err(),
        "expired Verified must refuse bind"
    );
    response.associations[0].evidence = AttributionEvidence::verified_kernel_capture(
        Relationship::HookContext,
        ValidityInterval::monotonic(500, 2500),
    );
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &response).is_ok(),
        "covering Verified must bind"
    );
}

/// Coverage needs both windows: an Asserted reply to a capture-less
/// request, or an Asserted reply with no validity window, cannot
/// establish applicability and refuses binding. (Round-3 oracle.)
#[test]
fn bind_refuses_asserted_without_coverable_window() {
    // No counted interval on the request: nothing to cover.
    let req = request(vec![key(KERNEL_A, 43812)]);
    let reply = escape_response(
        key(KERNEL_A, 43812),
        container_identity(),
        Some(ValidityInterval::monotonic(0, u64::MAX)),
    );
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &reply).is_err(),
        "Asserted to a capture-less request must refuse bind"
    );
    // No validity window on the reply: nothing to cover with.
    let req = request_with_capture(vec![key(KERNEL_A, 43812)], 1000, 2000);
    let reply = escape_response(key(KERNEL_A, 43812), container_identity(), None);
    assert!(
        kryprobe_core::workload::bind_response_to_request(&req, &reply).is_err(),
        "Asserted without validity must refuse bind"
    );
}

/// The closed 6-method IPC vocabulary holds for EVERY status: a
/// schema-invalid method refuses decode even on stale/unresolved/
/// ambiguous/unsupported associations. (Round-3 oracle.)
#[test]
fn schema_invalid_evidence_method_refuses_decode() {
    for status in [
        AttributionStatus::Unresolved,
        AttributionStatus::Ambiguous,
        AttributionStatus::Stale,
        AttributionStatus::Unsupported,
    ] {
        // Stale is usable: it carries an identity; the rest do not.
        let identity = if status == AttributionStatus::Stale {
            container_identity()
        } else {
            WorkloadIdentity::none()
        };
        let mut response = escape_response(
            key(KERNEL_A, 43812),
            identity,
            Some(ValidityInterval::monotonic(500, 2500)),
        );
        response.associations[0].evidence = AttributionEvidence::new(
            Relationship::HookContext,
            "not_a_method",
            WorkloadOrigin::OperatorMetadataFile,
            status,
            Some(ValidityInterval::monotonic(500, 2500)),
        );
        response.counters = SnapshotCounters {
            resolved: 0,
            unresolved: 1,
            refused: 0,
        };
        let bytes = serde_json::to_vec(&response).expect("encodes");
        assert!(
            kryprobe_core::workload::decode_response(&bytes).is_err(),
            "{status:?} with a schema-invalid method must refuse decode"
        );
        assert!(
            response.validate().is_err(),
            "{status:?} with a schema-invalid method must refuse validate"
        );
    }
    // Positive control: the rule is vocabulary membership, not a new
    // status pairing — an in-vocabulary method on an unusual status
    // still decodes.
    let mut response = escape_response(
        key(KERNEL_A, 43812),
        WorkloadIdentity::none(),
        Some(ValidityInterval::monotonic(500, 2500)),
    );
    response.associations[0].evidence = AttributionEvidence::new(
        Relationship::HookContext,
        METHOD_METADATA_FILE,
        WorkloadOrigin::OperatorMetadataFile,
        AttributionStatus::Unresolved,
        Some(ValidityInterval::monotonic(500, 2500)),
    );
    response.counters = SnapshotCounters {
        resolved: 0,
        unresolved: 1,
        refused: 0,
    };
    let bytes = serde_json::to_vec(&response).expect("encodes");
    assert!(
        kryprobe_core::workload::decode_response(&bytes).is_ok(),
        "in-vocabulary method on Unresolved must still decode"
    );
}
