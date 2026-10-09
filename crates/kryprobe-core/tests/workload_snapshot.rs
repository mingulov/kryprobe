// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Stage 2A snapshot-contract tests (frozen): typed metadata snapshots,
//! snapshot responses, pure resolution, byte/count budgets, and the exact
//! wire field names consumed by Stage 2B/2C/2D.

use kryprobe_core::workload::{
    AttributionStatus, BindingProvenance, ChunkInfo, KernelIdentity, MetadataEntry,
    MetadataSnapshot, ResponseStatus, SnapshotCounters, SnapshotErrorCode, SnapshotKey,
    SnapshotRequest, ValidityInterval, WorkloadIdentity, WorkloadOrigin,
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

/// A same-kernel cgroup match resolves to an asserted association; the
/// pure path never corroborates past asserted.
#[test]
fn same_kernel_match_resolves_asserted() {
    let req = request(vec![key(KERNEL_A, 43812)]);
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
    assert_eq!(req_keys, vec!["keys", "session_id"]);

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
    let keys: Vec<SnapshotKey> = (0..MAX_SNAPSHOT_ASSOCIATIONS as u64)
        .map(|c| SnapshotKey {
            kernel_scope: "k".repeat(128),
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
    let snap = snapshot(KernelIdentity::Known("k".repeat(128)), entries);
    let err = kryprobe_core::workload::resolve(&req, &snap).expect_err("unwritable refuses");
    assert_eq!(
        err,
        kryprobe_core::workload::MetadataUnavailable::BudgetExceeded
    );
}

/// Unused-import guard: every imported contract type is exercised above.
#[test]
fn contract_types_are_all_exercised() {
    let _ = WorkloadIdentity::none();
    let _ = ResponseStatus::Complete;
    let _ = SnapshotErrorCode::Unsupported;
}
