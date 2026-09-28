// SPDX-License-Identifier: GPL-3.0-or-later
//! Live-render tests (moved with the tables from the CLI, 1B-H2/1B-M8).

use kryprobe_core::enums::{BackendId, CallKind, CoverageStatus, EvidencePhase, OperationClass};
use kryprobe_core::evidence::{
    CoverageSummary, DimensionCoverage, IntegrityRef, NativeObservation, NativeResult,
    ValidityInterval,
};
use kryprobe_core::ids::ObservationId;
use kryprobe_report::live_render::{
    LIFECYCLE_MAX_ROWS, render_lifecycle_block, render_lifecycle_histograms, render_watch_tables,
    trailer_dims,
};
use kryprobe_report::{lifecycle_v1_payload, validate_lifecycle_v1};

fn complete_dim() -> DimensionCoverage {
    DimensionCoverage::new(
        CoverageStatus::CompleteForDeclaredBoundary,
        ValidityInterval {
            start_ns: 100,
            end_ns: Some(200),
        },
    )
}

fn healthy_coverage() -> CoverageSummary {
    CoverageSummary {
        target_population: complete_dim(),
        object_discovery: complete_dim(),
        attachment: complete_dim(),
        aggregate_counts: complete_dim(),
        detailed_events: complete_dim(),
        attribution: complete_dim(),
        correlation: complete_dim(),
        completion: complete_dim(),
    }
}

#[test]
fn trailer_names_each_gap_in_kp2_order() {
    // Each dimension alone maps to its kp2 §8 token.
    let cases = [
        ("target_population", "operation"),
        ("object_discovery", "attach"),
        ("attachment", "attach"),
        ("aggregate_counts", "capture-integrity"),
        ("detailed_events", "capture-integrity"),
        ("attribution", "attribution"),
        ("correlation", "correlation"),
        ("completion", "completion"),
    ];
    for (field, token) in cases {
        let mut coverage = healthy_coverage();
        let dim = match field {
            "target_population" => &mut coverage.target_population,
            "object_discovery" => &mut coverage.object_discovery,
            "attachment" => &mut coverage.attachment,
            "aggregate_counts" => &mut coverage.aggregate_counts,
            "detailed_events" => &mut coverage.detailed_events,
            "attribution" => &mut coverage.attribution,
            "correlation" => &mut coverage.correlation,
            "completion" => &mut coverage.completion,
            _ => unreachable!("pinned field list"),
        };
        dim.status = CoverageStatus::Partial;
        assert_eq!(trailer_dims(&coverage), vec![token], "field {field}");
    }
    // Every non-complete status weakens (Unsupported/NotRun/Unknown
    // are gaps too, never COMPLETE).
    for status in [
        CoverageStatus::Partial,
        CoverageStatus::Unsupported,
        CoverageStatus::NotRun,
        CoverageStatus::Unknown,
    ] {
        let mut coverage = healthy_coverage();
        coverage.attachment.status = status;
        assert_eq!(
            trailer_dims(&coverage),
            vec!["attach"],
            "status {status:?} weakens"
        );
    }
    // Multi-gap order is the kp2 §8 order, deduped.
    let mut coverage = healthy_coverage();
    coverage.completion.status = CoverageStatus::Partial;
    coverage.attachment.status = CoverageStatus::Partial;
    coverage.aggregate_counts.status = CoverageStatus::Partial;
    coverage.correlation.status = CoverageStatus::Unknown;
    assert_eq!(
        trailer_dims(&coverage),
        vec!["attach", "capture-integrity", "completion", "correlation"]
    );
    // Contract held (incl. interval end) is COMPLETE.
    assert!(trailer_dims(&healthy_coverage()).is_empty());
}

/// Lifecycle observation with the production live payload shape
/// (`LIFECYCLE_KEYS` dispatch envelope, as the backend emits it).
fn lifecycle_obs(
    id: u64,
    terminal: &str,
    status: serde_json::Value,
    duration_ns: serde_json::Value,
) -> NativeObservation {
    let (phase, call_kind, native_result) = match terminal {
        "unknown" => (
            EvidencePhase::Entered,
            CallKind::Unknown,
            NativeResult::KCryptoUnknown,
        ),
        _ => (
            EvidencePhase::Completed,
            CallKind::Operation,
            NativeResult::KCrypto {
                status: status.as_i64().unwrap_or(0) as i32,
            },
        ),
    };
    NativeObservation {
        id: ObservationId::new(id),
        backend: BackendId::KCrypto,
        target: None,
        object: None,
        implementation: None,
        phase,
        call_kind,
        operation_class: OperationClass::Unknown,
        native_name: None,
        native_code: None,
        native_result,
        started_ns: None,
        ended_ns: None,
        correlation: None,
        integrity: IntegrityRef::new(0),
        backend_payload: serde_json::json!({
            "row": "lifecycle",
            "capture_profile": "request-lifecycle",
            "id": format!("lc:{id}"),
            "tfm_id": 7,
            "terminal": terminal,
            "status": status,
            "duration_ns": duration_ns,
            "evidence": terminal != "unknown",
            "count_unit": "request_lifecycle",
            "completion_coverage": if terminal == "unknown" { "unobserved" } else { "observed" },
        }),
    }
}

/// Sized lifecycle row (P6-N9): the backend's 14-key envelope plus
/// explicit size words (`serde_json::Value` — numbers or null).
#[allow(clippy::too_many_arguments)]
fn lifecycle_obs_sized(
    id: u64,
    terminal: &str,
    status: serde_json::Value,
    duration_ns: serde_json::Value,
    family: &str,
    cryptlen: serde_json::Value,
    assoclen: serde_json::Value,
    authsize: serde_json::Value,
) -> NativeObservation {
    let mut obs = lifecycle_obs(id, terminal, status, duration_ns);
    let payload = obs.backend_payload.as_object_mut().expect("object");
    payload.insert("family".to_owned(), serde_json::json!(family));
    payload.insert("cryptlen".to_owned(), cryptlen);
    payload.insert("assoclen".to_owned(), assoclen);
    payload.insert("authsize".to_owned(), authsize);
    obs
}

#[test]
fn size_histogram_folds_qualified_cryptlen() {
    // P6-N9 RED: the size histogram folds qualified per-request
    // cryptlen bytes (named population/units/bounds/counts):
    // skcipher rows fold their cryptlen; AEAD rows fold theirs only
    // with a known authsize; everything else counts unknown.
    let obs = [
        lifecycle_obs_sized(
            1,
            "sync",
            serde_json::json!(0),
            serde_json::json!("50"),
            "skcipher",
            serde_json::json!(16),
            serde_json::json!(null),
            serde_json::json!(null),
        ),
        lifecycle_obs_sized(
            2,
            "sync",
            serde_json::json!(0),
            serde_json::json!("60"),
            "skcipher",
            serde_json::json!(5000),
            serde_json::json!(null),
            serde_json::json!(null),
        ),
        lifecycle_obs_sized(
            3,
            "callback",
            serde_json::json!(0),
            serde_json::json!("70"),
            "aead",
            serde_json::json!(1040),
            serde_json::json!(32),
            serde_json::json!(16),
        ),
        // AEAD without authsize: cryptlen uninterpretable as payload.
        lifecycle_obs_sized(
            4,
            "sync",
            serde_json::json!(0),
            serde_json::json!("80"),
            "aead",
            serde_json::json!(2000),
            serde_json::json!(8),
            serde_json::json!(null),
        ),
        // Unknown cryptlen stays unknown (never 0-as-data).
        lifecycle_obs_sized(
            5,
            "sync",
            serde_json::json!(0),
            serde_json::json!("90"),
            "skcipher",
            serde_json::json!(null),
            serde_json::json!(null),
            serde_json::json!(null),
        ),
        lifecycle_obs_sized(
            6,
            "unknown",
            serde_json::json!(null),
            serde_json::json!(null),
            "skcipher",
            serde_json::json!(null),
            serde_json::json!(null),
            serde_json::json!(null),
        ),
    ];
    let text = render_lifecycle_histograms(&obs);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "latency + sizes lines:\n{text}");
    let sizes = lines[1];
    assert!(
        sizes.starts_with("HISTOGRAM population=request_cryptlen_bytes unit=bytes "),
        "named population + units: {sizes}"
    );
    assert!(sizes.contains("samples=3"), "exact samples: {sizes}");
    assert!(sizes.contains("unknown=3"), "exact unknown: {sizes}");
    assert!(
        sizes.contains("bounds=[64, 512, 4096, 65536, 1048576]"),
        "explicit bounds: {sizes}"
    );
    assert!(
        sizes.contains("counts=[1, 0, 1, 1, 0, 0]"),
        "16/1040/5000 land in buckets 0/2/3: {sizes}"
    );
    assert!(
        !sizes.contains("mode=sampled"),
        "no announcement under the cap: {sizes}"
    );
}

#[test]
fn authsize_less_aead_contributes_no_payload_bytes() {
    // P6-N9 constraint pin: an AEAD row with known cryptlen but
    // unknown authsize contributes NOTHING (no ambiguous totals).
    let obs = [lifecycle_obs_sized(
        1,
        "sync",
        serde_json::json!(0),
        serde_json::json!("50"),
        "aead",
        serde_json::json!(100),
        serde_json::json!(16),
        serde_json::json!(null),
    )];
    let text = render_lifecycle_histograms(&obs);
    let sizes = text.lines().nth(1).expect("sizes line");
    assert!(sizes.contains("samples=0"), "no payload bytes: {sizes}");
    assert!(sizes.contains("unknown=1"), "counted unknown: {sizes}");
}

#[test]
fn lifecycle_projection_emits_valid_v1() {
    // Grounded + unknown rows project to exactly the six schema keys
    // and validate clean; non-lifecycle rows project to None.
    for (terminal, status, duration) in [
        ("sync", serde_json::json!(0), serde_json::json!("50")),
        ("callback", serde_json::json!(-5), serde_json::json!("70")),
        ("unknown", serde_json::json!(null), serde_json::json!(null)),
    ] {
        let obs = lifecycle_obs(1, terminal, status, duration);
        let projected = lifecycle_v1_payload(&obs)
            .expect("lifecycle row projects")
            .expect("projection validates");
        let mut keys: Vec<&str> = projected
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "duration_ns",
                "request_id",
                "schema",
                "status",
                "terminal",
                "tfm_id"
            ],
            "exactly the six schema keys"
        );
        assert_eq!(projected["schema"], "kryprobe.kcrypto.lifecycle/v1");
        assert_eq!(projected["request_id"], "lc:1");
        assert_eq!(projected["tfm_id"], "kcrypto:tfm-7");
        assert!(
            validate_lifecycle_v1(&projected).is_empty(),
            "projected payload validates"
        );
    }
    let mut agg = lifecycle_obs(2, "sync", serde_json::json!(0), serde_json::json!("50"));
    agg.backend_payload["row"] = serde_json::json!("agg");
    assert!(
        lifecycle_v1_payload(&agg).is_none(),
        "non-lifecycle rows do not project"
    );
}

#[test]
fn lifecycle_projection_fails_closed_on_drift() {
    // A forbidden combination (unknown terminal carrying a duration)
    // fails the projection — the report breaks (exit 1) rather than
    // emitting a schema-violating document.
    let obs = lifecycle_obs(
        3,
        "unknown",
        serde_json::json!(null),
        serde_json::json!("50"),
    );
    let err = lifecycle_v1_payload(&obs)
        .expect("lifecycle row projects")
        .expect_err("unknown+duration must fail");
    assert!(err.contains("payload-v1"), "names the artifact: {err}");
}

#[test]
fn lifecycle_block_renders_rows_and_exact_totals() {
    let obs = [
        lifecycle_obs(2, "sync", serde_json::json!(0), serde_json::json!("50")),
        lifecycle_obs(
            1,
            "unknown",
            serde_json::json!(null),
            serde_json::json!(null),
        ),
        lifecycle_obs(
            3,
            "callback",
            serde_json::json!(-5),
            serde_json::json!("70"),
        ),
    ];
    let text = render_lifecycle_block(&obs);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "ID TERMINAL STATUS DURATION_NS");
    // Sorted by id, unknowns render `unknown` (never zero-filled).
    assert_eq!(lines[1], "lc:1 unknown unknown unknown");
    assert_eq!(lines[2], "lc:2 sync 0 50");
    assert_eq!(lines[3], "lc:3 callback -5 70");
    assert_eq!(lines[4], "LIFECYCLE TOTAL n=3 sync=1 callback=1 unknown=1");
    assert_eq!(lines.len(), 5);
    // Empty renders nothing (agg sessions keep exact bytes).
    assert_eq!(render_lifecycle_block(&[]), "");
}

#[test]
fn watch_tables_carry_lifecycle_sessions() {
    // A lifecycle-only session no longer reports zero activity: the
    // lifecycle block follows the (empty) agg table.
    let obs = [lifecycle_obs(
        1,
        "sync",
        serde_json::json!(0),
        serde_json::json!("50"),
    )];
    let text = render_watch_tables(&obs, &healthy_coverage());
    assert!(
        text.contains("LIFECYCLE TOTAL n=1 sync=1 callback=0 unknown=0"),
        "lifecycle activity reported:\n{text}"
    );
    assert!(text.ends_with("COMPLETE\n"), "trailer intact:\n{text}");
}

#[test]
fn histograms_fold_every_row_with_named_populations() {
    // Two grounded rows (50ns, 70ns) + one unknown: the latency
    // histogram names its population/units/bounds/counts and folds
    // exactly the two latencies; the unknown's null duration is
    // absent (not zero, not extrapolated); sizes stay explicit
    // unavailable.
    let obs = [
        lifecycle_obs(2, "sync", serde_json::json!(0), serde_json::json!("50")),
        lifecycle_obs(
            1,
            "unknown",
            serde_json::json!(null),
            serde_json::json!(null),
        ),
        lifecycle_obs(
            3,
            "callback",
            serde_json::json!(-5),
            serde_json::json!("70"),
        ),
    ];
    let text = render_lifecycle_histograms(&obs);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "latency + sizes lines:\n{text}");
    assert!(
        lines[0].starts_with("HISTOGRAM population=terminal_latency_ns unit=ns "),
        "named population + units: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("samples=2"),
        "exact samples: {}",
        lines[0]
    );
    assert!(lines[0].contains("unparsed=0"), "no unparsed: {}", lines[0]);
    assert!(
        lines[0].contains("bounds=[100, 1000, 10000, 100000, 1000000, 10000000]"),
        "explicit bounds: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("counts=[2, 0, 0, 0, 0, 0, 0]"),
        "both latencies in the first bucket: {}",
        lines[0]
    );
    assert!(
        !lines[0].contains("mode=sampled"),
        "no announcement under the cap: {}",
        lines[0]
    );
    // P6-N9: the sizes line is a real histogram now — these rows
    // carry no size words, so all three count unknown (never folded,
    // never zero-filled).
    assert_eq!(
        lines[1],
        "HISTOGRAM population=request_cryptlen_bytes unit=bytes samples=0 unknown=3 bounds=[64, 512, 4096, 65536, 1048576] counts=[0, 0, 0, 0, 0, 0]"
    );
    // Empty renders nothing (agg sessions keep exact bytes).
    assert_eq!(render_lifecycle_histograms(&[]), "");
}

#[test]
fn histograms_cover_collapsed_details_and_announce_sampling() {
    // LIFECYCLE_MAX_ROWS + 5 rows: details collapse in the block but
    // the histogram still folds every latency, and announces the
    // mode change.
    let obs: Vec<NativeObservation> = (0..LIFECYCLE_MAX_ROWS + 5)
        .map(|i| {
            lifecycle_obs(
                i as u64,
                "sync",
                serde_json::json!(0),
                serde_json::json!("5000"),
            )
        })
        .collect();
    let block = render_lifecycle_block(&obs);
    assert!(
        block.contains(&format!("+{} more", 5)),
        "details collapse:\n{block}"
    );
    let text = render_lifecycle_histograms(&obs);
    assert!(
        text.contains(&format!("samples={}", LIFECYCLE_MAX_ROWS + 5)),
        "aggregate independent of sampled details:\n{text}"
    );
    assert!(
        text.contains("mode=sampled"),
        "mode change announced:\n{text}"
    );
    // And the tables carry the block ahead of the trailer.
    let tables = render_watch_tables(&obs, &healthy_coverage());
    assert!(
        tables.contains("HISTOGRAM population=terminal_latency_ns"),
        "tables publish histograms:\n{tables}"
    );
    assert!(tables.ends_with("COMPLETE\n"), "trailer intact");
}

#[test]
fn filtered_tables_carry_exact_filter_line() {
    // P6-N3: an active filter adds the exact FILTER line ahead of
    // the trailer; None renders byte-identical unfiltered tables.
    use kryprobe_report::live_render::{FilterCounts, render_watch_tables_filtered};
    let obs = [lifecycle_obs(
        1,
        "sync",
        serde_json::json!(0),
        serde_json::json!("50"),
    )];
    let plain = render_watch_tables(&obs, &healthy_coverage());
    assert!(
        !plain.contains("FILTER admitted="),
        "unfiltered tables carry no FILTER line:\n{plain}"
    );
    assert_eq!(
        render_watch_tables_filtered(&obs, &healthy_coverage(), None),
        plain,
        "None is byte-identical"
    );
    let filtered = render_watch_tables_filtered(
        &obs,
        &healthy_coverage(),
        Some(FilterCounts {
            admitted: 1,
            filtered: 2,
            unknown: 3,
        }),
    );
    assert!(
        filtered.contains("FILTER admitted=1 filtered=2 unknown=3\n"),
        "exact FILTER line:\n{filtered}"
    );
    assert!(
        filtered.ends_with("FILTER admitted=1 filtered=2 unknown=3\nCOMPLETE\n"),
        "FILTER line sits ahead of the trailer:\n{filtered}"
    );
}
