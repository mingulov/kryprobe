// SPDX-License-Identifier: GPL-3.0-or-later
//! Ledger oracle tests: the fixture's JSONL truth parses into
//! per-request records, and every corruption class is rejected.
//! Truth never comes from KryProbe aggregates, decoder or counters.

use kryprobe_testkit::kernel_crypto_ledger::{LedgerError, parse_ledger};

/// One async submit: entry, EINPROGRESS return, progress callback,
/// terminal success, run DONE. Two callback notifications (progress
/// + terminal), one completed request.
const LITERAL_ASYNC_SUBMIT: &str = r#"{"v":1,"run":"run-1","seq":7,"phase":"submit","op":"encrypt","ts":1000,"cpu":3}
{"v":1,"run":"run-1","seq":7,"phase":"return","errno":-115,"ts":1200,"cpu":3}
{"v":1,"run":"run-1","seq":7,"phase":"progress","errno":-115,"ts":1500,"cpu":5}
{"v":1,"run":"run-1","seq":7,"phase":"terminal","errno":0,"ts":1800,"cpu":5}
{"v":1,"run":"run-1","phase":"done","fixture_result":0,"overflow":0,"ts":1900}
"#;

#[test]
fn literal_async_submit_yields_one_completed_request_and_two_notifications() {
    let ledger = parse_ledger("run-1", LITERAL_ASYNC_SUBMIT).expect("literal parses");
    assert_eq!(ledger.run_id, "run-1");
    assert!(ledger.done, "run reached DONE");
    assert_eq!(ledger.requests.len(), 1, "exactly one request");
    let req = &ledger.requests[0];
    assert_eq!(req.seq, 7);
    assert_eq!(req.submit_op, "encrypt", "submit op label carried");
    assert_eq!(req.return_errno, -115, "submit-return errno carried");
    assert_eq!(req.progress_errno, Some(-115), "progress errno carried");
    assert_eq!(req.terminal_errno, 0, "terminal success");
    assert_eq!(req.notifications, 2, "progress + terminal notifications");
}

#[test]
fn terminal_without_errno_rejected() {
    let text =
        LITERAL_ASYNC_SUBMIT.replace(r#""phase":"terminal","errno":0"#, r#""phase":"terminal""#);
    let err = parse_ledger("run-1", &text).expect_err("errno-less terminal rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn terminal_before_return_parses() {
    // Genuine preemption interleaving (matrix Q04): the terminal
    // lands before the return row. Return existence is required,
    // return order is not.
    let mut lines: Vec<&str> = LITERAL_ASYNC_SUBMIT.lines().collect();
    lines.swap(1, 3);
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let ledger = parse_ledger("run-1", &text).expect("interleaving parses");
    assert_eq!(ledger.requests.len(), 1);
    let req = &ledger.requests[0];
    assert_eq!(req.return_errno, -115);
    assert_eq!(req.terminal_errno, 0);
    assert_eq!(req.notifications, 2);
}

#[test]
fn submit_without_op_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(r#""op":"encrypt","#, "");
    let err = parse_ledger("run-1", &text).expect_err("op-less submit rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

const TERMINAL_ROW: &str =
    r#"{"v":1,"run":"run-1","seq":7,"phase":"terminal","errno":0,"ts":1800,"cpu":5}"#;
const DONE_ROW: &str =
    r#"{"v":1,"run":"run-1","phase":"done","fixture_result":0,"overflow":0,"ts":1900}"#;

#[test]
fn duplicate_terminal_row_rejected() {
    // Duplicate lands BEFORE done: still the DuplicateRow class
    // (anything after DONE is row-after-done instead).
    let text: String = LITERAL_ASYNC_SUBMIT
        .lines()
        .flat_map(|l| {
            if l.contains(r#""phase":"done""#) {
                vec![TERMINAL_ROW, l]
            } else {
                vec![l]
            }
        })
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(
        parse_ledger("run-1", &text),
        Err(LedgerError::DuplicateRow {
            seq: 7,
            phase: "terminal".to_owned(),
        }),
    );
}

#[test]
fn done_row_after_done_rejected() {
    // A second DONE is a row after DONE, not a duplicate row.
    let text = format!("{LITERAL_ASYNC_SUBMIT}{DONE_ROW}\n");
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn row_after_done_rejected() {
    let text = format!("{LITERAL_ASYNC_SUBMIT}{TERMINAL_ROW}\n");
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn missing_done_rejected() {
    let text: String = LITERAL_ASYNC_SUBMIT
        .lines()
        .filter(|l| !l.contains(r#""phase":"done""#))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(parse_ledger("run-1", &text), Err(LedgerError::MissingDone));
}

#[test]
fn terminal_without_submit_rejected() {
    let text: String = LITERAL_ASYNC_SUBMIT
        .lines()
        .filter(|l| !l.contains(r#""phase":"submit""#))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn return_before_submit_rejected() {
    let mut lines: Vec<&str> = LITERAL_ASYNC_SUBMIT.lines().collect();
    lines.swap(0, 1);
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn terminal_without_return_rejected() {
    // Every invocation has a submit return, even async EINPROGRESS.
    let text: String = LITERAL_ASYNC_SUBMIT
        .lines()
        .filter(|l| !l.contains(r#""phase":"return""#))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn return_without_errno_rejected() {
    let text =
        LITERAL_ASYNC_SUBMIT.replace(r#""phase":"return","errno":-115"#, r#""phase":"return""#);
    let err = parse_ledger("run-1", &text).expect_err("errno-less return rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn progress_without_errno_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(
        r#""phase":"progress","errno":-115"#,
        r#""phase":"progress""#,
    );
    let err = parse_ledger("run-1", &text).expect_err("errno-less progress rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn done_without_overflow_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(r#""overflow":0,"#, "");
    let err = parse_ledger("run-1", &text).expect_err("overflow-less done rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn free_without_final_rejected() {
    let text = LITERAL_WITH_LIFETIME.replace(r#""final":true"#, r#""final":null"#);
    let err = parse_ledger("run-1", &text).expect_err("final-less free rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn submit_empty_op_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(r#""op":"encrypt""#, r#""op":"""#);
    let err = parse_ledger("run-1", &text).expect_err("empty op rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn alloc_empty_req_rejected() {
    let text = LITERAL_WITH_LIFETIME.replace(r#""req":"kxcipher""#, r#""req":"""#);
    let err = parse_ledger("run-1", &text).expect_err("empty req rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn alloc_empty_drv_rejected() {
    let text = LITERAL_WITH_LIFETIME.replace(r#""drv":"kcipher-sync""#, r#""drv":"""#);
    let err = parse_ledger("run-1", &text).expect_err("empty drv rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn nonzero_overflow_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(
        r#""phase":"progress","errno":-115"#,
        r#""phase":"progress","errno":-115,"overflow":1"#,
    );
    assert_eq!(
        parse_ledger("run-1", &text),
        Err(LedgerError::Overflow { seq: 7 }),
    );
}

#[test]
fn foreign_run_id_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(
        r#""run":"run-1","seq":7,"phase":"progress""#,
        r#""run":"run-2","seq":7,"phase":"progress""#,
    );
    assert_eq!(
        parse_ledger("run-1", &text),
        Err(LedgerError::ForeignRunId {
            expected: "run-1".to_owned(),
            found: "run-2".to_owned(),
        }),
    );
}

#[test]
fn nonzero_fixture_result_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(r#""fixture_result":0"#, r#""fixture_result":3"#);
    assert_eq!(
        parse_ledger("run-1", &text),
        Err(LedgerError::NonzeroFixtureResult(3)),
    );
}

#[test]
fn done_without_fixture_result_rejected() {
    let text = LITERAL_ASYNC_SUBMIT.replace(r#","fixture_result":0"#, "");
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::Malformed(_))
    ));
}

/// Transform lifetime rows share the run's sequence counter:
/// alloc takes a value, its free reuses it. Lifetimes need no
/// terminal row, but free requires a prior alloc.
const LITERAL_WITH_LIFETIME: &str = r#"{"v":1,"run":"run-1","seq":3,"phase":"alloc","req":"kxcipher","drv":"kcipher-sync","ts":900}
{"v":1,"run":"run-1","seq":7,"phase":"submit","op":"encrypt","ts":1000,"cpu":3}
{"v":1,"run":"run-1","seq":7,"phase":"return","errno":-115,"ts":1200,"cpu":3}
{"v":1,"run":"run-1","seq":7,"phase":"progress","errno":-115,"ts":1500,"cpu":5}
{"v":1,"run":"run-1","seq":7,"phase":"terminal","errno":0,"ts":1800,"cpu":5}
{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}
{"v":1,"run":"run-1","phase":"done","fixture_result":0,"overflow":0,"ts":1900}
"#;

#[test]
fn alloc_free_lifetime_parses_alongside_requests() {
    let ledger = parse_ledger("run-1", LITERAL_WITH_LIFETIME).expect("lifetime parses");
    assert_eq!(ledger.requests.len(), 1);
    assert_eq!(ledger.allocs.len(), 1, "one transform lifetime");
    let alloc = &ledger.allocs[0];
    assert_eq!(alloc.seq, 3);
    assert_eq!(alloc.req_name, "kxcipher", "requested name carried");
    assert_eq!(alloc.drv_name, "kcipher-sync", "resolved driver carried");
    assert!(alloc.freed, "free row closed the lifetime");
    assert!(alloc.final_free, "final-free flag carried");
}

#[test]
fn alloc_without_req_rejected() {
    let text = LITERAL_WITH_LIFETIME.replace(r#""req":"kxcipher","#, "");
    let err = parse_ledger("run-1", &text).expect_err("req-less alloc rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn alloc_without_drv_rejected() {
    let text = LITERAL_WITH_LIFETIME.replace(r#""drv":"kcipher-sync","#, "");
    let err = parse_ledger("run-1", &text).expect_err("drv-less alloc rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn free_without_alloc_rejected() {
    let text: String = LITERAL_WITH_LIFETIME
        .lines()
        .filter(|l| !l.contains(r#""phase":"alloc""#))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn alloc_without_free_at_done_rejected() {
    let text: String = LITERAL_WITH_LIFETIME
        .lines()
        .filter(|l| !l.contains(r#""phase":"free""#))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

// T07 RED: allocation type/mask provenance (F02), repeated
// releases with last-final-wins (F04), config epochs (F07).

#[test]
fn f02_alloc_carries_type_and_mask_provenance() {
    let text = LITERAL_WITH_LIFETIME.replace(
        r#""drv":"kcipher-sync","#,
        r#""drv":"kcipher-sync","type":2,"mask":15,"#,
    );
    let ledger = parse_ledger("run-1", &text).expect("typed alloc parses");
    assert_eq!(ledger.allocs.len(), 1);
    assert_eq!(ledger.allocs[0].alg_type, Some(2), "type carried");
    assert_eq!(ledger.allocs[0].alg_mask, Some(15), "mask carried");
}

#[test]
fn f02_alloc_without_type_and_mask_parses_as_unknown() {
    let ledger = parse_ledger("run-1", LITERAL_WITH_LIFETIME).expect("literal parses");
    assert_eq!(ledger.allocs.len(), 1);
    assert_eq!(ledger.allocs[0].alg_type, None, "untyped stays unknown");
    assert_eq!(ledger.allocs[0].alg_mask, None, "unmasked stays unknown");
}

#[test]
fn f02_alloc_non_u32_type_rejected() {
    let text = LITERAL_WITH_LIFETIME.replace(
        r#""drv":"kcipher-sync","#,
        r#""drv":"kcipher-sync","type":"skcipher","#,
    );
    let err = parse_ledger("run-1", &text).expect_err("non-u32 type rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn f04_repeated_release_last_final_wins() {
    // Refcount-retained release then the proved final free: two
    // free rows share the alloc seq; the last final flag wins.
    let text = LITERAL_WITH_LIFETIME.replace(
        r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
        concat!(
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":false,"ts":1840}"#,
            "\n",
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
        ),
    );
    let ledger = parse_ledger("run-1", &text).expect("repeated free parses");
    assert_eq!(ledger.allocs.len(), 1);
    assert!(ledger.allocs[0].freed, "released");
    assert!(ledger.allocs[0].final_free, "last final wins");
    assert_eq!(ledger.allocs[0].releases, 2, "both puts counted");
}

#[test]
fn r5_duplicate_final_free_rejected() {
    // Two finals is not a shared release — the second free lands
    // after the lifetime ended (impossible history).
    let text = LITERAL_WITH_LIFETIME.replace(
        r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
        concat!(
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1840}"#,
            "\n",
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
        ),
    );
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn r5_final_nonfinal_final_rejected() {
    // A retained release after a final free resurrects a dead
    // lifetime — rejected at the second row already.
    let text = LITERAL_WITH_LIFETIME.replace(
        r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
        concat!(
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1830}"#,
            "\n",
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":false,"ts":1840}"#,
            "\n",
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
        ),
    );
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn r5_config_after_final_free_rejected() {
    // Configuration lands on a live transform — after the final
    // free there is no transform to configure.
    let text = LITERAL_WITH_CONFIG.replace(
        r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
        concat!(
            r#"{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}"#,
            "\n",
            r#"{"v":1,"run":"run-1","seq":3,"phase":"config","op":"setkey","errno":0,"len":16,"ts":1860}"#,
        ),
    );
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn f04_single_nonfinal_release_not_final() {
    let text = LITERAL_WITH_LIFETIME.replace(
        r#""phase":"free","final":true"#,
        r#""phase":"free","final":false"#,
    );
    let ledger = parse_ledger("run-1", &text).expect("nonfinal free parses");
    assert!(ledger.allocs[0].freed, "released");
    assert!(!ledger.allocs[0].final_free, "not finally freed");
    assert_eq!(ledger.allocs[0].releases, 1, "one put counted");
}

const LITERAL_WITH_CONFIG: &str = r#"{"v":1,"run":"run-1","seq":3,"phase":"alloc","req":"kxcipher","drv":"kcipher-sync","ts":900}
{"v":1,"run":"run-1","seq":3,"phase":"config","op":"setkey","errno":0,"len":16,"ts":950}
{"v":1,"run":"run-1","seq":3,"phase":"config","op":"setkey","errno":-22,"len":7,"ts":960}
{"v":1,"run":"run-1","seq":3,"phase":"config","op":"setauthsize","errno":0,"len":16,"ts":970}
{"v":1,"run":"run-1","seq":3,"phase":"free","final":true,"ts":1850}
{"v":1,"run":"run-1","phase":"done","fixture_result":0,"overflow":0,"ts":1900}
"#;

#[test]
fn f07_config_rows_parse_with_op_errno_len() {
    let ledger = parse_ledger("run-1", LITERAL_WITH_CONFIG).expect("configs parse");
    assert_eq!(ledger.configs.len(), 3, "three config rows");
    assert_eq!(ledger.configs[0].op, "setkey");
    assert_eq!(ledger.configs[0].result_errno, 0);
    assert_eq!(ledger.configs[0].len, 16);
    assert_eq!(ledger.configs[1].result_errno, -22, "failed setkey kept");
    assert_eq!(ledger.configs[1].len, 7, "rejected length kept");
    assert_eq!(ledger.configs[2].op, "setauthsize");
    assert!(
        ledger.configs.iter().all(|c| c.seq == 3),
        "configs join the alloc"
    );
}

#[test]
fn f07_config_requires_prior_alloc() {
    let text: String = LITERAL_WITH_CONFIG
        .lines()
        .filter(|l| !l.contains(r#""phase":"alloc""#))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(matches!(
        parse_ledger("run-1", &text),
        Err(LedgerError::PhaseInconsistency(_))
    ));
}

#[test]
fn f07_config_missing_len_rejected() {
    let text = LITERAL_WITH_CONFIG.replace(r#""errno":0,"len":16"#, r#""errno":0"#);
    let err = parse_ledger("run-1", &text).expect_err("len-less config rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn f07_config_missing_op_rejected() {
    let text = LITERAL_WITH_CONFIG.replace(r#""op":"setkey","errno""#, r#""errno""#);
    let err = parse_ledger("run-1", &text).expect_err("op-less config rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}

#[test]
fn f07_config_missing_errno_rejected() {
    let text = LITERAL_WITH_CONFIG.replace(r#""errno":0,"len""#, r#""len""#);
    let err = parse_ledger("run-1", &text).expect_err("errno-less config rejected");
    assert!(
        matches!(err, LedgerError::Malformed(_)),
        "malformed: {err:?}"
    );
}
