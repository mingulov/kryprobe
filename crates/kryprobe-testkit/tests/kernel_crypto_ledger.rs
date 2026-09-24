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
{"v":1,"run":"run-1","phase":"done","fixture_result":0,"ts":1900}
"#;

#[test]
fn literal_async_submit_yields_one_completed_request_and_two_callbacks() {
    let ledger = parse_ledger("run-1", LITERAL_ASYNC_SUBMIT).expect("literal parses");
    assert_eq!(ledger.run_id, "run-1");
    assert!(ledger.done, "run reached DONE");
    assert_eq!(ledger.requests.len(), 1, "exactly one request");
    let req = &ledger.requests[0];
    assert_eq!(req.seq, 7);
    assert_eq!(req.terminal_errno, 0, "terminal success");
    assert_eq!(req.callbacks, 2, "progress + terminal notifications");
}

const TERMINAL_ROW: &str =
    r#"{"v":1,"run":"run-1","seq":7,"phase":"terminal","errno":0,"ts":1800,"cpu":5}"#;
const DONE_ROW: &str = r#"{"v":1,"run":"run-1","phase":"done","fixture_result":0,"ts":1900}"#;

#[test]
fn duplicate_terminal_row_rejected() {
    let text = format!("{LITERAL_ASYNC_SUBMIT}{TERMINAL_ROW}\n");
    assert_eq!(
        parse_ledger("run-1", &text),
        Err(LedgerError::DuplicateRow {
            seq: 7,
            phase: "terminal".to_owned(),
        }),
    );
}

#[test]
fn duplicate_done_row_rejected() {
    let text = format!("{LITERAL_ASYNC_SUBMIT}{DONE_ROW}\n");
    assert_eq!(
        parse_ledger("run-1", &text),
        Err(LedgerError::DuplicateRow {
            seq: u64::MAX,
            phase: "done".to_owned(),
        }),
    );
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
