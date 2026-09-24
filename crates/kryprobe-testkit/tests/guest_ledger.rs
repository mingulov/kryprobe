// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-ledger validation: parses a ledger captured from a fixture
//! guest run and asserts the scenario's exact expected shape.
//!
//! Driven by environment (set by `scripts/kcrypto-lab.py`):
//! - `KCRYPTO_LEDGER_PATH`: captured JSONL ledger file (required)
//! - `KCRYPTO_RUN_ID`: run the ledger must belong to (required)
//! - `KCRYPTO_SCENARIO`: one of the eight fixture scenarios (required)
//! - `KCRYPTO_SUFFIX`: fixture driver-name suffix, for `exact-driver`
//!
//! Truth comes from the fixture file; expectations come from the
//! scenario contract — never from KryProbe aggregates or counters.
//!
//! Lab-driven (needs a guest ledger): `#[ignore]`d like the T7 lane;
//! run via `scripts/kcrypto-lab.py`, never in the host gate.

use kryprobe_testkit::kernel_crypto_ledger::{ParsedLedger, parse_ledger};

/// Native ENOENT: `crypto_alloc_skcipher` on an unknown name.
const ENOENT: i32 = 2;

fn load() -> (String, ParsedLedger) {
    let path = std::env::var("KCRYPTO_LEDGER_PATH").expect("KCRYPTO_LEDGER_PATH set");
    let run = std::env::var("KCRYPTO_RUN_ID").expect("KCRYPTO_RUN_ID set");
    let scenario = std::env::var("KCRYPTO_SCENARIO").expect("KCRYPTO_SCENARIO set");
    let text = std::fs::read_to_string(&path).expect("ledger file readable");
    let ledger = parse_ledger(&run, &text).expect("guest ledger parses strictly");
    assert!(ledger.done, "guest run reached DONE");
    (scenario, ledger)
}

/// Exactly one transform, allocated and finally freed.
fn expect_single_lifetime(ledger: &ParsedLedger) {
    assert_eq!(ledger.allocs.len(), 1, "one transform lifetime");
    assert!(ledger.allocs[0].freed, "transform freed");
    assert!(ledger.allocs[0].final_free, "final free");
}

#[test]
#[ignore = "lab-driven: needs KCRYPTO_* guest ledger env (see scripts/kcrypto-lab.py)"]
fn guest_ledger_matches_scenario_contract() {
    let (scenario, ledger) = load();
    match scenario.as_str() {
        // Encrypt + decrypt, each submit/return/terminal, errno 0.
        // Terminal rows count as the completion notification.
        "sync-once" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 2, "encrypt + decrypt");
            let ops: Vec<&str> = ledger
                .requests
                .iter()
                .map(|req| req.submit_op.as_str())
                .collect();
            assert_eq!(ops, ["encrypt", "decrypt"], "submit op labels");
            for req in &ledger.requests {
                assert_eq!(req.terminal_errno, 0, "sync success");
                assert_eq!(req.notifications, 1, "one terminal notification");
            }
        }
        // One submit, EINPROGRESS return, one terminal notification.
        "async-once" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 1, "one async invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "encrypt", "submit op label");
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // Slow waiter: one progress marker plus the terminal.
        "delayed-completion" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 1, "one delayed invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "encrypt-delayed", "submit op label");
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 2, "progress + terminal");
        }
        // Four concurrent MAY_BACKLOG submits on one transform.
        "backlog-accepted" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 4, "burst of four");
            for req in &ledger.requests {
                assert_eq!(req.submit_op, "encrypt-burst", "submit op label");
                assert_eq!(req.terminal_errno, 0, "burst terminal success");
                assert_eq!(req.notifications, 1, "one terminal notification each");
            }
        }
        // Pre-wait poll recorded as one progress row either way.
        "early-callback" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 1, "one polled invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "encrypt-early", "submit op label");
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 2, "poll progress + terminal");
        }
        // Generic-name request resolved to exactly the async driver.
        "exact-driver" => {
            let suffix = std::env::var("KCRYPTO_SUFFIX").expect("KCRYPTO_SUFFIX set");
            assert_eq!(ledger.allocs.len(), 1, "one transform lifetime");
            let alloc = &ledger.allocs[0];
            assert_eq!(alloc.req_name, "kxcipher", "generic name requested");
            assert_eq!(
                alloc.drv_name,
                format!("kxcipher-async-{suffix}"),
                "resolved to the async fixture driver"
            );
            assert!(alloc.freed && alloc.final_free, "transform finally freed");
            assert_eq!(ledger.requests.len(), 1, "one async invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "encrypt-exact", "submit op label");
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // Unknown-name alloc fails; the probe triple carries ENOENT.
        "failed-alloc" => {
            assert!(ledger.allocs.is_empty(), "nothing allocated");
            assert_eq!(ledger.requests.len(), 1, "one alloc probe");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "alloc-probe", "submit op label");
            assert_eq!(req.terminal_errno, -ENOENT, "native ENOENT carried");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // Reference held across the run, zero invocations.
        "refheld-release" => {
            expect_single_lifetime(&ledger);
            assert!(ledger.requests.is_empty(), "no invocations");
        }
        other => panic!("unknown KCRYPTO_SCENARIO: {other}"),
    }
}
