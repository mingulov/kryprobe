// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-ledger validation: parses a ledger captured from a fixture
//! guest run and asserts the scenario's exact expected shape.
//!
//! Driven by environment (set by `scripts/kcrypto-lab.py`):
//! - `KCRYPTO_LEDGER_PATH`: captured JSONL ledger file (required)
//! - `KCRYPTO_RUN_ID`: run the ledger must belong to (required)
//! - `KCRYPTO_SCENARIO`: `sync-once` or `async-once` (required)
//!
//! Truth comes from the fixture file; expectations come from the
//! scenario contract — never from KryProbe aggregates or counters.

use kryprobe_testkit::kernel_crypto_ledger::{ParsedLedger, parse_ledger};

fn load() -> (String, ParsedLedger) {
    let path = std::env::var("KCRYPTO_LEDGER_PATH").expect("KCRYPTO_LEDGER_PATH set");
    let run = std::env::var("KCRYPTO_RUN_ID").expect("KCRYPTO_RUN_ID set");
    let scenario = std::env::var("KCRYPTO_SCENARIO").expect("KCRYPTO_SCENARIO set");
    let text = std::fs::read_to_string(&path).expect("ledger file readable");
    let ledger = parse_ledger(&run, &text).expect("guest ledger parses strictly");
    assert!(ledger.done, "guest run reached DONE");
    (scenario, ledger)
}

#[test]
fn guest_ledger_matches_scenario_contract() {
    let (scenario, ledger) = load();
    // Every scenario here: exactly one transform, allocated and
    // finally freed.
    assert_eq!(ledger.allocs.len(), 1, "one transform lifetime");
    assert!(ledger.allocs[0].freed, "transform freed");
    assert!(ledger.allocs[0].final_free, "final free");
    match scenario.as_str() {
        // Encrypt + decrypt, each submit/return/terminal, errno 0.
        // Terminal rows count as the completion notification.
        "sync-once" => {
            assert_eq!(ledger.requests.len(), 2, "encrypt + decrypt");
            for req in &ledger.requests {
                assert_eq!(req.terminal_errno, 0, "sync success");
                assert_eq!(req.callbacks, 1, "one terminal notification");
            }
        }
        // One submit, EINPROGRESS return, one terminal callback.
        "async-once" => {
            assert_eq!(ledger.requests.len(), 1, "one async invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.callbacks, 1, "one terminal callback");
        }
        other => panic!("unknown KCRYPTO_SCENARIO: {other}"),
    }
}
