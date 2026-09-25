// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-ledger validation: parses a ledger captured from a fixture
//! guest run and asserts the scenario's exact expected shape.
//!
//! Driven by environment (set by `scripts/kcrypto-lab.py`):
//! - `KCRYPTO_LEDGER_PATH`: captured JSONL ledger file (required)
//! - `KCRYPTO_RUN_ID`: run the ledger must belong to (required)
//! - `KCRYPTO_SCENARIO`: one of the fourteen fixture scenarios (required)
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
/// Native EINPROGRESS: async submit queued.
const EINPROGRESS: i32 = 115;
/// Native EBUSY: MAY_BACKLOG submit queued as backlog.
const EBUSY: i32 = 16;
/// Native EINVAL: failing provider init / rejected key length.
const EINVAL: i32 = 22;
/// Typed-sync restriction: CRYPTO_ALG_TYPE_SKCIPHER with
/// CRYPTO_ALG_TYPE_MASK|CRYPTO_ALG_ASYNC — "skcipher and sync",
/// nonzero provenance that still selects the sync driver.
const KXC_TYPED_TYPE: u32 = 0x05;
const KXC_TYPED_MASK: u32 = 0x8f;

/// Load the lab-driven ledger, or `None` when the driver env is
/// absent (bare `sudo-lane.sh` runs every `--ignored` binary,
/// including this lab-driven one — skipping honestly with a reason
/// instead of failing on a missing harness). When the env IS set
/// (the lab always sets it), every failure below stays loud: an
/// unreadable/unparseable ledger or a run that never reached DONE
/// is a broken positive control, never a skip.
fn load() -> Option<(String, ParsedLedger)> {
    let path = std::env::var("KCRYPTO_LEDGER_PATH").ok()?;
    let run = std::env::var("KCRYPTO_RUN_ID").ok()?;
    let scenario = std::env::var("KCRYPTO_SCENARIO").ok()?;
    let text = std::fs::read_to_string(&path).expect("ledger file readable");
    let ledger = parse_ledger(&run, &text).expect("guest ledger parses strictly");
    assert!(ledger.done, "guest run reached DONE");
    Some((scenario, ledger))
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
    let Some((scenario, ledger)) = load() else {
        println!("SKIP: lab-driven test needs KCRYPTO_* env (run scripts/kcrypto-lab.py)");
        return;
    };
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
                assert_eq!(req.return_errno, 0, "sync return");
                assert_eq!(req.progress_errno, None, "no progress marker");
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
            assert_eq!(req.return_errno, -EINPROGRESS, "async return");
            assert_eq!(req.progress_errno, None, "no progress marker");
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // Genuine slow completion: in-flight progress marker,
        // then the terminal ~200ms later (elapsed verified by the
        // fixture; order + gap receipted per run).
        "delayed-completion" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 1, "one delayed invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "encrypt-delayed", "submit op label");
            assert_eq!(req.return_errno, -EINPROGRESS, "async return");
            assert_eq!(
                req.progress_errno,
                Some(-EINPROGRESS),
                "genuinely in-flight marker"
            );
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 2, "progress + terminal");
        }
        // Four MAY_BACKLOG submits on one transform against the
        // depth-1 held queue: exactly EINPROGRESS then EBUSY x3.
        "backlog-accepted" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 4, "burst of four");
            let returns: Vec<i32> = ledger.requests.iter().map(|req| req.return_errno).collect();
            assert_eq!(
                returns,
                [-EINPROGRESS, -EBUSY, -EBUSY, -EBUSY],
                "exact backlog return script"
            );
            for req in &ledger.requests {
                assert_eq!(req.submit_op, "encrypt-burst", "submit op label");
                assert_eq!(req.progress_errno, None, "no progress marker");
                assert_eq!(req.terminal_errno, 0, "burst terminal success");
                assert_eq!(req.notifications, 1, "one terminal notification each");
            }
        }
        // Pre-wait poll recorded as one progress row either way:
        // 0 if the callback already landed, EINPROGRESS if still
        // in flight. Both are truthful poll results.
        "early-callback" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.requests.len(), 1, "one polled invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "encrypt-early", "submit op label");
            assert_eq!(req.return_errno, -EINPROGRESS, "async return");
            assert!(
                req.progress_errno == Some(0) || req.progress_errno == Some(-EINPROGRESS),
                "truthful poll result, got {:?}",
                req.progress_errno
            );
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
            assert_eq!(req.return_errno, -EINPROGRESS, "async return");
            assert_eq!(req.progress_errno, None, "no progress marker");
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // Unknown-name alloc fails; the probe triple carries ENOENT.
        "failed-alloc" => {
            assert!(ledger.allocs.is_empty(), "nothing allocated");
            assert_eq!(ledger.requests.len(), 1, "one alloc probe");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "alloc-probe", "submit op label");
            assert_eq!(req.return_errno, -ENOENT, "probe return carries ENOENT");
            assert_eq!(req.progress_errno, None, "no progress marker");
            assert_eq!(req.terminal_errno, -ENOENT, "native ENOENT carried");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // Reference held across the run, zero invocations.
        "refheld-release" => {
            expect_single_lifetime(&ledger);
            assert!(ledger.requests.is_empty(), "no invocations");
        }
        // T07 F02: exact lower-priority sync driver, twice — once
        // untyped (0,0 like every normal caller) and once with
        // explicit type/mask restrictions; both rows carry exact
        // provenance, both resolve to the sync driver.
        "typed-sync" => {
            let suffix = std::env::var("KCRYPTO_SUFFIX").expect("KCRYPTO_SUFFIX set");
            assert_eq!(ledger.allocs.len(), 2, "two typed lifetimes");
            for alloc in &ledger.allocs {
                assert_eq!(
                    alloc.drv_name,
                    format!("kxcipher-sync-{suffix}"),
                    "exact sync driver selected"
                );
                assert!(alloc.freed && alloc.final_free, "finally freed");
                assert_eq!(alloc.releases, 1, "one put each");
            }
            assert_eq!(ledger.allocs[0].alg_type, Some(0), "untyped type carried");
            assert_eq!(ledger.allocs[0].alg_mask, Some(0), "untyped mask carried");
            assert_eq!(
                ledger.allocs[1].alg_type,
                Some(KXC_TYPED_TYPE),
                "restricted type carried"
            );
            assert_eq!(
                ledger.allocs[1].alg_mask,
                Some(KXC_TYPED_MASK),
                "restricted mask carried"
            );
            assert!(ledger.requests.is_empty(), "no invocations");
            assert!(ledger.configs.is_empty(), "no configurations");
        }
        // T07 F03: the failing provider's cra_init rejects the
        // allocation; the probe triple carries EINVAL, nothing
        // was allocated or configured.
        "failed-init" => {
            assert!(ledger.allocs.is_empty(), "nothing allocated");
            assert!(ledger.configs.is_empty(), "nothing configured");
            assert_eq!(ledger.requests.len(), 1, "one alloc probe");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "alloc-probe", "submit op label");
            assert_eq!(req.return_errno, -EINVAL, "probe return carries EINVAL");
            assert_eq!(req.progress_errno, None, "no progress marker");
            assert_eq!(req.terminal_errno, -EINVAL, "native EINVAL carried");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // T07 F04: one transform, released at refcount 2 (no free)
        // then finally freed (last put); the observer must retire
        // on the second row only. 6.12/7.0 only (7.2 has no tfm
        // refcount; the scenario refuses there with -EOPNOTSUPP).
        "shared-release" => {
            assert_eq!(ledger.allocs.len(), 1, "one shared lifetime");
            let alloc = &ledger.allocs[0];
            assert!(alloc.freed, "released");
            assert!(alloc.final_free, "last put was final");
            // R5: the parser rejects any release after a final
            // free, so releases == 2 + final proves the ordered
            // [retained, final] sequence — a duplicate final
            // never parses.
            assert_eq!(alloc.releases, 2, "retained release + final free");
            assert!(ledger.requests.is_empty(), "no invocations");
        }
        // T07 F06: one thousand alloc/free lifetimes back to
        // back; every one closed and final (forced reuse comes
        // from the slab, the observer proves fresh IDs per
        // proven lifetime against this truth).
        "reuse-burst" => {
            assert_eq!(ledger.allocs.len(), 1000, "one thousand lifetimes");
            for (i, alloc) in ledger.allocs.iter().enumerate() {
                assert!(
                    alloc.freed && alloc.final_free,
                    "lifetime {i} finally freed"
                );
                assert_eq!(alloc.releases, 1, "lifetime {i} one put");
            }
            assert!(ledger.requests.is_empty(), "no invocations");
            assert!(ledger.configs.is_empty(), "no configurations");
        }
        // T07 F07 (skcipher leg): setkey ok, an encrypt between
        // the changes, then a rejected short key; epochs and
        // failures are truth rows, never dropped.
        "rekey" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.configs.len(), 2, "two setkey rows");
            assert_eq!(ledger.configs[0].op, "setkey");
            assert_eq!(ledger.configs[0].result_errno, 0, "first setkey ok");
            assert_eq!(ledger.configs[0].len, 16, "accepted key length");
            assert_eq!(ledger.configs[1].op, "setkey");
            assert_eq!(
                ledger.configs[1].result_errno, -EINVAL,
                "short key rejected"
            );
            assert_eq!(ledger.configs[1].len, 7, "rejected length kept");
            assert_eq!(ledger.requests.len(), 1, "one op between changes");
            assert_eq!(ledger.requests[0].terminal_errno, 0, "op succeeded");
        }
        // T07 F07 (AEAD leg): setkey, valid authsize, an encrypt
        // between the changes, then an oversize authsize; metadata
        // only, failures kept. (Minimal fixture AEAD: XOR, no tag
        // semantics until T10.)
        "authsize" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.configs.len(), 3, "setkey + two setauthsize rows");
            assert_eq!(ledger.configs[0].op, "setkey");
            assert_eq!(ledger.configs[0].result_errno, 0, "setkey ok");
            assert_eq!(ledger.configs[0].len, 16, "accepted key length");
            assert_eq!(ledger.configs[1].op, "setauthsize");
            assert_eq!(ledger.configs[1].result_errno, 0, "valid authsize ok");
            assert_eq!(ledger.configs[1].len, 16, "accepted authsize");
            assert_eq!(ledger.configs[2].op, "setauthsize");
            assert_eq!(
                ledger.configs[2].result_errno, -EINVAL,
                "oversize authsize rejected"
            );
            assert_eq!(ledger.configs[2].len, 64, "rejected authsize kept");
            assert_eq!(ledger.requests.len(), 1, "one op between changes");
            assert_eq!(ledger.requests[0].terminal_errno, 0, "op succeeded");
        }
        other => panic!("unknown KCRYPTO_SCENARIO: {other}"),
    }
}
