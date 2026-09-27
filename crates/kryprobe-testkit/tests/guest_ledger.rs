// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-ledger validation: parses a ledger captured from a fixture
//! guest run and asserts the scenario's exact expected shape.
//!
//! Driven by environment (set by `scripts/kcrypto-lab.py`):
//! - `KCRYPTO_LEDGER_PATH`: captured JSONL ledger file (required)
//! - `KCRYPTO_RUN_ID`: run the ledger must belong to (required)
//! - `KCRYPTO_SCENARIO`: one of the twenty fixture scenarios (required)
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
/// Native ENOSPC: queue full without backlog consent (immediate,
/// terminal — never queued, never rewritten).
const ENOSPC: i32 = 28;
/// Native EINVAL: failing provider init / rejected key length.
const EINVAL: i32 = 22;
/// Native EBADMSG: AEAD tag verification failure.
const EBADMSG: i32 = 74;
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

/// T07-R2-04: every `kxc_tfm_acquire` setup setkey rides the
/// transcript as its own config row (success or failure) — the
/// oracle pins exactly `n` of them (setkey, errno 0, len 16),
/// never a silent setup step. (`rekey`/`authsize` acquire raw
/// and drive configs explicitly, so they assert their own rows.)
fn expect_setup_configs(ledger: &ParsedLedger, n: usize) {
    assert_eq!(ledger.configs.len(), n, "setup setkey rows");
    for (i, cfg) in ledger.configs.iter().enumerate() {
        assert_eq!(cfg.op, "setkey", "setup row {i} op");
        assert_eq!(cfg.result_errno, 0, "setup row {i} ok");
        assert_eq!(cfg.len, 16, "setup row {i} key length");
    }
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
            expect_setup_configs(&ledger, 1);
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
            expect_setup_configs(&ledger, 1);
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
            expect_setup_configs(&ledger, 1);
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
        // T09: the worker mirrors cryptd_queue_worker, so reqs 1-3
        // each record one KERNEL progress row (-EINPROGRESS,
        // always before their terminal) while req 0 goes straight
        // to terminal (drain order P1,T0,P2,T1,P3,T2,T3 — pinned
        // by the sensor canary's row-order join, which retains
        // notification order; this oracle pins per-request rows).
        "backlog-accepted" => {
            expect_single_lifetime(&ledger);
            expect_setup_configs(&ledger, 1);
            assert_eq!(ledger.requests.len(), 4, "burst of four");
            let returns: Vec<i32> = ledger.requests.iter().map(|req| req.return_errno).collect();
            assert_eq!(
                returns,
                [-EINPROGRESS, -EBUSY, -EBUSY, -EBUSY],
                "exact backlog return script"
            );
            for (i, req) in ledger.requests.iter().enumerate() {
                assert_eq!(req.submit_op, "encrypt-burst", "submit op label");
                assert_eq!(req.terminal_errno, 0, "burst terminal success");
                if i == 0 {
                    assert_eq!(req.progress_errno, None, "head goes straight to terminal");
                    assert_eq!(req.notifications, 1, "one terminal notification");
                } else {
                    assert_eq!(
                        req.progress_errno,
                        Some(-EINPROGRESS),
                        "backlogged req {i} progress row"
                    );
                    assert_eq!(req.notifications, 2, "progress + terminal");
                }
            }
        }
        // T09: held queue + 2 submits WITHOUT MAY_BACKLOG: submit
        // 0 queues (terminal via callback), submit 1 answers
        // -ENOSPC immediately — terminal, exact, no callback
        // follows (the live ENOSPC proof: never rewritten, never
        // queued).
        "no-backlog-burst" => {
            expect_single_lifetime(&ledger);
            expect_setup_configs(&ledger, 1);
            assert_eq!(ledger.requests.len(), 2, "burst of two");
            let returns: Vec<i32> = ledger.requests.iter().map(|req| req.return_errno).collect();
            assert_eq!(returns, [-EINPROGRESS, -ENOSPC], "exact no-backlog script");
            let head = &ledger.requests[0];
            assert_eq!(head.submit_op, "encrypt-burst", "submit op label");
            assert_eq!(head.progress_errno, None, "no backlog, no progress");
            assert_eq!(head.terminal_errno, 0, "terminal success");
            assert_eq!(head.notifications, 1, "one terminal notification");
            let refused = &ledger.requests[1];
            assert_eq!(refused.submit_op, "encrypt-burst", "submit op label");
            assert_eq!(refused.progress_errno, None, "no progress marker");
            assert_eq!(refused.terminal_errno, -ENOSPC, "exact ENOSPC carried");
            assert_eq!(refused.notifications, 1, "waiter terminal only");
        }
        // T09 real-cryptd driver: generic control alloc (freed,
        // untrafficked), full-name cryptd alloc + op, async-masked
        // alloc + op. Each binding drives one encrypt-cryptd op
        // (queued -EINPROGRESS, terminal 0); each refusal is an
        // alloc-probe triple, never a run failure. The 7.2.6 cell
        // binds both (A3: drv cryptd(ecb(aes-lib)) twice); the
        // oracle pins shape per row, never the bind outcome —
        // rows ARE the verdict.
        "cryptd-async" => {
            assert!(
                ledger.allocs.len() <= 3,
                "at most control + 2 cryptd allocs, got {}",
                ledger.allocs.len()
            );
            for alloc in &ledger.allocs {
                assert!(alloc.freed && alloc.final_free, "alloc finally freed");
            }
            for req in &ledger.requests {
                if req.submit_op == "alloc-probe" {
                    assert_eq!(req.progress_errno, None, "probe has no progress");
                    assert_eq!(req.notifications, 1, "probe terminal only");
                    continue;
                }
                assert_eq!(req.submit_op, "encrypt-cryptd", "traffic op label");
                assert_eq!(req.return_errno, -EINPROGRESS, "cryptd queues");
                assert_eq!(req.progress_errno, None, "single in-flight, no backlog");
                assert_eq!(req.terminal_errno, 0, "terminal success");
                assert_eq!(req.notifications, 1, "one terminal notification");
            }
        }
        // P4r2 forced callback-before-return: the inline one-shot
        // completes the op inside the submit call (terminal row
        // before the return row — order pinned by the sensor
        // canary's row-order join, which retains cross-phase row
        // order; this oracle pins per-request rows). One
        // notification, no waiter-side marker.
        "early-callback" => {
            expect_single_lifetime(&ledger);
            expect_setup_configs(&ledger, 1);
            assert_eq!(ledger.requests.len(), 1, "one early invocation");
            let req = &ledger.requests[0];
            assert_eq!(req.submit_op, "encrypt-early", "submit op label");
            assert_eq!(req.return_errno, -EINPROGRESS, "async return");
            assert_eq!(req.progress_errno, None, "no progress marker");
            assert_eq!(req.terminal_errno, 0, "terminal success");
            assert_eq!(req.notifications, 1, "one terminal notification");
        }
        // P4r2 forced callback-triggered reuse: the outer op
        // completes inline and the same callback resubmits the
        // request storage (nested rows before the outer return —
        // full order pinned by the sensor canary; this oracle pins
        // per-request rows). Two queued ops, both terminal 0.
        "reuse-in-callback" => {
            expect_single_lifetime(&ledger);
            expect_setup_configs(&ledger, 1);
            assert_eq!(ledger.requests.len(), 2, "outer + nested reuse");
            let ops: Vec<&str> = ledger
                .requests
                .iter()
                .map(|req| req.submit_op.as_str())
                .collect();
            assert_eq!(
                ops,
                ["encrypt-reuse", "encrypt-reuse-cb"],
                "submit op labels"
            );
            for req in &ledger.requests {
                assert_eq!(req.return_errno, -EINPROGRESS, "async return");
                assert_eq!(req.progress_errno, None, "no progress marker");
                assert_eq!(req.terminal_errno, 0, "terminal success");
                assert_eq!(req.notifications, 1, "one terminal notification");
            }
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
            expect_setup_configs(&ledger, 1);
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
            expect_setup_configs(&ledger, 1);
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
            // Both typed acquisitions key their transform (one setup
            // row each — the oracle pins them, never silent).
            expect_setup_configs(&ledger, 2);
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
            expect_setup_configs(&ledger, 1);
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
            // Every burst lifetime keys its transform: 1,000 setup
            // rows, one per lifetime, all pinned.
            expect_setup_configs(&ledger, 1000);
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
        // T10 (AEAD accepted sync schedule): good roundtrip, bad
        // tag, short input, failed setauthsize (no epoch), tag-8
        // roundtrip. Every op carries its len + AEAD scalars for
        // byte accounting; every terminal equals its return.
        "aead-meta" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.configs.len(), 4, "setkey + three setauthsize rows");
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
            assert_eq!(ledger.configs[3].op, "setauthsize");
            assert_eq!(ledger.configs[3].result_errno, 0, "tag-8 reconfig ok");
            assert_eq!(ledger.configs[3].len, 8, "reconfigured authsize");
            // (label, len, assoc, authsize, errno).
            let want = [
                ("aead-encrypt", 1024u32, 32u32, 16u32, 0),
                ("aead-decrypt", 1040, 32, 16, 0),
                ("aead-decrypt", 1040, 32, 16, -EBADMSG),
                ("aead-decrypt", 8, 32, 16, -EINVAL),
                ("aead-encrypt", 1024, 32, 8, 0),
                ("aead-decrypt", 1032, 32, 8, 0),
            ];
            assert_eq!(ledger.requests.len(), want.len(), "six AEAD ops");
            for (req, (op, len, assoc, authsize, errno)) in
                ledger.requests.iter().zip(want.iter())
            {
                assert_eq!(req.submit_op, *op, "submit op label");
                assert_eq!(req.len, Some(*len), "submitted input length");
                assert_eq!(req.assoc, Some(*assoc), "assoclen scalar");
                assert_eq!(req.authsize, Some(*authsize), "authsize scalar");
                assert_eq!(req.return_errno, *errno, "sync return");
                assert_eq!(req.progress_errno, None, "no progress marker");
                assert_eq!(req.terminal_errno, *errno, "terminal equals return");
                assert_eq!(req.notifications, 1, "one terminal notification");
            }
        }
        // T10 (AEAD accepted async schedule): encrypt then decrypt,
        // each queued once and completed via the shared fixture
        // callback — the simple schedule only (no backlog legs).
        "aead-async" => {
            expect_single_lifetime(&ledger);
            assert_eq!(ledger.configs.len(), 2, "setkey + setauthsize rows");
            assert_eq!(ledger.configs[0].op, "setkey");
            assert_eq!(ledger.configs[0].result_errno, 0, "setkey ok");
            assert_eq!(ledger.configs[1].op, "setauthsize");
            assert_eq!(ledger.configs[1].result_errno, 0, "valid authsize ok");
            assert_eq!(ledger.configs[1].len, 16, "accepted authsize");
            let want = [
                ("aead-encrypt", 1024u32, 32u32, 16u32),
                ("aead-decrypt", 1040, 32, 16),
            ];
            assert_eq!(ledger.requests.len(), want.len(), "two AEAD ops");
            for (req, (op, len, assoc, authsize)) in ledger.requests.iter().zip(want.iter()) {
                assert_eq!(req.submit_op, *op, "submit op label");
                assert_eq!(req.len, Some(*len), "submitted input length");
                assert_eq!(req.assoc, Some(*assoc), "assoclen scalar");
                assert_eq!(req.authsize, Some(*authsize), "authsize scalar");
                assert_eq!(req.return_errno, -EINPROGRESS, "async return");
                assert_eq!(req.progress_errno, None, "no progress marker");
                assert_eq!(req.terminal_errno, 0, "terminal success");
                assert_eq!(req.notifications, 1, "one terminal notification");
            }
        }
        // T10 (AEAD live leg): the decrypt-1040 shape against real
        // gcm(aes) (sync instantiation — the alloc row records the
        // mask + the selected driver as truth).
        "aead-live" => {
            expect_single_lifetime(&ledger);
            assert_eq!(
                ledger.allocs[0].req_name, "gcm(aes)",
                "live leg requests gcm(aes)"
            );
            assert!(
                !ledger.allocs[0].drv_name.is_empty(),
                "selected driver recorded"
            );
            assert_eq!(ledger.configs.len(), 2, "setkey + setauthsize rows");
            assert_eq!(ledger.configs[0].op, "setkey");
            assert_eq!(ledger.configs[0].result_errno, 0, "setkey ok");
            assert_eq!(ledger.configs[0].len, 16, "accepted key length");
            assert_eq!(ledger.configs[1].op, "setauthsize");
            assert_eq!(ledger.configs[1].result_errno, 0, "valid authsize ok");
            assert_eq!(ledger.configs[1].len, 16, "accepted authsize");
            let want = [
                ("aead-encrypt", 1024u32, 32u32, 16u32),
                ("aead-decrypt", 1040, 32, 16),
            ];
            assert_eq!(ledger.requests.len(), want.len(), "two AEAD ops");
            for (req, (op, len, assoc, authsize)) in ledger.requests.iter().zip(want.iter()) {
                assert_eq!(req.submit_op, *op, "submit op label");
                assert_eq!(req.len, Some(*len), "submitted input length");
                assert_eq!(req.assoc, Some(*assoc), "assoclen scalar");
                assert_eq!(req.authsize, Some(*authsize), "authsize scalar");
                assert_eq!(req.return_errno, 0, "sync return");
                assert_eq!(req.progress_errno, None, "no progress marker");
                assert_eq!(req.terminal_errno, 0, "sync success");
                assert_eq!(req.notifications, 1, "one terminal notification");
            }
        }
        other => panic!("unknown KCRYPTO_SCENARIO: {other}"),
    }
}
