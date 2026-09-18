// SPDX-License-Identifier: GPL-3.0-or-later
//! Decoy-pid harness (FU6): privileged-lane negatives for the BPF
//! TGID/generation guards, in the osslscope canary shape (cells fire,
//! positive control, scan, DONE verdict).
//!
//! - TGID cell: path-wide link (pid 0), CONFIG pinned to the target;
//!   a decoy pid emits the same fixture binary concurrently. Strict
//!   asserts: decoy hits dropped + exactly counted in LOSS[1], target
//!   records clean (counts, seqs, per-record tgid), ledger Clean.
//!   The wide link is issued by the harness's test-local raw
//!   link-create, NOT through the attach facet: the facet refuses
//!   pid 0 for every caller (T16 B10 — a zero pid would widen a
//!   single-target scope system-wide), and that refusal is correct
//!   for all production paths. The cell needs the wide link anyway
//!   because its whole point is proving the BPF TGID guard
//!   discriminates — the guard must see foreign hits to drop them,
//!   and a pid-scoped link can never deliver any. No production
//!   path uses the raw helper; the facet behavior is unchanged
//!   (see `pid_zero_rejected_before_syscall` in `attach_gates.rs`).
//! - Generation cell: CONFIG rotated stale after attach; every hit
//!   dropped + counted, zero records leak, ledger Clean.
//!
//! `#[ignore]`d like the T7 lane; run with `cargo xtask test bpf`.
//! Unprivileged runs honestly skip at load (never false-pass).

use kryprobe_core::{LossLedger, ReconcileVerdict};
use kryprobe_privilege::bpfselftest::{BpfSelftestError, view_spine_event};
use kryprobe_privilege::decoy::{DecoyConfig, StaleGenConfig, run_stale_gen_cell, run_tgid_cell};
use std::path::PathBuf;

/// Target calls for the TGID cell: 200 calls → 400 target records.
const TARGET_CALLS: u64 = 200;
/// Decoy calls for the TGID cell: 50 calls → 100 guard drops.
const DECOY_CALLS: u64 = 50;
/// Fixture calls for the stale-generation cell: 25 calls → 50 drops.
const STALE_CALLS: u64 = 25;
/// Test generation pinned into cookies (CONFIG rotates away in the gen cell).
const GENERATION: u32 = 1;

/// Workspace-relative path of the built spine object.
fn spine_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("spine.bpf.o")
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("debug")
        .join("spine_fixture")
}

#[test]
fn decoy_artifacts_present() {
    let object = spine_object_path();
    assert!(
        object.is_file(),
        "missing BPF spine object at {} — run `cargo xtask test bpf`",
        object.display()
    );
    let fixture = fixture_path();
    assert!(
        fixture.is_file(),
        "missing fixture at {} — run `cargo xtask test bpf`",
        fixture.display()
    );
}

/// Little-endian u32 at an offset (SpineEvent field order: cookie@0,
/// tgid@8, tid@12 — see kryprobe_abi::SpineEvent).
fn u32le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().expect("u32 width"))
}

/// TGID guard negative: a decoy pid emitting the same binary while the
/// pinned target runs must be dropped (LOSS[1], exactly counted) while
/// every target record stays clean. The cell attaches path-wide (pid 0)
/// via the harness's test-local raw link-create — the only confinement
/// under test is the BPF TGID guard, which a pid-scoped link could
/// never exercise.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn decoy_tgid_guard_drops_foreign() {
    eprintln!("DECOY-CELL name=tgid target_calls={TARGET_CALLS} decoy_calls={DECOY_CALLS}");
    let outcome = match run_tgid_cell(&DecoyConfig {
        target_calls: TARGET_CALLS,
        decoy_calls: DECOY_CALLS,
        object: spine_object_path(),
        fixture: fixture_path(),
    }) {
        Ok(outcome) => outcome,
        Err(BpfSelftestError::Denied { stage, errno }) => {
            eprintln!("decoy: tgid cell honestly denied at {stage} (errno {errno}); skipping");
            return;
        }
        Err(err) => panic!("decoy: tgid cell failed dishonestly: {err}"),
    };
    // Positive control: both processes ran to DONE with exit 0, so the
    // drop count below proves guard action, not a stillborn decoy.
    assert_eq!(outcome.target_exit, Some(0), "target must exit 0");
    assert_eq!(outcome.decoy_exit, Some(0), "decoy must exit 0");
    let decoy_pid = outcome.decoy_pid.expect("tgid cell always spawns a decoy");
    assert_ne!(
        outcome.target_pid, decoy_pid,
        "decoy must be a distinct pid"
    );
    // Scan: every record parses, carries the test generation and the
    // TARGET tgid/tid; any decoy leak breaks counts, seqs, or tgid.
    let mut entries = 0u64;
    let mut returns = 0u64;
    let mut entry_seqs: Vec<u64> = Vec::with_capacity(outcome.records.len());
    let mut ret_seqs: Vec<u64> = Vec::with_capacity(outcome.records.len());
    for bytes in &outcome.records {
        let view = view_spine_event(bytes).expect("spine record must parse");
        assert_eq!(view.cookie >> 32, u64::from(GENERATION), "stale gen leaked");
        assert_eq!(u32le(bytes, 8), outcome.target_pid, "foreign tgid leaked");
        assert_eq!(u32le(bytes, 12), outcome.target_pid, "foreign tid leaked");
        match view.flags {
            0 => {
                assert_eq!(
                    view.cookie & 0xffff_ffff,
                    u64::from(outcome.entry_base),
                    "entry index drifted"
                );
                entries += 1;
                entry_seqs.push(view.seq);
            }
            1 => {
                assert_eq!(
                    view.cookie & 0xffff_ffff,
                    u64::from(outcome.ret_base),
                    "return index drifted"
                );
                returns += 1;
                ret_seqs.push(view.seq);
            }
            other => panic!("bad flags {other}"),
        }
    }
    entry_seqs.sort_unstable();
    ret_seqs.sort_unstable();
    let want: Vec<u64> = (1..=TARGET_CALLS).collect();
    assert_eq!(entries, TARGET_CALLS, "entry count drifted");
    assert_eq!(returns, TARGET_CALLS, "return count drifted");
    assert_eq!(entry_seqs, want, "entry seqs must cover 1..=N exactly once");
    assert_eq!(ret_seqs, want, "return seqs must cover 1..=N exactly once");
    assert_eq!(outcome.count_entry, TARGET_CALLS, "entry COUNT drifted");
    assert_eq!(outcome.count_ret, TARGET_CALLS, "return COUNT drifted");
    // The guard verdict: every decoy hit (entry+return) dropped into
    // LOSS[1], exactly counted; no other loss anywhere.
    assert_eq!(
        outcome.dropped,
        2 * DECOY_CALLS,
        "every decoy hit must land in LOSS[1]"
    );
    assert_eq!(outcome.ring, 0, "no ring loss expected");
    assert_eq!(outcome.truncated, 0, "no truncation expected");
    assert_eq!(outcome.queue_drops, 0, "userspace queue must not drop");
    let ledger = LossLedger {
        exact: 2 * (TARGET_CALLS + DECOY_CALLS),
        received: outcome.records.len() as u64,
        drops: outcome
            .ring
            .saturating_add(outcome.dropped)
            .saturating_add(outcome.truncated),
    };
    assert_eq!(
        ledger.reconcile(),
        ReconcileVerdict::Clean,
        "reconcile must be Clean (target={} decoy={} ring={} drop={} trunc={})",
        outcome.records.len(),
        2 * DECOY_CALLS,
        outcome.ring,
        outcome.dropped,
        outcome.truncated,
    );
    eprintln!(
        "DECOY-DONE cell=tgid target={} decoy_drops={} verdict=Clean",
        outcome.records.len(),
        outcome.dropped,
    );
}

/// Generation guard negative: hits whose cookie generation no longer
/// matches CONFIG must be dropped + counted with zero leakage.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn decoy_stale_generation_drops() {
    eprintln!("DECOY-CELL name=stale-gen calls={STALE_CALLS}");
    let outcome = match run_stale_gen_cell(&StaleGenConfig {
        calls: STALE_CALLS,
        object: spine_object_path(),
        fixture: fixture_path(),
    }) {
        Ok(outcome) => outcome,
        Err(BpfSelftestError::Denied { stage, errno }) => {
            eprintln!("decoy: stale-gen cell honestly denied at {stage} (errno {errno}); skipping");
            return;
        }
        Err(err) => panic!("decoy: stale-gen cell failed dishonestly: {err}"),
    };
    // Positive control: the fixture ran its calls and exited 0, so the
    // empty record set below proves guard action, not a stillborn run.
    assert_eq!(outcome.target_exit, Some(0), "target must exit 0");
    assert!(
        outcome.decoy_pid.is_none(),
        "stale-gen cell spawns no decoy"
    );
    assert!(
        outcome.records.is_empty(),
        "stale gen: probe must not fire ({} records leaked)",
        outcome.records.len()
    );
    assert_eq!(outcome.count_entry, 0, "stale gen: COUNT must stay zero");
    assert_eq!(outcome.count_ret, 0, "stale gen: COUNT must stay zero");
    assert_eq!(outcome.ring, 0, "stale gen: no ring loss expected");
    assert_eq!(outcome.truncated, 0, "stale gen: no truncation expected");
    assert_eq!(
        outcome.dropped,
        2 * STALE_CALLS,
        "stale gen: every hit (entry+return) must land in LOSS[1]"
    );
    assert_eq!(outcome.queue_drops, 0, "userspace queue must not drop");
    let ledger = LossLedger {
        exact: 2 * STALE_CALLS,
        received: 0,
        drops: outcome.dropped,
    };
    assert_eq!(
        ledger.reconcile(),
        ReconcileVerdict::Clean,
        "reconcile must be Clean (received=0 drops={})",
        outcome.dropped,
    );
    eprintln!(
        "DECOY-DONE cell=stale-gen stale_drops={} verdict=Clean",
        outcome.dropped,
    );
}
