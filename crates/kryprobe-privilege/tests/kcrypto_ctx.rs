// SPDX-License-Identifier: GPL-3.0-or-later
//! M1 Task 02 ctx-v1 accounting tests (ADR-0008): migration oracle,
//! per-CPU fold separation, unknown-vs-host, map-full totals, and the
//! writer-fence admission interleavings.
//!
//! RED first: `kcrypto_snapshot::fold_ctx_dump`,
//! `kcrypto_ctx_obs::{ctx_observation, CtxBucket}`,
//! `kcrypto_fence::{FenceController, bpf_admit_twins}`, and the loader's
//! ctx maps do not exist yet, so this file must fail to compile before
//! the Task 02 implementation lands. (The fence follows ADR-0009:
//! `CLOSED` flag + per-CPU lanes, increment-then-check.)

use kryprobe_abi::kcrypto_agg::{KFAM_SK, KOP_ENC, KRES_OK, kh_of};
use kryprobe_abi::kcrypto_ctx::{KCtxKey, VCtx};
use kryprobe_privilege::kcrypto_ctx_obs::{CtxBucket, ctx_observation};
use kryprobe_privilege::kcrypto_fence::{FenceController, bpf_admit_twins};
use kryprobe_privilege::kcrypto_snapshot::fold_ctx_dump;

/// F01 release gate: one process issuing 20 AF_ALG ops in cgroup A
/// then 30 in B yields split `KCTX` rows — per crypto class {10, 15}
/// across A/B, plus one tfm alloc per phase — with a shared nonzero
/// lifetime, distinct nonzero cgroups, and no other rows for our
/// tgid (6 rows, cgroup totals 21/31, our sum exactly 52).
/// System-wide background traffic lands in other rows (filtered by
/// tgid), so the oracle asserts OUR rows exactly and the system
/// total as a lower bound. Privileged: needs the true object + own
/// cgroups; SKIPs (runs + prints) when unprivileged.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn same_process_cgroup_migration_splits_counts() {
    if !is_root_with_btf() {
        println!("SKIP: needs root + BTF (privileged exactness lane)");
        return;
    }
    let outcome = run_migration_oracle(10, 15).expect("migration oracle runs");
    // 6 rows: enc/dec × {A, B} plus one tfm alloc per phase (the
    // fixture binds once per roundtrip call — deterministic).
    assert_eq!(
        outcome.rows_for_self.len(),
        6,
        "exactly 6 rows for our tgid"
    );
    // Lifetime: all four rows share one nonzero start, close to our
    // /proc-derived start (within 2 clock ticks — tick granularity).
    let starts: std::collections::HashSet<u64> = outcome
        .rows_for_self
        .iter()
        .map(|row| row.start_ns)
        .collect();
    assert_eq!(starts.len(), 1, "one shared lifetime across migration");
    let start = starts.into_iter().next().unwrap();
    assert_ne!(start, 0, "lifetime captured, not unreadable");
    let skew = start.abs_diff(outcome.own_start);
    assert!(
        skew < 20_000_000,
        "start matches /proc within 2 ticks: skew {skew}ns"
    );
    // Split shape: group by kh (enc/dec/alloc, driver-name agnostic).
    // Each crypto class splits {10, 15} across A and B; the alloc
    // class splits {1, 1} (one tfm bind per phase). Cgroup totals
    // are then 21 / 31 and our rows sum to exactly 52.
    let mut by_kh: std::collections::HashMap<u64, Vec<(u64, u64)>> = Default::default();
    for row in &outcome.rows_for_self {
        assert_ne!(row.cgroup, 0, "migrated rows carry real cgroups");
        by_kh
            .entry(row.kh)
            .or_default()
            .push((row.cgroup, row.calls));
    }
    assert_eq!(by_kh.len(), 3, "enc, dec, and alloc classes");
    let mut by_cgroup: std::collections::HashMap<u64, u64> = Default::default();
    let mut class_splits = Vec::new();
    for rows in by_kh.values() {
        assert_eq!(rows.len(), 2, "each class splits across A and B");
        assert_ne!(rows[0].0, rows[1].0, "distinct cgroups per class");
        let mut calls = [rows[0].1, rows[1].1];
        calls.sort_unstable();
        class_splits.push(calls);
        for (cgroup, calls) in rows {
            *by_cgroup.entry(*cgroup).or_insert(0) += calls;
        }
    }
    class_splits.sort_unstable();
    assert_eq!(
        class_splits,
        [[1, 1], [10, 15], [10, 15]],
        "alloc {{1,1}}, crypto {{10,15}} x2"
    );
    let mut totals: Vec<u64> = by_cgroup.values().copied().collect();
    totals.sort_unstable();
    assert_eq!(
        totals,
        vec![21, 31],
        "cgroup totals A=21 B=31 in some order"
    );
    let ours: u64 = outcome.rows_for_self.iter().map(|row| row.calls).sum();
    assert_eq!(ours, 52, "our rows sum to exactly 52");
    assert!(
        outcome.system_total >= 52,
        "system total covers our 52 (background adds more): {}",
        outcome.system_total
    );
}

/// Per-CPU fold preserves context: folding two keys' lanes never merges
/// counts across keys, and idle lanes never poison `first_ns`.
#[test]
fn percpu_fold_preserves_context() {
    let kh = kh_of(KFAM_SK, KOP_ENC, KRES_OK, 0, &[7; 16], &[0; 16]);
    let key_a = KCtxKey {
        kh,
        cgroup: 100,
        tgid: 1000,
        uid: 1000,
        start_ns: 555,
    };
    let key_b = KCtxKey {
        kh,
        cgroup: 200,
        tgid: 1000,
        uid: 1000,
        start_ns: 555,
    };
    let lane = |calls: u64, first: u64, last: u64| VCtx {
        calls,
        bytes: calls * 512,
        ok: calls,
        errors: 0,
        queued: 0,
        first_ns: first,
        last_ns: last,
    };
    let dump = vec![
        (key_a, vec![lane(20, 100, 200), VCtx::default()]),
        (key_b, vec![VCtx::default(), lane(30, 150, 250)]),
    ];
    let folded = fold_ctx_dump(&dump);
    assert_eq!(folded.len(), 2, "one row per context key");
    let row_a = folded
        .iter()
        .find(|(k, _)| k.cgroup == 100)
        .expect("row A")
        .1;
    let row_b = folded
        .iter()
        .find(|(k, _)| k.cgroup == 200)
        .expect("row B")
        .1;
    assert_eq!((row_a.calls, row_a.first_ns, row_a.last_ns), (20, 100, 200));
    assert_eq!((row_b.calls, row_b.first_ns, row_b.last_ns), (30, 150, 250));
    assert_eq!(row_a.bytes + row_b.bytes, 50 * 512);
}

/// An unknown-context row (unreadable cgroup/lifetime) lands in the
/// Unknown bucket — it never becomes a host workload row.
#[test]
fn context_unknown_does_not_become_host() {
    let kh = kh_of(KFAM_SK, KOP_ENC, KRES_OK, 0, &[7; 16], &[0; 16]);
    let unknown_cgroup = KCtxKey {
        kh,
        cgroup: 0,
        tgid: 1000,
        uid: 1000,
        start_ns: 555,
    };
    let unknown_lifetime = KCtxKey {
        kh,
        cgroup: 100,
        tgid: 1000,
        uid: 1000,
        start_ns: 0,
    };
    let known = KCtxKey {
        kh,
        cgroup: 100,
        tgid: 1000,
        uid: 1000,
        start_ns: 555,
    };
    let folded = VCtx {
        calls: 5,
        first_ns: 1,
        last_ns: 2,
        ..VCtx::default()
    };
    assert_eq!(
        ctx_observation(&unknown_cgroup, &folded).bucket,
        CtxBucket::Unknown
    );
    assert_eq!(
        ctx_observation(&unknown_lifetime, &folded).bucket,
        CtxBucket::Unknown
    );
    assert_ne!(
        ctx_observation(&unknown_cgroup, &folded).bucket,
        CtxBucket::Host,
        "unknown context must not render as host"
    );
    assert_eq!(ctx_observation(&known, &folded).bucket, CtxBucket::Context);
}

/// A full KCTX retains system totals and exposes the attribution gap:
/// refused calls stay in KTOT, increment the exact drops counter, and
/// surface as unknown-by-difference — never silent, never zeroed.
#[test]
fn ctx_map_full_retains_system_totals() {
    // 1024 resident rows + 40 refused: totals 1064, unknown 40, drops 40.
    let outcome = kryprobe_privilege::kcrypto_snapshot::ctx_unknown_from_totals(1064, 1024, 40)
        .expect("consistent totals resolve");
    assert_eq!(outcome.system_total, 1064);
    assert_eq!(outcome.per_context_sum, 1024);
    assert_eq!(outcome.unknown, 40);
    assert_eq!(outcome.refused, 40);
    // Contradiction surfaces instead of saturating.
    assert!(kryprobe_privilege::kcrypto_snapshot::ctx_unknown_from_totals(50, 60, 0).is_err());
}

/// Fence admission interleavings (faithful BPF-side twins + the real
/// userspace controller over a `CLOSED` flag + per-CPU lanes): writers
/// paused before/after admission and around the count updates, across
/// two lanes; close refuses later entrants, waits for every earlier
/// admitted writer on every lane, and a timeout can never yield
/// `Quiescent`.
#[test]
fn fence_admission_interleavings() {
    let fence = FenceController::new_for_test(4);
    // Writers admitted before close on two lanes, paused mid-update.
    let (admit0, release0) = bpf_admit_twins(&fence, 0);
    let (admit1, release1) = bpf_admit_twins(&fence, 3);
    assert!(admit0(), "pre-close entrant admitted (lane 0)");
    assert!(admit1(), "pre-close entrant admitted (lane 3)");
    assert_eq!(fence.active_count(), 2);
    assert!(
        fence.try_close(1).is_pending(),
        "admitted writers inside: close pends"
    );
    release0();
    assert!(
        fence.try_close(100).is_pending(),
        "lane 3 still busy: close pends"
    );
    release1();
    let receipt = fence.try_close(10_000).expect("drains after release");
    assert!(receipt.quiescent(), "clean drain yields Quiescent");
    // Entrants after close refuse on every lane without data writes.
    for lane in 0..4 {
        let (admit_after, _) = bpf_admit_twins(&fence, lane);
        assert!(!admit_after(), "post-close entrant refused (lane {lane})");
    }
    assert_eq!(fence.active_count(), 0, "refusals leave no count");
    // Timeout with a stuck writer never yields Quiescent.
    let fence2 = FenceController::new_for_test(2);
    let (admit_stuck, _never_released) = bpf_admit_twins(&fence2, 1);
    assert!(admit_stuck());
    assert!(
        fence2.try_close(0).is_pending(),
        "zero-deadline close pends"
    );
    assert!(
        !fence2.try_close(0).is_quiescent_receipt(),
        "no receipt without drain"
    );
}

/// Ambiguous-hash fixture (§11.4): one `kh` shared by several full
/// keys never merges — the fold splits by the whole context key, so a
/// hash shared across cgroups, tgids, uids, or lifetimes keeps every
/// population's counts exact.
#[test]
fn ambiguous_kh_splits_by_full_context() {
    let kh = kh_of(KFAM_SK, KOP_ENC, KRES_OK, 0, &[9; 16], &[0; 16]);
    let keys = [
        KCtxKey {
            kh,
            cgroup: 100,
            tgid: 1000,
            uid: 1000,
            start_ns: 555,
        },
        KCtxKey {
            kh,
            cgroup: 100,
            tgid: 2000,
            uid: 1000,
            start_ns: 777,
        },
        KCtxKey {
            kh,
            cgroup: 100,
            tgid: 1000,
            uid: 2000,
            start_ns: 555,
        },
    ];
    let lane = |calls: u64| VCtx {
        calls,
        bytes: calls,
        ok: calls,
        errors: 0,
        queued: 0,
        first_ns: 1,
        last_ns: 2,
    };
    let dump = vec![
        (keys[0], vec![lane(11)]),
        (keys[1], vec![lane(22)]),
        (keys[2], vec![lane(33)]),
    ];
    let folded = fold_ctx_dump(&dump);
    assert_eq!(folded.len(), 3, "one row per full key, never merged");
    let mut calls: Vec<u64> = folded.iter().map(|(_, v)| v.calls).collect();
    calls.sort_unstable();
    assert_eq!(calls, vec![11, 22, 33], "each population keeps its count");
}

/// Lifetime-reuse fixture (§11.4): the same tgid after pid reuse (new
/// `start_ns`) is a NEW row — the historical row keeps its exact old
/// counts, never rewritten by the successor lifetime.
#[test]
fn lifetime_reuse_splits_rows_without_rewrite() {
    let kh = kh_of(KFAM_SK, KOP_ENC, KRES_OK, 0, &[9; 16], &[0; 16]);
    let old = KCtxKey {
        kh,
        cgroup: 100,
        tgid: 1000,
        uid: 1000,
        start_ns: 555,
    };
    let new = KCtxKey {
        kh,
        cgroup: 100,
        tgid: 1000,
        uid: 1000,
        start_ns: 999,
    };
    let lane = |calls: u64, first: u64, last: u64| VCtx {
        calls,
        bytes: 0,
        ok: calls,
        errors: 0,
        queued: 0,
        first_ns: first,
        last_ns: last,
    };
    let dump = vec![(old, vec![lane(40, 10, 20)]), (new, vec![lane(7, 30, 40)])];
    let folded = fold_ctx_dump(&dump);
    assert_eq!(folded.len(), 2, "pid reuse splits old and new lifetimes");
    let old_row = folded
        .iter()
        .find(|(k, _)| k.start_ns == 555)
        .expect("historical row")
        .1;
    let new_row = folded
        .iter()
        .find(|(k, _)| k.start_ns == 999)
        .expect("successor row")
        .1;
    assert_eq!(
        (old_row.calls, old_row.first_ns, old_row.last_ns),
        (40, 10, 20),
        "history keeps exact old counts"
    );
    assert_eq!(
        (new_row.calls, new_row.first_ns, new_row.last_ns),
        (7, 30, 40),
        "successor lifetime counted separately"
    );
}

// --- Privileged oracle harness (implemented with the Task 02 loader) ---

fn is_root_with_btf() -> bool {
    (unsafe { libc::geteuid() == 0 }) && std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

struct CtxRowSummary {
    kh: u64,
    cgroup: u64,
    start_ns: u64,
    calls: u64,
}

struct MigrationOutcome {
    rows_for_self: Vec<CtxRowSummary>,
    own_start: u64,
    system_total: u64,
}

/// Owned-cgroup fixture: create `$CGROUP_BASE/kprobe-t02-$PID-{a,b}`,
/// move SELF between them around AF_ALG fixture traffic, and read
/// back our `KCTX` rows. Cleanup (move self home + rmdir) runs on
/// every path; leftovers fail the test loudly, never silently.
fn run_migration_oracle(ops_a: u64, ops_b: u64) -> Result<MigrationOutcome, String> {
    use kryprobe_privilege::btf_resolve::load_kcrypto_configured;
    use kryprobe_privilege::kcrypto_backend::snapshot_ctx;
    use kryprobe_privilege::kcrypto_snapshot::{parse_snapshot_row, snapshot_rows};

    let pid = unsafe { libc::getpid() };
    let base = std::path::PathBuf::from("/sys/fs/cgroup");
    if !base.join("cgroup.controllers").is_file() {
        return Err("cgroup v2 base unavailable".to_string());
    }
    let tag = format!("kprobe-t02-{}", pid);
    let dir_a = base.join(format!("{}-a", tag));
    let dir_b = base.join(format!("{}-b", tag));
    struct Guard {
        dir_a: std::path::PathBuf,
        dir_b: std::path::PathBuf,
        base: std::path::PathBuf,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            // Best-effort restore: move self home, then remove owned dirs.
            let pid = unsafe { libc::getpid() }.to_string();
            let _ = std::fs::write(self.base.join("cgroup.procs"), &pid);
            let _ = std::fs::remove_dir(&self.dir_a);
            let _ = std::fs::remove_dir(&self.dir_b);
        }
    }
    let _guard = Guard {
        dir_a: dir_a.clone(),
        dir_b: dir_b.clone(),
        base: base.clone(),
    };
    std::fs::create_dir(&dir_a).map_err(|e| format!("mkdir A: {e}"))?;
    std::fs::create_dir(&dir_b).map_err(|e| format!("mkdir B: {e}"))?;
    let move_self = |dir: &std::path::Path| -> Result<(), String> {
        std::fs::write(dir.join("cgroup.procs"), pid.to_string())
            .map_err(|e| format!("move self to {}: {e}", dir.display()))
    };

    let object = {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("kryprobe-bpf")
            .join("kcrypto.bpf.o");
        std::fs::read(&path).map_err(|_| {
            format!(
                "missing BPF object at {} — run `cargo xtask build --bpf`",
                path.display()
            )
        })?
    };
    let (sensor, _points) =
        load_kcrypto_configured(&object, None).map_err(|e| format!("bring-up: {e:?}"))?;

    // Phase A: 2*ops_a ops (enc+dec pairs) in cgroup A.
    move_self(&dir_a)?;
    let counts_a = kryprobe_testkit::alg_fixture::skcipher_roundtrip("cbc(aes)", ops_a)
        .map_err(|e| format!("phase A traffic: {e:?}"))?;
    // Phase B: migrate self, then 2*ops_b ops in cgroup B.
    move_self(&dir_b)?;
    let counts_b = kryprobe_testkit::alg_fixture::skcipher_roundtrip("cbc(aes)", ops_b)
        .map_err(|e| format!("phase B traffic: {e:?}"))?;
    assert_eq!((counts_a.enc, counts_a.dec), (ops_a, ops_a));
    assert_eq!((counts_b.enc, counts_b.dec), (ops_b, ops_b));
    // Home before teardown (the Drop guard repeats this on failure paths).
    move_self(&base)?;

    // Read back: our tgid's KCTX rows + the KTOT system total.
    let own_start = task_start_ns(pid as u32)?;
    let (rows, _drops) = snapshot_ctx(&sensor).map_err(|e| format!("snapshot KCTX: {e:?}"))?;
    let snap = snapshot_rows(&sensor).map_err(|e| format!("snapshot rows: {e:?}"))?;
    let system_total = match snap.totals {
        Some(totals) => match parse_snapshot_row(totals.as_bytes()) {
            Ok(kryprobe_privilege::kcrypto_snapshot::ParsedRow::Totals { vagg }) => vagg.calls,
            other => return Err(format!("KTOT row did not decode: {other:?}")),
        },
        None => return Err("KTOT totals missing".to_string()),
    };
    // Our rows: filter by tgid alone (no driver-name guessing —
    // the test binary drives no other crypto in this process, and
    // sibling test binaries are separate processes/tgids). Op-class
    // grouping happens by kh in the assertions.
    let mut rows_for_self = Vec::new();
    for row in &rows {
        if row.key.tgid != pid as u32 {
            continue;
        }
        rows_for_self.push(CtxRowSummary {
            kh: row.key.kh,
            cgroup: row.key.cgroup,
            start_ns: row.key.start_ns,
            calls: row.val.calls,
        });
    }
    Ok(MigrationOutcome {
        rows_for_self,
        own_start,
        system_total,
    })
}

/// Our task start time (boot-time ns) from `/proc/<pid>/stat` field
/// 22 (starttime, clock ticks) — the same quantity BPF reads from
/// `task_struct.start_time`, converted for the equality check.
fn task_start_ns(pid: u32) -> Result<u64, String> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid))
        .map_err(|e| format!("read /proc stat: {e}"))?;
    let after_comm = stat.rsplit_once(')').ok_or("stat comm parse")?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // Field 22 overall = index 19 after `)` (fields 3..=21 precede it).
    let start_ticks: u64 = fields
        .get(19)
        .ok_or("stat field 22 missing")?
        .parse()
        .map_err(|_| "stat start parse")?;
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    Ok(start_ticks.saturating_mul(1_000_000_000) / ticks_per_sec.max(1))
}

/// Read the built kcrypto object (BPF lane prerequisite).
fn kcrypto_object_bytes() -> Result<Vec<u8>, String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("kryprobe-bpf")
        .join("kcrypto.bpf.o");
    std::fs::read(&path).map_err(|_| {
        format!(
            "missing BPF object at {} — run `cargo xtask build --bpf`",
            path.display()
        )
    })
}

/// One `KCTX` row as a full-key + calls tuple (exact freeze
/// comparisons across a fence close).
type CtxRowTuple = (u64, u64, u32, u32, u64, u64);

/// One tgid's `KCTX` rows as sorted full-key + calls tuples (exact
/// freeze comparisons across a fence close).
fn our_ctx_rows(
    sensor: &kryprobe_privilege::btf_resolve::ConfiguredKcrypto,
    pid: u32,
) -> Result<Vec<CtxRowTuple>, String> {
    use kryprobe_privilege::kcrypto_backend::snapshot_ctx;
    let (rows, _drops) = snapshot_ctx(sensor).map_err(|e| format!("snapshot KCTX: {e:?}"))?;
    let mut out: Vec<CtxRowTuple> = rows
        .iter()
        .filter(|row| row.key.tgid == pid)
        .map(|row| {
            (
                row.key.kh,
                row.key.cgroup,
                row.key.tgid,
                row.key.uid,
                row.key.start_ns,
                row.val.calls,
            )
        })
        .collect();
    out.sort_unstable();
    Ok(out)
}

/// Live fence drain (ADR-0009): with the fence open, fixture traffic
/// lands in our `KCTX` rows; after `close_kernel_fence` returns the
/// `Quiescent` receipt, further traffic from the same process leaves
/// our rows byte-identical (refused entrants touch nothing — not even
/// `KTOT`). Privileged: needs the true object; SKIPs otherwise.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn fence_close_freezes_our_ctx_rows() {
    use kryprobe_privilege::btf_resolve::load_kcrypto_configured;
    use kryprobe_privilege::kcrypto_fence::close_kernel_fence;

    if !is_root_with_btf() {
        println!("SKIP: needs root + BTF (privileged exactness lane)");
        return;
    }
    let object = kcrypto_object_bytes().expect("BPF object present");
    let (sensor, _points) = load_kcrypto_configured(&object, None).expect("bring-up");
    let pid = unsafe { libc::getpid() } as u32;

    // Phase 1 (fence open): 5 roundtrips = 5 enc + 5 dec + 1 alloc.
    let counts =
        kryprobe_testkit::alg_fixture::skcipher_roundtrip("cbc(aes)", 5).expect("phase 1 traffic");
    assert_eq!((counts.enc, counts.dec), (5, 5));
    let before = our_ctx_rows(&sensor, pid).expect("snapshot before close");
    assert_eq!(
        before.len(),
        3,
        "alloc + enc + dec rows admitted while open"
    );
    let sum_before: u64 = before.iter().map(|row| row.5).sum();
    assert_eq!(sum_before, 11, "5 enc + 5 dec + 1 alloc");

    // Close: the drain must quiesce (hook bodies are bounded and we
    // issue no concurrent traffic, so no writer can remain inside).
    let outcome = close_kernel_fence(&sensor.loaded.maps).expect("fence close drives maps");
    assert!(
        outcome.is_quiescent_receipt(),
        "close drains to Quiescent, got {outcome:?}"
    );

    // Phase 2 (fence closed): 7 more roundtrips execute (the syscalls
    // succeed) but must be refused by the fence.
    let counts = kryprobe_testkit::alg_fixture::skcipher_roundtrip("cbc(aes)", 7)
        .expect("phase 2 traffic executes");
    assert_eq!((counts.enc, counts.dec), (7, 7));
    let after = our_ctx_rows(&sensor, pid).expect("snapshot after close");
    assert_eq!(after, before, "our rows frozen across the close");

    // Close is idempotent: still Quiescent, still frozen.
    let again = close_kernel_fence(&sensor.loaded.maps).expect("second close");
    assert!(
        again.is_quiescent_receipt(),
        "second close stays Quiescent, got {again:?}"
    );
    let after2 = our_ctx_rows(&sensor, pid).expect("snapshot after second close");
    assert_eq!(after2, before, "rows still frozen after second close");
}

/// One alloc + enc + dec via raw syscalls only (fork-child-safe: no
/// allocation, no std I/O, stack buffers only). Mirrors the fixture's
/// `alg_bind("skcipher", "cbc(aes)")` → setkey → accept → enc → dec
/// choreography (same constants, same order, same bytes), so the same
/// three hooks fire. Returns 0 on success, 10+stage on failure. The
/// caller `_exit`s with this code (never returns into the harness).
unsafe fn child_crypto_once() -> i32 {
    // `socket(AF_ALG, SOCK_SEQPACKET)`.
    let tfm = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
    if tfm < 0 {
        return 11;
    }
    // `sockaddr_alg`: family + "skcipher" + "cbc(aes)" (fixture layout).
    let mut addr = [0u8; 88];
    addr[0..2].copy_from_slice(&(libc::AF_ALG as u16).to_ne_bytes());
    addr[2..10].copy_from_slice(b"skcipher");
    addr[24..32].copy_from_slice(b"cbc(aes)");
    // SAFETY: `addr` is a live 88-byte `sockaddr_alg`.
    let bound = unsafe {
        libc::bind(
            tfm,
            addr.as_ptr() as *const libc::sockaddr,
            addr.len() as libc::socklen_t,
        )
    };
    if bound != 0 {
        unsafe { libc::close(tfm) };
        return 12;
    }
    // `setsockopt(ALG_SET_KEY)` with the fixture's zero-length fallback.
    let key = [0x42u8; 16];
    // SAFETY: `key` outlives the calls.
    let set = unsafe {
        libc::setsockopt(
            tfm,
            libc::SOL_ALG,
            1,
            key.as_ptr() as *const libc::c_void,
            key.len() as libc::socklen_t,
        )
    };
    let set = if set == 0 {
        0
    } else {
        unsafe {
            libc::setsockopt(
                tfm,
                libc::SOL_ALG,
                1,
                key.as_ptr() as *const libc::c_void,
                0,
            )
        }
    };
    if set != 0 {
        unsafe { libc::close(tfm) };
        return 13;
    }
    // `accept(tfm)` — the alloc edge (one op socket, like the fixture).
    // SAFETY: no address capture.
    let op = unsafe { libc::accept(tfm, std::ptr::null_mut(), std::ptr::null_mut()) };
    if op < 0 {
        unsafe { libc::close(tfm) };
        return 14;
    }
    let iv = [0x11u8; 16];
    let input = [0xaau8; 32];
    let mut out = [0u8; 32];
    // Enc then dec (CBC decrypt of anything succeeds — no tag).
    if unsafe { child_send_op(op, 1, &iv, &input) } != 0 {
        unsafe { libc::close(op) };
        unsafe { libc::close(tfm) };
        return 15;
    }
    if unsafe { child_read_exact(op, &mut out) } != 0 {
        unsafe { libc::close(op) };
        unsafe { libc::close(tfm) };
        return 16;
    }
    if unsafe { child_send_op(op, 0, &iv, &input) } != 0 {
        unsafe { libc::close(op) };
        unsafe { libc::close(tfm) };
        return 17;
    }
    if unsafe { child_read_exact(op, &mut out) } != 0 {
        unsafe { libc::close(op) };
        unsafe { libc::close(tfm) };
        return 18;
    }
    unsafe { libc::close(op) };
    unsafe { libc::close(tfm) };
    0
}

/// One cipher op: `sendmsg` with `ALG_SET_OP` + `ALG_SET_IV` cmsgs
/// (fixture `send_op` choreography, stack only).
unsafe fn child_send_op(opfd: i32, op: u32, iv: &[u8; 16], input: &[u8; 32]) -> i32 {
    let mut cbuf = [0u8; 256];
    let iov = libc::iovec {
        iov_base: input.as_ptr() as *mut libc::c_void,
        iov_len: input.len(),
    };
    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
        msg_iovlen: 1,
        msg_control: cbuf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cbuf.len(),
        msg_flags: 0,
    };
    // SAFETY: `cbuf`/`iov` outlive the `sendmsg`; cmsg writes stay in
    // bounds (OP header + u32, then IV header + ivlen word + 16B).
    unsafe {
        let first = libc::CMSG_FIRSTHDR(&msg);
        if first.is_null() {
            return -1;
        }
        (*first).cmsg_level = libc::SOL_ALG;
        (*first).cmsg_type = 3; // ALG_SET_OP
        (*first).cmsg_len = libc::CMSG_LEN(4) as usize;
        (libc::CMSG_DATA(first) as *mut u32).write_unaligned(op);
        let second = libc::CMSG_NXTHDR(&msg, first);
        if second.is_null() {
            return -1;
        }
        (*second).cmsg_level = libc::SOL_ALG;
        (*second).cmsg_type = 2; // ALG_SET_IV
        (*second).cmsg_len = libc::CMSG_LEN(20) as usize;
        let iv_data = libc::CMSG_DATA(second);
        (iv_data as *mut u32).write_unaligned(iv.len() as u32);
        std::ptr::copy_nonoverlapping(iv.as_ptr(), iv_data.add(4), iv.len());
        msg.msg_controllen =
            (second as usize) + (*second).cmsg_len.next_multiple_of(8) - cbuf.as_ptr() as usize;
        if libc::sendmsg(opfd, &msg, 0) < 0 {
            return -1;
        }
    }
    0
}

/// One `read` demanding exactly 32 bytes (seqpacket: one per op).
unsafe fn child_read_exact(opfd: i32, buf: &mut [u8; 32]) -> i32 {
    // SAFETY: `buf` outlives the call.
    let got = unsafe { libc::read(opfd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if got != buf.len() as isize { -1 } else { 0 }
}

/// System-ledger total (`KTOT` calls) decoded from one rows snapshot
/// (same decode as the migration oracle).
fn decode_ktot(snap: &kryprobe_privilege::kcrypto_snapshot::SnapshotRows) -> Result<u64, String> {
    use kryprobe_privilege::kcrypto_snapshot::{ParsedRow, parse_snapshot_row};
    match &snap.totals {
        Some(totals) => match parse_snapshot_row(totals.as_bytes()) {
            Ok(ParsedRow::Totals { vagg }) => Ok(vagg.calls),
            other => Err(format!("KTOT row did not decode: {other:?}")),
        },
        None => Err("KTOT totals missing".to_string()),
    }
}

/// True-map-full refuse-new exactness: 350 forked children × 3 AF_ALG
/// keys (alloc + enc + dec, distinct tgids by kernel construction)
/// exceed the 1024-entry `KCTX`; every attempt is either present or
/// refused — no silent loss, no eviction. `present + drops >= 1050`
/// and `drops >= 26` hold regardless of background traffic (which only
/// adds refusals, never removes ours). A missing hook fails LOUDLY
/// (fewer attempts than asserted), never silently. Privileged: needs
/// the true object; SKIPs otherwise.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn ctx_map_full_refuse_new_is_exact() {
    use kryprobe_privilege::kcrypto_backend::snapshot_ctx;
    use kryprobe_privilege::kcrypto_snapshot::snapshot_rows;

    if !is_root_with_btf() {
        println!("SKIP: needs root + BTF (privileged exactness lane)");
        return;
    }
    const KIDS: usize = 350;
    const KEYS_PER_KID: u64 = 3;
    let object = kcrypto_object_bytes().expect("BPF object present");
    let (sensor, _points) =
        kryprobe_privilege::btf_resolve::load_kcrypto_configured(&object, None).expect("bring-up");
    let (_rows0, drops0) = snapshot_ctx(&sensor).expect("baseline snapshot");
    let snap0 = snapshot_rows(&sensor).expect("baseline rows");
    let ktot0 = decode_ktot(&snap0).expect("baseline KTOT");

    let mut kids = Vec::with_capacity(KIDS);
    for _ in 0..KIDS {
        // SAFETY: the child runs raw syscalls only, then `_exit` — no
        // allocator, no std locks, no harness return.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe { libc::_exit(child_crypto_once()) };
        }
        kids.push(pid);
    }
    for pid in &kids {
        let mut status = 0;
        // SAFETY: `status` is a live int; blocking wait for our child.
        let got = unsafe { libc::waitpid(*pid, &mut status, 0) };
        assert_eq!(got, *pid, "waitpid reaps our child");
        assert!(
            libc::WIFEXITED(status),
            "child {pid} exited normally, status {status}"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child {pid} crypto stages all green (10+stage otherwise)"
        );
    }
    let kid_tgids: std::collections::HashSet<u32> = kids.iter().map(|pid| *pid as u32).collect();
    let (rows, drops1) = snapshot_ctx(&sensor).expect("post-fill snapshot");
    let drops_delta = drops1.saturating_sub(drops0);
    let mut present = 0u64;
    for row in &rows {
        if kid_tgids.contains(&row.key.tgid) {
            assert_eq!(
                row.val.calls, 1,
                "each admitted child key attempted exactly once"
            );
            present += 1;
        }
    }
    let attempted = KEYS_PER_KID * KIDS as u64;
    assert!(
        present + drops_delta >= attempted,
        "every attempt present or refused: present={present} \
         drops_delta={drops_delta} attempted={attempted}"
    );
    assert!(
        drops_delta >= attempted.saturating_sub(1024),
        "map saturated: drops_delta={drops_delta} attempted={attempted}"
    );
    // The overflow-event decode path runs over live bytes; the count
    // is reported (first-per-kh gating makes it a lower bound, not an
    // exact identity — drops carry the exactness). ADR-0008 (d): the
    // refused observations still increment `KTOT` — the ledger never
    // loses a counted call, so its delta covers every attempt.
    let snap_after = snapshot_rows(&sensor).expect("snapshot rows decode");
    let ktot1 = decode_ktot(&snap_after).expect("post-fill KTOT");
    let ktot_delta = ktot1.saturating_sub(ktot0);
    assert!(
        ktot_delta >= attempted,
        "ledger keeps counting under full map: ktot_delta={ktot_delta} attempted={attempted}"
    );
    println!(
        "map-full: present={present} drops_delta={drops_delta} \
         ktot_delta={ktot_delta} ctx_overflow_identities={}",
        snap_after.ctx_overflow_identities
    );
}

/// Isolated first-over-capacity EQUALITY oracle (M1 Stage 1): 344
/// forked children x 3 contexts (alloc + enc + dec, distinct tgids by
/// kernel construction) = 1032 distinct contexts against the
/// 1024-entry `KCTX` on a FRESH isolated sensor (own bring-up, no
/// shared state with any other test). Every equality is exact (`==`,
/// never `>=`): rows == 1024 (the FIRST refusal lands on the 1025th
/// distinct context — earlier saturation fails), drops == 8,
/// present == 1024, system == 1032, unknown == 8. The KTOT gate
/// (system == 1032 exactly) proves zero ambient traffic for the
/// whole attempt window — any ambient crypto fails loudly (re-run
/// on a quiet host), never silently. Fenced (`Quiescent` receipt)
/// and terminal-read. Privileged: needs root + BTF + the true
/// object; lane-ignored.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn ctx_first_over_capacity_is_exact() {
    use kryprobe_privilege::kcrypto_backend::{snapshot_ctx, snapshot_ctx_terminal};
    use kryprobe_privilege::kcrypto_fence::close_kernel_fence;

    if !is_root_with_btf() {
        println!("SKIP: needs root + BTF (privileged exactness lane)");
        return;
    }
    const KIDS: usize = 344;
    const KEYS_PER_KID: u64 = 3;
    const ATTEMPTED: u64 = KIDS as u64 * KEYS_PER_KID;
    const OVER: u64 = ATTEMPTED - 1024;
    assert_eq!(ATTEMPTED, 1032);
    assert_eq!(OVER, 8);
    let object = kcrypto_object_bytes().expect("BPF object present");
    let (sensor, _points) =
        kryprobe_privilege::btf_resolve::load_kcrypto_configured(&object, None).expect("bring-up");
    // Pre-quiet: a fresh sensor with no traffic yet — any ambient
    // row already occupying a slot voids the equality (fail loud).
    let (rows0, drops0) = snapshot_ctx(&sensor).expect("baseline snapshot");
    assert!(
        rows0.is_empty(),
        "ambient rows before our kids void isolation: {} rows",
        rows0.len()
    );
    assert_eq!(drops0, 0, "ambient drops before our kids void isolation");

    let mut kids = Vec::with_capacity(KIDS);
    for _ in 0..KIDS {
        // SAFETY: the child runs raw syscalls only, then `_exit` — no
        // allocator, no std locks, no harness return.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe { libc::_exit(child_crypto_once()) };
        }
        kids.push(pid);
    }
    for pid in &kids {
        let mut status = 0;
        // SAFETY: `status` is a live int; blocking wait for our child.
        let got = unsafe { libc::waitpid(*pid, &mut status, 0) };
        assert_eq!(got, *pid, "waitpid reaps our child");
        assert!(
            libc::WIFEXITED(status),
            "child {pid} exited normally, status {status}"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child {pid} crypto stages all green (10+stage otherwise)"
        );
    }
    let kid_tgids: std::collections::HashSet<u32> = kids.iter().map(|pid| *pid as u32).collect();
    // Fence first (Quiescent receipt), then the terminal account —
    // the equalities below read frozen maps, never a live race.
    let close = close_kernel_fence(&sensor.loaded.maps).expect("fence closes");
    assert!(
        close.is_quiescent_receipt(),
        "fence drains to Quiescent, got {close:?}"
    );
    let terminal = snapshot_ctx_terminal(&sensor);
    let rows = terminal.rows.expect("rows Some");
    let present = terminal.present_calls.expect("present Some");
    let system = terminal.system_calls.expect("system Some");
    let unknown = terminal.unknown_calls.expect("unknown Some");
    let drops = terminal.drops.expect("drops Some");
    // Ambient gate FIRST: system counts every observation on the
    // machine — exactly our attempts, or the equality is unevaluable
    // (fail loud, re-run quiet).
    assert_eq!(
        system, ATTEMPTED,
        "ambient gate: system={system} want exactly {ATTEMPTED} (ambient or loss voids equality)"
    );
    assert_eq!(rows, 1024, "map holds exactly 1024 rows");
    assert_eq!(present, 1024, "exactly 1024 attempts present");
    assert_eq!(
        drops, OVER,
        "first refusal at context 1025: drops == {OVER}"
    );
    assert_eq!(unknown, OVER, "unknown == drops == {OVER}");
    // Every admitted kid context attempted exactly once.
    let (live_rows, _) = snapshot_ctx(&sensor).expect("post-fence snapshot");
    let mut admitted = 0u64;
    for row in &live_rows {
        if kid_tgids.contains(&row.key.tgid) {
            assert_eq!(row.val.calls, 1, "admitted kid key attempted once");
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1024, "all 1024 rows are ours");
    println!("first-over-capacity: rows=1024 present=1024 system=1032 unknown=8 drops=8");
}

/// Controlled second observer (req 5): two live sensors share the
/// fexit trampoline and the same machine-wide calls land in both
/// ledgers. Both fences close `Quiescent` and both terminal snapshots
/// agree on our rows exactly. Privileged; SKIPs otherwise.
#[test]
#[ignore = "BPF lane: run with `cargo xtask test bpf`"]
fn second_observer_sees_same_ctx_rows() {
    use kryprobe_privilege::btf_resolve::load_kcrypto_configured;
    use kryprobe_privilege::kcrypto_fence::close_kernel_fence;

    if !is_root_with_btf() {
        println!("SKIP: needs root + BTF (privileged exactness lane)");
        return;
    }
    let object = kcrypto_object_bytes().expect("BPF object present");
    let (a, _pa) = load_kcrypto_configured(&object, None).expect("bring-up A");
    let (b, _pb) = load_kcrypto_configured(&object, None).expect("bring-up B");
    let pid = unsafe { libc::getpid() } as u32;
    // Traffic runs only after BOTH sensors are live (no attach gap).
    let counts =
        kryprobe_testkit::alg_fixture::skcipher_roundtrip("cbc(aes)", 6).expect("shared traffic");
    assert_eq!((counts.enc, counts.dec), (6, 6));
    let close_a = close_kernel_fence(&a.loaded.maps).expect("close A");
    assert!(
        close_a.is_quiescent_receipt(),
        "A drains to Quiescent, got {close_a:?}"
    );
    let close_b = close_kernel_fence(&b.loaded.maps).expect("close B");
    assert!(
        close_b.is_quiescent_receipt(),
        "B drains to Quiescent, got {close_b:?}"
    );
    let rows_a = our_ctx_rows(&a, pid).expect("rows A");
    let rows_b = our_ctx_rows(&b, pid).expect("rows B");
    assert_eq!(rows_a, rows_b, "both ledgers agree on our rows");
    assert_eq!(rows_a.len(), 3, "alloc + enc + dec in each ledger");
    let sum: u64 = rows_a.iter().map(|row| row.5).sum();
    assert_eq!(sum, 13, "6 enc + 6 dec + 1 alloc per ledger");
}
