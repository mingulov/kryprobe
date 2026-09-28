// SPDX-License-Identifier: GPL-3.0-or-later
//! P7/T12 output suite: terminal output finalization, observation-cap
//! reconciliation, stop ordering, and signal gates — all through the
//! public CLI surface against scripted sensors and failing writers.
//! The guest lane (E04–E07) proves the same behaviors against real
//! kernel mechanisms and real pipes.

use kryprobe_cli::cmd_report::render_lifecycle_session_with_id;
use kryprobe_cli::live::{
    LifecycleSessionSensor, LiveConfig, LiveError, LiveOutcome, drive_lifecycle_session,
    emit_stdout_text,
};
use kryprobe_core::ids::{IdIssuer, PlanGeneration, SessionId};
use kryprobe_core::kcrypto::{ReducerStats, RequestRecord, Terminal};
use kryprobe_core::session::{SessionController, SessionState};
use kryprobe_privilege::host::SIGINT_SEEN;
use kryprobe_privilege::kcrypto_lifecycle::async_adapter::AdapterStats;
use kryprobe_privilege::kcrypto_lifecycle::backend::LifecycleBackend;
use kryprobe_privilege::kcrypto_lifecycle::decode::DecodeStats;
use kryprobe_privilege::kcrypto_lifecycle::profile::{LifecycleProfile, manifest, max_programs};
use kryprobe_privilege::kcrypto_lifecycle::sensor::{
    DrainOutcome, EnrichmentStatus, LifecycleLedger, QuietOutcome,
};
use kryprobe_privilege::kcrypto_lifecycle::tfm::TfmStats;
use std::io::{Error, ErrorKind, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Serializes the SIGINT-global cells: `SIGINT_SEEN` is
/// process-global, so every emit/drive test in this suite holds the
/// guard and resets the flag first (a set flag aborts emits and
/// interrupts drives — without the guard parallel tests flake).
static SIGINT_GUARD: Mutex<()> = Mutex::new(());

fn reset_sigint() -> std::sync::MutexGuard<'static, ()> {
    let guard = SIGINT_GUARD.lock().expect("suite guard");
    SIGINT_SEEN.store(false, Ordering::Relaxed);
    guard
}

/// Writer failing with `EPIPE` after `limit` bytes (partial write,
/// then broken pipe). Bytes already accepted stay in `buf`.
struct FailAfter {
    limit: usize,
    buf: Vec<u8>,
}

impl Write for FailAfter {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        let room = self.limit.saturating_sub(self.buf.len());
        if room == 0 {
            return Err(Error::new(ErrorKind::BrokenPipe, "failing writer: EPIPE"));
        }
        let take = room.min(chunk.len());
        self.buf.extend_from_slice(&chunk[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writer failing every write with `EPIPE` (broken pipe, nothing
/// accepted).
struct BrokenPipe;

impl Write for BrokenPipe {
    fn write(&mut self, _chunk: &[u8]) -> std::io::Result<usize> {
        Err(Error::new(ErrorKind::BrokenPipe, "failing writer: EPIPE"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writer accepting every byte but failing `flush` (final-flush
/// failure — only a checked flush catches it).
struct FlushFails {
    buf: Vec<u8>,
}

impl Write for FlushFails {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(Error::other("failing writer: flush EIO"))
    }
}

/// Output partial write: 10 of 26 bytes land, then EPIPE — the emit
/// reports the terminal failure (exit 1 + `cannot write stdout`),
/// never the capture's success code over a torn stream.
#[test]
fn output_partial_write_reports_terminal_failure() {
    let _sigint = reset_sigint();
    let mut stdout = FailAfter {
        limit: 10,
        buf: Vec::new(),
    };
    let mut stderr = Vec::new();
    let code = emit_stdout_text(
        &mut stdout,
        &mut stderr,
        "report",
        "abcdefghijklmnopqrstuvwxyz",
        0,
    );
    assert_eq!(
        stdout.buf, b"abcdefghij",
        "exactly the accepted prefix lands"
    );
    assert_eq!(code, 1, "torn stream never reports success");
    let stderr = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("report: cannot write stdout"),
        "explicit terminal output status: {stderr}"
    );
}

/// Output broken pipe: nothing lands — exit 1 with the explicit
/// status, never a silent success code.
#[test]
fn output_broken_pipe_reports_terminal_failure() {
    let _sigint = reset_sigint();
    let mut stdout = BrokenPipe;
    let mut stderr = Vec::new();
    let code = emit_stdout_text(&mut stdout, &mut stderr, "watch", "tables…", 3);
    assert_eq!(code, 1, "broken pipe never reports the capture code");
    let stderr = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("watch: cannot write stdout"),
        "explicit terminal output status: {stderr}"
    );
}

/// Output final flush: every byte accepted but the flush fails —
/// exit 1 with the explicit flush status. An emit that never
/// flushes would wrongly report success here.
#[test]
fn output_final_flush_failure_reports_terminal_failure() {
    let _sigint = reset_sigint();
    let mut stdout = FlushFails { buf: Vec::new() };
    let mut stderr = Vec::new();
    let code = emit_stdout_text(&mut stdout, &mut stderr, "report", "session…", 0);
    assert_eq!(stdout.buf, b"session\xe2\x80\xa6", "bytes accepted");
    assert_eq!(code, 1, "failed flush never reports success");
    let stderr = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("report: cannot flush stdout"),
        "explicit flush status: {stderr}"
    );
}

/// Healthy emit: bytes land verbatim and the capture code passes
/// through untouched (success stays success, partial stays partial).
#[test]
fn output_healthy_emit_preserves_bytes_and_code() {
    let _sigint = reset_sigint();
    for code in [0, 3] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let out = emit_stdout_text(&mut stdout, &mut stderr, "report", "evidence\n", code);
        assert_eq!(stdout, b"evidence\n", "verbatim bytes");
        assert_eq!(out, code, "capture code passes through");
        assert!(stderr.is_empty(), "no stderr on success");
    }
}

/// E04-shaped slow sink: at most 1 KiB per `write` call, paced
/// 100 ms per call (test stimulus — the product never sleeps).
struct SlowSink {
    buf: Vec<u8>,
}

impl Write for SlowSink {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let take = chunk.len().min(1024);
        self.buf.extend_from_slice(&chunk[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// E04 (host seam) — slow sink: the declared emit mode is
/// blocking-complete (no omission at emit — the full text lands or
/// the failure is explicit). 5 KiB through a 1 KiB/100 ms sink
/// lands whole (~0.5 s) with the capture code preserved — a short
/// report is never silently clean. (The guest E04 cell proves the
/// same against a real slow pipe + resume + responsive stop.)
#[test]
fn e04_slow_sink_delivers_complete_or_explicit() {
    let _sigint = reset_sigint();
    let text = "x".repeat(5 * 1024);
    let mut stdout = SlowSink { buf: Vec::new() };
    let mut stderr = Vec::new();
    let start = std::time::Instant::now();
    let code = emit_stdout_text(&mut stdout, &mut stderr, "report", &text, 0);
    let elapsed = start.elapsed();
    assert_eq!(stdout.buf.len(), text.len(), "whole text lands");
    assert_eq!(stdout.buf, text.as_bytes(), "verbatim bytes");
    assert_eq!(code, 0, "capture code preserved");
    assert!(stderr.is_empty(), "no stderr on success");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "slow emit stays bounded: {elapsed:?}"
    );
}

/// Writer raising the real SIGINT witness on its Nth `write`
/// (simulates a fresh second Ctrl-C arriving mid-emit —
/// deterministic: no threads, no timing).
struct SigintOnNthWrite {
    buf: Vec<u8>,
    writes: usize,
    raise_at: usize,
}

impl Write for SigintOnNthWrite {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        if self.writes == self.raise_at {
            SIGINT_SEEN.store(true, Ordering::Relaxed);
        }
        self.buf.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Fresh SIGINT mid-emit aborts promptly with the torn-stream
/// status: 20 KiB emit (three 8 KiB chunks), the witness raised
/// during chunk one — chunk two's check aborts, so exactly one
/// chunk lands, exit 1, and stderr names the torn byte counts.
#[test]
fn output_fresh_sigint_mid_emit_aborts_promptly() {
    let _sigint = reset_sigint();
    let text = "y".repeat(20 * 1024);
    let mut stdout = SigintOnNthWrite {
        buf: Vec::new(),
        writes: 0,
        raise_at: 1,
    };
    let mut stderr = Vec::new();
    let code = emit_stdout_text(&mut stdout, &mut stderr, "report", &text, 0);
    assert_eq!(stdout.buf.len(), 8 * 1024, "exactly one chunk lands");
    assert_eq!(code, 1, "torn stream never reports success");
    let stderr = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("report: stdout emit interrupted (8192/20480 bytes)"),
        "explicit torn-stream status: {stderr}"
    );
    SIGINT_SEEN.store(false, Ordering::Relaxed);
}

/// Writer failing its first `write` with `Interrupted` while the
/// witness is SET (the privilege fd writer's fresh-SIGINT shape —
/// a stalled sink aborted mid-chunk): the emit maps it to the
/// torn-stream status (exit 1), never a silent code and never a
/// retry of an aborted stall.
struct InterruptedWithWitness {
    buf: Vec<u8>,
    failed: bool,
}

impl Write for InterruptedWithWitness {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        if !self.failed {
            self.failed = true;
            SIGINT_SEEN.store(true, Ordering::Relaxed);
            return Err(Error::new(
                ErrorKind::Interrupted,
                "stdout emit interrupted by SIGINT",
            ));
        }
        self.buf.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// P7-N1 — witness-set `Interrupted` mid-chunk aborts with the
/// torn-stream status: nothing lands (the stall aborted the first
/// write), exit 1, stderr names the torn byte counts.
#[test]
fn output_interrupted_with_witness_aborts_torn() {
    let _sigint = reset_sigint();
    let mut stdout = InterruptedWithWitness {
        buf: Vec::new(),
        failed: false,
    };
    let mut stderr = Vec::new();
    let code = emit_stdout_text(&mut stdout, &mut stderr, "report", "evidence\n", 0);
    assert!(stdout.buf.is_empty(), "stalled write lands nothing");
    assert_eq!(code, 1, "torn stream never reports success");
    let stderr = String::from_utf8(stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("report: stdout emit interrupted (0/9 bytes)"),
        "explicit torn-stream status: {stderr}"
    );
    SIGINT_SEEN.store(false, Ordering::Relaxed);
}

/// Writer failing its first `write` with a SPURIOUS `Interrupted`
/// (witness clear — a foreign signal cut the write, not ours): the
/// emit retries and the full text lands with the code preserved —
/// never an abort on a signal that is not ours.
struct SpuriousInterrupted {
    buf: Vec<u8>,
    failed: bool,
}

impl Write for SpuriousInterrupted {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        if !self.failed {
            self.failed = true;
            assert!(
                !SIGINT_SEEN.load(Ordering::Relaxed),
                "witness clear on the spurious cut"
            );
            return Err(Error::new(ErrorKind::Interrupted, "foreign signal"));
        }
        self.buf.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// P7-N1 — spurious `Interrupted` (witness clear) retries: the full
/// text lands verbatim with the capture code preserved.
#[test]
fn output_spurious_interrupted_retries() {
    let _sigint = reset_sigint();
    let mut stdout = SpuriousInterrupted {
        buf: Vec::new(),
        failed: false,
    };
    let mut stderr = Vec::new();
    let code = emit_stdout_text(&mut stdout, &mut stderr, "report", "evidence\n", 3);
    assert_eq!(stdout.buf, b"evidence\n", "verbatim bytes after retry");
    assert_eq!(code, 3, "capture code preserved");
    assert!(stderr.is_empty(), "no stderr on success");
}

/// Stale SIGINT (the capture's own interruption, already latched
/// into the outcome) never aborts the render: the emit re-arms
/// first, so the full text lands with the capture code preserved.
/// (Pins the interrupted-capture exit-3-with-evidence contract at
/// the emit seam.)
#[test]
fn output_stale_sigint_does_not_abort_emit() {
    let _sigint = reset_sigint();
    SIGINT_SEEN.store(true, Ordering::Relaxed); // stale: pre-emit set
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = emit_stdout_text(&mut stdout, &mut stderr, "watch", "tables\n", 3);
    assert_eq!(stdout, b"tables\n", "stale set never aborts the render");
    assert_eq!(code, 3, "capture code preserved");
    assert!(stderr.is_empty(), "no stderr on success");
    assert!(
        !SIGINT_SEEN.load(Ordering::Relaxed),
        "emit re-armed the witness"
    );
}

// ---------------------------------------------------------------------------
// Scripted lifecycle drives: stop ordering, E05 gates, E06 cap, backlog.
// ---------------------------------------------------------------------------

fn attached_controller() -> SessionController {
    use kryprobe_core::session::SessionState as S;
    let mut controller = SessionController::new();
    for state in [S::Qualified, S::Discovering, S::Attaching] {
        controller.transition(state).expect("bring-up hop legal");
    }
    controller
}

fn output_record(id: u64, terminal: Terminal) -> RequestRecord {
    let duration_ns = if terminal == Terminal::Unknown {
        None
    } else {
        Some(1000 + id)
    };
    RequestRecord {
        id,
        tfm_id: None,
        terminal,
        duration_ns,
        meta: kryprobe_core::kcrypto::RequestMeta {
            family: kryprobe_core::kcrypto::LifecycleFamily::Skcipher,
            direction: kryprobe_core::kcrypto::OpDirection::Encrypt,
            cryptlen: Some(16),
            req_flags: Some(0),
            epoch: Some(0),
            aead: None,
        },
    }
}

fn output_ledger(admitted: u64, emitted: u64, unfinished: u64) -> LifecycleLedger {
    LifecycleLedger {
        completed: Vec::new(),
        edge_hits: [0; 22],
        decode: DecodeStats {
            admitted,
            ..DecodeStats::default()
        },
        reducer: ReducerStats {
            admitted,
            emitted,
            unfinished,
            ..ReducerStats::default()
        },
        adapter: AdapterStats::default(),
        kernel_loss: [0; 5],
        agg_accepted: [0; 22],
        retained_dropped: 0,
        view_valid: true,
        loss_baseline: [0; 5],
        agg_baseline: [0; 22],
        prog_misses: Vec::new(),
        miss_current: Vec::new(),
        tfm_stats: TfmStats::default(),
        generations: Vec::new(),
        enrichment: EnrichmentStatus::Available {
            entries: 0,
            truncated: false,
        },
    }
}

/// Scripted lifecycle sensor with a call-order tape: teardown calls
/// (`fence_admissions` → `drain_fenced`/`take_fenced` (only when the
/// script stages fence records — otherwise in-flight reads zero and
/// no round runs) → `verify_identity` → `close_input` →
/// `drain_quiet` → `take_close` → `finish_stop` → `take_close` →
/// `ledger`) record in order (per-tick takes stay off the tape).
/// Structural pins (beyond string equality): `close_input` refuses
/// unless fenced, `drain_quiet`/`finish_stop` refuse unless
/// detached. Optional SIGINT injection on a chosen `drain_tick`
/// (E05 mid-burst) or in `drain_quiet` (E05 closing drain).
struct ScriptedOutputSensor<'a> {
    ticks: Vec<Vec<RequestRecord>>,
    fence_records: Vec<RequestRecord>,
    finish_records: Vec<RequestRecord>,
    finish_staged: bool,
    ledger: LifecycleLedger,
    now: u64,
    drains: AtomicU64,
    taken: AtomicU64,
    fenced: bool,
    fence_served: AtomicBool,
    teardown: bool,
    order: Mutex<Vec<&'static str>>,
    quiet_backlog: u64,
    sigint_on_drain: Option<u64>,
    sigint_on_quiet: bool,
    stop: &'a AtomicBool,
}

impl ScriptedOutputSensor<'_> {
    fn tape(&self, call: &'static str) {
        self.order.lock().expect("tape").push(call);
    }
}

impl LifecycleSessionSensor for ScriptedOutputSensor<'_> {
    fn wait_for_activity(
        &mut self,
        _max_wait: std::time::Duration,
        _pending_writer: bool,
    ) -> Result<(), LiveError> {
        Ok(())
    }

    fn drain_tick(&mut self, _max_records: usize) -> Result<DrainOutcome, LiveError> {
        if self.fenced && !self.teardown {
            // Stop-phase in-flight round (never a tick drain — the
            // tick counters stay untouched, and SIGINT injection
            // targets ticks only).
            self.tape("drain_fenced");
            let completed = self.fence_records.len();
            return Ok(DrainOutcome {
                records: completed,
                completed,
                busy: false,
            });
        }
        let call = self.drains.fetch_add(1, Ordering::Relaxed);
        if Some(call) == self.sigint_on_drain {
            SIGINT_SEEN.store(true, Ordering::Relaxed);
        }
        if call + 1 >= self.ticks.len() as u64 {
            self.stop.store(true, Ordering::Relaxed);
        }
        let completed = self.ticks[(call as usize).min(self.ticks.len() - 1)].len();
        Ok(DrainOutcome {
            records: completed,
            completed,
            busy: false,
        })
    }

    fn take_completed(&mut self) -> Result<Vec<RequestRecord>, LiveError> {
        if self.finish_staged {
            self.finish_staged = false;
            self.tape("take_close");
            return Ok(self.finish_records.clone());
        }
        if self.fenced && !self.teardown && !self.fence_served.load(Ordering::Relaxed) {
            self.fence_served.store(true, Ordering::Relaxed);
            self.tape("take_fenced");
            return Ok(self.fence_records.clone());
        }
        let call = self.taken.fetch_add(1, Ordering::Relaxed);
        if self.teardown {
            self.tape("take_close");
            return Ok(Vec::new());
        }
        if call >= self.ticks.len() as u64 {
            return Ok(Vec::new());
        }
        Ok(self.ticks[call as usize].clone())
    }

    fn verify_identity(&self) -> Result<(), LiveError> {
        self.tape("verify_identity");
        Ok(())
    }

    fn fence_admissions(&mut self) -> Result<(), LiveError> {
        self.fenced = true;
        self.tape("fence_admissions");
        Ok(())
    }

    fn in_flight(&self) -> Result<u64, LiveError> {
        // Scripted in-flight: nonzero until the staged fence batch
        // is served once (an empty script reads zero — no round
        // runs, exactly like a drained production sensor).
        if self.fenced
            && !self.fence_served.load(Ordering::Relaxed)
            && !self.fence_records.is_empty()
        {
            Ok(self.fence_records.len() as u64)
        } else {
            Ok(0)
        }
    }

    fn close_input(&mut self) -> Result<(), LiveError> {
        assert!(self.fenced, "fence precedes detach (P7-N5 order)");
        self.teardown = true;
        self.tape("close_input");
        Ok(())
    }

    fn drain_quiet(&mut self) -> Result<QuietOutcome, LiveError> {
        assert!(self.teardown, "detach precedes the remaining drain");
        self.tape("drain_quiet");
        if self.sigint_on_quiet {
            SIGINT_SEEN.store(true, Ordering::Relaxed);
        }
        Ok(QuietOutcome {
            rounds: 1,
            records: 0,
            quiet: self.quiet_backlog == 0,
            backlog_bytes: self.quiet_backlog,
        })
    }

    fn finish_stop(&mut self, stop_ns: u64) -> Result<(), LiveError> {
        assert_eq!(stop_ns, self.now, "finish stamps the closing wall");
        assert!(self.teardown, "detach precedes truthless finish");
        self.tape("finish_stop");
        self.finish_staged = true;
        Ok(())
    }

    fn ledger(&self) -> Result<LifecycleLedger, LiveError> {
        self.tape("ledger");
        Ok(self.ledger.clone())
    }

    fn now_ns(&self) -> Result<u64, LiveError> {
        Ok(self.now)
    }
}

fn output_config() -> LiveConfig {
    LiveConfig {
        source: "kernel-crypto".to_owned(),
        duration_secs: None,
        tick_ms: 1,
        token: None,
        json_audit: false,
        profile: LifecycleProfile::RequestLifecycle,
    }
}

fn attached_points() -> usize {
    max_programs(&manifest(LifecycleProfile::RequestLifecycle))
}

fn drive_scripted(sensor: &mut ScriptedOutputSensor<'_>, stop: &AtomicBool) -> LiveOutcome {
    let backend = LifecycleBackend::new();
    let cfg = output_config();
    let mut controller = attached_controller();
    drive_lifecycle_session(
        &cfg,
        &backend,
        sensor,
        stop,
        attached_points(),
        SessionId::new(1),
        PlanGeneration::new(1),
        &IdIssuer::default(),
        &mut controller,
        None,
    )
    .expect("scripted session drives")
}

/// Renders the outcome's session envelope and returns the parsed
/// receipt record (verdict + populations + loss map).
fn receipt_of(outcome: &LiveOutcome) -> serde_json::Value {
    let text = render_lifecycle_session_with_id(
        outcome,
        LifecycleProfile::RequestLifecycle,
        "session:t12-test",
        None,
    )
    .expect("scripted outcome renders");
    text.lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("jsonl"))
        .find(|record| record["kind"] == "session_receipt")
        .expect("terminal receipt")
}

fn new_sensor<'a>(
    ticks: Vec<Vec<RequestRecord>>,
    finish_records: Vec<RequestRecord>,
    ledger: LifecycleLedger,
    stop: &'a AtomicBool,
) -> ScriptedOutputSensor<'a> {
    ScriptedOutputSensor {
        ticks,
        fence_records: Vec::new(),
        finish_records,
        finish_staged: false,
        ledger,
        now: 555,
        drains: AtomicU64::new(0),
        taken: AtomicU64::new(0),
        fenced: false,
        fence_served: AtomicBool::new(false),
        teardown: false,
        order: Mutex::new(Vec::new()),
        quiet_backlog: 0,
        sigint_on_drain: None,
        sigint_on_quiet: false,
        stop,
    }
}

/// Item 2 — stop ordering: admission fence → bounded in-flight
/// → snapshot → detach/drain → writer finalize → verdict, read off
/// the call tape: `fence_admissions` (no new admits; links stay up)
/// → `drain_fenced` + `take_fenced` (the staged in-flight batch
/// completes BEFORE detach) → `verify_identity` (attached
/// snapshot, links still up) → `close_input` (disarm+detach) →
/// `drain_quiet` (remaining drain) → `take_close` →
/// `finish_stop` (truthless reconciliation) → `take_close` →
/// `ledger` (terminal snapshot, LAST). The equation holds exactly
/// (`admitted == emitted`, `unfinished ⊆ emitted`), the machine
/// finalizes, and the unfinished record forces a partial receipt —
/// all without any global-machine idle (the scripted transport is
/// never quiet-gated: takes serve scripted batches, never a drain
/// to machine silence).
#[test]
fn stop_ordering_fence_then_drain_then_verdict() {
    let _sigint = reset_sigint();
    let stop = AtomicBool::new(false);
    let mut sensor = new_sensor(
        vec![vec![output_record(1, Terminal::Sync(0))]],
        vec![output_record(3, Terminal::Unknown)],
        output_ledger(3, 3, 1),
        &stop,
    );
    // The staged in-flight batch: completes in the fence window
    // (before detach), proving the phase is real handling, not a
    // relabelled detach-first tape.
    sensor.fence_records = vec![output_record(2, Terminal::Callback(-5))];
    let start = std::time::Instant::now();
    let outcome = drive_scripted(&mut sensor, &stop);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "stop completes promptly without machine idle"
    );
    let tape = sensor.order.lock().expect("tape").clone();
    assert_eq!(
        tape,
        vec![
            "fence_admissions",
            "drain_fenced",
            "take_fenced",
            "verify_identity",
            "close_input",
            "drain_quiet",
            "take_close",
            "finish_stop",
            "take_close",
            "ledger",
        ],
        "teardown call order: {tape:?}"
    );
    assert_eq!(outcome.terminal_state, SessionState::Finalized);
    assert!(!outcome.interrupted, "no interruption");
    assert_eq!(outcome.observations.len(), 3, "every completion kept");
    let totals = outcome.lifecycle_totals.as_ref().expect("totals ride");
    assert_eq!((totals.admitted, totals.emitted), (3, 3), "exact equation");
    assert_eq!(totals.unfinished, 1, "truthless finish counted");
    assert!(totals.unfinished <= totals.emitted, "unfinished ⊆ emitted");
    let receipt = receipt_of(&outcome);
    assert_eq!(receipt["verdict"], "partial", "unfinished forces partial");
    assert_eq!(receipt["admitted"], 3);
    assert_eq!(receipt["emitted"], 3);
    assert_eq!(receipt["unfinished"], 1);
}

/// E05 gate 1 (host seam) — SIGINT before GO: the window ends
/// interrupted on the first tick, teardown still runs the ordered
/// fence→drain→verdict sequence, the equation holds, and the
/// receipt is partial with the final writer outcome explicit
/// (observations kept + receipt present). Stop/reap ≤ 10 s.
#[test]
fn e05_sigint_before_go_interrupts_deterministically() {
    let _sigint = reset_sigint();
    let stop = AtomicBool::new(false);
    let mut sensor = new_sensor(
        vec![vec![output_record(1, Terminal::Sync(0))]],
        vec![output_record(2, Terminal::Unknown)],
        output_ledger(2, 2, 1),
        &stop,
    );
    SIGINT_SEEN.store(true, Ordering::Relaxed); // before GO
    let start = std::time::Instant::now();
    let outcome = drive_scripted(&mut sensor, &stop);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "interrupted stop prompt"
    );
    SIGINT_SEEN.store(false, Ordering::Relaxed);
    assert!(outcome.interrupted, "window latched the interruption");
    assert_eq!(outcome.terminal_state, SessionState::Finalized);
    let tape = sensor.order.lock().expect("tape").clone();
    assert_eq!(
        tape,
        vec![
            "fence_admissions",
            "verify_identity",
            "close_input",
            "drain_quiet",
            "take_close",
            "finish_stop",
            "take_close",
            "ledger",
        ],
        "interrupted teardown keeps the order: {tape:?}"
    );
    let totals = outcome.lifecycle_totals.as_ref().expect("totals ride");
    assert_eq!((totals.admitted, totals.emitted), (2, 2));
    assert_eq!(totals.unfinished, 1);
    let receipt = receipt_of(&outcome);
    assert_eq!(receipt["verdict"], "partial", "interrupted forces partial");
}

/// E05 gate 2 (host seam) — SIGINT mid-burst: the witness raised
/// on the second drain tick cuts an active burst; the records
/// taken before the cut are kept, the equation holds over the
/// scripted ledger, and the receipt is partial. No global-machine
/// idle: the stop flag + witness end the window with scripted
/// batches still unserved.
#[test]
fn e05_sigint_mid_burst_keeps_prefix_and_equation() {
    let _sigint = reset_sigint();
    let stop = AtomicBool::new(false);
    let mut sensor = new_sensor(
        vec![
            vec![output_record(1, Terminal::Sync(0))],
            vec![output_record(2, Terminal::Sync(0))],
            vec![output_record(3, Terminal::Sync(0))],
            vec![output_record(4, Terminal::Sync(0))],
        ],
        Vec::new(),
        output_ledger(4, 4, 0),
        &stop,
    );
    sensor.sigint_on_drain = Some(1);
    let start = std::time::Instant::now();
    let outcome = drive_scripted(&mut sensor, &stop);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "mid-burst stop prompt"
    );
    SIGINT_SEEN.store(false, Ordering::Relaxed);
    assert!(outcome.interrupted, "burst latched the interruption");
    assert_eq!(outcome.terminal_state, SessionState::Finalized);
    assert!(
        !outcome.observations.is_empty() && outcome.observations.len() <= 4,
        "cut prefix kept: {}",
        outcome.observations.len()
    );
    let totals = outcome.lifecycle_totals.as_ref().expect("totals ride");
    assert_eq!((totals.admitted, totals.emitted), (4, 4));
    let receipt = receipt_of(&outcome);
    assert_eq!(receipt["verdict"], "partial", "interrupted forces partial");
}

/// E05 gate 3 (host seam) — SIGINT with queued async pending: one
/// request never completes (nothing taken pre-stop); the stop
/// drains it truthless at finish (no hang waiting for the missing
/// terminal — stopping never requires the machine to go idle),
/// counts it unfinished, and receipts partial.
#[test]
fn e05_sigint_with_async_pending_drains_truthless() {
    let _sigint = reset_sigint();
    let stop = AtomicBool::new(false);
    let mut sensor = new_sensor(
        vec![Vec::new()],
        vec![output_record(1, Terminal::Unknown)],
        output_ledger(1, 1, 1),
        &stop,
    );
    SIGINT_SEEN.store(true, Ordering::Relaxed);
    let start = std::time::Instant::now();
    let outcome = drive_scripted(&mut sensor, &stop);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "pending stop never waits for idle"
    );
    SIGINT_SEEN.store(false, Ordering::Relaxed);
    assert!(outcome.interrupted);
    assert_eq!(outcome.terminal_state, SessionState::Finalized);
    assert_eq!(outcome.observations.len(), 1, "truthless record kept");
    let totals = outcome.lifecycle_totals.as_ref().expect("totals ride");
    assert_eq!(
        (totals.admitted, totals.emitted, totals.unfinished),
        (1, 1, 1)
    );
    let receipt = receipt_of(&outcome);
    assert_eq!(receipt["verdict"], "partial");
    assert_eq!(receipt["unfinished"], 1);
}

/// E05 gate 4 (host seam) — SIGINT during the closing drain: the
/// witness raised inside `drain_quiet` (teardown already past the
/// window loop) changes NOTHING — teardown completes, the window
/// evidence is whole (`interrupted` stays false: the window
/// closed before the arrival), and totals match the no-signal run
/// exactly (differential pin — no absolute clean claim over
/// scripted coverage).
#[test]
fn e05_sigint_during_close_leaves_finalization_whole() {
    let _sigint = reset_sigint();
    let run = |sigint_on_quiet: bool| {
        SIGINT_SEEN.store(false, Ordering::Relaxed);
        let stop = AtomicBool::new(false);
        let mut sensor = new_sensor(
            vec![
                vec![output_record(1, Terminal::Sync(0))],
                vec![output_record(2, Terminal::Callback(-5))],
            ],
            Vec::new(),
            output_ledger(2, 2, 0),
            &stop,
        );
        sensor.sigint_on_quiet = sigint_on_quiet;
        let outcome = drive_scripted(&mut sensor, &stop);
        SIGINT_SEEN.store(false, Ordering::Relaxed);
        let totals = outcome.lifecycle_totals.clone().expect("totals ride");
        let receipt = receipt_of(&outcome);
        (
            outcome.interrupted,
            outcome.terminal_state,
            outcome.observations.len(),
            totals,
            receipt["verdict"].clone(),
        )
    };
    let plain = run(false);
    let signaled = run(true);
    assert_eq!(plain, signaled, "closing-drain SIGINT changes nothing");
    assert!(!signaled.0, "window closed before the arrival");
    assert_eq!(signaled.1, SessionState::Finalized);
    assert_eq!(signaled.2, 2, "whole window kept");
}

/// E06 (host seam) — 100,005 completions against the 100,000
/// observation cap: exactly 100,000 observations kept, exactly 5
/// counted omissions (`driver.omitted`), the equation exact
/// (`admitted == emitted == 100,005`, `unfinished == 0`), and an
/// explicit partial receipt carrying the omission stage — a short
/// report is never silently clean. (The guest E06 cell proves the
/// same against real completions.)
#[test]
fn e06_cap_reconciles_truncated_retained_unfinished() {
    let _sigint = reset_sigint();
    const TOTAL: u64 = 100_005;
    const BATCHES: usize = 11;
    let per = TOTAL / BATCHES as u64;
    let mut ticks = Vec::with_capacity(BATCHES);
    let mut id = 1u64;
    for batch in 0..BATCHES {
        let count = if batch == BATCHES - 1 {
            TOTAL - id + 1
        } else {
            per
        };
        let mut records = Vec::with_capacity(count as usize);
        for _ in 0..count {
            records.push(output_record(id, Terminal::Sync(0)));
            id += 1;
        }
        ticks.push(records);
    }
    assert_eq!(id - 1, TOTAL, "script carries all 100,005");
    let stop = AtomicBool::new(false);
    let mut sensor = new_sensor(ticks, Vec::new(), output_ledger(TOTAL, TOTAL, 0), &stop);
    let start = std::time::Instant::now();
    let outcome = drive_scripted(&mut sensor, &stop);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(120),
        "capped drive terminates"
    );
    assert_eq!(
        outcome.observations.len(),
        100_000,
        "cap retains exactly 100,000"
    );
    let totals = outcome.lifecycle_totals.as_ref().expect("totals ride");
    assert_eq!((totals.admitted, totals.emitted), (TOTAL, TOTAL));
    assert_eq!(totals.unfinished, 0, "no unfinished work");
    assert_eq!(totals.omitted, 5, "exactly 5 counted omissions");
    assert!(
        totals.loss_stages().contains(&("driver.omitted", 5)),
        "omission rides its own stage: {:?}",
        totals.loss_stages()
    );
    assert!(totals.loss_total() > 0, "loss_total names the shortfall");
    let receipt = receipt_of(&outcome);
    assert_eq!(receipt["verdict"], "partial", "cap forces partial");
    assert_eq!(receipt["admitted"], TOTAL);
    assert_eq!(receipt["emitted"], TOTAL);
    assert_eq!(receipt["unfinished"], 0);
    assert_eq!(
        receipt["loss"]["driver.omitted"], 5,
        "receipt carries the omission stage"
    );
}

/// Close backlog (host seam) — a non-quiet close (512 backlog
/// bytes) voids clean: the byte measurement rides its own stage,
/// `loss_total` is nonzero, and the receipt is partial. An
/// incomplete close drain can never certify a clean stream.
#[test]
fn close_backlog_forces_partial_receipt() {
    let _sigint = reset_sigint();
    let stop = AtomicBool::new(false);
    let mut sensor = new_sensor(
        vec![vec![output_record(1, Terminal::Sync(0))]],
        Vec::new(),
        output_ledger(1, 1, 0),
        &stop,
    );
    sensor.quiet_backlog = 512;
    let outcome = drive_scripted(&mut sensor, &stop);
    assert_eq!(outcome.terminal_state, SessionState::Finalized);
    let totals = outcome.lifecycle_totals.as_ref().expect("totals ride");
    assert_eq!(totals.close_backlog_bytes, 512, "measured backlog rides");
    assert!(
        totals
            .loss_stages()
            .contains(&("transport.close_backlog_bytes", 512)),
        "backlog rides its own bytes stage: {:?}",
        totals.loss_stages()
    );
    let receipt = receipt_of(&outcome);
    assert_eq!(receipt["verdict"], "partial", "backlog voids clean");
}
