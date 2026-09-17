// SPDX-License-Identifier: GPL-3.0-or-later
//! Attach suite: link create/destroy latency (median + p99 over cycles).

use super::{
    SuiteResult, SuiteStatus, locate_bpf_object, locate_fixture, median_of, percentile_of,
};
use kryprobe_core::ids::PlanGeneration;
use kryprobe_core::object::{ObjectRef, ObjectRole};
use kryprobe_core::plan::TargetScope;
use kryprobe_core::{GenerationGuard, LinkGroup, ProgramId};
use kryprobe_privilege::attach::{AttachError, attach_group};
use kryprobe_privilege::bpfloader::{LoaderError, SpineProgs, load_spine_object};
use kryprobe_privilege::elfread::goblin_parser;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Cycles per iteration; one warmup iteration is discarded.
const CYCLES: usize = 200;
/// Measured iterations after warmup.
const ITERS: usize = 5;

fn denied(name: &'static str, stage: impl Into<String>) -> SuiteResult {
    SuiteResult {
        name,
        status: SuiteStatus::Denied {
            stage: stage.into(),
        },
    }
}

fn pump_lines<R: std::io::Read + Send + 'static>(reader: R) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// One iteration: spawn, time 200 create/destroy cycles, reap.
fn iteration(
    fixture: &PathBuf,
    guard: &GenerationGuard,
    progs: &SpineProgs,
    offset: u64,
    generation: PlanGeneration,
) -> Result<Vec<f64>, String> {
    let mut child: Child = Command::new(fixture)
        .arg("0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("fixture-spawn: {err}"))?;
    let lines = pump_lines(child.stdout.take().expect("piped stdout"));
    let mut out = Vec::with_capacity(CYCLES);
    let run = (|| -> Result<(), String> {
        if lines
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "fixture-ready".to_owned())?
            != "READY"
        {
            return Err("fixture-ready".to_owned());
        }
        // Groups scope the LIVE child: metadata + pid pinned per iteration.
        let meta =
            std::fs::symlink_metadata(fixture).map_err(|err| format!("fixture-meta: {err}"))?;
        let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
        let group = |entry: bool| LinkGroup {
            object: ObjectRef {
                dev: meta.dev(),
                ino: meta.ino(),
                size: meta.size(),
                mtime: mtime_ns,
                role: ObjectRole::Executable,
            },
            program: ProgramId::UprobeMultiSelfProbe,
            scope: TargetScope::Pid { pid: child.id() },
            entry,
            generation,
        };
        let (ret_group, entry_group) = (group(false), group(true));
        for i in 0..CYCLES {
            let entry = i % 2 == 0;
            let prog = if entry { &progs.entry } else { &progs.ret };
            let link_group = if entry { &entry_group } else { &ret_group };
            let start = Instant::now();
            let link = attach_group(link_group, guard, prog, fixture, &[offset]).map_err(
                |err| match err {
                    AttachError::LinkFailed { stage, .. } => stage,
                    AttachError::Rejected { reason } => format!("rejected:{reason}"),
                },
            )?;
            drop(link);
            out.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(b"GO\n")
            .map_err(|err| format!("fixture-go: {err}"))?;
        if lines
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "fixture-done".to_owned())?
            .starts_with("DONE ")
        {
            Ok(())
        } else {
            Err("fixture-done".to_owned())
        }
    })();
    child.kill().ok();
    child.wait().ok();
    run?;
    Ok(out)
}

/// Runs the attach suite: 200 cycles × (1 warmup + 5 measured).
pub(crate) fn run() -> SuiteResult {
    let Some(object) = locate_bpf_object() else {
        return denied("attach", "missing-object");
    };
    let Some(fixture) = locate_fixture() else {
        return denied("attach", "missing-fixture");
    };
    let loaded = match load_spine_object(&object) {
        Ok(loaded) => loaded,
        Err(LoaderError::MapFailed { stage, errno })
        | Err(LoaderError::LoadFailed { stage, errno, .. }) => {
            let refused = errno == libc::EPERM || errno == libc::EACCES;
            return denied(
                "attach",
                if refused {
                    stage
                } else {
                    format!("loader:{stage}")
                },
            );
        }
        Err(err) => return denied("attach", format!("loader:{err:?}")),
    };
    let bytes = match std::fs::read(&fixture) {
        Ok(bytes) => bytes,
        Err(err) => return denied("attach", format!("fixture-read:{err}")),
    };
    let offset = match goblin_parser::static_symbol_file_offset(&bytes, "spine_target_fn") {
        Ok(Some(offset)) => offset,
        _ => return denied("attach", "offset"),
    };
    let generation = PlanGeneration::new(1);
    let guard = GenerationGuard { generation };
    let mut samples: Vec<f64> = Vec::with_capacity(CYCLES * ITERS);
    for iter in 0..=ITERS {
        match iteration(&fixture, &guard, &loaded.progs, offset, generation) {
            Ok(mut batch) => {
                if iter > 0 {
                    samples.append(&mut batch);
                }
            }
            Err(stage) => return denied("attach", stage),
        }
    }
    let median = median_of(&mut samples);
    let p99 = percentile_of(&mut samples, 99.0);
    SuiteResult {
        name: "attach",
        status: SuiteStatus::Ok {
            human: format!(
                "median={median:.3}ms p99={p99:.3}ms cycles={}",
                samples.len()
            ),
            json: serde_json::json!({"median_ms": median, "p99_ms": p99, "cycles": samples.len()}),
        },
    }
}
