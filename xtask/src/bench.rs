// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask bench`: receipt suites (attach/drain/elf/e2e) + machine line.
//!
//! Values are recorded, never asserted: every suite prints one row (or
//! `DENIED <stage>` when it produced no numbers), and the command exits
//! 0 when all suites ran, 4 when any suite was denied. `DENIED` covers
//! missing artifacts and harness faults too — the stage names the cause.

mod attach;
mod drain;
mod e2e;
mod elf;

use std::path::PathBuf;

/// One suite's receipt: numbers or an honest denial stage.
pub(crate) enum SuiteStatus {
    /// Suite ran; human detail plus the JSON payload.
    Ok {
        /// Human row suffix after `"<name>: "`.
        human: String,
        /// JSON detail object (merged under the suite entry).
        json: serde_json::Value,
    },
    /// Suite produced no numbers; stage names the cause.
    Denied {
        /// Denial stage (`map_create`, `missing-object`, ...).
        stage: String,
    },
}

/// Named suite receipt.
pub(crate) struct SuiteResult {
    /// Suite name (`attach`, `drain`, `elf`, `e2e`).
    pub(crate) name: &'static str,
    /// Receipt or denial.
    pub(crate) status: SuiteStatus,
}

/// Median of samples (sorts in place; empty reads 0.0 and never panics).
pub(crate) fn median_of(samples: &mut [f64]) -> f64 {
    percentile_of(samples, 50.0)
}

/// Percentile of samples (sorts in place; `p` in 0–100).
pub(crate) fn percentile_of(samples: &mut [f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(f64::total_cmp);
    let rank = (p / 100.0 * samples.len() as f64).ceil() as usize;
    samples[rank.clamp(1, samples.len()) - 1]
}

/// Machine description for the receipt header.
struct Machine {
    kernel: String,
    cpu: String,
    nproc: String,
    rustc: String,
}

/// Kernel, cpu model, nproc, rustc — fallbacks, never panics.
fn machine() -> Machine {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned());
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|rest| rest.split_once(':').map(|(_, v)| v.trim().to_owned()))
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let nproc = std::thread::available_parallelism()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "?".to_owned());
    let rustc = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    Machine {
        kernel,
        cpu,
        nproc,
        rustc,
    }
}

/// Locates the spine object: `KRYPROBE_BPF_OBJ`, exe-relative, CWD-relative.
pub(crate) fn locate_bpf_object() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("KRYPROBE_BPF_OBJ") {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() && path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let path = dir.join("../kryprobe-bpf/spine.bpf.o");
        if path.is_file() {
            return Some(path);
        }
    }
    let path = PathBuf::from("target/kryprobe-bpf/spine.bpf.o");
    if path.is_file() {
        return Some(path);
    }
    None
}

/// Locates `spine_fixture`: exe sibling, then CWD `target/debug`.
pub(crate) fn locate_fixture() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let path = dir.join("spine_fixture");
        if path.is_file() {
            return Some(path);
        }
    }
    let path = PathBuf::from("target/debug/spine_fixture");
    if path.is_file() {
        return Some(path);
    }
    None
}

/// Runs all suites; 0 when all ran, 4 when any was denied.
pub(crate) fn bench(json: bool) -> i32 {
    let machine = machine();
    let results = [attach::run(), drain::run(), elf::run(), e2e::run()];
    if json {
        let suites: Vec<serde_json::Value> = results
            .iter()
            .map(|result| match &result.status {
                SuiteStatus::Ok { json, .. } => {
                    serde_json::json!({"name": result.name, "status": "ok", "detail": json})
                }
                SuiteStatus::Denied { stage } => {
                    serde_json::json!({"name": result.name, "status": "denied", "stage": stage})
                }
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "machine": {"kernel": machine.kernel, "cpu": machine.cpu, "nproc": machine.nproc, "rustc": machine.rustc},
                "suites": suites,
            })
        );
    } else {
        println!(
            "machine: kernel={} cpu=\"{}\" nproc={} rustc=\"{}\"",
            machine.kernel, machine.cpu, machine.nproc, machine.rustc
        );
        for result in &results {
            match &result.status {
                SuiteStatus::Ok { human, .. } => println!("{}: {human}", result.name),
                SuiteStatus::Denied { stage } => println!("{}: DENIED {stage}", result.name),
            }
        }
    }
    if results
        .iter()
        .any(|r| matches!(r.status, SuiteStatus::Denied { .. }))
    {
        4
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{median_of, percentile_of};

    #[test]
    fn median_odd_even_empty() {
        assert_eq!(median_of(&mut [3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median_of(&mut [4.0, 1.0, 3.0, 2.0]), 2.0);
        assert_eq!(median_of(&mut []), 0.0);
    }

    #[test]
    fn p99_takes_tail() {
        let mut samples: Vec<f64> = (1..=100).map(|n| n as f64).collect();
        assert_eq!(percentile_of(&mut samples, 99.0), 99.0);
        assert_eq!(percentile_of(&mut [], 99.0), 0.0);
    }
}
