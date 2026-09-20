// SPDX-License-Identifier: GPL-3.0-or-later
//! `doctor`: the 19-row probe matrix plus backend rows plus the kcrypto
//! coverage profile + ready/degraded verdict.
//!
//! The 5 K2.3/K5/review rows extend [`run_probe_matrix`]'s 14 in fixed order
//! (appended after, never reordered) as a library consumer: symbols via
//! [`resolve_btf_ids`], attach via a real [`load_kcrypto_configured`]
//! load+attach+RAII drop, lockdown via a file parse, `token_delegated`
//! via the default-pin probe + CapEff. Lockdown and `token_delegated`
//! are informational and never block the verdict.

use crate::cmd_backends::{backend_rows, human_row};
use crate::cmd_token::{DEFAULT_TOKEN_PIN, PinState, probe_pin};
use kryprobe_privilege::bpfloader::{LoaderError, PointStatus};
use kryprobe_privilege::btf_resolve::{
    AttachOutcome, ConfiguredError, ConfiguredPoint, KCRYPTO_SYMBOLS, load_kcrypto_configured,
    resolve_btf_ids,
};
use kryprobe_privilege::mapops::MapOpsError;
use kryprobe_privilege::probe::{ProbeOutcome, ProbeRow};
use kryprobe_privilege::run_probe_matrix;
use std::io::Write;

/// Coverage profile string (brief-exact).
pub const COVERAGE_PROFILE: &str = "kernel-crypto-v1";

fn human_outcome(outcome: &ProbeOutcome) -> String {
    match outcome {
        ProbeOutcome::Pass { detail } => format!("pass: {detail}"),
        ProbeOutcome::Denied { stage, errno } => format!("denied: {stage} (errno {errno})"),
        ProbeOutcome::Skipped { reason } => format!("skipped: {reason}"),
    }
}

fn json_outcome(outcome: &ProbeOutcome) -> serde_json::Value {
    match outcome {
        ProbeOutcome::Pass { detail } => serde_json::json!({"outcome": "pass", "detail": detail}),
        ProbeOutcome::Denied { stage, errno } => {
            serde_json::json!({"outcome": "denied", "stage": stage, "errno": errno})
        }
        ProbeOutcome::Skipped { reason } => {
            serde_json::json!({"outcome": "skipped", "reason": reason})
        }
    }
}

/// The 9 kcrypto symbols resolve (unprivileged) or the BTF read fails;
/// `Denied` never (resolution needs no privilege).
fn kcrypto_symbols_row() -> ProbeRow {
    let outcome = match resolve_btf_ids() {
        Ok(ids) => ProbeOutcome::pass(format!("{}/{}", ids.len(), KCRYPTO_SYMBOLS.len())),
        Err(err) => ProbeOutcome::skipped(format!("bpf_btf_unreadable: {err}")),
    };
    ProbeRow {
        name: "kcrypto_symbols",
        outcome,
    }
}

/// Effective caps from CapEff (the shared `cmd_token` reader — one
/// CapEff parse for the crate; fail-closed as before).
fn effective_caps() -> Vec<String> {
    crate::cmd_token::effective_cap_names()
}

/// Attach privilege: tracing links need CAP_BPF (or CAP_SYS_ADMIN).
fn is_privileged(caps: &[String]) -> bool {
    crate::cmd_token::caps_allow_bpf_bringup(caps)
}

/// K5 delegation probe over its inputs (pin state + effective caps):
/// `pass` when a usable token pin exists OR the process holds
/// effective `CAP_BPF` (the ruling's literal condition — file caps
/// granted by `token mint` always include it); `denied` when a pin
/// exists but retrieves corrupt (reason carried); `skipped` when
/// neither mechanism is present. Never feeds the coverage verdict.
#[must_use]
pub fn token_delegated_outcome(pin: &PinState, caps: &[String]) -> ProbeOutcome {
    if matches!(pin, PinState::Usable) {
        return ProbeOutcome::pass(format!("token pin {DEFAULT_TOKEN_PIN} usable"));
    }
    if crate::cmd_token::caps_have_bpf(caps) {
        return ProbeOutcome::pass("effective CAP_BPF (setcap grant or privilege)".to_owned());
    }
    match pin {
        PinState::PresentUnusable(reason) => ProbeOutcome::denied(
            format!("token pin {DEFAULT_TOKEN_PIN} unusable: {reason}"),
            libc::EIO,
        ),
        PinState::Usable | PinState::Absent => ProbeOutcome::skipped(format!(
            "no token pin at {DEFAULT_TOKEN_PIN}; no effective CAP_BPF"
        )),
    }
}

/// `token_delegated` row over one pin path (the hermetic seam: tests
/// feed fixture paths; production passes the default pin).
fn token_delegated_row_at(pin_path: &std::path::Path, caps: &[String]) -> ProbeRow {
    ProbeRow {
        name: "token_delegated",
        outcome: token_delegated_outcome(&probe_pin(pin_path), caps),
    }
}

/// Resolved kcrypto object row (4B-H6.3): the effective artifact
/// path is inspectable, so a poisoned env/CWD shows up in `doctor`
/// output. Informational, never blocks the verdict.
fn kcrypto_object_row() -> ProbeRow {
    let outcome = match kryprobe_privilege::locate_kcrypto_object_bytes() {
        Ok((path, _)) => ProbeOutcome::pass(path.display().to_string()),
        Err(err) => ProbeOutcome::skipped(err.to_string()),
    };
    ProbeRow {
        name: "kcrypto_object",
        outcome,
    }
}

/// First readable candidate via the consolidated privilege locator
/// (single read — bytes return with the path, never a re-open);
/// `Err` is the exact skip reason it reports.
fn kcrypto_object_bytes() -> Result<Vec<u8>, String> {
    let (_path, bytes) =
        kryprobe_privilege::locate_kcrypto_object_bytes().map_err(|err| err.to_string())?;
    Ok(bytes)
}

/// One configured point as `name=word` (Task-2 `point_word` vocabulary).
fn point_word(point: &ConfiguredPoint) -> String {
    let load = match &point.load {
        PointStatus::Loaded { .. } => match &point.attach {
            Some(AttachOutcome::Attached) => "loaded+attached".to_owned(),
            Some(AttachOutcome::Failed { detail }) => format!("loaded+attach-failed:{detail}"),
            None => "loaded+unattached".to_owned(),
        },
        PointStatus::Missing { .. } => "missing".to_owned(),
        PointStatus::Unsupported { detail, .. } => format!("unsupported:{detail}"),
    };
    format!("{}={load}", point.name)
}

/// Per-point detail rides the denied stage (`Denied` carries no detail
/// field); the stage always starts with `attach` per the brief.
fn attach_stage(points: &[ConfiguredPoint], attached: usize) -> String {
    let words = points.iter().map(point_word).collect::<Vec<_>>().join(", ");
    format!("attach {attached}/{}: {words}", KCRYPTO_SYMBOLS.len())
}

/// Kernel errno when the bring-up error carries one, else EIO (generic
/// I/O failure — the `bpf_sys::last_errno` fallback precedent).
fn configured_errno(err: &ConfiguredError) -> i32 {
    match err {
        ConfiguredError::Load(LoaderError::MapFailed { errno, .. })
        | ConfiguredError::Load(LoaderError::LoadFailed { errno, .. }) => *errno,
        ConfiguredError::Configure(MapOpsError::LookupFailed { errno, .. })
        | ConfiguredError::Configure(MapOpsError::UpdateFailed { errno, .. }) => *errno,
        _ => libc::EIO,
    }
}

fn attach_denied(err: &ConfiguredError) -> ProbeOutcome {
    match err {
        ConfiguredError::NoPointAttached { points } => {
            let attached = points
                .iter()
                .filter(|point| matches!(point.attach, Some(AttachOutcome::Attached)))
                .count();
            ProbeOutcome::denied(attach_stage(points, attached), libc::EIO)
        }
        other => ProbeOutcome::denied(format!("attach: {other}"), configured_errno(other)),
    }
}

/// Attach probe outcome plus the verdict inputs it determines.
struct AttachProbe {
    row: ProbeRow,
    object_ok: bool,
    proven: bool,
}

/// Real load + attach + RAII drop when privileged; skips otherwise.
/// Privilege is checked FIRST so unprivileged renders the caps skip
/// deterministically (never the object skip) with or without a built
/// object; the object check runs only when attach is possible.
fn kcrypto_attach_probe(caps: &[String]) -> AttachProbe {
    if !is_privileged(caps) {
        let have = if caps.is_empty() {
            String::from("none")
        } else {
            caps.join(",")
        };
        return AttachProbe {
            row: ProbeRow {
                name: "kcrypto_attach",
                outcome: ProbeOutcome::skipped(format!("needs CAP_BPF (have: {have})")),
            },
            object_ok: false,
            proven: false,
        };
    }
    let bytes = match kcrypto_object_bytes() {
        Ok(bytes) => bytes,
        Err(reason) => {
            return AttachProbe {
                row: ProbeRow {
                    name: "kcrypto_attach",
                    outcome: ProbeOutcome::skipped(reason),
                },
                object_ok: false,
                proven: false,
            };
        }
    };
    let outcome = match load_kcrypto_configured(&bytes, None) {
        Ok((sensor, points)) => {
            let attached = points
                .iter()
                .filter(|point| matches!(point.attach, Some(AttachOutcome::Attached)))
                .count();
            drop(sensor);
            if attached == KCRYPTO_SYMBOLS.len() {
                ProbeOutcome::pass(format!("{attached}/{} attached", KCRYPTO_SYMBOLS.len()))
            } else {
                ProbeOutcome::denied(attach_stage(&points, attached), libc::EIO)
            }
        }
        Err(err) => attach_denied(&err),
    };
    let proven = matches!(outcome, ProbeOutcome::Pass { .. });
    AttachProbe {
        row: ProbeRow {
            name: "kcrypto_attach",
            outcome,
        },
        object_ok: true,
        proven,
    }
}

/// First bracketed mode in the lockdown file (`[none] integrity ...`).
fn parse_lockdown_mode(text: &str) -> Option<&str> {
    let start = text.find('[')? + 1;
    let end = text[start..].find(']')?;
    Some(text[start..start + end].trim())
}

/// Lockdown mode, informational only (never blocks the verdict).
fn lockdown_row() -> ProbeRow {
    let outcome = match std::fs::read_to_string("/sys/kernel/security/lockdown") {
        Err(err) => ProbeOutcome::skipped(format!("lockdown file unreadable: {err}")),
        Ok(text) => match parse_lockdown_mode(&text) {
            Some(mode) => ProbeOutcome::pass(mode.to_owned()),
            None => ProbeOutcome::skipped(format!("lockdown mode unparseable: {}", text.trim())),
        },
    };
    ProbeRow {
        name: "lockdown",
        outcome,
    }
}

/// Ready rule (D11): symbols 9/9 ∧ btf ∧ (CAP_BPF ∨ CAP_SYS_ADMIN) ∧
/// (priv → attach proven). Lockdown never blocks. Missing pieces in
/// brief order: symbols, caps, btf, attach, object.
fn coverage_verdict(
    symbols_ok: bool,
    btf_ok: bool,
    privileged: bool,
    object_ok: bool,
    attach_proven: bool,
) -> (&'static str, Vec<&'static str>) {
    let mut missing = Vec::new();
    if !symbols_ok {
        missing.push("symbols");
    }
    if !privileged {
        missing.push("caps");
    }
    if !btf_ok {
        missing.push("btf");
    }
    if privileged && object_ok && !attach_proven {
        missing.push("attach");
    }
    if privileged && !object_ok {
        missing.push("object");
    }
    let status = if missing.is_empty() {
        "ready"
    } else {
        "degraded"
    };
    (status, missing)
}

/// Runs `doctor`; always exit 0 (degraded rows are data, not failure).
pub fn run(json: bool, stdout: &mut dyn Write) -> i32 {
    let mut matrix = run_probe_matrix();
    let caps = effective_caps();
    let privileged = is_privileged(&caps);
    let symbols_row = kcrypto_symbols_row();
    let symbols_ok = matches!(symbols_row.outcome, ProbeOutcome::Pass { .. });
    let attach = kcrypto_attach_probe(&caps);
    let lockdown = lockdown_row();
    let btf_ok = matrix
        .rows
        .iter()
        .find(|row| row.name == "btf_present")
        .is_some_and(|row| matches!(row.outcome, ProbeOutcome::Pass { .. }));
    matrix.rows.push(symbols_row);
    matrix.rows.push(kcrypto_object_row());
    matrix.rows.push(attach.row);
    matrix.rows.push(lockdown);
    matrix.rows.push(token_delegated_row_at(
        std::path::Path::new(DEFAULT_TOKEN_PIN),
        &caps,
    ));
    let (status, missing) = coverage_verdict(
        symbols_ok,
        btf_ok,
        privileged,
        attach.object_ok,
        attach.proven,
    );
    if json {
        let probes: Vec<serde_json::Value> = matrix
            .rows
            .iter()
            .map(|row| {
                let mut value = json_outcome(&row.outcome);
                value["name"] = serde_json::Value::String(row.name.to_owned());
                value
            })
            .collect();
        let backends: Vec<serde_json::Value> = backend_rows()
            .iter()
            .map(|row| serde_json::json!({"id": row.id, "state": row.state, "note": row.note}))
            .collect();
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::json!({
                "probes": probes,
                "backends": backends,
                "coverage_profile": COVERAGE_PROFILE,
                "verdict": {"status": status, "missing": missing},
            })
        );
        return 0;
    }
    for row in &matrix.rows {
        let _ = writeln!(
            stdout,
            "probe {}: {}",
            row.name,
            human_outcome(&row.outcome)
        );
    }
    for row in &backend_rows() {
        let _ = writeln!(stdout, "backend {}", human_row(row));
    }
    let _ = writeln!(stdout, "coverage-profile: {COVERAGE_PROFILE}");
    if status == "ready" {
        let _ = writeln!(stdout, "verdict: ready");
    } else {
        let _ = writeln!(stdout, "verdict: degraded: {}", missing.join(","));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn verdict_truth_table_pins_ready_and_missing_set() {
        // (symbols, btf, priv, object, attach) → (status, missing).
        let cases = [
            ((true, true, true, true, true), ("ready", vec![])),
            // Unprivileged on a healthy host: caps only (attach/object
            // are priv-gated, never listed unpriv).
            (
                (true, true, false, false, false),
                ("degraded", vec!["caps"]),
            ),
            ((true, true, false, true, true), ("degraded", vec!["caps"])),
            // Each dimension alone.
            (
                (false, true, true, true, true),
                ("degraded", vec!["symbols"]),
            ),
            ((true, false, true, true, true), ("degraded", vec!["btf"])),
            (
                (true, true, true, true, false),
                ("degraded", vec!["attach"]),
            ),
            (
                (true, true, true, false, false),
                ("degraded", vec!["object"]),
            ),
            // Multi-missing keeps brief order: symbols, caps, btf, attach, object.
            (
                (false, false, false, false, false),
                ("degraded", vec!["symbols", "caps", "btf"]),
            ),
            (
                (false, false, true, false, false),
                ("degraded", vec!["symbols", "btf", "object"]),
            ),
            (
                (false, true, true, true, false),
                ("degraded", vec!["symbols", "attach"]),
            ),
            // Lockdown never blocks: no input for it (compile-time arity).
        ];
        for ((symbols, btf, priv_, object, attach), (status, missing)) in cases {
            assert_eq!(
                coverage_verdict(symbols, btf, priv_, object, attach),
                (status, missing),
                "symbols={symbols} btf={btf} priv={priv_} object={object} attach={attach}"
            );
        }
    }

    #[test]
    fn privilege_needs_bpf_or_admin() {
        let caps = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        assert!(is_privileged(&caps(&["CAP_BPF"])));
        assert!(is_privileged(&caps(&["CAP_SYS_ADMIN"])));
        assert!(is_privileged(&caps(&["CAP_BPF", "CAP_SYS_ADMIN"])));
        assert!(!is_privileged(&caps(&[])));
        assert!(!is_privileged(&caps(&["CAP_NET_RAW", "CAP_CHOWN"])));
    }

    #[test]
    fn locator_tier_order_env_exe_dev() {
        use kryprobe_privilege::kcrypto_backend::kcrypto_object_candidates;
        let dev = PathBuf::from("target/kryprobe-bpf/kcrypto.bpf.o");
        let exe = PathBuf::from("/exe/dir");
        let bundled = PathBuf::from("/exe/dir/kryprobe-bpf/kcrypto.bpf.o");
        // Unset env: exe-bundled first, dev last.
        assert_eq!(
            kcrypto_object_candidates(None, Some(exe.as_path()), false),
            [bundled.clone(), dev.clone()]
        );
        // Missing dir: dir-joined candidate first, then exe, then dev.
        let dir = std::env::temp_dir().join("kryprobe-doctor-locator-absent");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            kcrypto_object_candidates(
                Some(dir.to_str().expect("utf-8 tmp")),
                Some(exe.as_path()),
                false
            ),
            [dir.join("kcrypto.bpf.o"), bundled.clone(), dev.clone()]
        );
        // A real file is tried as-is (not dir-joined).
        let file = std::env::temp_dir().join("kryprobe-doctor-locator-file.o");
        std::fs::write(&file, b"object").expect("write tmp file");
        assert_eq!(
            kcrypto_object_candidates(
                Some(file.to_str().expect("utf-8 tmp")),
                Some(exe.as_path()),
                false
            ),
            [file.clone(), bundled.clone(), dev.clone()]
        );
        std::fs::remove_file(&file).ok();
        // Unknown exe dir: tier 2 skipped, never fabricated.
        assert_eq!(kcrypto_object_candidates(None, None, false), [dev]);
    }

    #[test]
    fn lockdown_parse_pins_bracketed_mode() {
        assert_eq!(
            parse_lockdown_mode("[none] integrity confidentiality"),
            Some("none")
        );
        assert_eq!(
            parse_lockdown_mode("[integrity] none confidentiality"),
            Some("integrity")
        );
        assert_eq!(parse_lockdown_mode("none"), None);
        assert_eq!(parse_lockdown_mode(""), None);
        assert_eq!(parse_lockdown_mode("[unclosed"), None);
    }

    #[test]
    fn unpriv_attach_probe_skips_on_caps_with_exact_csv() {
        // Pure over caps: no privilege, no object read.
        let probe = kcrypto_attach_probe(&["CAP_CHOWN".to_owned(), "CAP_NET_RAW".to_owned()]);
        assert_eq!(probe.row.name, "kcrypto_attach");
        assert!(!probe.object_ok);
        assert!(!probe.proven);
        match &probe.row.outcome {
            ProbeOutcome::Skipped { reason } => {
                assert_eq!(reason, "needs CAP_BPF (have: CAP_CHOWN,CAP_NET_RAW)");
            }
            other => panic!("expected caps skip, got {}", human_outcome(other)),
        }
        let empty = kcrypto_attach_probe(&[]);
        match &empty.row.outcome {
            ProbeOutcome::Skipped { reason } => {
                assert_eq!(reason, "needs CAP_BPF (have: none)");
            }
            other => panic!("expected empty-caps skip, got {}", human_outcome(other)),
        }
    }

    #[test]
    fn token_delegated_row_probes_fixture_pin() {
        // Hermetic over fixture paths (no default-pin touch): a missing
        // path skips, a regular file denies (never a BPF object — the
        // kernel refuses retrieval on every host, with or without bpf()).
        let dir = std::env::temp_dir().join(format!("kryprobe-k5-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let missing = dir.join("absent");
        let row = token_delegated_row_at(&missing, &[]);
        assert_eq!(row.name, "token_delegated");
        assert!(
            matches!(row.outcome, ProbeOutcome::Skipped { .. }),
            "absent pin skips: {}",
            human_outcome(&row.outcome)
        );
        let file = dir.join("regular");
        std::fs::write(&file, b"not a token").expect("write fixture");
        let row = token_delegated_row_at(&file, &[]);
        assert!(
            matches!(row.outcome, ProbeOutcome::Denied { .. }),
            "regular file denies: {}",
            human_outcome(&row.outcome)
        );
        // Caps rescue either shape (the pass arm is pin-independent).
        let caps = vec!["CAP_BPF".to_owned()];
        for path in [&missing, &file] {
            let row = token_delegated_row_at(path, &caps);
            assert!(
                matches!(row.outcome, ProbeOutcome::Pass { .. }),
                "caps pass over {}: {}",
                path.display(),
                human_outcome(&row.outcome)
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
