// SPDX-License-Identifier: GPL-3.0-or-later
//! `token mint|status`: the K5 mint-once delegation surface (dispatch).
//!
//! Branch ruling (Task 1 proved init-ns token mint/consume is
//! kernel-refused): `token mint` implements the spec §3.3 `setcap`
//! fallback — a root one-shot writes a `security.capability` xattr
//! granting `cap_bpf,cap_perfmon+ep` on the kryprobe binary, and later
//! `watch`/`report`/`check` run unprivileged against the file
//! capabilities (the kernel's designed path for exactly this goal).
//! Token-FD loader paths (`--token` / `KRYPROBE_TOKEN` / default pin)
//! stay for the userns use-case; `token status` and the doctor
//! `token_delegated` probe report both mechanisms.
//!
//! Thin dispatch (1B-M8): the mechanism lives in [`crate::token`],
//! runtime facts in [`crate::runtime_facts`].

use crate::token::{
    CAP_BPF, CAP_PERFMON, DEFAULT_TOKEN_PIN, PinState, decode_capability_xattr,
    encode_capability_xattr, mint_receipt_json, os_error_text, probe_pin, utc_now_string,
};
use kryprobe_privilege::host as priv_host;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Mint target: `--bin` or the current exe (`/proc/self/exe` via
/// [`std::env::current_exe`]), always canonicalized (L-SEC-03):
/// symlinks resolve to the real binary (never the link), and
/// nonexistent paths are invalid input.
fn mint_target(bin: Option<&Path>) -> Result<PathBuf, String> {
    match bin {
        Some(path) => std::fs::canonicalize(path)
            .map_err(|err| format!("invalid --bin {}: {err}", path.display())),
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| std::fs::canonicalize(exe).ok())
            .ok_or_else(|| "cannot resolve current exe".to_owned()),
    }
}

/// Mint identity gate (L-SEC-03): granting file caps to anything but
/// the running kryprobe binary needs explicit `--force`. Pure over
/// canonical paths for unit tests; unresolvable self fails closed.
fn check_mint_identity(target: &Path, current: Option<&Path>, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    match current {
        Some(current) if current == target => Ok(()),
        _ => Err(format!(
            "refusing to grant caps to {} (not the running kryprobe binary; pass --force to override)",
            target.display()
        )),
    }
}

/// Runs `token mint`: root one-shot file-cap grant + receipt.
/// Exit 0 prints the receipt JSON to stdout (one object, nothing
/// else); hints ride stderr. Refusals: exit 4 without root, exit 2 on
/// a bad `--bin` path, a foreign-binary target without `--force`, or
/// receipt-overwrite without `--force`.
pub fn run_mint(
    bin: Option<&Path>,
    receipt: Option<&Path>,
    force: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    // Root gate FIRST (baseline precedence): every unprivileged
    // invocation refuses exit 4 naming root, before any input
    // validation. The target resolves for the message only.
    let target = mint_target(bin);
    // Root gate via the privilege boundary (1B-M7: no `libc::` here).
    if !priv_host::euid_is_root() {
        let what = match &target {
            Ok(target) => target.display().to_string(),
            Err(_) => bin
                .map(|bin| bin.display().to_string())
                .unwrap_or_else(|| String::from("current exe")),
        };
        let _ = writeln!(
            stderr,
            "token mint: needs root (euid != 0); run once as root to grant \
             cap_bpf,cap_perfmon on {what}"
        );
        return 4;
    }
    let target = match target {
        Ok(target) => target,
        Err(reason) => {
            let _ = writeln!(stderr, "token mint: {reason}");
            return 2;
        }
    };
    let current = std::env::current_exe()
        .ok()
        .and_then(|exe| std::fs::canonicalize(exe).ok());
    if let Err(reason) = check_mint_identity(&target, current.as_deref(), force) {
        let _ = writeln!(stderr, "token mint: {reason}");
        return 2;
    }
    if let Some(path) = receipt
        && !force
        && std::fs::symlink_metadata(path).is_ok()
    {
        let _ = writeln!(
            stderr,
            "token mint: receipt {} exists (pass --force to overwrite)",
            path.display()
        );
        return 2;
    }
    let granted = encode_capability_xattr(&[CAP_PERFMON, CAP_BPF]);
    if let Err(code) = write_caps(&target, &granted, stderr) {
        return code;
    }
    let text = format!(
        "{}\n",
        mint_receipt_json(
            &target.to_string_lossy(),
            &crate::runtime_facts::os_release(),
            &utc_now_string()
        )
    );
    let _ = write!(stdout, "{text}");
    if let Some(path) = receipt
        && let Err(err) = kryprobe_report::write_str_atomic(path, &text)
    {
        let _ = writeln!(
            stderr,
            "token mint: granted caps on {} but cannot write receipt {}: {err:#}",
            target.display(),
            path.display()
        );
        return 1;
    }
    let _ = writeln!(
        stderr,
        "token mint: granted cap_bpf,cap_perfmon+ep on {} (mechanism=setcap)",
        target.display()
    );
    0
}

/// Writes the `security.capability` xattr through the privilege seam
/// ([`kryprobe_privilege::filecaps`], no shell — ADR-0002 Rule B
/// forbids the raw call here). A `NUL` path or `ENOENT` (bad `--bin`)
/// is invalid input (exit 2); unsupported filesystems are
/// environmental (exit 4); the rest is internal (1).
fn write_caps(target: &Path, granted: &[u8; 20], stderr: &mut dyn Write) -> Result<(), i32> {
    // NUL attribution happens HERE (a seam-level `EINVAL` could also
    // be a kernel value rejection — unreachable with our constant
    // bytes, but the message must not claim a NUL it never saw).
    if target.as_os_str().as_bytes().contains(&0) {
        let _ = writeln!(
            stderr,
            "token mint: invalid --bin {}: NUL byte in path",
            target.display()
        );
        return Err(2);
    }
    if let Err(errno) = kryprobe_privilege::filecaps::set_capability_xattr(target, granted) {
        return Err(write_caps_exit(target, errno, stderr));
    }
    Ok(())
}

fn write_caps_exit(target: &Path, errno: i32, stderr: &mut dyn Write) -> i32 {
    // Errno classification lives behind the boundary (1B-M7); the CLI
    // only maps classified outcomes to exit codes.
    if priv_host::errno_is_missing(errno) {
        let _ = writeln!(
            stderr,
            "token mint: no such binary {} ({})",
            target.display(),
            os_error_text(errno)
        );
        return 2;
    }
    if priv_host::errno_is_refused(errno) {
        let _ = writeln!(
            stderr,
            "token mint: setxattr security.capability on {} refused ({})",
            target.display(),
            os_error_text(errno)
        );
        return 4;
    }
    let _ = writeln!(
        stderr,
        "token mint: setxattr security.capability on {} failed ({})",
        target.display(),
        os_error_text(errno)
    );
    1
}

/// Reads one `security.capability` value through the privilege seam
/// ([`kryprobe_privilege::filecaps`] — ADR-0002 Rule B forbids the raw
/// call here).
fn read_caps(target: &Path) -> Result<Vec<u8>, i32> {
    kryprobe_privilege::filecaps::get_capability_xattr(target)
}

/// The `caps:` line for one target (missing xattr reads as no caps;
/// every other failure carries its reason — never a crash).
fn caps_line(target: &Path) -> String {
    let bytes = match read_caps(target) {
        Ok(bytes) => bytes,
        Err(errno) if priv_host::errno_is_absent_xattr(errno) => {
            return String::from("caps: none not-effective");
        }
        Err(errno) => return format!("caps: unreadable ({})", os_error_text(errno)),
    };
    match decode_capability_xattr(&bytes) {
        Some((caps, effective)) => {
            let csv = if caps.is_empty() {
                String::from("none")
            } else {
                caps.iter()
                    .map(|cap| crate::runtime_facts::cap_display_name(*cap))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            format!(
                "caps: {csv} {}",
                if effective {
                    "effective"
                } else {
                    "not-effective"
                }
            )
        }
        None => format!(
            "caps: unreadable (bad security.capability: {} bytes)",
            bytes.len()
        ),
    }
}

/// Runs `token status`: file caps + default-pin usability. Never
/// requires privilege; unreadable inputs report with reasons, exit 0.
pub fn run_status(bin: Option<&Path>, stdout: &mut dyn Write) -> i32 {
    let target = match mint_target(bin) {
        Ok(target) => target,
        Err(reason) => {
            let _ = writeln!(stdout, "caps: unreadable ({reason})");
            let _ = writeln!(stdout, "pin: absent unreadable");
            return 0;
        }
    };
    let _ = writeln!(stdout, "{}", caps_line(&target));
    let pin = match probe_pin(Path::new(DEFAULT_TOKEN_PIN)) {
        PinState::Usable => "pin: present readable",
        PinState::PresentUnusable { .. } => "pin: present unreadable",
        PinState::Absent => "pin: absent unreadable",
    };
    let _ = writeln!(stdout, "{pin}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> kryprobe_testkit::TempDir {
        kryprobe_testkit::TempDir::named(&format!("k5-token-{tag}")).expect("scratch dir")
    }

    #[test]
    fn mint_target_canonicalizes_bin() {
        // L-SEC-03: --bin resolves through symlinks (never the link
        // itself); nonexistent paths are invalid input.
        let exe = std::env::current_exe().expect("current exe");
        let canonical = std::fs::canonicalize(&exe).expect("canonical exe");
        assert_eq!(mint_target(None).expect("self resolves"), canonical);
        let scratch = scratch_dir("canon");
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&exe, &link).expect("symlink");
        assert_eq!(mint_target(Some(&link)).expect("link resolves"), canonical);
        assert!(
            mint_target(Some(Path::new("/nonexistent-k5-token-zzz"))).is_err(),
            "nonexistent --bin is invalid"
        );
    }

    #[test]
    fn mint_identity_requires_force_for_foreign_binary() {
        // L-SEC-03/H-T1: granting caps to anything but the running
        // kryprobe binary needs explicit --force.
        let this = PathBuf::from("/usr/local/bin/kryprobe");
        let other = PathBuf::from("/tmp/evil-helper");
        assert!(check_mint_identity(&this, Some(&this), false).is_ok());
        let err = check_mint_identity(&other, Some(&this), false)
            .expect_err("foreign binary needs --force");
        assert!(err.contains("--force"), "names the override: {err}");
        assert!(check_mint_identity(&other, Some(&this), true).is_ok());
        assert!(
            check_mint_identity(&other, None, false).is_err(),
            "unresolvable self fails closed without --force"
        );
        assert!(check_mint_identity(&other, None, true).is_ok());
    }
}
