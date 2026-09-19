// SPDX-License-Identifier: GPL-3.0-or-later
//! Stubs: thin-spine `plan`/`observe`/`run` plus the kp2 system-scope
//! shape for commands whose backends are not installed (always exit 4
//! — the environment cannot produce evidence, never a fake result).

use std::io::Write;

/// Runs a stub: names itself honestly and exits 4.
pub fn run(name: &str, stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(
        stderr,
        "unsupported-in-thin-spine: '{name}' is not implemented in thin spine"
    );
    4
}

/// Runs a scope-parsed stub (arguments validated, backend not
/// installed, nothing to capture) — exit 4, never a fake success or
/// violation.
pub fn run_uninstalled(cmd: &str, need: &str, stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(stderr, "unsupported: '{cmd}' needs {need} (not installed)");
    4
}

#[cfg(test)]
mod tests {
    use super::run_uninstalled;

    #[test]
    fn uninstalled_stub_names_command_and_need() {
        let mut stderr = Vec::new();
        let code = run_uninstalled("watch --system", "the kcrypto backend", &mut stderr);
        assert_eq!(code, 4);
        assert_eq!(
            String::from_utf8(stderr).expect("stub writes UTF-8"),
            "unsupported: 'watch --system' needs the kcrypto backend (not installed)\n"
        );
    }
}
