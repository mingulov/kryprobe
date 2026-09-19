// SPDX-License-Identifier: GPL-3.0-or-later
//! Stubs: thin-spine `plan`/`observe`/`run` plus the kp2 system-scope
//! commands whose backends are not installed yet (always exit 3).

use std::io::Write;

/// Runs a stub: names itself honestly and exits 3.
pub fn run(name: &str, stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(
        stderr,
        "unsupported-in-thin-spine: '{name}' is not implemented in thin spine"
    );
    3
}

/// Runs a scope-parsed stub (`watch`/`report`/`check --system`): the
/// arguments validated, but the backend is not installed, so there is
/// nothing to capture — exit 3, never a fake success or violation.
pub fn run_uninstalled(cmd: &str, need: &str, stderr: &mut dyn Write) -> i32 {
    let _ = writeln!(stderr, "unsupported: '{cmd}' needs {need} (not installed)");
    3
}

#[cfg(test)]
mod tests {
    use super::run_uninstalled;

    #[test]
    fn uninstalled_stub_names_command_and_need() {
        let mut stderr = Vec::new();
        let code = run_uninstalled("watch --system", "the kcrypto backend", &mut stderr);
        assert_eq!(code, 3);
        assert_eq!(
            String::from_utf8(stderr).expect("stub writes UTF-8"),
            "unsupported: 'watch --system' needs the kcrypto backend (not installed)\n"
        );
    }
}
