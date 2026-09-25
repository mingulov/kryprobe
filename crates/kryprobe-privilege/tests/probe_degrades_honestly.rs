// SPDX-License-Identifier: GPL-3.0-or-later
//! Live probe-matrix test: honest degrade with and without privilege.

use kryprobe_privilege::{ProbeOutcome, run_probe_matrix};

const EXPECTED: [&str; 15] = [
    "kernel_release",
    "bpf_syscall",
    "map_create",
    "prog_load_minimal",
    "uprobe_multi_link_self",
    "attach_cookies",
    "ringbuf_create",
    "btf_present",
    "fsession_capable",
    "userns_create",
    "yama_scope",
    "cap_state",
    "token_create_exists",
    "file_caps_gate",
    "uretprobe_seccomp_fork",
];

#[test]
fn probe_degrades_honestly() {
    let matrix = run_probe_matrix();
    assert_eq!(matrix.rows.len(), 15, "matrix must have exactly 15 rows");
    for (row, want) in matrix.rows.iter().zip(EXPECTED) {
        assert_eq!(row.name, want, "row order drifted");
        match &row.outcome {
            ProbeOutcome::Pass { detail } => assert!(!detail.is_empty(), "{want}: empty detail"),
            ProbeOutcome::Denied { stage, .. } => assert!(!stage.is_empty(), "{want}: empty stage"),
            ProbeOutcome::Skipped { reason } => assert!(!reason.is_empty(), "{want}: empty reason"),
            ProbeOutcome::Failed { detail } => assert!(!detail.is_empty(), "{want}: empty detail"),
        }
    }
    let release = &matrix.rows[0];
    assert!(
        matches!(release.outcome, ProbeOutcome::Pass { .. }),
        "kernel_release must Pass on this host (7.0 >= 6.12)"
    );
}
