// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw capability probe matrix: 14 rows consumed by `doctor`.
//!
//! Every row degrades honestly: `Pass`, `Denied{stage, errno}`, or
//! `Skipped{reason}` — never a panic, never a faked Pass. Row order is the
//! thin-spine plan Step 4 order.

pub mod bpf_prog;
pub mod bpf_rows;
pub mod bpf_sys;
pub mod decoders;
pub mod host_rows;

pub use bpf_prog::{
    attach_cookies, prog_load_minimal, token_create_exists, uprobe_multi_link_self,
};
pub use bpf_rows::{bpf_syscall, kernel_release, map_create, ringbuf_create};
pub use decoders::{cap_names, parse_kernel_release, yama_verdict};
pub use host_rows::{
    btf_present, cap_state, file_caps_gate, uretprobe_seccomp_fork, userns_create, yama_scope,
};

/// Minimum supported kernel: Linux 6.12 (thin-spine policy).
pub const KERNEL_FLOOR: (u32, u32) = (6, 12);

/// Honest outcome of one probe row.
pub enum ProbeOutcome {
    Pass { detail: String },
    Denied { stage: String, errno: i32 },
    Skipped { reason: String },
}

impl ProbeOutcome {
    pub fn pass(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        assert!(!detail.is_empty(), "pass detail must be non-empty");
        Self::Pass { detail }
    }

    pub fn denied(stage: impl Into<String>, errno: i32) -> Self {
        let stage = stage.into();
        assert!(!stage.is_empty(), "denied stage must be non-empty");
        Self::Denied { stage, errno }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        assert!(!reason.is_empty(), "skipped reason must be non-empty");
        Self::Skipped { reason }
    }
}

/// One named row of the probe matrix.
pub struct ProbeRow {
    pub name: &'static str,
    pub outcome: ProbeOutcome,
}

/// The 14-row matrix, in canonical `doctor` order.
pub struct ProbeMatrix {
    pub rows: Vec<ProbeRow>,
}

/// Runs all 14 probes in order; safe with and without privilege.
pub fn run_probe_matrix() -> ProbeMatrix {
    let rows = [
        ("kernel_release", kernel_release()),
        ("bpf_syscall", bpf_syscall()),
        ("map_create", map_create()),
        ("prog_load_minimal", prog_load_minimal()),
        ("uprobe_multi_link_self", uprobe_multi_link_self()),
        ("attach_cookies", attach_cookies()),
        ("ringbuf_create", ringbuf_create()),
        ("btf_present", btf_present()),
        ("userns_create", userns_create()),
        ("yama_scope", yama_scope()),
        ("cap_state", cap_state()),
        ("token_create_exists", token_create_exists()),
        ("file_caps_gate", file_caps_gate()),
        ("uretprobe_seccomp_fork", uretprobe_seccomp_fork()),
    ]
    .into_iter()
    .map(|(name, outcome)| ProbeRow { name, outcome })
    .collect();
    ProbeMatrix { rows }
}
