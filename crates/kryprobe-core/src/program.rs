// SPDX-License-Identifier: GPL-3.0-or-later
//! Program identities for privileged probe attachment.
//!
//! T6a seeds the enum with the self-probe used by the thin spine.
//! T7 extends it with further program kinds.

/// Identifies a privileged program attachable by kryprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramId {
    /// uprobe-multi self-probe used by the thin-spine spike (T6b).
    UprobeMultiSelfProbe,
}
