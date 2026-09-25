// SPDX-License-Identifier: GPL-3.0-or-later
//! Program identities for privileged probe attachment.
//!
//! T6a seeds the enum with the self-probe used by the thin spine.
//! T7 extends it with further program kinds.

use serde::{Deserialize, Serialize};

/// Identifies a privileged program attachable by kryprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProgramId {
    /// uprobe-multi self-probe used by the thin-spine spike (T6b).
    UprobeMultiSelfProbe,
    /// uprobe-multi probe for the retired p11 backend (first
    /// CONTRACTS §2 backend). Declared but NEVER allowlisted: loads
    /// always refuse (ADR-0004); the negative tests pin this.
    UprobeMultiP11Probe,
    /// fexit kcrypto programs (1B-L3): the link-group/diagnostic
    /// label for kcrypto attaches. NOT on the spine-load allowlist
    /// by design — kcrypto loads are shape-authenticated through
    /// their own entry (`bpfloader::load_kcrypto`), never through
    /// the `load_program` facet the allowlist gates.
    KCryptoFexit,
    /// fentry/fexit lifecycle programs (T06): the link-group/
    /// diagnostic label for request-lifecycle attaches. Same
    /// shape-authenticated loading as `KCryptoFexit` (own
    /// `load_lifecycle` entry, never the gated facet).
    KCryptoLifecycle,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1B-L3: the kcrypto link label exists and keeps its wire
    /// spelling (link groups and diagnostics render it).
    #[test]
    fn kcrypto_fexit_roundtrips() {
        let id = ProgramId::KCryptoFexit;
        let wire = serde_json::to_string(&id).unwrap();
        assert_eq!(wire, "\"KCryptoFexit\"");
        assert_eq!(serde_json::from_str::<ProgramId>(&wire).unwrap(), id);
    }

    /// T06: the lifecycle link label exists and keeps its wire
    /// spelling (link groups and diagnostics render it, distinct
    /// from the aggregate sensor's label).
    #[test]
    fn kcrypto_lifecycle_roundtrips() {
        let id = ProgramId::KCryptoLifecycle;
        let wire = serde_json::to_string(&id).unwrap();
        assert_eq!(wire, "\"KCryptoLifecycle\"");
        assert_eq!(serde_json::from_str::<ProgramId>(&wire).unwrap(), id);
    }
}
