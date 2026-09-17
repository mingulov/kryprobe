// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime capability facts and per-backend requirements (ARCH §4.2).
//!
//! [`RuntimeCapabilities`] records actual probe results from the
//! qualification phase. Version text is supporting context only; only the
//! probed booleans gate attachment. A plan's
//! [`CapabilityRequirements`](crate::plan::CapabilityRequirements) must be
//! satisfied before any backend attaches.

use crate::enums::BackendId;
use crate::plan::CapabilityRequirements;
use serde::{Deserialize, Serialize};

/// Probed host capabilities for one session's qualification phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    /// Kernel release text; supporting context only, never a gate.
    pub kernel_release: String,
    /// `BPF_TRACE_UPROBE_MULTI` attach works.
    pub uprobe_multi: bool,
    /// BPF cookie support works.
    pub cookies: bool,
    /// Ring-buffer transport works.
    pub ringbuf: bool,
    /// Target kernel BTF is present (informational for baseline backends).
    pub btf_present: bool,
    /// A private user namespace is available for the worker.
    pub userns: bool,
    /// Yama `ptrace_scope` value observed at qualification time.
    pub yama_scope: u32,
    /// Effective capability names held (e.g. `"CAP_BPF"`).
    pub caps: Vec<String>,
}

impl RuntimeCapabilities {
    /// True when every capability the plan requires probed present.
    #[must_use]
    pub const fn satisfies(&self, required: &CapabilityRequirements) -> bool {
        (!required.uprobe_multi || self.uprobe_multi)
            && (!required.cookies || self.cookies)
            && (!required.ringbuf || self.ringbuf)
            && (!required.btf || self.btf_present)
    }
}

/// Capability requirements attributed to one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackendRequirements {
    /// Backend these requirements gate.
    pub backend: BackendId,
    /// Capabilities that must have probed present.
    pub required: CapabilityRequirements,
}

impl BackendRequirements {
    /// True when the runtime facts satisfy this backend's requirements.
    #[must_use]
    pub const fn is_satisfied_by(&self, runtime: &RuntimeCapabilities) -> bool {
        runtime.satisfies(&self.required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> RuntimeCapabilities {
        RuntimeCapabilities {
            kernel_release: "6.12.107+deb13-cloud-amd64".to_owned(),
            uprobe_multi: true,
            cookies: true,
            ringbuf: true,
            btf_present: false,
            userns: true,
            yama_scope: 1,
            caps: vec!["CAP_BPF".to_owned()],
        }
    }

    #[test]
    fn satisfies_checks_each_required_flag() {
        let runtime = runtime();
        let none = CapabilityRequirements::default();
        assert!(runtime.satisfies(&none));
        let need_ringbuf = CapabilityRequirements {
            ringbuf: true,
            ..CapabilityRequirements::default()
        };
        assert!(runtime.satisfies(&need_ringbuf));
        let need_btf = CapabilityRequirements {
            btf: true,
            ..CapabilityRequirements::default()
        };
        assert!(!runtime.satisfies(&need_btf));
    }

    #[test]
    fn backend_requirements_attribute_and_gate() {
        let runtime = runtime();
        let req = BackendRequirements {
            backend: BackendId::P11,
            required: CapabilityRequirements {
                uprobe_multi: true,
                cookies: true,
                ..CapabilityRequirements::default()
            },
        };
        assert!(req.is_satisfied_by(&runtime));
        assert_eq!(req.backend, BackendId::P11);
    }
}
