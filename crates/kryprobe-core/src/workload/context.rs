// SPDX-License-Identifier: GPL-3.0-or-later
//! Captured execution context (ADR-0008 §(g)): the observed hook-time
//! identity, never an inferred originator.

use serde::{Deserialize, Serialize};

/// Observed execution kind. `Softirq` mirrors `KCTX_SOFTIRQ`: reserved,
/// never written by BPF (no stable in-BPF detector); softirq executions
/// misattribute to proc/kthread (known K5 limitation, carried forward).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionKind {
    /// Process context (no `PF_KTHREAD` on current).
    Proc,
    /// Kernel thread (`PF_KTHREAD`).
    Kthread,
    /// Reserved: never emitted by BPF.
    Softirq,
    /// `bpf_get_current_task` failed (essentially never).
    Unknown,
}

/// The observed boundary an execution context was captured at. Owned
/// and decodable (D12): IPC buffers decode into this without static
/// input. Later milestones extend the vocabulary versioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationBoundary {
    /// Kernel crypto API return edge (M1).
    ApiReturn,
}

/// Which boundary/context properties were actually established for one
/// captured context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContextQualification {
    /// Capture happened in hook context (vs a later snapshot join).
    pub hook_context: bool,
    /// Observed boundary.
    pub boundary: ObservationBoundary,
    /// The cgroup id was read (vs `cgroup == 0` unreadable).
    pub cgroup_observed: bool,
    /// The process lifetime discriminator was read (vs `start_ns == 0`).
    pub lifetime_observed: bool,
}

impl ContextQualification {
    /// Qualification derived from one [`ContextIdentity`]: observed-ness
    /// follows the zero-means-unreadable convention, never a guess.
    #[must_use]
    pub fn for_identity(id: &ContextIdentity) -> Self {
        Self {
            hook_context: true,
            boundary: ObservationBoundary::ApiReturn,
            cgroup_observed: id.cgroup != 0,
            lifetime_observed: id.start_ns != 0,
        }
    }
}

/// Captured kernel/session context plus optional process lifetime.
///
/// Zero-means-unreadable: `cgroup == 0` or `start_ns == 0` rows form
/// explicit unknown populations and never merge with observed rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContextIdentity {
    /// `kh_of` row hash over the full `KAgg` row.
    pub kh: u64,
    /// Event-time cgroup id; 0 = unreadable.
    pub cgroup: u64,
    /// Event-time thread-group id.
    pub tgid: u32,
    /// Event-time uid (low 32).
    pub uid: u32,
    /// Task start time, boot-time ns; 0 = unreadable.
    pub start_ns: u64,
    /// Observed execution kind.
    pub execution_kind: ExecutionKind,
}

impl ContextIdentity {
    /// Capture one observed context. No validation: every field value is
    /// representable, including the unreadable zeros.
    #[must_use]
    pub fn new(
        kh: u64,
        cgroup: u64,
        tgid: u32,
        uid: u32,
        start_ns: u64,
        execution_kind: ExecutionKind,
    ) -> Self {
        Self {
            kh,
            cgroup,
            tgid,
            uid,
            start_ns,
            execution_kind,
        }
    }

    /// The accounting key: two contexts share a `KCTX` row iff all five
    /// fields agree. Migration, uid change, and TGID reuse each split.
    #[must_use]
    pub fn accounting_key(&self) -> (u64, u64, u32, u32, u64) {
        (self.kh, self.cgroup, self.tgid, self.uid, self.start_ns)
    }

    /// A container-ID-looking cgroup name is a *candidate* until checked:
    /// returns the candidate token only when it has container-ID shape
    /// (64 lowercase hex chars); otherwise `None`.
    #[must_use]
    pub fn qualified_container_candidate<'a>(&self, token: &'a str) -> Option<&'a str> {
        if token.len() == 64
            && token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            Some(token)
        } else {
            None
        }
    }

    /// Promoting a candidate without a check is forbidden: there is no
    /// evidence path from a name pattern to a kernel ownership claim.
    /// Always refuses; the resolver's checked promotion lives in Task 03.
    pub fn promote_candidate_unchecked(&self) -> Result<(), &'static str> {
        Err("container candidate promotion requires a checked join (Task 03)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_fields_mark_unobserved_without_merging() {
        let observed = ContextIdentity::new(7, 43812, 1000, 1000, 555, ExecutionKind::Proc);
        let no_cgroup = ContextIdentity::new(7, 0, 1000, 1000, 555, ExecutionKind::Proc);
        let no_lifetime = ContextIdentity::new(7, 43812, 1000, 1000, 0, ExecutionKind::Proc);
        assert_ne!(observed.accounting_key(), no_cgroup.accounting_key());
        assert_ne!(observed.accounting_key(), no_lifetime.accounting_key());
        assert_ne!(no_cgroup.accounting_key(), no_lifetime.accounting_key());
        assert!(ContextQualification::for_identity(&observed).cgroup_observed);
        assert!(!ContextQualification::for_identity(&no_cgroup).cgroup_observed);
        assert!(!ContextQualification::for_identity(&no_lifetime).lifetime_observed);
    }

    #[test]
    fn migration_uid_change_and_reuse_each_split_rows() {
        let a = ContextIdentity::new(7, 100, 1000, 1000, 555, ExecutionKind::Proc);
        let migrated = ContextIdentity::new(7, 200, 1000, 1000, 555, ExecutionKind::Proc);
        let dropped_root = ContextIdentity::new(7, 100, 1000, 0, 555, ExecutionKind::Proc);
        let reused_tgid = ContextIdentity::new(7, 100, 1000, 1000, 999, ExecutionKind::Proc);
        assert_ne!(a.accounting_key(), migrated.accounting_key());
        assert_ne!(a.accounting_key(), dropped_root.accounting_key());
        assert_ne!(a.accounting_key(), reused_tgid.accounting_key());
    }
}
