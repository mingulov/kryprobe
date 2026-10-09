// SPDX-License-Identifier: GPL-3.0-or-later
//! Workload identities (ADR-0008 §(g), spec F03, as corrected by the
//! Stage 2A contract ADR): UID-keyed pod identity, full runtime/container
//! identity, display-only names, verified outer-container association.
//!
//! Identity keys are structured values ([`IdentityKey`]), never ambiguous
//! delimiter-joined strings: components compare field-wise, so a `':'` in
//! a cluster name cannot merge two distinct identities. Every established
//! association yields its own key; an identity with no established
//! association has no keys and never promotes (see [`qualify_join`]).

use serde::{Deserialize, Serialize};

/// Optional container/pod/cluster/node/ancestor associations for one
/// captured context. Every identity key is UID-based; names are
/// display/selection metadata and never identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    /// Runtime instance + full container id + lifetime metadata.
    pub container: Option<ContainerRef>,
    /// Cluster identity + pod UID; name/namespace are display-only.
    pub pod: Option<PodRef>,
    /// Cluster identity.
    pub cluster: Option<String>,
    /// Node identity.
    pub node: Option<String>,
    /// Verified outer-container association (kind nodes).
    pub ancestor_container: Option<ContainerRef>,
}

/// A runtime container reference: instance + FULL id + lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerRef {
    /// Runtime instance identity.
    pub runtime: String,
    /// Full container id (abbreviations refuse at the selector layer).
    pub id: String,
    /// Runtime lifetime metadata when available; `None` (or empty, which
    /// normalizes to unobserved in keys) means the lifetime was not
    /// established — an explicit unknown, never a wildcard.
    #[serde(default)]
    pub lifetime: Option<String>,
}

/// A pod reference: cluster + UID identity, name display-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodRef {
    /// Cluster identity.
    pub cluster: String,
    /// Pod UID: the identity.
    pub uid: String,
    /// Pod name: display/selection metadata only.
    pub name: String,
    /// Kubernetes namespace: display/selection metadata only.
    pub namespace: String,
}

/// One structured identity key: a single established association in
/// directly comparable form. Field-wise equality only — there is no
/// string serialization of a key that participates in identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentityKey {
    /// Runtime instance + full container id + observed lifetime (or
    /// explicit unknown lifetime). Distinct runtimes, ids, or known
    /// lifetimes each split; two unknown lifetimes merge only when no
    /// evidence distinguishes them, and the association status stays
    /// below verified.
    Container {
        /// Runtime instance identity.
        runtime: String,
        /// Full container id.
        id: String,
        /// Observed lifetime, or `None` when unobserved.
        lifetime: Option<String>,
    },
    /// Cluster identity + pod UID. Name/namespace never participate:
    /// recreating a pod under the same name yields a new key, and counts
    /// keyed by the old UID do not transfer.
    Pod {
        /// Cluster identity.
        cluster: String,
        /// Pod UID.
        uid: String,
    },
    /// Node identity.
    Node {
        /// Node identity string.
        node: String,
    },
    /// Verified outer-container association (kind nodes): kept distinct
    /// from the workload's own container so an ancestor never merges
    /// with (or replaces) the application identity.
    AncestorContainer {
        /// Runtime instance identity.
        runtime: String,
        /// Full container id.
        id: String,
        /// Observed lifetime, or `None` when unobserved.
        lifetime: Option<String>,
    },
}

impl WorkloadIdentity {
    /// Empty identity: captured context with no associations yet.
    #[must_use]
    pub fn none() -> Self {
        Self {
            container: None,
            pod: None,
            cluster: None,
            node: None,
            ancestor_container: None,
        }
    }

    /// Container association: runtime instance + full id + lifetime.
    /// A `None` (or empty) lifetime records an explicitly unobserved
    /// lifetime.
    #[must_use]
    pub fn container(runtime: &str, id: &str, lifetime: Option<&str>) -> Self {
        Self {
            container: Some(ContainerRef {
                runtime: runtime.to_string(),
                id: id.to_string(),
                lifetime: lifetime.map(str::to_string),
            }),
            pod: None,
            cluster: None,
            node: None,
            ancestor_container: None,
        }
    }

    /// Pod association: cluster + name + namespace + UID.
    #[must_use]
    pub fn pod(cluster: &str, name: &str, namespace: &str, uid: &str) -> Self {
        Self {
            container: None,
            pod: Some(PodRef {
                cluster: cluster.to_string(),
                uid: uid.to_string(),
                name: name.to_string(),
                namespace: namespace.to_string(),
            }),
            cluster: Some(cluster.to_string()),
            node: None,
            ancestor_container: None,
        }
    }

    /// Every established identity key, in deterministic order (container,
    /// pod, node, ancestor). Associations with empty identity components
    /// establish nothing: they yield no key rather than a wildcard key.
    /// An empty result means unresolved (see [`Self::is_resolved`]).
    #[must_use]
    pub fn identity_keys(&self) -> Vec<IdentityKey> {
        let mut keys = Vec::new();
        if let Some(c) = &self.container
            && !c.runtime.is_empty()
            && !c.id.is_empty()
        {
            keys.push(IdentityKey::Container {
                runtime: c.runtime.clone(),
                id: c.id.clone(),
                lifetime: normalize_lifetime(&c.lifetime),
            });
        }
        if let Some(p) = &self.pod
            && !p.cluster.is_empty()
            && !p.uid.is_empty()
        {
            keys.push(IdentityKey::Pod {
                cluster: p.cluster.clone(),
                uid: p.uid.clone(),
            });
        }
        if let Some(node) = &self.node
            && !node.is_empty()
        {
            keys.push(IdentityKey::Node { node: node.clone() });
        }
        if let Some(c) = &self.ancestor_container
            && !c.runtime.is_empty()
            && !c.id.is_empty()
        {
            keys.push(IdentityKey::AncestorContainer {
                runtime: c.runtime.clone(),
                id: c.id.clone(),
                lifetime: normalize_lifetime(&c.lifetime),
            });
        }
        keys
    }

    /// Whether at least one association is established. Unresolved
    /// identities carry captured context only and must stay in their
    /// context rows — they never promote to [`JoinQualification::Unique`].
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !self.identity_keys().is_empty()
    }

    /// String-budget check: every identity component fits the bounded
    /// string field. Used by snapshot wire validation.
    #[must_use]
    pub fn check_bounds(&self, max_bytes: usize) -> bool {
        let fields = [
            self.container
                .as_ref()
                .map(|c| c.runtime.as_str())
                .unwrap_or(""),
            self.container.as_ref().map(|c| c.id.as_str()).unwrap_or(""),
            self.container
                .as_ref()
                .and_then(|c| c.lifetime.as_deref())
                .unwrap_or(""),
            self.pod.as_ref().map(|p| p.cluster.as_str()).unwrap_or(""),
            self.pod.as_ref().map(|p| p.uid.as_str()).unwrap_or(""),
            self.pod.as_ref().map(|p| p.name.as_str()).unwrap_or(""),
            self.pod
                .as_ref()
                .map(|p| p.namespace.as_str())
                .unwrap_or(""),
            self.cluster.as_deref().unwrap_or(""),
            self.node.as_deref().unwrap_or(""),
            self.ancestor_container
                .as_ref()
                .map(|c| c.runtime.as_str())
                .unwrap_or(""),
            self.ancestor_container
                .as_ref()
                .map(|c| c.id.as_str())
                .unwrap_or(""),
            self.ancestor_container
                .as_ref()
                .and_then(|c| c.lifetime.as_deref())
                .unwrap_or(""),
        ];
        fields.iter().all(|f| f.len() <= max_bytes)
    }

    /// Consistency of the two cluster sources: when both the top-level
    /// cluster and the pod's cluster are present they must agree —
    /// contradictory cluster sources refuse (D02). The pod identity key
    /// always uses the pod's own cluster.
    #[must_use]
    pub fn check_consistency(&self) -> bool {
        match (&self.cluster, &self.pod) {
            (Some(top), Some(pod)) => top == &pod.cluster,
            _ => true,
        }
    }

    /// Selection-name equality (name + namespace): used to detect the
    /// name-reuse case that MUST still split by UID.
    #[must_use]
    pub fn same_selection_name(&self, other: &Self) -> bool {
        match (&self.pod, &other.pod) {
            (Some(a), Some(b)) => a.name == b.name && a.namespace == b.namespace,
            (None, None) => true,
            _ => false,
        }
    }
}

/// Empty lifetime strings normalize to unobserved (`None`): only a
/// non-empty observed lifetime participates in the key.
fn normalize_lifetime(lifetime: &Option<String>) -> Option<String> {
    match lifetime {
        Some(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Outcome of joining one hash bucket to workload identities: hashes
/// are indexes, not proof. Zero or one distinct identity keys resolve;
/// two or more distinct keys sharing a bucket are `Ambiguous` and their
/// counts stay split, never merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinQualification {
    /// No candidate in the bucket.
    None,
    /// Candidates exist but none resolves to an identity key. The
    /// candidates stay in their captured-context rows; this outcome
    /// never promotes to `Unique`.
    Unresolved,
    /// Exactly one distinct identity key (boxed: the struct is large
    /// next to the unit/`Vec` variants).
    Unique(Box<WorkloadIdentity>),
    /// Two or more distinct identity keys share the bucket: ambiguous.
    /// Keys are sorted for deterministic rendering.
    Ambiguous(Vec<IdentityKey>),
}

/// Qualify one hash-bucket join over candidate identities. Compares full
/// structured identity keys (never the hash alone, never a joined
/// string): distinct keys with the same hash yield `Ambiguous` with every
/// competing key retained. Candidates without keys do not resolve and
/// can never yield `Unique` on their own; callers keep them in their
/// captured-context (unknown-workload) rows rather than merging them
/// into a resolved row.
#[must_use]
pub fn qualify_join(candidates: &[WorkloadIdentity]) -> JoinQualification {
    if candidates.is_empty() {
        return JoinQualification::None;
    }
    let mut keys: Vec<IdentityKey> = Vec::new();
    for candidate in candidates {
        for key in candidate.identity_keys() {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    match keys.len() {
        0 => JoinQualification::Unresolved,
        1 => JoinQualification::Unique(Box::new(
            candidates
                .iter()
                .find(|c| c.identity_keys().contains(&keys[0]))
                .expect("key came from these candidates")
                .clone(),
        )),
        _ => {
            keys.sort();
            JoinQualification::Ambiguous(keys)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_identity_has_no_keys() {
        assert!(WorkloadIdentity::none().identity_keys().is_empty());
        assert!(!WorkloadIdentity::none().is_resolved());
    }

    #[test]
    fn empty_components_establish_no_key() {
        let empty_container = WorkloadIdentity::container("", "", None);
        assert!(empty_container.identity_keys().is_empty());
        let empty_pod = WorkloadIdentity::pod("", "api", "production", "");
        assert!(empty_pod.identity_keys().is_empty());
    }

    #[test]
    fn contradictory_cluster_sources_are_inconsistent() {
        let mut conflicted = WorkloadIdentity::pod("cluster-a", "api", "production", "uid-1");
        conflicted.cluster = Some("cluster-b".to_string());
        assert!(!conflicted.check_consistency());
        let agreed = WorkloadIdentity::pod("cluster-a", "api", "production", "uid-1");
        assert!(agreed.check_consistency());
        assert!(WorkloadIdentity::none().check_consistency());
    }

    #[test]
    fn empty_lifetime_normalizes_to_unobserved() {
        let empty = WorkloadIdentity::container("rt", "id", Some(""));
        let missing = WorkloadIdentity::container("rt", "id", None);
        assert_eq!(empty.identity_keys(), missing.identity_keys());
    }

    #[test]
    fn synthetic_hash_collision_stays_ambiguous_and_split() {
        // Two distinct pods (distinct UIDs) landing in one hash bucket:
        // the join qualifies ambiguous and retains BOTH keys. Counts
        // keyed by either UID never merge into one row.
        let a = WorkloadIdentity::pod("cluster-a", "api-7c9d", "production", "uid-1111");
        let b = WorkloadIdentity::pod("cluster-a", "api-7c9d", "production", "uid-2222");
        match qualify_join(&[a.clone(), b.clone()]) {
            JoinQualification::Ambiguous(keys) => {
                assert_eq!(keys.len(), 2);
                assert!(keys.contains(&a.identity_keys()[0]));
                assert!(keys.contains(&b.identity_keys()[0]));
            }
            other => panic!("collision must qualify ambiguous, got {other:?}"),
        }
        assert!(matches!(qualify_join(&[a]), JoinQualification::Unique(_)));
        assert!(matches!(qualify_join(&[]), JoinQualification::None));
        assert!(matches!(
            qualify_join(&[WorkloadIdentity::none()]),
            JoinQualification::Unresolved
        ));
    }
}
