// SPDX-License-Identifier: GPL-3.0-or-later
//! Workload identities (ADR-0008 §(g), spec F03): UID-keyed pod identity,
//! display-only names, verified outer-container association.

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
    /// Runtime lifetime metadata when available.
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

    /// The stable identity key: cluster + pod UID only. Names never
    /// participate: recreating a pod under the same name yields a new
    /// key, and counts keyed by the old UID do not transfer.
    #[must_use]
    pub fn identity_key(&self) -> String {
        match (&self.cluster, &self.pod) {
            (Some(cluster), Some(pod)) => format!("pod:{cluster}:{}", pod.uid),
            _ => "unresolved".to_string(),
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

/// Outcome of joining one hash bucket to workload identities: hashes
/// are indexes, not proof. Zero or one distinct identity keys resolve;
/// two or more distinct keys sharing a bucket are `Ambiguous` and their
/// counts stay split, never merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinQualification {
    /// No candidate in the bucket.
    None,
    /// Exactly one distinct identity key (boxed: the struct is large
    /// next to the unit/`Vec` variants).
    Unique(Box<WorkloadIdentity>),
    /// Two or more distinct identity keys share the bucket: ambiguous.
    Ambiguous(Vec<String>),
}

/// Qualify one hash-bucket join over candidate identities. Compares full
/// identity keys (never the hash alone): distinct keys with the same
/// hash yield `Ambiguous` with every competing key retained.
#[must_use]
pub fn qualify_join(candidates: &[WorkloadIdentity]) -> JoinQualification {
    let mut keys: Vec<String> = Vec::new();
    for candidate in candidates {
        let key = candidate.identity_key();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    match keys.len() {
        0 => JoinQualification::None,
        1 => JoinQualification::Unique(Box::new(
            candidates
                .iter()
                .find(|c| c.identity_key() == keys[0])
                .expect("key came from these candidates")
                .clone(),
        )),
        _ => JoinQualification::Ambiguous(keys),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_identity_has_no_key() {
        assert_eq!(WorkloadIdentity::none().identity_key(), "unresolved");
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
                assert!(keys.contains(&a.identity_key()));
                assert!(keys.contains(&b.identity_key()));
            }
            other => panic!("collision must qualify ambiguous, got {other:?}"),
        }
        assert!(matches!(qualify_join(&[a]), JoinQualification::Unique(_)));
        assert!(matches!(qualify_join(&[]), JoinQualification::None));
    }
}
