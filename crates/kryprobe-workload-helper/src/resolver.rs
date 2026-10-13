// SPDX-License-Identifier: GPL-3.0-or-later
//! Conservative join orchestration (spec §5.2/§5.4, frozen contract
//! ADR-0012): the frozen pure [`resolve()`] first, then verified-liveness
//! upgrades from the unprivileged host view.
//!
//! Rules:
//!
//! - The frozen pure entry point answers every key first (asserted/stale/
//!   ambiguous/unresolved associations, kernel-mismatch/unknown-kernel
//!   refusals). The helper never reimplements that logic.
//! - Only `Unresolved` associations are promotion candidates, and only to
//!   `Verified(cgroup_inode_bind)` — but R3 ingress coherence (ADR-0012
//!   (c6)) requires an established identity for `Verified`, and liveness
//!   observation (dev/ino) establishes no workload identity, so
//!   identity-less candidates stay `Unresolved`: liveness is remembered
//!   (bounding re-scans) but never promoted, and workload identity is
//!   never invented. Stale stays stale, asserted stays asserted,
//!   refusals stand.
//! - Upgrades require the key's kernel scope to equal the live host scope
//!   (no cross-boot verification) plus a confined pid-hint check and a
//!   single batched inode scan for the request's whole uncached set.
//! - Cache (positive/negative/tombstone), refresh, and deadline budgets
//!   gate host work; saturation and failures surface in
//!   [`HelperCounters`], never silently. A tripped deadline converts
//!   still-pending unresolved associations to `Unsupported` (partial
//!   response); already-established results stand. The deadline is
//!   checked during the pid phase, before/during the scan (via the
//!   walk's deadline predicate), and once more before serialization;
//!   scan work itself is capped by an internal [`ScanBudget`]
//!   (entries examined plus queued directories).
//!
//! [`ScanBudget`]: crate::host_reader::ScanBudget
//! - The response is recounted exactly, tail-truncated to the byte budget
//!   (mirroring the frozen truncation semantics), revalidated, and its
//!   outcome retained in bounded history.
//!
//! [`resolve()`]: kryprobe_core::workload::resolve
//! [`HelperCounters`]: crate::cache::HelperCounters

use crate::cache::{HelperCounters, LiveBinding, OutcomeRecord, ResolverCache, span_elapsed};
use crate::host_reader::{HostReadError, HostView, RealFs, ScanBudget};
use kryprobe_core::workload::{
    AttributionEvidence, AttributionStatus, HELPER_REQUEST_TIMEOUT_NS, KernelIdentity,
    METHOD_METADATA_FILE, MetadataSnapshot, MetadataUnavailable, Relationship, ResolvedAssociation,
    ResponseStatus, SnapshotCounters, SnapshotErrorCode, SnapshotInterval, SnapshotKeyDetail,
    SnapshotKeyError, SnapshotRequest, SnapshotResponse, ValidityInterval, WorkloadOrigin, resolve,
};

/// Boot-nanosecond clock (uptime-derived in production, scripted in
/// tests — deterministic deadlines without sleeping).
pub trait Clock {
    /// Current time in boot nanoseconds.
    fn now_ns(&self) -> u64;
}

/// Scripted clock for deterministic deadline/TTL tests: yields each
/// programmed time in order, repeating the last.
#[cfg(test)]
#[derive(Debug)]
pub struct ScriptedClock {
    times: Vec<u64>,
    pos: std::cell::Cell<usize>,
}

#[cfg(test)]
impl ScriptedClock {
    /// Program the yielded times (at least one).
    #[must_use]
    pub fn new(times: Vec<u64>) -> Self {
        assert!(!times.is_empty(), "scripted clock needs times");
        Self {
            times,
            pos: std::cell::Cell::new(0),
        }
    }
}

#[cfg(test)]
impl Clock for ScriptedClock {
    fn now_ns(&self) -> u64 {
        let index = self.pos.get().min(self.times.len() - 1);
        self.pos.set(self.pos.get().saturating_add(1));
        self.times[index]
    }
}

/// The M1 resolver: frozen pure resolution plus liveness joins.
#[derive(Debug)]
pub struct Resolver {
    view: HostView,
    metadata: Option<MetadataSnapshot>,
    cache: ResolverCache,
}

impl Resolver {
    /// Bind a host view and optional validated metadata snapshot.
    #[must_use]
    pub fn new(view: HostView, metadata: Option<MetadataSnapshot>) -> Self {
        Self {
            view,
            metadata,
            cache: ResolverCache::new(),
        }
    }

    /// Saturation/error counters.
    pub fn counters(&mut self) -> &mut HelperCounters {
        self.cache.counters()
    }

    /// Retained outcome count (bounded ring).
    #[cfg(test)]
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.cache.history_len()
    }

    /// Resolve one request: frozen pure answer first, then the
    /// same-boot liveness pass under `start_ns` + helper-timeout
    /// deadline (`Verified` promotion requires an established identity
    /// per R3 coherence). `now` readings come from `clock`.
    pub fn resolve(
        &mut self,
        request: &SnapshotRequest,
        clock: &dyn Clock,
        start_ns: u64,
    ) -> Result<SnapshotResponse, MetadataUnavailable> {
        request.validate()?;
        let now_ns = clock.now_ns();
        let host_kernel = self
            .view
            .kernel_scope()
            .map_err(|_| MetadataUnavailable::UnsupportedEnvironment)?;
        let effective = self.metadata.clone().unwrap_or_else(|| MetadataSnapshot {
            collector: "kryprobe-workload-helper".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: now_ns,
                end_ns: now_ns,
            },
            kernel_identity: KernelIdentity::Known(host_kernel.clone()),
            entries: Vec::new(),
        });
        let mut response = resolve(request, &effective)?;
        // Defense in depth (R2 D01): the frozen entry point already
        // honors an explicit file `stale` status, so this downgrade is
        // a post-merge no-op — kept so a stale file can never surface
        // as asserted through this path.
        honor_explicit_stale(&mut response, &effective);
        self.upgrade_unresolved(&mut response, &host_kernel, clock, start_ns, now_ns);
        recount(&mut response);
        truncate_to_budget(&mut response)?;
        recount(&mut response);
        response.validate()?;
        self.cache.record_outcome(OutcomeRecord {
            at_ns: now_ns,
            resolved: response.counters.resolved,
            unresolved: response.counters.unresolved,
            refused: response.counters.refused,
        });
        Ok(response)
    }

    /// Liveness pass over unresolved same-boot associations (cache hits,
    /// pid checks, one batched inode scan). Promotion to `Verified`
    /// additionally requires an established identity (R3 coherence), so
    /// liveness-only candidates stay `Unresolved` with their liveness
    /// remembered. Deadline trips convert still-pending keys to
    /// `Unsupported`; established results stand.
    fn upgrade_unresolved(
        &mut self,
        response: &mut SnapshotResponse,
        host_kernel: &str,
        clock: &dyn Clock,
        start_ns: u64,
        now_ns: u64,
    ) {
        // Partition association indices: upgradeable vs settled.
        let mut pending: Vec<usize> = Vec::new();
        for (index, assoc) in response.associations.iter().enumerate() {
            if assoc.evidence.status != AttributionStatus::Unresolved {
                continue;
            }
            if assoc.key.kernel_scope != host_kernel {
                continue;
            }
            pending.push(index);
        }
        // Cache pass (cheap, no deadline): fresh positives carry
        // remembered liveness — promotion still requires an established
        // identity (R3 coherence), so identity-less hits stay unresolved
        // with their host work saved. Fresh negatives/tombstones settle
        // as unanswered.
        let mut need_host: Vec<usize> = Vec::new();
        for index in pending {
            let cgroup = response.associations[index].key.cgroup;
            if let Some(binding) = self.cache.lookup_positive(cgroup, now_ns) {
                if response.associations[index].identity.is_resolved() {
                    apply_verified(&mut response.associations[index], binding);
                }
            } else if self.cache.lookup_negative(cgroup, now_ns) {
                // Throttled: stays unresolved.
            } else if self.cache.lookup_tombstone(cgroup, now_ns) {
                // Ended: stays unresolved.
            } else {
                need_host.push(index);
            }
        }
        // Pid phase (cheap, bounded work per key: two small file reads
        // plus one depth-bounded confined resolution): liveness hints,
        // lifetime stability, and hint/cgroup agreement. The resolution
        // deadline gates each key's work: a trip converts every
        // still-pending key (worked or not) to `Unsupported`, counted
        // once; established results stand.
        let mut need_scan: Vec<usize> = Vec::new();
        let mut pid_tripped_at: Option<usize> = None;
        for (pos, index) in need_host.iter().enumerate() {
            if span_elapsed(start_ns, clock.now_ns(), HELPER_REQUEST_TIMEOUT_NS) {
                pid_tripped_at = Some(pos);
                break;
            }
            if self.pid_consistent(*index, response, now_ns) {
                need_scan.push(*index);
            }
        }
        if let Some(pos) = pid_tripped_at {
            self.cache.counters().inc_deadline_trips();
            let mut pending = need_scan;
            pending.extend_from_slice(&need_host[pos..]);
            convert_list_to_unsupported(response, &pending);
            return;
        }
        if need_scan.is_empty() {
            return;
        }
        // Scan phase: one batched walk for the whole request, gated by
        // the resolution deadline before, during (the walk re-checks the
        // predicate as it goes), and after. A trip converts the
        // still-pending keys to `Unsupported` (partial response); every
        // established result stands.
        if span_elapsed(start_ns, clock.now_ns(), HELPER_REQUEST_TIMEOUT_NS) {
            self.cache.counters().inc_deadline_trips();
            convert_list_to_unsupported(response, &need_scan);
            return;
        }
        if !self.cache.note_scan(now_ns) {
            return;
        }
        let targets: Vec<u64> = need_scan
            .iter()
            .map(|i| response.associations[*i].key.cgroup)
            .collect();
        let mut budget = ScanBudget::new();
        let scan = self.view.find_cgroups(
            &targets,
            self.cache.counters(),
            &RealFs,
            &mut budget,
            &|| span_elapsed(start_ns, clock.now_ns(), HELPER_REQUEST_TIMEOUT_NS),
        );
        match scan {
            Ok((found, _denied)) => {
                for index in &need_scan {
                    let index = *index;
                    let cgroup = response.associations[index].key.cgroup;
                    match found.get(&cgroup) {
                        Some(object) => {
                            let binding = LiveBinding {
                                dev: object.dev,
                                ino: object.ino,
                                observed_ns: now_ns,
                            };
                            // The liveness observation is remembered
                            // (bounding re-scans; a full cache refuses the
                            // insert, counted, never silent) — but
                            // promotion to `Verified` additionally requires
                            // an established identity (R3 coherence), which
                            // liveness alone never establishes.
                            let _ = self.cache.insert_positive(cgroup, binding);
                            if response.associations[index].identity.is_resolved() {
                                apply_verified(&mut response.associations[index], binding);
                            }
                        }
                        None => {
                            let _ = self.cache.insert_tombstone(cgroup, now_ns);
                            let _ = self.cache.insert_negative(cgroup, now_ns);
                        }
                    }
                }
                // Post-scan gate, before serialization: a deadline crossed
                // after the last in-scan check still converts the
                // still-pending keys (partial response); associations the
                // scan established (e.g. identity-held `Verified`) stand.
                if span_elapsed(start_ns, clock.now_ns(), HELPER_REQUEST_TIMEOUT_NS) {
                    self.cache.counters().inc_deadline_trips();
                    convert_list_to_unsupported(response, &need_scan);
                }
            }
            Err(HostReadError::BudgetExceeded) | Err(HostReadError::DeadlineExceeded) => {
                // Scan work or the in-scan deadline gave out (already
                // counted exactly once inside the walk): the still-pending
                // keys convert to `Unsupported` (partial response).
                convert_list_to_unsupported(response, &need_scan);
            }
            Err(HostReadError::ReuseDetected) => {
                // A replaced object refuses binding; keys stay unresolved
                // (the error is already counted).
            }
            Err(_) => {
                // Unsupported view mid-scan: keys stay unresolved.
            }
        }
    }

    /// Per-key pid consistency: the tgid is readable, its lifetime is
    /// stable, and its confined hint resolves to the captured cgroup.
    /// Any failure throttles (negative) and returns false; reuse also
    /// tombstones the captured cgroup.
    fn pid_consistent(&mut self, index: usize, response: &SnapshotResponse, now_ns: u64) -> bool {
        let key = &response.associations[index].key;
        let (cgroup, tgid) = (key.cgroup, key.tgid);
        let entry = match self.view.read_pid(tgid) {
            Ok(entry) => entry,
            Err(error) => {
                // Gone readers throttle briefly; denials likewise — but
                // the captured ids stay on the key either way.
                self.cache.counters().note_host_error(&error);
                if matches!(error, HostReadError::GonePid { .. }) {
                    let _ = self.cache.insert_negative(cgroup, now_ns);
                    return self.pid_gone_allows_liveness(cgroup);
                }
                let _ = self.cache.insert_negative(cgroup, now_ns);
                return false;
            }
        };
        match self.cache.note_pid_lifetime(tgid, entry.start_ticks) {
            crate::cache::LifetimeVerdict::Reused => {
                let _ = self.cache.insert_tombstone(cgroup, now_ns);
                return false;
            }
            crate::cache::LifetimeVerdict::FirstSeen | crate::cache::LifetimeVerdict::Stable => {}
        }
        let (_, ino) = match self.view.resolve_hint(&entry.hint, self.cache.counters()) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = self.cache.insert_negative(cgroup, now_ns);
                return false;
            }
        };
        if ino != cgroup {
            // The pid moved on: this hint is not the captured cgroup.
            self.cache.counters().inc_migration_skipped();
            let _ = self.cache.insert_negative(cgroup, now_ns);
            return false;
        }
        true
    }

    /// A gone pid does not block cgroup liveness: the captured cgroup may
    /// outlive the process. Returns true so the scan still binds it.
    fn pid_gone_allows_liveness(&mut self, cgroup: u64) -> bool {
        // Drop the just-added negative: absence of the pid is not absence
        // of the cgroup object.
        self.cache.clear_negative(cgroup);
        true
    }
}

/// Honor an explicit file `stale` status: when the single matching
/// entry says stale but frozen resolution asserted (validity overlap or
/// absence), rewrite the association to `Stale` with the entry's own
/// validity. Downgrades only; anything else (zero or several matches,
/// non-asserted associations) is left untouched.
fn honor_explicit_stale(response: &mut SnapshotResponse, effective: &MetadataSnapshot) {
    for assoc in &mut response.associations {
        if assoc.evidence.status != AttributionStatus::Asserted {
            continue;
        }
        let mut matches = effective
            .entries
            .iter()
            .filter(|entry| entry.cgroup_id == Some(assoc.key.cgroup));
        let (Some(entry), None) = (matches.next(), matches.next()) else {
            continue;
        };
        if entry.binding.status == AttributionStatus::Stale {
            assoc.evidence = AttributionEvidence::new(
                Relationship::HookContext,
                METHOD_METADATA_FILE,
                WorkloadOrigin::OperatorMetadataFile,
                AttributionStatus::Stale,
                entry.binding.validity,
            );
        }
    }
}

/// Verified-liveness evidence: the captured cgroup bound to the live
/// object, valid for one cache TTL from observation. Callers must ensure
/// the association already carries an established identity: R3 coherence
/// refuses `Verified` without one, and liveness invents no workload.
fn apply_verified(assoc: &mut ResolvedAssociation, binding: LiveBinding) {
    let validity = ValidityInterval::monotonic(
        binding.observed_ns,
        binding
            .observed_ns
            .saturating_add(kryprobe_core::workload::RESOLVER_CACHE_TTL_NS),
    );
    assoc.evidence =
        AttributionEvidence::verified_local_binding(Relationship::HookContext, validity);
}

/// Convert one pending unresolved association into an `Unsupported` key
/// error (deadline/scan-budget partial responses). Non-unresolved
/// associations are never touched.
fn convert_one_to_unsupported(response: &mut SnapshotResponse, index: usize) {
    if response.associations[index].evidence.status != AttributionStatus::Unresolved {
        return;
    }
    let key = response.associations[index].key.clone();
    response.associations.remove(index);
    // Removal shifts later indices: convert via
    // convert_list_to_unsupported (descending) only.
    response.errors.push(SnapshotKeyError {
        key,
        code: SnapshotErrorCode::Unsupported,
        detail: SnapshotKeyDetail::UnsupportedKey,
    });
}

/// Convert a pending index list to `Unsupported` in descending order so
/// removals keep the remaining indices valid.
fn convert_list_to_unsupported(response: &mut SnapshotResponse, indices: &[usize]) {
    let mut ordered: Vec<usize> = indices.to_vec();
    ordered.sort_unstable();
    ordered.reverse();
    for index in ordered {
        convert_one_to_unsupported(response, index);
    }
}

/// Recompute exact counters over the current associations/errors.
fn recount(response: &mut SnapshotResponse) {
    let mut resolved: u64 = 0;
    let mut unresolved: u64 = 0;
    for assoc in &response.associations {
        match assoc.evidence.status {
            AttributionStatus::Verified | AttributionStatus::Asserted => resolved += 1,
            AttributionStatus::Unresolved
            | AttributionStatus::Ambiguous
            | AttributionStatus::Stale
            | AttributionStatus::Unsupported => unresolved += 1,
        }
    }
    response.counters = SnapshotCounters {
        resolved,
        unresolved,
        refused: response.errors.len() as u64,
    };
}

/// Tail-truncate to the response byte budget, mirroring the frozen
/// resolver semantics: request-order tail associations convert to
/// `BudgetExceeded` errors (status `Truncated`) until the response fits;
/// an unwritable key set refuses outright.
fn truncate_to_budget(response: &mut SnapshotResponse) -> Result<(), MetadataUnavailable> {
    while response.encoded_len()? > kryprobe_core::workload::MAX_SNAPSHOT_RESPONSE_BYTES {
        let Some(dropped) = response.associations.pop() else {
            return Err(MetadataUnavailable::BudgetExceeded);
        };
        response.errors.push(SnapshotKeyError {
            key: dropped.key,
            code: SnapshotErrorCode::BudgetExceeded,
            detail: SnapshotKeyDetail::BudgetDropped,
        });
        response.status = ResponseStatus::Truncated;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kryprobe_core::workload::{
        BindingProvenance, ContainerRef, KernelIdentity, MetadataEntry, SnapshotInterval,
        SnapshotKey, SnapshotRequest, WorkloadOrigin, decode_response,
    };
    use std::os::unix::fs::MetadataExt;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";
    const SCOPE: &str = "7.0.0-test/test-boot-id-001";
    const NOW: u64 = 100_000_000_000;

    struct TFixture {
        dir: std::path::PathBuf,
    }

    impl TFixture {
        fn create(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "kwh-res-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            let write = |rel: &str, body: &[u8]| {
                let path = dir.join(rel);
                std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
                std::fs::write(&path, body).expect("write");
            };
            write("proc/sys/kernel/osrelease", b"7.0.0-test\n");
            write("proc/sys/kernel/random/boot_id", b"test-boot-id-001\n");
            write("proc/uptime", b"100.00 200.00\n");
            std::fs::create_dir_all(dir.join("cgroup")).expect("cgroup");
            Self { dir }
        }

        fn view(&self) -> HostView {
            HostView::new(&self.dir.join("proc"), &self.dir.join("cgroup"))
        }

        fn cgroup_dir(&self, rel: &str) -> u64 {
            let path = self.dir.join("cgroup").join(rel);
            std::fs::create_dir_all(&path).expect("mkdir");
            std::fs::metadata(&path).expect("stat").ino()
        }

        fn pid(&self, tgid: u32, hint: &str, ticks: u64) {
            let base = self.dir.join("proc").join(tgid.to_string());
            std::fs::create_dir_all(&base).expect("mkdir");
            std::fs::write(base.join("cgroup"), format!("0::{hint}\n")).expect("write");
            std::fs::write(
                base.join("stat"),
                format!("{tgid} (t) R 1 1 1 0 -1 4194304 10 0 0 0 5 5 0 0 20 0 2 0 {ticks} 0 0\n"),
            )
            .expect("write");
        }
    }

    impl Drop for TFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn key(cgroup: u64, tgid: u32) -> SnapshotKey {
        SnapshotKey {
            kernel_scope: SCOPE.to_string(),
            cgroup,
            tgid,
            start_ns: 555,
        }
    }

    fn request(keys: Vec<SnapshotKey>) -> SnapshotRequest {
        SnapshotRequest {
            session_id: SESSION.to_string(),
            keys,
            capture_interval: None,
        }
    }

    /// A request with an established counted interval: only this form can
    /// reach covered `Asserted` bindings (R2 coverage gate). Tests whose
    /// intent needs asserted metadata use this; liveness/upgrade tests
    /// with no counted interval honestly stay absent.
    fn request_with_capture(keys: Vec<SnapshotKey>, start_ns: u64, end_ns: u64) -> SnapshotRequest {
        SnapshotRequest {
            session_id: SESSION.to_string(),
            keys,
            capture_interval: Some(SnapshotInterval { start_ns, end_ns }),
        }
    }

    fn metadata_for(cgroup: u64) -> MetadataSnapshot {
        MetadataSnapshot {
            collector: "t".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: 1000,
                end_ns: 2000,
            },
            kernel_identity: KernelIdentity::Known(SCOPE.to_string()),
            entries: vec![MetadataEntry {
                container: Some(ContainerRef {
                    runtime: "rt".to_string(),
                    id: "id".to_string(),
                    lifetime: None,
                }),
                pod: None,
                cluster: None,
                node: None,
                ancestor_container: None,
                display_name: None,
                cgroup_id: Some(cgroup),
                binding: BindingProvenance {
                    method: kryprobe_core::workload::METHOD_METADATA_FILE.to_string(),
                    source: WorkloadOrigin::OperatorMetadataFile,
                    status: AttributionStatus::Asserted,
                    validity: None,
                },
            }],
        }
    }

    #[test]
    fn empty_snapshot_tags_host_kernel_and_gates_foreign_keys() {
        let fixture = TFixture::create("empty");
        let mut resolver = Resolver::new(fixture.view(), None);
        let clock = ScriptedClock::new(vec![NOW]);
        let foreign = SnapshotKey {
            kernel_scope: "other-boot".to_string(),
            cgroup: 1,
            tgid: 1,
            start_ns: 1,
        };
        let response = resolver
            .resolve(&request(vec![key(999_999_111, 4242), foreign]), &clock, NOW)
            .expect("resolves");
        assert_eq!(
            response.kernel_identity,
            KernelIdentity::Known(SCOPE.to_string())
        );
        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].code, SnapshotErrorCode::KernelMismatch);
        // Same-boot unknown cgroup: unresolved, retained.
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, 999_999_111);
    }

    #[test]
    fn live_cgroup_without_identity_stays_unresolved() {
        // R3 coherence (ADR-0012 (c6)): `Verified` requires an established
        // identity, and liveness observation (dev/ino) establishes none —
        // so a live cgroup with no metadata stays `Unresolved`, with its
        // liveness remembered (bounding re-scans) rather than promoted.
        // Workload identity is never invented.
        let fixture = TFixture::create("verify");
        let live = fixture.cgroup_dir("live");
        let mut resolver = Resolver::new(fixture.view(), None);
        let clock = ScriptedClock::new(vec![NOW]);
        let response = resolver
            .resolve(&request(vec![key(live, 4242)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(response.associations.len(), 1);
        let assoc = &response.associations[0];
        assert_eq!(assoc.evidence.status, AttributionStatus::Unresolved);
        assert_eq!(assoc.evidence.method, "unresolved");
        assert!(!assoc.identity.is_resolved());
        assert!(assoc.evidence.validity.is_none());
        assert_eq!(resolver.counters().inserts, 1);
        // The response still validates and binds to its request
        // (`Unresolved` carries no temporal requirement, so the
        // capture-less request binds).
        assert!(response.validate().is_ok());
        assert!(
            kryprobe_core::workload::bind_response_to_request(
                &request(vec![key(live, 4242)]),
                &response
            )
            .is_ok()
        );
        // ...and survives the frozen wire codec.
        let bytes = kryprobe_core::workload::encode_response(&response).expect("encodes");
        assert!(decode_response(&bytes).is_ok());
        assert_eq!(resolver.history_len(), 1);
        // Second resolve: remembered liveness saves the host work (a
        // positive hit) while the key still stays unresolved.
        let again = resolver
            .resolve(&request(vec![key(live, 4242)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(
            again.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert_eq!(resolver.counters().positive_hits, 1);
    }

    #[test]
    fn explicit_file_stale_is_honored_despite_overlap() {
        // R2 D01: the frozen entry point honors an explicit file `stale`
        // status whatever the validity (overlap, absence, or coverage);
        // the helper downgrade converges with that ruling and is now a
        // no-op on this path (kept as defense in depth).
        let fixture = TFixture::create("file-stale");
        let live = fixture.cgroup_dir("live");
        for validity in [None, Some(ValidityInterval::monotonic(1500, 2500))] {
            let mut meta = metadata_for(live);
            meta.entries[0].binding.status = AttributionStatus::Stale;
            meta.entries[0].binding.validity = validity;
            // Sanity: the frozen path alone honors stale here (R2 fix).
            let frozen = resolve(&request(vec![key(live, 4242)]), &meta).expect("frozen");
            assert_eq!(
                frozen.associations[0].evidence.status,
                AttributionStatus::Stale,
                "frozen baseline for validity {validity:?}"
            );
            let mut resolver = Resolver::new(fixture.view(), Some(meta));
            let clock = ScriptedClock::new(vec![NOW]);
            let response = resolver
                .resolve(&request(vec![key(live, 4242)]), &clock, NOW)
                .expect("resolves");
            assert_eq!(
                response.associations[0].evidence.status,
                AttributionStatus::Stale,
                "validity {validity:?} must honor file stale"
            );
            assert!(response.validate().is_ok());
            assert_eq!(response.counters.unresolved, 1);
            assert_eq!(response.counters.resolved, 0);
        }
    }

    #[test]
    fn asserted_and_stale_never_upgrade() {
        // The counted interval is established ([1000,2000]): the expired
        // validity [100,200] stays stale (uncovered, identity kept) while
        // the covering validity [500,2500] asserts — and neither settled
        // status is promoted by liveness.
        let fixture = TFixture::create("no-upgrade");
        let live = fixture.cgroup_dir("live");
        let mut stale_meta = metadata_for(live);
        stale_meta.entries[0].binding.validity = Some(ValidityInterval::monotonic(100, 200));
        let mut resolver = Resolver::new(fixture.view(), Some(stale_meta));
        let clock = ScriptedClock::new(vec![NOW]);
        let response = resolver
            .resolve(
                &request_with_capture(vec![key(live, 4242)], 1000, 2000),
                &clock,
                NOW,
            )
            .expect("resolves");
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Stale,
            "expired bindings stay stale even when live"
        );

        let mut asserted_meta = metadata_for(live);
        asserted_meta.entries[0].binding.validity = Some(ValidityInterval::monotonic(500, 2500));
        let mut resolver = Resolver::new(fixture.view(), Some(asserted_meta));
        let response = resolver
            .resolve(
                &request_with_capture(vec![key(live, 4242)], 1000, 2000),
                &clock,
                NOW,
            )
            .expect("resolves");
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Asserted,
            "asserted files are not promoted by liveness"
        );
    }

    #[test]
    fn migrated_pid_hint_skips_verification() {
        let fixture = TFixture::create("migrated");
        let live = fixture.cgroup_dir("live");
        let other = fixture.cgroup_dir("other");
        // Pid claims membership of `other` while the key captured `live`:
        // the process moved on; verification refuses.
        fixture.pid(7001, "/other", 111);
        // Sanity: hint resolves (guards the fixture, not the code).
        let mut counters = HelperCounters::new();
        let (_, ino) = fixture
            .view()
            .resolve_hint("/other", &mut counters)
            .expect("hint resolves");
        assert_eq!(ino, other);
        let mut resolver = Resolver::new(fixture.view(), None);
        let clock = ScriptedClock::new(vec![NOW]);
        let response = resolver
            .resolve(&request(vec![key(live, 7001)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert_eq!(resolver.counters().migration_skipped, 1);
    }

    #[test]
    fn consistent_pid_hint_stays_unresolved_without_identity() {
        // The pid agrees with the captured cgroup and the object is live,
        // but R3 coherence withholds `Verified`: no established identity,
        // no promotion. Liveness is still remembered (contrast the
        // migrated-hint path, which skips the scan entirely).
        let fixture = TFixture::create("consistent");
        let live = fixture.cgroup_dir("grp/live");
        fixture.pid(7002, "/grp/live", 222);
        let mut resolver = Resolver::new(fixture.view(), None);
        let clock = ScriptedClock::new(vec![NOW]);
        let response = resolver
            .resolve(&request(vec![key(live, 7002)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert_eq!(resolver.counters().inserts, 1);
        assert_eq!(resolver.counters().migration_skipped, 0);
    }

    #[test]
    fn pid_reuse_tombstones_and_refuses() {
        let fixture = TFixture::create("reuse");
        let live = fixture.cgroup_dir("live");
        fixture.pid(7003, "/live", 100);
        let mut resolver = Resolver::new(fixture.view(), None);
        let clock = ScriptedClock::new(vec![NOW]);
        // Prime the pid table with the old lifetime (against a missing
        // cgroup so nothing else caches).
        let primed = resolver
            .resolve(&request(vec![key(424_243, 7003)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(
            primed.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        // Same tgid, new lifetime: the captured process is gone; the
        // captured cgroup tombstones and verification refuses even
        // though the object is live.
        fixture.pid(7003, "/live", 200);
        let refused = resolver
            .resolve(&request(vec![key(live, 7003)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(resolver.counters().reuse_detected, 1);
        assert_eq!(
            refused.associations[0].evidence.status,
            AttributionStatus::Unresolved,
            "reused tgid must not verify the captured cgroup"
        );
    }

    #[test]
    fn deadline_trip_yields_partial_response() {
        let fixture = TFixture::create("deadline");
        let a = fixture.cgroup_dir("a");
        let b = fixture.cgroup_dir("b");
        let mut resolver = Resolver::new(fixture.view(), None);
        // Prime: key a's liveness is observed and remembered under a
        // generous clock (R3 coherence withholds `Verified`: no
        // established identity — but the remembered liveness stands).
        let primer = ScriptedClock::new(vec![NOW]);
        let primed = resolver
            .resolve(&request(vec![key(a, 4242)]), &primer, NOW)
            .expect("primes");
        assert_eq!(
            primed.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert_eq!(resolver.counters().inserts, 1);
        // Main request: key a re-resolves from remembered liveness
        // (established work stands) while the scan-phase deadline trips
        // for key b.
        let start = NOW + 10_000;
        let clock = ScriptedClock::new(vec![
            start,                                 // request now
            start + HELPER_REQUEST_TIMEOUT_NS + 1, // scan check: tripped
        ]);
        let response = resolver
            .resolve(&request(vec![key(a, 4242), key(b, 4243)]), &clock, start)
            .expect("partial resolves");
        assert!(response.validate().is_ok());
        assert!(
            kryprobe_core::workload::bind_response_to_request(
                &request(vec![key(a, 4242), key(b, 4243)]),
                &response
            )
            .is_ok()
        );
        // Key a stands on its remembered liveness (a positive hit, no
        // re-scan); key b converts to `Unsupported` (deadline).
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, a);
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert_eq!(resolver.counters().positive_hits, 1);
        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].code, SnapshotErrorCode::Unsupported);
        assert_eq!(response.errors[0].key.cgroup, b);
        assert_eq!(resolver.counters().deadline_trips, 1);
    }

    /// PRIV02: the deadline is checked DURING the scan, not only before
    /// it. Pre-scan clock reads see a live deadline; the scan-phase read
    /// trips. Still-pending keys convert to `Unsupported` (partial
    /// response, deadline counter exactly 1, no scan inserts); the
    /// established asserted association stands untouched.
    #[test]
    fn deadline_crossed_during_scan() {
        let fixture = TFixture::create("deadline-scan");
        let a = fixture.cgroup_dir("a");
        let b = fixture.cgroup_dir("b");
        let asserted_cgroup = fixture.cgroup_dir("asserted-live");
        let mut meta = metadata_for(asserted_cgroup);
        meta.entries[0].binding.validity = Some(ValidityInterval::monotonic(500, 2500));
        let mut resolver = Resolver::new(fixture.view(), Some(meta));
        let start = NOW;
        let tripped = start + HELPER_REQUEST_TIMEOUT_NS + 1;
        // Request now, pid pre-checks, pre-scan check: live. First
        // scan-phase read: crossed.
        let clock = ScriptedClock::new(vec![start, start, start, start, tripped]);
        let keys = vec![key(asserted_cgroup, 4240), key(a, 4242), key(b, 4243)];
        let response = resolver
            .resolve(
                &request_with_capture(keys.clone(), 1000, 2000),
                &clock,
                start,
            )
            .expect("partial resolves");
        assert!(response.validate().is_ok());
        assert!(
            kryprobe_core::workload::bind_response_to_request(
                &request_with_capture(keys, 1000, 2000),
                &response
            )
            .is_ok()
        );
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, asserted_cgroup);
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Asserted
        );
        assert_eq!(response.errors.len(), 2);
        assert!(
            response
                .errors
                .iter()
                .all(|e| e.code == SnapshotErrorCode::Unsupported),
            "pending keys must convert to Unsupported: {:?}",
            response.errors
        );
        let mut err_cgroups: Vec<u64> = response.errors.iter().map(|e| e.key.cgroup).collect();
        err_cgroups.sort_unstable();
        let mut wanted = vec![a, b];
        wanted.sort_unstable();
        assert_eq!(err_cgroups, wanted);
        assert_eq!(resolver.counters().deadline_trips, 1);
        assert_eq!(resolver.counters().inserts, 0);
        assert_eq!(resolver.counters().tombstone_inserts, 0);
    }

    /// PRIV02: the deadline is checked DURING the pid phase. The first
    /// key's pre-check sees a live deadline; the second key's trips. Both
    /// pending keys (worked and unworked alike) convert to `Unsupported`
    /// with the deadline counter exactly 1 and no scan at all; the
    /// established asserted association stands untouched.
    #[test]
    fn deadline_crossed_during_pid_phase() {
        let fixture = TFixture::create("deadline-pid");
        let a = fixture.cgroup_dir("a");
        let b = fixture.cgroup_dir("b");
        let asserted_cgroup = fixture.cgroup_dir("asserted-live");
        let mut meta = metadata_for(asserted_cgroup);
        meta.entries[0].binding.validity = Some(ValidityInterval::monotonic(500, 2500));
        let mut resolver = Resolver::new(fixture.view(), Some(meta));
        let start = NOW;
        let tripped = start + HELPER_REQUEST_TIMEOUT_NS + 1;
        // Request now, first pid pre-check: live. Second pid pre-check:
        // crossed.
        let clock = ScriptedClock::new(vec![start, start, tripped]);
        let keys = vec![key(asserted_cgroup, 4240), key(a, 4242), key(b, 4243)];
        let response = resolver
            .resolve(
                &request_with_capture(keys.clone(), 1000, 2000),
                &clock,
                start,
            )
            .expect("partial resolves");
        assert!(response.validate().is_ok());
        assert!(
            kryprobe_core::workload::bind_response_to_request(
                &request_with_capture(keys, 1000, 2000),
                &response
            )
            .is_ok()
        );
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, asserted_cgroup);
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Asserted
        );
        assert_eq!(response.errors.len(), 2);
        assert!(
            response
                .errors
                .iter()
                .all(|e| e.code == SnapshotErrorCode::Unsupported),
            "pending keys must convert to Unsupported: {:?}",
            response.errors
        );
        let mut err_cgroups: Vec<u64> = response.errors.iter().map(|e| e.key.cgroup).collect();
        err_cgroups.sort_unstable();
        let mut wanted = vec![a, b];
        wanted.sort_unstable();
        assert_eq!(err_cgroups, wanted);
        assert_eq!(resolver.counters().deadline_trips, 1);
        assert_eq!(resolver.counters().inserts, 0);
        assert_eq!(resolver.counters().tombstone_inserts, 0);
    }

    /// PRIV02: the deadline is checked once more after the scan,
    /// before serialization. Every in-scan read sees a live deadline; the
    /// post-scan read trips. The still-pending keys convert to
    /// `Unsupported` (deadline counter exactly 1) while the scan's
    /// established cache work and the asserted association stand.
    #[test]
    fn deadline_crossed_after_scan_converts_pending() {
        let fixture = TFixture::create("deadline-post");
        let a = fixture.cgroup_dir("a");
        let b = fixture.cgroup_dir("b");
        let asserted_cgroup = fixture.cgroup_dir("asserted-live");
        let mut meta = metadata_for(asserted_cgroup);
        meta.entries[0].binding.validity = Some(ValidityInterval::monotonic(500, 2500));
        let mut resolver = Resolver::new(fixture.view(), Some(meta));
        let start = NOW;
        let tripped = start + HELPER_REQUEST_TIMEOUT_NS + 1;
        // 1 request now + 2 pid pre-checks + 1 pre-scan + 1 pre-walk + 1
        // loop-top + 2 confirm checks: live. Post-scan read: crossed.
        let clock = ScriptedClock::new(vec![
            start, start, start, start, start, start, start, start, tripped,
        ]);
        let keys = vec![key(asserted_cgroup, 4240), key(a, 4242), key(b, 4243)];
        let response = resolver
            .resolve(
                &request_with_capture(keys.clone(), 1000, 2000),
                &clock,
                start,
            )
            .expect("partial resolves");
        assert!(response.validate().is_ok());
        assert!(
            kryprobe_core::workload::bind_response_to_request(
                &request_with_capture(keys, 1000, 2000),
                &response
            )
            .is_ok()
        );
        assert_eq!(response.associations.len(), 1);
        assert_eq!(response.associations[0].key.cgroup, asserted_cgroup);
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Asserted
        );
        assert_eq!(response.errors.len(), 2);
        assert!(
            response
                .errors
                .iter()
                .all(|e| e.code == SnapshotErrorCode::Unsupported),
            "pending keys must convert to Unsupported: {:?}",
            response.errors
        );
        assert_eq!(resolver.counters().deadline_trips, 1);
        // The completed scan's liveness observations stand in the cache
        // (bounding re-scans) even though the response went partial.
        assert_eq!(resolver.counters().inserts, 2);
    }

    #[test]
    fn second_key_reuses_positive_cache_without_rescan() {
        let fixture = TFixture::create("cachehit");
        let live = fixture.cgroup_dir("live");
        let mut resolver = Resolver::new(fixture.view(), None);
        let clock = ScriptedClock::new(vec![NOW]);
        // Same cgroup, two tgids (both gone): one scan serves both.
        // R3 coherence withholds `Verified` (no established identity),
        // but the remembered liveness is still shared.
        let response = resolver
            .resolve(
                &request(vec![key(live, 4242), key(live, 4243)]),
                &clock,
                NOW,
            )
            .expect("resolves");
        assert_eq!(response.associations.len(), 2);
        assert!(
            response
                .associations
                .iter()
                .all(|a| a.evidence.status == AttributionStatus::Unresolved),
            "both keys stay unresolved, second from the shared scan"
        );
        // Second resolve: both served from remembered liveness (scan
        // throttle would refuse a re-scan anyway within the refresh
        // interval).
        let response = resolver
            .resolve(
                &request(vec![key(live, 4242), key(live, 4243)]),
                &clock,
                NOW,
            )
            .expect("resolves");
        assert!(
            response
                .associations
                .iter()
                .all(|a| a.evidence.status == AttributionStatus::Unresolved)
        );
        assert!(resolver.counters().positive_hits >= 2);
        // One walk bound both keys (two inserts, one scan generation).
        assert_eq!(resolver.counters().inserts, 2);
    }

    #[test]
    fn full_cache_stays_unresolved_with_visible_saturation() {
        let fixture = TFixture::create("cachefull");
        // A single response cannot hold 256 associations (byte budget),
        // so fill the cache pin across four in-process batches, then
        // resolve one more live cgroup: remembered liveness still fills
        // the cache (R3 coherence withholds `Verified`, but the
        // observation is real) while the overflow refusal is counted,
        // never silent.
        let pin = kryprobe_core::workload::MAX_RESOLVER_CACHE_ENTRIES as u64;
        let step = kryprobe_core::workload::RESOLVER_MIN_REFRESH_INTERVAL_NS + 1;
        let mut resolver = Resolver::new(fixture.view(), None);
        for batch in 0..4u64 {
            let mut keys = Vec::new();
            for i in 0..64u64 {
                let n = batch * 64 + i;
                let live = fixture.cgroup_dir(&format!("grp-{n}"));
                keys.push(key(live, 9000 + n as u32));
            }
            let at = NOW + batch * step;
            let clock = ScriptedClock::new(vec![at]);
            let filled = resolver.resolve(&request(keys), &clock, at).expect("fills");
            assert!(
                filled
                    .associations
                    .iter()
                    .all(|a| a.evidence.status == AttributionStatus::Unresolved),
                "batch {batch} stays unresolved"
            );
        }
        assert_eq!(resolver.counters().inserts, pin);
        let overflow = fixture.cgroup_dir("grp-overflow");
        let later = NOW + 4 * step;
        let tick = ScriptedClock::new(vec![later]);
        let response = resolver
            .resolve(&request(vec![key(overflow, 9999)]), &tick, later)
            .expect("resolves");
        assert_eq!(
            response.associations[0].evidence.status,
            AttributionStatus::Unresolved,
            "remembered liveness never promotes without an established identity"
        );
        assert_eq!(resolver.counters().insert_refused_full, 1);
        assert!(response.validate().is_ok());
    }

    #[test]
    fn missing_object_tombstones_and_throttles() {
        let fixture = TFixture::create("tomb");
        let mut resolver = Resolver::new(fixture.view(), None);
        let clock = ScriptedClock::new(vec![NOW]);
        let missing = 888_777_666;
        let first = resolver
            .resolve(&request(vec![key(missing, 4242)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(
            first.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert_eq!(resolver.counters().tombstone_inserts, 1);
        // Second resolve inside the throttle: negative hit, no re-scan.
        let second = resolver
            .resolve(&request(vec![key(missing, 4242)]), &clock, NOW)
            .expect("resolves");
        assert_eq!(
            second.associations[0].evidence.status,
            AttributionStatus::Unresolved
        );
        assert_eq!(resolver.counters().negative_hits, 1);
    }

    #[test]
    fn truncation_mirror_drops_tail_to_budget() {
        // Craft an over-budget response directly: the mirror must drop
        // tail associations into BudgetExceeded errors, exactly like the
        // frozen path, and recount exactly.
        let fixture = TFixture::create("trunc");
        let live = fixture.cgroup_dir("live");
        let big_id = "i".repeat(256);
        let mut entries = Vec::new();
        for i in 0..256u64 {
            entries.push(MetadataEntry {
                container: Some(ContainerRef {
                    runtime: format!("rt-{big_id}-{i}")[..256].to_string(),
                    id: format!("{big_id}-{i:03}")[..256].to_string(),
                    lifetime: Some(big_id.clone()),
                }),
                pod: None,
                cluster: None,
                node: None,
                ancestor_container: None,
                display_name: Some(format!("{big_id}-{i:03}")[..256].to_string()),
                cgroup_id: Some(1000 + i),
                binding: BindingProvenance {
                    method: kryprobe_core::workload::METHOD_METADATA_FILE.to_string(),
                    source: WorkloadOrigin::OperatorMetadataFile,
                    status: AttributionStatus::Asserted,
                    // Covered by the [1000,2000] capture below, so these
                    // assert with full max-size identity (R2 coverage
                    // gate): slim unresolved rows would fit the budget.
                    validity: Some(ValidityInterval::monotonic(500, 2500)),
                },
            });
        }
        let snapshot = MetadataSnapshot {
            collector: "t".to_string(),
            snapshot_interval: SnapshotInterval {
                start_ns: 1000,
                end_ns: 2000,
            },
            kernel_identity: KernelIdentity::Known(SCOPE.to_string()),
            entries,
        };
        // Sanity: the frozen path truncates this on its own.
        let keys: Vec<SnapshotKey> = (0..256u64).map(|i| key(1000 + i, 4242)).collect();
        let frozen = resolve(&request_with_capture(keys.clone(), 1000, 2000), &snapshot)
            .expect("frozen resolves");
        assert_eq!(frozen.status, ResponseStatus::Truncated);

        // The helper path preserves frozen truncation end to end.
        let mut resolver = Resolver::new(fixture.view(), Some(snapshot));
        let clock = ScriptedClock::new(vec![NOW]);
        let response = resolver
            .resolve(&request_with_capture(keys, 1000, 2000), &clock, NOW)
            .expect("resolves");
        assert!(response.validate().is_ok());
        assert_eq!(response.status, ResponseStatus::Truncated);
        assert!(
            response
                .errors
                .iter()
                .any(|e| e.code == SnapshotErrorCode::BudgetExceeded)
        );
        let _ = live;
    }
}
