// SPDX-License-Identifier: GPL-3.0-or-later
//! P6 task-lifetime contexts: submitter, execution, completion.
//!
//! Pure correlation logic over task identity plus best-effort userspace
//! lifetime reads (`/proc` start markers). No BPF/ABI/wire surface here:
//! the frozen BPF programs emit what they emit, and this module qualifies
//! what userspace may claim about it.
//!
//! Rules (task record items 2–4, ADR session-envelope draft):
//!
//! - A task lifetime keys on pid + start marker. Same pid with a
//!   different marker is a NEW lifetime ([`LifetimeVerdict::Reused`]);
//!   a missing marker is explicit [`LifetimeVerdict::Unknown`], never a
//!   guess. Mutable fields (comm/uid/cgroup) mark drift, never identity.
//! - Submitter, execution, and completion contexts are captured
//!   independently. Any may be unavailable; unavailability is explicit.
//! - Worker PID or stack text alone never establishes original user
//!   causality: a worker names an origin only through a proved handoff
//!   edge. A softirq execution never inherits the interrupted task as
//!   its origin.
//! - Filters run AFTER identity/correlation ingestion, per request. An
//!   admitted completion follows its request even when the landing task
//!   fails the submitter filter. Unknown fields resolve through the
//!   filter's explicit [`UnknownPolicy`]; filtered and unknown
//!   populations tally separately.
//!
//! Privacy: contexts carry pids, start markers, comm/uid/cgroup scalars,
//! and stack *markers* (missing/sampled/full — never raw IPs, never raw
//! kernel pointers).

use kryprobe_abi::kcrypto_agg::{KWhoKey, VWho};
use std::fmt::Write as _;

/// One userspace task lifetime: a pid/tgid plus the `/proc` start-time
/// marker that discriminates PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskLifetime {
    /// Thread id (pid namespace of the observer).
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// `/proc/<pid>/stat` field-22 start time, clock ticks since boot.
    /// `None` means unobserved — an unqualified lifetime, never joined.
    pub start_marker: Option<u64>,
}

/// Join verdict between two [`TaskLifetime`] observations believed to
/// share a pid key. Guides correlation joins only; cross-pid pairs are
/// out of scope ([`LifetimeVerdict::Unknown`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeVerdict {
    /// Same pid, same observed start marker: the same lifetime.
    Same,
    /// Same pid, different observed markers: PID reuse — a NEW
    /// lifetime that must never join with the old one.
    Reused,
    /// Unqualified: either marker missing, or the pair is not
    /// pid-keyed. Explicit unknown, never a guess either way.
    Unknown,
}

impl TaskLifetime {
    /// Correlates two observations of (allegedly) one pid.
    #[must_use]
    pub fn verdict_against(&self, other: &Self) -> LifetimeVerdict {
        if self.pid != other.pid {
            return LifetimeVerdict::Unknown;
        }
        match (self.start_marker, other.start_marker) {
            (Some(a), Some(b)) if a == b => LifetimeVerdict::Same,
            (Some(_), Some(_)) => LifetimeVerdict::Reused,
            _ => LifetimeVerdict::Unknown,
        }
    }
}

/// Best-effort start-marker read for `pid`: `/proc/<pid>/stat` field 22
/// (start time, ticks since boot). `None` when the pid is dead,
/// unreadable, or unparseable — never a panic, never a guess. Bounded:
/// at most 64 KiB is read (a stat line is far shorter).
#[must_use]
pub fn read_start_marker(pid: u32) -> Option<u64> {
    use std::io::Read;
    let path = format!("/proc/{pid}/stat");
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(64 * 1024).read_to_end(&mut buf).ok()?;
    let text = std::str::from_utf8(&buf).ok()?;
    // Field 1 is `(comm)` and may contain spaces/parens: the fields
    // after it start past the LAST `)`.
    let after = text.rsplit(')').next()?;
    let mut fields = after.split_whitespace();
    // Fields 3..=21 precede field 22 (9 fields to skip after `)`:
    // state ppid pgrp session tty_nr tpgid flags minflt cminflt … —
    // count exactly: field 3 is index 0 here, field 22 is index 19.
    fields.nth(19)?.parse::<u64>().ok().filter(|m| *m > 0)
}

/// How much stack evidence a context carries. Markers only — raw stack
/// IPs never ride a context (privacy gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StackMarker {
    /// No stack captured (helper errno, absent row, unobserved).
    #[default]
    Missing,
    /// A representative sample (e.g. api-returns first-seen `KSTACK`
    /// row): frames may be attached, but they sample the population,
    /// never each observation.
    Sampled,
    /// A per-observation stack. No current profile produces these;
    /// reserved so synthetic/qualified producers stay representable.
    Full,
}

impl StackMarker {
    /// Whether frames may be attached at all.
    #[must_use]
    pub fn has_frames(self) -> bool {
        !matches!(self, Self::Missing)
    }

    /// Closed wire word for the marker.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Sampled => "sampled",
            Self::Full => "full",
        }
    }
}

/// The task lifetime that issued the call, plus first-seen identity
/// scalars. Every scalar is optional: unknown stays `None`, never
/// zero-filled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitterContext {
    /// Issuing lifetime (marker may be `None` — unqualified then).
    pub lifetime: TaskLifetime,
    /// Calling thread comm at first sight (rename drifts, never
    /// re-keys). Kernel bytes, lossy-decoded: may carry control
    /// characters — renderers must route it through
    /// `kryprobe_report::sanitize_cell`, never raw.
    pub comm: Option<String>,
    /// Calling uid at first sight.
    pub uid: Option<u32>,
    /// Calling cgroup id at first sight.
    pub cgroup: Option<u64>,
    /// Parent thread-group id (`None` when the chase failed).
    pub ppid: Option<u32>,
    /// Stack evidence marker.
    pub stack: StackMarker,
}

/// Mutable-field drift between two snapshots of one lifetime key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drift {
    /// The pid + marker key still joins ([`LifetimeVerdict::Same`]).
    pub same_lifetime: bool,
    /// `comm` moved (rename).
    pub comm_changed: bool,
    /// `uid` moved.
    pub uid_changed: bool,
    /// `cgroup` moved.
    pub cgroup_changed: bool,
}

impl SubmitterContext {
    /// Builds a submitter from an api-returns who row: the key's tgid
    /// plus the value's last-writer tid/comm and first-seen
    /// uid/cgroup/ppid/stack. `start_marker` is the userspace
    /// [`read_start_marker`] read for the tid (`None` when the task is
    /// already gone — the lifetime is unqualified then, never guessed).
    ///
    /// Shape notes (frozen BPF, honest mapping): `comm` truncates at the
    /// first NUL (lossy — kernel bytes, never trusted as UTF-8);
    /// `ppid` 0 means the chase failed (`None`); `stack` negative is
    /// the raw helper errno ([`StackMarker::Missing`]) while a
    /// non-negative id is first-seen-only ([`StackMarker::Sampled`] —
    /// one stack sampled for the row's whole population, never
    /// per-observation).
    #[must_use]
    pub fn from_who(key: &KWhoKey, val: &VWho, start_marker: Option<u64>) -> Self {
        let comm_len = val
            .comm
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(val.comm.len());
        Self {
            lifetime: TaskLifetime {
                pid: val.tid,
                tgid: key.tgid,
                start_marker,
            },
            comm: Some(String::from_utf8_lossy(&val.comm[..comm_len]).into_owned()),
            uid: Some(val.uid),
            cgroup: Some(val.cgroup),
            ppid: if val.ppid == 0 { None } else { Some(val.ppid) },
            stack: if val.stack < 0 {
                StackMarker::Missing
            } else {
                StackMarker::Sampled
            },
        }
    }

    /// Compares two snapshots: the lifetime key decides the join,
    /// mutable fields report drift. A reused or unqualified key sets
    /// `same_lifetime: false` — drift flags alone never re-key.
    #[must_use]
    pub fn drift_against(&self, other: &Self) -> Drift {
        Drift {
            same_lifetime: self.lifetime.verdict_against(&other.lifetime) == LifetimeVerdict::Same,
            comm_changed: self.comm != other.comm,
            uid_changed: self.uid != other.uid,
            cgroup_changed: self.cgroup != other.cgroup,
        }
    }
}

/// Where an op body (or terminal edge) ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionKind {
    /// Ran in process context on this lifetime.
    Process(TaskLifetime),
    /// Ran on a worker (kworker/cryptd): the worker is named, and the
    /// original user causality needs a proved handoff edge or stays
    /// unavailable.
    Worker {
        /// Executing worker lifetime.
        worker: TaskLifetime,
        /// Proved causal handoff to the originator, when one exists.
        handoff: Option<TaskLifetime>,
    },
    /// Ran in softirq: the interrupted task is context, never origin.
    SoftIrq {
        /// Interrupted task lifetime, when observed.
        interrupted: Option<TaskLifetime>,
    },
    /// Execution site unobserved.
    Unknown,
}

/// What origin a context may claim. There are exactly two answers:
/// proved, or explicitly unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginClaim {
    /// Proved originator lifetime.
    Proved(TaskLifetime),
    /// No proved origin (missing handoff, softirq, unobserved).
    Unavailable,
}

/// Execution context: where the op body ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionContext {
    /// Execution site.
    pub kind: ExecutionKind,
}

impl ExecutionContext {
    /// Process-context execution on `lifetime` (api-returns: the
    /// observed API ran and returned in the caller's process context —
    /// the tally row's own lifetime).
    #[must_use]
    pub fn process(lifetime: TaskLifetime) -> Self {
        Self {
            kind: ExecutionKind::Process(lifetime),
        }
    }

    /// Explicitly unobserved execution.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            kind: ExecutionKind::Unknown,
        }
    }

    /// The origin this execution may claim. Only a process execution
    /// names itself, and only a worker WITH a proved handoff names its
    /// originator; softirq and unknown never name an origin. A claimed
    /// lifetime WITHOUT a start marker is unqualified (P6-N7: a
    /// missing lifetime marker stays unavailable, never proved —
    /// the same qualification the lifetime join applies).
    #[must_use]
    pub fn origin(&self) -> OriginClaim {
        match self.kind {
            ExecutionKind::Process(lifetime) if lifetime.start_marker.is_some() => {
                OriginClaim::Proved(lifetime)
            }
            ExecutionKind::Worker {
                handoff: Some(origin),
                ..
            } if origin.start_marker.is_some() => OriginClaim::Proved(origin),
            ExecutionKind::Process(_)
            | ExecutionKind::Worker { .. }
            | ExecutionKind::SoftIrq { .. }
            | ExecutionKind::Unknown => OriginClaim::Unavailable,
        }
    }

    /// The interrupted task, for softirq executions that observed one.
    /// Context for display, never an origin claim.
    #[must_use]
    pub fn interrupted_task(&self) -> Option<TaskLifetime> {
        match self.kind {
            ExecutionKind::SoftIrq { interrupted } => interrupted,
            _ => None,
        }
    }
}

/// Completion context: where the terminal edge landed. Set once the
/// request is admitted; an admitted completion follows its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletionContext {
    /// Landing site.
    pub landed: ExecutionContext,
    /// Always true on an admitted completion: the completion follows
    /// its request even when the landing task fails the submitter
    /// filter. Filters gate admission, never orphan completions.
    pub follows_request: bool,
}

impl CompletionContext {
    /// Completion at `landed`: the terminal edge belongs to its
    /// admitted request, unconditionally.
    #[must_use]
    pub fn follows(landed: ExecutionContext) -> Self {
        Self {
            landed,
            follows_request: true,
        }
    }
}

/// One request's three independently captured contexts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// Opaque request id (joins to the lifecycle record).
    pub request_id: String,
    /// Submitter context (`None` = explicitly unavailable).
    pub submitter: Option<SubmitterContext>,
    /// Execution context (always present; may be `Unknown`).
    pub execution: ExecutionContext,
    /// Completion context (`None` until the terminal edge lands).
    pub completion: Option<CompletionContext>,
    /// Original evidence version (behind any consumer label).
    pub evidence_version: String,
    /// Original rule version (behind any consumer label).
    pub rule_version: String,
    /// Consumer label, when a consumer view relabels this context.
    /// Informational only: the original versions above are preserved.
    pub consumer_label: Option<String>,
}

impl RequestContext {
    /// Request-lifecycle contexts: explicitly unobserved. The frozen
    /// lifecycle edges carry no task identity (no pid/tid/comm — see
    /// `decode::RawEdge`), and BPF is frozen, so there is no proved
    /// join to any task lifetime. The submitter is unavailable, the
    /// execution is unknown, and no completion context is claimed —
    /// never guessed from worker PIDs or stack text.
    #[must_use]
    pub fn lifecycle_unobserved(
        request_id: &str,
        evidence_version: &str,
        rule_version: &str,
    ) -> Self {
        Self {
            request_id: request_id.to_owned(),
            submitter: None,
            execution: ExecutionContext::unknown(),
            completion: None,
            evidence_version: evidence_version.to_owned(),
            rule_version: rule_version.to_owned(),
            consumer_label: None,
        }
    }

    /// Relabels for a consumer view. The label is informational: the
    /// original evidence/rule versions are preserved behind it, never
    /// overwritten.
    #[must_use]
    pub fn with_consumer_label(mut self, label: &str) -> Self {
        self.consumer_label = Some(label.to_owned());
        self
    }
}

/// Unknown-inclusion policy for ONE filter. Explicit per filter, never
/// a global default: the caller states, per filter construction, what
/// happens to records whose filtered field is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnknownPolicy {
    /// Unknown fields do not match: the verdict is
    /// [`FilterVerdict::Unknown`] (counted, visible, never Admitted).
    #[default]
    Exclude,
    /// Unknown fields pass: the verdict is [`FilterVerdict::Admitted`].
    /// Loud opt-in only.
    Include,
}

/// Per-request filter. Every field is optional (`None` = unconstrained);
/// set fields must ALL match for admission. Filters run after
/// identity/correlation ingestion, per request — never per edge — so an
/// admitted completion follows its request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContextFilter {
    /// Constrain submitter pid (exact match).
    pub submitter_pid: Option<u32>,
    /// Constrain submitter uid (exact match).
    pub submitter_uid: Option<u32>,
    /// Constrain submitter comm (exact match).
    pub submitter_comm: Option<String>,
    /// What happens to records whose constrained field is unknown.
    pub unknown_policy: UnknownPolicy,
}

/// Filter verdict for one request. Filtered and unknown are SEPARATE
/// populations: `FilteredOut` failed a constraint, `Unknown` could not
/// be evaluated under the filter's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    /// Admitted (all constraints matched, or unknowns included).
    Admitted,
    /// A set constraint failed on a known field.
    FilteredOut,
    /// A set constraint met an unknown field under
    /// [`UnknownPolicy::Exclude`].
    Unknown,
}

/// Applies `filter` to one request's contexts. EVERY set constraint
/// is evaluated (P6-N6): a known mismatch on ANY constrained field
/// decides [`FilterVerdict::FilteredOut`] immediately — an
/// included unknown satisfies ONLY its own field and never
/// short-circuits a later mismatch. Fields the request cannot
/// answer (`None` submitter, `None` constrained scalar) resolve
/// through the filter's [`UnknownPolicy`] ONLY when no known
/// mismatch decided first. The completion is never evaluated
/// separately: admission is per request, so an admitted completion
/// follows.
#[must_use]
pub fn apply_filter(req: &RequestContext, filter: &ContextFilter) -> FilterVerdict {
    let mut saw_unknown = false;
    if let Some(want) = filter.submitter_pid {
        match req.submitter.as_ref() {
            None => saw_unknown = true,
            Some(sub) if sub.lifetime.pid != want => return FilterVerdict::FilteredOut,
            Some(_) => {}
        }
    }
    if let Some(want) = filter.submitter_uid {
        match req.submitter.as_ref().and_then(|sub| sub.uid) {
            None => saw_unknown = true,
            Some(got) if got != want => return FilterVerdict::FilteredOut,
            Some(_) => {}
        }
    }
    if let Some(want) = filter.submitter_comm.as_deref() {
        match req.submitter.as_ref().and_then(|sub| sub.comm.as_deref()) {
            None => saw_unknown = true,
            Some(got) if got != want => return FilterVerdict::FilteredOut,
            Some(_) => {}
        }
    }
    if saw_unknown {
        match filter.unknown_policy {
            UnknownPolicy::Exclude => FilterVerdict::Unknown,
            UnknownPolicy::Include => FilterVerdict::Admitted,
        }
    } else {
        FilterVerdict::Admitted
    }
}

/// Separate tallies for the three verdict populations. Every evaluated
/// request lands in exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FilterTally {
    /// Admitted requests.
    pub admitted: u64,
    /// Requests failing a constraint on a known field.
    pub filtered_out: u64,
    /// Requests unresolvable under the filter's unknown policy.
    pub unknown: u64,
}

impl FilterTally {
    /// Records one verdict.
    pub fn record(&mut self, verdict: FilterVerdict) {
        match verdict {
            FilterVerdict::Admitted => self.admitted = self.admitted.saturating_add(1),
            FilterVerdict::FilteredOut => self.filtered_out = self.filtered_out.saturating_add(1),
            FilterVerdict::Unknown => self.unknown = self.unknown.saturating_add(1),
        }
    }

    /// Total evaluated requests (the three populations sum exactly —
    /// saturating, so an overflowed tally reads huge, never wraps to a
    /// clean-looking small number).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.admitted
            .saturating_add(self.filtered_out)
            .saturating_add(self.unknown)
    }
}

/// One named aggregate population with explicit units, bucket bounds,
/// and an exact sample count. Aggregates are independent of sampled
/// details: [`Histogram::observe`] sees every observation, while
/// [`Histogram::render_with_cap`] may sample the DETAIL rows — and
/// announces the mode change when it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    /// Population name (e.g. `submit_bytes`, `terminal_latency_ns`).
    name: String,
    /// Unit word (e.g. `bytes`, `ns`).
    unit: String,
    /// Inclusive upper bounds, ascending (the last bucket is
    /// `> bounds.last`, always present as the overflow bucket).
    bounds: Vec<u64>,
    /// Per-bucket counts (`bounds.len() + 1` entries).
    counts: Vec<u64>,
    /// Exact observations folded (the aggregate population size).
    samples: u64,
}

impl Histogram {
    /// New histogram over `bounds` (sorted, deduplicated; empty bounds
    /// mean a single overflow bucket).
    #[must_use]
    pub fn new(name: &str, unit: &str, mut bounds: Vec<u64>) -> Self {
        bounds.sort_unstable();
        bounds.dedup();
        let buckets = bounds.len() + 1;
        Self {
            name: name.to_owned(),
            unit: unit.to_owned(),
            bounds,
            counts: vec![0; buckets],
            samples: 0,
        }
    }

    /// Folds one observation into its bucket (exact: every call counts).
    pub fn observe(&mut self, value: u64) {
        let bucket = self
            .bounds
            .iter()
            .position(|b| value <= *b)
            .unwrap_or(self.bounds.len());
        if let Some(count) = self.counts.get_mut(bucket) {
            *count = count.saturating_add(1);
        }
        self.samples = self.samples.saturating_add(1);
    }

    /// Exact folded population size.
    #[must_use]
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Renders the aggregate with at most `cap` detail rows. The
    /// aggregate line always names the exact population (`samples=N`);
    /// when `cap` samples the details, the render announces
    /// `mode=sampled` (a mode change, never silent).
    #[must_use]
    pub fn render_with_cap(&self, cap: usize) -> String {
        let mut out = String::new();
        let _ = write!(
            out,
            "population={} unit={} samples={} bounds={:?} counts={:?}",
            self.name, self.unit, self.samples, self.bounds, self.counts,
        );
        let details = (self.samples as usize).min(cap);
        let _ = write!(out, " details={details}");
        if (self.samples as usize) > cap {
            out.push_str(" mode=sampled");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who_key() -> KWhoKey {
        KWhoKey {
            kh: 0xc2,
            tgid: 100,
            _pad: 0,
        }
    }

    fn who_val() -> VWho {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        VWho {
            comm,
            tid: 101,
            uid: 1000,
            cgroup: 7,
            ppid: 1,
            pcomm: [0u8; 16],
            stack: 3,
            calls: 9,
            first_ns: 10,
            last_ns: 20,
        }
    }

    #[test]
    fn from_who_maps_identity_honestly() {
        let sub = SubmitterContext::from_who(&who_key(), &who_val(), Some(50_000));
        assert_eq!(
            sub.lifetime,
            TaskLifetime {
                pid: 101,
                tgid: 100,
                start_marker: Some(50_000),
            }
        );
        assert_eq!(sub.comm.as_deref(), Some("bash"));
        assert_eq!(sub.uid, Some(1000));
        assert_eq!(sub.cgroup, Some(7));
        assert_eq!(sub.ppid, Some(1));
        // First-seen stack id: sampled, never per-observation full.
        assert_eq!(sub.stack, StackMarker::Sampled);
    }

    #[test]
    fn from_who_marks_absent_stack_and_failed_parent() {
        let mut val = who_val();
        val.stack = -22;
        val.ppid = 0;
        let sub = SubmitterContext::from_who(&who_key(), &val, None);
        assert_eq!(sub.stack, StackMarker::Missing);
        assert_eq!(sub.ppid, None, "ppid 0 is chase failure, not init");
        assert_eq!(sub.lifetime.start_marker, None, "unqualified lifetime");
        assert_eq!(
            sub.lifetime.verdict_against(&sub.lifetime),
            LifetimeVerdict::Unknown,
            "a markerless lifetime never joins, even with itself"
        );
    }

    #[test]
    fn lifecycle_contexts_are_explicitly_unobserved() {
        let req = RequestContext::lifecycle_unobserved("req:9", "evidence:v1", "rule:v1");
        assert_eq!(req.submitter, None);
        assert_eq!(req.execution, ExecutionContext::unknown());
        assert_eq!(req.execution.origin(), OriginClaim::Unavailable);
        assert_eq!(req.completion, None);
        // Under an excluding filter the unobserved request lands in the
        // unknown population — counted, never admitted-by-default.
        let filter = ContextFilter {
            submitter_pid: Some(100),
            ..Default::default()
        };
        assert_eq!(apply_filter(&req, &filter), FilterVerdict::Unknown);
    }

    #[test]
    fn consumer_label_preserves_original_versions() {
        let req = RequestContext::lifecycle_unobserved("req:9", "evidence:v1", "rule:v1")
            .with_consumer_label("consumer:dashboard");
        assert_eq!(req.consumer_label.as_deref(), Some("consumer:dashboard"));
        assert_eq!(req.evidence_version, "evidence:v1");
        assert_eq!(req.rule_version, "rule:v1");
    }

    #[test]
    fn process_completion_follows_its_request() {
        let lifetime = TaskLifetime {
            pid: 101,
            tgid: 100,
            start_marker: Some(50_000),
        };
        let completion = CompletionContext::follows(ExecutionContext::process(lifetime));
        assert!(completion.follows_request);
        assert_eq!(completion.landed.origin(), OriginClaim::Proved(lifetime));
    }

    fn filtered_request() -> RequestContext {
        // Matching pid, MISSING uid, KNOWN comm mismatch: the comm
        // mismatch is decisive whatever the unknown policy says.
        let sub = SubmitterContext {
            lifetime: TaskLifetime {
                pid: 101,
                tgid: 100,
                start_marker: Some(50_000),
            },
            comm: Some("different".to_owned()),
            uid: None,
            cgroup: Some(7),
            ppid: Some(1),
            stack: StackMarker::Missing,
        };
        RequestContext {
            request_id: "req:filter".to_owned(),
            submitter: Some(sub),
            execution: ExecutionContext::unknown(),
            completion: None,
            evidence_version: "evidence:v1".to_owned(),
            rule_version: "rule:v1".to_owned(),
            consumer_label: None,
        }
    }

    #[test]
    fn known_mismatch_dominates_included_unknown() {
        // P6-N6 RED: include-unknown must satisfy ONLY its own field
        // — a known comm mismatch still filters out.
        let req = filtered_request();
        let filter = ContextFilter {
            submitter_pid: Some(101),
            submitter_uid: Some(1000),
            submitter_comm: Some("wanted".to_owned()),
            unknown_policy: UnknownPolicy::Include,
        };
        assert_eq!(apply_filter(&req, &filter), FilterVerdict::FilteredOut);
    }

    #[test]
    fn known_mismatch_dominates_excluded_unknown() {
        // Same decisive mismatch under Exclude (unknown would ALSO
        // refuse — but the verdict is FilteredOut, never Unknown).
        let req = filtered_request();
        let filter = ContextFilter {
            submitter_pid: Some(101),
            submitter_uid: Some(1000),
            submitter_comm: Some("wanted".to_owned()),
            unknown_policy: UnknownPolicy::Exclude,
        };
        assert_eq!(apply_filter(&req, &filter), FilterVerdict::FilteredOut);
    }

    #[test]
    fn unknown_resolves_via_policy_absent_mismatch() {
        // No known mismatch: the missing uid resolves through the
        // policy (Include admits, Exclude counts unknown).
        let req = filtered_request();
        let include = ContextFilter {
            submitter_pid: Some(101),
            submitter_uid: Some(1000),
            submitter_comm: Some("different".to_owned()),
            unknown_policy: UnknownPolicy::Include,
        };
        assert_eq!(apply_filter(&req, &include), FilterVerdict::Admitted);
        let exclude = ContextFilter {
            unknown_policy: UnknownPolicy::Exclude,
            ..include
        };
        assert_eq!(apply_filter(&req, &exclude), FilterVerdict::Unknown);
    }

    #[test]
    fn markerless_process_origin_is_unavailable() {
        // P6-N7 RED: a claimed process lifetime without a start
        // marker proves nothing (task: missing lifetime marker
        // stays unavailable).
        let lifetime = TaskLifetime {
            pid: 100,
            tgid: 100,
            start_marker: None,
        };
        assert_eq!(
            ExecutionContext::process(lifetime).origin(),
            OriginClaim::Unavailable
        );
    }

    #[test]
    fn markerless_handoff_origin_is_unavailable() {
        // Same rule for worker handoffs: a markerless originator is
        // unavailable, never proved.
        let worker = TaskLifetime {
            pid: 7,
            tgid: 7,
            start_marker: Some(11),
        };
        let origin = TaskLifetime {
            pid: 100,
            tgid: 100,
            start_marker: None,
        };
        let exec = ExecutionContext {
            kind: ExecutionKind::Worker {
                worker,
                handoff: Some(origin),
            },
        };
        assert_eq!(exec.origin(), OriginClaim::Unavailable);
    }

    #[test]
    fn marked_origins_stay_proved() {
        // The qualification keeps every honestly-marked claim: a
        // marked process proves itself, a marked handoff proves its
        // originator.
        let lifetime = TaskLifetime {
            pid: 100,
            tgid: 100,
            start_marker: Some(50_000),
        };
        assert_eq!(
            ExecutionContext::process(lifetime).origin(),
            OriginClaim::Proved(lifetime)
        );
        let exec = ExecutionContext {
            kind: ExecutionKind::Worker {
                worker: TaskLifetime {
                    pid: 7,
                    tgid: 7,
                    start_marker: Some(11),
                },
                handoff: Some(lifetime),
            },
        };
        assert_eq!(exec.origin(), OriginClaim::Proved(lifetime));
    }
}
