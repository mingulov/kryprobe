<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Attach policy: who may observe a scope, and follow-fork rules (FU4)

One uprobe-multi link filters on one pid, so `Tree`/`Cgroup` scopes
attach as userspace fan-out: the scope resolves to admitted member
pids, and each member gets its own link through the unchanged Pid
path. This document is the policy; the mechanism is
`crates/kryprobe-privilege/src/fanout.rs`, entered only through
`LocalPrivilegedAuthority::resolve_scope` / `refresh_fanout`.
Generation semantics (fork/exec/reuse) follow ADR-0003; this policy
covers admission only. The single-link entry (`attach_group`) still
rejects non-Pid scopes: fan-out plans must be resolved first.

## Who may observe

Observability is exactly inspectability. A member is admittable if
and only if the inspection facet (`TargetInspectionAuthority::inspect`:
pidfd pin + bounded `/proc` reads) succeeds on it. No separate
identity check exists: pidfd + `/proc` permission checks already
encode same-user-or-privileged (Yama scope and `CapEff` ride along as
context notes, never as gates). Consequences:

- Observing your own tree/cgroup works unprivileged; observing
  another user's processes requires the privilege that makes
  `inspect` succeed (typically `CAP_SYS_PTRACE` or uid match).
- A BPF token authorizes BPF operation categories, never target
  confinement: token-delegated loads still fan out through this same
  per-member admission.
- There is no "observe the cgroup directory" privilege: a cgroup
  path is only an enumeration source. Readable `cgroup.procs` files
  list candidates; per-member `inspect` admits them.

## Admission rules

- `Pid` attaches directly via `attach_group`; it is not a fan-out
  scope and `resolve_scope` rejects it (use the link path).
- `OwnedRun` rejects: it has no session spawner (declined: no
  backend consumer), so it is not a fan-out scope.
- `Tree{root}`: root 0 rejects; a gone root rejects; a denied root
  rejects. Members are the root plus all descendants enumerated via
  `/proc/<pid>/task/*/children`.
- `Cgroup{path}`: an empty or NUL-bearing path rejects; a missing
  path, a non-directory, or a directory without `cgroup.procs`
  rejects. Members are enumerated from `cgroup.procs` recursively;
  symlinks are not followed and visited (dev, ino) pairs are
  skipped, so bind mounts cannot cycle the walk.
- Any live-but-denied member rejects the whole scope: a subset
  attach without a coverage channel would be silent, so fail-closed
  refuses it. The rejection names the pid and stage.
- An exited member (gone between enumeration and admission) is
  skipped with an exact `exited_during_resolve` receipt: exit races
  are inherent, and exited processes emit no events.
- Admission beyond `max_targets` rejects without partial attach;
  the budget counts admitted members, not raw candidates.
- An unreadable-for-permission enumeration file rejects; a
  not-found one skips (exit/rmdir race). Unparseable pid text
  rejects: fail-closed on corrupt input.
- Known TOCTOU window: a pid can be reused between enumeration and
  admission, admitting a same-pid process that is not a true member.
  The admitted process still passed `inspect` (the observer may
  already observe it), and refresh re-validates; the window is
  microseconds and the prize is nil. Documented, accepted.

## Follow-fork rules

- Fork creates a new process lifetime (ADR-0003): a child is never
  covered by its parent's link. Under `Pid` scope the child is out
  of scope and needs no action (pid-filtered links cannot see it).
- Under `Tree` scope, follow-fork is poll-based re-resolution:
  `refresh_fanout` re-resolves the plan's scope through the same
  admission gates and returns an added/exited diff. There is no
  kernel fork hook in the spine; the drain-side join (ADR-0003)
  stays the backstop against misattribution.
- A newly seen pid admits exactly like an initial member
  (`inspect` + budget); a denied newcomer fails the whole refresh
  and the caller keeps the last good plan.
- A reused pid (same number, new start-time) reports as an exited
  old member plus an added new one, never a silent carry: identity
  is (pid, start-time).
- Exit receipts accumulate across refreshes so follow-fork churn
  stays visible on the plan.
- Under `Cgroup` scope the same refresh applies: members that leave
  the subtree report as exited, joiners admit as added.

## Mechanism

`FanoutPlan::link_groups` stamps one Pid-scoped link group per
member from a template (object, program, entry, generation); each
group attaches via the unchanged `attach_group` gates (generation
guard, offsets, path checks). An empty plan yields zero links: an
honest no-op, not an error. No BPF, ABI, or authority-trait change
was needed: fan-out is userspace code behind two inherent facet
methods on `LocalPrivilegedAuthority`.

## Cookie/index namespace (T9)

Cookies are `(generation << 32) | index` with `index` in `0..64`
(frozen by the BPF `COUNT` map). Two groups sharing a generation and
indices would merge `COUNT[idx]`, so index ranges are
driver-owned: `CookieAllocator` (`kryprobe-core/src/attach.rs`,
held as session state by `BackendDriver`) issues disjoint ranges per
group, and each `LinkGroup` is built solely through
`LinkGroup::from_range` over an issued range (issuance-only: no
hand-built base). Rules:

- One allocator per (session, `COUNT` map, generation); ranges never
  overlap within a generation.
- The allocator is never `Copy` (a copy would fork the namespace);
  each range carries its issuing allocator's generation, so cookies
  stamp the issuance — never a caller-supplied value.
- The attach boundary re-validates (`base + len <= 64`) and rejects
  overflows before the syscall; a lying base cannot alias.
- Exhaustion refuses with `CookieExhausted` (fail closed, never
  alias): the caller attaches nothing, so no loss counter accrues
  and the T6 exactly-once rollup is unaffected.
- Generations partition the namespace: the BPF generation gate drops
  stale cookies, so a new generation starts a fresh allocator and
  reuses index space.
- Fan-out members share their template's range (one logical group);
  per-member index attribution needs TGID multiplexing (future).
- Sequential attach→detach cycles (attach bench) may reuse one range:
  only one link is live at a time.
