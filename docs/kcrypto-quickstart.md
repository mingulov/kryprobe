<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# KryProbe kernel-crypto quick start (v0.1.0)

Observe kernel crypto API use (skcipher/AEAD/hash call returns,
transform selection, submitter attribution) on a supported Linux
kernel. This page goes from a release bundle to a first verified
capture in five steps; `docs/deployment.md` is the full privilege
runbook and `docs/kcrypto-support.md` is the support table with
the release's measured limits. Section 6 adds the M1 workload
views (grouped reports, cgroup filters, metadata binding) as
three recipes.

The [first-release notes](releases/v0.1.0.md) state the owner-approved
scope and remaining qualification gaps. Full R1 performance qualification
is incomplete.

## 1. Install the release bundle

From a pinned release stage (built by
`packaging/build-release.sh`, shipped with `manifest.json` v2 +
`sha256sums.txt`):

```sh
sudo packaging/install.sh --stage /owned/pkg-YYYYMMDD
```

This installs the binary plus both kcrypto BPF objects into
`$PREFIX/bin/kryprobe{,-bpf/}`, grants file capabilities, and
verifies the install. It refuses anything but a byte-exact v2
stage — a missing or swapped object fails closed, never loads
a stray file.

## 2. Verify the install

```sh
kryprobe doctor --versions
kryprobe token status
kryprobe doctor
```

`doctor --versions` must report `pins_enforced: true` with both
object digests; `token status` shows the file-cap grant;
`doctor` shows the capability probe matrix (`Pass` on all nine
kcrypto attach points on a supported kernel).

## 3. First capture (bounded, unprivileged-readable output)

```sh
kryprobe report --system --duration 30 --format json --out first.json
```

`report --system` attaches the api-returns sensor for 30 seconds
and renders aggregate call counts, caller attribution (who
rows), and a coverage receipt. Exit 0/3 with a `partial`
verdict is normal (completion is unobserved by design — see
step 5). Exit 4 names the missing capability instead of
guessing (see `docs/runbook.md` for the exit-4 triage tree).

## 4. Read the output

- `observations[]` with `"row": "agg"`: per (family, op,
  result) call counts and bytes — the supported quantitative
  boundary.
- `"row": "who"`: submitter attribution (tgid/comm/uid, sampled
  stack id) — supported inference, never a proved user origin.
- `coverage.*`: per-dimension status + loss counters. Any
  nonzero unexpected-loss counter (`ring_drops`, `user_queue_drops`,
  `overflow_identities`, `ctx_overflow_identities`, `predrop_*`
  except the C7-expected `destroy_skip`) takes the measurement
  outside the qualified envelope — re-run quieter or shorter, do
  not ratio it.
- `snapshot_gap_unreconciled` (older diagnostic alias `ktot_gap`) is
  the difference between separate terminal map reads, not a lost-call
  count. Zero does not establish an atomic sample or complete delivery;
  see [evidence semantics](kcrypto-evidence.md).
- `verdict: partial` with `missing: [capture-integrity,
  completion]` is the declared honest state, not a failure.

For per-request detail (submit/terminal/status/latency rows)
use `--kcrypto-profile request-lifecycle` — supported on 7.x
only (typed refusal on the 6.12 floor), bounded at 100,000
observations per capture with explicit truncation, and hash
lifecycles are not observed under either profile. Measured
detail bound (P9 campaign): detail captures retaining more
than ~4096 observations report counted
`tombstone_evictions` loss in the session receipt (4096-entry
adapter FIFO) — size captures to stay below it, or treat
the loss as disqualifying, never as free headroom.

## 5. Know the limits (read before publishing numbers)

- Measured aggregation overhead (P9 campaign, 4 KiB skcipher
  at ~41–47k ops/s): ~18–20% throughput cost and ~20–22%
  tail-latency cost vs tracing-disabled — the release does
  NOT meet a ≤5%/≤10% budget there (both kernels FAIL).
  The measured 7.x 1 MiB workloads cost ~3–6% throughput; the
  7.0.14 budget verdict remains INCONCLUSIVE. The corrected
  6.12 floor measurements show ~26.1%/11.0% throughput cost
  at 4 KiB/1 MiB, with no predefined budget. Never
  publish an overhead number without its workload rate.
- Completion is unobserved: api-returns rows prove API returns,
  never provider-body execution or async completion. Do not
  claim work the rows do not show.
- The bundled performance envelopes (`docs/bench-thresholds.md`
  P9 section, `docs/kcrypto-support.md` §P9) hold only for
  qualified cells: exact driver/product reconciliation, zero
  unexpected loss, rc 0/3, quiet lane. Any measured rate with
  unexplained loss is outside the envelope regardless of
  overhead.
- Async terminals under request-lifecycle are `Unknown` unless
  a callback site attaches; never publish an async latency
  percentile without terminal coverage.
- Pre-attach boot traffic is unobserved. Transform state from
  before attach has unknown provenance (never a fabricated
  allocation).
- The boot demo is initramfs-local: three fresh boots plus late/broken
  observer controls. Continuous capture through `switch_root` is deferred.

Support window, kernel floor, and accepted residuals:
`docs/kcrypto-support.md`. Release identity and evidence map:
`docs/release-ledger.md`.

## 6. Workload reports: what ran where (M1)

Workload views join per-workload crypto call counts to kernel
context (event-time cgroup, thread-group, start time) and,
when metadata binds, to operator workload identities. Context
is observed execution — never a proved user origin, never a
guessed label. All three recipes need the api-returns profile
(the default) and a privileged capture (§1–§3); workload flags
refuse `--format json|jsonl` and the submitter filters
(`--filter-pid/--filter-uid/--filter-comm`), which render or
constrain live observations that carry no workload rows.

### Recipe 1 — what ran: grouped crypto counts

```sh
kryprobe report --system --duration 30 --group-by cgroup
kryprobe report --system --duration 30 --group-by cgroup --format workload-json --out wl.json
kryprobe report wl.json
```

The first command renders per-cgroup call counts with a
coverage trailer (four dimensions: capture, attribution,
metadata, correlation). The second stores the same report as
`kryprobe.workload-report.v2` bytes; the third replays those
bytes with no helper and no host queries — replay-after-exit
renders workloads that are long gone, with exits on the stored
evidence (0 asserted-complete, 3 on stored gaps or raw IDs).

Expect exit 3 on a live capture: the ledger gap is exported
unreconciled by disposition and at least one coverage
dimension reads below complete. Exit 3 with named gaps is the
honest state, not a failure — read the trailer before the
counts.

### Recipe 2 — which cgroups: narrow to one workload

Read the cgroup ids from a recipe-1 capture, then narrow:

```sh
kryprobe report --system --duration 30 --filter-cgroup-id 4021
kryprobe check --system --policy scoped.yaml --filter-cgroup-id 4021
```

`--filter-cgroup-id` takes one exact id (0 refuses — the
unreadable marker is never selectable). The scoped `check`
evaluates that one cgroup view against a scoped policy: exit
10 prints `VIOLATION` plus the exact scoped partition
(`matched=/nonmatched=/unknown_match=`) on stderr, 0 prints
`CLEAN`, 3 prints `INCONCLUSIVE`. Pod and runtime selectors
refuse until M2; `--filter-container` is unsupported (group by
container instead).

### Recipe 3 — why origin unknown: read the raw IDs

Rows without bound metadata render as raw IDs (numeric
cgroup, thread-group, start time — no names, no labels). That
is the product refusing to guess. Diagnose from the coverage
trailer:

- `metadata: unavailable` + a `HelperRefused` note: the helper
  sibling is missing (fresh release-stage installs carry none
  until the Stage-6 layout freezes — a stage install over an
  existing sibling preserves that file instead; dev installs
  ship it), crashed, or refused attestation — capture still
  completes, with raw IDs. Install or repair the sibling and
  re-run; never hand-fill identities into the stored bytes.
- `metadata: partial` with `kernel_mismatch` refusals: the
  metadata snapshot came from a different kernel — the keys
  refuse typed and the rows stay unresolved.
- `attribution: partial` with stale rows: the identity is kept
  and shown, but its validity window does not cover the
  capture interval — the row is marked stale, never promoted.
- Principal rows reading raw IDs under root: root captures
  carry no trusted non-root principal (`NoPrincipal`), so
  launch-scoped metadata cannot bind. Capture as the owning
  user through the file-cap binary instead.

The privileged CLI never parses metadata itself: when no
verified helper can serve the lookup, the rows stay raw and
the coverage says why. Anything stricter than raw IDs needs a
covering metadata file (`--workload-metadata FILE`, bound
after capture through the confined helper) — and even then,
attribution is asserted evidence, not proof of origin.
