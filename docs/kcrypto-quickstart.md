<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# KryProbe kernel-crypto quick start (R1 release candidate)

Observe kernel crypto API use (skcipher/AEAD/hash call returns,
transform selection, submitter attribution) on a supported Linux
kernel. This page goes from a release bundle to a first verified
capture in five steps; `docs/deployment.md` is the full privilege
runbook and `docs/kcrypto-support.md` is the support table with
the release's measured limits.

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
  nonzero unexpected-loss counter (`ktot_gap`, `ring_drops`,
  `overflow_identities`, `predrop_*` except the C7-expected
  `destroy_skip`) takes the measurement outside the qualified
  envelope — re-run quieter or shorter, do not ratio it.
- `verdict: partial` with `missing: [capture-integrity,
  completion]` is the declared honest state, not a failure.

For per-request detail (submit/terminal/status/latency rows)
use `--kcrypto-profile request-lifecycle` — supported on 7.x
only (typed refusal on the 6.12 floor), bounded at 100,000
observations per capture with explicit truncation, and hash
lifecycles are not observed under either profile.

## 5. Know the limits (read before publishing numbers)

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

Support window, kernel floor, and accepted residuals:
`docs/kcrypto-support.md`. Release identity and evidence map:
`docs/release-ledger.md`.
