<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto profile support table (P6)

Profile × family × boundary × provider × kernel, checked against the
hook lists and the test suites below — not against release strings.
"Supported" means hooks attach, rows flow, and the cited suites assert
the boundary on that kernel. Anything else is an explicit refusal or
an explicit unknown, never a silent gap.

Evidence basis: accepted P3–P5 records and coverage at `88757d6`
(hook lists verified in-tree; suite names verified in-tree). T11
re-verifies the cited guest cells on 7.0.14 + 7.2.6 with controls
(see the T11 handoff); until then the kernel column carries the
accepted prior verdicts forward, marked as such.

## Hook basis (verified)

api-returns (fexit, `KCRYPTO_SYMBOLS` in
`crates/kryprobe-privilege/src/btf_resolve.rs`):

- `crypto_alloc_tfm_node`, `crypto_destroy_tfm`
- `crypto_skcipher_encrypt`, `crypto_skcipher_decrypt`
- `crypto_aead_encrypt`, `crypto_aead_decrypt`
- `crypto_ahash_digest`, `crypto_shash_digest`, `crypto_shash_finup`

request-lifecycle (fsession required + fentry callbacks,
`LIFECYCLE_REQUIRED`/`LIFECYCLE_CALLBACKS` in
`crates/kryprobe-privilege/src/kcrypto_lifecycle/profile.rs`):

- skcipher: `crypto_skcipher_encrypt`, `crypto_skcipher_decrypt`,
  `crypto_alloc_skcipher`, `crypto_destroy_tfm`,
  `crypto_skcipher_setkey`
- AEAD: `crypto_aead_encrypt`, `crypto_aead_decrypt`,
  `crypto_alloc_aead`, `crypto_aead_setauthsize`,
  `crypto_aead_setkey`
- callbacks (attach-if-present, never gating):
  `cryptd_skcipher_complete` (module `cryptd`),
  `kxc_complete` (module `kcrypto_fixture`)

No hash hooks exist under request-lifecycle. No update/final hash
hooks exist under either profile.

## api-returns

| Family | Boundary (what rows prove) | Provider / completion | 6.12.111 | 7.0.14 | 7.2.6 | Tests |
|---|---|---|---|---|---|---|
| skcipher | API returns per (op, result, context); caller contexts (who rows); params + first failure | Selected driver observed per row; provider-body entry unproven (F03); `-EINPROGRESS`/`-EBUSY` read `queued`, never completion | supported | supported | supported | `kcrypto_agg` (`skcipher_exactness`), `kcrypto_canary`, `kcrypto_who` |
| AEAD | Same return/context boundary as skcipher | Same provider limits as skcipher; bad-tag decrypt proven live as `errors` | supported | supported | supported | `kcrypto_agg` (`aead_exactness_and_bad_tag_errors`), `kcrypto_canary` |
| ahash | `digest` returns only | Same provider limits; native ahash routes outside the shash finup expectation | supported | supported | supported | `kcrypto_agg`, `kcrypto_snapshot`, `kcrypto_driver` |
| shash | `digest` + `finup` returns only (no update/final) | Same provider limits; finup bytes sum observed `len` only | supported, route note 1 | supported | supported, route note 2 | `kcrypto_agg`, `kcrypto_driver`, `cli_e2e`, `live_session` |
| alloc | Transform selection + requested names; destroy counted as skip only (no exit-edge read — C7) | Failed setup (incl. early ENOKEY) claims no provider entry, no work | supported | supported | supported | `kcrypto_agg`, `kcrypto_canary` |

Route note 1 (6.12.111): multipart messages ending with an empty send
use the unhooked update/final APIs — zero finup proves nothing there.
Route note 2 (7.2.6): shash update/final wrappers route through finup
instead. See `docs/kcrypto-evidence.md`.

## request-lifecycle

| Family | Boundary (what rows prove) | Provider / completion | 6.12.111 | 7.0.14 | 7.2.6 | Tests |
|---|---|---|---|---|---|---|
| skcipher | Per-request submit/terminal/status/latency; transform generations + config epochs; exact native errnos | Selected driver per submit (`drv`); sync terminals exact; async terminals only where a callback site attaches (else `Unknown`) | REFUSED (typed `Unsupported` — predates fsession) | supported | supported, refcount note | `kcrypto_requests`, `kcrypto_async`, `kcrypto_tfm_lifecycle`, `kcrypto_semantics`, `kcrypto_lifecycle_sensor`, `kcrypto_lifecycle_backend` |
| AEAD | skcipher boundary + `assoclen`/`authsize`/tag semantics (P5 wire v7; populations never relabeled) | Same completion rule as skcipher; fabricated creation type/mask/truncation refused | REFUSED (same floor) | supported | supported | `kcrypto_aead_lifecycle`, `kcrypto_lifecycle_*` |
| ahash / shash | NOT OBSERVED (no hooks) | — | — | — | — | — (absence is the contract) |
| transform mgmt | Generations (alloc/destroy pairs), config epochs (setkey/setauthsize), registry enrichment available/unavailable | Failed alloc claims no generation; unbound destroys ride inventory, never loss | REFUSED (same floor) | supported | supported, refcount note | `kcrypto_tfm_lifecycle`, `kcrypto_lifecycle_sensor` |

Refcount note (7.2+): the kernel removed the tfm refcount, so the
retained-vs-final destroy shape differs from 7.0 (`refcnt_present`
gates the read; the sensor lane pins the host ingest shape and
kernel-excludes that in-guest scenario — see
`kcrypto_lifecycle_sensor.rs`).

Floor note: the request-lifecycle discriminator is fsession attach
acceptance (type 58) at load, not the release string and not kfunc
presence (the session kfuncs exist as vmlinux BTF FUNCs even on
6.12). 7.0.14 reports attach type 0 for fsession links — monitored
drift, never pinned. See ADR-0006 and `docs/deployment.md`.

## Contexts, filters, streaming (P6)

| Surface | api-returns | request-lifecycle |
|---|---|---|
| Submitter context | From who rows (tgid/tid/comm/uid/cgroup/ppid/sampled stack) + userspace start-marker lifetime reads; PID reuse is a new lifetime; CLI `--filter-pid`/`--filter-uid`/`--filter-comm` constrain it post-ingestion | Explicitly unavailable (frozen edges carry no task identity; never guessed) |
| Execution context | Process (the observed API ran in the caller's context) | `Unknown` (no proved handoff exists on this path) |
| Completion context | The observed return, in process context | Follows its admitted request; rows never split by filter (landing site unobserved) |
| Filters | After ingestion, per request (`Exclude` policy from the CLI); proved mismatches hide, unevaluable rows stay visible; admitted/filtered/unknown tallied on the FILTER line + `filter_*` coverage counters; `comm` is the decoded display name (lossy UTF-8), so `--filter-comm` matches the rendered identity exactly | Same engine; unobserved contexts land in `Unknown` under `Exclude` and still render; tallies additionally ride the envelope coverage record (exact unknown-union + filtered) |
| Session streaming | Event-v0 JSONL (unchanged, frozen) | Versioned session envelope (`lifecycle-session/v1`) with run-unique `session:live-*` id, start/observations/coverage/receipt; receiptless streams are truncated, never clean |

## P8 real-consumer re-verification (T13)

Head `f938fe6`, 11/11 sealed cells PASS (campaign PASS;
`docs/kcrypto-matrix.md`). The api-returns rows above are
re-verified on live consumers on all three kernels with
kernel-exact oracles (product == ftrace on every traced
function, or exact attribution equations where no kernel
reference exists):

- skcipher/dm-crypt (R02, 7.0.14 + 7.2.6): 64 MiB bounded I/O
  each direction, checksums match, 131072/131072 exact with
  per-direction byte equality plus integral-average 512 B/call
  consistency (average-only, not a uniformity proof); wrong-key
  mismatch is the in-cell negative control; quiet windows 0/0.
- AEAD/ESP-XFRM (R03, 7.0.14 + 7.2.6): owned netns/veth with
  authenc(hmac(sha256),cbc(aes)) SAs; 1000/1000 delivered both
  directions per kernel; wrong-key leg 100 sent / 0 received
  with kernel-equality on the authfail counts (nesting-aware);
  packet totals stay contextual (state/packet ledgers), never
  equated to API calls.
- ahash/shash fixture + floor (R01): deterministic 10-row
  ledgers identical across legs on 7.x (validate rc 0/0,
  attach 9/9); 6.12 floor proves hash 20 + skcipher 10x2 with
  product == ftrace exactly, and the request-lifecycle floor
  refusal stays typed (`kcrypto_fsession_unavailable`, attach
  type 58 refused, exit 4).
- Negatives (R04, both 7.x kernels): unprivileged capture
  refuses exit 4 (`live session unusable`, control workload
  kernel-proved); foreign-traffic cells prove unique owned
  correspondence (outer ahash 20:6, bind-alloc 1:1, who ==
  agg exactly, zero unattributed rows) — aggregate totals
  cannot absorb the decoy.

Route note 3 (T13, all kernels): the nested hash route below
the outer ahash call is scatterlist/page-layout-shaped PER
BURST, not per kernel or per release: identical fixture bytes
take digest-1x, finup-1x, or finup-2x arms on different runs
(digest-1x on the 6.12 floor seal this wave, sealed 20/20/0
kernel == product, and on both 7.x foreign seals, sealed
26/26/0 product; finup-1x on the superseded 6.12 floor
seals, sealed 20/0/20; finup-2x on a superseded 7.0.14
foreign seal). The T13
oracles admit exactly these arms. Simultaneous product ==
kernel equality on `crypto_ahash_digest`, `crypto_shash_digest`,
and `crypto_shash_finup` is claimed only where an ftrace
reference binds all three functions (the 6.12 floor aggregate
leg); each seal records its arm, so the taken arm never affects
exactness there. R04-foreign cells carry no kernel reference
(attribution proof only, never kernel equality). R04-deny
controls trace the digest functions only: their finup
observations (0 finups for 10 outer calls on both 7.x deny
controls this wave, sealed 10/10/0 product with 10/10
kernel-ref and no finup reference; 20 finups for 10 outer
calls on the superseded 7.2.6 deny seals) are explicitly
unqualified residuals, as is any finup-2x arm taken outside a
kernel-referenced leg. Pinning any single nested shape (e.g.
shash_digest == issued) is unprovable and must not be
reintroduced.

## P9 release-candidate promotion (T14)

Wave head `task/kcrypto-t14` (final SHA + tree in
`docs/release-ledger.md` and the T14 HANDOFF), budgets frozen
before sampling (`docs/bench-thresholds.md` P9 section;
manifest `tests/kcrypto_perf/cells.json`). Five workload
classes (64 B,
4 KiB, 1 MiB skcipher; high-rate AEAD; deliberately async) ×
observer modes (disabled baseline, aggregation, full details)
in 5 attempted alternating A/B pairs per set (10 s warm-up +
30 s measurement; aggregate sets qualified 5/5, all det and
floor sets 0/5 — see verdicts below), one vng guest per set
on 7.0.14 + 7.2.6 with
6.12.111 floor aggregate sets, plus attached-idle footprint
legs, per-op reference-perturbation controls, and one
many-submitter stack probe. Every observed leg reconciles
exactly with its independent driver ledger (7.x flat 1 call
per op per direction; 6.12 floor nested 1:1 outer+inner;
async EINPROGRESS/queued with per-GO terminal coverage) with
zero unexpected loss, or the pair is invalid with its reason
preserved — never dropped, never averaged away.

Budget verdicts (qualified 4 KiB / 1 MiB aggregate sets only;
median plus ≥80% of pairs inside, else INCONCLUSIVE):

- `perf-P-4K-agg-7014`: FAIL (B1 FAIL median 0.819,
  B2 FAIL median 1.222; 5/5 pairs, all miss both)
- `perf-P-1M-agg-7014`: INCONCLUSIVE (spread 0.84–1.13,
  only 2/5 inside; medians 0.940/1.072)
- `perf-P-4K-agg-726`: FAIL (B1 FAIL median 0.805,
  B2 FAIL median 1.203; 5/5 pairs, all miss both)
- `perf-P-1M-agg-726`: PASS (B1/B2 PASS; medians
  0.967/1.050)

Published envelopes (no budget; measured operating data, see
the campaign report): 64 B + AEAD + async aggregate ratios.
NO detail-mode ratio is published anywhere: every flat det
set truncates at the 100,000-observation bound (offered
28–44x the cap on sync classes), and every below-cap det leg
(1 MiB flat-out both kernels; 64 B / 4 KiB / AEAD paced at
1000 ops/s on 7.0.14) carries counted
`adapter.tombstone_evictions`, failing the frozen `loss ==
{}` detail rule — all 13 det sets INVALID with reasons
preserved. Reported instead: truncation points, below-cap
absolute operating data (never ratioed), async detail
envelope-only (terminals `Unknown`, `unfinished` == offered),
6.12 floor absolute operating data with pairs INVALID
(`destroy_skip == 3` vs the flat pin `== 1`; see the report),
attached-idle CPU/RSS per kernel, and first-seen stack
attribution counts from the aggregation who rows. Lifecycle
on the 6.12 floor refuses typed exit 4
(`kcrypto_fsession_unavailable`).

Mode resolutions: stack sampling is NOT_RUN as a standalone
mode (no product toggle — R1 stacks are first-seen-only
attribution inside api-returns; the lifecycle object captures
no stacks), with stack observables reported from the
aggregation cells plus the `diag-stack-7014` probe.
Attached-idle is an observer-footprint leg, not a workload
pair. The api-returns `lat[8]` array is unpopulated (zeros);
workload latency comes only from the independent driver
ledger. P7 E08 on 7.2.6 stays NOT_RUN (accepted P7 residual);
X01–X03/D01–D08 remain the separate P10 demo scope.

## Explicit non-goals (both profiles)

- Keys, IVs, plaintext/ciphertext, AAD/tag bytes, digest outputs, RNG
  output, scatterlist contents, callback private data, raw kernel
  pointers — never read, stored, or emitted (NEVER list in
  `docs/kcrypto-capture-allowlist.md`). Exception: first-seen
  kernel-stack IPs ride the allowlisted api-returns `stack.frames`
  path only (`docs/kcrypto-capture-allowlist.md`, `observe.rs`
  `observation_for_who`) — sampled attribution frames, never raw
  pairing pointers.
- Softirq attribution: no stable in-BPF detector (api-returns `ctx`
  never writes `SOFTIRQ`; softirq execution never names a user origin).
- Per-request caller identity under request-lifecycle (BPF frozen
  without task fields — contexts stay explicit-unknown).
- Hash request lifecycles (no hooks, no plans in this scope).
