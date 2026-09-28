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
