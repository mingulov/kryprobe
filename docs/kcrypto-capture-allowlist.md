<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto capture allowlist (K1 sensor v0.1)

Closed list of everything the kcrypto fexit sensor stores in
`KCFG`/`KAGG`/`KTOT`/`KIDN`/`KRING`. Anything not on this list is not
captured; the [NEVER](#never-list) section names the categories the
sensor must never read. Field order and sizes twin
`crates/bpf-kcrypto/src/bin/kcrypto.rs` (BPF owns the originals) and
`crates/kryprobe-abi/src/kcrypto_agg.rs` (userspace mirrors).

Change discipline (deliberate friction, brief Step 2): each mirror
struct carries a manually-maintained `FIELDS` list; the test
`allowlist_field_set_matches_docs`
(`crates/kryprobe-abi/tests/kcrypto_allowlist.rs`) pins every list
against a hardcoded expectation AND against this doc (each field must
appear backticked below). The privileged `canary_kcrypto` suite
(`crates/kryprobe-privilege/tests/kcrypto_canary.rs`) byte-scans every
map + ring dump for `KPROBE-CANARY` markers planted in key and
plaintext fixture buffers. A new captured field moves all four —
struct, `FIELDS`, this doc, canary reasoning — or fails the build.

Privacy anchor: kp2 §9 ("Privacy boundary"). kp2 §9 forbids reading or
publishing keys, IV, nonce, plaintext, ciphertext, AAD, digest
outputs, signatures, RNG output, scatterlist contents, arbitrary
buffers, and callback private data; it allows only bounded
algorithm/driver/module names, family and operation, scalar byte
counts, return/error class, timestamps, PID/TGID/comm/cgroup metadata,
and kernel/build metadata. Every field below cites the §9 category it
falls under (plus the sharper kp2 section where one exists).

## `KCFG`: loader-written config, not observations (40B `KConfig`)

Written once by `load_kcrypto_configured` from live-BTF resolution
(`kconfig_from_offsets`); never touched by traffic. WHY: kernel/build
metadata (kp2 §9) — the running kernel's struct layout, without which
the BPF cannot chase request→tfm→algorithm.

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `sk_req_base` | u32 | BTF `skcipher_request.base` | kernel layout metadata |
| `async_tfm` | u32 | BTF `crypto_async_request.tfm` | kernel layout metadata |
| `tfm_alg` | u32 | BTF `crypto_tfm.__crt_alg` | kernel layout metadata |
| `alg_name` | u32 | BTF `crypto_alg.cra_name` | kernel layout metadata |
| `alg_drv` | u32 | BTF `crypto_alg.cra_driver_name` | kernel layout metadata |
| `task_flags` | u32 | BTF `task_struct.flags` | kernel layout metadata |
| `pf_kthread` | u32 | `PF_KTHREAD` (`linux/sched.h`) | kernel constant; doubles as the unconfigured gate (all-zero KCFG skips observations) |
| `aead_cryptlen_off` | u32 | BTF `aead_request.cryptlen` | kernel layout metadata |
| `ahash_nbytes_off` | u32 | BTF `ahash_request.nbytes` | kernel layout metadata |
| `_pad` | u32 | zero | reserved, always 0 |

## `KAGG` key: attribution head + identity (260B `KAgg`)

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `fam` | u8 | probe site (skcipher/AEAD/ahash/shash/alloc) | family (kp2 §9: family and operation) |
| `op` | u8 | probe site (alloc/enc/dec/digest/finup; destroy — see below) | operation (kp2 §9: family and operation) |
| `res` | u8 | classified return value (`KRES_OK/ERR/QUEUED/UNOBSERVED`) | return/error class (kp2 §9; semantics kp2 §5) |
| `ctx` | u8 | current-task flags vs `pf_kthread` (proc/kthread/unknown) | coarse process-vs-kthread attribution (kp2 §9 PID/TGID/comm/cgroup category, hardened: no raw IDs — see Attribution) |
| `alg` | 128B | `cra_name` (or requested alloc name), NUL-padded whole | bounded algorithm name (kp2 §9) |
| `drv` | 128B | `cra_driver_name`, NUL-padded whole (zeros on alloc: driver not chosen yet) | bounded driver name (kp2 §9) |

Destroy rows never materialize: the kernel zeroes the tfm allocation
before `crypto_destroy_tfm` returns (kretprobe-proven), so the
exit-edge chase yields 0 and fail-closes. The destroy program, op
bucket, and `KRES_UNOBSERVED` exist; no `op=DESTROY` row is asserted.

## `KAGG`/`KTOT` value: counters + stamps (120B `VAgg`)

Per-CPU lanes, userspace-folded (`fold_vagg`: saturating sums, min
`first_ns` over busy lanes, max `last_ns`).

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `calls` | u64 | observations attributed to this row | return/error class tallies (kp2 §9; kp2 §5 `immediate_results`) |
| `bytes` | u64 | request `cryptlen`/`nbytes`, shash `len` arg (sizes only) | scalar byte counts (kp2 §9; kp2 §6 request size) |
| `ok` | u64 | return 0 / valid alloc pointer | return/error class tallies (kp2 §9; kp2 §5) |
| `errors` | u64 | other-negative return / `ERR_PTR` (bad-tag decrypt proven live) | return/error class tallies (kp2 §9; kp2 §5) |
| `queued` | u64 | `-EINPROGRESS`/`-EBUSY` return | return/error class tallies (kp2 §9; kp2 §5). Honest zero on sync hosts (no async source; same gap as K0 P4) |
| `first_ns` | u64 | first seen-edge `ktime` per lane | timestamps (kp2 §9) |
| `last_ns` | u64 | last seen-edge `ktime` per lane | timestamps (kp2 §9) |
| `lat` | 8×u64 | never written | reserved zeros: no durations from a single edge (C4; absent from kp2 §5 schema) |

## `KIDN`: first-seen gate + overflow counters (key u64 → value u8)

- Key: `kcrypto_ident_hash` = FNV-1a over (`fam`, `op`, 128 `alg`
  bytes, 128 `drv` bytes). Name-free derived join key (kp2 §7: the
  ring stays control-event-only; kp2 §8 capture integrity).
- Value: `0` for a first-seen gate entry; saturating per-identity
  `KAGG`-full overflow count on the overflow path (kp2 §8: identity /
  attribution overflows published, never silent loss).
- Reserved key `KIDN_DROPS` (`u64::MAX`): ring-reserve-failure counter,
  saturating (kp2 §8 capture integrity: reserve failures surface here
  instead of vanishing).
- C9 corner: a full `KIDN` (257th+ distinct identity) stays SILENT by
  design — a per-observation `OVERFLOW` there would flood the ring
  (kp2 §7: rare control events only). Observable via the
  `KTOT`-vs-`ΣKAGG` gap (K2 publishes as `attribution_overflow`) + the
  `KIDN` dump showing full; totals preserved.
- Alloc rows' requested-name hashes are cross-run UNSTABLE (heap
  padding past the NUL is hashed); within-run joins hold, and the
  suite matches alloc rows by decoded string, never by hash.

## `KRING`: control events, name-free (48B `KCtl`)

`IDENT` + `OVERFLOW` only; `GENCHANGE`/`GAP`/`HEALTH` reserved, never
emitted (kp2 §7 ring discipline; the privileged suite zero-pins the
reserved kinds). `IDENT` = `key_hash` + packed header: the full
identity lives in the `KAGG` row created on first-seen, userspace
joins by hash; the ring carries no names by construction.

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `kind` | u8 | `KCTL_IDENT` / `KCTL_OVERFLOW` | control-event kind (kp2 §7 ring uses) |
| `_p` | 3B | zero | padding, always 0 |
| `key_hash` | u64 | `kcrypto_ident_hash` of the gated identity | name-free join key (kp2 §7; kp2 §9 boundary) |
| `val0` | u64 | packed head `fam\|op<<8\|res<<16\|ctx<<24` | filter attribution without a map join (kp2 §9 family/operation/class fields, packed) |
| `val1` | u64 | packed NUL-scanned name lengths `alg_len\|drv_len<<32` | scalar length metadata (kp2 §9 scalar counts; lengths, never names) |
| `val2` | u64 | first-seen `ktime` ns | timestamps (kp2 §9) |
| `val3` | u64 | zero | reserved, always 0 |

## Attribution: `ctx` classifier, no raw IDs

The v0.1 sensor captures NO PID, TGID, comm, or cgroup id — only the
`ctx` classifier (`PROC` / `KTHREAD` / `UNKNOWN`) derived from the
current task's flags word. That is a deliberate privacy-hardened
subset of the kp2 §9 "PID/TGID/comm/cgroup metadata" allowance:
enough for kp2 §8 attribution coverage (process vs kernel-thread
split), nothing that identifies a task. (The brief's "context/cgroup
id" parenthetical is aspirational: no cgroup id exists in any v0.1
struct.) `SOFTIRQ` is never written (no stable in-BPF detector;
executions in softirq misattribute to `PROC`/`KTHREAD` — known
limitation, zero-pinned by the privileged suite).

Pointers are never stored either: the current-task pointer feeds only
a null check, and request/tfm pointers feed only the offset chase —
addresses never land in any map or ring record.

## NEVER list

The sensor NEVER reads, stores, or emits: keys, IVs, nonces,
plaintext, ciphertext, AAD, digest outputs, signatures, RNG output,
scatterlist contents, arbitrary buffers, callback private data, or
request/tfm/task pointers (kp2 §9 never-list + request pointers).
Length scalars (`cryptlen`/`nbytes`/shash `len`) ARE captured — sizes,
not contents (kp2 §9: scalar byte counts). The `canary_kcrypto`
privileged test plants `KPROBE-CANARY-*` markers in key AND plaintext
fixture buffers and byte-scans every `KAGG`/`KTOT`/`KIDN`/`KRING`/
`KCFG` dump for zero occurrences: any allowlist drift that leaks
buffer bytes fails the build.
