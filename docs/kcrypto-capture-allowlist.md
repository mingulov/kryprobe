<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto capture allowlist (K1 sensor v0.1 + K5 attribution)

Closed list of everything the kcrypto fexit sensor stores in
`KCFG`/`KAGG`/`KTOT`/`KIDN`/`KRING` (K1) plus
`KWHO`/`KSTACK`/`KERR`/`KPARAMS` (K5 attribution) plus `KDROPS`
(fix-wave pre-`KTOT` site counters) plus `KIDENT` (R1 per-`alg`
identity cache, BPF-internal). Anything not on
this list is not captured; the [NEVER](#never-list) section names the
categories the sensor must never read. Field order and sizes twin
`crates/bpf-kcrypto/src/bin/kcrypto.rs` (BPF owns the originals) and
`crates/kryprobe-abi/src/kcrypto_agg.rs` (userspace mirrors).

Change discipline (deliberate friction, brief Step 2): each mirror
struct carries a manually-maintained `FIELDS` list; the test
`allowlist_field_set_matches_docs`
(`crates/kryprobe-abi/tests/kcrypto_allowlist.rs`) pins every list
against a hardcoded expectation AND against this doc (each field must
appear backticked below). The privileged `canary_kcrypto` suite
(`crates/kryprobe-privilege/tests/kcrypto_canary.rs`) byte-scans every
map + ring dump for `KPROBE-CANARY` markers planted in key, IV, and
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

## `KCFG`: loader-written config, not observations (76B `KConfig`)

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
| `shash_base` | u32 | BTF `crypto_shash.base` | kernel layout metadata (replaces the retired C3 hardcoded-0 link: @0 on 7.0, @8 on 6.12) |
| `_pad` | u32 | zero | reserved, always 0 |
| `task_real_parent` | u32 | BTF `task_struct.real_parent` (K5) | kernel layout metadata |
| `task_tgid` | u32 | BTF `task_struct.tgid` (K5) | kernel layout metadata |
| `task_comm` | u32 | BTF `task_struct.comm` (K5) | kernel layout metadata |
| `cra_blocksize` | u32 | BTF `crypto_alg.cra_blocksize` (K5) | kernel layout metadata |
| `cra_ivsize` | u32 | BTF per-family ivsize member (K5) | kernel layout metadata |
| `cra_min_keysize` | u32 | BTF per-family min-keysize member (K5) | kernel layout metadata |
| `cra_max_keysize` | u32 | BTF per-family max-keysize member (K5) | kernel layout metadata |
| `parent_ok` | u8 | nonzero iff the parent offsets resolved (K5) | resolution flag, not an observation |
| `params_ok` | u8 | nonzero iff the params offsets resolved (K5) | resolution flag, not an observation |
| `_pad2` | 2B | zero | reserved, always 0 |

## `KAGG` key: attribution head + identity (260B `KAgg`)

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `fam` | u8 | probe site (skcipher/AEAD/ahash/shash/alloc) | family (kp2 §9: family and operation) |
| `op` | u8 | probe site (alloc/enc/dec/digest/finup; destroy — see below) | operation (kp2 §9: family and operation) |
| `res` | u8 | classified return value (`KRES_OK/ERR/QUEUED/UNOBSERVED`) | return/error class (kp2 §9; semantics kp2 §5) |
| `ctx` | u8 | current-task flags vs `pf_kthread` (proc/kthread/unknown) | coarse process-vs-kthread attribution (kp2 §9 PID/TGID/comm/cgroup category, hardened: no raw IDs — see Attribution) |
| `alg` | 128B | `cra_name` (or requested alloc name), NUL-padded whole | bounded algorithm name (kp2 §9) |
| `drv` | 128B | `cra_driver_name`, NUL-padded whole (zeros on alloc: driver not chosen yet) | bounded driver name (kp2 §9) |

Destroy rows never materialize: a final release frees the transform
before `crypto_destroy_tfm` returns. Zeroing before free does not make
an exit-edge read safe or guarantee that freed storage still contains
zeroes. This program reads no target memory or arguments and counts
only `destroy_skip` (or `cfg_fail` when unconfigured). The attached
program and reserved op/result IDs remain; no `op=DESTROY` identity
or final-free proof is supplied by this profile.

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
- Alloc rows' requested-name hashes are cross-run STABLE (the K5
  fix wave NUL-canonicalizes both names in `observe()` before hashing:
  bytes past the first NUL are zeroed, so heap padding no longer
  splits logical identities into phantom keys). Joins hold within and
  across runs; the suite still matches alloc rows by decoded string
  where display equality is the question.

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

## `KWHO` key: row hash + thread group (16B `KWhoKey`, K5)

Per-CPU hash, 2048 entries. One row per (`kh`, `tgid`).

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `kh` | u64 | FNV-1a over the full `KAgg` row (`fam`/`op`/`res`/`ctx` + `alg`/`drv` words) | name-free join key (same discipline as `KIDN`) |
| `tgid` | u32 | `bpf_get_current_pid_tgid` high 32 | PID/TGID metadata (kp2 §9; raw identity is owner-approved for K5, superseding the v0.1 no-raw-IDs hardening below) |
| `_pad` | u32 | zero | padding, always 0 |

## `KWHO` value: caller identity + tallies (80B `VWho`, K5)

First-seen fields are written once at insert; the hit path updates
only `calls`, `last_ns`, `tid`, `comm` (last-writer).

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `comm` | 16B | `bpf_get_current_comm` (last-writer) | comm metadata (kp2 §9) |
| `tid` | u32 | `bpf_get_current_pid_tgid` low 32 (last-writer) | PID/TGID metadata (kp2 §9) |
| `uid` | u32 | `bpf_get_current_uid_gid` low 32 | caller identity metadata (kp2 §9) |
| `cgroup` | u64 | `bpf_get_current_cgroup_id` | cgroup metadata (kp2 §9) |
| `ppid` | u32 | parent `tgid` via `task_struct.real_parent` chase (iff `parent_ok`, else 0) | PID/TGID metadata (kp2 §9) |
| `pcomm` | 16B | parent `comm` via the same chase (iff `parent_ok`, else zeros) | comm metadata (kp2 §9) |
| `stack` | i32 | `bpf_get_stackid` first-seen id (negative = helper errno, no row) | kernel-stack reference (kp2 §9 kernel metadata; IPs, never contents) |
| `calls` | u64 | observations attributed to this row | return/error class tallies (kp2 §9) |
| `first_ns` | u64 | first seen-edge `ktime` per lane | timestamps (kp2 §9) |
| `last_ns` | u64 | last seen-edge `ktime` per lane | timestamps (kp2 §9) |

## `KSTACK`: kernel stacks by id (K5)

`BPF_MAP_TYPE_STACK_TRACE`, 1024 entries: key u32 stack id → value
127 × u64 kernel IPs. Written implicitly by `bpf_get_stackid`
(first-seen per key only, never per event). Symbolized userspace-side
against `/proc/kallsyms` (best-effort; unreadable → raw IPs kept).

## `KERR`: first nonzero return per `kh` (K5)

Plain hash `u64 → i32`, 256 entries, insert-if-absent only: the raw
`i32` return of the first nonzero-return event for that `kh` (alloc
path: the decoded negative errno of an `ERR_PTR`; void destroy never
records). Return/error class (kp2 §9; kp2 §5).

## `KPARAMS`: per-`kh` crypto parameters (16B `VParams`, K5)

Plain hash `u64 → VParams`, 256 entries, insert-if-absent only,
written iff `params_ok` and the `crypto_alg` address is known (failed
allocs have no `alg`: no row, and userspace omits the keys — never
zero-filled). Per-family BTF member reads, fail-soft zeros on probe
faults.

| Field | Bytes | Source | WHY (kp2 §9) |
|---|---|---|---|
| `blocksize` | u32 | `cra_blocksize` | kernel/build metadata (algorithm properties, not material) |
| `ivsize` | u32 | per-family ivsize member (0-legit: ECB has no IV) | kernel/build metadata (a size, never IV bytes) |
| `min_keysize` | u32 | per-family min-keysize member | kernel/build metadata (a bound, never key bytes) |
| `max_keysize` | u32 | per-family max-keysize member | kernel/build metadata (a bound, never key bytes) |

Reserved key `KWHO_DROPS` (`u64::MAX - 1`) in `KIDN`:
`KWHO`/`KERR`/`KPARAMS` insert-failure counter, saturating (kp2 §8:
attribution loss surfaces here instead of vanishing; separate from
`KIDN_DROPS` so ring loss and attribution loss stay distinguishable).

## `KDROPS`: pre-`KTOT` skip sites (8 per-CPU u64, fix wave)

Per-CPU array, 8 entries: one exact `u64` counter per pre-`KTOT` skip
site (`cfg_fail` / `fret_fail` / `arg_null` / `chase_fail` /
`name_fail` / `destroy_skip` / two spares, reserved). Every BPF
`return 0` before the `KTOT` update bumps its site; userspace folds
lanes and surfaces per-site coverage counters. Scalar skip counts
only — no identities, no names (kp2 §8 capture integrity, kp2 §9
scalar counts). The configured destroy site always counts (C7: live
transform identity is unavailable at the exit edge); it is separately keyed and excluded from loss
verdicts, still counted (never silent).

## `KIDENT`: per-`alg` identity cache (key u64 → 256B `VIdent`, R1)

Plain hash, 256 entries, BPF-internal (never snapshotted, never
published): key = the `crypto_alg` address, value = the memoized
canonical `(cra_name, cra_driver_name)` byte pairs (128B + 128B) that
the slow path would otherwise re-read every event. Stores no new
capture — the same allowlisted names (kp2 §9 bounded names), memoized;
hit bytes are re-scanned through the same canonicalizer, so
downstream rows are bit-identical to the slow path. Exactness rests on
`crypto_alg`-address stability across the session (a crypto-driver
unload/reload mid-session requires a sensor restart — same
session-stability class as the pinned `KCFG` offsets); an 8+8-byte
prefix tripwire against fresh reads converts realistic staleness to
the correct slow path (defense-in-depth, documented non-exact). The
alloc path never touches the cache (requested-name identity).

## Known-uncountable remainder: fexit guard-skips (fix wave, G-C1)

`KDROPS` proves every in-program skip path reads zero — yet dual-
observer (bpftrace oracle) comparisons show a small load-coupled
shortfall (≤0.2% at flood scale under load, 0 when quiet/idle).
Root cause, proven by experiment: the kernel's per-CPU
`bpf_prog_active` recursion guard silently skips a same-program fexit
re-entry when the outer task is preempted mid-program and the middle
task's same-symbol fexit re-enters on that CPU. The skipped program
never executes, and the kernel counts nothing — no in-product
counter CAN exist for these (pre-existing since K1; RT-pinned
traffic shows delta-0 under identical load, confirming preemption as
the driver). The loss is therefore attributed externally (oracle
differential, measured ceiling) rather than silently absorbed: every
countable path is zero by `KDROPS`, and the remainder is bounded,
characterized, and disclosed here — never unexamined.

## Attribution: `ctx` classifier, no raw IDs (v0.1; K5 supersedes)

K5 (this doc's `KWHO`/`KSTACK`/`KERR`/`KPARAMS` sections above)
supersedes the v0.1 hardening by owner decision: raw tgid/tid, comm,
uid, cgroup id, parent, and kernel-stack references are captured (all
inside the kp2 §9 "PID/TGID/comm/cgroup metadata" allowance — the
v0.1 sensor deliberately captured a subset).

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

## Lifecycle payload: userspace-derived, no new capture (T05)

Payload-v1 (`schemas/kcrypto-lifecycle-v1.schema.json`, a
standalone report-JSON profile — not carried in the v0 event
envelope, which has no `backend_payload`; carriage deferred to an
envelope ADR) is derived in userspace by the pure
`LifecycleReducer` from already-captured edges — it reads no new
kernel state and adds no BPF map/ring field (outside the
`FIELDS`/canary pin; guarded instead by the payload-v1 validator
and its contract vectors).

| Field | Source | WHY (kp2 §9) |
|---|---|---|
| `request_id` | reducer id, rendered per-run opaque | correlation handle, not an address |
| `tfm_id` | submit-carried transform id or null | correlation handle, not an address |
| `terminal` | `sync`/`callback`/`unknown` disposition join | return/error class |
| `status` | exact native errno or null | return/error class |
| `duration_ns` | submit-to-terminal span or null | timestamp difference |

No payload-v1 field carries key material, buffer contents, or
pointers: ids are opaque handles, `status` is a scalar errno, and
`duration_ns` is a timestamp difference. Anything else in a
lifecycle payload is a validator finding, not data. (Producer
obligation: the schema checks ID shape, not provenance — the
future producer must derive ids opaquely, never from addresses;
validation cannot prove that.)

## `LRING`/`LCFG` lifecycle transport (T07, R6 pin)

Lifecycle edges ride the `LRING` ring as 112B `LEdge` v7 (op
submit/return — the v6 shape is retired: the API input length
rides at 28..32, the transform word at 40..48, the request flags
at 48..52, family/direction/validity at 52..56, the AEAD words
(`assoclen`/`authsize`) at 56..64, the driver name at 64..112)
and 112B `LTfm` (transform alloc/destroy/config halves); the 80B
`LCFG` row is loader-written config like `KCFG`. All three carry
`FIELDS` lists pinned by `allowlist_field_set_matches_docs` —
same tripwire as the aggregate structs.

| Struct | Fields | WHY (kp2 §9) |
|---|---|---|
| `LEdge` | `magic`, `version`, `edge`, `site`, `flags`, `key`, `ts_ns`, `status`, `cryptlen`, `invoc`, `tfm`, `req_flags`, `fam`, `dir`, `mflags`, `assoclen`, `authsize`, `drv` | wire tags + pairing pointers (`key`, `tfm` — kernel pairing material, `<redacted>` at every render) + timestamp + native errno + entry-side scalar request metadata (`cryptlen` API input length, `req_flags` request flags — validity-gated by `mflags`, unknown when the entry chase was unreadable — plus wire-pinned `fam`/`dir`; P5 AEAD submits add `assoclen` associated-data length + `authsize` tag width, same validity discipline, skcipher submits carry zero) + invocation id + submit-side selected driver (`drv` — public inventory, 47+NUL); returns carry `tfm` 0 + zero metadata + empty `drv` (R2 extended: never chased); P4 callback halves (`edge` 3, `site` 3/4) carry `key` + `status` + `ts_ns` only (`invoc` 0 — names no fsession invocation — zero metadata/`tfm`/`drv`, `flags` 0 — callbacks never taint) |
| `LTfm` | `magic`, `version`, `edge`, `site`, `flags`, `key`, `ts_ns`, `status`, `aux`, `aux2`, `token`, `name` | wire tags + pairing pointer (`key`, redacted) + timestamp + native errno + site scalars (alg type/mask, refcount snapshot, key length/authsize — sizes, not contents) + attempt token + bounded algorithm/driver name (public inventory) |
| `LConfig` | `magic`, `version`, `flags`, `tfm_alg`, `alg_drv`, `sk_base`, `refcnt_off`, `refcnt_present`, `req_base`, `req_tfm`, `req_cryptlen`, `req_flags`, `op_req_off`, `op_req_present`, `aead_req_base`, `aead_req_cryptlen`, `aead_req_assoclen`, `aead_base`, `aead_authsize`, `reserved` | arm tags + BTF-resolved struct offsets (loader-computed, no kernel reads — v4 adds the op metadata reads `req_cryptlen`/`req_flags`; v5 adds the fixture `op->req` chase `op_req_off` + `op_req_present`; v6 adds the AEAD chase words `aead_req_base`/`aead_req_cryptlen`/`aead_req_assoclen`/`aead_base`/`aead_authsize`, each shape-proven like the skcipher words) + disarm gate |

P4 callback-site reads (the two `fentry` programs): the cryptd
site reads arg0 (the request pointer — the half's `key`) and arg1
(the native status) and chases nothing; the fixture site reads
arg1 (status) plus ONE `probe_read` at `arg0 + op_req_off` (the
consumer op's `req` member — the half's `key`; the op pointer
itself is never stored, a fault reads `LLOSS_BADKEY`, never a
wild key). Both are pairing material + errno only — no request
contents, no callback private data beyond the qualified `req`
member (BTF-resolved, pointer-to-`skcipher_request`-checked at
arm, or the arm refuses).

No lifecycle field carries key material, IVs, plaintext,
ciphertext, AAD/tag contents, or buffer contents:
`cryptlen`/`assoclen`/`authsize`/`aux`/`aux2`/`len` words are
length/type/flag scalars (sizes, never contents — the NEVER list's
AAD/tag ban covers bytes, while the counts ride the wire),
`name` is a bounded algorithm/driver name, and the two pairing
pointers never render (manual `Debug` redaction, pinned by
`public_views_carry_no_kernel_addresses` in decimal AND hex).
The privileged `lifecycle_canary_no_secret_bytes_in_views` lane
test keys a live transform with a `KPROBE-CANARY-*` marker and
scans every generation/ledger render for zero occurrences.

## NEVER list

The sensor NEVER reads, stores, or emits: keys, IVs, nonces,
plaintext, ciphertext, AAD, digest outputs, signatures, RNG output,
scatterlist contents, arbitrary buffers, callback private data, or
request/tfm/task pointers (kp2 §9 never-list + request pointers).
Length scalars (`cryptlen`/`nbytes`/shash `len`) ARE captured — sizes,
not contents (kp2 §9: scalar byte counts). The `canary_kcrypto`
privileged test plants `KPROBE-CANARY-*` markers in key, IV, AND plaintext
fixture buffers and byte-scans every `KAGG`/`KTOT`/`KIDN`/`KRING`/
`KCFG` dump for zero occurrences: any allowlist drift that leaks
buffer bytes fails the build. Canary reasoning for the K5 maps (the
fourth move of a new captured field): `KWHO`/`KSTACK`/`KERR`/
`KPARAMS` hold task/crypto metadata only (IDs, comms, stack IPs,
errno, sizes/bounds) — no read in the who-path touches a request
buffer, key, or IV, so no new scan surface is required; extending the
byte-scan to the who-map dumps is optional hardening for later.
