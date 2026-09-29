<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# R1 mandatory matrix reconciliation (P8/T13)

Every mandatory ID from the [test and evidence
contract](../../../planning/2026-09-24-kcrypto-test-matrix.md)
reconciled to its proving evidence. "Accepted prior" rows carry
their accepted verdicts forward (historical pass, not a new
verdict); "T13" rows are proved on the final tested artifacts by
this wave's sealed cells (11/11 PASS, campaign PASS). Optional
R2 IDs (X01–X03) and the QEMU demo (D01–D08) are out of R1 scope
and listed only as NOT_RUN.

Final tested artifacts (T13, head `603492c`, manifest
`8d663eb5…`): kryprobe `a3de8ca2…`, kcrypto.bpf.o
`bd14e714…`, kcrypto-lifecycle.bpf.o `6bc13e94…`, fixture
modules `53fc38b3…` (7.0.14) / `7b60903c…` (7.2.6), repo
fixture `f5dd2cbc…`, oracle `d7b2b027…` (full pins in each
sealed `stage.json`; pins uniform across all 11 cells).

## Deterministic cases (prior phases, accepted)

| ID | Owner | Proved by | Status |
|---|---|---|---|
| S01–S02 | T01 | accepted P1 delivery | accepted prior |
| S03–S04 | T02 | accepted P1 delivery | accepted prior |
| S05 | T03 | accepted P1 delivery; `release_artifacts` suite | accepted prior |
| F01–F07 | T04, T07 | accepted P1 delivery lane (37 PASS supported / 33+4 floor) | accepted prior |
| Q01–Q02 | T05, T08 | accepted P2/P3 suites + guest cells | accepted prior |
| Q03–Q08 | T05, T09 | accepted P4 (`e52c52e`) | accepted prior |
| Q09 | T05, T12 | accepted P7 (`0f43994`): I01/Q09 seams + E06/E07 cells | accepted prior |
| A01–A03 | T10 | accepted P5 (`88757d6`) | accepted prior |
| C01–C04 | T11 | accepted P6 (`4861b0a`) | accepted prior |
| O01–O02 | T11 | accepted P6 (`4861b0a`) | accepted prior |
| I01–I04 | T12 | accepted P7 (`0f43994`): E04–E07/sol04 cells | accepted prior |
| P01–P02 | T06–T12 | accepted P6/P7 canary lanes + sol04 | accepted prior |
| H01 (T06 share) | T06 | accepted loader gates | accepted prior |
| H02 (T06 share) | T06 | accepted loader gates | accepted prior |

## Pressure cells (prior phases, accepted)

| ID | Owner | Proved by | Status |
|---|---|---|---|
| E01–E03, E05–E06 | P2 | accepted bounded-mode checkpoint + P7 requalification | accepted prior |
| E04–E07 | P7 | accepted P7 (`0f43994`) guest cells, both kernels | accepted prior |
| E08 | P7 | accepted P7 7.0.14 soak (7.2.6 NOT_RUN, accepted) | accepted prior |

## Real consumers (this wave, T13 PASS)

| ID | Cell(s) | Result |
|---|---|---|
| task-R01 fixture determinism | R01-det-7014, R01-det-726 | PASS: 10-row ledgers identical across legs (validate rc 0/0), product agg identical, attach 9/9, declared-partial verdict |
| task-R01 floor / matrix R03 kernel matrix | R01-floor-612 | PASS (finup-1x arm): hash 20 (20 ahash outer + 20 shash finup, kernel == product exactly on all three hash functions); skcipher 10 ops (20+20 cryptd-nested, split pinned cbc(aes)/\_\_cbc(aes) 10/10); lifecycle refuses exit 4 |
| task-R02 / matrix R01 dm-crypt | R02-7014, R02-726 | PASS: 64 MiB write + 64 MiB read, sha256 match both directions, wrong-key mismatch proved; product 131072/131072 exact (512 B/call uniform chunking, kernel == product); quiet windows 0/0 |
| task-R03 / matrix R02 XFRM | R03-7014, R03-726 | PASS: ESP authenc(hmac(sha256),cbc(aes)) over netns/veth; main legs 1000/1000 delivered both directions; wrong-key leg 100/0 with kernel-equality on authfail counts; quiet windows clean |
| task-R04 negatives / matrix R04 | R04-deny-7014, R04-deny-726, R04-foreign-7014, R04-foreign-726 | PASS: deny legs refuse exit 4 (`live session unusable`, control 10 digests kernel-proved 10/10); foreign legs prove unique owned correspondence (outer 20:6, alloc 1:1, who == agg 54/54, zero unattributed rows) |
| H01 (T13 share) | R01-floor-612 refusal leg, R04-deny refusal legs | PASS: lifecycle floor refuses exit 4 (`kcrypto_fsession_unavailable`); unprivileged capture refuses exit 4 (`live session unusable`); capability reason names the missing observation |
| H02 (T13 share) | host `cargo xtask check` | PASS: rc 0, 89 blocks, 1482/0 (seam/manifest/fmt/clippy/doc/host gates incl. byte-shape tests) |

Note on numbering: the task record numbers R01 = deterministic
fixture cells, R02 = dm-crypt, R03 = XFRM, R04 = negatives; the
original matrix numbers R01 = dm-crypt, R02 = XFRM, R03 = kernel
matrix, R04 = negatives. Both numberings are shown above; the
cell IDs follow the task record.

T13 route notes (new findings, proved in-cell):

- Hash nesting below the outer ahash call is
  scatterlist/page-layout-shaped per burst, not per kernel: the
  same fixture bytes take digest-1x, finup-1x, or finup-2x arms
  on different runs (finup-1x on the 6.12 floor seal,
  digest-1x on both 7.x foreign seals this wave, finup-2x on
  the superseded 7.0.14 foreign seal). The oracles admit
  exactly these arms and require product == kernel equality on
  every hash function, so the arm never affects exactness.
- The foreign-cell proof is route-invariant by construction:
  the 20:6 issued ratio is proved on outer ahash rows only
  (one sendmsg is one outer digest whatever the nested arm),
  bind-allocs pin 1:1, and who covers every agg family.

## Out of R1 scope (explicit NOT_RUN)

| ID | Reason |
|---|---|
| X01–X03 | optional R2 extension (nested provider, virtio-crypto, CPU feature sets) |
| D01–D08 | separate P10 QEMU demo task, not R1 qualification |
| E08 on 7.2.6 | accepted P7 NOT_RUN (single-kernel soak) |

## Full runner inventory (new privileged bodies)

All new privileged execution in this wave runs through the
campaign CLI's owned-guest lane (one vng guest per portion, task
lock + verified reap); no new `#[ignore]` Rust bodies were
added. Privileged bodies executed:

- `kryprobe report --system` (api-returns + lifecycle refusal
  legs) in each guest cell (11 portions).
- `kcrypto_fixture` module (insmod/rmmod) in R01-det legs only.
- testkit `guest_ledger` host validation (unprivileged) for
  R01-det ledgers.
- ftrace function-tracer windows (in-guest, reset to nop) in
  R01-floor/R02/R03/R04-deny cells.
- dm-crypt mapping + loop (R02), netns/veth/XFRM (R03),
  unprivileged `setpriv` capture (R04-deny) — all owned and
  removed per cell (cleanup markers in each receipt).

No other task's lane, no sealed checkout, and no foreign VM was
touched (legacy QEMU 688185, start-tick 2844589, verified
unchanged before/after every run).
