# kcrypto_fixture — kernel truth fixture (TEST ONLY)

Out-of-tree kernel module implementing the T04 truth fixture: two
`skcipher` providers (sync priority 100, async priority 300, shared
generic name `kxcipher`) plus a consumer that runs scripted scenarios
and records every step as JSONL truth rows. Nothing here is secure
cryptography: the "cipher" is XOR with the key byte. Never install
on a production host; owned disposable VMs only.

## Layout

- `fixture.h` — shared declarations + the exact ledger row contract
- `provider.c` — drivers, ledger ring, debugfs, module lifecycle
- `consumer.c` — scenarios + control commands
- `Makefile` — kbuild wrapper (`KDIR=` required)

## Build (host, per guest kernel)

```sh
cp provider.c consumer.c fixture.h Makefile <scratch>/
cd <scratch>
make KDIR=<headers>/usr/src/linux-headers-<ver>-generic KCFLAGS=-g
pahole -J --btf_base <matching-vmlinux> kcrypto_fixture.ko
```

`KCFLAGS=-g` + the `pahole` step produce module BTF (needed to
attach to fixture functions); kbuild alone skips BTF without a
`vmlinux` in the tree. See the vng-qual spike HANDOFF for the
qualified recipe.

## Run (guest, as root)

```sh
insmod kcrypto_fixture.ko run_suffix=<per-run-id>
echo "PREPARE run-1 sync-once 42" > /sys/kernel/debug/kcrypto_fixture/control
cat /sys/kernel/debug/kcrypto_fixture/control   # READY when prepared=1 done=0
echo GO > /sys/kernel/debug/kcrypto_fixture/control
cat /sys/kernel/debug/kcrypto_fixture/ledger    # READ_LEDGER (JSONL truth)
cat /sys/kernel/debug/kcrypto_fixture/control   # DONE when done=1
rmmod kcrypto_fixture
```

`STOP` aborts a running scenario (`-ECANCELED`, nonzero DONE
result — rejected as truth, never silent). Every number the
observer is compared against comes from `ledger`, parsed by
testkit `kernel_crypto_ledger` (strict: duplicates, missing DONE,
phase breaks, overflow, foreign runs and nonzero fixture results
all reject).

## Scenarios

- `sync-once`: exact-driver sync alloc, encrypt+decrypt roundtrip,
  verified bytes, free. Every invocation still records a terminal
  row (a sync return IS its terminal result).
- `sync-meta` (P3): exact-driver sync alloc + setkey (epoch 1), 3
  encrypt+decrypt roundtrips with varied cryptlen (16/64/256) and
  request flags (0/`MAY_BACKLOG`), a mid-run rekey (epoch 2), then
  3 more roundtrips (12 ops total). Submit rows carry `len` +
  `flags` truth for the T08 metadata/epoch/errno/duration oracle.
- `sync-enokey` (P3r): raw sync alloc, 2 ops with no key (early
  `-ENOKEY` refusal), a rejected short setkey (failed config, epoch
  stays 0), then 2 more refused ops (4 ops total). Return rows +
  done trailer carry the provider-entry marker (0 throughout):
  the failed wrapper claims no provider entry.
- `async-once`: exact-driver async alloc, EINPROGRESS submit,
  workqueue completion on another CPU, free.
- `delayed-completion`: provider delays the async completion by
  200ms; the waiter marks the genuinely in-flight invocation with a
  progress row and verifies the elapsed time (progress + terminal
  notifications, in that order).
- `backlog-accepted`: four `MAY_BACKLOG` submits on one transform
  against a depth-1 driver queue with the drain held: submit 0
  returns `-EINPROGRESS`, submits 1-3 genuinely return `-EBUSY`
  (queued as backlog); all four complete via callback after the
  kick. The worker mirrors `cryptd_queue_worker` (backlog sampled
  before dequeue, `complete(backlog, -EINPROGRESS)` before the head
  terminal): reqs 1-3 each record one kernel progress row, drain
  order `P1,T0,P2,T1,P3,T2,T3`. Any deviation fails the run
  (`-EPROTO`).
- `no-backlog-burst` (P4): held queue + 2 submits WITHOUT
  `MAY_BACKLOG`: submit 0 queues (`-EINPROGRESS`, terminal via
  callback), submit 1 answers `-ENOSPC` immediately (terminal,
  exact, no callback follows). Any deviation fails the run
  (`-EPROTO`).
- `early-callback`: pre-wait completion poll recorded as exactly one
  progress row (hit or miss), then the terminal.
- `exact-driver`: generic-name alloc must resolve to exactly the
  async fixture driver (highest priority), else `-ENODEV`.
- `failed-alloc`: unknown-name alloc; the probe triple carries the
  native `ENOENT`, no alloc row, run result 0 (expected failure).
- `refheld-release`: transform held across the run with zero
  invocations, then released: alloc/free rows only.
- `cryptd-async` (P4): in-kernel real-cryptd driver (the 7.2
  real-path; 7.0 uses AF_ALG): generic control alloc, full-name
  cryptd alloc, async-masked alloc — each binding drives one op
  (submit/return/terminal rows), each refusal an alloc-probe
  triple with the native errno. Always result 0 (rows are the
  verdict, read by the T09 oracle, not lab.py).

Planned (matrix F/Q/H): rapid reuse.
