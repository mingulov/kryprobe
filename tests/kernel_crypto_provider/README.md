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
- `async-once`: exact-driver async alloc, EINPROGRESS submit,
  workqueue completion on another CPU, free.
- `delayed-completion`: slow waiter (200ms pre-wait sleep) plus a
  progress marker: progress + terminal callbacks.
- `backlog-accepted`: four concurrent `MAY_BACKLOG` submits on one
  transform; `-EBUSY` still means queued (terminal via callback).
- `early-callback`: pre-wait completion poll recorded as exactly one
  progress row (hit or miss), then the terminal.
- `exact-driver`: generic-name alloc must resolve to exactly the
  async fixture driver (highest priority), else `-ENODEV`.
- `failed-alloc`: unknown-name alloc; the probe triple carries the
  native `ENOENT`, no alloc row, run result 0 (expected failure).
- `refheld-release`: transform held across the run with zero
  invocations, then released: alloc/free rows only.

Planned (matrix F/Q/H): rapid reuse.
