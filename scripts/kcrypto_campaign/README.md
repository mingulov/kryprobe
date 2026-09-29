<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T13 common campaign harness (`scripts/kcrypto_campaign/`)

Audited campaign harness for the P8 real-consumer campaign
(R01–R04), with the thin CLI at `scripts/kcrypto-campaign.py`
(`plan` / `run` / `verify`). Layout follows the remaining-tests
plan; strictness patterns follow the reviewed P2 seed.

## Custody audit of `scripts/kcrypto-lab.py` (T04 helper)

The T04 lab helper is fit for fixture lab runs but NOT for
production acceptance orchestration unchanged:

1. **Output-path reuse.** `run_kernel` writes a fixed per-kernel
   tag dir (`lab-k<kernel>` under `--out-root`) and deletes only
   *known* stale files before each run. A rerun over the same
   dir silently mixes generations, and an unknown leftover file
   (new artifact, renamed log) survives into the next receipt.
   This harness refuses to reuse any run or evidence directory
   (`spawn.json` presence, existing dir → hard refusal).
2. **Task-only default lock.** The default `--lock` is the T04
   task lock; nothing binds the shared host BPF lane, and the
   lock wraps only the `vng` subprocess (validation and receipt
   steps run unlocked). This harness holds explicit common +
   task locks in-process from spawn to verified stop.
3. **Unbounded vng wait.** `subprocess.run(cmd)` around `vng`
   has no timeout: a hung guest hangs the campaign forever, and
   there is no stop/reap/cleanup verification (only a lock
   re-probe). This harness bounds every run by the manifest
   `timeout_s`, SIGTERM-then-SIGKILLs the owned process group on
   expiry, verifies the reap, and fails any timed-out receipt.
4. **Ambient orchestration assumptions.** Lab runs validate via
   `CARGO_TEST_CMD` (kept: the strict parser is reused, never
   reimplemented) but stage no artifact pins, capture no
   pre/post identity, and judge no receipt. This harness pins
   every staged byte, validates kernel/config/BTF/module/
   CLI/BPF/oracle identities before GO and after stop, and
   reconciles every receipt offline.

Reused from prior art (never reimplemented): the fixture
`PREPARE/READY/GO/STOP/DONE/READ_LEDGER` protocol, the testkit
strict ledger parser (`guest_ledger`), and the T07/P2 custody
mechanisms (fresh dirs, PID+start-tick identity, verified reap,
preexisting-unchanged checks).

## Modules

- `inputs.py` — strict loader for the frozen consumer manifest
  (`tests/kcrypto_campaign/cells.json`, schema
  `kryprobe-consumer-campaign/v1`).
- `owned_guest.py` — owned-guest custody (promoted P2 seed +
  command identity, spawn/stop receipts, `run_cell`).
- `receipt.py` — atomic terminal receipts + sealing (byte-
  identical to the reviewed P2 seed).
- `reconcile.py` — offline receipt/campaign judgment
  (expected-body equality, required/actual inventory, pin
  binding, cleanup + flush gates).
- `identity.py` — pre-GO/post-stop identity validation.
- `oracles.py` — R01–R04 oracle predicates + the pinned
  api-returns report parser (pure functions).
- `scenarios/` — committed in-guest scenario scripts and
  workload drivers (`r01_det.sh`, `r01_floor.sh`,
  `r02_dmcrypt.sh`, `r03_xfrm.sh`, `r04_deny.sh`,
  `r04_foreign.sh`, `ftrace_ref.sh`, `r02_io.py`,
  `r03_traffic.py`).

## Campaign methodology (uniform across R01–R04)

Every cell binds three independent legs: the **workload truth**
(fixture ledger, I/O checksums, packet ledgers, generator
stdout), the **kernel reference** (fixture protocol counts or
ftrace per-function invocation counts), and the **product
observation** (pinned `report --system --format json`). Oracles
compare product to the kernel reference exactly; bytes and
packets are never equated to API calls without the proved
relation (exact bytes + exact calls + explained chunking for
dm-crypt; exact packet ledgers + kernel equality for XFRM).

Refusals gate on stable contracts only (exit 4 = `Unusable`);
stderr is archived evidence, never scripted. Unsupported
capabilities get explicit cell results, never silent skips.

## Running

```sh
# List the runnable portions (manifest hash printed).
python3 -B scripts/kcrypto-campaign.py plan \
  --manifest tests/kcrypto_campaign/cells.json

# Run one portion (all paths explicit; --ko only for r01_det).
# Both locks are required: the shared host BPF lane lock plus the
# task VM lock (a per-task lock alone is not mutual exclusion).
python3 -B scripts/kcrypto-campaign.py run \
  --manifest tests/kcrypto_campaign/cells.json --portion R02-7014 \
  --kryprobe <release kryprobe> --bpf-dir target/kryprobe-bpf \
  --ko 7.0.14=<kcrypto_fixture.ko> \
  --fixture tests/fixtures/kcrypto_gen.py \
  --out-root <fresh run root> \
  --lock <shared host BPF lock> --lock <task vm lock> \
  --evidence-dir <fresh evidence root>

# Judge sealed cells offline (prints verdicts; writes nothing).
python3 -B scripts/kcrypto-campaign.py verify \
  --manifest tests/kcrypto_campaign/cells.json \
  --cells-dir <sealed cells>
```

Host test suites (stdlib only, no guests):

```sh
python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_consumer_*.py'
python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_ownership.py'
python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_reconcile.py'
python3 -B -m unittest discover -s tests/kcrypto_campaign -p 'test_traffic_fixture.py'
```
