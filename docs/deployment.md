<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deployment / privilege operations

The install story end to end: layout, privilege model, the trusted
BPF object path, the `token mint` → verify loop, and kernel
requirements. (`docs/commands.md` is the command reference; this is
the runbook.)

## Install layout (the trusted path)

One installer owns the layout: `packaging/install.sh` (`--prefix`,
default `/usr/local`; `--destdir` for staged packaging). It copies
the binary plus both kcrypto objects into the exe-bundled tier and —
as root — grants file caps and verifies:

```sh
cargo xtask build
cargo xtask build --bpf
sudo packaging/install.sh
```

Release packaging (pinned) instead stages first, then installs from
the verified stage:

```sh
packaging/build-release.sh --dest /owned/pkg-YYYYMMDD
sudo packaging/install.sh --stage /owned/pkg-YYYYMMDD
```

`build-release.sh` enforces the two-phase order: build BPF objects,
digest `kcrypto.bpf.o` and `kcrypto-lifecycle.bpf.o`, then build the
release binary with `KRYPROBE_REQUIRE_PINS=1` and
`KRYPROBE_PIN_OBJECTS=kcrypto.bpf.o=<sha256>,kcrypto-lifecycle.bpf.o=<sha256>`.
Each digest is bound to its object name; swapping two trusted objects
is refused. It stages the binary and both objects atomically, writes
`manifest.json` v2 and `sha256sums.txt` with that explicit object set,
and verifies that staged `doctor --versions` reports
`profile_pins_enforced: true` with both paths and digests. The installer
requires this byte-exact v2 manifest and verifies all three payload
files before copying. Older v1 stages must be rebuilt. Never rebuild
objects after pinning without rebuilding the host binary: the pin
would name bytes that no longer exist. Later privileged lanes use an
immutable staged executable owned by the task, never a mutable
worktree binary.

Result:

```text
$PREFIX/bin/kryprobe
$PREFIX/bin/kryprobe-bpf/kcrypto.bpf.o
$PREFIX/bin/kryprobe-bpf/kcrypto-lifecycle.bpf.o
```

`<exe-dir>/kryprobe-bpf/<object-name>` is the **trusted object
path** for each profile: the middle tier of the D2 locator try order (`KRYPROBE_BPF_DIR`
→ exe-bundled → CWD dev path). An elevated kryprobe (euid 0 or
effective `CAP_BPF`/`CAP_SYS_ADMIN`, i.e. every file-cap deployment)
loads **only** this tier — env and CWD tiers are refused, so a missing
object fails closed at exit 4 (`kcrypto_object_unreadable`) instead
of loading a stray file. Release builds additionally require the
name-bound sha256 baked into the binary. Legacy manual builds using
`KRYPROBE_PIN_DIGESTS` retain a flat allowlist and report
`profile_pins_enforced: false`; they are not accepted by the release
installer. The two pin variables cannot be combined. Unpinned builds skip
the check with a once-per-process stderr warning. Release packaging
must set `KRYPROBE_REQUIRE_PINS=1` so a missing pin set fails the
build instead of shipping an unpinned binary, and must record the
baked digests in the release evidence. `doctor` prints the resolved
path (`kcrypto_object` row) so the effective configuration is
inspectable, and `doctor --versions` reports the object digests
under `kcrypto` and `kcrypto_lifecycle`, plus `pins_enforced` and
`profile_pins_enforced`; any deviation from the path above in
a deployment is a finding, not a configuration.

## Privilege model

- Steady state is **unprivileged + file caps**: `token mint` (root
  one-shot) grants `cap_bpf,cap_perfmon+ep` on the installed binary.
  Day-to-day `watch`/`report`/`check` run as a normal user.
- Root runs are supported but unnecessary past install; env-capsule
  hygiene still applies (see below).
- Token-FD delegation (`--token` > `KRYPROBE_TOKEN` > default-pin
  discovery) covers bring-up variants; `token status` reports
  cap + pin usability without privilege.

## Deploy / upgrade runbook

Every binary swap (upgrade, recompile, `cp`) **silently strips the
`security.capability` xattr** — the next `watch`/`report`/`check`
then exits 4. So the unit of deploy is binary + object + caps, always
together:

1. `cargo xtask build` + `cargo xtask build --bpf` (pinned
   toolchain; host + BPF pins in `docs/dependencies/pins.md`).
2. `sudo packaging/install.sh` (install → `token mint` →
   `token status` + `doctor` verify). With `--destdir` staging, run
   the mint + verify steps against the live paths after the files
   land.
3. Confirm `doctor` shows `probe kcrypto_object: pass:
   $PREFIX/bin/kryprobe-bpf/kcrypto.bpf.o` and `token status`
   reports effective caps.
4. **Re-mint after every binary swap.** No exceptions; step 2 is the
   whole upgrade procedure.
5. Rollback is the previous bundle + re-mint + `doctor` re-verify
   (binary + object + caps move as a unit in both directions).

`token mint` guardrails: `--bin` canonicalizes (symlink targets are
refused); granting caps to anything but the running kryprobe binary
needs explicit `--force`; the receipt (`--receipt`, stdout by
default) records what was granted where.

## Kernel requirements

Kernel 6.12+ with BTF (`/sys/kernel/btf/vmlinux`), `bpf()`,
per-task tracing links, and ringbuf. The request-lifecycle sensor
needs kernel 7.0+ (fsession attach, type 58 — see ADR-0006);
pre-7.0 kernels refuse it typed (`Unsupported`, never a silent
no-op). The authoritative gate is the runtime probe matrix
(`doctor`), not the release string — deploy on what `doctor`
passes, not on what `uname` prints.

## Privileged qualification

Run `scripts/sudo-lane.sh --out /owned/new-run` from the selected
worktree (through the project's Rust tool manager). This needs Python
3.10+, `mount`, `unshare`, `setpriv`, and root or `sudo -n`. It builds with Cargo's
JSON artifact output, records package/target/features and hashes, and
checks the complete ignored-body inventory before privileged execution.
It never chooses an executable by modification time. The TFM suite's
host tests also run in `cargo xtask test bpf`; its three privileged
bodies belong to this runtime-qualified lane.

The runner stages both kcrypto objects, the selftest spine object and
the current executables. The privileged executor copies the complete
bundle into an owned tmpfs under `/run`, verifies every required file,
and makes that root-owned copy read-only in a private mount namespace.
Copies appear at compiled-in fixture paths, including a custom Cargo
target directory. It holds `flock` with an ownership receipt and runs
each of the 34 lane bodies separately, with a 180-second deadline:
33 as root and the privilege-refusal proof under a recorded non-root UID.
An empty test result, timeout, unexplained `SKIP`, missing body or
changed artifact fails. The guest-ledger body is recorded as
`OTHER_LANE` and remains the responsibility of `scripts/kcrypto-lab.py`.

`--prepare-only` builds and seals without privilege;
`--run-prepared /owned/new-run` executes those bytes, including inside
an owned VM with the same checkout paths. A prepared directory permits
one execution attempt; use a fresh bundle for a repeat. Preparation
requires a lab traffic generator: `--traffic-generator PATH` snapshots
an explicitly supplied file (the default input is `/tmp/kcrypto_gen.py`).
Tests receive the verified runtime copy through an explicit path;
there is no ambient `/tmp` fallback during a lane run. Its input path
and digest are recorded. Absent prerequisites cannot produce a green result.

Cancellation closes the wrapper's custody pipe. The executor terminates
and reaps its owned descendants, including children that started another
session, before releasing the lock. The runner creates no PID namespace:
kernel TGIDs and test traffic identities remain in the same namespace.
If a child cannot yet be reaped, the lock remains held and cleanup is
reported as pending; the enclosing VM supervisor supplies the final bound.

`results.json`, `summary.json`, `ownership.json`, Cargo messages and
per-body commands/logs remain in the run directory. Exit 0 means every
required privileged body passed. Exit 1 means failure. Exit 4 means
the lane lock is held or the runtime proves lifecycle fsession refusal;
each affected body is explicitly `SUPPORTED_REFUSAL`, never `PASS`.
The aggregate results remain visible on that kernel. No mount outside
the private namespace is changed.

## Supervision and cgroup notes

v0.1 has no systemd unit, no daemon mode, and no cgroup integration:
`watch`/`report`/`check` are foreground batch commands, and workload
selectors (`--pid`, `--tree`, `--cgroup`, `--unit`) are deferred
past v0.1 and rejected when passed. Supervise kryprobe like any
batch job (a timer or a supervised one-shot); it needs no
cgroup placement of its own. BPF links and maps live exactly as long
as the kryprobe process — killing it detaches everything, so there
is no stale-pin cleanup beyond the operator-owned bpffs token pin
(`token status` shows whether that pin is usable).

## Elevated-mode hygiene

- Never run elevated with a poisoned environment: `KRYPROBE_BPF_DIR`,
  `KRYPROBE_BPF_OBJ`, `KRYPROBE_FIXTURE`, and `KRYPROBE_TOKEN_WORKER`
  are dev-only overrides and are ignored when elevated, but prefer a
  clean env and a neutral CWD for root runs anyway. `KRYPROBE_TOKEN`
  is a bpffs pin path (not a credential) and stays honored — point it
  at a pin the deployment owns.
- `selftest token-smoke` is a root-only serial lane (no concurrent
  BPF activity on the host); see `docs/commands.md`.
