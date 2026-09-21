<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deployment / privilege operations

The install story end to end: layout, privilege model, the trusted
BPF object path, the `token mint` → verify loop, and kernel
requirements. (`docs/commands.md` is the command reference; this is
the runbook.)

## Install layout (the trusted path)

One installer owns the layout: `packaging/install.sh` (`--prefix`,
default `/usr/local`; `--destdir` for staged packaging). It copies
the binary plus the kcrypto object into the exe-bundled tier and —
as root — grants file caps and verifies:

```sh
cargo xtask build
cargo xtask build --bpf
sudo packaging/install.sh
```

Result:

```text
$PREFIX/bin/kryprobe
$PREFIX/bin/kryprobe-bpf/kcrypto.bpf.o
```

`<exe-dir>/kryprobe-bpf/kcrypto.bpf.o` is the **trusted object
path**: the middle tier of the D2 locator try order (`KRYPROBE_BPF_DIR`
→ exe-bundled → CWD dev path). An elevated kryprobe (euid 0 or
effective `CAP_BPF`/`CAP_SYS_ADMIN`, i.e. every file-cap deployment)
loads **only** this tier — env and CWD tiers are refused, so a missing
object fails closed at exit 4 (`kcrypto_object_unreadable`) instead
of loading a stray file. Release builds additionally refuse any
object whose sha256 is not in the `KRYPROBE_PIN_DIGESTS` build-time
pin set (empty in dev builds: pin check skipped). `doctor` prints the
resolved path (`kcrypto_object` row) so the effective configuration
is inspectable; any deviation from the path above in a deployment is
a finding, not a configuration.

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
per-task tracing links, and ringbuf. The authoritative gate is the
runtime probe matrix (`doctor`), not the release string — deploy on
what `doctor` passes, not on what `uname` prints.

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
