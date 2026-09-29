<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Operations runbook (4B-M3)

Triage on any exit-4/outage page. The tools are `doctor`
(always exit 0, safe mid-incident) and `token status`
(unprivileged). Start every page with:

```sh
kryprobe doctor --json   # verdict.status + verdict.missing drive this page
kryprobe token status    # file caps + token-pin usability
kryprobe doctor --versions  # what is actually deployed (binary + objects + pins)
```

## Exit-4 decision tree (verdict-missing order)

Work `verdict.missing` in order — `symbols, caps, btf, attach,
object` (`cmd_doctor.rs: coverage_verdict`). Fix the first entry
before reading the rest.

- `symbols`: the kcrypto trace points are absent from the running
  kernel (kallsyms/BTF lookup failed). Confirm the kernel still
  provides them (`doctor` human rows name the missing point);
  a kernel upgrade moved or renamed them → escalate (new kernel
  needs a lane re-run before it is trusted).
- `caps`: the process has no BPF capability. `token status` says
  whether the binary lost its file caps (see cap-loss recovery
  below) or the token pin is unusable (see token recovery).
- `btf`: `/sys/kernel/btf/vmlinux` is missing or unreadable.
  The host needs BTF enabled (kernel built with
  `CONFIG_DEBUG_INFO_BTF`, BTF readable by the kryprobe user).
  No operator workaround — fix the host, then re-run `doctor`.
- `attach`: the object loaded but zero points attached. Read the
  `attach` row detail: `loaded+attach-failed:<detail>` names the
  failing point (permissions, lockdown, or a kernel that refuses
  `BPF_TRACE_FEXIT`). If lockdown or a policy change is the
  cause, no kryprobe-side fix exists — escalate.
- `object`: the kcrypto object did not resolve. See object
  recovery below.

## Cap-loss recovery (4B-M2)

Any binary swap (upgrade, recompile, `cp`) silently strips the
`security.capability` xattr. Symptom: `caps` in
`verdict.missing` right after a deploy, with `token status`
showing no effective caps.

```sh
sudo kryprobe token mint --bin $PREFIX/bin/kryprobe   # re-grant cap_bpf,cap_perfmon+ep
kryprobe token status                                  # confirm effective caps
kryprobe doctor                                        # verdict back to ready
```

`--bin` canonicalizes (symlink targets are refused); granting to
anything but the running kryprobe binary needs `--force`.
**Re-mint after every binary swap. No exceptions.**

## Object recovery

Symptom: `object` in `verdict.missing`, or exit 4
`kcrypto_object_unreadable`. The `kcrypto_object` row shows where
the locator looked. Elevated kryprobe loads ONLY the exe-bundled
tier — `$PREFIX/bin/kryprobe-bpf/kcrypto.bpf.o`
(`docs/deployment.md`); env and CWD tiers are refused.

1. Confirm the bundled object exists at the trusted path above.
   If it is missing, re-run the install (`sudo
   packaging/install.sh`) — never hand-copy an object from
   another host without checking its digest against the release
   evidence.
2. Confirm the digest: `kryprobe doctor --versions` prints the
   resolved path + sha256 and the `pins_enforced` bit. A digest
   that matches no release pin is a finding, not a
   configuration — treat the host as suspect (see below) and do
   not mint caps onto it.

## Untrusted object suspected (H-SEC-01 response)

If the object path deviates from the trusted path, or its digest
is unpinned on a pinned build:

1. Stop scheduling captures on the host; do not re-mint.
2. Preserve evidence: `doctor --versions --json` output, the
   suspect file's sha256, `ls -l` + mtimes of the
   `kryprobe-bpf/` dir.
3. Reinstall from the release bundle, re-mint, re-verify with
   `doctor`, and compare digests against the release evidence
   before returning the host to service.

## Token recovery

`token status` reports pin usability without privilege. If the
default pin is gone (bpffs unmounted, pin removed), either
recreate the pin per `docs/deployment.md` or pass an explicit
`--token PATH` (`--token` > `KRYPROBE_TOKEN` > default pin).

## Rollback unit (4B-M1)

Binary + BPF objects + caps move as a unit in both directions.
Rollback is the previous bundle + re-mint + `doctor` re-verify
(`docs/deployment.md`): reinstall the previous release bundle,
re-mint caps onto the restored binary (the swap stripped them),
and confirm `verdict: ready` plus matching `doctor --versions`
digests before resuming captures.

## When to escalate to a privileged lane re-run

Re-run `scripts/sudo-lane.sh` (with the lane lock) when:

- the kernel, toolchain, or BPF objects changed (attach/drain
  behavior is kernel-sensitive);
- `doctor` is green but captures still fail (the lane asserts
  the paths `doctor` only probes);
- after any H-SEC-01 response, before returning the host to
  service.

If the lane host is unavailable, record `NOT_RUN` per
`AGENTS.md` — a skipped lane is data, never a pass.

## Accepted release limitations (R1)

Do not page on these — they are accepted, documented behavior:

- A `partial` verdict with `missing: [capture-integrity,
  completion]` is the declared honest state (completion is
  unobserved by design), not an outage.
- P7 E08 soak on 7.2.6 is NOT_RUN (single-kernel soak
  accepted); unreferenced-finup observations stay residual
  (see `docs/kcrypto-support.md` §P9 + route note 3).
- Measurements with any nonzero unexpected-loss counter are
  outside the qualified envelope — re-run quieter/shorter
  rather than ratioing them (`docs/bench-thresholds.md` P9).
- Pre-attach boot traffic is unobserved; request-lifecycle on
  the 6.12 floor refuses typed exit 4 (floor limitation, not
  a fault).
