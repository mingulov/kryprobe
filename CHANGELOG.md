<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

All notable user-facing changes to the KryProbe thin spine. The
`kryprobe.event/v0` session schema is frozen and never appears here;
any schema change requires an ADR plus a version bump.

## Unreleased — kcrypto backend (K5)

Live kernel-crypto observation on top of the thin spine: the BPF
sensor, system-wide watch/report/check, policy verdicts, token
bring-up, and third-party import. Exit codes were renumbered — see
the migration note below.

### Added

- kcrypto BPF sensor (9 fexit points, percpu aggregates, ident ring)
  plus the configured loader (BTF resolution, offsets snapshot,
  token-fd delegation).
- Live capture session: `watch --system`, `report --system`
  (human/json/validated-JSONL), `check --system` with the YAML
  policy engine (`VIOLATION`/`CLEAN`/`INCONCLUSIVE` verdicts).
- Who attribution: per-identity rows with kallsyms symbolization
  and the K5 surface (`token mint|status`, doctor matrix rows).
- `import`: osslscope/p11scope docs become shell JSONL records.
- Deployment runbook (`docs/deployment.md`), policy guide
  (`docs/policy.md`), versioning policy (`docs/versioning.md`).

### Changed — exit-code migration

- The kp2 family is now 0 clean/ok, 1 internal failure, 2
  usage/invalid input, 3 inconclusive/PARTIAL, 4
  environment-unusable, 10 policy violation. Previously 3 meant
  refused/unsupported/denied and 4 meant partial: **every consumer
  script keyed on 3/4 must swap those two branches and add exit 10**.
  Stubs (`plan`/`observe`/`run`) and inspect denials moved from 3
  to 4 with the family.

### Fixed

- Per-tick drain respawns replaced by one session drain; kallsyms
  parses once per tick (not per row); fail-open policy verdicts
  closed (unevaluable rules yield `INCONCLUSIVE`, never `Clean`).

## Unreleased — thin-spine milestone

Executable skeleton: frozen contracts plus a working runtime spine
(session/target/authority model, CLI, reporting, synthetic backend,
BPF load/attach/drain pipeline, token plumbing, bench receipts) that
the p11/openssl/kcrypto backends can later plug into without redesign.

### Added

- Core contracts: session-scoped identities, wire enums, backend
  errors, probe plans, session state machine, authority facet traits,
  capability requirements, budget manager, evidence model
  (observations, coverage, integrity, relationships), seven-method
  `Backend` trait with duplicate-safe registry, and a deterministic
  scripted synthetic backend.
- Session-scoped observation ID issuer: backends take IDs from the
  decode context, so two backends can never collide in one session.
- CLI: `doctor`, `backends`, `inspect`, `selftest synthetic`,
  `selftest bpf`, `selftest token-smoke`, `report`, with `--json`
  output, typed exit codes (0/1/2/3/4), and honest stubs for
  `plan`/`observe`/`run`.
- Reporting: JSONL writer, schema validator, and summary renderer
  with per-phase tables, eight-dimension coverage, and integrity
  accounting; zero observations are always qualified.
- BPF spine: raw loader (parse, frozen map dims, relocations,
  reachability gate), uprobe-multi attach with generation guard,
  ring-buffer drain with loss ledger, and a 20k-call selftest that
  reconciles exact kernel counters against received events.
- Token lane: private-bpffs token mint, SCM_RIGHTS passing, nobody
  worker spawn with checked privilege drop, tokenized load path.
- Bench receipts: attach, drain, ELF-access, and end-to-end suites
  with median/p99 over measured runs, or typed denials.
- Command reference: `docs/commands.md`.

### Fixed

- BPF object carried dead compiler builtins the kernel verifier
  rejects; the build now strips unreachable `.text` functions and the
  loader fails closed naming the dead function.
- Drain throughput: ranged ring snapshots, full-ring budgets, and a
  concurrent collector take the 20k selftest from 88% loss to zero.
- Token mint passed the mount fd where the kernel wants a directory
  fd; mint now opens the mount root (this host's kernel still answers
  `EOPNOTSUPP`, honestly reported as `Denied`).
- Worker spawn checked nothing: `setgroups`/`setgid`/`setuid` are now
  all checked (exit 126 on failure), the worker marker travels in a
  private `envp` instead of mutating the parent environment, and the
  worker refuses outer root gid as well as uid.
- BPF selftest now reports the fixture exit code/signal in
  `session_end` instead of `null`.
- TGID guard is fail-closed: an unpinned target matches nothing.

### Security

- Privilege stays in three facets (BPF load, attach, inspection);
  backends perform no privileged syscalls directly.
- Keys, PINs, passwords, payload bytes, and arbitrary target memory
  are never retained; `inspect` takes bounded snapshots only.
