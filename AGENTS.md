# KryProbe product agent rules

Paths below are relative to this product repo root (`kryprobe/`). Product work happens only in an assigned workspace worktree (`.worktrees/<task-id>`); never edit the nested checkout in place for task work.

## Mission

Build a Linux 6.12+ runtime cryptographic observer for p11, OpenSSL and kcrypto. Preserve evidence meaning and privacy. Do not expand into network/TLS plaintext, generic scanning, enforcement, daemon/server/UI, or dynamic privileged plugins.

## Before editing

Read the assigned TASK, current base SHA, `docs/DECISIONS.md`, relevant requirements/contracts/backend spec, and source manifest. Verify branch/worktree/status and isolated `CARGO_TARGET_DIR`.

## Path ownership

Edit only assigned paths. Root manifests/lockfile/toolchain/xtask, ABI/schema/stable IDs, shared BPF maps and authority interfaces have one assigned writer. Stop for an ADR/task handoff if a backend needs a shared-contract change.

## KISS / DRY / eBPF

- Make the smallest contract-preserving change.
- No unrelated refactor or speculative framework.
- Share stable host mechanisms; keep backend state machines separate.
- Small deliberate duplication in verifier-sensitive BPF code is allowed when abstraction changes instructions/verifier state/coupling. Document it and share tests, not necessarily code.
- Do not introduce dynamic dispatch, allocation, unbounded loops or target-controlled sizes into BPF code.
- Use one source of truth for stable IDs/generated files; never edit generated output.

## Evidence semantics

Discovered != selected != entered != returned != completed != succeeded. Zero observed != absent. Native result/operation names remain available. Counts, detailed events, attribution and correlation have separate integrity.

Unknown build/layout/variant fails closed. Timestamp proximity cannot create cross-layer correlation.

## Privacy

Never retain keys, PINs, passwords, plaintext/ciphertext payloads, digest/signature bytes, arbitrary buffers/memory or unreviewed target strings. New metadata reads require bounded allowlist/lifetime/alias/privacy tests.

## Privilege

Backends never perform privileged operations directly. They produce plans consumed by authority/attachment code. A BPF token is not PID confinement. Do not weaken Yama/seccomp/LSM/lockdown/unprivileged-BPF settings to pass a test.

## Testing

Use actual source/test commands. Behavioral fixes require deterministic failing oracle then passing targeted/broader gates. Parse expected totals/positive controls, not only exit status. Mark unavailable privileged lanes `NOT_RUN`.

Do not fix races by increasing timeouts or expected skips. Do not run signal-sensitive gates under `nohup`.

## Commits and handoff

Focused `feat/fix/test/docs/build/refactor` commits. No force push/tag/public push. Handoff includes SHAs, changed paths, requirement/decision/issue IDs, exact commands/results/evidence hashes, NOT_RUN lanes, limitations and cleanup state.
