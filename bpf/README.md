<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# BPF layout (reserved)

This directory reserves the BPF program layout per pack proposal P-001:

```
bpf/
  userspace/   BTF-independent programs and maps for p11 + openssl
  kcrypto/     CO-RE/BTF-dependent kernel programs
```

One BTF-independent userspace object holds the p11 and OpenSSL programs
plus shared lifecycle maps; kcrypto stays in a separate BTF/CO-RE
object. The split changes only if coupling causes concrete load,
verifier, or ownership problems.

Thin-spine milestone: no backend BPF programs exist yet. The single
spine object (`spine.bpf.o`, with the common maps plus entry/return
selftest probes) is built from `crates/bpf-spine` in T7 and loaded by
the raw userspace loader — no `bpf/` sources are compiled in this
milestone.

Backend crates live under `crates/` (for example
`crates/kryprobe-backend-p11/`) per pack ARCH §3. There is intentionally
no top-level `backends/` directory.
