<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Repository-owned AF_ALG traffic fixture (`kcrypto_gen.py`)

Test-only kernel-crypto traffic generator. Campaigns stage this
exact committed file by explicit path — never an ambient
`/tmp/kcrypto_gen.py` or an uncommitted cache on a new host.

## Provenance

Promoted P8/T13 from the inspected, hash-bound T07
delivery-bundle generator
`.artifacts/kcrypto-t07/delivery-lane-09/stage/kcrypto_gen.py`,
SHA256
`82325c72d469b30c55604730e8e8c35cde614cfb8580f5d6b9d27f6d58ffc3eb`
(verified at promotion; the ambient `/tmp` copy hashed
identical). Delta vs the parent is the header (SPDX +
provenance marker) plus the two repairs below; everything else
is byte-identical (`diff` at promotion + repair commit, see
the T13 handoff).

## License

GPL-3.0-or-later (this repository's license; the generator was
workspace-authored in the T07 delivery lane and carried no
separate license header).

## Behavior (pinned by `tests/kcrypto_campaign/test_traffic_fixture.py`)

- `skcipher_burst(n=50)`: `cbc(aes)` via AF_ALG, encrypt+decrypt
  roundtrip per op with `decrypt(encrypt(m)) == m` asserted
  in-process; prints `skcipher: 2*n ops done`.
- `hash_burst(n=50)`: `sha256` via AF_ALG, complete messages (no
  `MSG_MORE`), 32-byte digest asserted; prints
  `hash: n digests done`.
- CLI: `kcrypto_gen.py [rounds] [--skcipher]`; non-integer
  rounds exits 2 with usage; AF_ALG errors exit 1 naming
  `CONFIG_CRYPTO_USER_API`.

No root needed to *generate* traffic; only the observer needs
privileges. No keys/IVs/plaintext leave the process except into
the kernel crypto API under test (fixed synthetic test vectors).

## Repairs vs the parent

1. **Two-cmsg OP+IV form.** The parent's single-cmsg form (op
   + IV bytes concatenated in one `ALG_SET_OP` cmsg) is
   replaced by the standard ABI two-cmsg form (`ALG_SET_OP` +
   `ALG_SET_IV`), matching the repo's Rust AF_ALG fixture
   (`kryprobe-testkit::alg_fixture`).
2. **Bounded skcipher wait.** Blocking AF_ALG skcipher
   `recvmsg` misses the completion wakeup on the campaign
   kernels and the build host: the call is observed
   kernel-side but userspace sleeps in `af_alg_wait_for_data`
   forever, while the timeout/select path observes the ready
   result immediately (bisected 2026-09-28: blocking hangs
   deterministically, timeout succeeds deterministically, on
   6.12.111/7.0.14/7.2.6 guests and the 7.0.0 host, for both
   cmsg forms). `skcipher_burst` therefore sets a 30 s op
   timeout: genuine non-delivery raises `TimeoutError`
   (honest nonzero exit), never a wedge.

These two repairs are the only functional deltas vs the
parent; the host behavior check requires the repaired
skcipher path to answer, and the sealed R01-floor cell proves
it in-guest against the ftrace kernel reference.
