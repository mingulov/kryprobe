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
identical). Delta vs the parent is the 6-line header only
(SPDX + provenance marker); the traffic core is byte-identical
(`diff` proved at promotion, see the T13 handoff).

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

## Known host quirk (not a fixture defect)

`skcipher_burst` uses the single-cmsg OP+IV form. That form is
answered on all three campaign guest kernels (6.12.111, 7.0.14,
7.2.6 — probed 2026-09-28) but the T13 build host
(7.0.0-31-generic) never completes the encrypt `recv`. The host
behavior check therefore runs skcipher in a bounded child and
skips with an explicit reason on this host; the sealed
R01-floor guest cell carries the skcipher proof.
