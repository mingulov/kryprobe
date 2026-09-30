<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto QEMU demo: kernel-address redaction procedure

Status: PROCEDURE ONLY. The redact-fork vs scope-change decision
is AWAITING-OWNER (O1). Do not execute this procedure until the
owner disposes O1; this document narrows the privacy claims and
records the exact successor-artifact recipe meanwhile.

## Observed state (p10a4, firsthand)

- Keys/credentials: CLEAN. Guest dm-crypt keys come from
  `/dev/urandom` into mode-600 table files, passed via
  `--table-file` (never argv/console/`set -x`); AF_ALG keys are
  in-process PRNG vectors never printed. The console parser
  refuses denylisted key-ish JSON keys on DEMO: rows, and the
  independent scan finds no 100+ hex run on any console.
- Kernel IPs: PRESENT in product passthrough. The hash-pinned
  product renderer emits decimal `"ip"` fields (kernel stack
  addresses, e.g. `18446744072638959210`) inside the KRYPROBE
  JSON blocks, which the demo seals verbatim. Counted: 407
  `"ip"` fields across the 10 nonzero p10a4
  `product-report.json` files (D01-rerun3 34, D02-rerun1 22,
  D03-rerun1 70, D04-rerun1 44, D04-rerun2 32, D04 32,
  D07-rerun1 59, D07 70, D08-rerun1 22, D08 22; D01/D02/D03
  first runs carry 0). Count method: bytes
  `.count('"ip"')` per file. The 100-hex no-secret regex cannot
  see decimal fields, so "no-secret scan green" never claimed
  address-freedom.
- DEMO: rows: ADDRESS-FREE. Zero `^DEMO:.*"ip"` matches across
  every sealed console; all IPs arrive via product passthrough.

Privacy claims are therefore narrowed to keys/credentials
everywhere; kernel-address material rides the product bytes
pending O1.

## Successor-artifact recipe

Definitions: ORIGINALS (the sealed campaign dir — immutable,
seal included) and SUCCESSOR (a redacted COPY with its own seal
and provenance). Verdicts bind the ORIGINALS only; the successor
is a presentation artifact, never re-judged.

1. Verify the origin seal: `sha256sum -c SHA256SUMS` in the
   origin campaign dir (expect all OK). Record the origin
   `SHA256SUMS` digest itself.
2. Copy the whole tree: `cp -a <origin> <successor>` (same
   layout, all files).
3. Transform ONLY these byte classes in the SUCCESSOR copy:
   - every `product-report.json`: replace each `"ip": <int>`
     value with `"ip": "REDACTED-kernel-ip"` (string marker —
     visibly schema-breaking by design, so the successor can
     never be mistaken for judgeable evidence);
   - every `console.log` KRYPROBE / KRYPROBE-WINDOW block: the
     same replacement, so console and ledgers agree.
   DEMO: rows, run logs, receipts, and seals are byte-identical
   to the origin otherwise.
4. Sketch (stdlib only; hash the exact script into provenance):
   `re.sub(r'"ip":\s*\d+', '"ip": "REDACTED-kernel-ip"', text)`
   applied to the files above, then recount (expect 0 remaining
   `"ip": <int>` and N replacements logged per file).
5. Write the successor seal: fresh `SHA256SUMS` over the
   successor tree (same `./`-prefixed `sha256sum` format). Never
   copy the origin `SHA256SUMS` as the successor's.
6. Write `REDACT-PROVENANCE.md` in the successor root: origin
   dir + origin seal digest, transform description + script
   hash, per-file replacement counts, operator, UTC timestamp,
   and the statement that verdicts bind the origin bytes only.

## Non-goals

- No sealed-byte edits, ever: originals preserved, original
  seals untouched and never re-sealed.
- No quiet substitution: the successor name, seal, and
  provenance must identify it as redacted.
- This procedure decides nothing about O1 (fork vs scope
  change); it only makes the fork branch mechanical.
