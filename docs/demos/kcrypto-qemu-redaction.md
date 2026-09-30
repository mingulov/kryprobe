<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# kcrypto QEMU demo: kernel-address redaction procedure

Status: OPTIONAL PROCEDURE, not selected for v0.1.0. On 2026-09-30
the owner allowed original kernel stack addresses in the completed
p10a4/p10a7 disposable-demo evidence, preserving original seals.
No redacted successor is required or produced for those campaigns.
The recipe below remains available for a future separately authorized
copy. See [release notes](../releases/v0.1.0.md).

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

## Observed state (p10a7 repair, firsthand)

Two address-bearing populations, both product passthrough:

- `product-report.json`: 252 `"ip"` fields (D04-repair1 32,
  D07-repair1/2/3 70 each, D08-repair2 10; D07-broken1,
  D07-late1, D08-repair1 carry 0; D05 has no product report
  by design). `privacy-scan.log` TOTAL 252 is accurate per
  its stated method (product reports only) and must not be
  read as the campaign total.
- `window-reports.json` (D08 retention, R1): 568 `"ip"`
  fields — D08-repair1 224, D08-repair2 344 (byte count and
  recursive JSON-key count agree). The sealed consoles carry
  the same per-window copies inside the numbered
  `KRYPROBE-WINDOW-BEGIN/END` blocks (14 blocks / 224 fields
  repair1, 20 blocks / 344 fields repair2).
- Campaign address-bearing total: 252 + 568 = 820. DEMO:
  rows stay address-free across all repair consoles.

Privacy claims are therefore narrowed to keys/credentials
everywhere; the original kernel-address material remains in the product
bytes under the scoped O1 owner exception.

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
   - every `window-reports.json` (D08 retention): the same
     replacement over every retained per-window report, so no
     window population survives the named transform;
   - every `console.log` KRYPROBE block and every numbered
     KRYPROBE-WINDOW block: the same replacement, so console
     and ledgers agree.
   DEMO: rows, run logs, receipts, and seals are byte-identical
   to the origin otherwise.
4. Sketch (stdlib only; hash the exact script into provenance):
   `re.sub(r'"ip":\s*\d+', '"ip": "REDACTED-kernel-ip"', text)`
   applied to every file above, then recount residual
   `"ip": <int>` across the whole successor tree (expect 0
   remaining anywhere, and N replacements logged per file —
   the per-file counts must sum to the origin populations:
   252 product + 568 window for p10a7, 407 product for p10a4,
   plus the identical console-block copies).
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
- This procedure does not broaden the owner exception to other captures
  or authorize publishing keys, credentials or payload contents.
