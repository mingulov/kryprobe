#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Demo guest cell dispatcher (attempt 1 stub).
# Usage: run-cells.sh <CELL-ID>
# Only the harness boot reports READY; every D-cell workload refuses with
# an explicit NOT_RUN marker until its task implements the guest side.
# No secret material (keys, IVs, tags, payloads) may ever appear on argv,
# trace output, or these ledgers: metadata only.
set -eu

CELL="${1:?usage: run-cells.sh <CELL-ID>}"
OUT="${DEMO_OUT:-/run/demo}"

mkdir -p "$OUT"

case "$CELL" in
  T01-harness)
    echo "READY cell=$CELL observer=absent workload=absent" > "$OUT/cell-$CELL.status"
    ;;
  D01|D02|D03|D04|D05|D06|D07|D08)
    echo "NOT_RUN cell=$CELL reason=guest-workload-not-implemented-attempt-1" > "$OUT/cell-$CELL.status"
    exit 3
    ;;
  *)
    echo "REFUSED cell=$CELL reason=unknown-cell" > "$OUT/cell-UNKNOWN.status"
    exit 2
    ;;
esac
