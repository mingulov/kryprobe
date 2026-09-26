#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Exact Cargo identities and per-body receipts; see docs/deployment.md.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$ROOT/scripts/sudo_lane.py" "$@"
