#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# ftrace kernel-reference helper (sourced by T13 in-guest scenarios).
# Counts kernel crypto-API invocations via the function tracer with
# a fixed filter + per-function profile hits (trace_stat/functions).
# Usage:
#   . "$OUT/ftrace_ref.sh"
#   ftrace_begin "crypto_skcipher_encrypt crypto_skcipher_decrypt" || exit 1
#   ... workload ...
#   ftrace_end crypto_skcipher_encrypt > "$OUT/counts.enc"
# Emits "NAME COUNT" lines; COUNT is exact (trace_stat profile
# hits), never sampled. Requires tracefs (already mounted in the
# vng guests); leaves the tracer NOP + filter cleared.

FTRACE=/sys/kernel/tracing

ftrace_begin() {
  if [ ! -d "$FTRACE" ]; then
    echo "ftrace: $FTRACE missing" >&2
    return 1
  fi
  echo nop > "$FTRACE/current_tracer" 2>/dev/null || return 1
  echo > "$FTRACE/set_ftrace_filter" 2>/dev/null || return 1
  echo 0 > "$FTRACE/function_profile_enabled" 2>/dev/null || return 1
  for fn in $1; do
    echo "$fn" >> "$FTRACE/set_ftrace_filter" 2>/dev/null || return 1
  done
  echo 1 > "$FTRACE/function_profile_enabled" 2>/dev/null || return 1
  echo function > "$FTRACE/current_tracer" 2>/dev/null || return 1
  echo 1 > "$FTRACE/tracing_on" 2>/dev/null || return 1
  return 0
}

ftrace_end() {
  echo 0 > "$FTRACE/tracing_on" 2>/dev/null || return 1
  # Profile hits: combined trace_stat/functions where present,
  # else summed over the per-CPU trace_stat/functionN files
  # (6.12+ splits per CPU; never sum both).
  stat_files="$FTRACE/trace_stat/functions"
  if [ ! -f "$stat_files" ]; then
    # Fail closed when no per-CPU file exists either (a zero
    # from unreadable inputs would be a lie).
    have_stat=0
    for candidate in "$FTRACE"/trace_stat/function[0-9]*; do
      if [ -f "$candidate" ]; then have_stat=1; break; fi
    done
    if [ "$have_stat" -ne 1 ]; then return 1; fi
    stat_files="$FTRACE/trace_stat/function[0-9]*"
  fi
  # shellcheck disable=SC2086
  for fn in "$@"; do
    hits=$(awk -v f="$fn" '$1 == f {t += $2} END {print t + 0}' $stat_files 2>/dev/null)
    case "$hits" in ''|*[!0-9]*) hits="MISSING";; esac
    echo "$fn $hits"
  done
  echo nop > "$FTRACE/current_tracer" 2>/dev/null || return 1
  echo 0 > "$FTRACE/function_profile_enabled" 2>/dev/null || return 1
  echo > "$FTRACE/set_ftrace_filter" 2>/dev/null || return 1
  return 0
}

ftrace_cleanup_marker() {
  # $1 = out file to append tracer=1/0.
  tracer=$(cat "$FTRACE/current_tracer" 2>/dev/null)
  if [ "$tracer" = "nop" ]; then
    echo "tracer=1" >> "$1"
  else
    echo "tracer=0" >> "$1"
  fi
}
