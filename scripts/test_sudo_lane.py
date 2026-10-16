#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial runner checks; no privilege or kernel support required."""
import ast
import builtins
import contextlib
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import tracemalloc
import unittest
from unittest import mock
import sys
import copy
import ctypes
import errno
import fcntl
import functools
import io
import shutil
import signal
import subprocess
import time

sys.dont_write_bytecode = True
import sudo_lane as lane


def artifact(path, features=()):
    return {
        "reason": "compiler-artifact",
        "package_id": "path+file:///fixture#example@0.1.0",
        "target": {"name": "probe", "kind": ["test"]},
        "profile": {"test": True},
        "features": list(features),
        "executable": str(path),
    }


def messages(*rows):
    return "\n".join(json.dumps(row) for row in rows)


FINISHED = {"reason": "build-finished", "success": True}
PASS = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.01s\n"


class CargoSelection(unittest.TestCase):
    def test_newer_stale_executable_cannot_replace_cargo_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            current, stale = Path(tmp) / "probe-current", Path(tmp) / "probe-stale"
            current.write_text("current")
            stale.write_text("stale")
            os.utime(stale, (4102444800, 4102444800))
            rows = lane.cargo_artifacts(messages(artifact(current), FINISHED))
            self.assertEqual([row["executable"] for row in rows], [str(current)])

    def test_empty_failed_or_unfinished_build_cannot_supply_inventory(self):
        for text in ["", messages(FINISHED), messages(artifact("/current")),
                     messages(artifact("/current"), {"reason": "build-finished", "success": False})]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                lane.cargo_artifacts(text)

    def test_conflicting_feature_or_executable_variants_are_not_guessed(self):
        for conflict in [artifact("/stale"), artifact("/current", ["different-feature"])]:
            with self.subTest(conflict=conflict), self.assertRaises(ValueError):
                lane.cargo_artifacts(messages(artifact("/current"), conflict, FINISHED))

    def test_identical_repeated_record_keeps_one_current_identity(self):
        self.assertEqual(len(lane.cargo_artifacts(messages(
            artifact("/current"), artifact("/current"), FINISHED))), 1)


class BodyAccounting(unittest.TestCase):
    def test_empty_ignored_listing_is_not_a_test_result(self):
        self.assertEqual(lane.parse_test_list("0 tests, 0 benchmarks\n"), [])
        with self.assertRaises(ValueError):
            lane.reconcile({("example", "probe"): []}, {("example", "probe"): ["required"]})

    def test_missing_extra_or_duplicate_body_fails_inventory(self):
        expected = {("example", "probe"): ["required"]}
        for observed in [{}, {("example", "probe"): ["other"]},
                         {("example", "probe"): ["required", "surprise"]},
                         {("example", "probe"): ["required", "required"]}]:
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                lane.reconcile(observed, expected)

    def test_exact_body_requires_execution_and_no_hidden_skip(self):
        self.assertEqual(lane.body_verdict(0, PASS), "PASS")
        self.assertEqual(lane.body_verdict(0, lane.DEV_PIN_WARNING + "\n" + PASS), "PASS")
        for code, output in [(0, ""), (0, PASS.replace("1 passed", "0 passed")),
                             (0, "SKIP: missing object\n" + PASS),
                             (0, "decoy: cell denied; skipping\n" + PASS),
                             (0, "NOT_RUN: missing BTF\n" + PASS), (1, PASS), (124, PASS)]:
            with self.subTest(code=code, output=output):
                self.assertEqual(lane.body_verdict(code, output), "FAIL")

    def test_env_gate_allowlist_is_exactly_the_two_documented_bodies(self):
        self.assertEqual(lane.ENV_GATED_BODIES, {
            ("kryprobe-cli", "live_k5", "attribution_golden_python"): "bpftrace",
            ("kryprobe-cli", "live_k5", "setcap_roundtrip_unpriv"): "nogroup",
        })

    def test_env_gated_skip_needs_allowlist_marker_and_clean_residual(self):
        key = ("kryprobe-cli", "live_k5")
        marker = ("SKIP (env-gated): attribution_golden_python requires bpftrace; "
                  "see docs/lane-environment.md")
        marker2 = ("SKIP (env-gated): setcap_roundtrip_unpriv requires nogroup; "
                   "see docs/lane-environment.md")
        self.assertEqual(lane.body_verdict(0, marker + "\n" + PASS, key, "attribution_golden_python"),
                         "ENV_GATED_SKIP")
        self.assertEqual(lane.body_verdict(0, marker2 + "\n" + PASS, key, "setcap_roundtrip_unpriv"),
                         "ENV_GATED_SKIP")
        # libtest pretty framing: the body's marker lands inline after
        # "test <body> ... " (observed on fedora) — still gated.
        inline = "test attribution_golden_python ... " + marker + "\nok\n" + PASS
        self.assertEqual(lane.body_verdict(0, inline, key, "attribution_golden_python"),
                         "ENV_GATED_SKIP")
        for name, output in [
            # allowlisted body, plain SKIP without the loud marker
            ("attribution_golden_python", "SKIP: requires bpftrace\n" + PASS),
            # marker for the wrong prerequisite
            ("attribution_golden_python", marker2 + "\n" + PASS),
            # marker plus unexplained skip text
            ("attribution_golden_python", marker + "\ndecoy: cell denied; skipping\n" + PASS),
            # non-allowlisted body printing the marker
            ("stack_symbol_smoke", marker + "\n" + PASS),
        ]:
            with self.subTest(name=name, output=output):
                self.assertEqual(lane.body_verdict(0, output, key, name), "FAIL")
        # unidentified caller (legacy shape): any skip fails
        self.assertEqual(lane.body_verdict(0, marker + "\n" + PASS), "FAIL")
        # nonzero exit never env-gates
        self.assertEqual(lane.body_verdict(1, marker + "\n" + PASS, key, "attribution_golden_python"),
                         "FAIL")


def _partial_output(entries, returns, received, ring, drop, trunc, queue,
                     printed_missing, marker="reconcile: partial\n",
                     verdict="PARTIAL", child_code=0, child_signal=None,
                     session=True):
    out = (
        f"selftest bpf: partial ({printed_missing} missing; ring={ring} drop={drop}"
        f" trunc={trunc} queue={queue})\n"
        "session session:bpf-selftest: 2 records\n"
        "phase completed: no completed-phase operations observed during 0..1000ns; event_transport: complete\n"
        f"selftest bpf: entries={entries} returns={returns} received={received}"
        f" ring={ring} drop={drop} trunc={trunc} queue={queue}\n"
        + marker
    )
    if session:
        signal = "null" if child_signal is None else f'"{child_signal}"'
        out += (
            '{"schema":"kryprobe.event/v0","kind":"session_start",'
            '"session_id":"s","record_id":"record:1","monotonic_ns":"0","payload":{}}\n'
            '{"schema":"kryprobe.event/v0","kind":"session_end",'
            '"session_id":"s","record_id":"record:2","monotonic_ns":"1000",'
            f'"payload":{{"verdict":"{verdict}","child_exit_code":{child_code},'
            f'"child_signal":{signal}}}}}\n'
        )
    return out


ANNOUNCEMENT = "selftest bpf: accounted partial (2 missing); child output follows:\n"


def _cargo_echo(*args, **kwargs):
    """Cargo-body echo: child stderr + blank + child stdout + blank.

    Production eprintln!s each already-newline-terminated stream,
    adding the separators (empirically confirmed with a bare libtest
    probe run under the lane-exact flags)."""
    full = _partial_output(*args, session=True, **kwargs)
    head, sep, tail = full.partition('{"schema"')
    return head + "\n" + sep + tail + "\n"

# Escape-sensitive fixtures (built from chr() so no decoder mangles them).
NBSP = chr(0xA0)
BOM = chr(0xFEFF)
PAIR_ESCAPE = chr(92) + "uD83D" + chr(92) + "uDE00"
USCORE_ESCAPE = chr(92) + "u005f"
NUL = chr(0)
VT = chr(11)


@contextlib.contextmanager
def _owned_mkstemp():
    # capture mkstemp descriptors so tests that stub the stream
    # owner (_text_sink) can close the real fds afterwards.
    made = []
    real_mkstemp = tempfile.mkstemp
    def capture(*args, **kwargs):
        fd, tmp = real_mkstemp(*args, **kwargs)
        made.append(fd)
        return fd, tmp
    with mock.patch("tempfile.mkstemp", side_effect=capture):
        try:
            yield
        finally:
            for fd in made:
                try:
                    os.close(fd)
                except OSError:
                    pass


def failed_tail_spaced():
    # every object opener spaced: carries no '{"', so only the
    # any-brace rule (not r6's token rule) can reject it
    return ('end", "payload": { "verdict": "FAILED", "child_exit_code": 1, '
            '"child_signal": null } }\n')


class PartialReceipt(unittest.TestCase):
    # Full Oct-13 GH log (run 38385103973, exit 3): fully-accounted
    # partial refused by the old code==0 rule. Byte-exact (see the
    # receipt-hash test); the phase/coverage/JSONL lines prove the
    # skip filter stays clean on real output.
    OCT13_LOG = (
        'selftest bpf: partial (581 missing; ring=581 drop=0 trunc=0 queue=0)\n'
        'session session:bpf-selftest: 2 records\n'
        'phase discovered: no discovered-phase operations observed during 0..1000ns; event_transport: complete\n'
        'phase selected: no selected-phase operations observed during 0..1000ns; event_transport: complete\n'
        'phase entered: no entered-phase operations observed during 0..1000ns; event_transport: complete\n'
        'phase returned: no returned-phase operations observed during 0..1000ns; event_transport: complete\n'
        'phase completed: no completed-phase operations observed during 0..1000ns; event_transport: complete\n'
        'coverage:\n'
        '  target_enumeration: complete; no gaps recorded during 0..1000ns\n'
        '  executable_discovery: complete; no gaps recorded during 0..1000ns\n'
        '  attachment: complete; no gaps recorded during 0..1000ns\n'
        '  semantic_resolution: complete; no gaps recorded during 0..1000ns\n'
        '  attribution: complete; no gaps recorded during 0..1000ns\n'
        '  aggregate_counts: complete; no gaps recorded during 0..1000ns\n'
        '  event_transport: complete; no gaps recorded during 0..1000ns\n'
        '  correlation: complete; no gaps recorded during 0..1000ns\n'
        '  observation_continuity: complete; no gaps recorded during 0..1000ns\n'
        'integrity: no aggregate snapshots observed during 0..1000ns; aggregate_counts: complete\n'
        'selftest bpf: entries=19707 returns=19712 received=39419 ring=581 drop=0 trunc=0 queue=0\n'
        'reconcile: partial\n'
        '{"schema":"kryprobe.event/v0","kind":"session_start","session_id":"session:bpf-selftest","record_id":"record:1","monotonic_ns":"0","payload":{"target_selector":"owned_run","capture_mode":"trace","requested_backends":[],"contract_version":"v0-proposed","qualification_id":"qualification:bpf-selftest-20000"}}\n'
        '{"schema":"kryprobe.event/v0","kind":"session_end","session_id":"session:bpf-selftest","record_id":"record:2","monotonic_ns":"1000","payload":{"verdict":"PARTIAL","final_barrier":"validated","unresolved_gap_ids":[],"child_exit_code":0,"child_signal":null}}\n'
    )
    OCT13_SHA256 = "b9f3c48a6a86b4c9aefb4ec58989a27d13621714632f65b291bcc070aa882632"

    def test_fixture_matches_archived_receipt(self):
        self.assertEqual(hashlib.sha256(self.OCT13_LOG.encode()).hexdigest(),
                         self.OCT13_SHA256)

    def test_oct13_full_log_receipts(self):
        receipt = lane.partial_receipt(self.OCT13_LOG, 20000)
        self.assertEqual(receipt, {"exit": 3, "calls": 20000, "missing": 581,
                                   "entries": 19707, "returns": 19712,
                                   "received": 39419, "ring": 581, "drop": 0,
                                   "trunc": 0, "queue": 0})

    def test_split_receipts_accepted(self):
        receipt = lane.partial_receipt(
            _partial_output(9, 9, 18, 1, 0, 0, 1, 2), 10)
        self.assertEqual(receipt["missing"], 2)

    def test_queue_receipted_partial_accepted(self):
        # The ledger excludes queue drops, so the producer prints the
        # remainder (10) while every record is receipted; the lane
        # equation counts queue and accepts.
        receipt = lane.partial_receipt(
            _partial_output(90, 90, 180, 10, 0, 0, 10, 10), 100)
        self.assertEqual(receipt["missing"], 20)

    def test_silent_loss_rejected(self):
        # calls=100, 6 records lost, only 3 receipted by ring: the
        # producer prints `partial (3 missing; ring=3 ...)` (remainder
        # semantics) and the old sum rule passed it.
        self.assertIsNone(lane.partial_receipt(
            _partial_output(97, 97, 194, 3, 0, 0, 0, 3), 100))

    def test_over_count_rejected(self):
        # otherwise-valid: only the over-count rejects (mutant-killing;
        # verified by disabling each half and observing acceptance)
        self.assertIsNone(lane.partial_receipt(
            _partial_output(101, 97, 198, 2, 0, 0, 0, 2), 100))
        self.assertIsNone(lane.partial_receipt(
            _partial_output(97, 101, 198, 2, 0, 0, 0, 2), 100))

    def test_kind_sum_mismatch_rejected(self):
        self.assertIsNone(lane.partial_receipt(
            _partial_output(90, 89, 180, 10, 0, 0, 10, 10), 100))

    def test_equation_shortfall_rejected(self):
        self.assertIsNone(lane.partial_receipt(
            _partial_output(90, 90, 180, 9, 0, 0, 0, 11), 100))

    def test_vacuous_partial_rejected(self):
        self.assertIsNone(lane.partial_receipt(
            _partial_output(100, 100, 200, 0, 0, 0, 0, 0), 100))

    def test_marker_shapes_rejected(self):
        base = _partial_output(9, 9, 18, 1, 0, 0, 1, 2)
        bad = [
            base + "reconcile: partial\n",  # duplicated marker
            base.replace("reconcile: partial\n", "reconcile: clean\n"),
            base.replace("reconcile: partial\n", "reconcile: defect\n"),
            base + "reconcile: defect (corrupt)\n",  # contradictory extra line
            base.replace("reconcile: partial\n", ""),  # missing marker
        ]
        for output in bad:
            with self.subTest(output=output):
                self.assertIsNone(lane.partial_receipt(output, 10))

    def test_line_count_shapes_rejected(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        self.assertIsNotNone(lane.partial_receipt(base, 10))
        entries = "selftest bpf: entries=9 returns=9 received=18 ring=2 drop=0 trunc=0 queue=0\n"
        partial = "selftest bpf: partial (2 missing; ring=2 drop=0 trunc=0 queue=0)\n"
        bad = [
            base + entries,  # duplicated entries line
            base + partial,  # duplicated partial line
            base.replace(partial, ""),  # partial line missing
            base.replace(entries, ""),  # entries line missing
            base + "reconcile: partial \n",  # trailing space
        ]
        for output in bad:
            with self.subTest(output=output):
                self.assertIsNone(lane.partial_receipt(output, 10))

    def test_unicode_digits_rejected(self):
        output = _partial_output(9, 9, 18, 1, 0, 0, 1, 2)
        output = output.replace("entries=9", "entries=\uff19")
        self.assertIsNone(lane.partial_receipt(output, 10))

    def test_anomaly_receipts_rejected(self):
        # drop/trunc are anomaly buckets (spine.rs: pre-arm hits,
        # generation/TGID mismatch, wide CONFIG) — pressure only.
        self.assertIsNone(lane.partial_receipt(
            _partial_output(99, 99, 198, 1, 1, 0, 0, 2), 100))
        self.assertIsNone(lane.partial_receipt(
            _partial_output(99, 99, 198, 1, 0, 1, 0, 2), 100))
        # all-anomaly wipeout satisfies the bare equation
        self.assertIsNone(lane.partial_receipt(
            _partial_output(0, 0, 0, 0, 40000, 0, 0, 40000), 20000))

    def test_delivery_floor(self):
        self.assertIsNone(lane.partial_receipt(
            _partial_output(0, 10, 10, 10, 0, 0, 0, 10), 10))
        self.assertIsNone(lane.partial_receipt(
            _partial_output(10, 0, 10, 10, 0, 0, 0, 10), 10))

    def test_malformed_extra_lines_rejected(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        bad = [
            base + "selftest bpf: entries=0 returns=0 received=0 ring=0 drop=0 trunc=0 queue=0 CORRUPT\n",
            base + "selftest bpf: partial (bogus)\n",
            base + "reconcile:defect\n",
        ]
        for output in bad:
            with self.subTest(output=output):
                self.assertIsNone(lane.partial_receipt(output, 10))

    def test_control_and_replacement_characters_rejected(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        self.assertIsNone(lane.partial_receipt(base.replace("\n", "\r\n"), 10))
        self.assertIsNone(lane.partial_receipt(base + "noise�\n", 10))

    def test_huge_digits_rejected_without_raising(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        self.assertIsNone(lane.partial_receipt(
            base.replace("entries=9", "entries=" + "9" * 5000), 10))

    def test_partial_line_values_u64_ranged(self):
        huge = str(2 ** 64)
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        out = base.replace("partial (2 missing;", f"partial ({huge} missing;")
        self.assertIsNone(lane.partial_receipt(out, 10))
        out = base.replace("partial (2 missing; ring=2 ",
                           f"partial (2 missing; ring={huge} ")
        self.assertIsNone(lane.partial_receipt(out, 10))

    def test_receipt_lines_must_agree(self):
        # both lines print the same producer fields; the entries side
        # still satisfies the equation, isolating the cross-check
        out = _partial_output(9, 9, 18, 1, 0, 0, 1, 2).split("\n")
        out[0] = out[0].replace("ring=1", "ring=2").replace("queue=1", "queue=0")
        self.assertIsNone(lane.partial_receipt("\n".join(out), 10))

    def test_session_end_cross_check(self):
        self.assertIsNone(lane.partial_receipt(
            _partial_output(9, 9, 18, 2, 0, 0, 0, 2, session=False), 10))
        self.assertIsNone(lane.partial_receipt(
            _partial_output(9, 9, 18, 2, 0, 0, 0, 2, verdict="FAILED"), 10))
        self.assertIsNone(lane.partial_receipt(
            _partial_output(9, 9, 18, 2, 0, 0, 0, 2, child_code=1), 10))
        self.assertIsNone(lane.partial_receipt(
            _partial_output(9, 9, 18, 2, 0, 0, 0, 2, child_signal="TERM"), 10))
        self.assertIsNone(lane.partial_receipt(
            _partial_output(9, 9, 18, 2, 0, 0, 0, 2) + "{oops\n", 10))
        dup = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        end = [line for line in dup.split("\n") if "session_end" in line][0]
        self.assertIsNone(lane.partial_receipt(dup + end + "\n", 10))

    def test_calls_bound(self):
        out = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        self.assertIsNone(lane.partial_receipt(out, 0))
        huge = 2 ** 63
        out = _partial_output(huge - 1, huge - 1, 2 * huge - 2, 2, 0, 0, 0, 2)
        # the equation holds but calls exceeds u64::MAX/2
        self.assertIsNone(lane.partial_receipt(out, huge))

    def test_whitespace_prefixed_contradictory_end_rejected(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        forged = ('  {"schema":"kryprobe.event/v0","kind":"session_end",'
                  '"session_id":"s","record_id":"record:9","monotonic_ns":"9",'
                  '"payload":{"verdict":"FAILED","child_exit_code":1,'
                  '"child_signal":null}}\n')
        self.assertIsNone(lane.partial_receipt(base + forged, 10))

    def test_payload_must_be_object_with_exact_types(self):
        stem = _partial_output(9, 9, 18, 2, 0, 0, 0, 2, session=False)
        head = ('{"schema":"kryprobe.event/v0","kind":"session_end",'
                '"session_id":"s","record_id":"record:2","monotonic_ns":"1000",')
        good_payload = ('"payload":{"verdict":"PARTIAL","child_exit_code":0,'
                        '"child_signal":null}')
        bad_payloads = [
            '"payload":null',
            '"payload":[]',
            '"payload":{"verdict":"PARTIAL","child_exit_code":false,"child_signal":null}',
            '"payload":{"verdict":"PARTIAL","child_exit_code":0.0,"child_signal":null}',
            '"payload":{"verdict":"PARTIAL","child_exit_code":0}',
            '"payload":{"verdict":"PARTIAL","child_exit_code":0,"child_signal":null},"x":NaN',
            '"payload":{"verdict":"PARTIAL","child_exit_code":0,"child_signal":null},"x":"\\ud800"'
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(
                    lane.partial_receipt(stem + head + payload + "}\n", 10))
        self.assertIsNotNone(
            lane.partial_receipt(stem + head + good_payload + "}\n", 10))

    def test_surrogate_walk_is_depth_robust(self):
        value = 0
        for _ in range(5000):
            value = [value]
        self.assertFalse(lane._has_surrogate(value))

    def test_duplicate_json_keys_rejected(self):
        stem = _partial_output(9, 9, 18, 2, 0, 0, 0, 2, session=False)
        head = ('{"schema":"kryprobe.event/v0","kind":"session_end",'
                '"session_id":"s","record_id":"record:2","monotonic_ns":"1000",')
        bad_payloads = [
            # last-wins would smuggle a passing exit code
            '"payload":{"verdict":"PARTIAL","child_exit_code":1,"child_exit_code":0,'
            '"child_signal":null}',
            # last-wins would smuggle a passing verdict
            '"payload":{"verdict":"FAILED","verdict":"PARTIAL","child_exit_code":0,'
            '"child_signal":null}',
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload):
                self.assertIsNone(
                    lane.partial_receipt(stem + head + payload + "}\n", 10))
        # duplicate kind hides a contradictory end from uniqueness
        forged = ('{"kind":"session_end","kind":"noise",'
                  '"payload":{"verdict":"FAILED","child_exit_code":1,'
                  '"child_signal":null}}\n')
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        self.assertIsNone(lane.partial_receipt(base + forged, 10))

    def test_integer_range_stricter_than_serde(self):
        # serde floats out-of-range ints and errors only past f64::MAX;
        # Python restricts auxiliaries to i64/u64 (fail-closed).
        # True parity: in-range accepts, past-f64 rejects on both.
        stem = _partial_output(9, 9, 18, 2, 0, 0, 0, 2, session=False)
        head = ('{"schema":"kryprobe.event/v0","kind":"session_end",'
                '"session_id":"s","record_id":"record:2","monotonic_ns":"1000",'
                '"payload":{"verdict":"PARTIAL","child_exit_code":0,'
                '"child_signal":null},')
        good = head + '"x":18446744073709551615,"y":-9223372036854775808}\n'
        self.assertIsNotNone(lane.partial_receipt(stem + good, 10))
        self.assertIsNone(
            lane.partial_receipt(stem + head + '"x":' + "9" * 309 + "}\n", 10))
        # Documented strictness: serde would float-accept these.
        for raw in ["18446744073709551616", "-9223372036854775809",
                    "-170141183460469231731687303715884105729"]:
            with self.subTest(raw=raw[:12]):
                bad = head + f'"x":{raw}' + "}\n"
                self.assertIsNone(lane.partial_receipt(stem + bad, 10))

    def test_negative_zero_and_infinite_float_rejected(self):
        stem = _partial_output(9, 9, 18, 2, 0, 0, 0, 2, session=False)
        head = ('{"schema":"kryprobe.event/v0","kind":"session_end",'
                '"session_id":"s","record_id":"record:2","monotonic_ns":"1000",')
        self.assertIsNone(lane.partial_receipt(
            stem + head + '"payload":{"verdict":"PARTIAL","child_exit_code":-0,'
            '"child_signal":null}}\n', 10))
        self.assertIsNone(lane.partial_receipt(
            stem + head + '"payload":{"verdict":"PARTIAL","child_exit_code":0,'
            '"child_signal":null},"x":1e400}\n', 10))

    def test_nesting_depth_capped_like_serde(self):
        # serde allows 127 nested containers (probed: 127 ok, 128 err)
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        shallow = '{"a":' * 127 + '1' + '}' * 127 + "\n"
        self.assertIsNotNone(lane.partial_receipt(base + shallow, 10))
        deep = '{"a":' * 128 + '1' + '}' * 128 + "\n"
        self.assertIsNone(lane.partial_receipt(base + deep, 10))
        hollow = '{"a":' * 127 + '{}' + '}' * 127 + "\n"
        self.assertIsNone(lane.partial_receipt(base + hollow, 10))

    def test_exotic_prefixed_contradictory_end_rejected(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        forged = ('{"schema":"kryprobe.event/v0","kind":"session_end",'
                  '"session_id":"s","record_id":"record:9","monotonic_ns":"9",'
                  '"payload":{"verdict":"FAILED","child_exit_code":1,'
                  '"child_signal":null}}\n')
        self.assertIsNone(lane.partial_receipt(base + NBSP + forged, 10))
        self.assertIsNone(lane.partial_receipt(base + BOM + forged, 10))

    def test_escaped_kind_forgeries_rejected(self):
        # escape-spelled kinds miss the raw spelling count, so these
        # exercise the JSON scan itself (mutant-killing for the
        # uniqueness check and the space/tab narrowing; verified by
        # disabling each and observing acceptance)
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        forged = ('{"schema":"kryprobe.event/v0","kind":"session' + USCORE_ESCAPE
                  + 'end","session_id":"s","record_id":"record:9","monotonic_ns":"9",'
                  '"payload":{"verdict":"FAILED","child_exit_code":1,'
                  '"child_signal":null}}\n')
        self.assertIsNone(lane.partial_receipt(base + forged, 10))
        self.assertIsNone(lane.partial_receipt(base + " " + forged, 10))
        self.assertIsNone(lane.partial_receipt(base + "\t" + forged, 10))

    def test_exotic_framing_with_escaped_kind_rejected(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        bodies = [
            # compact, spaced, and tabbed object openers: JSON allows
            # whitespace after '{', so the framing rule cannot rely on
            # quote adjacency
            '{"kind":"session',
            '{ "kind": "session',
            '{\t"kind":\t"session',
        ]
        tail = ('end", "payload": { "verdict": "FAILED", "child_exit_code": 1, '
                '"child_signal": null } }\n')
        for prefix in [NBSP, BOM, VT, NUL, "  " + NBSP]:
            for body in bodies:
                forged = body + USCORE_ESCAPE + tail
                with self.subTest(prefix=ord(prefix.lstrip(" ")[0]),
                                  body=body[:4]):
                    if body != bodies[0]:
                        # spaced openers carry no '{"': the r6 token
                        # rule cannot see these forgeries
                        self.assertNotIn('{"', prefix + forged)
                    self.assertIsNone(
                        lane.partial_receipt(base + prefix + forged, 10))
        # mid-line object under an exotic prefix: every opener
        # spaced, or r6's '{"' rule already rejects it and the case
        # proves nothing (r7 gap)
        forged = ('note { "kind": "session' + USCORE_ESCAPE
                  + failed_tail_spaced())
        self.assertNotIn('{"', NBSP + forged)
        self.assertIsNone(lane.partial_receipt(base + NBSP + forged, 10))
        # split-line forgery: the brace dangles at end-of-line and
        # the record continues on the next line
        line1 = NBSP + "frag {\n"
        line2 = '"kind": "session' + USCORE_ESCAPE + failed_tail_spaced()
        self.assertNotIn('{"', line1)
        self.assertNotIn('{"', line2)
        self.assertIsNone(
            lane.partial_receipt(base + line1 + line2, 10))

    def test_exotic_prefixed_valid_end_rejected(self):
        # a valid end under an exotic prefix is unsupported framing,
        # not a parseable record
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2, session=False)
        end = ('{"schema":"kryprobe.event/v0","kind":"session_end",'
               '"session_id":"s","record_id":"record:2","monotonic_ns":"1000",'
               '"payload":{"verdict":"PARTIAL","child_exit_code":0,'
               '"child_signal":null}}\n')
        self.assertIsNone(lane.partial_receipt(base + NBSP + end, 10))

    def test_valid_surrogate_pair_accepted(self):
        stem = _partial_output(9, 9, 18, 2, 0, 0, 0, 2, session=False)
        line = ('{"schema":"kryprobe.event/v0","kind":"session_end",'
                '"session_id":"s","record_id":"record:2","monotonic_ns":"1000",'
                '"payload":{"verdict":"PARTIAL","child_exit_code":0,'
                '"child_signal":null},"x":"' + PAIR_ESCAPE + '"}\n')
        receipt = lane.partial_receipt(stem + line, 10)
        self.assertIsNotNone(receipt)

    def test_recursion_error_branch_never_raises(self):
        base = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        with mock.patch.object(lane.json, "loads", side_effect=RecursionError):
            self.assertIsNone(lane.partial_receipt(base, 10))

    def test_zero_padded_numbers_accepted(self):
        out = _partial_output(9, 9, 18, 2, 0, 0, 0, 2)
        for plain, padded in [("entries=9 ", "entries=0009 "),
                              ("returns=9 ", "returns=0009 "),
                              ("received=18 ", "received=00018 "),
                              ("(2 missing;", "(0002 missing;"),
                              ("ring=2 ", "ring=0002 "),
                              ("drop=0 ", "drop=0000 "),
                              ("trunc=0 ", "trunc=0000 "),
                              ("queue=0)", "queue=0000)"),
                              ("queue=0\n", "queue=0000\n")]:
            out = out.replace(plain, padded)
        receipt = lane.partial_receipt(out, 10)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["missing"], 2)
        # thousands of leading zeros: same value as Rust's u64 parse
        padded = out.replace("entries=0009 ", "entries=" + "0" * 5000 + "9 ")
        receipt = lane.partial_receipt(padded, 10)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["entries"], 9)


class E2EGuard(unittest.TestCase):
    LOG = _cargo_echo(9, 9, 18, 2, 0, 0, 0, 2)

    def test_unclaimed_passthrough(self):
        self.assertEqual(lane.e2e_partial_guard("ok\n", 10, "PASS"),
                         ("PASS", None))
        self.assertEqual(lane.e2e_partial_guard("ok\n", 10, "FAIL"),
                         ("FAIL", None))

    def test_claimed_receipted(self):
        status, receipt = lane.e2e_partial_guard(ANNOUNCEMENT + self.LOG, 10, "PASS")
        self.assertEqual(status, "PASS")
        self.assertEqual(receipt["missing"], 2)

    def test_claimed_unparseable_fails(self):
        # announcement without the echo
        self.assertEqual(
            lane.e2e_partial_guard(ANNOUNCEMENT + "ok\n", 10, "PASS"),
            ("FAIL", None))
        # echo without full accounting
        self.assertEqual(
            lane.e2e_partial_guard("reconcile: partial\n", 10, "PASS"),
            ("FAIL", None))

    def test_rejected_body_not_listed(self):
        # the receipt parses but the body failed (e.g. leak-normalized)
        self.assertEqual(
            lane.e2e_partial_guard(ANNOUNCEMENT + self.LOG, 10, "FAIL"),
            ("FAIL", None))


class CargoLogFraming(unittest.TestCase):
    # Empirical libtest `--format pretty --nocapture --exact
    # --test-threads=1` framing (bare libtest probe binary, same
    # toolchain): the announcement absorbs the inline `test ... `
    # prefix; echoed lines start at column 0.
    BODY = "selftest_bpf_clean_partial_or_denied"
    # filtered-out count tracks the cli_bpf_e2e body count minus one
    # (shape-checked only; the probe binary with one test prints 0).
    LOG = ("\nrunning 1 test\n"
           f"test {BODY} ... {ANNOUNCEMENT}"
           + _cargo_echo(9, 9, 18, 2, 0, 0, 0, 2)
           + "ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"
             " 26 filtered out; finished in 2.21s\n\n")

    def test_framed_log_verdicts_and_guards(self):
        key = ("kryprobe-cli", "cli_bpf_e2e")
        self.assertEqual(lane.body_verdict(0, self.LOG, key, self.BODY), "PASS")
        status, receipt = lane.e2e_partial_guard(self.LOG, 10, "PASS")
        self.assertEqual(status, "PASS")
        self.assertEqual(receipt["missing"], 2)


class SummarizePartials(unittest.TestCase):
    def test_collects_and_identifies(self):
        results = [
            {"test": "selftest-bpf", "status": "PASS",
             "accepted_partial": {"exit": 3, "missing": 2}},
            {"package": "kryprobe-cli", "target": "cli_bpf_e2e",
             "test": "selftest_bpf_clean_partial_or_denied", "status": "PASS",
             "accepted_partial": {"exit": 3, "missing": 2}},
            {"test": "other", "status": "PASS"},
        ]
        self.assertEqual(lane.summarize_partials(results), [
            {"test": "selftest-bpf", "exit": 3, "missing": 2},
            {"test": "kryprobe-cli/cli_bpf_e2e::selftest_bpf_clean_partial_or_denied",
             "exit": 3, "missing": 2},
        ])

    def test_empty_and_serializable(self):
        self.assertEqual(lane.summarize_partials([]), [])
        self.assertEqual(lane.summarize_partials([{"test": "x"}]), [])
        json.dumps(lane.summarize_partials([
            {"test": "selftest-bpf", "accepted_partial": {"exit": 3}}]))


class CommittedPrefix(unittest.TestCase):
    RESULTS = [{"test": "a"}, {"test": "b", "accepted_partial": {"exit": 3}}]

    def test_slices_to_committed_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            # nothing committed yet
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            # partial commit (interruption after the first row persisted)
            (out / "results.json").write_text(json.dumps(self.RESULTS[:1]))
            self.assertEqual(
                lane.committed_prefix(out, self.RESULTS), self.RESULTS[:1])
            # full commit
            (out / "results.json").write_text(json.dumps(self.RESULTS))
            self.assertEqual(
                lane.committed_prefix(out, self.RESULTS), self.RESULTS)

    def test_unreadable_or_foreign_file_claims_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("not json {{{")
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            (out / "results.json").write_text(json.dumps({"test": "a"}))
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])

    def test_hostile_file_never_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("[" * 5000)
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            big = json.dumps([{"test": f"t{i}"} for i in range(60000)])
            assert len(big) > 1024 * 1024
            (out / "results.json").write_text(big)
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            (out / "results.json").write_text("[]")
            with mock.patch.object(lane.json, "loads", side_effect=RecursionError):
                self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])

    def test_signal_during_prefix_read_defers_without_leak(self):
        # the whole body runs shielded: SIGTERM during the read
        # defers (flag set, read completes, fd owned) instead of
        # raising through the parse.
        def raising(signum, frame):
            lane._CANCEL_REQUESTED = True
            raise InterruptedError("cancelled")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("[]")
            saved_flag = lane._CANCEL_REQUESTED
            old = signal.signal(signal.SIGTERM, raising)
            before = len(os.listdir("/proc/self/fd"))
            real_fstat = os.fstat
            def killer(fd):
                os.kill(os.getpid(), signal.SIGTERM)
                return real_fstat(fd)
            try:
                lane._CANCEL_REQUESTED = False
                with mock.patch("os.fstat", side_effect=killer):
                    self.assertEqual(
                        lane.committed_prefix(out, self.RESULTS), [])
                self.assertTrue(lane._CANCEL_REQUESTED)
            finally:
                signal.signal(signal.SIGTERM, old)
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_signal_between_open_return_and_assignment_defers(self):
        # the exact STORE_FAST window: kill after the real open
        # returns, before the caller assigns. Shielded: defers
        # and completes with the fd owned. (Unshielded, the
        # raise lands with fd still None: silent leak.)
        def raising(signum, frame):
            lane._CANCEL_REQUESTED = True
            raise InterruptedError("cancelled")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("[]")
            saved_flag = lane._CANCEL_REQUESTED
            old = signal.signal(signal.SIGTERM, raising)
            before = len(os.listdir("/proc/self/fd"))
            real_open = os.open
            def killer(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                os.kill(os.getpid(), signal.SIGTERM)
                return fd
            try:
                lane._CANCEL_REQUESTED = False
                with mock.patch("os.open", side_effect=killer):
                    self.assertEqual(
                        lane.committed_prefix(out, self.RESULTS), [])
                self.assertTrue(lane._CANCEL_REQUESTED)
            finally:
                signal.signal(signal.SIGTERM, old)
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_no_shield_exit_window_before_ownership(self):
        # structural pin: a kill placed exactly at shield exit
        # fires after the body (fd already closed) — it raises
        # without leaking. A shield-around-open-only shape leaks
        # here instead; a shield-less shape never fires and
        # returns instead of raising.
        def raising(signum, frame):
            lane._CANCEL_REQUESTED = True
            raise InterruptedError("cancelled")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("[]")
            saved_flag = lane._CANCEL_REQUESTED
            old = signal.signal(signal.SIGTERM, raising)
            before = len(os.listdir("/proc/self/fd"))
            real_dc = lane._deferred_cancel
            @contextlib.contextmanager
            def killer_shield():
                with real_dc():
                    yield
                os.kill(os.getpid(), signal.SIGTERM)
            try:
                lane._CANCEL_REQUESTED = False
                with mock.patch.object(lane, "_deferred_cancel",
                                       side_effect=lambda: killer_shield()):
                    with self.assertRaises(InterruptedError):
                        lane.committed_prefix(out, self.RESULTS)
            finally:
                signal.signal(signal.SIGTERM, old)
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_read_is_bounded_before_parsing(self):
        # the read budget is measured with tracemalloc inside the
        # test window: ru_maxrss is a high-water mark, so a prior
        # 160MB allocation lets an unbounded mutant pass (r8 gap).
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            big = out / "results.json"
            with open(big, "wb") as stream:
                stream.truncate(100 * 1024 * 1024)
            # reset_peak + current-baseline: peak-subtraction
            # cannot isolate the window from a taller freed peak
            # (160MB freed hides a 100MB unbounded read). Resetting
            # the diagnostic peak is acceptable; killing outer
            # tracing is not, so start/stop stay conditional.
            # Boundary (Codex r11-8): a release of caller ballast
            # INSIDE the window would conceal the same way — the
            # window therefore holds a single committed_prefix
            # call, which allocates but releases no caller
            # memory, so no such release can occur here.
            was_tracing = tracemalloc.is_tracing()
            if not was_tracing:
                tracemalloc.start()
            try:
                tracemalloc.reset_peak()
                current_before, _ = tracemalloc.get_traced_memory()
                self.assertEqual(
                    lane.committed_prefix(out, self.RESULTS), [])
                _, window_peak = tracemalloc.get_traced_memory()
            finally:
                if not was_tracing:
                    tracemalloc.stop()
            growth = (window_peak - current_before) / (1024 * 1024)
            self.assertLess(
                growth, 20, f"read allocated {growth:.0f} MiB")
            big.unlink()
            os.mkfifo(big)
            # a regressed blocking read must fail the test, not
            # hang the suite: run it off-thread with a deadline.
            outcome = []
            worker = threading.Thread(
                target=lambda: outcome.append(
                    lane.committed_prefix(out, self.RESULTS)),
                daemon=True)
            worker.start()
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive(), "read blocked on FIFO")
            self.assertEqual(outcome, [[]])

    def test_symlink_and_nonregular_files_claim_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = out / "target.json"
            target.write_text(json.dumps(self.RESULTS))
            (out / "results.json").symlink_to(target)
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            (out / "results.json").unlink()
            (out / "results.json").mkdir()
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])

    def test_oversize_is_rejected_not_truncated(self):
        # a valid list at exactly the cap parses; one byte of
        # trailing garbage must reject, not claim a prefix.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            inner = json.dumps(self.RESULTS[0]).encode()
            exact = b"[" + inner + b" " * (1024 * 1024 - len(inner) - 2) + b"]"
            assert len(exact) == 1024 * 1024
            (out / "results.json").write_bytes(exact)
            self.assertEqual(lane.committed_prefix(out, self.RESULTS),
                             self.RESULTS[:1])
            (out / "results.json").write_bytes(exact + b"INVALID")
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])

    def test_boundary_pins_cap_plus_one(self):
        # precisely cap+1 bytes of VALID json must reject: the
        # cap+7 INVALID case above cannot catch a cap raised by one.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            inner = json.dumps(self.RESULTS[0]).encode()
            over = b"[" + inner + b" " * (1024 * 1024 - len(inner) - 1) + b"]"
            assert len(over) == 1024 * 1024 + 1
            (out / "results.json").write_bytes(over)
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])

    def test_committed_rows_must_match_memory(self):
        # only the count comes from disk: a foreign-length or
        # foreign-content list must not claim in-memory rows.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("[null,null]")
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            (out / "results.json").write_text(
                json.dumps(self.RESULTS + [{"test": "c"}]))
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            mutated = [dict(self.RESULTS[0], test="forged")]
            (out / "results.json").write_text(json.dumps(mutated))
            self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])
            (out / "results.json").write_text(json.dumps(self.RESULTS[:1]))
            self.assertEqual(lane.committed_prefix(out, self.RESULTS),
                             self.RESULTS[:1])

    def test_committed_rows_must_match_types_exactly(self):
        # Python == conflates True/1/1.0 and False/0, and duplicate
        # keys collapse before comparison: none of these are the
        # in-memory rows.
        rows = [{"test": "a", "ring": 1, "timed_out": False}]
        hostile = [
            json.dumps([{"test": "a", "ring": True, "timed_out": False}]),
            json.dumps([{"test": "a", "ring": 1.0, "timed_out": False}]),
            json.dumps([{"test": "a", "ring": 1, "timed_out": 0}]),
            '[{"test": "x", "test": "a", "ring": 1, "timed_out": false}]',
            json.dumps([{"test": "a", "ring": 1}]),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for payload in hostile:
                with self.subTest(payload=payload[:40]):
                    (out / "results.json").write_text(payload)
                    self.assertEqual(lane.committed_prefix(out, rows), [])
            (out / "results.json").write_text(json.dumps(rows))
            self.assertEqual(lane.committed_prefix(out, rows), rows)

    def test_fifo_with_live_writer_claims_nothing(self):
        # the only input distinguishing the regular-file check:
        # a FIFO streaming bytes that WOULD validate. A held
        # reader keeps the written bytes buffered while the
        # writer end is closed, so the read sees data-then-EOF
        # (an open writer would EAGAIN and mask the mutant).
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            fifo = out / "results.json"
            os.mkfifo(fifo)
            prefix = json.dumps(self.RESULTS[:1]).encode()
            reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
            try:
                writer = os.open(fifo, os.O_WRONLY)
                try:
                    os.write(writer, prefix)
                finally:
                    os.close(writer)
                self.assertEqual(
                    lane.committed_prefix(out, self.RESULTS), [])
            finally:
                os.close(reader)

    def test_close_failure_does_not_escape(self):
        # a read-only descriptor has nothing to flush: EIO on
        # close must not break the never-raises contract. The
        # mock closes for real first, so the test itself holds
        # the no-leak invariant it pins.
        real_close = os.close
        def close_then_fail(fd):
            real_close(fd)
            raise OSError("eio")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text(json.dumps(self.RESULTS[:1]))
            before = len(os.listdir("/proc/self/fd"))
            with mock.patch("os.close", side_effect=close_then_fail):
                self.assertEqual(
                    lane.committed_prefix(out, self.RESULTS),
                    self.RESULTS[:1])
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_memory_error_during_parse_claims_nothing(self):
        # 1MB of [{},{}...] decodes to ~25MB: a constrained
        # address space raises a RECOVERABLE MemoryError that
        # must not skip cleanup (r8 decline refuted by bytes).
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("[]")
            with mock.patch.object(lane.json, "loads",
                                   side_effect=MemoryError):
                self.assertEqual(lane.committed_prefix(out, self.RESULTS), [])


class DumpAtomicity(unittest.TestCase):
    def test_planted_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            victim = out / "victim.txt"
            victim.write_text("untouched")
            (out / "results.json.tmp").symlink_to(victim)
            lane.dump(out / "results.json", [{"test": "a"}])
            self.assertEqual(victim.read_text(), "untouched")
            self.assertEqual(
                json.loads((out / "results.json").read_text()), [{"test": "a"}])

    def test_roundtrip_replaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            lane.dump(out / "results.json", [{"test": "a"}])
            lane.dump(out / "results.json", [{"test": "a"}, {"test": "b"}])
            self.assertEqual(
                json.loads((out / "results.json").read_text()),
                [{"test": "a"}, {"test": "b"}])

    def test_published_files_stay_world_readable(self):
        # mkstemp is 0600: without an explicit fchmod the CI
        # summary check (unprivileged open as the runner user)
        # fails on every privileged run.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            lane.dump(out / "summary.json", {"complete": True})
            mode = (out / "summary.json").stat().st_mode & 0o777
            self.assertEqual(oct(mode), oct(0o644))

    def test_failed_replace_leaves_no_temp_and_raises_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "summary.json").mkdir()
            # IsADirectoryError, not a cleanup error: identity matters
            with self.assertRaises(IsADirectoryError):
                lane.dump(out / "summary.json", {"complete": True})
            leftovers = [p.name for p in out.iterdir()
                         if p.name.startswith("summary.json.")]
            self.assertEqual(leftovers, [])

    def test_failed_write_unlinks_without_masking_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            boom = ValueError("boom")
            before = len(os.listdir("/proc/self/fd"))
            for cleanup_error in (FileNotFoundError("raced"),
                                  PermissionError("denied")):
                with self.subTest(cleanup_error=type(cleanup_error).__name__):
                    stream = mock.MagicMock()
                    stream.write.side_effect = boom
                    with _owned_mkstemp(), \
                         mock.patch.object(lane, "_text_sink",
                                           return_value=stream), \
                         mock.patch("os.unlink",
                                    side_effect=cleanup_error):
                        with self.assertRaises(ValueError) as caught:
                            lane.dump(out / "summary.json",
                                      {"complete": True})
                    self.assertIs(caught.exception, boom)
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_write_error_stays_primary_when_close_also_fails(self):
        # a real TextIOWrapper retries the flush on close: the
        # close error must not demote the write error to context.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            stream = mock.MagicMock()
            stream.flush.side_effect = OSError(errno.ENOSPC, "no space")
            stream.close.side_effect = OSError(errno.EIO, "i/o error")
            before = len(os.listdir("/proc/self/fd"))
            with _owned_mkstemp(), \
                    mock.patch.object(lane, "_text_sink",
                                      return_value=stream):
                with self.assertRaises(OSError) as caught:
                    lane.dump(out / "summary.json", {"complete": True})
            self.assertEqual(caught.exception.errno, errno.ENOSPC)
            self.assertIsNotNone(caught.exception.__context__)
            self.assertEqual(caught.exception.__context__.errno, errno.EIO)
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_close_only_failure_propagates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            stream = mock.MagicMock()
            stream.close.side_effect = OSError(errno.EIO, "i/o error")
            before = len(os.listdir("/proc/self/fd"))
            with _owned_mkstemp(), \
                    mock.patch.object(lane, "_text_sink",
                                      return_value=stream):
                with self.assertRaises(OSError) as caught:
                    lane.dump(out / "summary.json", {"complete": True})
            self.assertEqual(caught.exception.errno, errno.EIO)
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_owned_mkstemp_cleans_up_on_unexpected_failure(self):
        # helper cleanup is in a finally: an unexpected test
        # failure inside must not contaminate later fd counts.
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(AssertionError):
            with _owned_mkstemp():
                tempfile.mkstemp()
                raise AssertionError("unexpected")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_publish_reports_instead_of_raising(self):
        # cleanup-time publishing must not abort the unmount /
        # ownership sequence: hostile FS conditions report.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertIsNone(
                lane._publish_json(out / "summary.json", {"a": 1}))
            self.assertEqual(
                json.loads((out / "summary.json").read_text()), {"a": 1})
            (out / "blocked.json").mkdir()
            error = lane._publish_json(out / "blocked.json", {"a": 1})
            self.assertIsInstance(error, str)
            self.assertTrue(error)

    def test_guarded_publish_defers_non_oserror(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            publish_errors, deferred = [], []
            lane._guarded_publish(out / "ok.json", {"a": 1},
                                  publish_errors, deferred)
            self.assertEqual((publish_errors, deferred), ([], []))
            (out / "blocked.json").mkdir()
            lane._guarded_publish(out / "blocked.json", {"a": 1},
                                  publish_errors, deferred)
            self.assertEqual(len(publish_errors), 1)
            self.assertEqual(deferred, [])
            boom = MemoryError("injected")
            with mock.patch.object(lane, "dump", side_effect=boom):
                lane._guarded_publish(out / "ok.json", {"a": 1},
                                      publish_errors, deferred)
            self.assertEqual(len(publish_errors), 1)
            self.assertEqual(deferred, [boom])

    def test_failed_dump_leaks_no_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            def fds():
                return len(os.listdir("/proc/self/fd"))
            before = fds()
            with mock.patch("os.fchmod", side_effect=OSError("nope")):
                with self.assertRaises(OSError):
                    lane.dump(out / "a.json", {})
            # close-then-raise mirrors _text_sink's contract (it
            # owns all its failures); a raise-without-close mock
            # would contradict it and lock in a double close.
            def close_then_raise(fd):
                os.close(fd)
                raise OSError("nope")
            with mock.patch.object(lane, "_text_sink",
                                   side_effect=close_then_raise):
                with self.assertRaises(OSError):
                    lane.dump(out / "b.json", {})
            self.assertEqual(fds(), before)

    def test_sink_failure_never_recloses_the_descriptor(self):
        # the number _text_sink closed may already be reused: a
        # witness fd opened in the mock deterministically takes
        # it (lowest-free reuse, single-threaded). dump must not
        # touch it.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            witness = []
            def close_and_track(fd):
                os.close(fd)
                witness.append(os.open(out / "witness",
                                       os.O_RDWR | os.O_CREAT, 0o644))
                raise OSError("no sink")
            before = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(lane, "_text_sink",
                                   side_effect=close_and_track):
                with self.assertRaises(OSError):
                    lane.dump(out / "c.json", {})
            os.fstat(witness[0])
            os.close(witness[0])
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)


class SelftestBpfVerdict(unittest.TestCase):
    LOG = PartialReceipt.OCT13_LOG

    def test_clean_exits_pass(self):
        self.assertEqual(
            lane.selftest_verdict(0, "reconcile: clean\n", "selftest-bpf", 20000),
            "PASS")
        self.assertEqual(
            lane.selftest_verdict(0, "token roundtrip ok\n", "selftest-token-smoke",
                                  20000),
            "PASS",
        )

    def test_accounted_partial_passes(self):
        self.assertEqual(
            lane.selftest_verdict(3, self.LOG, "selftest-bpf", 20000), "PASS")

    def test_unaccounted_defect_or_mismatch_fails(self):
        bad = [
            (3, ""),  # no accounting at all
            (3, "reconcile: partial\n"),  # marker without the count lines
            # silent loss: 6 gone, 3 receipted
            (3, _partial_output(97, 97, 194, 3, 0, 0, 0, 3)),
            # vacuous: exit 3 with nothing missing
            (3, _partial_output(100, 100, 200, 0, 0, 0, 0, 0)),
            # marker disagrees with the exit
            (3, _partial_output(9, 9, 18, 1, 0, 0, 1, 2,
                                marker="reconcile: defect\n")),
            (1, self.LOG),  # defect exit keeps failing
            (4, self.LOG),  # denied exit keeps failing
            (0, "SKIP: banned\n"),  # skip markers still fail at exit 0
            (3, self.LOG + "decoy: cell denied; skipping\n"),  # skips fail at 3 too
        ]
        for code, output in bad:
            with self.subTest(code=code, output=output):
                self.assertEqual(
                    lane.selftest_verdict(code, output, "selftest-bpf", 20000),
                    "FAIL")

    def test_partial_carveout_is_bpf_only(self):
        self.assertEqual(
            lane.selftest_verdict(3, self.LOG, "selftest-token-smoke", 20000),
            "FAIL",
        )


class ReadBodyLog(unittest.TestCase):
    def test_cr_preserved_end_to_end(self):
        out = _partial_output(9, 9, 18, 2, 0, 0, 0, 2).replace("\n", "\r\n")
        text = lane.decode_body_log(out.encode())
        self.assertIn("\r", text)
        self.assertIsNone(lane.partial_receipt(text, 10))

    def test_decode_is_explicit_utf8_with_replacement(self):
        text = lane.decode_body_log(b"ok \xff\xfe end")
        self.assertIn("ok ", text)
        self.assertIn("\ufffd", text)


class LeakNormalization(unittest.TestCase):
    def test_leak_fails_every_exit(self):
        for code in [0, 1, 3, 4, 124]:
            with self.subTest(code=code):
                self.assertEqual(lane.normalize_leak(code, True), 1)

    def test_no_leak_preserves_exit(self):
        for code in [0, 1, 3, 4, 124]:
            with self.subTest(code=code):
                self.assertEqual(lane.normalize_leak(code, False), code)


class GuestInventory(unittest.TestCase):
    def test_vng_guest_suite_inventory_is_explicit(self):
        # P3r narrowed (c): the vng-only suite stays inventoried
        # (reconcile-exact) with all three guest bodies; any drift
        # still aborts the lane via reconcile().
        self.assertEqual(lane.VNG_SUITE, ("kryprobe-privilege", "kcrypto_requests"))
        self.assertEqual(sorted(lane.EXPECTED[lane.VNG_SUITE]), [
            "guest_below_floor_refuses_typed",
            "guest_enokey_leaves_provider_unentered",
            "guest_sync_meta_matches_fixture_truth",
        ])


class PreparedIntegrity(unittest.TestCase):
    def bundle(self, root):
        paths = ["stage/runner.py", "stage/kcrypto_gen.py", "stage/debug/test-current"]
        paths += [f"{directory}/{name}" for directory in (
            "stage/kryprobe-bpf", "stage/debug/kryprobe-bpf", "stage/debug/deps/kryprobe-bpf"
        ) for name in lane.OBJECTS]
        hashes = {}
        for name in paths:
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(p.name if p.name in lane.OBJECTS else name)
            hashes[name] = lane.digest(p)
        return {"sha256": hashes, "host_debug": "/compiled/debug", "artifacts": [{
            "package_id": "example", "package": "example", "target": "test-current",
            "kind": ["test"], "features": [], "test": True,
            "executable": "/compiled/debug/test-current", "staged": "stage/debug/test-current",
            "sha256": hashes["stage/debug/test-current"], "bodies": ["required"],
        }]}

    def test_incomplete_hash_cover_and_changed_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.bundle(root)
            lane.verify_stage(root, manifest)
            for missing in ["stage/debug/test-current", "stage/kryprobe-bpf/kcrypto-lifecycle.bpf.o", "stage/kcrypto_gen.py"]:
                broken = copy.deepcopy(manifest)
                del broken["sha256"][missing]
                with self.subTest(missing=missing), self.assertRaises(ValueError):
                    lane.verify_stage(root, broken)
            (root / "stage/debug/test-current").write_text("old executable")
            with self.assertRaises(ValueError):
                lane.verify_stage(root, manifest)

    def test_escaped_or_duplicate_artifact_and_false_receipt_hash_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self.bundle(root)
            variants = []
            escaped = copy.deepcopy(original)
            escaped["artifacts"][0]["staged"] = "../outside"
            variants.append(escaped)
            duplicate = copy.deepcopy(original)
            duplicate["artifacts"] *= 2
            variants.append(duplicate)
            false_hash = copy.deepcopy(original)
            false_hash["artifacts"][0]["sha256"] = "0" * 64
            variants.append(false_hash)
            for variant in variants:
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    lane.verify_stage(root, variant)

    def test_a_second_execution_never_overwrites_first_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.bundle(root)
            manifest["schema"] = "kryprobe-privileged-lane/v1"
            lane.dump(root / "manifest.json", manifest)
            (root / "ownership.json").write_text("first run ownership\n")
            (root / "summary.json").write_text("first run terminal verdict\n")
            with mock.patch.object(lane.os, "geteuid", return_value=0), \
                    mock.patch.object(lane.os, "readlink", return_value="private"), \
                    self.assertRaises(ValueError):
                lane.execute(root, root / "lock", "parent", 1)
            self.assertEqual((root / "ownership.json").read_text(), "first run ownership\n")
            self.assertEqual((root / "summary.json").read_text(), "first run terminal verdict\n")

    def test_only_the_runtime_fsession_refusal_counts_as_supported_refusal(self):
        reason = "report: unsupported: kcrypto_fsession_unavailable (attach type 58 refused (errno 22) despite session kfuncs)"
        self.assertEqual(lane.lifecycle_verdict(4, reason), "SUPPORTED_REFUSAL")
        # F-C1: P5 manifest is 10 required fsession + 2 optional fentry
        # callbacks (attach-if-present, never gating); bring-up is
        # all-or-nothing on the required set, so a live sensor reports
        # attached in 10..12 against expected 12.
        for attached in (10, 11, 12):
            with self.subTest(attached=attached):
                line = json.dumps({"attached": attached, "audit": "attach", "expected": 12}) + "\n"
                self.assertEqual(lane.lifecycle_verdict(3, line), "PASS")
        self.assertEqual(lane.lifecycle_verdict(
            0, '{"attached":12,"audit":"attach","expected":12}\n'), "PASS")
        for code, output in [(0, reason), (4, "kernel 6.12"), (4, "object missing"),
                             (4, "permission denied"), (3, "partial without attach proof"),
                             (3, '{"attached":9,"audit":"attach","expected":12}\n'),
                             (3, '{"attached":13,"audit":"attach","expected":12}\n'),
                             (3, '{"attached":10,"audit":"attach","expected":11}\n'),
                             (3, '{"attached":7,"audit":"attach","expected":7}\n'),
                             (1, '{"attached":10,"audit":"attach","expected":12}\n'),
                             (3, '{"attached":10,"audit":"attach"}\n'),
                             (3, '{"attached":10,"audit":"attach","expected":12,"extra":1}\n')]:
            with self.subTest(code=code, output=output):
                self.assertEqual(lane.lifecycle_verdict(code, output), "FAIL")


def _bound_names(target):
    # names bound by an assignment-ish target.
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Starred):
        yield from _bound_names(target.value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _bound_names(elt)


def _match_names(pattern):
    # names bound by a match-case pattern.
    for node in ast.walk(pattern):
        if isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name:
                yield node.name
        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                yield node.rest


_NAMESPACE_FUNCS = ("globals", "locals", "vars")


def _namespace_store(target):
    # globals()["name"] = ... (locals/vars likewise)
    # rebinds "name" without an assignment-ish target.
    # Returns (found, key): key None means a dynamic
    # (non-constant) key — unresolvable, fail-closed
    # at the call site.
    if isinstance(target, ast.Subscript) \
            and isinstance(target.value, ast.Call) \
            and isinstance(target.value.func, ast.Name) \
            and target.value.func.id in _NAMESPACE_FUNCS:
        key = target.slice
        if isinstance(key, ast.Constant) \
                and isinstance(key.value, str):
            return True, key.value
        return True, None
    return False, None


def _store_root(target):
    # container root a subscript/attribute store lands
    # in (box for box["k"]/box.attr, None when the
    # target binds plain names instead).
    root = target
    while isinstance(root, (ast.Subscript, ast.Attribute)):
        root = root.value
    return root.id if isinstance(root, ast.Name) else None


def _binding_violations(source):
    """Tripwire violations for `source` (taint over execute/prepare).

    No reads through the log path or its aliases: taint seeds
    from the `log` name and from each run_logged call's log
    argument (a renamed seed must not launder it), flows
    through every rebinding form (assign, for, walrus, match;
    with/except names rebind but carry __enter__/exception
    values, never the path) and through targeted value
    shapes (IfExp, BoolOp, BinOp, Subscript, f-string,
    attribute access, and method calls on a tainted
    receiver), and must not reach a read or exec primitive
    — directly as a bare argument (starred arguments
    unwrapped) to any call except the diagnostic sinks
    (print, _say) and the bare run_logged consumer,
    both voided when rebound anywhere, by any form
    (plain, globals()/setattr, or dynamic — a
    dynamic namespace rebind fails closed outright;
    a dotted .run_logged call is never the
    consumer), and a call through a rebound method
    (Path.run_logged = Path.read_bytes) fires on a
    tainted receiver; and
    except the results.append publish sink narrowed
    to a CLEAN dict display or a CLEAN dict-bound-
    only name — dict targets must be direct Names
    (unpacking yields keys), mutations and nested
    def/class/global bindings void, tainted stores
    (subscript, attribute, or known-mutating method)
    taint the container root, and data positions
    must carry no taint (a bare path, raw, keyed,
    or read back through a subscript, fires right
    at the append; dict keys count, and only
    str(x.relative_to(...)) survives in a call
    position); or nested inside a larger argument
    to a read/exec primitive (copy/getoutput shapes
    included, so derived-path bookkeeping through
    publish sinks stays allowed but laundered reads
    fire). Containers
    (Tuple/List/Dict/Set displays) propagate taint, so
    a container round-trip back into a read fires;
    calls with an unrecognized callee (a call, a
    subscript, any other computed shape) are unknown
    sinks (a bare tainted argument fires), and read
    methods on tainted-containing receivers fire.
    Every run_logged is 3-unpacked
    (a discarded bare call is a violation too) with the
    bytes used past the call site but before the next
    rebinding of that name — positions are (line, col)
    so same-line semicolon rebinds narrow the horizon —
    and the deleted reader is gone module-wide.
    """
    read_attrs = ("open", "read_text", "read_bytes", "read")
    consumers = ("run_logged",)
    diagnostic_sinks = ("print", "_say")
    nested_denied = ("open", "Path", "PurePath", "fspath",
                     "check_output", "check_call", "run",
                     "Popen", "execv", "execve", "execl",
                     "execlp", "execvp", "execvpe", "system",
                     "popen", "read_bytes", "read_text",
                     "getoutput", "getstatusoutput",
                     "copyfile", "copy", "copy2", "move")
    tree = ast.parse(source)
    # A rebound sink name is no sink: any binding of a
    # diagnostic or consumer name voids its exemption
    # for the whole module — anywhere, by any form,
    # except the single top-level def that IS the real
    # sink (a wholesale replacement of that def is body
    # verification, out of scope like any new helper).
    top_level_defs = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            top_level_defs.add(id(stmt))
    rebound = set()
    dynamic_rebinds = []
    module_rebound_methods = set()

    def read_ref(value):
        # a read capability by shape alone (no taint
        # needed): a read-primitive name or a method
        # reference off one. Functions retrieved this
        # way bind their receiver when called through
        # an attribute, so the receiver's taint reads.
        if isinstance(value, ast.Name):
            return value.id in read_attrs
        if isinstance(value, ast.Attribute):
            return value.attr in read_attrs
        return False

    for top in ast.walk(tree):
        if isinstance(top, ast.Assign):
            maybe = list(top.targets)
        elif isinstance(top, ast.AnnAssign) \
                and top.value is not None:
            maybe = [top.target]
        elif isinstance(top, (ast.For, ast.AsyncFor)):
            maybe = [top.target]
        elif isinstance(top, ast.AugAssign):
            maybe = [top.target]
        elif isinstance(top, ast.NamedExpr):
            maybe = [top.target]
        elif isinstance(top, (ast.With, ast.AsyncWith)):
            maybe = [item.optional_vars for item in top.items
                     if item.optional_vars is not None]
        elif isinstance(top, ast.comprehension):
            maybe = [top.target]
        else:
            maybe = []
        for target in maybe:
            for name in _bound_names(target):
                rebound.add(name)
            found, key = _namespace_store(target)
            if found:
                if key is None:
                    dynamic_rebinds.append(top)
                else:
                    rebound.add(key)
        if isinstance(top, (ast.Assign, ast.AnnAssign)):
            stored = top.value
            targets = top.targets if isinstance(
                top, ast.Assign) else [top.target]
            if stored is not None:
                for target in targets:
                    if isinstance(target, ast.Attribute) \
                            and read_ref(stored):
                        module_rebound_methods.add(target.attr)
        if isinstance(top, ast.Call) \
                and isinstance(top.func, ast.Name) \
                and top.func.id == "setattr" \
                and len(top.args) >= 3:
            named = top.args[1]
            if isinstance(named, ast.Constant) \
                    and isinstance(named.value, str):
                if not isinstance(top.args[0], ast.Name):
                    rebound.add(named.value)
                elif read_ref(top.args[2]):
                    module_rebound_methods.add(named.value)
            else:
                dynamic_rebinds.append(top)
        if isinstance(top, ast.ExceptHandler) and top.name:
            rebound.add(top.name)
        if isinstance(top, ast.Match):
            for case in top.cases:
                for name in _match_names(case.pattern):
                    rebound.add(name)
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef,
                            ast.ClassDef)) \
                and id(top) not in top_level_defs:
            rebound.add(top.name)
        if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef,
                            ast.Lambda)):
            args = top.args
            params = list(args.args) + list(args.kwonlyargs)
            params += list(getattr(args, "posonlyargs", []))
            for extra in (args.vararg, args.kwarg):
                if extra is not None:
                    params.append(extra)
            for param in params:
                rebound.add(param.arg)
        if isinstance(top, (ast.Import, ast.ImportFrom)):
            for alias in top.names:
                bound = alias.asname or alias.name.split(".")[0]
                rebound.add(bound)
    rebound_diagnostics = rebound & set(diagnostic_sinks)
    rebound_consumers = rebound & set(consumers)
    funcs = [node for node in ast.walk(tree)
             if isinstance(node, ast.FunctionDef)
             and node.name in ("execute", "prepare")]
    violations = []
    if len(funcs) != 2:
        violations.append(f"expected execute+prepare, found {len(funcs)}")
        return violations
    for node in dynamic_rebinds:
        # A namespace rebind the guard cannot resolve
        # (globals()[computed] / setattr with a computed
        # name) fails closed right here: the rebound
        # name is unknowable, so no exemption survives
        # it silently.
        violations.append(
            f"line {node.lineno}: dynamic namespace rebind")

    def tainted_in(node, tainted):
        # Loads only: a Store (walrus target, comprehension
        # variable) merely reuses the spelling without
        # carrying the value.
        return any(isinstance(found, ast.Name)
                   and isinstance(found.ctx, ast.Load)
                   and found.id in tainted
                   for found in ast.walk(node))

    for func in funcs:
        tainted = {"log"}
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            called = node.func
            if not isinstance(called, ast.Name) \
                    or called.id != "run_logged":
                continue
            log_arg = node.args[1] if len(node.args) > 1 else None
            if log_arg is None:
                for keyword in node.keywords:
                    if keyword.arg == "log":
                        log_arg = keyword.value
            if isinstance(log_arg, ast.Name):
                tainted.add(log_arg.id)

        def direct_hit(value):
            # a bare name only: every deeper shape goes
            # through laundered() containment below.
            return isinstance(value, ast.Name) \
                and value.id in tainted

        def laundered(value):
            # targeted value-shape spread: the path
            # survives these launderings, so a binding
            # through any of them stays tainted.
            # Containers (Tuple/List/Dict/Set) propagate
            # too: the result-dict bookkeeping this
            # taints flows only to the results.append
            # publish sink, which stays allowed. A
            # method call on a tainted receiver counts;
            # a plain call with tainted arguments
            # already fires at its own construction
            # site (bare tainted argument), so
            # spreading through it would add nothing.
            if isinstance(value, (ast.IfExp, ast.BoolOp,
                                  ast.BinOp, ast.Subscript,
                                  ast.JoinedStr,
                                  ast.Attribute,
                                  ast.Tuple, ast.List,
                                  ast.Set, ast.Dict,
                                  ast.NamedExpr, ast.Lambda)):
                # A lambda counts by its body (and
                # defaults): a name bound to it yields
                # taint when called.
                return tainted_in(value, tainted)
            if isinstance(value, ast.Call) and isinstance(
                    value.func, ast.Attribute):
                return tainted_in(value.func.value,
                                  tainted)
            return False

        changed = True
        while changed:
            changed = False

            def spread(value, targets):
                nonlocal changed
                if not direct_hit(value) \
                        and not laundered(value):
                    return
                for target in targets:
                    for name in _bound_names(target):
                        if name not in tainted:
                            tainted.add(name)
                            changed = True

            def taint_store(value, targets):
                # A tainted store into a container taints
                # the container root: the path survives
                # inside (a later append publishes it, a
                # readback resolves it). Plain names are
                # spread()'s job; namespace stores rebind
                # their key; a tainted subscript key
                # smuggles the path just like a tainted
                # value. Runs inside the fixpoint so
                # aliases of the root taint in turn.
                nonlocal changed
                stored = direct_hit(value) \
                    or laundered(value)
                for target in targets:
                    for sub in ast.walk(target):
                        if not isinstance(sub, (ast.Subscript,
                                               ast.Attribute)) \
                                or not isinstance(
                                    sub.ctx, ast.Store):
                            continue
                        hit = stored
                        if isinstance(sub, ast.Subscript):
                            hit = hit or tainted_in(
                                sub.slice, tainted)
                        if hit:
                            root = _store_root(sub)
                            if root is not None \
                                    and root not in tainted:
                                tainted.add(root)
                                changed = True
                    found, key = _namespace_store(target)
                    if found and key is not None and stored \
                            and key not in tainted:
                        tainted.add(key)
                        changed = True

            def taint_receiver(node):
                # A known-mutating method call carrying
                # taint (box.update(raw=log)) taints the
                # receiver root, like a subscript store.
                # Deliberately narrow (update/setdefault/
                # extend/__setitem__): tainting every
                # method receiver would smear through
                # results.append itself.
                nonlocal changed
                if not isinstance(node.func, ast.Attribute) \
                        or not isinstance(node.func.value,
                                         ast.Name) \
                        or node.func.attr not in (
                            "update", "setdefault", "extend",
                            "__setitem__"):
                    return
                carried = [arg.value
                           if isinstance(arg, ast.Starred)
                           else arg for arg in node.args]
                carried.extend(keyword.value
                               for keyword in node.keywords)
                if any(direct_hit(arg) or laundered(arg)
                       for arg in carried):
                    receiver = node.func.value.id
                    if receiver not in tainted:
                        tainted.add(receiver)
                        changed = True

            for node in ast.walk(func):
                if isinstance(node, ast.Assign):
                    spread(node.value, list(node.targets))
                    taint_store(node.value, list(node.targets))
                elif isinstance(node, ast.AnnAssign) \
                        and node.value is not None:
                    spread(node.value, [node.target])
                    taint_store(node.value, [node.target])
                elif isinstance(node, ast.AugAssign):
                    spread(node.value, [node.target])
                    taint_store(node.value, [node.target])
                elif isinstance(node, (ast.For, ast.AsyncFor)):
                    spread(node.iter, [node.target])
                    taint_store(node.iter, [node.target])
                elif isinstance(node, ast.Call):
                    taint_receiver(node)
                elif isinstance(node, ast.NamedExpr):
                    spread(node.value, [node.target])
                elif isinstance(node, ast.Match):
                    if direct_hit(node.subject) \
                            or laundered(node.subject):
                        for case in node.cases:
                            for name in _match_names(case.pattern):
                                if name not in tainted:
                                    tainted.add(name)
                                    changed = True
            for node in ast.walk(func):
                # Minimal function summaries: a nested def
                # returning or yielding taint binds a name
                # that yields taint when called (appending
                # it for a later call-readback is an
                # escape). Runs inside the fixpoint so
                # late taint propagates into summaries.
                if not isinstance(node, (ast.FunctionDef,
                                         ast.AsyncFunctionDef)) \
                        or node is func:
                    continue
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Return):
                        yielded = sub.value
                    elif isinstance(sub, (ast.Yield,
                                          ast.YieldFrom)):
                        yielded = sub.value
                    else:
                        continue
                    if yielded is not None \
                            and (direct_hit(yielded)
                                 or laundered(yielded)) \
                            and node.name not in tainted:
                        tainted.add(node.name)
                        changed = True
        # Attribute names bound to a read capability or
        # a tainted value (taint now final): calling
        # through one passes the receiver, so
        # log.run_logged() reads when run_logged is
        # Path.read_bytes. Module-level read-ref
        # bindings join the per-function tainted ones.
        func_rebound_methods = set()
        for node in ast.walk(func):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                stored = node.value
                if stored is None:
                    continue
                if not read_ref(stored) \
                        and not tainted_in(stored, tainted):
                    continue
                targets = node.targets if isinstance(
                    node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute):
                        func_rebound_methods.add(target.attr)
            elif isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Name) \
                    and node.func.id == "setattr" \
                    and len(node.args) >= 3 \
                    and isinstance(node.args[0], ast.Name):
                named = node.args[1]
                if isinstance(named, ast.Constant) \
                        and isinstance(named.value, str) \
                        and (read_ref(node.args[2])
                             or tainted_in(node.args[2],
                                           tainted)):
                    func_rebound_methods.add(named.value)
        rebound_methods = (module_rebound_methods
                           | func_rebound_methods)
        # Names bound solely to dict displays in this
        # scope (taint now final, so mutations are
        # judged on the settled set): the only names
        # results.append accepts besides a clean dict
        # display itself. Only a DIRECT Name target of
        # a Dict counts (unpacking a dict yields keys,
        # not the dict). Comprehension targets never
        # appear here (no binding node exists for them,
        # and they cannot touch the function binding);
        # every other binding form voids, including
        # nested def/class names, global declarations,
        # and bindings inside nested bodies
        # (fail-closed: a nested non-dict binding voids
        # the exemption loudly rather than missing an
        # escape silently). A subscript store of a
        # tainted value, or a method call carrying
        # tainted arguments on the receiver, voids the
        # receiver root: the dict no longer holds only
        # its clean displays.
        dict_only = set()
        voided = set()
        dict_bindings = {}

        def void_names(target):
            for name in _bound_names(target):
                voided.add(name)

        def void_root(target):
            while isinstance(target, (ast.Subscript,
                                      ast.Attribute)):
                target = target.value
            if isinstance(target, ast.Name):
                voided.add(target.id)

        def arg_tainted(arg):
            return direct_hit(arg) or laundered(arg)

        for node in ast.walk(func):
            if isinstance(node, ast.Assign) \
                    and isinstance(node.value, ast.Dict) \
                    and all(isinstance(target, ast.Name)
                            for target in node.targets):
                for target in node.targets:
                    dict_only.add(target.id)
                    dict_bindings.setdefault(
                        target.id, []).append(node.value)
            elif isinstance(node, ast.AnnAssign) \
                    and node.value is not None \
                    and isinstance(node.value, ast.Dict) \
                    and isinstance(node.target, ast.Name):
                dict_only.add(node.target.id)
                dict_bindings.setdefault(
                    node.target.id, []).append(node.value)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(
                    node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    found, key = _namespace_store(target)
                    if found and key is not None:
                        # A namespace store rebinds its
                        # key exactly like a plain
                        # assignment of that name.
                        if isinstance(value, ast.Dict):
                            dict_only.add(key)
                            dict_bindings.setdefault(
                                key, []).append(value)
                        else:
                            voided.add(key)
                    elif isinstance(target, ast.Subscript) \
                            and value is not None \
                            and (arg_tainted(value)
                                 or tainted_in(target.slice,
                                               tainted)):
                        void_root(target)
                    else:
                        void_names(target)
            elif isinstance(node, ast.AugAssign):
                found, key = _namespace_store(node.target)
                if found and key is not None:
                    voided.add(key)
                elif isinstance(node.target, ast.Subscript) \
                        and (arg_tainted(node.value)
                             or tainted_in(node.target.slice,
                                           tainted)):
                    void_root(node.target)
                else:
                    void_names(node.target)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                found, key = _namespace_store(node.target)
                if found and key is not None:
                    voided.add(key)
                elif isinstance(node.target, ast.Subscript) \
                        and (arg_tainted(node.iter)
                             or tainted_in(node.target.slice,
                                           tainted)):
                    void_root(node.target)
                else:
                    void_names(node.target)
            elif isinstance(node, ast.NamedExpr):
                void_names(node.target)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        found, key = _namespace_store(
                            item.optional_vars)
                        if found and key is not None:
                            voided.add(key)
                        else:
                            void_names(item.optional_vars)
            elif isinstance(node, ast.ExceptHandler):
                if node.name:
                    voided.add(node.name)
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    for name in _match_names(case.pattern):
                        voided.add(name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    voided.add(alias.asname
                               or alias.name.split(".")[0])
            elif isinstance(node, (ast.FunctionDef,
                                   ast.AsyncFunctionDef,
                                   ast.ClassDef)) \
                    and node is not func:
                voided.add(node.name)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for name in node.names:
                    voided.add(name)
            elif isinstance(node, ast.Call) \
                    and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name):
                carried = [arg.value
                           if isinstance(arg, ast.Starred)
                           else arg for arg in node.args]
                carried.extend(keyword.value
                               for keyword in node.keywords)
                if any(arg_tainted(arg) for arg in carried):
                    voided.add(node.func.value.id)
        func_args = func.args
        for param in list(func_args.args) \
                + list(func_args.kwonlyargs) \
                + list(getattr(func_args, "posonlyargs", [])):
            voided.add(param.arg)
        for extra in (func_args.vararg, func_args.kwarg):
            if extra is not None:
                voided.add(extra.arg)
        dict_bound = dict_only - voided

        def pos_clean(value):
            # Data positions recurse; a call is clean only
            # when it is the sanctioned derived-path
            # bookkeeping (str(x.relative_to(...)) — a
            # relative path string, never the raw path)
            # or holds no taint at all (a bare tainted
            # argument into any call still fires at its
            # own construction site); anything else
            # holding taint is a readable path. Dict keys
            # count like values (**unpacking checks the
            # mapping itself).
            if isinstance(value, ast.Call):
                func = value.func
                if isinstance(func, ast.Name) \
                        and func.id == "str" \
                        and len(value.args) == 1 \
                        and not value.keywords:
                    inner = value.args[0]
                    if isinstance(inner, ast.Call) \
                            and isinstance(inner.func,
                                         ast.Attribute) \
                            and inner.func.attr == "relative_to":
                        return True
                return not tainted_in(value, tainted)
            if isinstance(value, ast.Dict):
                for key, item in zip(value.keys, value.values):
                    if key is None:
                        if not pos_clean(item):
                            return False
                    elif not pos_clean(key) \
                            or not pos_clean(item):
                        return False
                return True
            if isinstance(value, (ast.List, ast.Tuple,
                                  ast.Set)):
                return all(pos_clean(item)
                           for item in value.elts)
            if isinstance(value, ast.Starred):
                return pos_clean(value.value)
            return not tainted_in(value, tainted)

        def append_clean(only):
            if isinstance(only, ast.Dict):
                return pos_clean(only)
            if isinstance(only, ast.Name) \
                    and only.id in dict_bound:
                return all(pos_clean(display)
                           for display in dict_bindings.get(
                               only.id, []))
            return False

        loads = {(node.id, node.lineno, node.col_offset)
                 for node in ast.walk(func)
                 if isinstance(node, ast.Name)
                 and isinstance(node.ctx, ast.Load)}
        rebinds = {}

        def note(target, node):
            for name in _bound_names(target):
                rebinds.setdefault(name, []).append(
                    (node.lineno, node.col_offset))
            found, key = _namespace_store(target)
            if found and key is not None:
                rebinds.setdefault(key, []).append(
                    (node.lineno, node.col_offset))

        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    note(target, node)
            elif isinstance(node, ast.AnnAssign) \
                    and node.value is not None:
                note(node.target, node)
            elif isinstance(node, ast.AugAssign):
                note(node.target, node)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                note(node.target, node)
            elif isinstance(node, ast.NamedExpr):
                note(node.target, node)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        note(item.optional_vars, node)
            elif isinstance(node, ast.ExceptHandler):
                if node.name:
                    rebinds.setdefault(node.name, []).append(
                        (node.lineno, node.col_offset))
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    for name in _match_names(case.pattern):
                        rebinds.setdefault(name, []).append(
                            (node.lineno, node.col_offset))
        run_logged_calls = 0
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            called = node.func
            if isinstance(called, ast.Attribute) \
                    and called.attr in read_attrs \
                    and tainted_in(called.value, tainted):
                violations.append(
                    f"{func.name}:{node.lineno} reads tainted path")
                continue
            unknown = False
            if isinstance(called, ast.Name):
                opener = called.id
                simple = called.id
            elif isinstance(called, ast.Attribute):
                dotted = [called.attr]
                value = called.value
                while isinstance(value, ast.Attribute):
                    dotted.append(value.attr)
                    value = value.value
                if not isinstance(value, ast.Name):
                    unknown = True
                else:
                    dotted.append(value.id)
                    opener = ".".join(reversed(dotted))
                    simple = called.attr
            else:
                # Unknown sink: the callee is itself a
                # call (getattr(P, "m")), a subscript
                # (ops[0]), or any other computed shape
                # — a bare tainted argument still
                # escapes to it.
                unknown = True
            carried = [(arg.value
                        if isinstance(arg, ast.Starred) else arg)
                       for arg in node.args]
            carried.extend(keyword.value
                           for keyword in node.keywords)
            if unknown:
                if any(isinstance(arg, ast.Name)
                       and arg.id in tainted
                       for arg in carried):
                    violations.append(
                        f"{func.name}:{node.lineno} tainted "
                        "path escapes to call()")
                continue
            if opener in consumers \
                    and not rebound_consumers:
                # Bare run_logged only: a dotted
                # .run_logged call is not the consumer
                # (an attribute-store rebind would sail
                # through an endswith exemption).
                continue
            if opener in diagnostic_sinks \
                    and opener not in rebound_diagnostics:
                continue
            if opener == "results.append":
                # Publish sink, narrowly: a CLEAN dict
                # display or a CLEAN dict-bound-only name
                # (the result-dict bookkeeping, tainted
                # only inside sanitizing calls by design).
                # A tainted argument that is not clean
                # fires right here — falling through
                # would miss dict displays (never bare
                # Names) and bless subscript readbacks.
                if len(node.args) == 1 and not node.keywords:
                    only = node.args[0]
                    if append_clean(only):
                        continue
                    if isinstance(only, ast.Name) \
                            and only.id in tainted:
                        pass
                    elif not tainted_in(only, tainted):
                        continue
                    violations.append(
                        f"{func.name}:{node.lineno} tainted path "
                        f"escapes to {opener}()")
                    continue
            if isinstance(called, ast.Attribute) \
                    and simple in rebound_methods \
                    and tainted_in(called.value, tainted):
                # A rebound method receives the path
                # through its receiver: log.run_logged()
                # reads when run_logged is known to be
                # Path.read_bytes (or tainted).
                violations.append(
                    f"{func.name}:{node.lineno} tainted path escapes "
                    f"to {opener}()")
                continue
            if any(isinstance(arg, ast.Name)
                   and arg.id in tainted for arg in carried):
                violations.append(
                    f"{func.name}:{node.lineno} tainted path escapes "
                    f"to {opener}()")
                continue
            if simple in nested_denied and any(
                    tainted_in(arg, tainted) for arg in carried):
                violations.append(
                    f"{func.name}:{node.lineno} tainted path escapes "
                    f"to {opener}()")
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) \
                    and isinstance(node.value, ast.Call) \
                    and isinstance(node.value.func, ast.Name) \
                    and node.value.func.id == "run_logged":
                run_logged_calls += 1
                targets = node.targets[0]
                elts = targets.elts \
                    if isinstance(targets, (ast.Tuple, ast.List)) else []
                if len(elts) != 3:
                    violations.append(
                        f"{func.name}:{node.lineno} run_logged "
                        "not 3-unpacked")
                elif isinstance(elts[2], ast.Name):
                    bound = elts[2].id
                    site = (node.lineno, node.col_offset)
                    later = [pos for pos in rebinds.get(bound, [])
                             if pos > site]
                    horizon = min(later) if later \
                        else (float("inf"), float("inf"))
                    if not any(name == bound
                               and site < (line, col) < horizon
                               for name, line, col in loads):
                        violations.append(
                            f"{func.name}:{node.lineno} captured "
                            "bytes unused past the call site")
            elif isinstance(node, ast.Expr) \
                    and isinstance(node.value, ast.Call) \
                    and isinstance(node.value.func, ast.Name) \
                    and node.value.func.id == "run_logged":
                violations.append(
                    f"{func.name}:{node.lineno} run_logged "
                    "return discarded")
        if not run_logged_calls:
            violations.append(f"{func.name}: no run_logged calls")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) \
                and isinstance(node.func, ast.Name) \
                and node.func.id == "read_body_log":
            violations.append(f"deleted reader at line {node.lineno}")
    return violations


class CapturedBytesBinding(unittest.TestCase):
    def test_verdict_sites_never_reopen_log_paths(self):
        # the substitution fix is structural: verdicts hash and
        # parse fd-captured bytes. A call site reverted to path
        # reads stays green functionally, so pin the shape with
        # the narrow tripwire (see _binding_violations).
        # Known-narrow (documented, not missed): novel
        # primitives reached only through nested laundering
        # into unknown sinks (evil(deep(log)) with no bare
        # tainted argument anywhere), bindings
        # established inside comprehensions and lambda
        # signatures (a lambda BOUND to a name is
        # caught — its body and defaults count),
        # plain-container append
        # round-trips (x.append(log) then open(x[0]) —
        # appends don't bind; but a tainted container
        # reaching results.append fires at the append,
        # and subscript/attribute/known-mutator stores
        # propagate taint to the root), setattr through
        # a Name-held module (indistinguishable from an
        # attribute rebind), new helper functions,
        # nested-function scopes, and wholesale
        # replacement of the sink defs. Direct
        # constructor calls (Path(log),
        # pathlib.Path(log)) ARE caught, as is nesting
        # inside read/exec primitives. The
        # mock-driven ExecuteWiring behavioral tests
        # (selftest + Cargo + e2e + runtime-list +
        # lifecycle-support conflicting-bytes fixtures) are
        # the backstop for the execute verdict sites; the
        # prepare inventory sites have their own
        # mocked-subprocess drive (PrepareDriving) with
        # planted-path fixtures. This guard only catches
        # mechanical reverts.
        self.assertEqual(
            _binding_violations(Path(lane.__file__).read_text()), [])

    def test_tripwire_catches_documented_revert_shapes(self):
        # the guard's power, not just its passivity: each
        # revert shape must produce its violation. (AST-only;
        # mutants are never executed.)
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        cases = [
            ("kwargs",
             anchor,
             head + "            output = decode_body_log("
             "open(file=log, mode=\"rb\").read())\n",
             "tainted path escapes to open()"),
            ("attribute-open",
             anchor,
             head + "            output = decode_body_log("
             "os.read(os.open(log, 0), 9))\n",
             "tainted path escapes to os.open()"),
            ("annotated-alias",
             anchor,
             head + "            pth: str = log\n"
             "            output = decode_body_log("
             "open(pth, \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("tuple-alias",
             anchor,
             head + "            pth, _n = log, 0\n"
             "            output = decode_body_log("
             "open(pth, \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("direct-constructor",
             anchor,
             head + "            output = decode_body_log("
             "Path(log).read_bytes())\n",
             "tainted path escapes to Path()"),
            ("unused-site",
             anchor,
             head + "            output = decode_body_log(b\"\")\n",
             "captured bytes unused past the call site"),
            ("discard-before-rebind",
             "            bodies = parse_test_list("
             "captured.decode(\"utf-8\")) if code == 0 else []",
             "            bodies = []",
             "captured bytes unused past the call site"),
            ("discard-expr",
             "            code, _, captured = run_logged(\n"
             "                [str(runtime / row[\"staged\"]), \"--ignored\", "
             "\"--list\", \"--format\", \"terse\"],\n"
             "                log, 30, cwd=root, env=env)\n"
             "            bodies = parse_test_list("
             "captured.decode(\"utf-8\")) if code == 0 else []",
             "            run_logged([str(runtime / row[\"staged\"]), "
             "\"--ignored\", \"--list\", \"--format\", \"terse\"],\n"
             "                       log, 30, cwd=root, env=env)\n"
             "            bodies = row[\"bodies\"]",
             "run_logged return discarded"),
            ("for-rebind",
             anchor,
             head + "            for captured in [b\"x\"]:\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("walrus-rebind",
             anchor,
             head + "            print(captured := b\"x\")\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("with-rebind",
             anchor,
             head + "            with open(\"x\") as captured:\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("except-rebind",
             anchor,
             head + "            try:\n"
             "                pass\n"
             "            except OSError as captured:\n"
             "                pass\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("match-rebind",
             anchor,
             head + "            match code:\n"
             "                case int() as captured:\n"
             "                    pass\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("attribute-direct-fspath",
             anchor,
             head + "            tag = os.fspath(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to os.fspath()"),
            ("attribute-direct-pathlib",
             anchor,
             head + "            tag = pathlib.Path(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to pathlib.Path()"),
            ("nested-open-fspath",
             anchor,
             head + "            output = decode_body_log("
             "open(os.fspath(log), \"rb\").read())\n",
             "tainted path escapes to open()"),
            ("nested-exec-list",
             anchor,
             head + "            tag = "
             "subprocess.check_output([\"cat\", log])\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to "
             "subprocess.check_output()"),
            ("renamed-seed",
             "            log = logs / f\"{name}.log\"\n"
             "            code, timed_out, captured = "
             "run_logged([str(cli), *args], log, 180, "
             "cwd=root, env=env)\n"
             "            output = decode_body_log(captured)\n",
             "            slog = logs / f\"{name}.log\"\n"
             "            code, timed_out, captured = "
             "run_logged([str(cli), *args], slog, 180, "
             "cwd=root, env=env)\n"
             "            output = "
             "decode_body_log(slog.read_bytes())\n",
             "reads tainted path"),
            ("ifexp-alias",
             anchor,
             head + "            pth = log if code == 0 else None\n"
             "            output = decode_body_log(captured)\n"
             "            _diag = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("boolop-alias",
             anchor,
             head + "            pth = log or Path(\"/x\")\n"
             "            output = decode_body_log(captured)\n"
             "            _diag = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("binop-alias",
             anchor,
             head + "            pth = log / \"\"\n"
             "            output = decode_body_log(captured)\n"
             "            _diag = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("subscript-alias",
             anchor,
             head + "            pth = [log][0]\n"
             "            output = decode_body_log(captured)\n"
             "            _diag = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("fstring-alias",
             anchor,
             head + "            pth = f\"{log}\"\n"
             "            output = decode_body_log(captured)\n"
             "            _diag = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("method-receiver-alias",
             anchor,
             head + "            pth = log.absolute()\n"
             "            output = decode_body_log(captured)\n"
             "            _diag = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("attribute-alias",
             anchor,
             head + "            pth = log.parent\n"
             "            output = decode_body_log(captured)\n"
             "            _diag = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("semicolon-rebind",
             anchor,
             "            code, timed_out, captured = "
             "run_logged([str(cli), *args], log, 180, "
             "cwd=root, env=env); captured = b\"x\"\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("rebound-say",
             anchor,
             head + "            _say = open\n"
             "            output = decode_body_log(captured)\n"
             "            _d = _say(log, \"rb\").read()\n",
             "tainted path escapes to _say()"),
            ("dict-roundtrip",
             anchor,
             head + "            box = {\"p\": log}\n"
             "            output = decode_body_log(captured)\n"
             "            _d = open(box[\"p\"], \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("list-roundtrip",
             anchor,
             head + "            box = [log]\n"
             "            output = decode_body_log(captured)\n"
             "            _d = open(box[0], \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("tuple-call-elt",
             anchor,
             head + "            pth, _n = log.absolute(), 0\n"
             "            output = decode_body_log(captured)\n"
             "            _d = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("augassign-spread",
             anchor,
             head + "            pth = Path(\"/x\")\n"
             "            pth /= log\n"
             "            output = decode_body_log(captured)\n"
             "            _d = open(pth, \"rb\").read()\n",
             "tainted path escapes to open()"),
            ("augassign-horizon",
             anchor,
             head + "            captured += b\"x\"\n"
             "            output = decode_body_log(captured)\n",
             "captured bytes unused past the call site"),
            ("call-of-call",
             anchor,
             head + "            output = decode_body_log(captured)\n"
             "            _d = getattr(Path, \"read_bytes\")(log)\n",
             "tainted path escapes to call()"),
            ("chained-read",
             anchor,
             head + "            output = decode_body_log(captured)\n"
             "            _d = log.absolute().read_bytes()\n",
             "reads tainted path"),
            ("append-bare-path",
             anchor,
             head + "            results.append(log)\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("append-publish-roundtrip",
             anchor,
             head + "            results.append(log)\n"
             "            _d = results[0].read_bytes()\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("rebound-consumer",
             anchor,
             head + "            run_logged = open\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to run_logged()"),
            ("subscript-sink",
             anchor,
             head + "            ops[0](log)\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to call()"),
            ("starred-escape",
             anchor,
             head + "            pair = [log]\n"
             "            store(*pair)\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to store()"),
            ("getoutput-nested",
             anchor,
             head + "            tag = getoutput(f\"cat {log}\")\n"
             + "            output = decode_body_log(captured)\n",
             "tainted path escapes to getoutput()"),
            ("classmethod-nested-read",
             anchor,
             head + "            data = Path.read_bytes(log.parent)\n"
             + "            output = decode_body_log(captured)\n",
             "tainted path escapes to Path.read_bytes()"),
            ("copyfile-nested",
             anchor,
             head + "            shutil.copyfile(str(log), \"x\")\n"
             + "            output = decode_body_log(captured)\n",
             "tainted path escapes to shutil.copyfile()"),
            ("append-dict-unpack",
             anchor,
             head + "            p, = {log: None}\n"
             "            results.append(p)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("append-attr-consumer",
             anchor,
             head + "            Path.run_logged = Path.read_bytes\n"
             "            payload = Path.run_logged(log)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to Path.run_logged()"),
            ("append-subscript-store",
             anchor,
             head + "            result[\"raw\"] = log\n"
             "            results.append(result)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("append-dict-display-readback",
             anchor,
             head + "            results.append({\"p\": log})\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("append-update-mutation",
             anchor,
             head + "            result.update(**{\"raw\": log})\n"
             "            results.append(result)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("append-def-rebind",
             anchor,
             head + "            box = {\"log\": \"x\"}\n"
             "            def box():\n"
             "                return log\n"
             "            results.append(box)\n"
             "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("append-fresh-subscript-store",
             anchor,
             head + "            box = {}\n"
             "            box[\"raw\"] = log\n"
             "            results.append(box)\n"
             "            payload = results[0][\"raw\"].read_bytes()\n"
             + "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("append-dict-key",
             anchor,
             head + "            results.append({log: None})\n"
             "            payload = next(iter(results[0]))"
             ".read_bytes()\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("rebound-method-receiver",
             anchor,
             head + "            Path.run_logged = Path.read_bytes\n"
             "            payload = log.run_logged()\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.run_logged()"),
            ("append-unsanctioned-call",
             anchor,
             head + "            results.append({\"p\": "
             "str(log.absolute())})\n"
             "            _d = open(results[-1][\"p\"], "
             "\"rb\").read()\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to results.append()"),
            ("globals-sink-rebind",
             anchor,
             head + "            globals()[\"_say\"] = open\n" + "            output = decode_body_log(captured)\n"
             + "            _d = _say(log, \"rb\").read()\n",
             "tainted path escapes to _say()"),
            ("globals-dynamic-key",
             anchor,
             head + "            globals()[key] = open\n" + "            output = decode_body_log(captured)\n",
             "dynamic namespace rebind"),
            ("setattr-method-rebind",
             anchor,
             head + "            setattr(Path, \"run_logged\", "
             "Path.read_bytes)\n"
             "            payload = log.run_logged()\n" + "            output = decode_body_log(captured)\n",
             "tainted path escapes to log.run_logged()"),
            ("setattr-dynamic-name",
             anchor,
             head + "            setattr(Path, name, "
             "Path.read_bytes)\n" + "            output = decode_body_log(captured)\n",
             "dynamic namespace rebind"),
        ]
        for name, find, repl, fragment in cases:
            with self.subTest(shape=name):
                self.assertEqual(source.count(find), 1, name)
                violations = _binding_violations(
                    source.replace(find, repl))
                self.assertTrue(
                    any(fragment in violation
                        for violation in violations),
                    f"{name}: {violations}")

    def test_tripwire_allows_legitimate_shapes(self):
        # the guard's precision: derived-path bookkeeping and
        # uses before a rebinding must stay silent. Each case
        # must produce no violation at all.
        source = Path(lane.__file__).read_text()
        anchor = ("            code, timed_out, captured = "
                  "run_logged([str(cli), *args], log, 180, "
                  "cwd=root, env=env)\n"
                  "            output = decode_body_log(captured)\n")
        head = ("            code, timed_out, captured = "
                "run_logged([str(cli), *args], log, 180, "
                "cwd=root, env=env)\n")
        use = "            output = decode_body_log(captured)\n"
        cases = [
            ("alias-derived-write",
             anchor,
             head + "            pth = log\n"
             "            dump(pth.with_suffix(\".x\"), {})\n" + use),
            ("nested-allow-str",
             anchor,
             head + "            tag = "
             "str(log.relative_to(out))\n" + use),
            ("print-fstring",
             anchor,
             head + "            print(f\"wrote {log}\")\n" + use),
            ("use-before-for-rebind",
             anchor,
             anchor + "            for captured in [b\"x\"]:\n"
             "                pass\n"),
            ("use-before-with-rebind",
             anchor,
             anchor + "            with open(\"x\") as captured:\n"
             "                pass\n"),
            ("semicolon-use",
             anchor,
             "            code, timed_out, captured = "
             "run_logged([str(cli), *args], log, 180, "
             "cwd=root, env=env); "
             "output = decode_body_log(captured)\n"),
            ("say-log",
             anchor,
             head + "            _say(log)\n" + use),
            ("print-log",
             anchor,
             head + "            print(log)\n" + use),
            ("method-untainted-receiver",
             anchor,
             head + "            tag = captured.decode(\"utf-8\")\n"
             + use),
            ("append-dict-display",
             anchor,
             head + "            results.append("
             "{\"log\": str(log.relative_to(out))})\n" + use),
            ("append-dict-bound-name",
             anchor,
             head + "            box = {\"log\": str(log.relative_to(out))}\n"
             "            results.append(box)\n" + use),
            ("append-clean-subscript-store",
             anchor,
             head + "            box = {\"log\": str(log.relative_to(out))}\n"
             "            box[\"status\"] = \"ok\"\n"
             "            results.append(box)\n" + use),
            ("append-clean-method-update",
             anchor,
             head + "            box = {\"log\": str(log.relative_to(out))}\n"
             "            box.update(status=\"ok\")\n"
             "            results.append(box)\n" + use),
        ]
        for name, find, repl in cases:
            with self.subTest(shape=name):
                self.assertEqual(source.count(find), 1, name)
                self.assertEqual(
                    _binding_violations(source.replace(find, repl)),
                    [], name)


class DeferredCancel(unittest.TestCase):
    def test_signal_inside_window_sets_flag_without_raising(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(sig=sig):
                def boom(signum, frame):
                    raise InterruptedError("should be deferred")
                saved_flag = lane._CANCEL_REQUESTED
                old = signal.signal(sig, boom)
                try:
                    lane._CANCEL_REQUESTED = False
                    with lane._deferred_cancel():
                        os.kill(os.getpid(), sig)
                        deadline = time.monotonic() + 5
                        while not lane._CANCEL_REQUESTED \
                                and time.monotonic() < deadline:
                            pass
                        self.assertTrue(lane._CANCEL_REQUESTED)
                    self.assertIs(signal.getsignal(sig), boom)
                finally:
                    signal.signal(sig, old)
                    lane._CANCEL_REQUESTED = saved_flag

    def test_off_main_thread_is_plain_yield(self):
        errors = []
        def worker():
            try:
                with lane._deferred_cancel():
                    pass
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_failed_install_restores_partial_table_and_mask(self):
        # a fault between the two installs must not escape
        # with a half-installed table or a stuck mask.
        def boom(signum, frame):
            raise AssertionError("must not fire")
        saved_flag = lane._CANCEL_REQUESTED
        old_term = signal.signal(signal.SIGTERM, boom)
        old_int = signal.signal(signal.SIGINT, boom)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        real_signal = signal.signal
        def flaky(sig, handler):
            if sig == signal.SIGINT:
                raise OSError("install fault")
            return real_signal(sig, handler)
        try:
            lane._CANCEL_REQUESTED = False
            with mock.patch.object(lane.signal, "signal",
                                   side_effect=flaky):
                with self.assertRaises(OSError):
                    with lane._deferred_cancel():
                        pass
            self.assertIs(signal.getsignal(signal.SIGTERM), boom)
            self.assertIs(signal.getsignal(signal.SIGINT), boom)
            self.assertEqual(
                signal.pthread_sigmask(signal.SIG_BLOCK, ()), old_mask)
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
            lane._CANCEL_REQUESTED = saved_flag

    def test_install_and_restore_run_masked(self):
        # the mask order is the whole fix: block, swap, unmask
        # on the way in and on the way out.
        events = []
        real_mask = signal.pthread_sigmask
        real_signal = signal.signal
        def mask(op, sigs):
            events.append(("mask", op))
            return real_mask(op, sigs)
        def install(sig, handler):
            events.append(("swap", sig))
            return real_signal(sig, handler)
        old_term = signal.getsignal(signal.SIGTERM)
        old_int = signal.getsignal(signal.SIGINT)
        try:
            with mock.patch.object(lane.signal, "pthread_sigmask",
                                   side_effect=mask), \
                    mock.patch.object(lane.signal, "signal",
                                      side_effect=install):
                with lane._deferred_cancel():
                    pass
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
        kinds = [kind for kind, _ in events]
        self.assertEqual(kinds, ["mask", "swap", "swap", "mask",
                                 "mask", "swap", "swap", "mask"])
        self.assertEqual(
            [op for kind, op in events if kind == "mask"],
            [signal.SIG_BLOCK, signal.SIG_SETMASK,
             signal.SIG_BLOCK, signal.SIG_SETMASK])


class TextSink(unittest.TestCase):
    def test_fileio_failure_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "f.txt")
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
            before = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(lane.io, "FileIO",
                                   side_effect=OSError("no FileIO")):
                with self.assertRaises(OSError):
                    lane._text_sink(fd)
            self.assertEqual(len(os.listdir("/proc/self/fd")), before - 1)

    def test_chain_failure_leaks_nothing(self):
        for target in ("BufferedWriter", "TextIOWrapper"):
            with self.subTest(target=target), \
                    tempfile.TemporaryDirectory() as tmp:
                path = str(Path(tmp) / "f.txt")
                fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
                before = len(os.listdir("/proc/self/fd"))
                with mock.patch.object(lane.io, target,
                                       side_effect=MemoryError("no mem")):
                    with self.assertRaises(MemoryError):
                        lane._text_sink(fd)
                self.assertEqual(len(os.listdir("/proc/self/fd")), before - 1)

    def test_fileio_setup_failure_keeps_descriptor_open(self):
        # pins _text_sink's founding premise against a real
        # FileIO (not a mock): setup failure never owns the fd.
        with tempfile.TemporaryDirectory() as tmp:
            dfd = os.open(tmp, os.O_RDONLY)
            before = len(os.listdir("/proc/self/fd"))
            with self.assertRaises(OSError):
                lane.io.FileIO(dfd, "w")
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            os.fstat(dfd)
            os.close(dfd)

    def test_roundtrip_matches_fdopen_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "f.txt")
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
            stream = lane._text_sink(fd)
            stream.write('{"a": 1}\nline2\n')
            stream.close()
            with open(path, "rb") as check:
                self.assertEqual(check.read(), b'{"a": 1}\nline2\n')


class LoggedPaths(unittest.TestCase):
    def test_planted_log_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "victim.txt"
            victim.write_text("untouched")
            log = root / "body.log"
            log.symlink_to(victim)
            marker = root / "spawned"
            with self.assertRaises(OSError):
                lane.run_logged(["touch", str(marker)], log, 30)
            self.assertEqual(victim.read_text(), "untouched")
            self.assertFalse(marker.exists(), "no child may spawn")

    def test_preexisting_log_name_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "body.log"
            log.write_text("previous attempt")
            with self.assertRaises(OSError):
                lane.run_logged(["true"], log, 30)
            self.assertEqual(log.read_text(), "previous attempt")

    def test_planted_stderr_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "victim.txt"
            victim.write_text("untouched")
            err = root / "body.stderr"
            err.symlink_to(victim)
            with self.assertRaises(OSError):
                lane.run_logged(["true"], root / "body.log", 30,
                                stderr_path=err)
            self.assertEqual(victim.read_text(), "untouched")

    def test_captured_bytes_survive_post_write_path_swap(self):
        # the child renames a forged file over its own log path:
        # verdict bytes and the recorded hash must come from the
        # open descriptor, not from a re-read of the pathname.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "body.log"
            code, timed_out, captured = lane.run_logged(
                ["sh", "-c",
                 'printf "true-output"; printf "forged" > "$1.staged"; '
                 'mv "$1.staged" "$1"', "swapper", str(log)],
                log, 30)
            self.assertEqual((code, timed_out), (0, False))
            self.assertEqual(captured, b"true-output")
            self.assertEqual(log.read_bytes(), b"forged",
                             "positive control: the swap happened")
            result = json.loads(
                (root / "body.log.result.json").read_text())
            self.assertEqual(
                result["log_sha256"],
                hashlib.sha256(b"true-output").hexdigest())

    def test_log_sink_readable_under_restrictive_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = os.umask(0o077)
            try:
                lane.run_logged(["true"], root / "body.log", 30)
            finally:
                os.umask(old)
            mode = (root / "body.log").stat().st_mode & 0o777
            self.assertEqual(oct(mode), oct(0o644))

    def test_cancel_during_wait_raises_promptly(self):
        # flag-only cancel must break a long wait within
        # slices, not at child exit: a 10 s sleeper with
        # the flag set at 0.5 s raises in well under 8 s.
        # (On the single-wait shape this takes the full
        # 10 s: the flag is only honored in the finally.)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "sleep.log"
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = False
            def setter():
                lane._CANCEL_REQUESTED = True
            timer = threading.Timer(0.5, setter)
            timer.start()
            try:
                start = time.monotonic()
                with self.assertRaises(InterruptedError):
                    lane.run_logged(
                        [sys.executable, "-c",
                         "import time; time.sleep(10)"],
                        log, 30)
                self.assertLess(time.monotonic() - start, 8)
            finally:
                timer.cancel()
                timer.join(timeout=5)
                lane._CANCEL_REQUESTED = saved_flag
            result = json.loads(
                (Path(tmp) / "sleep.log.result.json").read_text())
            self.assertTrue(result["cancelled"])
            self.assertTrue(result["descendants_reaped"])

    def test_exited_child_is_never_mislabeled_timeout(self):
        # terminal status is observed before expiry: an
        # already-exited child with timeout=0 reports its
        # code, not 124. (On the expiry-first shape this
        # yields (124, True) with reaped_status 0.)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "instant.log"
            proc = subprocess.Popen(["true"])
            self.assertEqual(proc.wait(), 0)
            with mock.patch.object(lane.subprocess, "Popen",
                                   return_value=proc):
                code, timed_out, captured = lane.run_logged(
                    ["true"], log, 0)
            self.assertEqual((code, timed_out), (0, False))

    def test_sink_setup_is_not_charged_to_timeout(self):
        # the wait budget starts at spawn: a 0.5 s sink
        # setup with timeout=0.3 and a sleep-0.1 child
        # still reports the child's code. (On the
        # pre-spawn deadline this yields 124.) The child
        # lifetime is synchronized, not instant: an
        # instant child may already be terminal at the
        # first poll, and the poll-first branch then
        # returns before the deadline matters — the pin
        # silently disarms. A second gap sits between
        # the first poll and the expiry re-poll: a
        # stall there lets the child exit mid-decision,
        # and the re-poll observes termination on the
        # mutant too. So the first two polls per child
        # report canned alive to the lane (the decision
        # spans canned polls regardless of preemption)
        # while recording the real outcomes (the armed
        # proof stays honest: the child really is alive
        # then). Every iteration proves it is armed
        # (the first poll observes None) and proves the
        # delay applied (elapsed clears the setup
        # floor); under pathological load this fails
        # loud, never silent.
        with tempfile.TemporaryDirectory() as tmp:
            real_sink = lane._exclusive_sink
            real_popen = subprocess.Popen
            def slow_sink(*args, **kwargs):
                time.sleep(0.5)
                return real_sink(*args, **kwargs)
            polls = []
            class Recording(real_popen):
                def __init__(self, *args, **kwargs):
                    self._canned = 2
                    super().__init__(*args, **kwargs)

                def poll(self):
                    result = super().poll()
                    polls.append(result)
                    if self._canned > 0:
                        self._canned -= 1
                        return None
                    return result
            with mock.patch.object(lane, "_exclusive_sink",
                                   side_effect=slow_sink), \
                    mock.patch.object(lane.subprocess, "Popen",
                                       Recording):
                for iteration in range(3):
                    del polls[:]
                    log = Path(tmp) / f"slow-sink-{iteration}.log"
                    begin = time.monotonic()
                    code, timed_out, captured = lane.run_logged(
                        ["sleep", "0.1"], log, 0.3)
                    elapsed = time.monotonic() - begin
                    with self.subTest(iteration=iteration):
                        self.assertEqual((code, timed_out),
                                         (0, False))
                        self.assertGreaterEqual(elapsed, 0.5)
                        self.assertTrue(polls and polls[0] is None,
                                        f"pin disarmed: {polls}")

    def test_expiry_repolls_before_declaring_timeout(self):
        # terminal status is re-observed at the expiry
        # edge: a child that exits inside the budget is
        # reported exited even when the runner was
        # preempted after a stale poll. (Without the
        # re-poll this reports code 124 with
        # reaped_status 0.)
        real_popen = subprocess.Popen
        class Preempted(real_popen):
            def poll(self):
                result = super().poll()
                if result is None and not getattr(
                        self, "_once", False) \
                        and time.monotonic() - self._t0 > 0.05:
                    self._once = True
                    time.sleep(0.4)
                return result

            def __init__(self, *args, **kwargs):
                self._t0 = time.monotonic()
                super().__init__(*args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "race.log"
            with mock.patch.object(lane.subprocess, "Popen",
                                   Preempted), \
                    mock.patch.object(lane, "_WAIT_SLICE", 0.06):
                code, timed_out, captured = lane.run_logged(
                    ["sleep", "0.1"], log, 0.3)
            self.assertEqual((code, timed_out), (0, False))
            result = json.loads(
                log.with_suffix(".log.result.json").read_text())
            self.assertEqual(result["reaped_status"], 0)
            self.assertEqual(result["raw_exit"], 0)

    def test_failed_spawn_leaks_no_sink(self):
        # raw descriptors go to Popen (no wrap stage to fail);
        # a spawn failure must still unwind both sinks.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before = len(os.listdir("/proc/self/fd"))
            with mock.patch.object(lane.subprocess, "Popen",
                                   side_effect=OSError("noexec")):
                with self.assertRaises(OSError):
                    lane.run_logged(["true"], root / "body.log", 30,
                                    stderr_path=root / "body.stderr")
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_signal_during_sink_setup_defers_without_leak(self):
        # acquisition and the ownership arm share one shield:
        # SIGTERM inside fchmod defers (flag set, setup
        # completes, caller owns the fd) instead of leaking.
        def raising(signum, frame):
            lane._CANCEL_REQUESTED = True
            raise InterruptedError("cancelled")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved_flag = lane._CANCEL_REQUESTED
            old = signal.signal(signal.SIGTERM, raising)
            before = len(os.listdir("/proc/self/fd"))
            real_fchmod = os.fchmod
            def killer(fd, mode):
                os.kill(os.getpid(), signal.SIGTERM)
                return real_fchmod(fd, mode)
            try:
                lane._CANCEL_REQUESTED = False
                with mock.patch("os.fchmod", side_effect=killer):
                    fd = lane._exclusive_sink(root / "w.log")
                self.assertTrue(lane._CANCEL_REQUESTED)
                os.close(fd)
            finally:
                signal.signal(signal.SIGTERM, old)
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_signal_during_sink_registration_defers_without_leak(self):
        # acquisition and ExitStack registration share one
        # shield: SIGTERM between them defers instead of
        # leaking, and the run_logged checkpoint then raises
        # with both sinks owned and unwound.
        def raising(signum, frame):
            lane._CANCEL_REQUESTED = True
            raise InterruptedError("cancelled")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved_flag = lane._CANCEL_REQUESTED
            old = signal.signal(signal.SIGTERM, raising)
            before = len(os.listdir("/proc/self/fd"))
            real_callback = contextlib.ExitStack.callback
            fired = []
            def killer(self, *args, **kwargs):
                # only the two sink registrations (subprocess
                # uses ExitStack.callback internally too).
                if len(fired) < 2:
                    fired.append(1)
                    os.kill(os.getpid(), signal.SIGTERM)
                return real_callback(self, *args, **kwargs)
            try:
                lane._CANCEL_REQUESTED = False
                with mock.patch.object(contextlib.ExitStack, "callback",
                                       autospec=True,
                                       side_effect=killer):
                    with self.assertRaises(InterruptedError):
                        lane.run_logged(
                            ["true"], root / "c.log", 30,
                            stderr_path=root / "c.stderr")
                self.assertTrue(lane._CANCEL_REQUESTED)
            finally:
                signal.signal(signal.SIGTERM, old)
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)


class PrepareDriving(unittest.TestCase):
    # prepare() with a mocked subprocess layer (git, cargo,
    # test-list children) and real filesystem effects in a
    # tmp root: the prepare inventory sites get behavioral
    # conflicting-bytes fixtures instead of riding the
    # guard alone.
    CLI_ID = "kryprobe-cli 0.1.0 (path+file:///src)"
    POLICY_ID = "kryprobe-policy 0.1.0 (path+file:///src)"

    def _scaffold(self, root):
        host_debug = root / "host" / "debug"
        host_debug.mkdir(parents=True)
        (host_debug / "kryprobe").write_bytes(b"cli-binary")
        (host_debug / "probe_bin").write_bytes(b"probe-binary")
        for name in lane.OBJECTS:
            target = root / "target/kryprobe-bpf" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"object:" + name.encode())
        gen = root / "gen.py"
        gen.write_text("x = 1\n")
        out = root / "out"
        out.mkdir()
        return host_debug, gen, out

    def _cargo_payload(self, host_debug):
        def row(package_id, target, kind, test, exe):
            return {"reason": "compiler-artifact",
                    "package_id": package_id,
                    "target": {"name": target, "kind": kind},
                    "profile": {"test": test}, "features": [],
                    "executable": str(exe)}
        lines = [
            row(self.CLI_ID, "kryprobe", ["bin"], False,
                host_debug / "kryprobe"),
            row(self.POLICY_ID, "rule_unit", ["test"], True,
                host_debug / "probe_bin"),
            {"reason": "build-finished", "success": True},
        ]
        return ("\n".join(json.dumps(line) for line in lines)
                + "\n").encode()

    def _drive_prepare(self, root, out, cargo_bytes, listing,
                       run_hook=None, check_hook=None,
                       forbid_plain_check_output=False):
        saved_flag = lane._CANCEL_REQUESTED
        info = {"planted": [], "observed": [], "check_calls": []}
        metadata = json.dumps({"packages": [
            {"id": self.CLI_ID, "name": "kryprobe-cli"},
            {"id": self.POLICY_ID, "name": "kryprobe-policy"},
        ]}).encode()

        def fake_check_output(command, *, cwd=None, env=None,
                              text=False):
            info["check_calls"].append(list(command))
            if check_hook is not None:
                check_hook(command)
            if command[:2] == ["git", "ls-files"]:
                return b""
            if command[:2] == ["git", "rev-parse"]:
                return "deadbeef\n" if text else b"deadbeef\n"
            if command[1:2] == ["metadata"]:
                return metadata.decode() if text else metadata
            if command[-1:] == ["--version"]:
                return "tool 1.0\n" if text else b"tool 1.0\n"
            raise AssertionError(
                f"unexpected prepare call: {command}")

        def fake_run_logged(command, log, *args, **kwargs):
            if run_hook is not None:
                run_hook(command, log)
            if "--list" in command:
                return (0, False, listing)
            if command[1] == "xtask":
                return (0, False, b"")
            return (0, False, cargo_bytes)

        def fake_check_output_plain(*args, **kwargs):
            raise AssertionError("plain check_output used")

        patches = [
            mock.patch.object(lane, "_check_output_cancel",
                              side_effect=fake_check_output),
            mock.patch.object(lane, "run_logged",
                              side_effect=fake_run_logged),
            mock.patch.object(
                lane, "reconcile",
                side_effect=lambda observed: info[
                    "observed"].append(observed)),
        ]
        if forbid_plain_check_output:
            patches.append(mock.patch.object(
                lane.subprocess, "check_output",
                side_effect=fake_check_output_plain))
        try:
            with contextlib.ExitStack() as stack:
                for entered in patches:
                    stack.enter_context(entered)
                try:
                    manifest = lane.prepare(
                        root, out, "cargo", root / "gen.py")
                    return ("returned", manifest, info)
                except BaseException as error:
                    return ("raised", error, info)
        finally:
            lane._CANCEL_REQUESTED = saved_flag

    def test_prepare_cargo_uses_captured_bytes_not_planted_path(self):
        # the cargo-artifact site never reads the step log:
        # failed-build bytes planted there must not change
        # the inventory (the M8/G1 shape parses the log
        # path instead and dies on them). A divergent but
        # valid plant would break benign cross-step
        # agreement, so the plant is a meaningful failure
        # (cargo_artifacts rejects it), not a nominating
        # rival. BOTH cargo step logs are planted: a
        # revert reading either log must die, and a read
        # gated on one step's log cannot hide behind the
        # other's absence (the C4 shape).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_debug, gen, out = self._scaffold(root)
            cargo_bytes = self._cargo_payload(host_debug)
            planted = json.dumps(
                {"reason": "build-finished",
                 "success": False}) + "\n"
            planted_paths = []

            def plant(command, log):
                if command[1:2] in (["build"], ["test"]):
                    Path(log).write_bytes(planted.encode())
                    planted_paths.append(Path(log))

            listing = b"listed_body: test\n1 test, 0 benchmarks\n"
            outcome, manifest, info = self._drive_prepare(
                root, out, cargo_bytes, listing, run_hook=plant)
            self.assertEqual(outcome, "returned")
            by_target = {row["target"]: row
                         for row in manifest["artifacts"]}
            self.assertEqual(by_target["kryprobe"]["executable"],
                             str(host_debug / "kryprobe"))
            # the mock really did plant both conflicts.
            self.assertEqual(len(planted_paths), 2)
            for planted_path in planted_paths:
                self.assertEqual(planted_path.read_bytes(),
                                 planted.encode())

    def test_prepare_list_uses_captured_bytes_not_planted_path(self):
        # the prepare-listing site reads captured bytes: a
        # divergent listing planted at the list log must not
        # change the inventory (the M9/G2 shape reads it).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_debug, gen, out = self._scaffold(root)
            cargo_bytes = self._cargo_payload(host_debug)
            planted = b"planted_body: test\n1 test, 0 benchmarks\n"
            listing = b"listed_body: test\n1 test, 0 benchmarks\n"
            planted_paths = []

            def plant(command, log):
                if "--list" in command:
                    Path(log).write_bytes(planted)
                    planted_paths.append(Path(log))

            outcome, manifest, info = self._drive_prepare(
                root, out, cargo_bytes, listing, run_hook=plant)
            self.assertEqual(outcome, "returned")
            by_target = {row["target"]: row
                         for row in manifest["artifacts"]}
            self.assertEqual(by_target["rule_unit"]["bodies"],
                             ["listed_body"])
            self.assertEqual(
                info["observed"],
                [{("kryprobe-policy", "rule_unit"):
                  ["listed_body"]}])
            self.assertEqual(len(planted_paths), 1)
            self.assertEqual(planted_paths[0].read_bytes(),
                             planted)

    def test_prepare_checkpoint_aborts_between_staged_rows(self):
        # the per-row staging checkpoint (N6): the flag set
        # after the first row's digests raises at the second
        # row's checkpoint — with the prepare message, not
        # the digest one.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_debug, gen, out = self._scaffold(root)
            cargo_bytes = self._cargo_payload(host_debug)
            listing = b"listed_body: test\n1 test, 0 benchmarks\n"
            real_digest = lane.digest
            calls = []

            def counting_digest(path):
                result = real_digest(path)
                calls.append(path)
                if len(calls) == 2:
                    lane._CANCEL_REQUESTED = True
                return result

            with mock.patch.object(lane, "digest",
                                   side_effect=counting_digest):
                outcome, error, info = self._drive_prepare(
                    root, out, cargo_bytes, listing)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            self.assertEqual(str(error), "cancelled during prepare")
            self.assertGreaterEqual(len(calls), 2)

    def test_prepare_checkpoint_aborts_between_object_dirs(self):
        # the per-object-dir checkpoint (N7): the flag set
        # once staging copies finish raises at the first
        # object dir — before any object copy.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_debug, gen, out = self._scaffold(root)
            cargo_bytes = self._cargo_payload(host_debug)
            listing = b"listed_body: test\n1 test, 0 benchmarks\n"
            real_digest = lane.digest
            digests = []
            copies = []
            real_copyfile = lane.shutil.copyfile

            def counting_digest(path):
                result = real_digest(path)
                digests.append(path)
                if len(digests) == 4:
                    lane._CANCEL_REQUESTED = True
                return result

            def counting_copyfile(source, target):
                copies.append((source, target))
                return real_copyfile(source, target)

            with mock.patch.object(lane, "digest",
                                   side_effect=counting_digest), \
                    mock.patch.object(lane.shutil, "copyfile",
                                      side_effect=counting_copyfile):
                outcome, error, info = self._drive_prepare(
                    root, out, cargo_bytes, listing)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            self.assertEqual(str(error), "cancelled during prepare")
            self.assertEqual(len(copies), 2)

    def test_prepare_metadata_uses_cancel_aware_helper(self):
        # the cargo-metadata call routes through the
        # cancel-aware helper (N13): plain check_output is
        # never used.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host_debug, gen, out = self._scaffold(root)
            cargo_bytes = self._cargo_payload(host_debug)
            listing = b"listed_body: test\n1 test, 0 benchmarks\n"
            outcome, manifest, info = self._drive_prepare(
                root, out, cargo_bytes, listing,
                forbid_plain_check_output=True)
            self.assertEqual(outcome, "returned")
            self.assertTrue(any(command[1:2] == ["metadata"]
                                for command in info["check_calls"]))


class ExecuteWiring(unittest.TestCase):
    """Mock-driven execute() scenarios: finally wiring, publish
    precedence, signal shielding, and captured-bytes binding.

    Mocks replace only the privilege boundary (euid, mounts,
    stage verification, inventory reconciliation, child runs);
    the execute/finally control flow, verdicts, and publishing
    under test are real.
    """

    def _prepared_out(self, root, artifacts=()):
        out = root / "out"
        (out / "stage").mkdir(parents=True)
        (out / "logs").mkdir()
        manifest = {"schema": "kryprobe-privileged-lane/v1",
                    "artifacts": list(artifacts),
                    "sha256": {}, "host_debug": str(root / "host" / "debug"),
                    "root": str(root), "prepared_uid": 0, "prepared_gid": 0}
        (out / "manifest.json").write_text(json.dumps(manifest))
        for target in (root / "host" / "debug", root / "host" / "kryprobe-bpf",
                       root / "target" / "debug", root / "target" / "kryprobe-bpf"):
            target.mkdir(parents=True)
        lock = root / "lane.lock"
        lock.write_text("")
        return out, lock

    def _drive(self, root, out, lock, *, run_logged, run_hook=None,
               dump_hook=None, passthrough_run_cancel=False):
        saved_flag = lane._CANCEL_REQUESTED
        calls = []
        tmpfs_targets = []
        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[:2] == ["mount", "-t"]:
                tmpfs_targets.append(cmd[-1])
            if cmd[:1] == ["umount"]:
                # emulate the postcondition real unmount provides:
                # the mountpoint survives, its contents are gone.
                # Precondition (asserted): only the tmpfs runtime
                # may be nonempty — its contents lived on the
                # mount. A real bind-unmount would REVEAL
                # underlying contents instead of deleting them,
                # so a nonempty bind target fails the fixture.
                target = Path(cmd[1])
                if target.is_relative_to(root) and target.is_dir() \
                        and not target.is_symlink():
                    # In passthrough mode mounts bypass this
                    # mock (the test's Popen mock owns them),
                    # so tmpfs runtimes — always direct
                    # children of rt/ — are recognized by
                    # position. Anywhere else a bypassing
                    # mount is a harness bug and must fail.
                    known_tmpfs = str(target) in tmpfs_targets \
                        or (passthrough_run_cancel
                            and target.parent == runtime_base)
                    if any(target.iterdir()) and not known_tmpfs:
                        raise AssertionError(
                            "unmount emulation fed nonempty bind "
                            f"target: {target}")
                    for child in target.iterdir():
                        if child.is_dir() and not child.is_symlink():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
            if run_hook is not None:
                verdict = run_hook(cmd)
                if verdict is not None:
                    return verdict
            return mock.Mock(returncode=0, stderr="")
        runtime_base = root / "rt"
        runtime_base.mkdir(exist_ok=True)
        counter = [0]
        def fake_mkdtemp(*args, **kwargs):
            # pin the custody property the mock stands in for: the
            # runtime must live under /run, never a writable dir.
            assert kwargs.get("dir") == "/run", kwargs
            counter[0] += 1
            staged = runtime_base / f"r{counter[0]}"
            staged.mkdir()
            return str(staged)
        real_dump = lane.dump
        def fake_dump(path, value):
            if dump_hook is not None:
                override = dump_hook(path, value)
                if override is not None:
                    return override
            return real_dump(path, value)
        captured_stdout = io.StringIO()
        def fake_run_cancel(cmd, **kwargs):
            # Faithful to _run_cancel's contract: the
            # pre-spawn checkpoint raises before any
            # command runs; the mount itself is emulated
            # by fake_run (instant, so no poll window).
            if lane._CANCEL_REQUESTED:
                raise InterruptedError(
                    "cancelled before next command")
            return fake_run(cmd, **kwargs)
        patches = [
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(lane, "verify_stage"),
            mock.patch.object(lane, "reconcile"),
            mock.patch.object(lane.subprocess, "run", side_effect=fake_run),
            mock.patch("tempfile.mkdtemp", side_effect=fake_mkdtemp),
            mock.patch.object(lane, "run_logged", side_effect=run_logged),
        ]
        if not passthrough_run_cancel:
            # Mounts emulated (instant, so no poll window).
            # Passthrough runs the real _run_cancel with the
            # test's own Popen mock for wait-out coverage.
            patches.append(
                mock.patch.object(lane, "_run_cancel",
                                  side_effect=fake_run_cancel))
        if dump_hook is not None:
            patches.append(
                mock.patch.object(lane, "dump", side_effect=fake_dump))
        try:
            with contextlib.ExitStack() as stack:
                for entered in patches:
                    stack.enter_context(entered)
                stack.enter_context(contextlib.redirect_stdout(captured_stdout))
                try:
                    result = lane.execute(out, lock, "ns:fake", 20000)
                    return ("returned", result, calls,
                            captured_stdout.getvalue())
                except BaseException as error:
                    return ("raised", error, calls,
                            captured_stdout.getvalue())
        finally:
            # The flag restore is test hygiene (production
            # leaves it set for the enclosing scope); the
            # repair slot is deliberately NOT cleared — a
            # drive under cancellation() needs it to survive
            # until that scope consumes it, and every drive
            # overwrites it before it can matter.
            lane._CANCEL_REQUESTED = saved_flag

    def _assert_lock_released(self, lock):
        fd = os.open(lock, os.O_RDONLY)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.fail("lane lock still held after cleanup")
        finally:
            os.close(fd)

    def _umount_targets(self, calls):
        return [cmd[1] for cmd in calls if cmd[:1] == ["umount"]]

    def _mount_targets(self, calls):
        targets = []
        for cmd in calls:
            if cmd[:2] == ["mount", "--bind"]:
                targets.append(cmd[3])
            elif cmd[:2] == ["mount", "-t"]:
                targets.append(cmd[-1])
        return targets

    def test_failed_publish_keeps_cleanup_and_root_cause(self):
        # mid-run publish failures (ENOSPC-style) at both evidence
        # names: unmounts, ownership attempt, and lock close still
        # proceed, and the original failure (not the publish error)
        # propagates.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def nospace(path, value):
                if Path(path).name in ("summary.json", "ownership.json"):
                    raise OSError(errno.ENOSPC, "no space on device")
                return None
            def boom(*args, **kwargs):
                raise FileNotFoundError("stage binary gone")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                outcome, error, calls, printed = self._drive(
                    root, out, lock, run_logged=boom, dump_hook=nospace)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, FileNotFoundError)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self.assertGreater(len(self._umount_targets(calls)), 0)
            # failure/repair diagnostics go to stderr — a
            # parsed stdout must not ingest them.
            self.assertIn("failure summary not published",
                          stderr.getvalue())
            self.assertIn("evidence publishing problems",
                          stderr.getvalue())
            self.assertNotIn("failure summary not published", printed)
            self.assertNotIn("evidence publishing problems", printed)
            # the preamble reservation survives; the finished
            # receipt (children_reaped) never landed.
            preamble = json.loads((out / "ownership.json").read_text())
            self.assertEqual(preamble["status"], "running")
            self.assertNotIn("children_reaped", preamble)
            self._assert_lock_released(lock)

    def test_publish_failure_on_success_path_fails_lane(self):
        # nothing else pending: a lost ownership receipt must not
        # pass silently.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def nospace(path, value):
                if Path(path).name == "ownership.json":
                    raise OSError(errno.ENOSPC, "no space on device")
                return None
            outcome, error, calls, printed = self._drive(
                root, out, lock,
                run_logged=lambda *a, **k: (0, False, b""),
                dump_hook=nospace)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("lane evidence publishing failed", str(error))
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self._assert_lock_released(lock)

    def test_verdicts_follow_captured_bytes_not_paths(self):
        # the mock writes conflicting bytes to the log path while
        # returning the OCT13 partial log as captured: the PASS +
        # receipt must come from the descriptor, not the pathname.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            oct13 = PartialReceipt.OCT13_LOG.encode()
            def routed(command, log, *args, **kwargs):
                if command[1:3] == ["selftest", "bpf"]:
                    Path(log).write_bytes(
                        b"conflict: verdicts must ignore this\n")
                    return (3, False, oct13)
                if command[1:3] == ["selftest", "token-smoke"]:
                    return (0, False, b"token roundtrip ok\n")
                return (0, False, b"")
            outcome, code, calls, printed = self._drive(
                root, out, lock, run_logged=routed)
            self.assertEqual(outcome, "returned")
            summary = json.loads((out / "summary.json").read_text())
            self.assertTrue(summary["complete"])
            rows = {row["test"]: row for row in json.loads(
                (out / "results.json").read_text())}
            self.assertEqual(rows["selftest-bpf"]["status"], "PASS")
            accepted = rows["selftest-bpf"]["accepted_partial"]
            self.assertEqual(
                (accepted["exit"], accepted["calls"], accepted["missing"]),
                (3, 20000, 581))
            found = [row for row in summary["accepted_partials"]
                     if row.get("exit") == 3]
            self.assertEqual(len(found), 1)

    def test_body_verdicts_follow_captured_bytes_not_paths(self):
        # the Cargo body loop runs with a nonempty inventory
        # (runtime-list reconciliation + bodies): conflicting
        # bytes at the log path must not move verdicts — or
        # the e2e accepted receipt — off the captured bytes.
        key = ("kryprobe-policy", "rule_unit")
        row = {"package": key[0], "target": key[1],
               "test": "probe_bin", "staged": "stage/debug/probe_bin",
               "bodies": ["cargo_binding_probe"], "features": [],
               "sha256": "0" * 64}
        e2e_body = "selftest_bpf_clean_partial_or_denied"
        e2e = {"package": "kryprobe-cli", "target": "cli_bpf_e2e",
               "test": "e2e_bin", "staged": "stage/debug/e2e_bin",
               "bodies": [e2e_body], "features": [],
               "sha256": "0" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root, artifacts=[row, e2e])
            listing = b"cargo_binding_probe: test\n1 test, 0 benchmarks\n"
            e2e_listing = (e2e_body + ": test\n1 test, 0 benchmarks\n").encode()
            passing = (b"test cargo_binding_probe ... ok\n"
                       b"test result: ok. 1 passed; 0 failed; 0 ignored; "
                       b"0 measured; 0 filtered out; finished in 0.01s\n")
            failing = (b"test result: ok. 0 passed; 1 failed; 0 ignored; "
                       b"0 measured; 0 filtered out; finished in 0.01s\n")
            e2e_passing = (
                ("test %s ... ok\n"
                 "test result: ok. 1 passed; 0 failed; 0 ignored; "
                 "0 measured; 0 filtered out; finished in 0.01s\n"
                 "selftest bpf: accounted partial\n" % e2e_body).encode()
                + PartialReceipt.OCT13_LOG.encode())
            def routed(command, log, *args, **kwargs):
                if "--list" in command:
                    if command[0].endswith("probe_bin"):
                        return (0, False, listing)
                    return (0, False, e2e_listing)
                if "--exact" in command:
                    body = command[command.index("--exact") + 1]
                    if body == "cargo_binding_probe":
                        Path(log).write_bytes(failing)
                        return (0, False, passing)
                    Path(log).write_bytes(
                        b"conflict: no announcement here\n")
                    return (0, False, e2e_passing)
                return (0, False, b"")
            outcome, code, calls, printed = self._drive(
                root, out, lock, run_logged=routed)
            self.assertEqual(outcome, "returned")
            rows = json.loads((out / "results.json").read_text())
            cargo = [row for row in rows
                     if row.get("package") == key[0]
                     and row.get("test") == "cargo_binding_probe"]
            self.assertEqual(len(cargo), 1)
            self.assertEqual(cargo[0]["status"], "PASS")
            # the mock really did plant the conflict.
            self.assertIn(b"1 failed",
                          (out / cargo[0]["log"]).read_bytes())
            e2e_rows = [row for row in rows
                        if row.get("test") == e2e_body]
            self.assertEqual(len(e2e_rows), 1)
            self.assertEqual(e2e_rows[0]["status"], "PASS")
            accepted = e2e_rows[0]["accepted_partial"]
            self.assertEqual(
                (accepted["exit"], accepted["calls"], accepted["missing"]),
                (3, 20000, 581))
            # the receipt came from captured bytes: the path
            # never carried the announcement.
            self.assertNotIn(b"accounted partial",
                             (out / e2e_rows[0]["log"]).read_bytes())

    def test_runtime_list_mismatch_with_manifest_raises(self):
        # the runtime-listing inventory is bound to captured
        # bytes: a listing that disagrees with the manifest
        # raises instead of executing. A discard mutant
        # (bodies = row["bodies"]) sails through and stays
        # green here — this fixture is its red.
        key = ("kryprobe-policy", "rule_unit")
        row = {"package": key[0], "target": key[1],
               "test": "probe_bin", "staged": "stage/debug/probe_bin",
               "bodies": ["listed_body"], "features": [],
               "sha256": "0" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root, artifacts=[row])
            def routed(command, log, *args, **kwargs):
                if "--list" in command:
                    return (0, False, b"other_body: test\n"
                            b"1 test, 0 benchmarks\n")
                return (0, False, b"")
            outcome, error, calls, printed = self._drive(
                root, out, lock, run_logged=routed)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("runtime body inventory changed",
                          str(error))

    def test_runtime_list_failure_with_manifest_raises(self):
        # a nonzero listing exit invents no bodies: with a
        # nonempty manifest the empty inventory still raises.
        key = ("kryprobe-policy", "rule_unit")
        row = {"package": key[0], "target": key[1],
               "test": "probe_bin", "staged": "stage/debug/probe_bin",
               "bodies": ["listed_body"], "features": [],
               "sha256": "0" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root, artifacts=[row])
            def routed(command, log, *args, **kwargs):
                if "--list" in command:
                    return (1, False, b"")
                return (0, False, b"")
            outcome, error, calls, printed = self._drive(
                root, out, lock, run_logged=routed)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("runtime body inventory changed",
                          str(error))

    def test_runtime_list_follows_captured_bytes_not_planted_path(self):
        # the runtime-listing inventory is bound to captured
        # bytes even when the log path carries
        # manifest-matching bytes: a path-reading mutant
        # (open(log/"") instead of captured) sails through
        # and stays green here without this fixture.
        key = ("kryprobe-policy", "rule_unit")
        row = {"package": key[0], "target": key[1],
               "test": "probe_bin", "staged": "stage/debug/probe_bin",
               "bodies": ["listed_body"], "features": [],
               "sha256": "0" * 64}
        planted = (b"listed_body: test\n1 test, 0 benchmarks\n")
        captured = (b"other_body: test\n1 test, 0 benchmarks\n")
        self.assertEqual(lane.parse_test_list(planted.decode()),
                         ["listed_body"])
        self.assertEqual(lane.parse_test_list(captured.decode()),
                         ["other_body"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root, artifacts=[row])
            planted_paths = []
            def routed(command, log, *args, **kwargs):
                if "--list" in command:
                    Path(log).write_bytes(planted)
                    planted_paths.append(Path(log))
                    return (0, False, captured)
                return (0, False, b"")
            outcome, error, calls, printed = self._drive(
                root, out, lock, run_logged=routed)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("runtime body inventory changed",
                          str(error))
            # the mock really did plant the conflict.
            self.assertEqual(len(planted_paths), 1)
            self.assertEqual(planted_paths[0].read_bytes(),
                             planted)

    def test_runtime_list_nonzero_exit_with_matching_bytes_raises(self):
        # the exit code is honored, not just the bytes: a
        # matching listing with a nonzero exit still raises
        # (an ignore-the-code mutant sails through here —
        # the old empty-bytes fixture could not tell the
        # difference behaviorally).
        key = ("kryprobe-policy", "rule_unit")
        row = {"package": key[0], "target": key[1],
               "test": "probe_bin", "staged": "stage/debug/probe_bin",
               "bodies": ["listed_body"], "features": [],
               "sha256": "0" * 64}
        matching = (b"listed_body: test\n1 test, 0 benchmarks\n")
        self.assertEqual(lane.parse_test_list(matching.decode()),
                         ["listed_body"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root, artifacts=[row])
            def routed(command, log, *args, **kwargs):
                if "--list" in command:
                    return (1, False, matching)
                return (0, False, b"")
            outcome, error, calls, printed = self._drive(
                root, out, lock, run_logged=routed)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("runtime body inventory changed",
                          str(error))

    def test_lifecycle_verdict_follows_captured_bytes_not_path(self):
        # the lifecycle-support site reads captured bytes: a
        # failing log path next to passing bytes still
        # passes. (The evasive path-reading mutant survived
        # all 129 without this fixture.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            passing = json.dumps(
                {"audit": "attach",
                 "attached": lane.LIFECYCLE_REQUIRED,
                 "expected": lane.LIFECYCLE_EXPECTED}).encode() + b"\n"
            failing = b"no lifecycle announcement here\n"
            self.assertEqual(
                lane.lifecycle_verdict(0, failing.decode()), "FAIL")
            def routed(command, log, *args, **kwargs):
                if command[1:2] == ["report"]:
                    Path(log).write_bytes(failing)
                    return (0, False, passing)
                return (0, False, b"")
            outcome, code, calls, printed = self._drive(
                root, out, lock, run_logged=routed)
            self.assertEqual(outcome, "returned")
            rows = {row["test"]: row for row in json.loads(
                (out / "results.json").read_text())}
            self.assertEqual(rows["lifecycle-support"]["status"],
                             "PASS")
            # the mock really did plant the conflict.
            self.assertIn(b"no lifecycle announcement",
                          (out / rows["lifecycle-support"]["log"])
                          .read_bytes())

    def test_cancel_during_tmpfs_mount_still_unmounts(self):
        # wait-out mounts: the flag landing mid-mount does
        # not strand the effect — the tmpfs mount registers,
        # cleanup unmounts it, and the cancel raises at the
        # next checkpoint with the receipt rewritten. (On
        # the kill shape the mount never registers and no
        # unmount is attempted.) Runs the real _run_cancel
        # with a recording Popen mock.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            spawned = []

            def recording_popen(cmd, **kwargs):
                spawned.append(cmd)
                if cmd[:2] == ["mount", "-t"]:
                    lane._CANCEL_REQUESTED = True
                proc = mock.Mock()
                proc.wait.return_value = 0
                return proc

            with mock.patch.object(lane.subprocess, "Popen",
                                   side_effect=recording_popen):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""),
                    passthrough_run_cancel=True)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            tmpfs = [cmd[-1] for cmd in spawned
                     if cmd[:2] == ["mount", "-t"]]
            self.assertEqual(len(tmpfs), 1)
            self.assertEqual(self._umount_targets(calls), tmpfs)
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "cancelled")
            self._assert_lock_released(lock)

    def test_cancel_during_bind_mount_still_unmounts(self):
        # the same wait-out ownership for the bind path:
        # the flag landing during the first bind mount
        # registers it; the remount's pre-launch check
        # raises; cleanup unmounts both effects.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            spawned = []

            def recording_popen(cmd, **kwargs):
                spawned.append(cmd)
                if cmd[:2] == ["mount", "--bind"]:
                    lane._CANCEL_REQUESTED = True
                proc = mock.Mock()
                proc.wait.return_value = 0
                return proc

            with mock.patch.object(lane.subprocess, "Popen",
                                   side_effect=recording_popen):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""),
                    passthrough_run_cancel=True)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            tmpfs = [cmd[-1] for cmd in spawned
                     if cmd[:2] == ["mount", "-t"]]
            binds = [cmd[3] for cmd in spawned
                     if cmd[:2] == ["mount", "--bind"]]
            self.assertEqual((len(tmpfs), len(binds)), (1, 1))
            self.assertEqual(set(self._umount_targets(calls)),
                             set(tmpfs + binds))
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "cancelled")
            self._assert_lock_released(lock)

    def test_bind_mount_checks_cancel_before_spawn(self):
        # mount pre-launch pin (N12): a set flag raises
        # before any mount child spawns.
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = True
        try:
            with tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "mnt"
                target.mkdir()
                with mock.patch.object(
                        lane.subprocess, "Popen") as popen:
                    with self.assertRaises(InterruptedError):
                        lane.bind_readonly(Path(tmp), target, [])
                popen.assert_not_called()
        finally:
            lane._CANCEL_REQUESTED = saved_flag

    def test_busy_runtime_records_cleanup_error_not_skip(self):
        # rmdir containment: a busy runtime dir records a
        # cleanup error and the finalization still runs —
        # receipt, summary rewrite, and lock release. (On
        # the bare shape the OSError escapes with a stale
        # running receipt, no summary, and a held lock.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            with mock.patch.object(
                    Path, "rmdir",
                    side_effect=OSError(16, "Device or "
                                           "resource busy")):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("owned mount cleanup failed",
                          str(error))
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertTrue(any("rmdir failed" in entry.get(
                "stderr", "") for entry in receipt[
                    "cleanup_errors"]))
            summary = json.loads(
                (out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertIn("cleanup_errors", summary)
            self._assert_lock_released(lock)

    def test_umount_spawn_failure_records_and_continues(self):
        # umount containment: an OSError from the umount
        # call itself (fork EAGAIN, missing binary)
        # records a cleanup error per mount and every
        # unmount is still attempted — receipt, summary
        # rewrite, and lock release all run. (On the bare
        # shape the exception escapes with 1/6 unmounts
        # attempted, a stale running receipt, no summary,
        # and a held lock.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def fail_umount(cmd):
                if cmd[:1] == ["umount"]:
                    raise OSError(11, "Resource temporarily "
                                     "unavailable")
                return None
            outcome, error, calls, printed = self._drive(
                root, out, lock,
                run_logged=lambda *a, **k: (0, False, b""),
                run_hook=fail_umount)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("owned mount cleanup failed",
                          str(error))
            self.assertEqual(
                set(self._umount_targets(calls)),
                set(self._mount_targets(calls)))
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertTrue(any("umount failed" in entry.get(
                "stderr", "") for entry in receipt[
                    "cleanup_errors"]))
            summary = json.loads(
                (out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertIn("cleanup_errors", summary)
            self._assert_lock_released(lock)

    def test_umount_decode_failure_records_and_continues(self):
        # same containment for a ValueError from the
        # call (text-mode stderr decode of hostile
        # umount output): record per mount, attempt
        # every unmount, finalize.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def fail_umount(cmd):
                if cmd[:1] == ["umount"]:
                    raise UnicodeDecodeError(
                        "utf-8", b"\xff", 0, 1,
                        "invalid start byte")
                return None
            outcome, error, calls, printed = self._drive(
                root, out, lock,
                run_logged=lambda *a, **k: (0, False, b""),
                run_hook=fail_umount)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("owned mount cleanup failed",
                          str(error))
            self.assertEqual(
                set(self._umount_targets(calls)),
                set(self._mount_targets(calls)))
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertTrue(any("umount failed" in entry.get(
                "stderr", "") for entry in receipt[
                    "cleanup_errors"]))
            summary = json.loads(
                (out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertIn("cleanup_errors", summary)
            self._assert_lock_released(lock)

    def test_reap_failure_records_and_finalizes(self):
        # custody verification failure (children()
        # OSError at the first cleanup step) records a
        # reap error and finalizes: every unmount
        # attempted, failed receipt with children_reaped
        # False, summary rewritten, lock released.
        # (Uncontained, the OSError escapes with 0
        # unmounts, a stale running receipt, no summary,
        # and a held lock.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(12, "Cannot allocate "
                                            "memory")):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("owned mount cleanup failed",
                          str(error))
            self.assertEqual(
                set(self._umount_targets(calls)),
                set(self._mount_targets(calls)))
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertIs(receipt["children_reaped"], False)
            self.assertTrue(any(entry.get("target") == "reap"
                                for entry in receipt[
                                    "cleanup_errors"]))
            summary = json.loads(
                (out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertIn("cleanup_errors", summary)
            # the rmdir still ran: its gate tracks
            # unmounts only, not the custody failure.
            self.assertEqual(list((root / "rt").iterdir()), [])
            self._assert_lock_released(lock)

    def test_reap_verification_failure_records_and_finalizes(self):
        # children() failing at the final verification
        # (unmounts already done): failed receipt with
        # children_reaped False, a children record,
        # summary rewritten, lock released — and the
        # rmdir still ran (its gate tracks unmounts
        # only, not the custody failure).
        # (Uncontained: unmounts done but stale running
        # receipt, no summary, held lock.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_children = lane.children
            calls = []

            def flaky():
                calls.append(1)
                if len(calls) > 2:
                    raise OSError(12, "Cannot allocate memory")
                return real_children()

            with mock.patch.object(lane, "children",
                                   side_effect=flaky):
                outcome, error, drive_calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("owned mount cleanup failed",
                          str(error))
            receipt = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertIs(receipt["children_reaped"], False)
            self.assertTrue(any(entry.get("target") == "children"
                                for entry in receipt[
                                    "cleanup_errors"]))
            summary = json.loads(
                (out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertEqual(list((root / "rt").iterdir()), [])
            self._assert_lock_released(lock)

    def test_execute_ancestor_swap_before_pin_fails_closed(self):
        # out/'s ancestors stay preparer-writable: a
        # swap landing before the pin resolves fails the
        # pin open loud (ELOOP) — the privileged copy
        # never reads the replacement tree. (Unpinned,
        # the top resolves through the swap and foreign
        # bytes arrive silently.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            (root / "evil-out" / "stage").mkdir(parents=True)
            (root / "evil-out" / "stage" / "evil.txt").write_bytes(
                b"NOT-IN-STAGE")
            real_open = os.open
            swapped = []

            def racing_open(path, *args, **kwargs):
                if (not swapped
                        and kwargs.get("dir_fd") is None
                        and args and args[0] & os.O_DIRECTORY):
                    swapped.append(1)
                    os.rename(out, root / "out_orig")
                    os.symlink(root / "evil-out", out)
                return real_open(path, *args, **kwargs)

            with mock.patch("os.open", racing_open):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(swapped, [1])
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, OSError)
            self.assertFalse(list((root / "rt").glob(
                "*/stage/evil.txt")))
            self._assert_lock_released(lock)

    def test_execute_parent_swap_before_pin_fails_closed(self):
        # O_NOFOLLOW on out/ alone only guards the final
        # component: a symlink swapped into an ANCESTOR
        # before the pin resolves must fail the pin open
        # loud (ELOOP) — the privileged copy never reads
        # the replacement tree. (Final-component-only,
        # the top resolves through the swap; verify_stage
        # is mocked in this harness, so the evil bytes
        # would arrive silently and the drive succeed.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            evilroot = Path(tmp + "_evil")
            (evilroot / "out" / "stage").mkdir(parents=True)
            (evilroot / "out" / "manifest.json").write_bytes(
                (out / "manifest.json").read_bytes())
            (evilroot / "out" / "stage" / "evil.txt").write_bytes(
                b"NOT-IN-STAGE")
            os.rename(root, Path(tmp + "_orig"))
            os.symlink(evilroot, root)
            self.assertTrue(root.is_symlink())
            try:
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
                self.assertEqual(outcome, "raised")
                self.assertIsInstance(error, OSError)
                self.assertEqual(error.errno, errno.ELOOP)
                self.assertFalse(list((root / "rt").glob(
                    "*/stage/evil.txt")))
                self._assert_lock_released(lock)
            finally:
                # restore before the tmpdir teardown: rmtree
                # must see the real root, not the swap link.
                os.unlink(root)
                os.rename(Path(tmp + "_orig"), root)
                shutil.rmtree(evilroot, ignore_errors=True)

    def test_open_pinned_refuses_links_at_every_level(self):
        # the pin walk: a legit nested directory opens
        # (same identity as the path), a symlink at the
        # top or in any ancestor raises ELOOP exactly,
        # and a swapped-in non-directory raises ENOTDIR
        # — no descriptor leaks on any refusal. The
        # final-component file pins the fstat check
        # itself: the kernel open succeeds there, so
        # only the pin can refuse it (the mid-path file
        # dies in the next openat regardless).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deep = root / "a" / "b"
            deep.mkdir(parents=True)
            (root / "file").write_bytes(b"x")
            os.symlink(deep, root / "top-link")
            (root / "mid").mkdir()
            os.symlink(root / "mid", root / "mid-link")
            (root / "mid" / "leaf").mkdir()
            before = set(os.listdir("/proc/self/fd"))
            fd = lane._open_pinned(deep)
            try:
                self.assertEqual(
                    (os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                    (deep.stat().st_dev, deep.stat().st_ino))
            finally:
                os.close(fd)
            with self.assertRaises(FileNotFoundError):
                lane._open_pinned(root / "missing-link")
            with self.assertRaises(OSError) as caught:
                lane._open_pinned(root / "top-link")
            self.assertEqual(caught.exception.errno, errno.ELOOP)
            with self.assertRaises(OSError) as caught:
                lane._open_pinned(root / "mid-link" / "leaf")
            self.assertEqual(caught.exception.errno, errno.ELOOP)
            with self.assertRaises(OSError) as caught:
                lane._open_pinned(root / "file" / "leaf")
            self.assertEqual(caught.exception.errno, errno.ENOTDIR)
            with self.assertRaises(OSError) as caught:
                lane._open_pinned(root / "file")
            self.assertEqual(caught.exception.errno, errno.ENOTDIR)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_open_pinned_refuses_fifo_without_hang(self):
        # a FIFO swapped into the path refuses fast
        # (ENOTDIR): the component open must never
        # block on a writerless FIFO — the lane holds
        # its lock and mount there, and flag-only
        # cancel cannot release a blocking open (PEP 475
        # retries it). The watchdog rescues a hanging
        # worker with a writer end, then fails: a
        # rescue always means the shape regressed.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "block"
            os.mkfifo(path)
            errors, opened = [], []
            before = set(os.listdir("/proc/self/fd"))

            def attempt():
                try:
                    lane._open_pinned(path)
                except BaseException as error:
                    errors.append(error)
                else:
                    opened.append(1)

            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(10)
            rescued = worker.is_alive()
            if rescued:
                with contextlib.suppress(OSError):
                    release = os.open(
                        path, os.O_WRONLY | os.O_NONBLOCK)
                    os.close(release)
                worker.join(10)
            self.assertFalse(
                rescued, "pin walk blocked on a writerless FIFO")
            self.assertEqual(opened, [])
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], OSError)
            self.assertEqual(errors[0].errno, errno.ENOTDIR)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_open_pinned_parent_close_failure_releases_child(self):
        # a parent close failing mid-walk (EIO) releases
        # the owned child and never retries the parent
        # number: a failed close leaves the number's
        # state unknown (released-and-reused is
        # possible). (Retrying closes whatever reused
        # the number, and strands the child.)
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b"
            deep.mkdir(parents=True)
            real_close = os.close
            attempts = []
            state = {"fail": True}

            def flaky_close(fd):
                attempts.append(fd)
                real_close(fd)
                if state["fail"]:
                    state["fail"] = False
                    raise OSError(errno.EIO, "EIO")

            before = set(os.listdir("/proc/self/fd"))
            with mock.patch.object(os, "close",
                                   side_effect=flaky_close):
                with self.assertRaises(OSError) as caught:
                    lane._open_pinned(deep)
            self.assertEqual(caught.exception.errno, errno.EIO)
            self.assertEqual(len(attempts), len(set(attempts)),
                             attempts)
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_execute_copy_aborts_mid_tree_on_cancel(self):
        # the execute-site copy honors the flag mid-tree
        # (N14): shutil.copytree would run to completion.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            for index in range(5):
                (out / "stage" / f"f{index}").write_bytes(
                    b"data")
            real_stat = os.stat
            fired = []

            def flag_on_third(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if (path == "f2"
                        and kwargs.get("dir_fd") is not None):
                    fired.append(1)
                    lane._CANCEL_REQUESTED = True
                return result

            with mock.patch("os.stat", flag_on_third):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(fired, [1])
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)

    def test_signal_between_shield_installs_defers(self):
        # a real SIGINT placed deterministically between the two
        # installs of the OUTERMOST-open shield (the finally's —
        # a nested entry would already see deferred handlers):
        # the masked install pends it, cleanup completes, and
        # cancellation raises at the end with the table intact.
        def raising(signum, frame):
            lane._CANCEL_REQUESTED = True
            raise InterruptedError("real-signal")
        real_dc = lane._deferred_cancel
        counter = [0]
        stack = []
        @contextlib.contextmanager
        def tracking():
            counter[0] += 1
            index = counter[0]
            stack.append(index)
            try:
                with real_dc():
                    yield
            finally:
                stack.pop()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            seen = {}
            def mark(cmd):
                if cmd[:1] == ["umount"] and "target" not in seen:
                    seen["target"] = min(stack)
                return None
            with mock.patch.object(lane, "_deferred_cancel",
                                   side_effect=lambda: tracking()):
                self._drive(root, out, lock,
                            run_logged=lambda *a, **k: (0, False, b""),
                            run_hook=mark)
            target = seen["target"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            count = [0]
            @contextlib.contextmanager
            def armed():
                count[0] += 1
                if count[0] == target:
                    real_signal = signal.signal
                    def installs(sig, handler):
                        if sig == signal.SIGINT:
                            os.kill(os.getpid(), signal.SIGINT)
                        return real_signal(sig, handler)
                    with mock.patch.object(lane.signal, "signal",
                                           side_effect=installs):
                        with real_dc():
                            yield
                else:
                    with real_dc():
                        yield
            saved_flag = lane._CANCEL_REQUESTED
            old_term = signal.signal(signal.SIGTERM, raising)
            old_int = signal.signal(signal.SIGINT, raising)
            old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
            try:
                lane._CANCEL_REQUESTED = False
                with mock.patch.object(lane, "_deferred_cancel",
                                       side_effect=lambda: armed()):
                    outcome, error, calls, printed = self._drive(
                        root, out, lock,
                        run_logged=lambda *a, **k: (0, False, b""))
            finally:
                signal.signal(signal.SIGTERM, old_term)
                signal.signal(signal.SIGINT, old_int)
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self.assertGreater(len(self._umount_targets(calls)), 0)
            self.assertTrue((out / "ownership.json").is_file())
            self._assert_lock_released(lock)
            self.assertEqual(
                signal.pthread_sigmask(signal.SIG_BLOCK, ()), old_mask)

    def test_signal_during_cleanup_defers_to_end(self):
        # SIGTERM on the first umount: every unmount + ownership
        # still attempted, cancellation raised at the end.
        def raising(signum, frame):
            lane._CANCEL_REQUESTED = True
            raise InterruptedError(f"cancelled by signal {signum}")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            killed = []
            def kill_once(cmd):
                if cmd[:1] == ["umount"] and not killed:
                    killed.append(cmd)
                    os.kill(os.getpid(), signal.SIGTERM)
                return None
            old = signal.signal(signal.SIGTERM, raising)
            try:
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""),
                    run_hook=kill_once)
            finally:
                signal.signal(signal.SIGTERM, old)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self.assertGreater(len(self._umount_targets(calls)), 0)
            # the late cancel reaches the receipt (a bare
            # is_file check would pass on the preamble).
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "cancelled")
            self.assertIn("children_reaped", receipt)
            self._assert_lock_released(lock)

    def test_caller_except_context_does_not_suppress_publish_failure(self):
        # the end-raise gate keys on this invocation's own
        # failure flag: a caller-handled exception must not
        # produce a complete summary over a lost receipt.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def nospace(path, value):
                if Path(path).name == "ownership.json":
                    raise OSError(errno.ENOSPC, "no space on device")
                return None
            try:
                raise LookupError("unrelated, caller-handled")
            except LookupError:
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""),
                    dump_hook=nospace)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("lane evidence publishing failed", str(error))
            summary_path = out / "summary.json"
            if summary_path.exists():
                self.assertIsNot(
                    json.loads(summary_path.read_text()).get("complete"),
                    True)
            self._assert_lock_released(lock)

    def test_except_arm_oom_chains_instead_of_replacing(self):
        # SystemExit(23) in flight + MemoryError from the
        # failure summary publish: the exit survives with its
        # code, the escape chained as context.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def oom(path, value):
                if Path(path).name == "summary.json":
                    raise MemoryError("summary-fault")
                return None
            def die(*args, **kwargs):
                raise SystemExit(23)
            outcome, error, calls, printed = self._drive(
                root, out, lock, run_logged=die, dump_hook=oom)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, SystemExit)
            self.assertEqual(error.code, 23)
            self.assertIsInstance(error.__context__, MemoryError)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self._assert_lock_released(lock)

    def test_except_arm_termination_propagates_immediately(self):
        # genuine termination during failure reporting (the
        # lane's own cancel arrives as InterruptedError, never
        # this) is not chained-and-swallowed: it propagates,
        # with cleanup still running through the finally.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def intr(path, value):
                if Path(path).name == "summary.json":
                    raise KeyboardInterrupt()
                return None
            def fail(*args, **kwargs):
                raise ValueError("root cause")
            outcome, error, calls, printed = self._drive(
                root, out, lock, run_logged=fail, dump_hook=intr)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, KeyboardInterrupt)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self.assertGreater(len(self._umount_targets(calls)), 0)
            self._assert_lock_released(lock)

    def test_cancel_payload_escape_defers_like_publish_failure(self):
        # the cancel-summary payload (dict + summarize) is
        # evaluated under the site guard: a MemoryError there
        # defers past cleanup and chains onto the cancel raise
        # instead of aborting the sequence.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def flaky(results):
                raise MemoryError("payload-fault")
            def flag_on_mount(cmd):
                if cmd[:2] == ["mount", "-t"]:
                    lane._CANCEL_REQUESTED = True
                return None
            with mock.patch.object(lane, "summarize_partials",
                                   side_effect=flaky):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""),
                    run_hook=flag_on_mount)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            self.assertIsInstance(error.__cause__, MemoryError)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self.assertGreater(len(self._umount_targets(calls)), 0)
            self.assertTrue((out / "ownership.json").is_file())
            self._assert_lock_released(lock)

    def test_cleanup_failure_chains_deferred_publish_escape(self):
        # failing unmount + ownership MemoryError: the cleanup
        # error stays primary with the escape chained as cause.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def oom(path, value):
                if Path(path).name == "ownership.json":
                    raise MemoryError("injected")
                return None
            def fail_umount(cmd):
                if cmd[:1] == ["umount"]:
                    return mock.Mock(returncode=1, stderr="busy")
                return None
            outcome, error, calls, printed = self._drive(
                root, out, lock,
                run_logged=lambda *a, **k: (0, False, b""),
                run_hook=fail_umount, dump_hook=oom)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, ValueError)
            self.assertIn("owned mount cleanup failed", str(error))
            self.assertIsInstance(error.__cause__, MemoryError)
            self._assert_lock_released(lock)

    def test_cancel_during_final_publish_rewrites_evidence(self):
        # the flag set mid-dump of the complete summary (the
        # dump's own shield defers the signal): no complete:true
        # survives — ownership + summary are rewritten as
        # cancelled and the lane raises.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_dump = lane.dump
            def flag_on_complete(path, value):
                if Path(path).name == "summary.json" \
                        and value.get("complete") is True:
                    lane._CANCEL_REQUESTED = True
                return real_dump(path, value)
            with mock.patch.object(lane, "dump", side_effect=flag_on_complete):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertEqual(summary["error"], "cancelled")
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "cancelled")
            self._assert_lock_released(lock)

    def test_cancel_before_final_publish_skips_complete_write(self):
        # the flag set after the shielded finally exits but before
        # the final dump: the pre-dump checkpoint raises before
        # any complete:true payload is even built — none is
        # recorded, evidence is rewritten as cancelled.
        real_dc = lane._deferred_cancel
        counter = [0]
        stack = []
        @contextlib.contextmanager
        def tracking():
            counter[0] += 1
            index = counter[0]
            stack.append(index)
            try:
                with real_dc():
                    yield
            finally:
                stack.pop()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            seen = {}
            def mark(cmd):
                if cmd[:1] == ["umount"] and "target" not in seen:
                    seen["target"] = min(stack)
                return None
            with mock.patch.object(lane, "_deferred_cancel",
                                   side_effect=lambda: tracking()):
                self._drive(root, out, lock,
                            run_logged=lambda *a, **k: (0, False, b""),
                            run_hook=mark)
            target = seen["target"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            seen_payloads = []
            real_dump = lane.dump
            def record(path, value):
                if Path(path).name == "summary.json":
                    seen_payloads.append(value.get("complete"))
                return real_dump(path, value)
            count = [0]
            @contextlib.contextmanager
            def flag_after_outer():
                count[0] += 1
                index = count[0]
                with real_dc():
                    yield
                if index == target:
                    lane._CANCEL_REQUESTED = True
            with mock.patch.object(lane, "dump", side_effect=record), \
                    mock.patch.object(lane, "_deferred_cancel",
                                      side_effect=lambda: flag_after_outer()):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            self.assertNotIn(True, seen_payloads)
            self.assertEqual(seen_payloads, [False])
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")

    def test_signal_at_cleanup_entry_completes_cleanup(self):
        # inversion of the r14 hole: a real SIGTERM placed
        # exactly at the finally's shield entry, under the
        # lane's own flag-only cancellation. The shield
        # still installs, every unmount is attempted, the
        # lock is released, and the cancel is recorded
        # through the flag — no raise can abort the entry.
        # (On the raising shape this strands 0 unmounts,
        # a running receipt, and a held lock.)
        tree = ast.parse(Path(lane.__file__).read_text())
        func = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "execute")
        entries = []
        for node in ast.walk(func):
            if not isinstance(node, ast.Try) or not node.finalbody:
                continue
            for stmt in node.finalbody:
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.With):
                        for item in sub.items:
                            called = item.context_expr
                            if isinstance(called, ast.Call) \
                                    and isinstance(called.func, ast.Name) \
                                    and called.func.id == "_deferred_cancel":
                                entries.append(sub.lineno)
        self.assertEqual(len(entries), 1)
        entry_line = entries[0]
        real_dc = lane._deferred_cancel
        seen = []
        fired = []
        flagged = []
        @contextlib.contextmanager
        def killer_dc():
            frame = sys._getframe(1)
            while frame is not None:
                if frame.f_code.co_name == "execute" and \
                        frame.f_code.co_filename.endswith(
                            "sudo_lane.py"):
                    seen.append(frame.f_lineno)
                    if frame.f_lineno == entry_line \
                            and not fired:
                        fired.append(1)
                        os.kill(os.getpid(), signal.SIGTERM)
                        flagged.append(lane._CANCEL_REQUESTED)
                    break
                frame = frame.f_back
            with real_dc():
                yield
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = False
            try:
                with lane.cancellation():
                    with mock.patch.object(
                            lane, "_deferred_cancel",
                            side_effect=lambda: killer_dc()):
                        outcome, error, calls, printed = self._drive(
                            root, out, lock, run_logged=lambda *a, **k: (
                                0, False, b""))
                    # _drive's flag save/restore is test
                    # hygiene; in production the flag set by
                    # the kill persists into this scope.
                    lane._CANCEL_REQUESTED = True
            except InterruptedError as outer:
                self.assertIn("owned descendants reaped", str(outer))
            else:
                self.fail("cancel flag lost at cleanup entry")
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(fired, [1])
            self.assertEqual(flagged, [True])
            self.assertIn(entry_line, seen)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            self.assertEqual(
                self._umount_targets(calls),
                list(reversed(self._mount_targets(calls))))
            self.assertTrue(self._mount_targets(calls))
            self._assert_lock_released(lock)
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "cancelled")
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)

    def test_cancel_between_receipt_check_and_publish_republishes(self):
        # a flag landing after the adjacent L6 check but
        # before the ownership publish: the cancel-raise
        # branch republishes the receipt as cancelled
        # instead of leaving finished (the r14 comment
        # claimed the post-finally checkpoint corrects
        # this — it never runs on the raise path).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_gp = lane._guarded_publish
            hit = []
            def flag_on_publish(path, value, *args):
                if Path(path).name == "ownership.json" \
                        and not hit:
                    hit.append(value.get("status"))
                    lane._CANCEL_REQUESTED = True
                return real_gp(path, value, *args)
            with mock.patch.object(lane, "_guarded_publish",
                                   side_effect=flag_on_publish):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(hit, ["finished"])
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "cancelled")
            self._assert_lock_released(lock)

    def test_cancel_after_post_dump_check_repairs_evidence(self):
        # a real signal after the post-dump checkpoint, under
        # the lane's own cancellation: the completion
        # boundary holds — the slot repair rewrites the
        # complete summary as cancelled and the scope
        # raises. (On the raising shape the signal escapes
        # with complete:true retained.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            fired = []
            flagged = []
            real_print = print
            def killer_print(*args, **kwargs):
                if not fired and any("evidence" in str(part)
                                     for part in args):
                    fired.append(1)
                    os.kill(os.getpid(), signal.SIGTERM)
                    flagged.append(lane._CANCEL_REQUESTED)
                return real_print(*args, **kwargs)
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = False
            try:
                with lane.cancellation():
                    with mock.patch.object(builtins, "print",
                                           side_effect=killer_print):
                        outcome, code, calls, printed = self._drive(
                            root, out, lock,
                            run_logged=lambda *a, **k: (0, False, b""))
                    # _drive's flag save/restore is test
                    # hygiene; in production the flag set by
                    # the kill persists into this scope, where
                    # the consumed repair slot rewrites the
                    # evidence before the raise.
                    lane._CANCEL_REQUESTED = True
            except InterruptedError as outer:
                self.assertIn("owned descendants reaped", str(outer))
            else:
                self.fail("post-check cancel lost")
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(fired, [1])
            self.assertEqual(flagged, [True])
            self.assertEqual(outcome, "returned")
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertEqual(summary["error"], "cancelled")
            self.assertIn("accepted_partials", summary)
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["error"], "cancelled")
            self._assert_lock_released(lock)

    def test_repair_carries_snapshot_partials_not_raw_results(self):
        # the accepted partials are snapshotted at slot
        # registration: a cancel repair over nonempty
        # results writes the summarized partials, not the
        # raw result rows. (On the pass-results shape the
        # repair publishes rows without calls/missing.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            oct13 = PartialReceipt.OCT13_LOG.encode()
            fired = []
            real_print = print
            def killer_print(*args, **kwargs):
                if not fired and any("evidence" in str(part)
                                     for part in args):
                    fired.append(1)
                    os.kill(os.getpid(), signal.SIGTERM)
                return real_print(*args, **kwargs)
            def routed(command, log, *args, **kwargs):
                if command[1:3] == ["selftest", "bpf"]:
                    return (3, False, oct13)
                if command[1:3] == ["selftest", "token-smoke"]:
                    return (0, False, b"token roundtrip ok\n")
                return (0, False, b"")
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = False
            try:
                with lane.cancellation():
                    with mock.patch.object(builtins, "print",
                                           side_effect=killer_print):
                        outcome, code, calls, printed = self._drive(
                            root, out, lock, run_logged=routed)
                    lane._CANCEL_REQUESTED = True
            except InterruptedError:
                pass
            else:
                self.fail("post-check cancel lost")
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(fired, [1])
            self.assertEqual(outcome, "returned")
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            found = [row for row in summary["accepted_partials"]
                     if row.get("exit") == 3]
            self.assertEqual(len(found), 1)
            self.assertEqual((found[0].get("calls"),
                              found[0].get("missing")),
                             (20000, 581))

    def test_broken_body_print_keeps_lane_running(self):
        # stdout progress prints fail open: EPIPE on the
        # per-body line must not abort the run. (On the
        # bare-print shape this raises out of execute.)
        key = ("kryprobe-policy", "rule_unit")
        row = {"package": key[0], "target": key[1],
               "test": "probe_bin", "staged": "stage/debug/probe_bin",
               "bodies": ["b1"], "features": [],
               "sha256": "0" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root, artifacts=[row])
            real_print = print
            fired = []
            def flaky_print(*args, **kwargs):
                if any("rule_unit" in str(part) for part in args):
                    fired.append(1)
                    raise BrokenPipeError("stdout closed")
                return real_print(*args, **kwargs)
            def routed(command, log, *args, **kwargs):
                if "--list" in command:
                    return (0, False,
                            b"b1: test\n1 test, 0 benchmarks\n")
                return (0, False, b"")
            with mock.patch.object(builtins, "print",
                                   side_effect=flaky_print):
                outcome, code, calls, printed = self._drive(
                    root, out, lock, run_logged=routed)
            self.assertEqual(fired, [1])
            self.assertEqual(outcome, "returned")
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], True)
            self._assert_lock_released(lock)

    def test_second_signal_during_repair_still_repairs(self):
        # the flag set on the complete dump (post-check
        # fires) plus a second real signal between the
        # ownership and summary rewrites: under flag-only
        # semantics the second delivery only re-sets the
        # flag, so the repair completes anyway. (On the
        # raising shape the summary rewrite is skipped and
        # complete:true survives next to failed/cancelled.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_dump = lane.dump
            def flag_on_complete(path, value):
                if Path(path).name == "summary.json" \
                        and value.get("complete") is True:
                    lane._CANCEL_REQUESTED = True
                return real_dump(path, value)
            real_gp = lane._guarded_publish
            owners = []
            def in_rewrite():
                frame = sys._getframe(1)
                while frame is not None:
                    if frame.f_code.co_name == \
                            "publish_cancelled_and_raise":
                        return True
                    frame = frame.f_back
                return False
            def second_kill(path, value, *args):
                result = real_gp(path, value, *args)
                if Path(path).name == "ownership.json" \
                        and value.get("error") == "cancelled" \
                        and in_rewrite() and not owners:
                    owners.append(1)
                    os.kill(os.getpid(), signal.SIGTERM)
                return result
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = False
            try:
                with lane.cancellation():
                    with mock.patch.object(
                            lane, "dump",
                            side_effect=flag_on_complete), \
                            mock.patch.object(
                                lane, "_guarded_publish",
                                side_effect=second_kill):
                        outcome, error, calls, printed = self._drive(
                            root, out, lock,
                            run_logged=lambda *a, **k: (0, False, b""))
                    # _drive's flag save/restore is test
                    # hygiene; in production the flag that
                    # fired the post-check repair persists
                    # into this scope.
                    lane._CANCEL_REQUESTED = True
            except InterruptedError as outer:
                self.assertIn("owned descendants reaped", str(outer))
            else:
                self.fail("repair-path cancel lost")
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(owners, [1])
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, InterruptedError)
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertEqual(summary["error"], "cancelled")
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self._assert_lock_released(lock)

    def test_signal_during_slot_repair_still_repairs(self):
        # a real signal between the slot repair's two
        # publishes, under the lane's own cancellation: the
        # flag-only delivery cannot interrupt the backstop,
        # so the complete summary is still rewritten. (On
        # the raising shape the summary rewrite is skipped
        # and complete:true survives.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            fired = []
            flagged = []
            real_print = print
            def killer_print(*args, **kwargs):
                if not fired and any("evidence" in str(part)
                                     for part in args):
                    fired.append(1)
                    os.kill(os.getpid(), signal.SIGTERM)
                    flagged.append(lane._CANCEL_REQUESTED)
                return real_print(*args, **kwargs)
            real_gp = lane._guarded_publish
            owners = []
            def in_slot_repair():
                frame = sys._getframe(1)
                while frame is not None:
                    if frame.f_code.co_name == \
                            "_repair_cancelled_evidence":
                        return True
                    frame = frame.f_back
                return False
            def second_kill(path, value, *args):
                result = real_gp(path, value, *args)
                if Path(path).name == "ownership.json" \
                        and value.get("error") == "cancelled" \
                        and in_slot_repair() and not owners:
                    owners.append(1)
                    os.kill(os.getpid(), signal.SIGTERM)
                return result
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = False
            try:
                # the publish mock outlives the drive: the
                # slot repair runs at scope exit, after it.
                with mock.patch.object(
                        lane, "_guarded_publish",
                        side_effect=second_kill):
                    with lane.cancellation():
                        with mock.patch.object(
                                builtins, "print",
                                side_effect=killer_print):
                            outcome, code, calls, printed = \
                                self._drive(
                                    root, out, lock,
                                    run_logged=lambda *a, **k: (
                                        0, False, b""))
                        # _drive hygiene clears the flag the
                        # kill set; production persists it
                        # here, where the consumed slot
                        # rewrites the evidence.
                        lane._CANCEL_REQUESTED = True
            except InterruptedError as outer:
                self.assertIn("owned descendants reaped", str(outer))
            else:
                self.fail("post-check cancel lost")
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(fired, [1])
            self.assertEqual(flagged, [True])
            self.assertEqual(owners, [1])
            self.assertEqual(outcome, "returned")
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertEqual(summary["error"], "cancelled")
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self._assert_lock_released(lock)

    def test_repair_rewrites_without_reading_disk(self):
        # the slot repair is unconditional and memory-only:
        # with summary.json swapped for a symlink to a
        # divergent file, the repair replaces the link
        # itself instead of following it (a disk-reading
        # repair would trust the planted bytes and skip).
        # FIFOs and /dev/zero links are closed by the same
        # absence of any read — enforced here with traps:
        # results.json must never be opened at all, and
        # the evidence names never for read (temp writes
        # carry random suffixes, so exact-name matches
        # cannot false-fire).
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "results.json").write_text("[]")
            (out / "real.json").write_text(json.dumps(
                {"exit": 1, "complete": False,
                 "error": "planted"}))
            os.symlink(out / "real.json", out / "summary.json")
            receipt = {"status": "finished", "exit": 0}
            real_open = open
            real_os_open = os.open

            def no_evidence_read(path, *args, **kwargs):
                mode = args[0] if args else kwargs.get(
                    "mode", "r")
                if Path(path).name in (
                        "results.json", "summary.json",
                        "ownership.json") \
                        and ("r" in mode or "+" in mode):
                    raise AssertionError(
                        f"repair read evidence: {path}")
                return real_open(path, *args, **kwargs)

            def no_evidence_os_read(path, flags, *args,
                                    **kwargs):
                readable = flags & os.O_ACCMODE in (
                    os.O_RDONLY, os.O_RDWR)
                if Path(path).name == "results.json":
                    raise AssertionError(
                        f"repair touched results: {path}")
                if Path(path).name in (
                        "summary.json",
                        "ownership.json") and readable:
                    raise AssertionError(
                        f"repair read evidence: {path}")
                return real_os_open(path, flags, *args,
                                    **kwargs)

            with mock.patch.object(builtins, "open",
                                   side_effect=no_evidence_read), \
                    mock.patch.object(
                        os, "open",
                        side_effect=no_evidence_os_read):
                lane._repair_cancelled_evidence(out, receipt, [])
            self.assertFalse((out / "summary.json").is_symlink())
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertEqual(summary["error"], "cancelled")
            repaired = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(repaired["status"], "failed")
            # the planted target and the in-memory receipt
            # are untouched.
            self.assertEqual(
                json.loads((out / "real.json").read_text())["error"],
                "planted")
            self.assertEqual(receipt["status"], "finished")

    def test_execute_entry_clears_stale_repair_slot(self):
        # the unconditional repair must never run a stale
        # closure: execute drops the slot on entry, so a
        # raise before the tail leaves at most the
        # failure invalidator behind — never the stale
        # closure, never the cancel backstop.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            lane._CANCELLATION_REPAIR = lambda: None
            def boom(*args, **kwargs):
                raise FileNotFoundError("staged binary gone")
            try:
                outcome, error, calls, printed = self._drive(
                    root, out, lock, run_logged=boom)
                self.assertEqual(outcome, "raised")
                slot = lane._CANCELLATION_REPAIR
                self.assertIs(
                    slot.func,
                    lane._invalidate_custody_on_reap_failure)
            finally:
                lane._CANCELLATION_REPAIR = None

    def test_post_check_repair_registers_no_cancel_backstop(self):
        # the front-line repair runs before any backstop
        # registration: a flag at the post-dump check
        # raises with only the failure invalidator in the
        # slot — and the invalidator no-ops without a
        # reap failure, so the backstop cannot
        # double-repair. (Renamed: the slot is no longer
        # empty; it holds the custody invalidator.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_dump = lane.dump
            def flag_on_complete(path, value):
                if Path(path).name == "summary.json" \
                        and value.get("complete") is True:
                    lane._CANCEL_REQUESTED = True
                return real_dump(path, value)
            saved_flag = lane._CANCEL_REQUESTED
            saved_slot = lane._CANCELLATION_REPAIR
            saved_reap = lane._CANCELLATION_REAP_FAILED
            try:
                with mock.patch.object(lane, "dump",
                                       side_effect=flag_on_complete):
                    outcome, error, calls, printed = self._drive(
                        root, out, lock,
                        run_logged=lambda *a, **k: (0, False, b""))
                self.assertEqual(outcome, "raised")
                self.assertIsInstance(error, InterruptedError)
                slot = lane._CANCELLATION_REPAIR
                self.assertIs(
                    slot.func,
                    lane._invalidate_custody_on_reap_failure)
                snapshot = (out / "ownership.json").read_bytes()
                lane._CANCEL_REQUESTED = True
                with self.assertRaises(InterruptedError):
                    with lane.cancellation():
                        pass
                self.assertEqual(
                    (out / "ownership.json").read_bytes(), snapshot)
            finally:
                lane._CANCEL_REQUESTED = saved_flag
                lane._CANCELLATION_REPAIR = saved_slot
                lane._CANCELLATION_REAP_FAILED = saved_reap

    def test_cancelled_drive_plus_outer_reap_failure_invalidates(self):
        # a failed execution (no success slot) plus an
        # outer custody failure: the OSError propagates
        # and the stale children_reaped:true is amended —
        # preserving the original failure text. (Without
        # the failure invalidator, the OSError escapes
        # over an untouched true claim.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_dump = lane.dump
            def flag_on_complete(path, value):
                if Path(path).name == "summary.json" \
                        and value.get("complete") is True:
                    lane._CANCEL_REQUESTED = True
                return real_dump(path, value)
            saved_flag = lane._CANCEL_REQUESTED
            saved_slot = lane._CANCELLATION_REPAIR
            saved_reap = lane._CANCELLATION_REAP_FAILED
            try:
                with mock.patch.object(lane, "dump",
                                       side_effect=flag_on_complete):
                    outcome, error, calls, printed = self._drive(
                        root, out, lock,
                        run_logged=lambda *a, **k: (0, False, b""))
                self.assertEqual(outcome, "raised")
                self.assertIsInstance(error, InterruptedError)
                pre = json.loads(
                    (out / "ownership.json").read_text())
                self.assertIs(pre["children_reaped"], True)
                lane._CANCEL_REQUESTED = True
                with mock.patch.object(
                        lane, "children",
                        side_effect=OSError(5, "Input/output "
                                               "error")):
                    with self.assertRaises(OSError):
                        with lane.cancellation():
                            pass
                post = json.loads(
                    (out / "ownership.json").read_text())
                self.assertEqual(post["status"], "failed")
                self.assertIs(post["children_reaped"], False)
                self.assertIn("cancelled", post["error"])
                self.assertIn("reap failed", post["error"])
                summary = json.loads(
                    (out / "summary.json").read_text())
                self.assertIs(summary["complete"], False)
            finally:
                lane._CANCEL_REQUESTED = saved_flag
                lane._CANCELLATION_REPAIR = saved_slot
                lane._CANCELLATION_REAP_FAILED = saved_reap

    def test_broken_final_print_keeps_completed_lane(self):
        # the final diagnostic print is contained: EPIPE on
        # exactly that line must not fail a completed lane
        # (complete:true with exit 1). (On the bare-print
        # shape this raises out of execute.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_print = print
            fired = []
            def final_broken(*args, **kwargs):
                if any("evidence" in str(part) for part in args):
                    fired.append(1)
                    raise BrokenPipeError("stdout closed")
                return real_print(*args, **kwargs)
            with mock.patch.object(builtins, "print",
                                   side_effect=final_broken):
                outcome, code, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(fired, [1])
            self.assertEqual(outcome, "returned")
            summary = json.loads((out / "summary.json").read_text())
            self.assertIs(summary["complete"], True)

    def test_failed_complete_dump_marks_receipt_failed(self):
        # the complete dump failing (ENOSPC, a preparer
        # planting a directory) republishes the receipt as
        # failed instead of leaving finished over missing
        # evidence.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            real_dump = lane.dump
            def failing_dump(path, value):
                if Path(path).name == "summary.json" \
                        and value.get("complete") is True:
                    raise OSError(28, "No space left on device")
                return real_dump(path, value)
            with mock.patch.object(lane, "dump",
                                   side_effect=failing_dump):
                outcome, error, calls, printed = self._drive(
                    root, out, lock,
                    run_logged=lambda *a, **k: (0, False, b""))
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, OSError)
            receipt = json.loads((out / "ownership.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertIn("space", receipt["error"])
            self.assertFalse((out / "summary.json").exists())
            self._assert_lock_released(lock)

    def test_deferred_publish_escape_surfaces_after_cleanup(self):
        # MemoryError inside the ownership publish: unmounts and
        # the lock close still happen; the error surfaces gated
        # (nothing else pending here).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, lock = self._prepared_out(root)
            def oom(path, value):
                if Path(path).name == "ownership.json":
                    raise MemoryError("injected")
                return None
            outcome, error, calls, printed = self._drive(
                root, out, lock,
                run_logged=lambda *a, **k: (0, False, b""),
                dump_hook=oom)
            self.assertEqual(outcome, "raised")
            self.assertIsInstance(error, MemoryError)
            self.assertEqual(self._umount_targets(calls),
                             list(reversed(self._mount_targets(calls))))
            self.assertGreater(len(self._umount_targets(calls)), 0)
            self._assert_lock_released(lock)


class CancelHelper(unittest.TestCase):
    def test_check_output_cancel_breaks_slow_child(self):
        # the capture helper honors the flag within slices:
        # a 10 s sleeper with the flag set at 0.5 s raises
        # in well under 8 s, and the child is reaped. (On
        # the blocking shape this waits the full 10 s.)
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = False
        def setter():
            lane._CANCEL_REQUESTED = True
        timer = threading.Timer(0.5, setter)
        timer.start()
        try:
            start = time.monotonic()
            with self.assertRaises(InterruptedError):
                lane._check_output_cancel(
                    [sys.executable, "-c",
                     "import time; time.sleep(10)"])
            self.assertLess(time.monotonic() - start, 8)
        finally:
            timer.cancel()
            timer.join(timeout=5)
            lane._CANCEL_REQUESTED = saved_flag
        self.assertEqual(lane.children(), set())

    def test_check_output_cancel_skips_spawn_when_flagged(self):
        # pre-launch check: a set flag raises before any
        # child spawns.
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = True
        try:
            with mock.patch.object(lane.subprocess, "Popen") as popen:
                with self.assertRaises(InterruptedError):
                    lane._check_output_cancel(["true"])
            popen.assert_not_called()
        finally:
            lane._CANCEL_REQUESTED = saved_flag

    def test_check_output_cancel_keeps_exit_contract(self):
        # exit parity with check_output: bytes/text capture
        # and CalledProcessError with output on nonzero.
        out = lane._check_output_cancel(
            [sys.executable, "-c", "print('hi')"], text=True)
        self.assertEqual(out, "hi\n")
        raw = lane._check_output_cancel(
            [sys.executable, "-c", "print('hi')"])
        self.assertEqual(raw, b"hi\n")
        with self.assertRaises(subprocess.CalledProcessError) as failed:
            lane._check_output_cancel(
                [sys.executable, "-c",
                 "import sys; print('out'); sys.exit(3)"],
                text=True)
        self.assertEqual(failed.exception.returncode, 3)
        self.assertEqual(failed.exception.output, "out\n")

    def test_run_cancel_breaks_slow_child(self):
        # same slices without capture: flag at 0.5 s into a
        # 10 s sleeper raises in well under 8 s.
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = False
        def setter():
            lane._CANCEL_REQUESTED = True
        timer = threading.Timer(0.5, setter)
        timer.start()
        try:
            start = time.monotonic()
            with self.assertRaises(InterruptedError):
                lane._run_cancel(
                    [sys.executable, "-c",
                     "import time; time.sleep(10)"])
            self.assertLess(time.monotonic() - start, 8)
        finally:
            timer.cancel()
            timer.join(timeout=5)
            lane._CANCEL_REQUESTED = saved_flag
        self.assertEqual(lane.children(), set())

    def test_run_cancel_keeps_check_contract(self):
        # run parity: check=True raises on nonzero, plain
        # returns the code in a CompletedProcess.
        done = lane._run_cancel([sys.executable, "-c", "pass"],
                                check=True)
        self.assertEqual(done.returncode, 0)
        with self.assertRaises(subprocess.CalledProcessError):
            lane._run_cancel([sys.executable, "-c",
                              "import sys; sys.exit(3)"],
                             check=True)
        skewed = lane._run_cancel(
            [sys.executable, "-c", "import sys; sys.exit(3)"])
        self.assertEqual(skewed.returncode, 3)

    def test_digest_honors_flag(self):
        # the hash loop checks per chunk: a set flag raises
        # before hashing anything; clear hashes normally.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.bin"
            path.write_bytes(b"abc" * 1000)
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = True
            try:
                with self.assertRaises(InterruptedError):
                    lane.digest(path)
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual(
                lane.digest(path), hashlib.sha256(b"abc" * 1000)
                .hexdigest())

    def test_copytree_cancel_copies_and_refuses_exotic(self):
        # regular files, subdirs, and symlinks-as-links copy
        # across; a fifo fails closed instead of hanging.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/sub").mkdir(parents=True)
            (root / "src/top.bin").write_bytes(b"top")
            (root / "src/sub/nested.bin").write_bytes(b"nested")
            os.symlink("top.bin", root / "src/link.bin")
            lane._copytree_cancel(root / "src", root / "dst")
            self.assertEqual((root / "dst/top.bin").read_bytes(),
                             b"top")
            self.assertEqual(
                (root / "dst/sub/nested.bin").read_bytes(), b"nested")
            link = root / "dst/link.bin"
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "top.bin")
            os.mkfifo(root / "src/pipe")
            with self.assertRaises(ValueError):
                lane._copytree_cancel(root / "src", root / "dst2")

    def test_copytree_cancel_honors_flag(self):
        # pre-set flag: no file is copied, promptly.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src/big.bin").write_bytes(b"x" * (1 << 20))
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = True
            try:
                with self.assertRaises(InterruptedError):
                    lane._copytree_cancel(root / "src", root / "dst")
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertFalse((root / "dst/big.bin").exists())

    def test_copyfile_cancel_checks_per_chunk(self):
        # the per-chunk check: a pre-set flag raises before
        # the first chunk lands (the target stays empty).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src.bin").write_bytes(b"y" * (1 << 20))
            saved_flag = lane._CANCEL_REQUESTED
            lane._CANCEL_REQUESTED = True
            try:
                with self.assertRaises(InterruptedError):
                    lane._copyfile_cancel(root / "src.bin",
                                          root / "dst.bin")
            finally:
                lane._CANCEL_REQUESTED = saved_flag
            self.assertEqual((root / "dst.bin").read_bytes(), b"")

    def test_check_output_cancel_reaps_despite_pipe_holder(self):
        # no drain on the cancel path: a grandchild holding
        # the pipe open 10 s must not delay the raise (the
        # output is discarded; our end is closed and the
        # direct child reaped). (On the communicate shape
        # this waits the full 10 s.)
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = False
        kid = [sys.executable, "-c",
               "import os, sys, time\n"
               "sys.stdout.write('hi\\n'); sys.stdout.flush()\n"
               "if os.fork() == 0:\n"
               "    time.sleep(10)\n"
               "else:\n"
               "    sys.exit(0)\n"]
        timer = threading.Timer(
            0.5, lambda: setattr(lane, "_CANCEL_REQUESTED",
                                 True))
        timer.start()
        try:
            start = time.monotonic()
            with self.assertRaises(InterruptedError):
                lane._check_output_cancel(kid)
            self.assertLess(time.monotonic() - start, 8)
        finally:
            timer.cancel()
            timer.join(timeout=5)
            lane._CANCEL_REQUESTED = saved_flag
        # no children assertion: the orphaned grandchild
        # sleeps out its budget outside our custody.

    def test_run_cancel_skips_spawn_when_flagged(self):
        # pre-launch check: a set flag raises before any
        # child spawns (N8).
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = True
        try:
            with mock.patch.object(lane.subprocess, "Popen") as popen:
                with self.assertRaises(InterruptedError):
                    lane._run_cancel(["true"])
            popen.assert_not_called()
        finally:
            lane._CANCEL_REQUESTED = saved_flag

    def test_wait_cancel_waits_out_mounts(self):
        # wait-out shape: with kill_on_cancel=False a set
        # flag does not raise mid-wait — the effect
        # completes, the code returns for registration,
        # and the still-set flag acts at the next
        # checkpoint. (On the kill shape this raises and
        # the mount this guarded never registers.)
        proc = subprocess.Popen(["true"])
        self.assertEqual(proc.wait(), 0)
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = True
        try:
            self.assertEqual(
                lane._wait_cancel(proc, kill_on_cancel=False), 0)
            self.assertTrue(lane._CANCEL_REQUESTED)
        finally:
            lane._CANCEL_REQUESTED = saved_flag

    def test_copyfile_cancel_refuses_swapped_fifo(self):
        # TOCTOU: a FIFO swapped in after the lstat
        # fails closed without hanging (the open is
        # O_NONBLOCK and fstat-pinned regular).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "bin").write_bytes(b"payload")
            real_stat = os.stat
            swapped = []

            def racing_stat(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if (path == "bin" and not swapped
                        and kwargs.get("dir_fd") is not None):
                    swapped.append(1)
                    os.unlink(path, dir_fd=kwargs["dir_fd"])
                    os.mkfifo(path, 0o644,
                              dir_fd=kwargs["dir_fd"])
                return result

            res = []

            def run():
                try:
                    lane._copytree_cancel(src, root / "dst")
                    res.append("returned")
                except BaseException as error:
                    res.append(
                        f"{type(error).__name__}: {error}")

            with mock.patch("os.stat", racing_stat):
                worker = threading.Thread(target=run,
                                          daemon=True)
                worker.start()
                worker.join(5)
                alive = worker.is_alive()
            self.assertFalse(alive, f"copy hung on FIFO: {res}")
            self.assertEqual(len(res), 1)
            self.assertTrue(res[0].startswith("ValueError"),
                            res)

    def test_copyfile_cancel_refuses_swapped_symlink(self):
        # TOCTOU: a symlink swapped in after the
        # lstat fails closed (O_NOFOLLOW) — the link
        # target is never copied.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "bin").write_bytes(b"payload")
            secret = root / "secret"
            secret.write_text("SECRET")
            real_stat = os.stat
            swapped = []

            def racing_stat(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if (path == "bin" and not swapped
                        and kwargs.get("dir_fd") is not None):
                    swapped.append(1)
                    os.unlink(path, dir_fd=kwargs["dir_fd"])
                    os.symlink(secret, path,
                               dir_fd=kwargs["dir_fd"])
                return result

            with mock.patch("os.stat", racing_stat):
                with self.assertRaises(OSError):
                    lane._copytree_cancel(src, root / "dst")
            self.assertFalse((root / "dst/bin").exists())

    def test_copytree_parent_swap_mid_descent_stays_pinned(self):
        # the walk resolves below pinned directory
        # descriptors: a parent renamed to a symlink
        # AFTER its pin opens is traversed as the
        # pinned directory — the copy carries the
        # original content, never the swap target's.
        # (The hook doubles as the pre-pinned seam, so
        # on the path-resolving shape the swap lands
        # before descent and the outside bytes arrive.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            (src / "sub").mkdir(parents=True)
            (src / "sub" / "inner.txt").write_bytes(b"INSIDE")
            outside = root / "outside"
            outside.mkdir()
            (outside / "evil.txt").write_bytes(b"NOT-IN-STAGE")
            real_open = os.open
            real_is_symlink = Path.is_symlink
            swapped = []

            def swap():
                os.rename(src / "sub", src / "sub_orig")
                os.symlink(outside, src / "sub")

            def racing_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                if (path == "sub" and not swapped
                        and kwargs.get("dir_fd") is not None
                        and flags & os.O_DIRECTORY):
                    swapped.append(1)
                    swap()
                return fd

            def racing_is_symlink(self):
                result = real_is_symlink(self)
                if self.name == "sub" and not swapped \
                        and not result:
                    swapped.append(1)
                    swap()
                return result

            with mock.patch("os.open", racing_open), \
                    mock.patch.object(Path, "is_symlink",
                                      racing_is_symlink):
                lane._copytree_cancel(src, root / "dst")
            self.assertEqual(swapped, [1])
            self.assertTrue((src / "sub").is_symlink())
            self.assertEqual(
                (root / "dst/sub/inner.txt").read_bytes(),
                b"INSIDE")
            self.assertFalse(
                (root / "dst/sub/evil.txt").exists())

    def test_copytree_parent_swap_before_pin_fails_closed(self):
        # the swap landing between the lstat (DIR) and
        # the child pin open must fail closed: the
        # O_NOFOLLOW|O_DIRECTORY open refuses the
        # symlink, and the outside bytes never arrive.
        # (On the path-resolving shape the same swap
        # descends into the link without error.)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            (src / "sub").mkdir(parents=True)
            (src / "sub" / "inner.txt").write_bytes(b"INSIDE")
            outside = root / "outside"
            outside.mkdir()
            (outside / "evil.txt").write_bytes(b"NOT-IN-STAGE")
            real_stat = os.stat
            real_is_symlink = Path.is_symlink
            swapped = []

            def swap():
                os.rename(src / "sub", src / "sub_orig")
                os.symlink(outside, src / "sub")

            def racing_stat(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if (path == "sub" and not swapped
                        and kwargs.get("dir_fd") is not None):
                    swapped.append(1)
                    swap()
                return result

            def racing_is_symlink(self):
                result = real_is_symlink(self)
                if self.name == "sub" and not swapped \
                        and not result:
                    swapped.append(1)
                    swap()
                return result

            with mock.patch("os.stat", racing_stat), \
                    mock.patch.object(Path, "is_symlink",
                                      racing_is_symlink):
                with self.assertRaises(OSError):
                    lane._copytree_cancel(src, root / "dst")
            self.assertEqual(swapped, [1])
            self.assertFalse(
                (root / "dst/sub/evil.txt").exists())

    def test_copytree_dir_fd_top_ignores_ancestor_swap(self):
        # the top opens relative to the caller's pinned
        # parent: an ancestor renamed to a symlink after
        # the pin cannot redirect the copy (real bytes
        # arrive, outside bytes never do).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wrap" / "stage").mkdir(parents=True)
            (root / "wrap" / "stage" / "real.txt").write_bytes(
                b"REAL")
            (root / "evil").mkdir()
            (root / "evil" / "evil.txt").write_bytes(
                b"NOT-IN-STAGE")
            out_fd = os.open(root / "wrap",
                             os.O_RDONLY | os.O_NOFOLLOW
                             | os.O_DIRECTORY)
            try:
                os.rename(root / "wrap", root / "wrap_orig")
                os.symlink(root / "evil", root / "wrap")
                lane._copytree_cancel("stage", root / "dst",
                                      dir_fd=out_fd)
            finally:
                os.close(out_fd)
            self.assertEqual(
                (root / "dst/real.txt").read_bytes(), b"REAL")
            self.assertFalse((root / "dst/evil.txt").exists())

    def test_digest_refuses_fifo_without_hang(self):
        # digest fails closed on a FIFO: no writer ever
        # arrives, so a blocking open would hang the lane
        # uninterruptibly. (The open is O_NONBLOCK and
        # fstat-pinned regular.)
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "stalled"
            os.mkfifo(fifo)
            res = []

            def run():
                try:
                    lane.digest(fifo)
                    res.append("returned")
                except BaseException as error:
                    res.append(type(error).__name__)

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive(),
                             f"digest hung on FIFO: {res}")
            self.assertEqual(res, ["ValueError"])


class ProcessCustody(unittest.TestCase):
    def test_cancellation_repair_slot_consumed_once(self):
        # the repair slot is take-and-clear: a registered
        # repair runs exactly when the flag is set, and never
        # leaks into a later scope.
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        calls = []
        try:
            lane._CANCEL_REQUESTED = False
            lane._CANCELLATION_REPAIR = lambda: calls.append(1)
            with lane.cancellation():
                pass
            self.assertEqual(calls, [])
            self.assertIsNone(lane._CANCELLATION_REPAIR)
            lane._CANCEL_REQUESTED = True
            lane._CANCELLATION_REPAIR = lambda: calls.append(1)
            with self.assertRaises(InterruptedError):
                with lane.cancellation():
                    pass
            self.assertEqual(calls, [1])
            self.assertIsNone(lane._CANCELLATION_REPAIR)
            with self.assertRaises(InterruptedError):
                with lane.cancellation():
                    pass
            self.assertEqual(calls, [1])
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot

    def test_broken_stdout_subprocess_still_exits_zero(self):
        # the shutdown flush must not resurrect the failure:
        # a child whose stdout reader is gone exits 0, not
        # 120. (On the swallow-only shape the interpreter's
        # final flush raises BrokenPipeError -> exit 120.)
        reader, writer = os.pipe()
        os.close(reader)
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); "
             "import sudo_lane as lane; "
             "lane._say('x' * 100000); sys.exit(0)",
             str(Path(lane.__file__).parent)],
            stdout=writer, stderr=subprocess.DEVNULL)
        os.close(writer)
        self.assertEqual(proc.wait(timeout=30), 0)

    def test_closed_stdout_subprocess_still_exits_zero(self):
        # fd 1 closed outright (EBADF, not EPIPE): the
        # recovery's /dev/null open reuses fd 1 itself and
        # must leave it there — closing it again reopens
        # the hole and shutdown exits 120.
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import os, sys; sys.path.insert(0, sys.argv[1]); "
             "import sudo_lane as lane; "
             "os.close(1); lane._say('x'); sys.exit(0)",
             str(Path(lane.__file__).parent)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(proc.wait(timeout=30), 0)

    def test_dup_stdout_subprocess_still_exits_zero(self):
        # sys.stdout rebound to a broken descriptor that is
        # not fd 1: recovery must redirect the stream's own
        # descriptor — fd 1 alone leaves the shutdown
        # flush failing (exit 120).
        reader, writer = os.pipe()
        os.close(reader)
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import os, sys; sys.path.insert(0, sys.argv[1]); "
             "import sudo_lane as lane; "
             "sys.stdout = os.fdopen(int(sys.argv[2]), 'w', "
             "closefd=False); "
             "lane._say('y'); sys.exit(0)",
             str(Path(lane.__file__).parent), str(writer)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            pass_fds=(writer,))
        os.close(writer)
        self.assertEqual(proc.wait(timeout=30), 0)

    def test_say_leaves_aliased_stdout_strictly_alone(self):
        # sys.stdout rebound to a broken fd-2 stream while
        # fd 1 stays healthy: the line is swallowed but fd
        # 1 is never redirected — later output lands. The
        # residual shutdown failure (the broken stream is
        # still broken — nothing was redirected) exits
        # 120. The extra buffered write forces bytes to
        # be pending at shutdown: whether a failed flush
        # retains its buffer is version-dependent (3.12
        # exits 0 without it, 3.14 exits 120), but
        # pending bytes fail the shutdown flush on every
        # version. (On the blind-fallback shape fd 1 is
        # nulled and AFTER is lost; if fd 2 were
        # redirected the shutdown would exit 0.)
        reader, writer = os.pipe()
        os.close(reader)
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import os, sys; sys.path.insert(0, sys.argv[1]); "
             "import sudo_lane as lane; "
             "sys.stdout = os.fdopen(2, 'w', closefd=False); "
             "lane._say('x' * 100000); "
             "sys.stdout.write('z' * 100); "
             "os.write(1, b'AFTER\\n'); sys.exit(0)",
             str(Path(lane.__file__).parent)],
            stdout=subprocess.PIPE, stderr=writer)
        os.close(writer)
        out, _ = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 120)
        self.assertIn(b"AFTER\n", out)

    def test_say_leaves_proxied_stdout_strictly_alone(self):
        # a fileno-less proxy whose write raises: the
        # line is swallowed, no descriptor discovery is
        # possible, and fd 1 is left strictly alone —
        # later output lands. Exit 120 at the proxy's own
        # shutdown flush is the defined residual. (This
        # disposition documents the leave-alone contract;
        # it holds by the same path pre-split.)
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import os, sys\n"
             "sys.path.insert(0, sys.argv[1])\n"
             "import sudo_lane as lane\n"
             "class Proxy:\n"
             "    def write(self, text):\n"
             "        raise BrokenPipeError(32, 'gone')\n"
             "    def flush(self):\n"
             "        raise BrokenPipeError(32, 'gone')\n"
             "sys.stdout = Proxy()\n"
             "lane._say('lost')\n"
             "os.write(1, b'AFTER\\n')\n"
             "sys.exit(0)",
             str(Path(lane.__file__).parent)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, _ = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 120)
        self.assertIn(b"AFTER\n", out)

    def test_say_blocking_error_skips_recovery(self):
        # BlockingIOError never reaches discovery: the
        # descriptor is healthy, so fileno() must not
        # even be consulted — let alone redirected. (On
        # the null-on-OSError shape the OSError branch
        # runs discovery and nulls the fd.)
        calls = []
        owned_r, owned_w = os.pipe()
        class FullPipe:
            def write(self, text):
                calls.append("write")
                raise BlockingIOError(11, "full")
            def flush(self):
                calls.append("flush")
                raise BlockingIOError(11, "full")
            def fileno(self):
                calls.append("fileno")
                return owned_w
        saved = sys.stdout
        sys.stdout = FullPipe()
        try:
            lane._say("held")
        finally:
            sys.stdout = saved
            os.close(owned_r)
            os.close(owned_w)
        self.assertNotIn("fileno", calls)
        self.assertIn("write", calls)

    def test_say_pipe_still_full_at_exit_is_120(self):
        # the EAGAIN residual: when the pipe is STILL
        # full at interpreter shutdown, the retained
        # flush fails and the exit becomes 120. (The
        # defined residual — deterministic on 3.12 and
        # 3.14, unlike the bare alias shape.)
        reader, writer = os.pipe()
        os.set_blocking(writer, False)
        try:
            while True:
                os.write(writer, b"f" * 65536)
        except BlockingIOError:
            pass
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); "
             "import sudo_lane as lane; lane._say('HELD'); "
             "sys.exit(0)",
             str(Path(lane.__file__).parent)],
            stdout=writer, stderr=subprocess.DEVNULL)
        os.close(writer)
        # NOTE: no drain — the pipe stays full through
        # shutdown.
        self.assertEqual(proc.wait(timeout=30), 120)
        os.close(reader)

    def test_say_transient_full_pipe_keeps_descriptor(self):
        # end to end: against a transiently full
        # nonblocking pipe the first line is swallowed
        # (EAGAIN) but the descriptor survives — output
        # after the drain lands and the exit stays 0.
        # (On the null-on-OSError shape fd 1 is
        # redirected and SECOND is lost.) The ready byte
        # proves the first attempt ran against the full
        # pipe: nothing is drained before it arrives.
        reader, writer = os.pipe()
        os.set_blocking(writer, False)
        try:
            while True:
                os.write(writer, b"f" * 65536)
        except BlockingIOError:
            pass
        sig_reader, sig_writer = os.pipe()
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import os, sys, time; "
             "sys.path.insert(0, sys.argv[1]); "
             "import sudo_lane as lane; "
             "lane._say('FIRST'); "
             "os.write(int(sys.argv[2]), b'R'); "
             "time.sleep(2); "
             "lane._say('SECOND'); sys.exit(0)",
             str(Path(lane.__file__).parent),
             str(sig_writer)],
            stdout=writer, stderr=subprocess.DEVNULL,
            pass_fds=(sig_writer,))
        os.close(writer)
        os.close(sig_writer)
        self.assertEqual(os.read(sig_reader, 1), b"R")
        os.close(sig_reader)
        chunks = []
        while True:
            try:
                chunk = os.read(reader, 65536)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        os.close(reader)
        self.assertEqual(proc.wait(timeout=30), 0)
        self.assertIn(b"SECOND\n", b"".join(chunks))

    def test_say_non_int_fileno_leaves_fds_alone(self):
        # fileno() returning a str, True, a float, or an
        # absurd int: swallowed, no descriptor touched —
        # no TypeError/OverflowError escape, no blind
        # redirect. (Untyped discovery raises out of the
        # diagnostic or dup2s onto fd 1.)
        for name, value in (("str", "1"), ("bool", True),
                            ("float", 1.5), ("huge", 10 ** 100)):
            with self.subTest(shape=name):
                class OddFileno:
                    def write(self, text):
                        raise BrokenPipeError(32, "gone")

                    def flush(self):
                        raise BrokenPipeError(32, "gone")

                    def fileno(self, _value=value):
                        return _value

                saved_fd = reader = writer = None
                saved_stream = sys.stdout
                try:
                    saved_fd = os.dup(1)
                    reader, writer = os.pipe()
                    os.dup2(writer, 1)
                    sys.stdout = OddFileno()
                    lane._say("x")
                    target = os.readlink("/proc/self/fd/1")
                finally:
                    sys.stdout = saved_stream
                    if saved_fd is not None:
                        os.dup2(saved_fd, 1)
                    for fd in (saved_fd, reader, writer):
                        if fd is not None:
                            with contextlib.suppress(OSError):
                                os.close(fd)
                self.assertTrue(target.startswith("pipe:["),
                                target)

    def test_say_stream_replacement_keeps_captured_object(self):
        # a sys.stdout swap landing between the failed
        # print and discovery must not redirect the
        # replacement's healthy descriptor: print and
        # discovery use the captured object. (Re-reading
        # discovery nulls the stranger's fd.)
        entered, release = threading.Event(), threading.Event()

        class BlockingBroken:
            def __init__(self, fd):
                self._fd = fd

            def write(self, text):
                entered.set()
                self.released = release.wait(10)
                raise BrokenPipeError(32, "gone")

            def flush(self):
                pass

            def fileno(self):
                return self._fd

        errors = []

        def caller():
            try:
                lane._say("hello")
            except BaseException as error:
                errors.append(error)

        # Cleanup from the first acquisition: every pipe,
        # the stdout swap, and the worker join are owned
        # by the finally — a setup failure (thread start
        # raising, a wait timing out) errors without
        # sticking sys.stdout or leaking descriptors.
        held = []
        worker = None
        replacement = None
        saved = sys.stdout
        try:
            reader, writer = os.pipe()
            held += [reader, writer]
            replacement = os.fdopen(writer, "w", closefd=False)
            owned_r, owned_w = os.pipe()
            held += [owned_r, owned_w]
            sentinel_r, sentinel_w = os.pipe()
            held += [sentinel_r, sentinel_w]
            sys.stdout = BlockingBroken(owned_w)
            worker = threading.Thread(target=caller, daemon=True)
            worker.start()
            self.assertTrue(entered.wait(10))
            sys.stdout = replacement
            release.set()
            worker.join(10)
            self.assertFalse(worker.is_alive())
            target = os.readlink(f"/proc/self/fd/{writer}")
            owned_target = os.readlink(f"/proc/self/fd/{owned_w}")
            sentinel_target = os.readlink(
                f"/proc/self/fd/{sentinel_w}")
        finally:
            sys.stdout = saved
            release.set()
            if worker is not None:
                with contextlib.suppress(RuntimeError):
                    worker.join(10)
            if replacement is not None:
                with contextlib.suppress(OSError):
                    replacement.close()
            for fd in held:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(target.startswith("pipe:["),
                        target)
        # recovery nulled the captured (owned) stream's
        # descriptor only: an unrelated sentinel pipe
        # is untouched, and no foreign fd was harmed.
        self.assertEqual(owned_target, "/dev/null")
        self.assertTrue(sentinel_target.startswith("pipe:["),
                        sentinel_target)

    def test_stream_replacement_setup_failure_releases_everything(
            self):
        # a setup failure inside the committed
        # stream-replacement fixture (thread start
        # raising) errors the test but restores
        # sys.stdout and closes every owned descriptor —
        # never sticking the stream or leaking fds into
        # later tests.
        saved = sys.stdout
        before = set(os.listdir("/proc/self/fd"))
        with mock.patch.object(threading.Thread, "start",
                               side_effect=RuntimeError("boom")):
            case = type(self)(
                "test_say_stream_replacement_keeps_captured_object")
            result = unittest.TestResult()
            case.run(result)
        self.assertEqual(len(result.errors), 1)
        self.assertIn("boom", result.errors[0][1])
        self.assertIs(sys.stdout, saved)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_say_none_stdout_returns_silently(self):
        # a None stream returns at once: print is never
        # even attempted, so no recovery runs against a
        # missing stream. (print() with a None stream
        # would itself be a silent no-op, so the bare
        # call cannot fail — the print-not-called
        # assertion is what pins the early return.)
        saved = sys.stdout
        sys.stdout = None
        try:
            with mock.patch.object(builtins, "print") as printed:
                lane._say("nothing")
            printed.assert_not_called()
        finally:
            sys.stdout = saved

    def test_say_err_none_stderr_returns_silently(self):
        # sys.stderr None (interpreter shutdown ordering):
        # _say_err returns at once — nothing escapes and,
        # critically, nothing lands on stdout (print
        # with file=None would fall back to it).
        saved_out, saved_err = sys.stdout, sys.stderr
        with tempfile.TemporaryFile(mode="w+") as sink:
            sys.stdout = sink
            sys.stderr = None
            try:
                lane._say_err("LEAK?")
            finally:
                sys.stdout = saved_out
                sys.stderr = saved_err
            sink.seek(0)
            self.assertEqual(sink.read(), "")

    def test_say_err_broken_stderr_subprocess_contained(self):
        # _say_err with a dead stderr reader: swallowed,
        # fd 2 recovered to null, exit 0 — no traceback,
        # no 120. (On the bare-print shape the
        # BrokenPipeError escapes.)
        reader, writer = os.pipe()
        os.close(reader)
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, sys.argv[1]); "
             "import sudo_lane as lane; "
             "lane._say_err('x' * 100000); sys.exit(0)",
             str(Path(lane.__file__).parent)],
            stdout=subprocess.DEVNULL, stderr=writer)
        os.close(writer)
        self.assertEqual(proc.wait(timeout=30), 0)

    def test_reap_owned_broken_stderr_keeps_custody(self):
        # the reap loop's pending-cleanup diagnostic goes
        # through _say_err: with a dead stderr the
        # announcement is swallowed and custody still
        # completes — the owned child is reaped, nothing
        # escapes. (On the bare-print shape the
        # BrokenPipeError aborts the loop with the child
        # still owned.)
        ticks = [0]
        def fast_clock():
            # start, then TERM-eligible, then past the
            # 10 s announcement line for the rest.
            ticks[0] += 1
            if ticks[0] == 1:
                return 100.0
            if ticks[0] == 2:
                return 100.5
            return 112.0
        attempts = []
        class DeadStderr:
            def write(self, text):
                attempts.append(text)
                raise BrokenPipeError(32, "gone")
            def flush(self):
                raise BrokenPipeError(32, "gone")
            def fileno(self):
                raise ValueError("no descriptor")
        saved_stderr = sys.stderr
        child = subprocess.Popen(["sleep", "30"])
        try:
            sys.stderr = DeadStderr()
            with mock.patch("time.monotonic",
                            side_effect=fast_clock):
                lane.reap_owned()
        finally:
            sys.stderr = saved_stderr
            with contextlib.suppress(ProcessLookupError):
                child.kill()
            child.wait(timeout=30)
        # the announcement was attempted through the
        # dead stderr, swallowed, and custody completed:
        # no escape, no child left (a zombie would
        # still show in children()). The Popen status
        # is meaningless after the external reap.
        self.assertTrue(
            any("cleanup pending" in text for text in attempts),
            attempts)
        self.assertFalse(lane.children())
        with self.assertRaises(ProcessLookupError):
            os.kill(child.pid, 0)

    def test_flag_during_handler_restore_is_post_completion(self):
        # one flag read governs repair and raise alike: a
        # flag landing after the read (while the saved
        # handlers are restored) raises nothing and repairs
        # nothing — it is post-completion. (On the
        # split-check shape this raises with the complete
        # evidence unrepaired.)
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        old_term = signal.getsignal(signal.SIGTERM)
        old_int = signal.getsignal(signal.SIGINT)
        real_signal = signal.signal
        terms = []
        calls = []
        def restore_hook(sig, handler):
            # only cancellation's own restore reinstalls the
            # test's original handler (inner shields swap
            # defer/noted among themselves).
            if sig == signal.SIGTERM and handler is old_term \
                    and not terms:
                terms.append(1)
                lane._CANCEL_REQUESTED = True
            return real_signal(sig, handler)
        lane._CANCEL_REQUESTED = False
        lane._CANCELLATION_REPAIR = lambda: calls.append(1)
        try:
            with mock.patch.object(lane.signal, "signal",
                                   side_effect=restore_hook):
                with lane.cancellation():
                    pass
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot
        self.assertEqual(terms, [1])
        self.assertEqual(calls, [])
        self.assertIsNone(lane._CANCELLATION_REPAIR)
        self.assertIs(signal.getsignal(signal.SIGTERM), old_term)
        self.assertIs(signal.getsignal(signal.SIGINT), old_int)

    def test_cancellation_reap_failure_keeps_repair_and_raise(self):
        # children() failing inside cancellation's
        # custody still runs the repair, restores the
        # foreign handlers, and propagates the custody
        # OSError (it dominates the cancel raise: the
        # evidence records both facts, the raise names
        # the worst one). (Uncontained, the OSError
        # leaks the repair and the handler restore;
        # swallowed, a cancel-free failure exits 0.)
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        old_term = signal.getsignal(signal.SIGTERM)
        old_int = signal.getsignal(signal.SIGINT)
        calls = []
        lane._CANCEL_REQUESTED = True
        lane._CANCELLATION_REPAIR = lambda: calls.append(1)
        try:
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(12, "Cannot allocate "
                                            "memory")):
                with self.assertRaises(OSError) as raised:
                    with lane.cancellation():
                        pass
            # exact type + errno: a bare assertRaises
            # would also accept the cancel raise
            # (InterruptedError subclasses OSError),
            # leaving dominance untested.
            self.assertIs(type(raised.exception), OSError)
            self.assertEqual(raised.exception.errno, 12)
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot
            lane._CANCELLATION_REAP_FAILED = saved_reap
        self.assertEqual(calls, [1])
        self.assertIsNone(lane._CANCELLATION_REPAIR)
        self.assertIs(signal.getsignal(signal.SIGTERM), old_term)
        self.assertIs(signal.getsignal(signal.SIGINT), old_int)

    def test_cancellation_reap_failure_uncancelled_raises_and_repairs(
            self):
        # no cancel pending: a custody failure in the
        # outer scope still runs the registered repair
        # (invalidating the published success),
        # announces on stderr — never stdout — and
        # propagates the OSError. (Swallowed, the lane
        # exits 0 with custody unverified and
        # complete:true on disk.)
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        old_term = signal.getsignal(signal.SIGTERM)
        old_int = signal.getsignal(signal.SIGINT)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            receipt = {"status": "finished", "exit": 0,
                       "children_reaped": True}
            (out / "ownership.json").write_text(json.dumps(receipt))
            (out / "summary.json").write_text(json.dumps(
                {"exit": 0, "complete": True}))
            lane._CANCEL_REQUESTED = False
            lane._CANCELLATION_REPAIR = functools.partial(
                lane._repair_cancelled_evidence, out, receipt, [])
            stdout, stderr = io.StringIO(), io.StringIO()
            try:
                with mock.patch.object(
                        lane, "children",
                        side_effect=OSError(5, "Input/output "
                                               "error")), \
                        contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    with self.assertRaises(OSError) as raised:
                        with lane.cancellation():
                            pass
                self.assertIs(type(raised.exception), OSError)
                self.assertEqual(raised.exception.errno, 5)
            finally:
                lane._CANCEL_REQUESTED = saved_flag
                lane._CANCELLATION_REPAIR = saved_slot
                lane._CANCELLATION_REAP_FAILED = saved_reap
            repaired = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(repaired["status"], "failed")
            self.assertIs(repaired["children_reaped"], False)
            self.assertIn("reap failed", repaired["error"])
            summary = json.loads(
                (out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)
            self.assertIn("reap failed", summary["error"])
            self.assertNotIn("reap failed", stdout.getvalue())
            self.assertIn("reap failed", stderr.getvalue())
        self.assertIsNone(lane._CANCELLATION_REPAIR)
        self.assertIs(signal.getsignal(signal.SIGTERM), old_term)
        self.assertIs(signal.getsignal(signal.SIGINT), old_int)

    def test_cancellation_body_error_survives_reap_failure(self):
        # a body error plus an outer custody failure (no
        # cancel): the body error propagates — the reap
        # failure must not swallow the root cause. The
        # repair still runs and the handlers restore.
        # (Ungated, the OSError replaces the body error
        # and __main__ prints only its line.)
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        calls = []
        lane._CANCEL_REQUESTED = False
        lane._CANCELLATION_REPAIR = lambda: calls.append(1)
        try:
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(5, "Input/output "
                                           "error")):
                with self.assertRaises(ValueError) as raised:
                    with lane.cancellation():
                        raise ValueError("root-cause")
            self.assertEqual(str(raised.exception), "root-cause")
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot
            lane._CANCELLATION_REAP_FAILED = saved_reap
        self.assertEqual(calls, [1])

    def test_cancellation_sysexit_zero_still_fails_on_reap_failure(
            self):
        # SystemExit(0) — the sys.exit(main()) success
        # path — plus an outer custody failure: the
        # OSError wins, failing the lane closed (exit 1),
        # never 0. (Order pin: the reap error wins over
        # lane-control-flow bodies.)
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        calls = []
        lane._CANCEL_REQUESTED = False
        lane._CANCELLATION_REPAIR = lambda: calls.append(1)
        try:
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(5, "Input/output "
                                           "error")):
                with self.assertRaises(OSError) as raised:
                    with lane.cancellation():
                        raise SystemExit(0)
            self.assertIs(type(raised.exception), OSError)
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot
            lane._CANCELLATION_REAP_FAILED = saved_reap
        self.assertEqual(calls, [1])

    def test_cancellation_reap_beats_cancel_with_body_error(self):
        # total order reap > cancel > body: a body error
        # with cancel pending plus a custody failure
        # propagates the OSError — the cancel was going
        # to clobber the body error anyway (documented
        # cancel dominance), and the OSError reports the
        # worst fact truthfully. (Order pin.)
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        calls = []
        lane._CANCEL_REQUESTED = True
        lane._CANCELLATION_REPAIR = lambda: calls.append(1)
        try:
            with mock.patch.object(
                    lane, "children",
                    side_effect=OSError(5, "Input/output "
                                           "error")):
                with self.assertRaises(OSError) as raised:
                    with lane.cancellation():
                        raise ValueError("root-cause")
            self.assertIs(type(raised.exception), OSError)
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot
            lane._CANCELLATION_REAP_FAILED = saved_reap
        self.assertEqual(calls, [1])

    def test_cancellation_reap_failure_with_surviving_child(self):
        # the failure reaches the scope with a real owned
        # child still alive: custody is genuinely
        # unverified (not just unreadable) — the OSError
        # propagates and the published claim flips, with
        # the child demonstrably unreaped. (First-call
        # mocks never prove the live-child shape.)
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            receipt = {"status": "finished", "exit": 0,
                       "children_reaped": True}
            (out / "ownership.json").write_text(json.dumps(receipt))
            (out / "summary.json").write_text(json.dumps(
                {"exit": 0, "complete": True}))
            child = subprocess.Popen(["sleep", "30"])
            try:
                real_children = lane.children
                calls = []

                def flaky():
                    calls.append(1)
                    if len(calls) > 1:
                        raise OSError(5, "Input/output error")
                    return real_children()

                lane._CANCEL_REQUESTED = False
                lane._CANCELLATION_REPAIR = functools.partial(
                    lane._repair_cancelled_evidence, out, receipt, [])
                with mock.patch.object(lane, "children",
                                       side_effect=flaky):
                    with self.assertRaises(OSError):
                        with lane.cancellation():
                            pass
                self.assertTrue(calls)
                self.assertIsNone(child.poll())
                self.assertIn(child.pid, real_children())
                repaired = json.loads(
                    (out / "ownership.json").read_text())
                self.assertIs(repaired["children_reaped"], False)
            finally:
                lane._CANCEL_REQUESTED = saved_flag
                lane._CANCELLATION_REPAIR = saved_slot
                lane._CANCELLATION_REAP_FAILED = saved_reap
                with contextlib.suppress(ProcessLookupError):
                    child.kill()
                child.wait(timeout=30)

    def test_cancellation_reap_failure_cancelled_invalidates_custody(
            self):
        # cancel pending AND custody failing: the repair
        # records both facts and flips the published
        # children_reaped — a SIGTERM must not leave a
        # true custody claim over an unverified reap.
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        saved_reap = lane._CANCELLATION_REAP_FAILED
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            receipt = {"status": "finished", "exit": 0,
                       "children_reaped": True}
            (out / "ownership.json").write_text(json.dumps(receipt))
            (out / "summary.json").write_text(json.dumps(
                {"exit": 0, "complete": True}))
            lane._CANCEL_REQUESTED = True
            lane._CANCELLATION_REPAIR = functools.partial(
                lane._repair_cancelled_evidence, out, receipt, [])
            try:
                with mock.patch.object(
                        lane, "children",
                        side_effect=OSError(5, "Input/output "
                                               "error")):
                    with self.assertRaises(OSError) as raised:
                        with lane.cancellation():
                            pass
                self.assertIs(type(raised.exception), OSError)
                self.assertEqual(raised.exception.errno, 5)
            finally:
                lane._CANCEL_REQUESTED = saved_flag
                lane._CANCELLATION_REPAIR = saved_slot
                lane._CANCELLATION_REAP_FAILED = saved_reap
            repaired = json.loads(
                (out / "ownership.json").read_text())
            self.assertEqual(repaired["status"], "failed")
            self.assertIs(repaired["children_reaped"], False)
            self.assertIn("cancelled", repaired["error"])
            self.assertIn("reap failed", repaired["error"])
            summary = json.loads(
                (out / "summary.json").read_text())
            self.assertIs(summary["complete"], False)

    def test_cancellation_failed_repair_keeps_cancel_raise(self):
        # a repair that fails (disk gone) is reported, never
        # fatal: the cancel raise still propagates.
        saved_flag = lane._CANCEL_REQUESTED
        saved_slot = lane._CANCELLATION_REPAIR
        def boom():
            raise OSError("disk gone")
        try:
            lane._CANCEL_REQUESTED = True
            lane._CANCELLATION_REPAIR = boom
            with self.assertRaises(InterruptedError) as raised:
                with lane.cancellation():
                    pass
            self.assertIn("owned descendants reaped",
                          str(raised.exception))
            self.assertIsNone(lane._CANCELLATION_REPAIR)
        finally:
            lane._CANCEL_REQUESTED = saved_flag
            lane._CANCELLATION_REPAIR = saved_slot

    def test_supervised_wait_notices_cancel_promptly(self):
        # like the run_logged slice: a supervised child that
        # would idle past the test must still release on a
        # flag within slices (EOF on stdin wakes it), not at
        # its own 10 s self-timeout. (On the single-wait
        # shape the flag is ignored and the child times
        # itself out, returning instead of raising.)
        helper = ("import sys, select; "
                  "select.select([sys.stdin], [], [], 10)")
        saved_flag = lane._CANCEL_REQUESTED
        lane._CANCEL_REQUESTED = False
        def setter():
            lane._CANCEL_REQUESTED = True
        timer = threading.Timer(0.5, setter)
        timer.start()
        try:
            start = time.monotonic()
            with self.assertRaises(InterruptedError):
                lane.launch_supervised([sys.executable, "-c", helper])
            self.assertLess(time.monotonic() - start, 8)
        finally:
            timer.cancel()
            timer.join(timeout=5)
            lane._CANCEL_REQUESTED = saved_flag

    def test_watcher_thread_blocks_cancel_signals(self):
        # per-thread masks: the watcher must block SIGTERM/SIGINT
        # or a delivery there schedules the Python handler on
        # main mid-swap, defeating the install mask. Pinned via
        # /proc SigBlk of the live watcher thread.
        before = len(os.listdir("/proc/self/fd"))
        reader, writer = os.pipe()
        saved_stdin = os.dup(0)
        instances = []
        real_thread = threading.Thread
        def capture(*args, **kwargs):
            thread = real_thread(*args, **kwargs)
            instances.append(thread)
            return thread
        got_term = []
        old_term = signal.signal(
            signal.SIGTERM, lambda s, f: got_term.append(s))
        try:
            os.dup2(reader, 0)
            with mock.patch.object(lane.threading, "Thread",
                                   side_effect=capture):
                lane.watch_parent_pipe()
            self.assertEqual(len(instances), 1)
            watcher = instances[0]
            deadline = time.monotonic() + 5
            while watcher.native_id is None \
                    and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertIsNotNone(watcher.native_id)
            sigblk = 0
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = Path(
                    f"/proc/self/task/{watcher.native_id}/status"
                ).read_text()
                sigblk = int([line for line in status.splitlines()
                              if line.startswith("SigBlk:")][0].split()[1],
                             16)
                if sigblk & (1 << (signal.SIGTERM - 1)) \
                        and sigblk & (1 << (signal.SIGINT - 1)):
                    break
            self.assertNotEqual(sigblk & (1 << (signal.SIGTERM - 1)), 0)
            self.assertNotEqual(sigblk & (1 << (signal.SIGINT - 1)), 0)
            os.close(writer)  # EOF: watcher sends SIGTERM to self
            watcher.join(timeout=5)
            self.assertFalse(watcher.is_alive())
            self.assertEqual(got_term, [signal.SIGTERM])
        finally:
            # Stop the watcher BEFORE restoring fd 0 / the SIGTERM
            # handler: otherwise a live watcher sees EOF on the
            # restored /dev/null and kills the suite with the
            # default disposition.
            with contextlib.suppress(OSError):
                os.close(writer)
            for thread in instances:
                thread.join(timeout=5)
            os.dup2(saved_stdin, 0)
            os.close(saved_stdin)
            os.close(reader)
            signal.signal(signal.SIGTERM, old_term)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_watcher_born_blocked_before_first_mask_call(self):
        # the spawn mask (not the entry mask) covers birth:
        # pause the watcher before its first pthread_sigmask
        # and assert the cancel signals are already blocked.
        # Without inherited masking this reads zero.
        before = len(os.listdir("/proc/self/fd"))
        reader, writer = os.pipe()
        saved_stdin = os.dup(0)
        instances = []
        real_thread = threading.Thread
        def capture(*args, **kwargs):
            thread = real_thread(*args, **kwargs)
            instances.append(thread)
            return thread
        entered = threading.Event()
        release = threading.Event()
        real_mask = signal.pthread_sigmask
        def gate(op, sigs):
            if threading.get_ident() != threading.main_thread().ident:
                entered.set()
                self.assertTrue(release.wait(10))
            return real_mask(op, sigs)
        got_term = []
        old_term = signal.signal(
            signal.SIGTERM, lambda s, f: got_term.append(s))
        try:
            os.dup2(reader, 0)
            with mock.patch.object(lane.threading, "Thread",
                                   side_effect=capture), \
                    mock.patch.object(lane.signal, "pthread_sigmask",
                                      side_effect=gate):
                lane.watch_parent_pipe()
                self.assertEqual(len(instances), 1)
                watcher = instances[0]
                self.assertTrue(entered.wait(10))
                deadline = time.monotonic() + 5
                while watcher.native_id is None \
                        and time.monotonic() < deadline:
                    time.sleep(0.001)
                self.assertIsNotNone(watcher.native_id)
                status = Path(
                    f"/proc/self/task/{watcher.native_id}/status"
                ).read_text()
                sigblk = int([line for line in status.splitlines()
                              if line.startswith("SigBlk:")][0].split()[1],
                             16)
                self.assertNotEqual(sigblk & (1 << (signal.SIGTERM - 1)), 0)
                self.assertNotEqual(sigblk & (1 << (signal.SIGINT - 1)), 0)
                release.set()
        finally:
            with contextlib.suppress(OSError):
                os.close(writer)
            for thread in instances:
                thread.join(timeout=5)
            os.dup2(saved_stdin, 0)
            os.close(saved_stdin)
            os.close(reader)
            signal.signal(signal.SIGTERM, old_term)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_timeout_kills_and_reaps_owned_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            late = Path(tmp) / "late"
            code, timed_out, _captured = lane.run_logged(
                ["sh", "-c", 'sleep 2; touch "$1"', "fixture", str(late)],
                Path(tmp) / "timeout.log", timeout=0.05,
            )
            self.assertTrue(timed_out)
            self.assertEqual(code, 124)
            self.assertFalse(late.exists())
            result = json.loads((Path(tmp) / "timeout.log.result.json").read_text())
            self.assertEqual(result["exit"], 124)
            self.assertEqual(result["raw_exit"], 124)
            # killed on TERM: the true OS status, never the 124 sentinel
            self.assertEqual(result["reaped_status"], -signal.SIGTERM)

    def test_timeout_reaps_a_descendant_that_changed_session(self):
        # Adopt a surviving regression child so the RED case itself can
        # clean up every process it created; no unrelated PID is touched.
        self.assertEqual(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0), 0)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child.pid"
            script = (
                "import os,time; from pathlib import Path; "
                f"Path({str(child)!r}).write_text(str(os.getpid())); time.sleep(60)"
            )
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{script!r}],start_new_session=True); "
                "time.sleep(60)"
            )
            pid = None
            try:
                code, timed_out, _captured = lane.run_logged(
                    [sys.executable, "-c", parent], root / "timeout.log", timeout=0.4,
                )
                self.assertTrue(child.exists(), "positive control: detached child started")
                pid = int(child.read_text())
                self.assertTrue(timed_out)
                self.assertEqual(code, 124)
                self.assertFalse(Path(f"/proc/{pid}").exists(), "detached child must be reaped")
            finally:
                if pid is not None and Path(f"/proc/{pid}").exists():
                    fd = os.pidfd_open(pid)
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    finally:
                        os.close(fd)
                    os.waitpid(pid, 0)

    def test_cancellation_keeps_lease_until_owned_tree_is_reaped(self):
        lane.subreaper()
        for mode in ("executor-term", "wrapper-term", "wrapper-kill"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                leaf = (
                    "import os,time; from pathlib import Path; "
                    f"Path({str(root / 'leaf.pid')!r}).write_text(str(os.getpid())); time.sleep(60)"
                )
                body = (
                    "import subprocess,sys,os,time; from pathlib import Path; "
                    f"Path({str(root / 'body.pid')!r}).write_text(str(os.getpid())); "
                    f"subprocess.Popen([sys.executable,'-c',{leaf!r}],start_new_session=True); time.sleep(60)"
                )
                imports = f"import sys; sys.path.insert(0,{str(Path(lane.__file__).parent)!r}); import sudo_lane as lane\n"
                executor = imports + f"""
import os,fcntl
from pathlib import Path
root=Path({str(root)!r})
with lane.cancellation():
    if {mode != 'executor-term'!r}:
        lane.watch_parent_pipe()
    with (root/'lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        (root/'executor.pid').write_text(str(os.getpid()))
        lane.run_logged([sys.executable,'-c',{body!r}],root/'body.log',60)
"""
                command = [sys.executable, "-B", "-c", executor]
                if mode != "executor-term":
                    command = [sys.executable, "-B", "-c", imports +
                               f"with lane.cancellation():\n    lane.launch_supervised({command!r})\n"]
                with (root / "wrapper.log").open("wb") as log:
                    proc = subprocess.Popen(command, stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 5
                        while not (root / "leaf.pid").exists() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue((root / "leaf.pid").exists(), "positive control: test tree is alive")
                        body_pid, leaf_pid = [int((root / name).read_text()) for name in ("body.pid", "leaf.pid")]
                        with (root / "lock").open() as lock:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            proc.send_signal(signal.SIGKILL if mode == "wrapper-kill" else signal.SIGTERM)
                            while True:
                                try:
                                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                    break
                                except BlockingIOError:
                                    self.assertLess(time.monotonic(), deadline, "cancellation did not release custody")
                                    time.sleep(0.01)
                            self.assertFalse(Path(f"/proc/{body_pid}").exists(), "body survived lease release")
                            self.assertFalse(Path(f"/proc/{leaf_pid}").exists(), "detached leaf survived lease release")
                        self.assertNotEqual(proc.wait(timeout=5), 0)
                        receipt = json.loads((root / "body.log.result.json").read_text())
                        self.assertTrue(receipt["cancelled"])
                        self.assertTrue(receipt["descendants_reaped"])
                    finally:
                        lane.reap_owned(proc)

    def test_cancellation_during_timeout_cleanup_cannot_start_more_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                "import signal,time; from pathlib import Path; "
                f"signal.signal(signal.SIGTERM,lambda *_: Path({str(root / 'cleaning')!r}).write_text('TERM')); "
                "time.sleep(60)"
            )
            helper = (
                f"import sys; sys.path.insert(0,{str(Path(lane.__file__).parent)!r}); import sudo_lane as lane\n"
                "from pathlib import Path\n"
                "with lane.cancellation():\n"
                f"    lane.run_logged([sys.executable,'-c',{body!r}],Path({str(root / 'body.log')!r}),0.2)\n"
                f"    Path({str(root / 'continued')!r}).write_text('unexpected next command')\n"
            )
            with (root / "helper.log").open("wb") as log:
                proc = subprocess.Popen([sys.executable, "-B", "-c", helper], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 5
                    while not (root / "cleaning").exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue((root / "cleaning").exists(), "positive control: cleanup is waiting on TERM")
                    proc.terminate()
                    code = proc.wait(timeout=5)
                    self.assertFalse((root / "continued").exists(), "cancellation was lost during cleanup")
                    self.assertNotEqual(code, 0)
                finally:
                    lane.reap_owned(proc)


if __name__ == "__main__":
    unittest.main()
